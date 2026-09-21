//! A synchronous door onto one async SQLite connection.
//!
//! [`quokka_core::RowSink`] is synchronous, and deliberately so: `execute()` drives the
//! row stream itself and hands rows over one at a time, so a sink is a place to put a
//! row rather than a task to be scheduled. `sqlx` is asynchronous. Something has to give
//! at that seam, and the options are worse than they look:
//!
//! - Blocking on a future from inside the sink is not available: the sink is called from
//!   within the engine's tokio runtime, and tokio's `block_on` panics there by design.
//! - A second SQLite binding — `rusqlite` — would be genuinely synchronous, but
//!   `libsqlite3-sys` carries a `links = "sqlite3"` key, so Cargo permits exactly one
//!   version of it in the graph. Taking that dependency would tie this crate's build to
//!   whichever version `sqlx-sqlite` happens to pin, and break the workspace on the day
//!   the two disagree.
//!
//! So the connection lives on a thread of its own, running a current-thread runtime, and
//! the sink talks to it over a channel. Jobs are closures, which keeps every call site
//! ordinary async `sqlx` code rather than a command enum that grows a variant per query.
//!
//! The caller blocks while a job runs. That is the right trade here — the work is a
//! local SQLite write, and the engine is already calling a synchronous sink per row —
//! but it is why the writer batches rows before sending, and why reads go through the
//! async [`crate::read`] side instead of through this.

use std::sync::mpsc::{self, SyncSender};

use futures::future::BoxFuture;
use sqlx::sqlite::{SqliteConnectOptions, SqliteConnection};
use sqlx::{ConnectOptions, Connection};

use crate::error::SpoolError;

type Job = Box<dyn for<'a> FnOnce(&'a mut SqliteConnection) -> BoxFuture<'a, ()> + Send>;

/// One SQLite connection, reachable synchronously.
pub struct Worker {
    jobs: Option<SyncSender<Job>>,
    thread: Option<std::thread::JoinHandle<()>>,
}

impl std::fmt::Debug for Worker {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Worker").finish_non_exhaustive()
    }
}

impl Worker {
    /// Open a connection on a thread of its own.
    ///
    /// Returns once the connection is established, so a failure to open is a failure to
    /// construct rather than a surprise on the first write.
    pub fn open(options: SqliteConnectOptions) -> Result<Self, SpoolError> {
        // Depth one: the writer is allowed to prepare its next batch while this one is
        // being inserted, and no further ahead than that.
        let (jobs, rx) = mpsc::sync_channel::<Job>(1);
        let (ready_tx, ready_rx) = mpsc::sync_channel::<Result<(), String>>(1);

        let thread = std::thread::Builder::new()
            .name("quokka-spool".to_string())
            .spawn(move || {
                let runtime = match tokio::runtime::Builder::new_current_thread()
                    .enable_all()
                    .build()
                {
                    Ok(r) => r,
                    Err(e) => {
                        let _ = ready_tx.send(Err(e.to_string()));
                        return;
                    }
                };

                runtime.block_on(async move {
                    let mut conn = match options.connect().await {
                        Ok(c) => {
                            if ready_tx.send(Ok(())).is_err() {
                                return;
                            }
                            c
                        }
                        Err(e) => {
                            let _ = ready_tx.send(Err(e.to_string()));
                            return;
                        }
                    };

                    while let Ok(job) = rx.recv() {
                        job(&mut conn).await;
                    }

                    // The sender was dropped, which is the only way out of that loop:
                    // close cleanly so the file is flushed and unlocked before the
                    // thread ends.
                    let _ = conn.close().await;
                });
            })
            .map_err(|e| SpoolError::Thread(e.to_string()))?;

        match ready_rx.recv() {
            Ok(Ok(())) => Ok(Worker {
                jobs: Some(jobs),
                thread: Some(thread),
            }),
            Ok(Err(detail)) => Err(SpoolError::Open { detail }),
            Err(_) => Err(SpoolError::Thread(
                "the spool's writer thread ended before it opened its database".to_string(),
            )),
        }
    }

    /// Run one job on the connection and wait for its answer.
    pub fn call<T, F>(&self, job: F) -> Result<T, SpoolError>
    where
        T: Send + 'static,
        F: for<'a> FnOnce(&'a mut SqliteConnection) -> BoxFuture<'a, T> + Send + 'static,
    {
        let jobs = self.jobs.as_ref().ok_or_else(|| {
            SpoolError::Thread("this spool's writer has already been closed".to_string())
        })?;

        let (tx, rx) = mpsc::sync_channel::<T>(1);
        let wrapped: Job = Box::new(move |conn| {
            Box::pin(async move {
                let value = job(conn).await;
                // A closed receiver means the caller gave up waiting, which only
                // happens if it panicked. The work is done either way.
                let _ = tx.send(value);
            })
        });

        jobs.send(wrapped)
            .map_err(|_| SpoolError::Thread("the spool's writer thread has gone".to_string()))?;
        rx.recv()
            .map_err(|_| SpoolError::Thread("the spool's writer thread died mid-write".to_string()))
    }

    /// Close the connection and join the thread.
    ///
    /// Called when a spool is finished rather than at drop, so the file is committed and
    /// unlocked at a point the caller chose.
    pub fn close(&mut self) {
        self.jobs = None;
        if let Some(thread) = self.thread.take() {
            let _ = thread.join();
        }
    }
}

impl Drop for Worker {
    fn drop(&mut self) {
        self.close();
    }
}
