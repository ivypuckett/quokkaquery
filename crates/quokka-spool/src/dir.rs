//! Where spools live, and how a dead process's spools are cleaned up (§4.1).
//!
//! Three rules from §4.1, and one trap that decides the shape of the third:
//!
//! 1. **Under the XDG cache directory, not `/tmp`.** `/tmp` is tmpfs on many systems,
//!    and a 1 GiB spool would land in RAM.
//! 2. **Deleted on clean exit.** Nothing persists, so the cache directory never
//!    accumulates query results and the data-handling story is "we don't keep them".
//! 3. **Swept at startup**, because a crash leaves orphans.
//!
//! The trap is in the third. §4.1 says "startup sweeps any spool directory whose owning
//! PID is no longer alive", and a literal reading of that is wrong, because **PIDs are
//! reused**: a directory whose PID now belongs to somebody else's process is not
//! thereby alive, and a live process whose PID we misread is not thereby dead. Deleting
//! a running process's spool — pulling the rows out from under an open result tab — is
//! much worse than leaving a stale directory behind for the next sweep.
//!
//! So this module never asks whether a PID is alive. It asks a question that has a
//! sound answer: **is anyone still holding this spool directory's lock?** The lock is a
//! SQLite database the owner keeps an `EXCLUSIVE` transaction open on for as long as it
//! runs. The operating system releases file locks when a process ends, however it ends —
//! cleanly, by `SIGKILL`, or by the machine losing power — so "the lock is free" means
//! "nobody owns this", with no reasoning about identity at all. A PID still appears in
//! the directory's name, because it is genuinely useful when a human is looking at
//! `~/.cache` wondering what left a file there; nothing decides anything from it.

use std::path::{Path, PathBuf};

use sqlx::sqlite::{SqliteConnectOptions, SqliteConnection, SqliteJournalMode};
use sqlx::{ConnectOptions, Connection, Executor};
use uuid::Uuid;

use crate::error::SpoolError;
use crate::write::{Limits, SpoolWriter};

/// The lock file inside every spool directory.
const LOCK: &str = "owner.lock";

/// How long a directory with no lock file at all is left alone before it is treated as
/// an orphan.
///
/// A directory is created a moment before its lock is, so a sweep that ran in that
/// instant would otherwise delete a spool that is about to be used. Nothing depends on
/// the exact value; it only has to be longer than "a process is starting up".
const NO_LOCK_GRACE: std::time::Duration = std::time::Duration::from_secs(60);

/// This process's spool directory, and the lock that says so.
///
/// Dropping it does *not* delete the directory: a clean exit calls [`SpoolSet::close`],
/// and anything that is not a clean exit should leave the files for the next sweep
/// rather than racing to tidy up while the process is dying.
pub struct SpoolSet {
    root: PathBuf,
    dir: PathBuf,
    limits: Limits,
    lock: Option<SqliteConnection>,
    swept: Vec<PathBuf>,
}

impl std::fmt::Debug for SpoolSet {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SpoolSet")
            .field("dir", &self.dir)
            .field("swept", &self.swept.len())
            .finish_non_exhaustive()
    }
}

impl SpoolSet {
    /// Claim a directory for this process, sweeping any orphans first.
    pub async fn open(root: Option<&Path>, limits: Limits) -> Result<Self, SpoolError> {
        let root = match root {
            Some(p) => p.to_path_buf(),
            None => default_spool_root()?,
        };
        std::fs::create_dir_all(&root).map_err(|source| SpoolError::Io {
            path: root.clone(),
            source,
        })?;

        // A random suffix, so that a directory is never adopted from a dead process
        // that happened to have this PID. The PID is there for a human reading the
        // directory listing.
        let dir = root.join(format!(
            "{}-{}",
            std::process::id(),
            Uuid::now_v7().simple()
        ));
        std::fs::create_dir_all(&dir).map_err(|source| SpoolError::Io {
            path: dir.clone(),
            source,
        })?;

        let lock = take_lock(&dir).await?;

        // Swept after this process's own directory is locked, so its own spool is never
        // a candidate — the lock refuses, but not depending on that is cheaper than
        // reasoning about it.
        let swept = sweep(&root).await;

        Ok(SpoolSet {
            root,
            dir,
            limits,
            lock: Some(lock),
            swept,
        })
    }

    pub fn dir(&self) -> &Path {
        &self.dir
    }

    pub fn root(&self) -> &Path {
        &self.root
    }

    pub fn limits(&self) -> Limits {
        self.limits
    }

    /// Orphan directories this process removed at startup.
    pub fn swept(&self) -> &[PathBuf] {
        &self.swept
    }

    /// Where the spool for one query goes.
    pub fn path_for(&self, query_id: Uuid) -> PathBuf {
        self.dir.join(format!("{query_id}.db"))
    }

    /// A writer for one query's result, to hand to `execute()` as its sink.
    pub fn writer(&self, query_id: Uuid, connection: &str) -> Result<SpoolWriter, SpoolError> {
        SpoolWriter::create(&self.path_for(query_id), query_id, connection, self.limits)
    }

    /// Release the lock and delete this process's spools — the clean exit of §4.1.
    pub async fn close(mut self) {
        if let Some(lock) = self.lock.take() {
            let _ = lock.close().await;
        }
        let _ = std::fs::remove_dir_all(&self.dir);
    }

    /// Release the lock and leave every file behind, as a crash would.
    ///
    /// Exists so that the sweep can be tested against a directory that was genuinely
    /// abandoned rather than against one a test deleted by hand.
    pub async fn abandon(mut self) -> PathBuf {
        if let Some(lock) = self.lock.take() {
            let _ = lock.close().await;
        }
        self.dir.clone()
    }
}

/// Open the lock database and hold an `EXCLUSIVE` transaction on it.
///
/// The transaction is never committed. That is the point: SQLite holds the file lock
/// for as long as the transaction is open, and the operating system takes it back the
/// moment this process ends, whatever ends it.
async fn take_lock(dir: &Path) -> Result<SqliteConnection, SpoolError> {
    let mut conn = SqliteConnectOptions::new()
        .filename(dir.join(LOCK))
        .create_if_missing(true)
        // Not WAL: a rollback-journal database takes a plain file lock that another
        // process sees immediately, which is the whole mechanism here.
        .journal_mode(SqliteJournalMode::Delete)
        .connect()
        .await
        .map_err(|e| SpoolError::Open {
            detail: format!("claiming the spool directory {}: {e}", dir.display()),
        })?;

    conn.execute("CREATE TABLE IF NOT EXISTS owner (pid INTEGER)")
        .await?;
    conn.execute("BEGIN EXCLUSIVE").await?;
    conn.execute(sqlx::query("INSERT INTO owner (pid) VALUES (?)").bind(std::process::id()))
        .await?;

    Ok(conn)
}

/// Delete every spool directory under `root` that nobody holds the lock on.
///
/// Errs towards leaving files behind: anything this cannot prove is an orphan is left
/// for the next sweep, including a directory whose lock is merely unreadable.
pub async fn sweep(root: &Path) -> Vec<PathBuf> {
    let mut removed = Vec::new();
    let Ok(entries) = std::fs::read_dir(root) else {
        return removed;
    };

    for entry in entries.flatten() {
        let path = entry.path();
        if !path.is_dir() {
            continue;
        }
        if is_orphan(&path).await && std::fs::remove_dir_all(&path).is_ok() {
            removed.push(path);
        }
    }
    removed
}

async fn is_orphan(dir: &Path) -> bool {
    let lock = dir.join(LOCK);
    if !lock.exists() {
        // No lock file: either a directory from a version that had none, or one caught
        // in the instant between being created and being claimed. Old enough is the
        // only evidence available, and it is enough.
        return older_than(dir, NO_LOCK_GRACE);
    }

    // Try to take the write lock the owner would be holding. Succeeding means nobody
    // is; failing — for any reason at all, including a busy lock, a corrupt file or a
    // permission problem — means this is not ours to delete.
    let connect = SqliteConnectOptions::new()
        .filename(&lock)
        .create_if_missing(false)
        .journal_mode(SqliteJournalMode::Delete)
        .busy_timeout(std::time::Duration::from_millis(0))
        .connect()
        .await;

    let Ok(mut conn) = connect else {
        return false;
    };
    let free = conn.execute("BEGIN IMMEDIATE").await.is_ok();
    if free {
        let _ = conn.execute("ROLLBACK").await;
    }
    let _ = conn.close().await;
    free
}

fn older_than(path: &Path, age: std::time::Duration) -> bool {
    let Ok(meta) = std::fs::metadata(path) else {
        return false;
    };
    let Ok(modified) = meta.modified() else {
        return false;
    };
    modified
        .elapsed()
        .map(|elapsed| elapsed > age)
        .unwrap_or(false)
}

/// `$QUOKKA_CACHE_DIR`, else `<XDG cache dir>/quokkaquery/spool`.
///
/// Explicitly not `/tmp` (§4.1): it is tmpfs on many systems, and a 1 GiB spool would
/// land in RAM. The override is for a machine whose cache directory is on the wrong
/// disk, and for tests, which must never write to the developer's real cache.
pub fn default_spool_root() -> Result<PathBuf, SpoolError> {
    if let Some(dir) = std::env::var_os("QUOKKA_CACHE_DIR") {
        return Ok(PathBuf::from(dir).join("spool"));
    }
    let dirs = directories::ProjectDirs::from("", "", "quokkaquery").ok_or_else(|| {
        SpoolError::CacheDir(
            "no home directory: set QUOKKA_CACHE_DIR to choose where result spools live"
                .to_string(),
        )
    })?;
    Ok(dirs.cache_dir().join("spool"))
}
