//! What the server remembers between tool calls: one spool per query, and where each
//! page of it starts.
//!
//! This is the payoff ARCHITECTURE §6.2 describes, and the reason `quokka mcp` is a
//! long-lived process rather than a `quokka` invocation per call. A query runs **once**;
//! its rows land in a spool; the agent's next page, re-sort or export is a read of that
//! file. A `query` tool that re-executed to serve page 2 would defeat the milestone
//! before it started — and on Athena it would bill for it.
//!
//! The spools die with the process (§4.1). That is not a limitation to work around here:
//! a cache that outlived the session would serve rows that no longer match the database.

use std::collections::HashMap;
use std::sync::{Arc, Mutex};

use quokka_core::Outcome;
use quokka_spool::{Position, Spool, View};
use uuid::Uuid;

/// One finished query, open for paging.
pub struct Held {
    pub spool: Spool,
    pub outcome: Outcome,
    /// The view the last page was read under. A new sort or filter replaces it and
    /// starts again from the top, because a cursor into one ordering means nothing in
    /// another.
    pub view: View,
    /// Cursors minted for this result so far, and where each one resumes.
    ///
    /// Opaque on purpose. [`Position`] is opaque in `quokka-spool` because arrival order
    /// resumes from a rowid and a sorted view from an offset, and a caller that could
    /// mint one could ask for a page that means nothing. So the server mints the tokens
    /// and holds the positions, and an agent passes back what it was given.
    pub cursors: HashMap<String, Position>,
    pub next_cursor: u64,
}

impl Held {
    pub fn new(spool: Spool, outcome: Outcome) -> Self {
        Held {
            spool,
            outcome,
            view: View::arrival_order(),
            cursors: HashMap::new(),
            next_cursor: 0,
        }
    }

    /// Mint a token for a position, and remember it.
    pub fn mint(&mut self, at: Position) -> String {
        self.next_cursor += 1;
        let token = format!("p{}", self.next_cursor);
        self.cursors.insert(token.clone(), at);
        token
    }

    /// Forget every cursor, because the ordering they pointed into is gone.
    pub fn reset(&mut self, view: View) {
        self.view = view;
        self.cursors.clear();
    }
}

/// How many finished results the server keeps open at once.
///
/// There has to be a number. The CLI never needed one — a spool died with the
/// invocation that made it — but a server that ran four hundred queries would otherwise
/// hold four hundred SQLite files open and up to the spool cap of disk for each, and
/// "long-lived" would mean "grows until the disk does not". Thirty-two is enough that an
/// agent working through a result set, exporting it and comparing it with another never
/// notices, and small enough that the bound is real.
///
/// Losing a result is not a silent failure: the next call naming it is told that the
/// rows are gone and that getting them back means running the query again — which costs
/// a second scan, so it does not happen by itself (§1.4).
pub const MAX_HELD_RESULTS: usize = 32;

/// Every result this process is still holding, oldest first.
#[derive(Clone, Default)]
pub struct Results(Arc<Mutex<Inner>>);

#[derive(Default)]
struct Inner {
    held: HashMap<Uuid, Held>,
    /// Insertion order, so the oldest is the one that goes.
    order: Vec<Uuid>,
}

impl Results {
    pub fn new() -> Self {
        Results::default()
    }

    /// Hold a result, and hand back whichever one that pushed out.
    ///
    /// Returned rather than dropped here because closing a spool properly is async and
    /// this runs under a lock. The caller closes it and deletes its file; dropping it
    /// would work too, at the price of leaving a file behind for the exit sweep.
    #[must_use = "the evicted result owns an open SQLite file; close it"]
    pub fn insert(&self, query_id: Uuid, held: Held) -> Option<Held> {
        let mut inner = self.0.lock().expect("held results poisoned");
        if inner.held.insert(query_id, held).is_none() {
            inner.order.push(query_id);
        }
        if inner.order.len() <= MAX_HELD_RESULTS {
            return None;
        }
        let oldest = inner.order.remove(0);
        inner.held.remove(&oldest)
    }

    /// Do something with one held result.
    ///
    /// A closure rather than a guard, so the lock is never held across an `await`: every
    /// read of a spool is async, and a lock held over one would serialize the whole
    /// server behind the slowest page. Callers take what they need — a `Spool` is
    /// cheaply cloneable — and let go.
    pub fn with<T>(&self, query_id: Uuid, f: impl FnOnce(&mut Held) -> T) -> Option<T> {
        let mut inner = self.0.lock().expect("held results poisoned");
        inner.held.get_mut(&query_id).map(f)
    }
}

/// Close a result the cache pushed out, and take its file with it.
///
/// The pool is closed before the file is removed so that nothing is holding it; a
/// removal that fails anyway is not worth reporting, because the whole spool directory
/// goes at exit (§4.1) and the next process sweeps whatever a crash left.
pub async fn release(held: Held) {
    let path = held.spool.path().to_path_buf();
    held.spool.close().await;
    let _ = std::fs::remove_file(path);
}
