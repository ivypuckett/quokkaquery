//! QuokkaQuery's append-only audit log.
//!
//! One SQLite database, in WAL mode, at the XDG data dir. Every query that reaches a
//! database leaves exactly two rows here — one appended before execution and one after —
//! and every row is sealed into a hash chain so that an edit or an excision is
//! detectable (ARCHITECTURE §5).
//!
//! What this crate deliberately cannot store is result data. There is no field for a
//! row, a sample, or a digest of one, and adding one would break the promise the product
//! makes: the log describes queries, never what came back (§5.1).
//!
//! This crate sits at the bottom of the workspace graph. It knows nothing about drivers,
//! connections or surfaces; `quokka-core` depends on it so that `execute()` can append.

mod event;
mod hash;
mod log;
mod path;

pub use event::{ActorKind, AuditEvent, Client, EventKind, SqlLogging, Status, StoredEvent};
pub use hash::row_hash;
pub use log::{now_rfc3339, AuditError, AuditLog, Problem, VerifyReport};
pub use path::default_audit_path;
