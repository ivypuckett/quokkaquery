//! The result spool: one execution, then paging, sorting and streamed export.
//!
//! This is the mechanism behind "512 rows on screen, the whole dataset to a file"
//! (ARCHITECTURE §4). A query runs **once**; as its rows arrive they are written into a
//! per-result SQLite database, and everything downstream — the next page, a re-sort, an
//! export to Parquet — is a read of that file. Nothing here reaches a database, and
//! nothing here can: the spool implements [`quokka_core::RowSink`], which is the seam
//! `execute()` already hands its rows to, and it holds no
//! [`ExecutePermit`](quokka_core::ExecutePermit) because it has no use for one.
//!
//! That is what makes invariant 2 true rather than aspirational. Paging by re-running
//! the query with `LIMIT … OFFSET n` would mean paying for a second scan, and on Athena
//! that is money; worse, without a total ordering page 2 can repeat rows from page 1.
//! Here page 2 is `SELECT … WHERE rowid > ? LIMIT 512` over rows that are already paid
//! for.
//!
//! ## The shape of it
//!
//! ```text
//! SpoolSet    a PID-scoped directory under the XDG cache dir, locked while this
//!             process lives, swept of orphans at startup and deleted on clean exit
//!               └── SpoolWriter   one result, arriving: `execute()`'s sink
//!                     └── Spool   the same result, finished: paging, sorting, export
//! ```
//!
//! ## What every read carries
//!
//! [`Scoping`], on every page and every export report. §4.2's trap is that sort and
//! filter operate on the *spooled subset*: if a million of twelve million rows were
//! spooled, sorting yields the top of the first million, which looks authoritative and
//! is wrong. A surface cannot omit that here, because the scoping arrives whether it
//! asked for it or not.

mod blocking;
mod codec;
mod dir;
mod error;
mod export;
mod meta;
mod pager;
#[cfg(feature = "parquet")]
mod parquet;
mod read;
mod view;
mod write;

pub use codec::same_value;
pub use dir::{default_spool_root, sweep, SpoolSet};
pub use error::SpoolError;
pub use export::{export, Destination, ExportFailure, ExportReport, ExportSink, Format};
pub use meta::{Meta, MetaKey};
pub use pager::Pager;
pub use read::{filter_value, Page, Spool, MAX_PAGE_ROWS};
pub use view::{Direction, Filter, Op, Position, Scoping, SortKey, View};
pub use write::{Limits, SpoolWriter};

/// Whether this build can write Parquet (§4). False in a build that dropped the
/// `parquet` feature to keep `arrow` out of its tree.
pub const HAS_PARQUET: bool = cfg!(feature = "parquet");
