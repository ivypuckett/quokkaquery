//! The `meta` table: row count, truncation and timings (§4).
//!
//! Keys rather than columns, because what belongs here grows: M4 wants the creation
//! time to render "as of 10:00 (45m ago)", M5 will want Athena's bytes scanned, and a
//! key/value table absorbs both without a migration on a file that lives for minutes.
//!
//! What is *not* here is any part of a row. The spool holds the result; `meta` describes
//! it.

use quokka_core::{Cap, Outcome};
use uuid::Uuid;

/// A key in the `meta` table.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MetaKey {
    /// When the spool was created — the "as of" a result tab shows (§4.1).
    CreatedAt,
    /// The query whose rows these are.
    QueryId,
    Connection,
    /// Rows the spool holds.
    Rows,
    /// `rows` | `bytes` when the spool's own cap stopped it, absent otherwise (§4.2).
    SpoolCapped,
    /// Whether the caller's `max_rows` stopped the read.
    TruncatedByMaxRows,
    /// Rows the query returned to the engine, which is more than `rows` exactly when
    /// the spool's cap bound first.
    RowsReturned,
    /// How long the query took, in milliseconds.
    QueryDurationMs,
    /// How the query ended.
    Status,
}

impl MetaKey {
    pub fn as_str(self) -> &'static str {
        match self {
            MetaKey::CreatedAt => "created_at",
            MetaKey::QueryId => "query_id",
            MetaKey::Connection => "connection",
            MetaKey::Rows => "rows",
            MetaKey::SpoolCapped => "spool_capped",
            MetaKey::TruncatedByMaxRows => "truncated_by_max_rows",
            MetaKey::RowsReturned => "rows_returned",
            MetaKey::QueryDurationMs => "query_duration_ms",
            MetaKey::Status => "status",
        }
    }
}

/// Everything the writer records once a query has finished.
pub fn entries_for(
    created_at: &str,
    query_id: Uuid,
    connection: &str,
    rows: u64,
    capped: Option<Cap>,
    outcome: &Outcome,
) -> Vec<(String, String)> {
    let mut entries = vec![
        (
            MetaKey::CreatedAt.as_str().to_string(),
            created_at.to_string(),
        ),
        (MetaKey::QueryId.as_str().to_string(), query_id.to_string()),
        (
            MetaKey::Connection.as_str().to_string(),
            connection.to_string(),
        ),
        (MetaKey::Rows.as_str().to_string(), rows.to_string()),
        (
            MetaKey::TruncatedByMaxRows.as_str().to_string(),
            outcome.truncated.to_string(),
        ),
        (
            MetaKey::RowsReturned.as_str().to_string(),
            outcome.rows_returned.to_string(),
        ),
        (
            MetaKey::QueryDurationMs.as_str().to_string(),
            outcome.duration_ms.to_string(),
        ),
        (
            MetaKey::Status.as_str().to_string(),
            outcome.status.to_string(),
        ),
    ];
    if let Some(cap) = capped {
        entries.push((
            MetaKey::SpoolCapped.as_str().to_string(),
            cap.as_str().to_string(),
        ));
    }
    entries
}

/// What a finished spool says about itself.
///
/// [`Meta::scoping`] is the field that matters most and the one easiest to forget: see
/// [`crate::Scoping`].
#[derive(Debug, Clone, PartialEq, serde::Serialize)]
pub struct Meta {
    pub created_at: Option<String>,
    pub query_id: Option<Uuid>,
    pub connection: Option<String>,
    /// Rows the spool holds — what paging, sorting and export can reach.
    pub rows: u64,
    /// Rows the query returned. Larger than `rows` exactly when the spool's cap bound.
    pub rows_returned: u64,
    pub spool_capped: Option<String>,
    pub truncated_by_max_rows: bool,
    pub query_duration_ms: Option<i64>,
    pub status: Option<String>,
}

impl Meta {
    /// How much of the query's result these rows are — the thing every read carries so
    /// that no surface can report a sort as authoritative when it is not (§4.2).
    pub fn scoping(&self) -> crate::Scoping {
        crate::Scoping {
            spooled_rows: self.rows,
            rows_returned: self.rows_returned,
            spool_capped: self.spool_capped.clone(),
            truncated_by_max_rows: self.truncated_by_max_rows,
        }
    }
}
