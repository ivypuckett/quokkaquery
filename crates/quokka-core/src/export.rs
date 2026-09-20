//! The `export` audit event (ARCHITECTURE §5).
//!
//! **An export is logged even though it touches no database.** That looks like the
//! opposite of the rule one page earlier in §5 — a catalog cache hit appends nothing —
//! and it is, for a reason worth stating plainly rather than leaving to be rediscovered:
//!
//! - A cache hit logs nothing because *nothing was read*. There is no event: the program
//!   answered a question from memory. Recording it would fill the log with what was
//!   asked rather than what happened.
//! - An export logs because the thing being recorded is **"someone wrote ten million
//!   rows to a file"**, which is precisely what an audit trail exists to catch. That the
//!   rows came from a local spool rather than from the server makes no difference to the
//!   review that matters: data left the tool.
//!
//! Getting these the wrong way round would produce a log that is noisy about questions
//! and silent about exfiltration.
//!
//! Three further rules, each inherited from a decision already made in §5:
//!
//! 1. **One event, after the fact.** Like `introspect`, and unlike a query, there is no
//!    outcome to hold open: the count that makes the event worth reading — how many rows
//!    reached the file — exists only once the writing is done. So fail-closed does not
//!    apply here either (there is no "before" event to fail), and a failed append is
//!    surfaced loudly rather than swallowed, because the file is already on disk.
//! 2. **Linked by `parent_id`.** The event points at the `query_id` whose rows these
//!    were, which is how a reviewer gets from "this file exists" to "this is the query
//!    that filled it".
//! 3. **No result data, still.** Invariant 4 does not soften for exports: the row count,
//!    the format and the path, never a value from the file.

use uuid::Uuid;

use crate::config::dialect_hint;
use crate::engine::{Actor, Engine};
use crate::error::CoreError;
use crate::redact::scrub;
use quokka_audit::{AuditEvent, Client, EventKind, Status};

/// What one export did, as the log records it.
#[derive(Debug, Clone)]
pub struct ExportRecord {
    /// The connection the exported rows came from, so the event sits beside that
    /// connection's queries.
    pub connection: String,
    /// The query whose rows these are. Becomes `parent_id`.
    pub parent_query_id: Uuid,
    /// That query's fingerprint, repeated here so "which query's rows left the
    /// building" is answerable without a join. Never the SQL text: the text lives on
    /// the `query_started` row alone, and copying it would only multiply the copies of
    /// a literal in the log.
    pub sql_fingerprint: String,
    pub actor: Actor,
    pub client: Client,
    pub format: String,
    /// Where the bytes went. Scrubbed on the way in: a path is not a credential, but
    /// `s3://user:pass@…` is.
    pub path: String,
    pub rows: u64,
    /// True when the exported rows were a prefix of the query's result — a capped
    /// spool, or a capped read.
    pub truncated: bool,
    pub duration_ms: i64,
    pub status: Status,
    pub error_code: Option<String>,
    pub error_message: Option<String>,
    pub tags: Option<String>,
}

/// Append the one `export` event for a finished export.
///
/// Returns the event's id. A failure here means the file exists and the log does not
/// say so, which is worth shouting about — the caller surfaces it rather than treating
/// the export as successful.
pub async fn record_export(engine: &Engine, record: ExportRecord) -> Result<Uuid, CoreError> {
    let cfg = engine
        .registry()
        .get(&record.connection)
        .cloned()
        .ok_or_else(|| CoreError::UnknownConnection(record.connection.clone()))?;

    let id = Uuid::now_v7();
    let event = AuditEvent {
        id,
        // Its own group of one, exactly as an `introspect` event is: the export is not
        // one of the two events of a query, and the `queries` view joins on those. The
        // link to the query lives in `parent_id`, which is where §5 puts it.
        query_id: Uuid::now_v7(),
        parent_id: Some(record.parent_query_id),
        at: quokka_audit::now_rfc3339()?,
        duration_ms: Some(record.duration_ms),
        actor_kind: record.actor.kind,
        actor_id: record.actor.id.clone(),
        session_id: engine.session_id().to_string(),
        client: record.client,
        connection: cfg.name.clone(),
        dialect: dialect_hint(&cfg.driver).as_str().to_string(),
        database: cfg.database.clone(),
        schema_name: cfg.schema.clone(),
        event_kind: EventKind::Export,
        sql_logging: cfg.sql_logging,
        sql_text: None,
        sql_fingerprint: record.sql_fingerprint.clone(),
        statement_kind: Some("export".to_string()),
        read_only: Some(true),
        params: None,
        status: record.status,
        error_code: record.error_code.clone(),
        error_message: record.error_message.as_deref().map(scrub),
        // Rows that reached the file. A count, never a row (invariant 4).
        rows_returned: Some(record.rows as i64),
        rows_affected: None,
        rows_spooled: None,
        truncated: Some(record.truncated),
        export_format: Some(record.format.clone()),
        export_path: Some(scrub(&record.path)),
        data_scanned_bytes: None,
        cost_estimate_usd: None,
        approved_by: None,
        tags: record.tags.clone(),
    };

    engine
        .audit()
        .append(event)
        .await
        .map_err(|source| CoreError::ExportNotRecorded { source })?;

    Ok(id)
}
