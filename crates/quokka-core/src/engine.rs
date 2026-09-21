//! `quokka-core::execute()` — the one path to a database.
//!
//! Invariant 1: nothing reaches a database except through here. Every surface — CLI, UI,
//! MCP — calls this function, and [`ExecutePermit`] makes that a compile-time property
//! rather than a convention.
//!
//! The shape of the function follows from the audit rules rather than from taste.
//! `execute()` drives the row stream to completion itself and hands rows to a
//! [`RowSink`], instead of returning the stream to the caller, because
//! `query_finished` has to be written whatever happens to those rows — an error
//! mid-stream, a closed pipe, a cap reached. A caller holding the stream could simply
//! drop it, and the log would be missing the half that says how the query went.
//!
//! At M2 the sink is the spool; at M0 it is whatever the surface writes to.

use std::collections::HashMap;
use std::sync::Arc;
use std::time::{Duration, Instant};

use futures::StreamExt;
use quokka_audit::{
    ActorKind, AuditEvent, AuditLog, Client, EventKind, SqlLogging, Status, StoredEvent,
};
use uuid::Uuid;

use quokka_policy::{AccessMode, Denial, Outcome as PolicyOutcome, Policy, SqlSummary};

use crate::catalog::CatalogCache;
use crate::config::{dialect_hint, ConnectionConfig, Registry};
use crate::driver::{
    Catalog, Driver, DriverFactory, ExecutePermit, Plan, QueryHandle, QueryRequest, Scope,
};
use crate::error::{CoreError, DriverError};
use crate::redact::scrub;
use crate::sql::summarize;
use crate::value::{Column, Row, Value};

/// The CLI's default preview size (ARCHITECTURE §4.2). The UI grid and MCP tool
/// responses cap at this number and cannot be raised; a shell pipeline is not a context
/// window, so `--max-rows` may exceed it.
pub const DEFAULT_MAX_ROWS: u64 = 512;

/// Who ran the query.
#[derive(Debug, Clone)]
pub struct Actor {
    pub kind: ActorKind,
    pub id: String,
}

/// One request to run SQL against one connection.
#[derive(Debug, Clone)]
pub struct ExecuteRequest {
    pub connection: String,
    pub sql: String,
    pub params: Vec<Value>,
    pub actor: Actor,
    pub client: Client,
    /// Rows delivered to the sink before the result is marked truncated.
    ///
    /// A ceiling the connection sets (`max_rows` in its config) lowers this; nothing
    /// raises it. §6.3 wants the cap enforced here rather than by trusting a `LIMIT` in
    /// the text, and this is where "here" is.
    pub max_rows: u64,
    /// How long the statement may run before it is cancelled and logged as `timeout`.
    ///
    /// `--timeout` on the CLI. A connection's own `timeout` shortens it, and applies
    /// when the caller named none.
    pub timeout: Option<Duration>,
    /// The call-site opt-in a write needs on top of `mode = read_write` (§6.3).
    ///
    /// This never widens anything: the mode is the authorization and only a human can
    /// set it (invariant 7). What this adds is that the caller had to *mean* it, so a
    /// mis-generated statement cannot spend authority a human left in the lock.
    pub write: bool,
    /// A posture the surface was started with, which may narrow the connection's mode
    /// and can never widen it.
    ///
    /// `quokka mcp` without `--allow-writes` sets `ReadOnly` here, so an agent's
    /// `write: true` is confined to what *two* human decisions already allowed. Not an
    /// exemption from invariant 9: an exemption is a surface that gets more than the
    /// mode allows, and this can only take less.
    pub surface_mode: AccessMode,
    /// Links a re-run or an export back to the query it came from (§5).
    pub parent_id: Option<Uuid>,
    pub tags: Option<String>,
}

impl ExecuteRequest {
    pub fn new(connection: impl Into<String>, sql: impl Into<String>, actor: Actor) -> Self {
        Self {
            connection: connection.into(),
            sql: sql.into(),
            params: Vec::new(),
            actor,
            client: Client::Cli,
            max_rows: DEFAULT_MAX_ROWS,
            timeout: None,
            write: false,
            surface_mode: AccessMode::ReadWrite,
            parent_id: None,
            tags: None,
        }
    }
}

/// How a query went. Carries no result data — only its shape and its counts.
#[derive(Debug, Clone, serde::Serialize)]
pub struct Outcome {
    pub query_id: Uuid,
    pub connection: String,
    pub status: Status,
    pub columns: Vec<Column>,
    pub rows_returned: u64,
    pub rows_affected: Option<i64>,
    /// True when `max_rows` stopped the read before the result was exhausted. Never
    /// silent (§4.2): the sink is told, and so is the log.
    pub truncated: bool,
    /// Rows the sink kept for paging and export, when it is a spool (§4). `None` when
    /// the sink caches nothing — a formatter writing to stdout has nothing to page.
    pub rows_spooled: Option<u64>,
    /// Set when the *spool's* own cap stopped it keeping more (§4.2) — a different
    /// thing from `truncated`, which is the caller's `max_rows`.
    ///
    /// The two stay distinguishable in the log without a new column: at `max_rows`
    /// every row that came back was kept, so `rows_spooled = rows_returned`; at the
    /// spool's cap the rows went on reaching the caller while the cache stopped
    /// growing, so `rows_spooled < rows_returned`.
    pub spool_capped: Option<Cap>,
    pub duration_ms: i64,
    pub error_code: Option<String>,
    pub error_message: Option<String>,
}

impl Outcome {
    pub fn is_ok(&self) -> bool {
        matches!(self.status, Status::Ok)
    }

    /// True when what the user can reach is a prefix of what the query returned —
    /// whichever cap stopped it. This is the question a footer or a pager is asking.
    pub fn is_partial(&self) -> bool {
        self.truncated || self.spool_capped.is_some()
    }
}

/// Which of a caching sink's own limits stopped it (§4.2).
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize)]
#[serde(rename_all = "snake_case")]
pub enum Cap {
    Rows,
    Bytes,
}

impl Cap {
    pub fn as_str(self) -> &'static str {
        match self {
            Cap::Rows => "rows",
            Cap::Bytes => "bytes",
        }
    }
}

impl std::fmt::Display for Cap {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_str())
    }
}

/// What a caching sink kept, for the `rows_spooled` and `truncated` columns (§5).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Retained {
    pub rows: u64,
    /// `Some` when the sink's own limit, not the caller's `max_rows`, stopped it.
    pub capped: Option<Cap>,
}

/// Where `execute()` puts the rows it reads.
///
/// At M0 this is the CLI's formatter. At M2 the spool implements it, and every surface
/// reads from the spool instead.
///
/// `Send` is a supertrait so that `execute()` itself is `Send`, which a long-lived
/// server needs and a CLI never noticed: `&mut dyn RowSink` is only `Send` when the
/// trait object is, and without it M3's MCP request handlers could not call the one
/// execute path at all. No sink loses anything by it — a sink is somewhere to put a row.
pub trait RowSink: Send {
    /// Called once, before any row, with the result's shape.
    fn begin(&mut self, columns: &[Column]) -> std::io::Result<()>;
    /// Called once per row, in arrival order.
    fn row(&mut self, row: &Row) -> std::io::Result<()>;
    /// Called once, whatever the outcome — including after an error or a cancellation.
    fn end(&mut self, outcome: &Outcome) -> std::io::Result<()>;

    /// What this sink kept, if it is a cache the surface will read back.
    ///
    /// Asked *before* [`RowSink::end`], because the answer goes into the [`Outcome`]
    /// that `end` is then handed, and from there into `rows_spooled` and `truncated`
    /// (§5). The default is `None`: a formatter writing to stdout keeps nothing, and
    /// `rows_spooled` stays NULL rather than claiming a spool that does not exist.
    fn retained(&self) -> Option<Retained> {
        None
    }
}

/// A sink that discards rows. Useful for `EXPLAIN`-style callers and for tests that care
/// only about what the log recorded.
#[derive(Debug, Default)]
pub struct NullSink;

impl RowSink for NullSink {
    fn begin(&mut self, _columns: &[Column]) -> std::io::Result<()> {
        Ok(())
    }
    fn row(&mut self, _row: &Row) -> std::io::Result<()> {
        Ok(())
    }
    fn end(&mut self, _outcome: &Outcome) -> std::io::Result<()> {
        Ok(())
    }
}

/// Connections, drivers and the audit log, wired together.
pub struct Engine {
    registry: Registry,
    audit: AuditLog,
    factories: HashMap<String, Arc<dyn DriverFactory>>,
    /// Lazily opened, one per connection name, reused for the process's lifetime.
    drivers: tokio::sync::Mutex<HashMap<String, Arc<dyn Driver>>>,
    /// Queries currently executing, so `cancel()` can find the driver that owns one.
    inflight: std::sync::Mutex<HashMap<Uuid, Arc<dyn Driver>>>,
    /// Catalogs, per connection and scope, on a TTL (§3.1). A hit here is the one way
    /// this program answers a question about a database without touching it — and
    /// therefore the one way it answers without writing to the log (§5).
    catalogs: CatalogCache,
    session_id: String,
}

impl std::fmt::Debug for Engine {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Engine")
            .field("session_id", &self.session_id)
            .field("connections", &self.registry.names().collect::<Vec<_>>())
            .finish_non_exhaustive()
    }
}

impl Engine {
    pub fn new(
        registry: Registry,
        audit: AuditLog,
        factories: Vec<Arc<dyn DriverFactory>>,
    ) -> Self {
        Self {
            registry,
            audit,
            factories: factories
                .into_iter()
                .map(|f| (f.name().to_string(), f))
                .collect(),
            drivers: tokio::sync::Mutex::new(HashMap::new()),
            inflight: std::sync::Mutex::new(HashMap::new()),
            catalogs: CatalogCache::new(),
            session_id: Uuid::now_v7().to_string(),
        }
    }

    pub fn with_session_id(mut self, session_id: impl Into<String>) -> Self {
        self.session_id = session_id.into();
        self
    }

    pub fn registry(&self) -> &Registry {
        &self.registry
    }

    pub fn audit(&self) -> &AuditLog {
        &self.audit
    }

    pub fn session_id(&self) -> &str {
        &self.session_id
    }

    /// Ask the driver to stop an in-flight query. Costs nothing and runs no SQL, so it
    /// needs no [`ExecutePermit`].
    pub async fn cancel(&self, query_id: Uuid) -> Result<(), CoreError> {
        let driver = {
            let inflight = self.inflight.lock().expect("inflight map poisoned");
            inflight.get(&query_id).cloned()
        };
        match driver {
            Some(d) => Ok(d.cancel(QueryHandle(query_id)).await?),
            None => Err(CoreError::NotRunning(query_id)),
        }
    }

    /// Cancel every query this process currently has in flight.
    ///
    /// What a surface reaches for when the user hits Ctrl-C: the caller does not know
    /// the `query_id` it would otherwise need, and a cancelled query is still a fully
    /// logged one — `query_finished` records `status = 'cancelled'`.
    pub async fn cancel_all(&self) {
        let running: Vec<(Uuid, Arc<dyn Driver>)> = {
            let inflight = self.inflight.lock().expect("inflight map poisoned");
            inflight.iter().map(|(id, d)| (*id, d.clone())).collect()
        };
        for (id, driver) in running {
            let _ = driver.cancel(QueryHandle(id)).await;
        }
    }

    async fn driver_for(&self, cfg: &ConnectionConfig) -> Result<Arc<dyn Driver>, CoreError> {
        let mut open = self.drivers.lock().await;
        if let Some(d) = open.get(&cfg.name) {
            return Ok(d.clone());
        }
        let factory = self
            .factories
            .get(&cfg.driver)
            .ok_or_else(|| CoreError::UnknownDriver {
                connection: cfg.name.clone(),
                driver: cfg.driver.clone(),
            })?;
        let driver = factory.open(cfg).await?;
        open.insert(cfg.name.clone(), driver.clone());
        Ok(driver)
    }
}

/// Run `request` against a connection, streaming its rows into `sink`.
///
/// The two audit events (§5) bracket everything below: `query_started` is appended
/// before the driver is even opened, and `query_finished` after the last row, whatever
/// happened in between.
pub async fn execute(
    engine: &Engine,
    request: ExecuteRequest,
    sink: &mut dyn RowSink,
) -> Result<Outcome, CoreError> {
    let cfg = engine
        .registry
        .get(&request.connection)
        .cloned()
        .ok_or_else(|| CoreError::UnknownConnection(request.connection.clone()))?;

    let dialect = dialect_hint(&cfg.driver);
    let summary = summarize(&request.sql, dialect);
    let query_id = Uuid::now_v7();

    // §6.3's caps, applied here rather than by trusting a `LIMIT` in the text. The
    // connection's ceilings only ever lower what was asked for (invariant 7).
    let max_rows = cfg.limits.cap_rows(request.max_rows);
    let timeout = cfg.limits.cap_timeout(request.timeout);

    // The verdict is computed before `query_started` is written and acted on after, so
    // that a denial is recorded rather than merely returned. The `approved_by` column
    // needs the answer for the row it is about to write.
    let verdict = policy_for(&cfg, &request).decide(&summary);
    let approved_by = match &verdict {
        // Who turned the second key. The *authorization* is the connection's mode, which
        // only a human can set; this names the caller that opted in, which together with
        // `client` and `actor_id` is what a reviewer asking "who ran this write" wants.
        PolicyOutcome::Allow { writes: true } => Some(request.actor.id.clone()),
        _ => None,
    };

    // Scrubbing runs in every mode (§5); at `fingerprint` the text is dropped entirely
    // a line later, but the order matters if that default ever changes.
    let sql_text = match cfg.sql_logging {
        SqlLogging::Full => Some(scrub(&request.sql)),
        SqlLogging::Fingerprint => None,
    };
    let params = params_for_log(&request.params, cfg.sql_logging);

    let started = AuditEvent {
        id: Uuid::now_v7(),
        query_id,
        parent_id: request.parent_id,
        at: quokka_audit::now_rfc3339()?,
        duration_ms: None,
        actor_kind: request.actor.kind,
        actor_id: request.actor.id.clone(),
        session_id: engine.session_id.clone(),
        client: request.client,
        connection: cfg.name.clone(),
        dialect: dialect.as_str().to_string(),
        database: cfg.database.clone(),
        schema_name: cfg.schema.clone(),
        event_kind: EventKind::QueryStarted,
        sql_logging: cfg.sql_logging,
        sql_text,
        sql_fingerprint: summary.fingerprint.clone(),
        statement_kind: summary.statement_kind.clone(),
        read_only: summary.read_only,
        params,
        status: Status::Started,
        error_code: None,
        error_message: None,
        rows_returned: None,
        rows_affected: None,
        rows_spooled: None,
        truncated: None,
        export_format: None,
        export_path: None,
        data_scanned_bytes: None,
        cost_estimate_usd: None,
        approved_by: approved_by.clone(),
        tags: request.tags.clone(),
    };

    // Invariant 6: fail closed. Nothing below this line has touched a database, and
    // nothing will if the log would not have the record of it.
    engine
        .audit
        .append(started.clone())
        .await
        .map_err(|source| CoreError::AuditWriteFailed { source })?;

    // The guardrail, inside the one execute path (§6.3). It runs *after* the start is on
    // disk, so what an agent tried is recorded whether or not it was allowed, and
    // *before* the driver is opened, so a denied statement never reaches one — not even
    // as a connection attempt.
    if let Some(denial) = verdict.denial() {
        return Err(record_denial(engine, started, denial, query_id).await);
    }

    let started_at = Instant::now();
    let run = run_query(
        engine, &cfg, query_id, &request, &summary, max_rows, timeout, sink,
    )
    .await;
    let duration_ms = started_at.elapsed().as_millis().min(i64::MAX as u128) as i64;

    let (status, error_code, error_message, columns, rows_returned, rows_affected, truncated) =
        match run {
            Ok(done) => (
                Status::Ok,
                None,
                None,
                done.columns,
                done.rows_returned,
                done.rows_affected,
                done.truncated,
            ),
            Err(RunFailure {
                status,
                code,
                message,
                partial,
            }) => (
                status,
                Some(code),
                Some(message),
                partial.columns,
                partial.rows_returned,
                partial.rows_affected,
                partial.truncated,
            ),
        };

    // Asked before `end()`, because the answer belongs in the outcome that `end()` is
    // handed — and in the log below.
    let retained = sink.retained();

    let outcome = Outcome {
        query_id,
        connection: cfg.name.clone(),
        status,
        columns,
        rows_returned,
        rows_affected,
        truncated,
        rows_spooled: retained.map(|r| r.rows),
        spool_capped: retained.and_then(|r| r.capped),
        duration_ms,
        error_code,
        error_message,
    };

    // The sink is told how it went before the log is, so a surface can flush its last
    // bytes even if the finishing write is about to fail.
    let sink_end = sink.end(&outcome);

    let finished = AuditEvent {
        id: Uuid::now_v7(),
        query_id,
        parent_id: request.parent_id,
        at: quokka_audit::now_rfc3339()?,
        duration_ms: Some(outcome.duration_ms),
        actor_kind: request.actor.kind,
        actor_id: request.actor.id.clone(),
        session_id: engine.session_id.clone(),
        client: request.client,
        connection: cfg.name.clone(),
        dialect: dialect.as_str().to_string(),
        database: cfg.database.clone(),
        schema_name: cfg.schema.clone(),
        event_kind: EventKind::QueryFinished,
        sql_logging: cfg.sql_logging,
        // The text and the bound values live on the `query_started` row only. Repeating
        // them here would double the number of copies of a literal in the log for no
        // gain; `sql_fingerprint` is on both rows because the column is NOT NULL and
        // because grouping by shape must work without a join.
        sql_text: None,
        sql_fingerprint: summary.fingerprint.clone(),
        statement_kind: summary.statement_kind.clone(),
        read_only: summary.read_only,
        params: None,
        status: outcome.status,
        error_code: outcome.error_code.clone(),
        error_message: outcome.error_message.clone(),
        rows_returned: Some(outcome.rows_returned as i64),
        rows_affected: outcome.rows_affected,
        rows_spooled: outcome.rows_spooled.map(|n| n as i64),
        // Either cap makes what the user can reach a prefix of the result, so either
        // sets this column — §4.2 is explicit that hitting the spool cap marks the
        // result truncated. Which cap it was stays readable from the two row counts
        // beside it (see `Outcome::spool_capped`).
        truncated: Some(outcome.is_partial()),
        export_format: None,
        export_path: None,
        data_scanned_bytes: None,
        cost_estimate_usd: None,
        approved_by,
        tags: request.tags.clone(),
    };

    engine
        .audit
        .append(finished)
        .await
        .map_err(|source| CoreError::AuditFinishFailed { query_id, source })?;

    sink_end?;

    Ok(outcome)
}

/// [`execute()`], driven on a thread the runtime has been told is blocked.
///
/// **Why this exists at all.** [`RowSink`] is synchronous by design — `execute()` drives
/// the row stream itself and hands rows over one at a time — and the sink every
/// long-lived surface uses is the spool, which runs its SQLite connection on a thread of
/// its own and *blocks its caller* while a batch lands. That is harmless in a CLI, whose
/// whole job is this one query. It is not harmless behind an MCP request handler, where
/// a blocked worker is every other tool call waiting, and it is not harmless behind a
/// window, where it is every other task the UI has in flight.
///
/// `block_in_place` is the honest fix: it tells tokio that this worker is about to
/// block, so the runtime moves the other tasks off it, and `block_on` drives this
/// query's own I/O here. The alternative — making `RowSink` async — would push the seam
/// into `execute()` and into every surface for the sake of the callers that spool.
///
/// **On a current-thread runtime there is nothing to move work to**, so `block_in_place`
/// would panic and buy nothing; awaiting normally is then exactly the CLI's behaviour,
/// where the blocking was already fine. Both surfaces that need this run on a
/// multi-thread runtime: `quokka mcp` builds one, and `quokka ui` gets one from iced,
/// whose `tokio` feature makes its executor a `tokio::runtime::Runtime` — which is
/// multi-thread — and which runs every `Task` future as an ordinary tokio task on it.
pub async fn execute_blocking(
    engine: &Engine,
    request: ExecuteRequest,
    sink: &mut dyn RowSink,
) -> Result<Outcome, CoreError> {
    let future = execute(engine, request, sink);
    match tokio::runtime::Handle::try_current().map(|h| h.runtime_flavor()) {
        Ok(tokio::runtime::RuntimeFlavor::MultiThread) => {
            let handle = tokio::runtime::Handle::current();
            tokio::task::block_in_place(move || handle.block_on(future))
        }
        _ => future.await,
    }
}

/// One request for a statement's execution plan.
#[derive(Debug, Clone)]
pub struct ExplainRequest {
    pub connection: String,
    /// The statement to explain — *not* prefixed with `EXPLAIN`. The driver writes that
    /// part, which is what keeps `EXPLAIN ANALYZE` — the spelling that actually runs the
    /// statement — from being reachable from here at all.
    pub sql: String,
    pub actor: Actor,
    pub client: Client,
    pub timeout: Option<Duration>,
    pub surface_mode: AccessMode,
}

impl ExplainRequest {
    pub fn new(connection: impl Into<String>, sql: impl Into<String>, actor: Actor) -> Self {
        Self {
            connection: connection.into(),
            sql: sql.into(),
            actor,
            client: Client::Cli,
            timeout: None,
            surface_mode: AccessMode::ReadWrite,
        }
    }
}

/// A plan, and the query pair that recorded asking for it.
#[derive(Debug, Clone)]
pub struct ExplainOutcome {
    pub query_id: Uuid,
    pub connection: String,
    pub plan: Plan,
    pub duration_ms: i64,
}

/// Ask the engine for a statement's plan, on the audited path (§6.1, invariant 1).
///
/// `EXPLAIN` executes SQL, so this is a query like any other: the same policy check, the
/// same two events sharing a `query_id`, the same fail-closed rule. It is not
/// [`introspect()`]'s single-event shape, because the statement is the *caller's* — §5 is
/// explicit that the day a surface runs its own catalog query, it is a query pair.
///
/// **Explaining a write needs the same authorization as running one.** A plain `EXPLAIN`
/// does not execute the statement on any engine this build supports, so it is tempting to
/// let a read-only connection explain a `DELETE`: it is a safe and useful thing to want.
/// We do not, for the reason §3.0 gives for not claiming support we have not tested — the
/// relaxation would rest on a per-engine claim about whether `EXPLAIN` executes, made
/// once here and silently inherited by every driver added later. The mode binds every
/// statement identically instead, and the cost is a missing convenience rather than a
/// guarantee with an exception in it. A relaxation can be added later; the reverse cannot.
pub async fn explain(
    engine: &Engine,
    request: ExplainRequest,
) -> Result<ExplainOutcome, CoreError> {
    let cfg = engine
        .registry
        .get(&request.connection)
        .cloned()
        .ok_or_else(|| CoreError::UnknownConnection(request.connection.clone()))?;

    let dialect = dialect_hint(&cfg.driver);
    let summary = summarize(&request.sql, dialect);
    let query_id = Uuid::now_v7();
    let timeout = cfg.limits.cap_timeout(request.timeout);

    let policy = Policy {
        mode: cfg.mode,
        surface_mode: request.surface_mode,
        // Explaining is never a write, so there is nothing to opt into — and nothing an
        // opt-in could unlock, since the classification above is of the statement being
        // explained.
        write_requested: false,
        allow: &cfg.allow,
        default_schema: cfg.schema.as_deref(),
    };
    let verdict = policy.decide(&summary);

    let sql_text = match cfg.sql_logging {
        SqlLogging::Full => Some(scrub(&request.sql)),
        SqlLogging::Fingerprint => None,
    };

    let started = AuditEvent {
        id: Uuid::now_v7(),
        query_id,
        parent_id: None,
        at: quokka_audit::now_rfc3339()?,
        duration_ms: None,
        actor_kind: request.actor.kind,
        actor_id: request.actor.id.clone(),
        session_id: engine.session_id.clone(),
        client: request.client,
        connection: cfg.name.clone(),
        dialect: dialect.as_str().to_string(),
        database: cfg.database.clone(),
        schema_name: cfg.schema.clone(),
        event_kind: EventKind::QueryStarted,
        sql_logging: cfg.sql_logging,
        sql_text,
        // The fingerprint says what was sent, which is the explained statement's shape
        // with `EXPLAIN` in front of it. `statement_kind` says this was an explain, and
        // `read_only` keeps the *explained* statement's nature — so a review that asks
        // "did anyone look at how this delete would run" can answer it.
        sql_fingerprint: format!("EXPLAIN {}", summary.fingerprint),
        statement_kind: Some("explain".to_string()),
        read_only: summary.read_only,
        params: None,
        status: Status::Started,
        error_code: None,
        error_message: None,
        rows_returned: None,
        rows_affected: None,
        rows_spooled: None,
        truncated: None,
        export_format: None,
        export_path: None,
        data_scanned_bytes: None,
        cost_estimate_usd: None,
        approved_by: None,
        tags: None,
    };

    engine
        .audit
        .append(started.clone())
        .await
        .map_err(|source| CoreError::AuditWriteFailed { source })?;

    if let Some(denial) = verdict.denial() {
        return Err(record_denial(engine, started, denial, query_id).await);
    }

    let at = Instant::now();
    let run = run_explain(engine, &cfg, &request.sql, timeout).await;
    let duration_ms = at.elapsed().as_millis().min(i64::MAX as u128) as i64;

    let (status, error_code, error_message) = match &run {
        Ok(_) => (Status::Ok, None, None),
        Err(e) => (
            e.status,
            Some(e.code.clone()),
            Some(scrub(&e.message.clone())),
        ),
    };

    let finished = AuditEvent {
        id: Uuid::now_v7(),
        at: quokka_audit::now_rfc3339()?,
        duration_ms: Some(duration_ms),
        event_kind: EventKind::QueryFinished,
        sql_text: None,
        status,
        error_code,
        error_message,
        ..started
    };

    engine
        .audit
        .append(finished)
        .await
        .map_err(|source| CoreError::AuditFinishFailed { query_id, source })?;

    let plan = run.map_err(|e| e.into_core())?;
    Ok(ExplainOutcome {
        query_id,
        connection: cfg.name,
        plan,
        duration_ms,
    })
}

async fn run_explain(
    engine: &Engine,
    cfg: &ConnectionConfig,
    sql: &str,
    timeout: Option<Duration>,
) -> Result<Plan, RunFailure> {
    let deadline = timeout.map(|t| tokio::time::Instant::now() + t);
    let driver = engine
        .driver_for(cfg)
        .await
        .map_err(|e| RunFailure::from_core(e, Partial::default()))?;
    let permit = ExecutePermit::issue();
    match until(deadline, driver.explain(&permit, sql)).await {
        Some(result) => result.map_err(|e| RunFailure::from_driver(e, Partial::default())),
        None => Err(RunFailure::timed_out(timeout, Partial::default())),
    }
}

/// One request to refresh part of a connection's catalog.
#[derive(Debug, Clone)]
pub struct IntrospectRequest {
    pub connection: String,
    pub scope: Scope,
    pub actor: Actor,
    pub client: Client,
    /// Query the server even if the cached catalog is still within the TTL.
    ///
    /// §1.4 makes refreshing an explicit action; this is the flag a "Refresh catalog"
    /// button sets. It is never set by autocomplete.
    pub refresh: bool,
}

impl IntrospectRequest {
    pub fn new(connection: impl Into<String>, scope: Scope, actor: Actor) -> Self {
        Self {
            connection: connection.into(),
            scope,
            actor,
            client: Client::Cli,
            refresh: false,
        }
    }
}

/// A catalog, and the honest account of where it came from.
#[derive(Debug, Clone)]
pub struct CatalogResult {
    pub catalog: Catalog,
    /// `true` when nothing reached a database. Then `event_id` is `None`, because a hit
    /// appends no event at all (§5).
    pub from_cache: bool,
    /// The single `introspect` row this refresh appended — never a pair.
    pub event_id: Option<Uuid>,
    pub duration_ms: i64,
}

/// Refresh part of a catalog, on the audited path §5 specifies.
///
/// Three things about this differ from [`execute()`], and each is a decision in §5
/// rather than a shortcut:
///
/// 1. **One event, appended after the fact** — not a `query_started`/`query_finished`
///    pair. The statement is the driver's own and bounded, so there is no outcome to
///    hold open and no caller SQL to record having attempted.
/// 2. **Fail-closed does not apply.** There is no "before" event to fail. A failed
///    append is surfaced loudly instead, exactly as a failed `query_finished` is.
/// 3. **A cache hit appends nothing.** Nothing reached a database, so there is nothing
///    to describe. At a one-minute TTL this is the difference between a handful of rows
///    a day and thousands — and, more to the point, between a log that says what
///    happened and one that says what was asked.
///
/// This holds only while introspection cannot carry caller-supplied SQL. `Scope` is a
/// scope and never a statement; the day a surface wants to run its own catalog query,
/// that is a `query_started`/`query_finished` pair like any other, because it is one.
pub async fn introspect(
    engine: &Engine,
    request: IntrospectRequest,
) -> Result<CatalogResult, CoreError> {
    let cfg = engine
        .registry
        .get(&request.connection)
        .cloned()
        .ok_or_else(|| CoreError::UnknownConnection(request.connection.clone()))?;

    if !request.refresh {
        if let Some(catalog) = engine
            .catalogs
            .get(&cfg.name, &request.scope, cfg.catalog_ttl)
        {
            return Ok(CatalogResult {
                catalog,
                from_cache: true,
                event_id: None,
                duration_ms: 0,
            });
        }
    }

    let started_at = Instant::now();
    let outcome = refresh(engine, &cfg, &request.scope).await;
    let duration_ms = started_at.elapsed().as_millis().min(i64::MAX as u128) as i64;

    let (status, error_code, error_message, tables) = match &outcome {
        Ok(catalog) => (Status::Ok, None, None, Some(catalog.tables.len() as i64)),
        Err(e) => (
            Status::Error,
            Some(e.code().to_string()),
            Some(scrub(&e.to_string())),
            None,
        ),
    };

    let dialect = dialect_hint(&cfg.driver);
    let event_id = Uuid::now_v7();
    let event = AuditEvent {
        id: event_id,
        // Its own group of one. An introspect event is not part of a query's story, so
        // it does not borrow a query's id; `queries` joins on `query_started`, so this
        // row stays out of that view by construction.
        query_id: Uuid::now_v7(),
        parent_id: None,
        at: quokka_audit::now_rfc3339()?,
        duration_ms: Some(duration_ms),
        actor_kind: request.actor.kind,
        actor_id: request.actor.id.clone(),
        session_id: engine.session_id.clone(),
        client: request.client,
        connection: cfg.name.clone(),
        dialect: dialect.as_str().to_string(),
        database: request
            .scope
            .database
            .clone()
            .or_else(|| cfg.database.clone()),
        schema_name: request.scope.schema.clone().or_else(|| cfg.schema.clone()),
        event_kind: EventKind::Introspect,
        sql_logging: cfg.sql_logging,
        // Deliberately empty even at `full`: the SQL that ran is the driver's, not the
        // caller's, and it is the same text on every refresh. What review needs from
        // this row is the scope, which is below.
        sql_text: None,
        sql_fingerprint: scope_fingerprint(&request.scope),
        statement_kind: Some("introspect".to_string()),
        read_only: Some(true),
        params: None,
        status,
        error_code,
        error_message,
        // How many catalog objects came back. A count, not content: invariant 4 forbids
        // rows, samples and digests of rows, and this is the same kind of number
        // `rows_returned` already holds for a query. It is the difference between a
        // refresh that found four hundred tables and one that found none.
        rows_returned: tables,
        rows_affected: None,
        rows_spooled: None,
        truncated: None,
        export_format: None,
        export_path: None,
        data_scanned_bytes: None,
        cost_estimate_usd: None,
        approved_by: None,
        tags: None,
    };

    engine
        .audit
        .append(event)
        .await
        .map_err(|source| CoreError::IntrospectNotRecorded { source })?;

    let catalog = outcome?;
    // Cached only once the event is on disk. If the append failed we returned above with
    // the catalog dropped, so the next attempt queries again and tries to log again —
    // rather than serving a refresh the log never heard about.
    engine
        .catalogs
        .put(&cfg.name, &request.scope, catalog.clone());

    Ok(CatalogResult {
        catalog,
        from_cache: false,
        event_id: Some(event_id),
        duration_ms,
    })
}

async fn refresh(
    engine: &Engine,
    cfg: &ConnectionConfig,
    scope: &Scope,
) -> Result<Catalog, DriverError> {
    let driver = engine.driver_for(cfg).await.map_err(|e| match e {
        CoreError::Driver(d) => d,
        other => DriverError::Connect {
            connection: cfg.name.clone(),
            detail: other.to_string(),
        },
    })?;
    let permit = ExecutePermit::issue();
    driver.introspect(&permit, scope.clone()).await
}

/// What the `sql_fingerprint` column holds for an `introspect` row.
///
/// The column is `NOT NULL` and exists to say *what* was touched, so a scope descriptor
/// is the honest value: there is no caller statement to normalize. Identifiers survive
/// normalization everywhere else in the log (§5.1, rule 2), so naming the table here is
/// consistent rather than an exception.
fn scope_fingerprint(scope: &Scope) -> String {
    let parts: Vec<&str> = [
        scope.database.as_deref(),
        scope.schema.as_deref(),
        scope.table.as_deref(),
    ]
    .into_iter()
    .flatten()
    .collect();

    if parts.is_empty() {
        "INTROSPECT *".to_string()
    } else {
        format!("INTROSPECT {}", parts.join("."))
    }
}

/// How far a run got before it stopped.
#[derive(Debug, Default)]
struct Partial {
    columns: Vec<Column>,
    rows_returned: u64,
    rows_affected: Option<i64>,
    truncated: bool,
}

struct RunFailure {
    status: Status,
    code: String,
    message: String,
    partial: Partial,
}

impl RunFailure {
    /// The error a caller sees when there is no [`Outcome`] to hand back — the explain
    /// path, where the result is a plan rather than a stream of rows.
    fn into_core(self) -> CoreError {
        CoreError::Driver(match self.status {
            Status::Cancelled => DriverError::Cancelled,
            _ => DriverError::Execute {
                detail: self.message,
            },
        })
    }
}

#[allow(clippy::too_many_arguments)]
async fn run_query(
    engine: &Engine,
    cfg: &ConnectionConfig,
    query_id: Uuid,
    request: &ExecuteRequest,
    summary: &SqlSummary,
    max_rows: u64,
    timeout: Option<Duration>,
    sink: &mut dyn RowSink,
) -> Result<Partial, RunFailure> {
    // A deadline rather than a timer per step: the budget is for the statement, not for
    // each row, so a query that trickles a row a second does not get to run forever.
    //
    // Started before the connection is opened, because the caller asked how long this
    // call may take. Opening is not itself raced against it — an unreachable host is
    // `connect_timeout`'s business, which is a different setting answering a different
    // question — but the time it takes is spent out of this budget.
    let deadline = timeout.map(|t| tokio::time::Instant::now() + t);

    let driver = engine
        .driver_for(cfg)
        .await
        .map_err(|e| RunFailure::from_core(e, Partial::default()))?;

    let permit = ExecutePermit::issue();
    let query_request = QueryRequest {
        handle: QueryHandle(query_id),
        sql: request.sql.clone(),
        params: request.params.clone(),
    };

    {
        let mut inflight = engine.inflight.lock().expect("inflight map poisoned");
        inflight.insert(query_id, driver.clone());
    }
    let _guard = InflightGuard { engine, query_id };

    let mut stream = match until(deadline, driver.execute(&permit, query_request)).await {
        Some(result) => result.map_err(|e| RunFailure::from_driver(e, Partial::default()))?,
        None => {
            // Nothing has streamed yet, but the statement may well be running on the
            // server, so the driver is asked to stop it before we walk away.
            let _ = driver.cancel(QueryHandle(query_id)).await;
            return Err(RunFailure::timed_out(timeout, Partial::default()));
        }
    };

    let mut partial = Partial {
        columns: stream.columns.clone(),
        ..Partial::default()
    };

    if let Err(e) = sink.begin(&stream.columns) {
        return Err(RunFailure::from_sink(e, partial));
    }

    loop {
        let Some(next) = until(deadline, stream.rows.next()).await else {
            // The rows already in the sink stay there and are reported: a timeout is a
            // partial result, and `truncated` says the caller is holding a prefix.
            let _ = driver.cancel(QueryHandle(query_id)).await;
            partial.truncated = true;
            return Err(RunFailure::timed_out(timeout, partial));
        };
        let Some(item) = next else { break };
        match item {
            Ok(row) => {
                if partial.rows_returned >= max_rows {
                    // One row past the cap is how truncation becomes known. It costs a
                    // row, never a second execution (§1.4).
                    partial.truncated = true;
                    break;
                }
                if let Err(e) = sink.row(&row) {
                    return Err(RunFailure::from_sink(e, partial));
                }
                partial.rows_returned += 1;
            }
            Err(e) => return Err(RunFailure::from_driver(e, partial)),
        }
    }

    // Dropping the stream releases the driver's statement; anything the driver learned
    // while draining (rows affected, bytes scanned) is read back here.
    drop(stream.rows);
    // SQLite reports a change count for every statement, including a `SELECT`, where it
    // is a leftover from whatever last modified the database. Reporting it would be
    // worse than reporting nothing, so a statement the classifier calls a certain read
    // has no rows-affected count at all.
    if summary.read_only != Some(true) {
        partial.rows_affected = stream.meta.snapshot().rows_affected;
    }
    Ok(partial)
}

/// Await `future`, giving up at `deadline`. `None` means the deadline arrived first.
///
/// `None` rather than an error type because the caller has different things to say
/// depending on how far it had got, and a deadline is not a failure of the future.
async fn until<F: std::future::Future>(
    deadline: Option<tokio::time::Instant>,
    future: F,
) -> Option<F::Output> {
    match deadline {
        Some(at) => tokio::time::timeout_at(at, future).await.ok(),
        None => Some(future.await),
    }
}

/// The rules this connection and this call site put on the statement (§6.3).
///
/// Assembled here, inside `execute()`, rather than passed in by a surface — a guardrail
/// a surface could assemble differently is one that binds the surfaces differently, and
/// invariant 9 says it binds them identically.
fn policy_for<'a>(cfg: &'a ConnectionConfig, request: &'a ExecuteRequest) -> Policy<'a> {
    Policy {
        // Both, unmixed: `Policy` narrows them itself, and keeping them apart is what
        // lets a denial name whichever one said no.
        mode: cfg.mode,
        surface_mode: request.surface_mode,
        write_requested: request.write,
        allow: &cfg.allow,
        default_schema: cfg.schema.as_deref(),
    }
}

/// Append the `query_finished` row for a denial, then report it.
///
/// **A denial is two events like any other query**, sharing one `query_id` (invariant 5).
/// It would have been tempting to give it a shape of its own — one row, since nothing
/// ran — but the `queries` view joins a start to a finish and reports `unfinished` when
/// the finish is missing, so a lone row would make the view claim a query had been killed
/// mid-flight. A start plus a finish with `status = 'denied'` is the shape that already
/// exists and the one the view reads correctly.
///
/// **And the SQL is logged at the connection's fidelity, not at a denial's.** §6.3 says a
/// denial is audited "with the SQL that triggered it", and the SQL is on the
/// `query_started` row this function is handed — at `fingerprint`, that is the shape with
/// its literals replaced, exactly as for a query that ran. Special-casing `denied` into
/// storing full text would mean anyone who can get a statement refused on purpose can
/// write literals into the log of a connection whose owner asked for none: an
/// exfiltration channel *into* the audit trail, opened by the feature meant to close one.
/// Invariant 8 does not lift because the news is bad.
async fn record_denial(
    engine: &Engine,
    started: AuditEvent,
    denial: &Denial,
    query_id: Uuid,
) -> CoreError {
    let connection = started.connection.clone();
    let message = denial.explain(&connection);

    let at = match quokka_audit::now_rfc3339() {
        Ok(at) => at,
        Err(source) => return CoreError::AuditFinishFailed { query_id, source },
    };

    let finished = AuditEvent {
        id: Uuid::now_v7(),
        at,
        // Nothing ran, so there is nothing to have taken time. Zero rather than NULL:
        // the column means "how long this query took", and the answer is none of it.
        duration_ms: Some(0),
        event_kind: EventKind::QueryFinished,
        // The text and the bound values live on the `query_started` row alone, exactly
        // as for a query that ran.
        sql_text: None,
        params: None,
        status: Status::Denied,
        error_code: Some(denial.code().to_string()),
        // Scrubbed like every other message that reaches the log, though none of these
        // carries user text: a denial names the rule, the statement kind and at most an
        // identifier — never the statement.
        error_message: Some(scrub(&message)),
        rows_returned: None,
        rows_affected: None,
        rows_spooled: None,
        truncated: None,
        // Whatever was asked for, nothing was authorized.
        approved_by: None,
        ..started
    };

    if let Err(source) = engine.audit.append(finished).await {
        // The louder problem wins. The query did not run either way, and the caller
        // learns that from the error; what it must not do is carry on believing the log
        // is complete.
        return CoreError::AuditFinishFailed { query_id, source };
    }

    CoreError::Denied {
        connection,
        query_id,
        code: denial.code(),
        message,
    }
}

struct InflightGuard<'a> {
    engine: &'a Engine,
    query_id: Uuid,
}

impl Drop for InflightGuard<'_> {
    fn drop(&mut self) {
        if let Ok(mut inflight) = self.engine.inflight.lock() {
            inflight.remove(&self.query_id);
        }
    }
}

impl RunFailure {
    // Every message below is scrubbed on the way in. §5 puts secret scrubbing before
    // *every* write, and an error is a write: a driver's failure text can carry whatever
    // was in the statement, and a connection error from a wire-protocol driver can carry
    // a DSN. Scrubbing here rather than at the audit event covers the terminal too,
    // which is the other place a password must not appear.
    fn from_driver(e: DriverError, partial: Partial) -> Self {
        let status = match e {
            DriverError::Cancelled => Status::Cancelled,
            _ => Status::Error,
        };
        RunFailure {
            status,
            code: e.code().to_string(),
            message: scrub(&e.to_string()),
            partial,
        }
    }

    /// The statement outran its budget. §6.3's other server-side cap, and its own status
    /// in the log rather than a generic error, because "this took too long" and "this
    /// failed" are different things to a reviewer and to a script.
    fn timed_out(timeout: Option<Duration>, partial: Partial) -> Self {
        let budget = timeout
            .map(|t| format!("{:?}", t))
            .unwrap_or_else(|| "its budget".to_string());
        RunFailure {
            status: Status::Timeout,
            code: "policy.timeout".to_string(),
            message: format!(
                "the statement ran longer than {budget} and was cancelled. The budget is \
                 the connection's `timeout` or this call's, whichever is shorter."
            ),
            partial,
        }
    }

    fn from_sink(e: std::io::Error, partial: Partial) -> Self {
        RunFailure {
            status: Status::Error,
            code: "sink.io".to_string(),
            message: scrub(&e.to_string()),
            partial,
        }
    }

    fn from_core(e: CoreError, partial: Partial) -> Self {
        let code = match &e {
            CoreError::Driver(d) => d.code().to_string(),
            CoreError::UnknownDriver { .. } => "core.unknown_driver".to_string(),
            _ => "core.error".to_string(),
        };
        RunFailure {
            status: Status::Error,
            code,
            message: scrub(&e.to_string()),
            partial,
        }
    }
}

/// Bound values are literals that took a different road, so they follow `sql_logging`
/// exactly as the query text does (§5.1, rule 1).
fn params_for_log(params: &[Value], mode: SqlLogging) -> Option<String> {
    if params.is_empty() {
        return None;
    }
    match mode {
        SqlLogging::Full => serde_json::to_string(params).ok().map(|json| scrub(&json)),
        // The count still says something useful; the values do not survive.
        SqlLogging::Fingerprint => Some(
            serde_json::to_string(&vec!["?"; params.len()]).unwrap_or_else(|_| "[]".to_string()),
        ),
    }
}

/// Every event recorded for one query, in order. `quokka audit` and the tests both read
/// the log through this rather than reaching for SQL.
pub async fn events_for_query(
    engine: &Engine,
    query_id: Uuid,
) -> Result<Vec<StoredEvent>, CoreError> {
    Ok(engine.audit.events_for_query(query_id).await?)
}
