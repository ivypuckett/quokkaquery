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
use std::time::Instant;

use futures::StreamExt;
use quokka_audit::{
    ActorKind, AuditEvent, AuditLog, Client, EventKind, SqlLogging, Status, StoredEvent,
};
use uuid::Uuid;

use crate::catalog::CatalogCache;
use crate::config::{dialect_hint, ConnectionConfig, Registry};
use crate::driver::{
    Catalog, Driver, DriverFactory, ExecutePermit, QueryHandle, QueryRequest, Scope,
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
    pub max_rows: u64,
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
    /// True when the cap stopped the read before the result was exhausted. Never silent
    /// (§4.2): the sink is told, and so is the log.
    pub truncated: bool,
    pub duration_ms: i64,
    pub error_code: Option<String>,
    pub error_message: Option<String>,
}

impl Outcome {
    pub fn is_ok(&self) -> bool {
        matches!(self.status, Status::Ok)
    }
}

/// Where `execute()` puts the rows it reads.
///
/// At M0 this is the CLI's formatter. At M2 the spool implements it, and every surface
/// reads from the spool instead.
pub trait RowSink {
    /// Called once, before any row, with the result's shape.
    fn begin(&mut self, columns: &[Column]) -> std::io::Result<()>;
    /// Called once per row, in arrival order.
    fn row(&mut self, row: &Row) -> std::io::Result<()>;
    /// Called once, whatever the outcome — including after an error or a cancellation.
    fn end(&mut self, outcome: &Outcome) -> std::io::Result<()>;
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
        approved_by: None,
        tags: request.tags.clone(),
    };

    // Invariant 6: fail closed. Nothing below this line has touched a database, and
    // nothing will if the log would not have the record of it.
    engine
        .audit
        .append(started)
        .await
        .map_err(|source| CoreError::AuditWriteFailed { source })?;

    let started_at = Instant::now();
    let run = run_query(engine, &cfg, query_id, &request, &summary, sink).await;
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

    let outcome = Outcome {
        query_id,
        connection: cfg.name.clone(),
        status,
        columns,
        rows_returned,
        rows_affected,
        truncated,
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
        // The spool lands at M2; until then nothing is spooled and the column says so.
        rows_spooled: None,
        truncated: Some(outcome.truncated),
        export_format: None,
        export_path: None,
        data_scanned_bytes: None,
        cost_estimate_usd: None,
        approved_by: None,
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

async fn run_query(
    engine: &Engine,
    cfg: &ConnectionConfig,
    query_id: Uuid,
    request: &ExecuteRequest,
    summary: &crate::sql::SqlSummary,
    sink: &mut dyn RowSink,
) -> Result<Partial, RunFailure> {
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

    let mut stream = driver
        .execute(&permit, query_request)
        .await
        .map_err(|e| RunFailure::from_driver(e, Partial::default()))?;

    let mut partial = Partial {
        columns: stream.columns.clone(),
        ..Partial::default()
    };

    if let Err(e) = sink.begin(&stream.columns) {
        return Err(RunFailure::from_sink(e, partial));
    }

    while let Some(item) = stream.rows.next().await {
        match item {
            Ok(row) => {
                if partial.rows_returned >= request.max_rows {
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
