//! The seven tools of ARCHITECTURE §6.2, and the state they share.

use std::sync::Arc;
use std::time::Duration;

use quokka_audit::Client;
use quokka_core::{
    execute, explain as core_explain, introspect, record_export, summarize, AccessMode, Actor,
    Engine, ExecuteRequest, ExplainRequest, ExportRecord, IntrospectRequest, Outcome, Scope,
};
use quokka_spool::{
    Destination, Format as ExportFormat, Position, Spool, SpoolSet, View, MAX_PAGE_ROWS,
};
use rmcp::handler::server::wrapper::{Json, Parameters};
use rmcp::model::{ServerCapabilities, ServerConfig};
use rmcp::{tool, tool_handler, tool_router, ErrorData as McpError, ServerHandler};
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::params::{direction_name, value_from_json, view_for, FilterSpec, SortSpec};
use crate::state::{release, Held, Results, MAX_HELD_RESULTS};

/// How many rows an MCP `query` reads from the database when nothing says otherwise.
///
/// Distinct from [`MAX_PAGE_ROWS`], which is the hard cap on a *response* (§4.2) and is
/// not configurable at all. This is how much gets spooled, and it has to be larger than
/// one page or there would be nothing to page through. Ten thousand is a default rather
/// than a guardrail — the guardrails are the connection's own `max_rows` and the spool's
/// cap, both human-only — and an agent may raise it up to those, exactly as `--max-rows`
/// may exceed 512 on the CLI. What it is chosen for is the other half of §1.4: an
/// exploratory question should not quietly scan a table.
pub const DEFAULT_FETCH_ROWS: u64 = 10_000;

/// The MCP server: one engine, one spool set, one posture.
#[derive(Clone)]
pub struct QuokkaMcp {
    engine: Arc<Engine>,
    spools: Arc<SpoolSet>,
    actor: Actor,
    /// The posture this process was started with.
    ///
    /// `ReadOnly` unless `quokka mcp --allow-writes`, and that flag lives in the MCP
    /// client's configuration file — which a human writes. It **narrows** a connection's
    /// mode and can never widen it, so it is not the per-surface exemption invariant 9
    /// forbids: an exemption is a surface that gets more than the mode allows.
    ///
    /// This is also the answer to "what stops `write: true` being theatre". The flag an
    /// agent passes is the third key, and the two that matter are both held by a human:
    /// `mode = "read_write"` in the config file, and this posture at launch. An agent
    /// that asks itself for permission is confined to what those two already allowed.
    surface_mode: AccessMode,
    results: Results,
    /// Built once and held, rather than rebuilt per call — `#[tool_handler]` would
    /// default to `Self::tool_router()`, which assembles seven routes on every request.
    tool_router: rmcp::handler::server::tool::ToolRouter<Self>,
}

#[tool_router(vis = "pub")]
impl QuokkaMcp {
    pub fn new(
        engine: Arc<Engine>,
        spools: Arc<SpoolSet>,
        actor: Actor,
        surface_mode: AccessMode,
    ) -> Self {
        Self {
            engine,
            spools,
            actor,
            surface_mode,
            results: Results::new(),
            tool_router: Self::tool_router(),
        }
    }

    /// Every connection this build can reach, with the mode that governs it.
    ///
    /// **One registry, shared with the CLI.** The alternative — a separate view an agent
    /// is allowed to see — was rejected: a connection an agent cannot see is a connection
    /// it cannot reach, so hiding one would be a second guardrail competing with the real
    /// one, and a much weaker one. The name leaks through an error message the first time
    /// anything mentions it, and a hidden-but-reachable connection is worse than a
    /// visible read-only one. Visibility is documentation; the mode is the guardrail.
    #[tool(
        name = "list_connections",
        description = "List the configured database connections, with the dialect, access \
                       mode and SQL-logging setting that govern each. Read this before \
                       querying: `effective_mode` is what actually applies to you."
    )]
    pub async fn list_connections(&self) -> Json<ConnectionsResponse> {
        let connections = self
            .engine
            .registry()
            .iter()
            .map(|cfg| ConnectionInfo {
                name: cfg.name.clone(),
                driver: cfg.driver.clone(),
                dialect: cfg.dialect().as_str().to_string(),
                database: cfg.database.clone(),
                schema: cfg.schema.clone(),
                target: cfg.target(),
                mode: cfg.mode.as_str().to_string(),
                effective_mode: cfg.mode.narrowest(self.surface_mode).as_str().to_string(),
                sql_logging: cfg.sql_logging.as_str().to_string(),
                allowlisted: !cfg.allow.is_empty(),
                max_rows: cfg.limits.max_rows,
                timeout_ms: cfg.limits.timeout.map(|t| t.as_millis() as u64),
                builtin: cfg.builtin,
            })
            .collect();

        Json(ConnectionsResponse {
            connections,
            server_mode: self.surface_mode.as_str().to_string(),
            note: match self.surface_mode {
                AccessMode::ReadOnly => Some(
                    "This MCP server was started read-only, so every connection is \
                     read-only here whatever its own mode says. Only a human restarting \
                     it with --allow-writes changes that."
                        .to_string(),
                ),
                AccessMode::ReadWrite => None,
            },
        })
    }

    /// The catalog, grouped by namespace.
    #[tool(
        name = "list_schemas",
        description = "List the schemas (or databases) a connection can see, and the \
                       tables and views in each. Reads a cached catalog; pass refresh to \
                       query the server again."
    )]
    pub async fn list_schemas(
        &self,
        Parameters(args): Parameters<ListSchemasArgs>,
    ) -> Result<Json<SchemasResponse>, McpError> {
        let scope = Scope {
            database: args.database.clone(),
            schema: args.schema.clone(),
            table: None,
        };
        let result = self.catalog(&args.connection, scope, args.refresh).await?;

        let mut namespaces: Vec<SchemaInfo> = Vec::new();
        for table in &result.catalog.tables {
            let name = table.schema.clone().or_else(|| table.database.clone());
            let entry = match namespaces.iter_mut().find(|n| n.schema == name) {
                Some(existing) => existing,
                None => {
                    namespaces.push(SchemaInfo {
                        schema: name,
                        tables: Vec::new(),
                    });
                    namespaces.last_mut().expect("just pushed")
                }
            };
            entry.tables.push(TableSummary {
                name: table.name.clone(),
                kind: table.kind.clone(),
                columns: table.columns.len(),
            });
        }

        Ok(Json(SchemasResponse {
            connection: args.connection,
            schemas: namespaces,
            from_cache: result.from_cache,
        }))
    }

    /// One table's columns.
    #[tool(
        name = "describe_table",
        description = "Describe one table or view: its columns, their driver type names \
                       and whether each is nullable."
    )]
    pub async fn describe_table(
        &self,
        Parameters(args): Parameters<DescribeTableArgs>,
    ) -> Result<Json<DescribeTableResponse>, McpError> {
        let scope = Scope {
            database: args.database.clone(),
            schema: args.schema.clone(),
            table: Some(args.table.clone()),
        };
        let result = self.catalog(&args.connection, scope, args.refresh).await?;

        let tables = result
            .catalog
            .tables
            .iter()
            .map(|t| TableDetail {
                schema: t.schema.clone().or_else(|| t.database.clone()),
                name: t.name.clone(),
                kind: t.kind.clone(),
                columns: t
                    .columns
                    .iter()
                    .map(|c| ColumnInfo {
                        name: c.name.clone(),
                        driver_type: c.driver_type.clone(),
                        nullable: c.nullable,
                    })
                    .collect(),
            })
            .collect::<Vec<_>>();

        if tables.is_empty() {
            return Err(McpError::invalid_params(
                format!(
                    "connection {:?} has no table called {:?}. `list_schemas` names the \
                     ones it does have.",
                    args.connection, args.table
                ),
                None,
            ));
        }

        Ok(Json(DescribeTableResponse {
            connection: args.connection,
            tables,
            from_cache: result.from_cache,
        }))
    }

    /// Run SQL, or read another page of something already run.
    #[tool(
        name = "query",
        description = "Run one SQL statement and return the first page of its result, or \
                       page/sort/filter a result an earlier call already produced. Pass \
                       `sql` and `connection` to run; pass `query_id` (and `cursor`) to \
                       read more of a result without running anything again. At most 512 \
                       rows come back per call; `scope_note` says when those rows are a \
                       prefix rather than the whole result. Writes need `write: true` AND \
                       a connection a human set to read_write."
    )]
    pub async fn query(
        &self,
        Parameters(args): Parameters<QueryArgs>,
    ) -> Result<Json<QueryResponse>, McpError> {
        match (&args.sql, &args.query_id) {
            (Some(_), Some(_)) => Err(McpError::invalid_params(
                "pass `sql` to run a statement or `query_id` to read more of a result \
                 already run, not both — running the same statement again would cost a \
                 second scan, which this tool never does implicitly."
                    .to_string(),
                None,
            )),
            (Some(sql), None) => self.run_new(&args, sql).await,
            (None, Some(id)) => self.read_again(&args, id).await,
            (None, None) => Err(McpError::invalid_params(
                "a query needs either `sql` (with `connection`) or a `query_id` from an \
                 earlier call."
                    .to_string(),
                None,
            )),
        }
    }

    /// A statement's plan, without running it.
    #[tool(
        name = "explain",
        description = "Show the engine's execution plan for one statement. The statement \
                       is not run. Explaining a write needs the same access as running \
                       one, because whether EXPLAIN executes is an engine-by-engine \
                       claim this tool does not make."
    )]
    pub async fn explain(
        &self,
        Parameters(args): Parameters<ExplainArgs>,
    ) -> Result<Json<ExplainResponse>, McpError> {
        let mut request = ExplainRequest::new(&args.connection, &args.sql, self.actor.clone());
        request.client = Client::Mcp;
        request.surface_mode = self.surface_mode;
        request.timeout = args.timeout_ms.map(Duration::from_millis);

        let outcome = core_explain(&self.engine, request)
            .await
            .map_err(core_error)?;

        Ok(Json(ExplainResponse {
            query_id: outcome.query_id.to_string(),
            connection: outcome.connection,
            dialect: outcome.plan.dialect.as_str().to_string(),
            plan: outcome.plan.text,
            duration_ms: outcome.duration_ms,
        }))
    }

    /// Write a held result to a file, unbounded by the 512-row response cap.
    #[tool(
        name = "export",
        description = "Write the whole of a result an earlier `query` produced to a file \
                       — csv, tsv, json, ndjson or parquet. Reads the cached rows, so it \
                       costs no second scan. Exports are audited events in their own \
                       right."
    )]
    pub async fn export(
        &self,
        Parameters(args): Parameters<ExportArgs>,
    ) -> Result<Json<ExportResponse>, McpError> {
        let query_id = parse_uuid(&args.query_id)?;
        let format = ExportFormat::parse(&args.format).ok_or_else(|| {
            McpError::invalid_params(
                format!(
                    "unknown export format {:?}; this build writes {}",
                    args.format,
                    ExportFormat::names().join(", ")
                ),
                None,
            )
        })?;

        let (spool, outcome) = self
            .results
            .with(query_id, |held| (held.spool.clone(), held.outcome.clone()))
            .ok_or_else(|| unknown_result(query_id))?;

        let view = view_for(
            &spool,
            args.sort.as_deref().unwrap_or_default(),
            args.filter.as_deref().unwrap_or_default(),
        )?;

        let destination = Destination::Path(args.path.clone().into());
        let started = std::time::Instant::now();
        let report = quokka_spool::export(&spool, &destination, format, &view).await;

        // Logged whichever way it went, and with the rows that actually reached the
        // file. An export that filled a disk part way through has left rows on it, and a
        // log that said zero would disagree with what is there.
        let (rows, duration_ms, status, error) = match &report {
            Ok(r) => (r.rows, r.duration_ms, quokka_audit::Status::Ok, None),
            Err(f) => (
                f.rows,
                started.elapsed().as_millis().min(i64::MAX as u128) as i64,
                quokka_audit::Status::Error,
                Some(f.error.to_string()),
            ),
        };

        let scope = spool.scoping();
        record_export(
            &self.engine,
            ExportRecord {
                connection: outcome.connection.clone(),
                // §5 links an export to the query whose rows these are. The trap does not
                // stop applying because the caller is an agent.
                parent_query_id: query_id,
                sql_fingerprint: self.fingerprint_for(&outcome),
                actor: self.actor.clone(),
                client: Client::Mcp,
                format: format.as_str().to_string(),
                path: args.path.clone(),
                rows,
                truncated: !scope.is_whole_result(),
                duration_ms,
                status,
                error_code: error.as_ref().map(|_| "spool.export".to_string()),
                error_message: error.clone(),
                tags: None,
            },
        )
        .await
        .map_err(core_error)?;

        let report = report.map_err(|f| {
            McpError::internal_error(format!("the export could not be written: {f}"), None)
        })?;

        Ok(Json(ExportResponse {
            query_id: query_id.to_string(),
            whole_result: report.is_whole_result(),
            path: report.path.clone(),
            format: report.format.as_str().to_string(),
            rows: report.rows,
            bytes: report.bytes,
            duration_ms: report.duration_ms,
            scope_note: scope.note(),
        }))
    }

    /// Search the audit log — which is itself an audited query against `@audit`.
    #[tool(
        name = "search_audit",
        description = "Search the append-only audit log: who ran what, against which \
                       connection, when and how it went. Structured filters rather than \
                       SQL; for anything more, query the built-in @audit connection with \
                       the `query` tool. Searching the log is itself logged."
    )]
    pub async fn search_audit(
        &self,
        Parameters(args): Parameters<SearchAuditArgs>,
    ) -> Result<Json<QueryResponse>, McpError> {
        let (sql, params) = audit_search_sql(&args);
        let query = QueryArgs {
            connection: Some(quokka_core::AUDIT_CONNECTION.to_string()),
            sql: Some(sql.clone()),
            params: Some(params),
            limit: args.limit,
            ..QueryArgs::default()
        };
        self.run_new(&query, &sql).await
    }
}

impl QuokkaMcp {
    async fn catalog(
        &self,
        connection: &str,
        scope: Scope,
        refresh: Option<bool>,
    ) -> Result<quokka_core::CatalogResult, McpError> {
        let mut request = IntrospectRequest::new(connection, scope, self.actor.clone());
        request.client = Client::Mcp;
        // §1.4: refreshing is an explicit action. A cache hit reaches no database and
        // appends no event; this flag is the agent saying it wants the server asked.
        request.refresh = refresh.unwrap_or(false);
        introspect(&self.engine, request).await.map_err(core_error)
    }

    /// Run a statement once, spool it, and answer with the first page.
    async fn run_new(&self, args: &QueryArgs, sql: &str) -> Result<Json<QueryResponse>, McpError> {
        let connection = args.connection.clone().ok_or_else(|| {
            McpError::invalid_params(
                "running SQL needs a `connection`; `list_connections` names them.".to_string(),
                None,
            )
        })?;

        let mut params = Vec::new();
        for value in args.params.as_deref().unwrap_or_default() {
            params.push(value_from_json(value)?);
        }

        let query_id_hint = Uuid::now_v7();
        let mut writer = self
            .spools
            .writer(query_id_hint, &connection)
            .map_err(|e| McpError::internal_error(format!("preparing the spool: {e}"), None))?;
        let path = writer.path().to_path_buf();

        let mut request = ExecuteRequest::new(&connection, sql, self.actor.clone());
        request.client = Client::Mcp;
        request.params = params;
        request.write = args.write.unwrap_or(false);
        request.surface_mode = self.surface_mode;
        request.timeout = args.timeout_ms.map(Duration::from_millis);
        request.max_rows = args.max_rows.unwrap_or(DEFAULT_FETCH_ROWS);

        // The spool writer blocks its caller while a batch lands — harmless in a
        // short-lived CLI and not harmless behind a request handler, where a blocked
        // worker is every *other* tool call waiting. `block_in_place` is the honest fix:
        // it tells tokio this thread is about to block so the runtime moves other tasks
        // off it, and `block_on` drives this query's own I/O here. The alternative,
        // making `RowSink` async, would push the seam into `execute()` and every surface
        // for the sake of one caller.
        let outcome = run_blocking(execute(&self.engine, request, &mut writer))
            .await
            .map_err(core_error)?;

        if !outcome.is_ok() {
            return Ok(Json(QueryResponse::failed(&outcome)));
        }

        let spool = Spool::open(&path).await.map_err(|e| {
            McpError::internal_error(format!("opening the spool just written: {e}"), None)
        })?;

        let view = view_for(
            &spool,
            args.sort.as_deref().unwrap_or_default(),
            args.filter.as_deref().unwrap_or_default(),
        )?;

        let query_id = outcome.query_id;
        let mut held = Held::new(spool, outcome);
        held.view = view;
        if let Some(evicted) = self.results.insert(query_id, held) {
            release(evicted).await;
        }

        self.page(query_id, None, args.limit).await
    }

    /// Read more of a result already run. Nothing here reaches a database.
    async fn read_again(
        &self,
        args: &QueryArgs,
        query_id: &str,
    ) -> Result<Json<QueryResponse>, McpError> {
        let id = parse_uuid(query_id)?;

        let sort = args.sort.as_deref().unwrap_or_default();
        let filter = args.filter.as_deref().unwrap_or_default();
        if !sort.is_empty() || !filter.is_empty() {
            let spool = self
                .results
                .with(id, |held| held.spool.clone())
                .ok_or_else(|| unknown_result(id))?;
            let view = view_for(&spool, sort, filter)?;
            // A cursor into one ordering means nothing in another, so a new view starts
            // again from the top and the old tokens are forgotten rather than left to
            // return a page from a result that no longer exists in that shape.
            self.results.with(id, |held| held.reset(view));
            if args.cursor.is_some() {
                return Err(McpError::invalid_params(
                    "a cursor belongs to one ordering: pass `sort`/`filter` to start that \
                     ordering from the top, or a `cursor` to continue the one you have, \
                     not both."
                        .to_string(),
                    None,
                ));
            }
        }

        self.page(id, args.cursor.as_deref(), args.limit).await
    }

    /// One page, out of the spool. §4's `WHERE rowid > ? LIMIT 512`, never a second
    /// execution.
    async fn page(
        &self,
        query_id: Uuid,
        cursor: Option<&str>,
        limit: Option<u64>,
    ) -> Result<Json<QueryResponse>, McpError> {
        // §4.2: 512 is the hard cap for a tool response and is configurable downward
        // only. An unbounded result set dumped into a context window is a failure mode,
        // not a feature.
        let limit = limit.unwrap_or(MAX_PAGE_ROWS).clamp(1, MAX_PAGE_ROWS);

        let (spool, view, outcome, at) = self
            .results
            .with(query_id, |held| {
                let at = match cursor {
                    Some(token) => held.cursors.get(token).copied(),
                    None => Some(Position::start()),
                };
                (
                    held.spool.clone(),
                    held.view.clone(),
                    held.outcome.clone(),
                    at,
                )
            })
            .ok_or_else(|| unknown_result(query_id))?;

        let at = at.ok_or_else(|| {
            McpError::invalid_params(
                format!(
                    "cursor {:?} does not belong to result {query_id}. Cursors come from \
                     a previous page of this result and are invalidated by a new sort or \
                     filter.",
                    cursor.unwrap_or_default()
                ),
                None,
            )
        })?;

        let total = spool
            .count(&view)
            .await
            .map_err(|e| McpError::internal_error(format!("counting the result: {e}"), None))?;
        let page = spool
            .page(&view, at, limit)
            .await
            .map_err(|e| McpError::internal_error(format!("reading the spool: {e}"), None))?;

        let next_cursor = page
            .next
            .filter(|_| !page.rows.is_empty())
            .and_then(|next| self.results.with(query_id, |held| held.mint(next)));

        let scope = page.scope.clone();
        Ok(Json(QueryResponse {
            query_id: query_id.to_string(),
            connection: outcome.connection.clone(),
            status: outcome.status.as_str().to_string(),
            columns: page
                .columns
                .iter()
                .map(|c| ColumnInfo {
                    name: c.name.clone(),
                    driver_type: c.driver_type.clone(),
                    nullable: c.nullable,
                })
                .collect(),
            rows: page
                .rows
                .iter()
                .map(|row| {
                    row.0
                        .iter()
                        .map(|v| serde_json::to_value(v).unwrap_or(serde_json::Value::Null))
                        .collect()
                })
                .collect(),
            rows_before: page.rows_before,
            rows_in_view: total,
            rows_returned: outcome.rows_returned,
            rows_affected: outcome.rows_affected,
            next_cursor,
            sort: describe_sort(&view),
            // §4.2's trap, one layer up: an agent handed the top of a truncated spool as
            // though it were the top of the result will not notice. So the sentence
            // rides on every page whether it was asked for or not.
            scope_note: scope.note(),
            whole_result: scope.is_whole_result(),
            duration_ms: outcome.duration_ms,
            error_code: outcome.error_code.clone(),
            error_message: outcome.error_message.clone(),
        }))
    }

    /// The fingerprint to record on an export event.
    ///
    /// Recomputed from nothing — the outcome carries no SQL, and neither does this
    /// server after the query ran. `@audit` holds the fingerprint on the `query_started`
    /// row, which is where a reviewer reads it; repeating it here is a convenience, so
    /// when it cannot be had the event still says which query it belongs to through
    /// `parent_id`.
    fn fingerprint_for(&self, outcome: &Outcome) -> String {
        let dialect = self
            .engine
            .registry()
            .get(&outcome.connection)
            .map(|c| c.dialect())
            .unwrap_or(quokka_core::Dialect::Sqlite);
        // The statement is gone; what the export event needs is a shape, and the shape of
        // "the rows of query <id>" is exactly that.
        summarize(
            &format!("SELECT * FROM result_of_{}", outcome.query_id),
            dialect,
        )
        .fingerprint
    }
}

#[tool_handler(router = self.tool_router)]
impl ServerHandler for QuokkaMcp {
    fn get_info(&self) -> ServerConfig {
        let mut info = ServerConfig::new(ServerCapabilities::builder().enable_tools().build());
        info.server_info.name = "quokkaquery".to_string();
        info.server_info.version = env!("CARGO_PKG_VERSION").to_string();
        info.instructions = Some(
            "QuokkaQuery: a database client whose every query is recorded in an \
                 append-only audit log.\n\n\
                 Start with `list_connections`. Each connection's `effective_mode` is \
                 what applies to you: on a read_only connection every write is refused \
                 before it reaches the database, and asking for one is not a way to get \
                 it — only a human editing the config file changes a mode.\n\n\
                 `query` runs one statement (never several; no stacked bodies) and \
                 returns at most 512 rows. It does not re-run anything to give you more: \
                 call it again with the `query_id` and `next_cursor` you were given, or \
                 `export` the whole result to a file. Read `scope_note` on every page — \
                 it is there when the rows you have are a prefix of the result rather \
                 than all of it.\n\n\
                 Queries cost money and touch production, so nothing here runs \
                 implicitly and nothing refreshes itself."
                .to_string(),
        );
        info
    }
}

/// Drive a future to completion on a thread the runtime knows is blocked.
///
/// See the call site: the spool's writer is synchronous by design, and `execute()` calls
/// it per row.
async fn run_blocking<F: std::future::Future>(future: F) -> F::Output {
    match tokio::runtime::Handle::try_current().map(|h| h.runtime_flavor()) {
        Ok(tokio::runtime::RuntimeFlavor::MultiThread) => {
            let handle = tokio::runtime::Handle::current();
            tokio::task::block_in_place(move || handle.block_on(future))
        }
        // On a current-thread runtime there is no other worker to move work to, so
        // `block_in_place` would panic and buy nothing. Awaiting normally is the same
        // behaviour the CLI has, which is where the blocking was already acceptable.
        _ => future.await,
    }
}

fn parse_uuid(text: &str) -> Result<Uuid, McpError> {
    Uuid::parse_str(text).map_err(|_| {
        McpError::invalid_params(
            format!("{text:?} is not a query id; ids come back from `query` as `query_id`."),
            None,
        )
    })
}

fn unknown_result(query_id: Uuid) -> McpError {
    McpError::invalid_params(
        format!(
            "this server is not holding a result for query {query_id}. Results do not \
             outlive the server process (§4.1), and only the {MAX_HELD_RESULTS} most \
             recent are kept. Getting these rows back means running the query again — \
             which costs a second scan, so it does not happen by itself. Run it again \
             with `sql` if you want fresh rows."
        ),
        None,
    )
}

/// A core failure, as an MCP error.
///
/// A denial keeps its machine-readable code in `data`, so an agent can tell "your
/// guardrail refused this" from "the database refused this" without reading prose — and
/// so it can stop rather than retry, which is the useful thing to do with a denial.
fn core_error(e: quokka_core::CoreError) -> McpError {
    match &e {
        quokka_core::CoreError::Denied {
            code,
            connection,
            query_id,
            message,
        } => McpError::invalid_request(
            message.clone(),
            Some(serde_json::json!({
                "denied": true,
                "code": code,
                "connection": connection,
                "query_id": query_id.to_string(),
            })),
        ),
        _ => McpError::internal_error(e.to_string(), None),
    }
}

fn describe_sort(view: &View) -> Vec<SortDescription> {
    view.sort
        .iter()
        .map(|key| SortDescription {
            column: key.column,
            direction: direction_name(key.direction).to_string(),
        })
        .collect()
}

/// Build the audit search as parameterized SQL against `@audit`.
///
/// Structured filters rather than a second SQL door: an agent that wants arbitrary SQL
/// against the log already has it — `@audit` is an ordinary connection and `query`
/// reaches it — and that road is audited and classified like any other. What this adds
/// is the common questions, spelled so they cannot be got wrong.
fn audit_search_sql(args: &SearchAuditArgs) -> (String, Vec<serde_json::Value>) {
    let source = if args.queries.unwrap_or(false) {
        "queries"
    } else {
        "audit_log"
    };
    let ordering = if source == "queries" {
        "started_at"
    } else {
        "id"
    };

    let mut clauses: Vec<String> = Vec::new();
    let mut params: Vec<serde_json::Value> = Vec::new();
    let bind = |column: &str, value: &str, clauses: &mut Vec<String>, params: &mut Vec<_>| {
        clauses.push(format!("{column} = ?"));
        params.push(serde_json::Value::String(value.to_string()));
    };

    if let Some(actor) = &args.actor {
        bind("actor_id", actor, &mut clauses, &mut params);
    }
    if let Some(connection) = &args.connection {
        bind("connection", connection, &mut clauses, &mut params);
    }
    if let Some(status) = &args.status {
        bind("status", status, &mut clauses, &mut params);
    }
    if let Some(kind) = &args.statement_kind {
        bind("statement_kind", kind, &mut clauses, &mut params);
    }
    if source == "audit_log" {
        if let Some(event) = &args.event_kind {
            bind("event_kind", event, &mut clauses, &mut params);
        }
    }
    if let Some(since) = &args.since {
        clauses.push(format!(
            "{} >= ?",
            if source == "queries" {
                "started_at"
            } else {
                "at"
            }
        ));
        params.push(serde_json::Value::String(since.clone()));
    }

    let where_sql = if clauses.is_empty() {
        String::new()
    } else {
        format!(" WHERE {}", clauses.join(" AND "))
    };

    (
        format!("SELECT * FROM {source}{where_sql} ORDER BY {ordering} DESC"),
        params,
    )
}

// ---------------------------------------------------------------------------
// Tool arguments
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Default, Deserialize, JsonSchema)]
pub struct QueryArgs {
    /// The connection to run against. Required with `sql`.
    #[serde(default)]
    pub connection: Option<String>,
    /// One SQL statement. Several statements in one body are refused.
    #[serde(default)]
    pub sql: Option<String>,
    /// A result from an earlier call, to read more of without running anything.
    #[serde(default)]
    pub query_id: Option<String>,
    /// The `next_cursor` from a previous page of that result.
    #[serde(default)]
    pub cursor: Option<String>,
    /// Values for the statement's placeholders, in order.
    #[serde(default)]
    pub params: Option<Vec<serde_json::Value>>,
    /// Rows in this response. At most 512, which is also the default.
    #[serde(default)]
    pub limit: Option<u64>,
    /// Sort the cached rows. Costs no second execution.
    #[serde(default)]
    pub sort: Option<Vec<SortSpec>>,
    /// Filter the cached rows. Costs no second execution.
    #[serde(default)]
    pub filter: Option<Vec<FilterSpec>>,
    /// Say that this statement is meant to write.
    ///
    /// Needed on top of a connection a human set to `read_write`, never instead of it.
    #[serde(default)]
    pub write: Option<bool>,
    /// Rows to read from the database into the cache. Defaults to 10000, and a
    /// connection's own `max_rows` lowers it.
    #[serde(default)]
    pub max_rows: Option<u64>,
    /// Cancel the statement after this long.
    #[serde(default)]
    pub timeout_ms: Option<u64>,
}

#[derive(Debug, Clone, Deserialize, JsonSchema)]
pub struct ListSchemasArgs {
    pub connection: String,
    #[serde(default)]
    pub database: Option<String>,
    #[serde(default)]
    pub schema: Option<String>,
    /// Query the server rather than reading the cached catalog.
    #[serde(default)]
    pub refresh: Option<bool>,
}

#[derive(Debug, Clone, Deserialize, JsonSchema)]
pub struct DescribeTableArgs {
    pub connection: String,
    pub table: String,
    #[serde(default)]
    pub schema: Option<String>,
    #[serde(default)]
    pub database: Option<String>,
    #[serde(default)]
    pub refresh: Option<bool>,
}

#[derive(Debug, Clone, Deserialize, JsonSchema)]
pub struct ExplainArgs {
    pub connection: String,
    pub sql: String,
    #[serde(default)]
    pub timeout_ms: Option<u64>,
}

#[derive(Debug, Clone, Deserialize, JsonSchema)]
pub struct ExportArgs {
    /// The result to write out, from an earlier `query`.
    pub query_id: String,
    /// Where to write it.
    pub path: String,
    /// csv, tsv, json, ndjson or parquet.
    pub format: String,
    #[serde(default)]
    pub sort: Option<Vec<SortSpec>>,
    #[serde(default)]
    pub filter: Option<Vec<FilterSpec>>,
}

#[derive(Debug, Clone, Default, Deserialize, JsonSchema)]
pub struct SearchAuditArgs {
    /// Only this actor's events.
    #[serde(default)]
    pub actor: Option<String>,
    #[serde(default)]
    pub connection: Option<String>,
    /// `ok`, `error`, `denied`, `cancelled`, `timeout`, `started`.
    #[serde(default)]
    pub status: Option<String>,
    /// `query_started`, `query_finished`, `introspect`, `export`, …
    #[serde(default)]
    pub event_kind: Option<String>,
    /// `select`, `insert`, `explain`, …
    #[serde(default)]
    pub statement_kind: Option<String>,
    /// An RFC3339 timestamp; only events at or after it.
    #[serde(default)]
    pub since: Option<String>,
    /// One row per query rather than one per event: the `queries` view, which joins the
    /// start and the finish.
    #[serde(default)]
    pub queries: Option<bool>,
    #[serde(default)]
    pub limit: Option<u64>,
}

// ---------------------------------------------------------------------------
// Tool responses
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Serialize, JsonSchema)]
pub struct ConnectionsResponse {
    pub connections: Vec<ConnectionInfo>,
    /// The posture this server was started with.
    pub server_mode: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub note: Option<String>,
}

#[derive(Debug, Clone, Serialize, JsonSchema)]
pub struct ConnectionInfo {
    pub name: String,
    pub driver: String,
    pub dialect: String,
    pub database: Option<String>,
    pub schema: Option<String>,
    /// user@host:port/database, or the file path. Never a credential.
    pub target: String,
    /// What the config file says.
    pub mode: String,
    /// What applies here, once this server's own posture is taken into account.
    pub effective_mode: String,
    pub sql_logging: String,
    /// Whether the connection restricts which tables a statement may name.
    pub allowlisted: bool,
    pub max_rows: Option<u64>,
    pub timeout_ms: Option<u64>,
    pub builtin: bool,
}

#[derive(Debug, Clone, Serialize, JsonSchema)]
pub struct SchemasResponse {
    pub connection: String,
    pub schemas: Vec<SchemaInfo>,
    /// True when nothing reached a database — and so nothing was logged.
    pub from_cache: bool,
}

#[derive(Debug, Clone, Serialize, JsonSchema)]
pub struct SchemaInfo {
    pub schema: Option<String>,
    pub tables: Vec<TableSummary>,
}

#[derive(Debug, Clone, Serialize, JsonSchema)]
pub struct TableSummary {
    pub name: String,
    pub kind: String,
    pub columns: usize,
}

#[derive(Debug, Clone, Serialize, JsonSchema)]
pub struct DescribeTableResponse {
    pub connection: String,
    pub tables: Vec<TableDetail>,
    pub from_cache: bool,
}

#[derive(Debug, Clone, Serialize, JsonSchema)]
pub struct TableDetail {
    pub schema: Option<String>,
    pub name: String,
    pub kind: String,
    pub columns: Vec<ColumnInfo>,
}

#[derive(Debug, Clone, Serialize, JsonSchema)]
pub struct ColumnInfo {
    pub name: String,
    /// The driver's own type name, kept verbatim (invariant 10).
    pub driver_type: String,
    pub nullable: Option<bool>,
}

#[derive(Debug, Clone, Serialize, JsonSchema)]
pub struct SortDescription {
    pub column: usize,
    pub direction: String,
}

#[derive(Debug, Clone, Serialize, JsonSchema)]
pub struct QueryResponse {
    pub query_id: String,
    pub connection: String,
    pub status: String,
    pub columns: Vec<ColumnInfo>,
    /// Rows as positional arrays, matching `columns`. At most 512 (§4.2).
    pub rows: Vec<Vec<serde_json::Value>>,
    /// How many rows of this view precede the first one here.
    pub rows_before: u64,
    /// How many rows this view selects in total.
    pub rows_in_view: u64,
    /// How many rows the query returned to the engine.
    pub rows_returned: u64,
    pub rows_affected: Option<i64>,
    /// Pass this back with the same `query_id` for the next page. Absent on the last
    /// page. Reading a page runs no query.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub next_cursor: Option<String>,
    pub sort: Vec<SortDescription>,
    /// Present when these rows are a prefix of the result rather than all of it.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub scope_note: Option<String>,
    pub whole_result: bool,
    pub duration_ms: i64,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error_code: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error_message: Option<String>,
}

impl QueryResponse {
    /// A query that ran and failed. It is still a logged query, and the agent is told
    /// how it went rather than being handed an empty page.
    fn failed(outcome: &Outcome) -> Self {
        QueryResponse {
            query_id: outcome.query_id.to_string(),
            connection: outcome.connection.clone(),
            status: outcome.status.as_str().to_string(),
            columns: Vec::new(),
            rows: Vec::new(),
            rows_before: 0,
            rows_in_view: 0,
            rows_returned: outcome.rows_returned,
            rows_affected: outcome.rows_affected,
            next_cursor: None,
            sort: Vec::new(),
            scope_note: None,
            whole_result: false,
            duration_ms: outcome.duration_ms,
            error_code: outcome.error_code.clone(),
            error_message: outcome.error_message.clone(),
        }
    }
}

#[derive(Debug, Clone, Serialize, JsonSchema)]
pub struct ExplainResponse {
    pub query_id: String,
    pub connection: String,
    pub dialect: String,
    /// The engine's own plan text, unparsed.
    pub plan: String,
    pub duration_ms: i64,
}

#[derive(Debug, Clone, Serialize, JsonSchema)]
pub struct ExportResponse {
    pub query_id: String,
    pub path: String,
    pub format: String,
    pub rows: u64,
    pub bytes: u64,
    pub duration_ms: i64,
    pub whole_result: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub scope_note: Option<String>,
}
