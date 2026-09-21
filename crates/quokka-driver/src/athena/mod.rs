//! The Athena driver (ARCHITECTURE §3.2).
//!
//! Athena is not a wire-protocol database, so this is a hand-written driver over
//! `aws-sdk-athena` rather than another `sqlx` pool. §3.0's hedge 2 says the `trait
//! Driver` seam has to tolerate exactly this, and it is the same shape BigQuery or
//! Snowflake would take: submit, poll, page, cancel.
//!
//! The four steps §3.2 fixes, and where each one is:
//!
//! 1. [`start`] — `StartQueryExecution` with the configured workgroup and output
//!    location;
//! 2. [`poll`] — `GetQueryExecution` with capped exponential backoff;
//! 3. [`Pages`] — `GetQueryResults`, typing columns from `ResultSetMetadata`;
//! 4. [`AthenaDriver::cancel`] — `StopQueryExecution`.
//!
//! ## Three things about this driver that the others do not have to say
//!
//! **Cancelling means something stronger here, and the UI's label is now wrong in the
//! other direction.** M4 labelled the Stop button for what sqlx can do — "stops reading;
//! the server may still be finishing" — because sqlx 0.9 exposes neither the backend PID
//! nor the cancellation key, so all a cancel can do is stop consuming. On Athena
//! `StopQueryExecution` really does stop the execution, and it is the difference between
//! a scan that stops costing money and one that does not. So [`cancel`](AthenaDriver::cancel)
//! breaks the polling loop *and* calls `StopQueryExecution`; dropping the future would
//! leave the query running and billing.
//!
//! **Cost is reported after the fact, and that is why §6.4 has two layers.** The
//! `DataScannedInBytes` this driver publishes through [`MetaHandle`] arrives when the
//! execution reaches a terminal state — after the scan is paid for. Nothing here can
//! stop a single expensive query; only the workgroup's `BytesScannedCutoffPerQuery` can,
//! which is why a workgroup is a required setting rather than an inherited default.
//!
//! **Bound parameters are refused, on purpose.** Athena has `ExecutionParameters`, and
//! they are not parameter binding: the values are substituted as *text*, so the caller
//! has to write `'foo'` for a string and `foo` for an identifier, and a driver that
//! quoted on the caller's behalf would be guessing at types the engine never told it.
//! That is literal substitution with extra steps — the injection surface binding exists
//! to close. Until Athena offers typed binding, this driver says so rather than
//! pretending (see [`AthenaDriver::execute`]).

mod convert;
mod credentials;
#[cfg(test)]
mod fixtures;
mod results;

use std::collections::HashMap;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use async_trait::async_trait;
use aws_sdk_athena::types::{QueryExecutionContext, QueryExecutionState, ResultConfiguration};
use aws_sdk_athena::Client;
use aws_smithy_types::error::metadata::ProvideErrorMetadata;
use futures::StreamExt;
use quokka_core::{
    AthenaConfig, Catalog, Column, ConnectionConfig, Driver, DriverError, DriverFactory,
    ExecutePermit, MetaHandle, Plan, QueryHandle, QueryRequest, QueryStream, Row, Scope, TableInfo,
};
use uuid::Uuid;

use crate::common::ROW_CHANNEL_DEPTH;
pub use credentials::{advice_for, AthenaAuth};
pub use results::{column_from_info, value_for_type, Pages};

/// Opens Athena connections.
pub struct AthenaFactory;

#[async_trait]
impl DriverFactory for AthenaFactory {
    fn name(&self) -> &'static str {
        "athena"
    }

    fn dialect(&self) -> quokka_core::Dialect {
        quokka_core::Dialect::Athena
    }

    async fn open(&self, cfg: &ConnectionConfig) -> Result<Arc<dyn Driver>, DriverError> {
        Ok(Arc::new(AthenaDriver::connect(cfg).await?))
    }
}

/// How long to wait between `GetQueryExecution` calls (§3.2, step 2).
///
/// Capped exponential backoff rather than a fixed interval, because Athena query times
/// span three orders of magnitude: a partition-pruned lookup finishes in under a second
/// and a full scan takes minutes. Starting short keeps the fast case fast; the cap keeps
/// a long query from being noticed minutes after it finished, which on a cancel button
/// is the difference between responsive and broken.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Backoff {
    pub first: Duration,
    pub max: Duration,
    pub factor: u32,
}

impl Default for Backoff {
    fn default() -> Self {
        Backoff {
            first: Duration::from_millis(150),
            max: Duration::from_secs(5),
            factor: 2,
        }
    }
}

impl Backoff {
    /// The next wait, doubled and capped.
    pub fn next(&self, current: Duration) -> Duration {
        current
            .saturating_mul(self.factor.max(1))
            .min(self.max.max(self.first))
    }
}

/// Everything this driver needs that is not the SDK client.
///
/// Separate from [`ConnectionConfig`] so that [`AthenaDriver::with_client`] can build a
/// driver over a client somebody else configured — which is how the recorded-fixture
/// tests reach it without AWS credentials or a network.
#[derive(Debug, Clone)]
pub struct AthenaSettings {
    /// The connection's name, for error messages.
    pub connection: String,
    pub workgroup: String,
    pub output_location: Option<String>,
    pub database: Option<String>,
    pub catalog: String,
    /// The AWS profile this connection authenticates with, so an auth failure that
    /// arrives mid-query can name it in `aws sso login --profile X`.
    pub profile: Option<String>,
    pub poll: Backoff,
}

impl AthenaSettings {
    pub fn from_config(cfg: &ConnectionConfig, athena: &AthenaConfig) -> Self {
        AthenaSettings {
            connection: cfg.name.clone(),
            workgroup: athena.workgroup.clone(),
            output_location: athena.output_location.clone(),
            database: cfg.database.clone(),
            catalog: athena.catalog.clone(),
            profile: athena.profile.clone(),
            poll: Backoff::default(),
        }
    }
}

/// One query in flight, and the two things a cancel needs.
#[derive(Debug, Default)]
struct Inflight {
    /// Set by [`AthenaDriver::cancel`]. Read by the polling loop, which is where a
    /// cancel would otherwise go to die.
    cancelled: Arc<AtomicBool>,
    /// Athena's own id for the execution. `None` in the window between registering the
    /// query and `StartQueryExecution` returning — a cancel arriving then sets the flag
    /// and the start path stops the execution as soon as it has an id to stop.
    execution_id: Option<String>,
}

/// An Athena client for one connection.
pub struct AthenaDriver {
    client: Client,
    settings: AthenaSettings,
    inflight: Arc<Mutex<HashMap<Uuid, Inflight>>>,
}

impl std::fmt::Debug for AthenaDriver {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("AthenaDriver")
            .field("connection", &self.settings.connection)
            .field("workgroup", &self.settings.workgroup)
            .finish_non_exhaustive()
    }
}

impl AthenaDriver {
    /// Build over an already-configured SDK client.
    ///
    /// The seam [`Driver::connect`] lands on once it has resolved credentials, exposed
    /// because it is also the only way to test this driver without Athena: §9 settles on
    /// recorded HTTP fixtures, and a fixture server is reached by pointing a client's
    /// endpoint at it. Nothing here can reach a database on its own — every method below
    /// still demands an [`ExecutePermit`], which only `quokka-core::execute()` can make.
    pub fn with_client(client: Client, settings: AthenaSettings) -> Self {
        AthenaDriver {
            client,
            settings,
            inflight: Arc::new(Mutex::new(HashMap::new())),
        }
    }

    pub fn settings(&self) -> &AthenaSettings {
        &self.settings
    }

    fn register(&self, handle: QueryHandle) -> Arc<AtomicBool> {
        let cancelled = Arc::new(AtomicBool::new(false));
        let mut inflight = self.inflight.lock().expect("inflight map poisoned");
        inflight.insert(
            handle.0,
            Inflight {
                cancelled: cancelled.clone(),
                execution_id: None,
            },
        );
        cancelled
    }

    /// Record Athena's id for a query already registered, and say whether a cancel beat
    /// us to it.
    fn note_execution(&self, handle: QueryHandle, id: &str) -> bool {
        let mut inflight = self.inflight.lock().expect("inflight map poisoned");
        match inflight.get_mut(&handle.0) {
            Some(entry) => {
                entry.execution_id = Some(id.to_string());
                entry.cancelled.load(Ordering::SeqCst)
            }
            // Cancelled and forgotten while the start was in flight.
            None => true,
        }
    }

    fn forget(&self, handle: QueryHandle) {
        if let Ok(mut inflight) = self.inflight.lock() {
            inflight.remove(&handle.0);
        }
    }

    /// `StopQueryExecution`, which is what actually stops the bill.
    async fn stop(&self, execution_id: &str) {
        // Best effort: a query that already finished cannot be stopped, and saying so
        // would be reporting a failure to do something that no longer needed doing.
        let _ = self
            .client
            .stop_query_execution()
            .query_execution_id(execution_id)
            .send()
            .await;
    }
}

#[async_trait]
impl Driver for AthenaDriver {
    fn dialect(&self) -> quokka_core::Dialect {
        quokka_core::Dialect::Athena
    }

    async fn connect(cfg: &ConnectionConfig) -> Result<Self, DriverError> {
        let athena = cfg.athena.as_ref().ok_or_else(|| DriverError::Connect {
            connection: cfg.name.clone(),
            detail: "this connection has no athena settings; it needs `region` and \
                     `workgroup` in the config file"
                .to_string(),
        })?;

        let sdk = credentials::load(cfg, athena).await?;
        credentials::verify(&sdk, cfg, athena).await?;

        Ok(AthenaDriver::with_client(
            Client::new(&sdk),
            AthenaSettings::from_config(cfg, athena),
        ))
    }

    /// Athena's own catalog APIs — `ListDatabases`, `ListTableMetadata` — rather than a
    /// query against `information_schema`.
    ///
    /// Both are metadata calls that run no query, so a catalog refresh costs nothing and
    /// scans nothing. Introspecting through `information_schema` would be a *query*: it
    /// would queue in the workgroup, take seconds, and land on the bill — which would
    /// make autocomplete's TTL refresh (§3.1) the most expensive thing in the program.
    async fn introspect(
        &self,
        _permit: &ExecutePermit,
        scope: Scope,
    ) -> Result<Catalog, DriverError> {
        let catalog = scope
            .database
            .clone()
            .unwrap_or(self.settings.catalog.clone());
        let databases = match scope
            .schema
            .clone()
            .or_else(|| self.settings.database.clone())
        {
            Some(one) => vec![one],
            None => self.list_databases(&catalog).await?,
        };

        let mut tables = Vec::new();
        for database in databases {
            for table in self
                .list_tables(&catalog, &database, scope.table.as_deref())
                .await?
            {
                tables.push(table);
            }
        }
        Ok(Catalog { tables })
    }

    async fn execute(
        &self,
        _permit: &ExecutePermit,
        req: QueryRequest,
    ) -> Result<QueryStream, DriverError> {
        if !req.params.is_empty() {
            // See the note at the top of this module. Athena's `ExecutionParameters` are
            // textual substitution, not binding, and a driver that quoted for the caller
            // would be guessing at types.
            return Err(DriverError::Unsupported(format!(
                "this connection is Athena, which has no typed parameter binding: its \
                 `ExecutionParameters` substitute the value as text, so the caller would \
                 have to quote string literals itself and QuokkaQuery would be guessing \
                 at the rest. Write the {} value{} into the statement instead — the audit \
                 log records it at this connection's `sql_logging` either way (§5.1).",
                req.params.len(),
                if req.params.len() == 1 { "" } else { "s" }
            )));
        }

        let handle = req.handle;
        let cancelled = self.register(handle);
        match self.submit(&req.sql, handle, cancelled).await {
            Ok(stream) => Ok(stream),
            Err(e) => {
                // Nothing is draining, so the cancel map's entry is dead weight — and a
                // cancel arriving later would otherwise call `StopQueryExecution` on an
                // execution that has already stopped.
                self.forget(handle);
                Err(e)
            }
        }
    }

    /// Break the polling loop *and* stop the execution (§3.2, step 4).
    ///
    /// Both halves matter and for different reasons. The flag is what gets this process
    /// to stop waiting; `StopQueryExecution` is what gets Athena to stop scanning, which
    /// is what stops the money. Dropping the future would do neither.
    async fn cancel(&self, handle: QueryHandle) -> Result<(), DriverError> {
        let execution_id = {
            let mut inflight = self.inflight.lock().expect("inflight map poisoned");
            match inflight.get_mut(&handle.0) {
                Some(entry) => {
                    entry.cancelled.store(true, Ordering::SeqCst);
                    entry.execution_id.clone()
                }
                // Already finished. Cancelling a query that is no longer running is not
                // an error — the caller got what it asked for.
                None => return Ok(()),
            }
        };

        if let Some(id) = execution_id {
            self.stop(&id).await;
        }
        Ok(())
    }

    /// `EXPLAIN`, which Athena runs as a query that plans rather than executes.
    ///
    /// It goes through the same submit-and-poll path as any other statement — it has an
    /// execution id and a row of output — so there is nothing special here beyond
    /// joining the lines. It scans no data, which is why `quokka_core::explain()` does
    /// not put it through the cost budget.
    async fn explain(&self, permit: &ExecutePermit, sql: &str) -> Result<Plan, DriverError> {
        let request = QueryRequest {
            handle: QueryHandle(Uuid::now_v7()),
            sql: format!("EXPLAIN {sql}"),
            params: Vec::new(),
        };
        let mut stream = self.execute(permit, request).await?;

        let mut lines = Vec::new();
        while let Some(row) = stream.rows.next().await {
            let row = row?;
            lines.push(
                row.0
                    .iter()
                    .map(|v| v.to_string())
                    .collect::<Vec<_>>()
                    .join(" "),
            );
        }

        Ok(Plan {
            dialect: quokka_core::Dialect::Athena,
            text: lines.join("\n"),
        })
    }
}

impl AthenaDriver {
    /// Submit, wait, and hand back a stream over the pages.
    ///
    /// Split out of [`Driver::execute`] so that every failure between here and the first
    /// page takes the same cleanup path.
    ///
    /// **A query that failed still comes back as a stream**, whose first item is the
    /// error. That looks like the long way round and it is the only way round: the
    /// numbers this milestone exists to record — `DataScannedInBytes`, engine time —
    /// reach `quokka-core` through [`QueryStream::meta`], and `Result::Err` has nowhere
    /// to put them. A `SELECT` that scanned three terabytes and then failed on a missing
    /// column cost exactly what a successful one would have, and a budget that only saw
    /// the successes would be blind to an agent's worst hour. The engine reads the error
    /// off the stream and reports it exactly as it reports one that arrives mid-result,
    /// because to everything above the driver they are the same event.
    async fn submit(
        &self,
        sql: &str,
        handle: QueryHandle,
        cancelled: Arc<AtomicBool>,
    ) -> Result<QueryStream, DriverError> {
        let meta = MetaHandle::new();

        // The one failure that really is an `Err`: nothing was submitted, so nothing was
        // scanned and there is no meta to lose.
        let execution_id = self.start(sql).await?;

        if self.note_execution(handle, &execution_id) {
            // A cancel arrived while the start was in flight. It could not stop what it
            // had no id for, so it is stopped here — before a single page is read, and
            // before the scan runs any longer than it has to.
            self.stop(&execution_id).await;
            self.forget(handle);
            return Ok(failed(meta, DriverError::Cancelled));
        }

        match self.poll(&execution_id, &cancelled, &meta).await {
            Ok(None) => {}
            Ok(Some(reason)) | Err(reason) => {
                self.forget(handle);
                return Ok(failed(meta, reason));
            }
        }

        // The first page carries `ResultSetMetadata`, so the result's shape is known
        // before any row is handed over — which is what `RowSink::begin` needs, and why
        // this page is read here rather than in the streaming task below.
        let mut pages = Pages::start(self.client.clone(), execution_id.clone());
        let first = match pages.next_page().await {
            Ok(page) => page,
            Err(e) => {
                self.forget(handle);
                return Ok(failed(meta, e));
            }
        };
        let columns = first.columns.clone();

        let (tx, mut rx) =
            tokio::sync::mpsc::channel::<Result<Row, DriverError>>(ROW_CHANNEL_DEPTH);
        let inflight = self.inflight.clone();
        tokio::spawn(async move {
            let mut batch = Some(first);
            'paging: loop {
                let page = match batch.take() {
                    Some(page) => page,
                    None => match pages.next_page().await {
                        Ok(page) => page,
                        Err(e) => {
                            let _ = tx.send(Err(e)).await;
                            break 'paging;
                        }
                    },
                };
                for row in page.rows {
                    if cancelled.load(Ordering::SeqCst) {
                        let _ = tx.send(Err(DriverError::Cancelled)).await;
                        break 'paging;
                    }
                    // A closed receiver means the consumer stopped reading — the cap was
                    // reached, or the caller went away. Either way stop paging: every
                    // further `GetQueryResults` is a call nobody wants the answer to.
                    if tx.send(Ok(row)).await.is_err() {
                        break 'paging;
                    }
                }
                if !pages.has_more() {
                    break 'paging;
                }
            }
            // The query is over, so the entry that let it be cancelled goes with it.
            // Removing it here rather than when `execute` returns is the whole point:
            // rows are still arriving after that, and a cancel has to reach them.
            if let Ok(mut map) = inflight.lock() {
                map.remove(&handle.0);
            }
        });

        let rows = futures::stream::poll_fn(move |cx| rx.poll_recv(cx)).boxed();
        Ok(QueryStream {
            columns,
            rows,
            meta,
        })
    }

    /// Step 1: `StartQueryExecution` with the configured workgroup and output location.
    async fn start(&self, sql: &str) -> Result<String, DriverError> {
        let mut request = self
            .client
            .start_query_execution()
            .query_string(sql)
            // Always named, never inherited. The workgroup is where §6.4's layer 1
            // lives, so running in whichever one the account defaults to would be
            // running without the only control that can stop a single query.
            .work_group(&self.settings.workgroup);

        if let Some(location) = &self.settings.output_location {
            request = request.result_configuration(
                ResultConfiguration::builder()
                    .output_location(location)
                    .build(),
            );
        }
        if self.settings.database.is_some() {
            request = request.query_execution_context(
                QueryExecutionContext::builder()
                    .set_database(self.settings.database.clone())
                    .catalog(&self.settings.catalog)
                    .build(),
            );
        }

        let started = request
            .send()
            .await
            .map_err(|e| self.execute_error("starting the query", e))?;

        started
            .query_execution_id
            .ok_or_else(|| DriverError::Execute {
                detail: "Athena accepted the query but returned no query execution id, \
                         so there is nothing to poll or to stop"
                    .to_string(),
            })
    }

    /// Step 2: poll `GetQueryExecution` with capped exponential backoff.
    ///
    /// Returns `Ok(None)` when the execution succeeded, `Ok(Some(error))` when it
    /// reached a terminal state that is not success, and `Err` when the polling itself
    /// failed.
    ///
    /// **The statistics are published before this returns, whatever the outcome.** A
    /// query that failed still scanned what it scanned, and §6.4's accounting has to see
    /// it: charging only for successes would leave an agent's worst hour invisible to
    /// its own budget.
    async fn poll(
        &self,
        execution_id: &str,
        cancelled: &Arc<AtomicBool>,
        meta: &MetaHandle,
    ) -> Result<Option<DriverError>, DriverError> {
        let mut wait = self.settings.poll.first;
        loop {
            if cancelled.load(Ordering::SeqCst) {
                self.stop(execution_id).await;
                return Ok(Some(DriverError::Cancelled));
            }

            let answer = self
                .client
                .get_query_execution()
                .query_execution_id(execution_id)
                .send()
                .await
                .map_err(|e| self.execute_error("asking how the query is going", e))?;

            let execution = answer.query_execution.ok_or_else(|| DriverError::Execute {
                detail: format!("Athena reported nothing at all about query {execution_id}"),
            })?;

            if let Some(stats) = &execution.statistics {
                // Republished on every poll rather than only at the end: an execution
                // that dies between here and the terminal state still leaves the last
                // numbers Athena gave us, which is better than none.
                let scanned = stats.data_scanned_in_bytes;
                let engine = stats.engine_execution_time_in_millis;
                meta.update(|m| {
                    if scanned.is_some() {
                        m.data_scanned_bytes = scanned;
                    }
                    if engine.is_some() {
                        m.engine_time_ms = engine;
                    }
                });
            }

            let status = execution.status.as_ref();
            let state = status.and_then(|s| s.state.clone());
            match state {
                Some(QueryExecutionState::Succeeded) => return Ok(None),
                Some(QueryExecutionState::Cancelled) => {
                    return Ok(Some(DriverError::Cancelled));
                }
                Some(QueryExecutionState::Failed) => {
                    let reason = status
                        .and_then(|s| s.state_change_reason.clone())
                        .unwrap_or_else(|| "Athena gave no reason".to_string());
                    return Ok(Some(DriverError::Execute { detail: reason }));
                }
                // Queued, Running, or a state this build has never heard of. An unknown
                // state is waited on rather than failed on: Athena adding one should
                // slow a query down, never break it.
                _ => {}
            }

            tokio::time::sleep(wait).await;
            wait = self.settings.poll.next(wait);
        }
    }

    async fn list_databases(&self, catalog: &str) -> Result<Vec<String>, DriverError> {
        let mut names = Vec::new();
        let mut token: Option<String> = None;
        loop {
            let page = self
                .client
                .list_databases()
                .catalog_name(catalog)
                .set_next_token(token.clone())
                .send()
                .await
                .map_err(|e| self.execute_error("listing databases", e))?;

            names.extend(
                page.database_list
                    .unwrap_or_default()
                    .into_iter()
                    .map(|d| d.name),
            );
            token = page.next_token;
            if token.is_none() {
                break;
            }
        }
        Ok(names)
    }

    async fn list_tables(
        &self,
        catalog: &str,
        database: &str,
        only: Option<&str>,
    ) -> Result<Vec<TableInfo>, DriverError> {
        let mut tables = Vec::new();
        let mut token: Option<String> = None;
        loop {
            let page = self
                .client
                .list_table_metadata()
                .catalog_name(catalog)
                .database_name(database)
                .set_next_token(token.clone())
                .send()
                .await
                .map_err(|e| self.execute_error("listing tables", e))?;

            for table in page.table_metadata_list.unwrap_or_default() {
                if only.is_some_and(|name| !name.eq_ignore_ascii_case(&table.name)) {
                    continue;
                }
                tables.push(TableInfo {
                    database: Some(catalog.to_string()),
                    // Athena's "database" is a schema in everyone else's vocabulary, and
                    // the catalog is the database. Naming them that way here keeps
                    // `schema.table` meaning the same thing across drivers.
                    schema: Some(database.to_string()),
                    kind: table
                        .table_type
                        .clone()
                        .unwrap_or_else(|| "table".to_string()),
                    columns: table
                        .columns
                        .unwrap_or_default()
                        .into_iter()
                        .map(|c| Column {
                            name: c.name,
                            // Kept verbatim (invariant 10): an unrecognized type is a
                            // string in the grid, never a failed result set.
                            driver_type: c.r#type.unwrap_or_default(),
                            // Athena reports no nullability for a table column, and
                            // inventing one would be worse than saying so.
                            nullable: None,
                        })
                        .chain(
                            table
                                .partition_keys
                                .unwrap_or_default()
                                .into_iter()
                                .map(|c| Column {
                                    name: c.name,
                                    driver_type: c.r#type.unwrap_or_default(),
                                    nullable: None,
                                }),
                        )
                        .collect(),
                    name: table.name,
                });
            }

            token = page.next_token;
            if token.is_none() {
                break;
            }
        }
        Ok(tables)
    }

    /// One place that turns an SDK error into a `DriverError`, with the context that
    /// says which call failed.
    ///
    /// **What this exists to avoid is the raw SDK rendering.**
    /// `DisplayErrorContext` produces a hundred lines of nested `Debug` — the request
    /// id, the headers, the raw body, the retry classification — which is a protocol
    /// error in the exact sense §3.2 says an expired token must not be. Athena's own
    /// error metadata carries a code and a sentence, and those two are what a person
    /// needs. The full dump is what a bug report needs, and this is not one.
    ///
    /// An auth failure gets the same advice `connect` would have given it. It can
    /// arrive here rather than there: credentials that resolved may still be rejected,
    /// and a token that was valid when the connection opened may expire during a long
    /// session.
    fn execute_error<E, R>(
        &self,
        doing: &str,
        e: aws_sdk_athena::error::SdkError<E, R>,
    ) -> DriverError
    where
        E: std::error::Error + ProvideErrorMetadata + Send + Sync + 'static,
        R: std::fmt::Debug + 'static,
    {
        let code = e.code().unwrap_or_default().to_string();
        let said = match (e.code(), e.message()) {
            (Some(code), Some(message)) => format!("{code}: {message}"),
            (Some(code), None) => code.to_string(),
            // A dispatch failure, a timeout, a body that would not parse: no service
            // error to read, so the error's own chain is the best there is — and it is
            // short, unlike the `Debug` rendering.
            _ => error_chain(&e),
        };

        let mut detail = format!(
            "{doing} on connection {:?} (workgroup {:?}): {said}",
            self.settings.connection, self.settings.workgroup,
        );
        if is_auth_failure(&code) {
            detail.push_str("\n\n");
            detail.push_str(&credentials::advice_for(
                credentials::AthenaAuth::ExpiredSso,
                self.settings.profile.as_deref(),
            ));
        }
        DriverError::Execute { detail }
    }
}

/// Athena's error codes for "your credentials are the problem".
///
/// A list rather than a substring match, because these are the codes the service
/// documents and the failure they describe has one fix a person can act on. Anything
/// not on it is reported as whatever Athena called it.
fn is_auth_failure(code: &str) -> bool {
    matches!(
        code,
        "UnrecognizedClientException"
            | "ExpiredTokenException"
            | "ExpiredToken"
            | "InvalidClientTokenId"
            | "InvalidSignatureException"
            | "AuthFailure"
            | "MissingAuthenticationToken"
    )
}

/// Every layer of an error's `source` chain, joined — the short rendering, not the
/// `Debug` one.
fn error_chain(e: &(dyn std::error::Error + 'static)) -> String {
    let mut parts = vec![e.to_string()];
    let mut source = e.source();
    while let Some(next) = source {
        let text = next.to_string();
        // The SDK repeats itself down the chain more often than not.
        if !parts.iter().any(|p| p == &text) {
            parts.push(text);
        }
        source = next.source();
    }
    parts.join(": ")
}

/// A stream that carries one error and whatever the driver had already measured.
///
/// See the note on [`AthenaDriver::submit`]: the meta has to ride the stream because the
/// trait's error path has nowhere to put it.
fn failed(meta: MetaHandle, error: DriverError) -> QueryStream {
    QueryStream {
        columns: Vec::new(),
        rows: futures::stream::once(async move { Err(error) }).boxed(),
        meta,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_backoff_doubles_and_then_stops_doubling() {
        let backoff = Backoff {
            first: Duration::from_millis(150),
            max: Duration::from_secs(5),
            factor: 2,
        };
        let mut wait = backoff.first;
        let mut seen = vec![wait];
        for _ in 0..10 {
            wait = backoff.next(wait);
            seen.push(wait);
        }
        assert_eq!(seen[1], Duration::from_millis(300));
        assert_eq!(seen[2], Duration::from_millis(600));
        assert_eq!(
            *seen.last().expect("a last wait"),
            Duration::from_secs(5),
            "the cap is what keeps a finished query from being noticed minutes later"
        );
        assert!(
            seen.iter().all(|w| *w <= Duration::from_secs(5)),
            "no wait may exceed the cap: {seen:?}"
        );
    }

    /// A factor of zero would be an infinite polling loop at the first interval. It
    /// cannot be configured today; the guard costs one `max(1)` and outlives whoever
    /// remembers that.
    #[test]
    fn a_degenerate_factor_still_makes_progress() {
        let backoff = Backoff {
            first: Duration::from_millis(100),
            max: Duration::from_secs(1),
            factor: 0,
        };
        assert_eq!(backoff.next(backoff.first), Duration::from_millis(100));
    }
}
