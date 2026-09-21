//! The cost fields and the cumulative budget (ARCHITECTURE §3.2, §6.4).
//!
//! Over a *fake* driver rather than over Athena, because none of this is
//! Athena-specific: the seam exists for every driver, and what is being checked here is
//! that the wire between "the driver reported a number" and "the log holds that number"
//! is real, and that a budget refusal is the denial shape the log already has.
//!
//! The Athena end of the same wire — that `DataScannedInBytes` is what reaches this seam
//! — is in `quokka-driver`'s recorded fixtures.

use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;

use async_trait::async_trait;
use futures::StreamExt;
use quokka_audit::{AuditEvent, Client, SqlLogging};
use quokka_core::{
    execute, Actor, ActorKind, AuditLog, Catalog, Column, ConnectionConfig, CostGuard, Driver,
    DriverError, DriverFactory, Engine, EventKind, ExecutePermit, ExecuteRequest, MetaHandle,
    NullSink, Plan, QueryHandle, QueryRequest, QueryStream, Registry, Row, Scope, Status, Value,
};
use std::time::Duration;
use uuid::Uuid;

// ---------------------------------------------------------------------------
// A driver that reports whatever it is told to
// ---------------------------------------------------------------------------

struct Meter {
    /// What the driver publishes as `data_scanned_bytes`. `None` is a driver that does
    /// not measure this at all, which is every driver but Athena.
    scanned: Option<i64>,
    rows: usize,
}

#[async_trait]
impl Driver for Meter {
    fn dialect(&self) -> quokka_core::Dialect {
        quokka_core::Dialect::Athena
    }

    async fn connect(_cfg: &ConnectionConfig) -> Result<Self, DriverError> {
        unreachable!("the factory builds this driver directly")
    }

    async fn introspect(&self, _p: &ExecutePermit, _s: Scope) -> Result<Catalog, DriverError> {
        Err(DriverError::Unsupported("not in this test".into()))
    }

    async fn execute(
        &self,
        _permit: &ExecutePermit,
        _req: QueryRequest,
    ) -> Result<QueryStream, DriverError> {
        let meta = MetaHandle::new();
        if let Some(bytes) = self.scanned {
            // Published before the first row, as Athena's is: the statistics arrive when
            // the execution reaches a terminal state.
            meta.update(|m| {
                m.data_scanned_bytes = Some(bytes);
                m.engine_time_ms = Some(7);
            });
        }
        let rows: Vec<Result<Row, DriverError>> = (0..self.rows)
            .map(|i| Ok(Row(vec![Value::Int(i as i64)])))
            .collect();

        Ok(QueryStream {
            columns: vec![Column {
                name: "n".to_string(),
                driver_type: "integer".to_string(),
                nullable: Some(false),
            }],
            rows: futures::stream::iter(rows).boxed(),
            meta,
        })
    }

    async fn cancel(&self, _handle: QueryHandle) -> Result<(), DriverError> {
        Ok(())
    }

    async fn explain(&self, _p: &ExecutePermit, _sql: &str) -> Result<Plan, DriverError> {
        Err(DriverError::Unsupported("not in this test".into()))
    }
}

struct MeterFactory {
    scanned: Option<i64>,
    rows: usize,
    executions: Arc<AtomicUsize>,
}

#[async_trait]
impl DriverFactory for MeterFactory {
    fn name(&self) -> &'static str {
        "meter"
    }
    fn dialect(&self) -> quokka_core::Dialect {
        quokka_core::Dialect::Athena
    }
    async fn open(&self, _cfg: &ConnectionConfig) -> Result<Arc<dyn Driver>, DriverError> {
        self.executions.fetch_add(1, Ordering::SeqCst);
        Ok(Arc::new(Meter {
            scanned: self.scanned,
            rows: self.rows,
        }))
    }
}

struct Harness {
    engine: Engine,
    audit_path: std::path::PathBuf,
    _dir: tempfile::TempDir,
}

/// One connection called `lake`, over a driver that reports `scanned` bytes per query.
async fn harness(scanned: Option<i64>, guard: Option<CostGuard>) -> Harness {
    let dir = tempfile::tempdir().expect("tempdir");
    let audit_path = dir.path().join("audit.db");
    let audit = AuditLog::open(&audit_path).await.expect("open audit log");

    let mut registry = Registry::builtin_only(&audit_path);
    registry.insert(ConnectionConfig {
        cost_guard: guard,
        ..ConnectionConfig::new("lake", "meter")
    });
    // A second connection with the same budget, for the per-connection question.
    registry.insert(ConnectionConfig {
        cost_guard: guard,
        ..ConnectionConfig::new("lake-2", "meter")
    });

    let engine = Engine::new(
        registry,
        audit,
        vec![Arc::new(MeterFactory {
            scanned,
            rows: 3,
            executions: Arc::new(AtomicUsize::new(0)),
        })],
    );

    Harness {
        engine,
        audit_path,
        _dir: dir,
    }
}

fn actor(kind: ActorKind, id: &str) -> Actor {
    Actor {
        kind,
        id: id.to_string(),
    }
}

async fn run(h: &Harness, connection: &str, who: Actor) -> Result<Status, quokka_core::CoreError> {
    let request = ExecuteRequest::new(connection, "SELECT n FROM events", who);
    execute(&h.engine, request, &mut NullSink)
        .await
        .map(|o| o.status)
}

async fn events(h: &Harness) -> Vec<quokka_audit::StoredEvent> {
    h.engine.audit().read_all().await.expect("read the log")
}

fn guard(agent_limit: Option<u64>, human_limit: Option<u64>, warn: Option<u64>) -> CostGuard {
    CostGuard {
        window: Duration::from_secs(3600),
        agent_limit,
        human_limit,
        human_warn: warn,
    }
}

// ---------------------------------------------------------------------------
// The wire
// ---------------------------------------------------------------------------

/// **Filled from what the driver reported, and never invented.**
#[tokio::test]
async fn a_driver_that_reports_bytes_scanned_puts_them_in_query_finished() {
    let h = harness(Some(1_234_567), None).await;
    let request = ExecuteRequest::new(
        "lake",
        "SELECT n FROM events",
        actor(ActorKind::Human, "me"),
    );
    let outcome = execute(&h.engine, request, &mut NullSink)
        .await
        .expect("the query should run");

    assert_eq!(outcome.data_scanned_bytes, Some(1_234_567));
    assert_eq!(outcome.engine_time_ms, Some(7));

    let events = events(&h).await;
    let started = &events[0].event;
    let finished = &events[1].event;

    assert_eq!(started.event_kind, EventKind::QueryStarted);
    assert_eq!(
        started.data_scanned_bytes, None,
        "nothing has been scanned when the start is written — the number arrives after"
    );
    assert_eq!(finished.event_kind, EventKind::QueryFinished);
    assert_eq!(finished.data_scanned_bytes, Some(1_234_567));
}

/// The other half, and the one a careless implementation gets wrong: a driver that
/// reports none leaves NULL, not 0.
#[tokio::test]
async fn a_driver_that_reports_nothing_leaves_null_rather_than_zero() {
    let h = harness(None, None).await;
    let outcome = execute(
        &h.engine,
        ExecuteRequest::new(
            "lake",
            "SELECT n FROM events",
            actor(ActorKind::Human, "me"),
        ),
        &mut NullSink,
    )
    .await
    .expect("the query should run");

    assert_eq!(outcome.data_scanned_bytes, None);
    let events = events(&h).await;
    assert_eq!(
        events[1].event.data_scanned_bytes, None,
        "0 would claim this query scanned nothing; NULL says nobody measured"
    );
    assert_eq!(events[1].event.cost_estimate_usd, None);
}

/// `cost_estimate_usd` stays NULL beside an exact byte count. The decision and its
/// reasoning are on `quokka_core::execute`; this is the assertion that it holds.
#[tokio::test]
async fn the_dollar_column_is_left_to_whoever_reads_the_log() {
    let h = harness(Some(5_000_000_000_000), None).await;
    execute(
        &h.engine,
        ExecuteRequest::new(
            "lake",
            "SELECT n FROM events",
            actor(ActorKind::Human, "me"),
        ),
        &mut NullSink,
    )
    .await
    .expect("the query should run");

    let events = events(&h).await;
    assert_eq!(events[1].event.data_scanned_bytes, Some(5_000_000_000_000));
    assert_eq!(
        events[1].event.cost_estimate_usd, None,
        "a rate that was wrong when it was written cannot be corrected in an \
         append-only table; the byte count is exact and the arithmetic is the reader's"
    );
}

/// **A hash chain that spans the change verifies.**
///
/// These two fields have been in `row_hash`'s field list since M0 and NULL in every row
/// ever written. This is the first commit that stops them being NULL, so the chain has
/// to carry both eras — rows hashed with NULLs and rows hashed with numbers — in one
/// unbroken sequence.
#[tokio::test]
async fn a_chain_spanning_the_change_verifies() {
    let h = harness(Some(42_000), None).await;

    // The old era: events appended exactly as every M0–M4 event was, with both cost
    // fields NULL.
    for i in 0..3 {
        let event = AuditEvent {
            id: Uuid::now_v7(),
            query_id: Uuid::now_v7(),
            parent_id: None,
            at: quokka_audit::now_rfc3339().expect("a timestamp"),
            duration_ms: Some(i),
            actor_kind: ActorKind::Human,
            actor_id: "before".to_string(),
            session_id: "old".to_string(),
            client: Client::Cli,
            connection: "lake".to_string(),
            dialect: "athena".to_string(),
            database: None,
            schema_name: None,
            event_kind: EventKind::QueryFinished,
            sql_logging: SqlLogging::Fingerprint,
            sql_text: None,
            sql_fingerprint: "SELECT ?".to_string(),
            statement_kind: Some("query".to_string()),
            read_only: Some(true),
            params: None,
            status: Status::Ok,
            error_code: None,
            error_message: None,
            rows_returned: Some(1),
            rows_affected: None,
            rows_spooled: None,
            truncated: Some(false),
            export_format: None,
            export_path: None,
            data_scanned_bytes: None,
            cost_estimate_usd: None,
            approved_by: None,
            tags: None,
        };
        h.engine.audit().append(event).await.expect("append");
    }

    // The new era, through the ordinary path.
    for _ in 0..2 {
        execute(
            &h.engine,
            ExecuteRequest::new(
                "lake",
                "SELECT n FROM events",
                actor(ActorKind::Agent, "claude"),
            ),
            &mut NullSink,
        )
        .await
        .expect("the query should run");
    }

    let report = h.engine.audit().verify().await.expect("verify");
    assert!(
        report.is_intact(),
        "a chain that spans the change must verify: {:?}",
        report.problems
    );
    assert_eq!(report.rows_checked, 7);

    // And both eras really are in there, or this test would pass vacuously.
    let events = events(&h).await;
    assert!(events.iter().any(|e| e.event.data_scanned_bytes.is_none()));
    assert!(events
        .iter()
        .any(|e| e.event.data_scanned_bytes == Some(42_000)));

    // Reopening reads the same chain off disk, which is what `quokka audit verify` does.
    h.engine.audit().close().await;
    let reopened = AuditLog::open(&h.audit_path).await.expect("reopen");
    assert!(reopened.verify().await.expect("verify").is_intact());
}

// ---------------------------------------------------------------------------
// The budget
// ---------------------------------------------------------------------------

/// **A budget refusal is the denial shape already in the log**: two events, one
/// `query_id`, a finish that says `denied`, a stable code, and a message naming the
/// budget, the window and the spend. The fourth shape, not a fifth.
#[tokio::test]
async fn a_budget_refusal_is_a_denial_like_any_other() {
    let h = harness(Some(30_000), Some(guard(Some(50_000), None, None))).await;
    let claude = actor(ActorKind::Agent, "claude");

    // Two queries at 30 kB each: the first runs, the second takes the total to 60 kB.
    assert_eq!(
        run(&h, "lake", claude.clone()).await.expect("first"),
        Status::Ok
    );
    assert_eq!(
        run(&h, "lake", claude.clone()).await.expect("second"),
        Status::Ok,
        "the query that crosses the line is the one that runs — the budget stops the \
         one after it (§6.4)"
    );

    let refused = run(&h, "lake", claude.clone())
        .await
        .expect_err("the third should be refused");
    let quokka_core::CoreError::Denied {
        code,
        message,
        query_id,
        ..
    } = &refused
    else {
        panic!("a budget refusal must be a denial: {refused:?}");
    };
    assert_eq!(*code, "policy.cost_budget");
    assert!(message.contains("50 kB"), "the budget: {message}");
    assert!(message.contains("1h"), "the window: {message}");
    assert!(message.contains("60 kB"), "the spend: {message}");

    let all = events(&h).await;
    let denial: Vec<_> = all
        .iter()
        .filter(|e| e.event.query_id == *query_id)
        .collect();
    assert_eq!(denial.len(), 2, "a denial is a query pair, not a lone row");
    assert_eq!(denial[0].event.event_kind, EventKind::QueryStarted);
    assert_eq!(denial[1].event.event_kind, EventKind::QueryFinished);
    assert_eq!(denial[1].event.status, Status::Denied);
    assert_eq!(
        denial[1].event.error_code.as_deref(),
        Some("policy.cost_budget")
    );
    assert_eq!(
        denial[1].event.data_scanned_bytes, None,
        "nothing ran, so nothing was scanned"
    );

    assert!(h.engine.audit().verify().await.expect("verify").is_intact());
}

/// **The budget check leaves no events of its own.**
///
/// It reads the log before every query on a budgeted connection. If that read were an
/// audited query against `@audit`, three queries would leave far more than six rows —
/// and the log would fill with its own bookkeeping.
#[tokio::test]
async fn the_budget_check_leaves_no_events_of_its_own() {
    let h = harness(Some(1_000), Some(guard(Some(1_000_000), None, None))).await;
    let claude = actor(ActorKind::Agent, "claude");

    for _ in 0..3 {
        run(&h, "lake", claude.clone()).await.expect("should run");
    }

    let all = events(&h).await;
    assert_eq!(
        all.len(),
        6,
        "three queries, two events each, and nothing else: {:#?}",
        all.iter()
            .map(|e| (e.event.event_kind, e.event.connection.clone()))
            .collect::<Vec<_>>()
    );
    assert!(
        all.iter().all(|e| e.event.connection == "lake"),
        "nothing should have been logged against @audit"
    );
}

/// The asymmetry, through the engine rather than through the policy engine: one config,
/// one connection, two callers, two answers.
#[tokio::test]
async fn agents_and_humans_are_capped_separately_under_one_config() {
    let h = harness(
        Some(40_000),
        Some(guard(Some(50_000), None, Some(1_000_000))),
    )
    .await;

    // The agent spends 80 kB over two queries and is then refused.
    let claude = actor(ActorKind::Agent, "claude");
    run(&h, "lake", claude.clone()).await.expect("first");
    run(&h, "lake", claude.clone()).await.expect("second");
    let refused = run(&h, "lake", claude).await.expect_err("past 50 kB");
    assert!(matches!(
        refused,
        quokka_core::CoreError::Denied {
            code: "policy.cost_budget",
            ..
        }
    ));

    // A human on the same connection, uncapped, is unaffected — including by what the
    // agent spent.
    for _ in 0..5 {
        assert_eq!(
            run(&h, "lake", actor(ActorKind::Human, "ivy"))
                .await
                .expect("a human is uncapped here"),
            Status::Ok
        );
    }
}

/// An automation is capped as an agent. The question a budget asks is whether anyone is
/// watching, and a cron job at 3am is no more awake than an agent.
#[tokio::test]
async fn an_automation_is_capped_as_an_agent() {
    let h = harness(Some(60_000), Some(guard(Some(50_000), None, None))).await;
    let cron = actor(ActorKind::Automation, "nightly");
    run(&h, "lake", cron.clone()).await.expect("first");
    let refused = run(&h, "lake", cron).await.expect_err("past the agent cap");
    assert!(matches!(
        refused,
        quokka_core::CoreError::Denied {
            code: "policy.cost_budget",
            ..
        }
    ));
}

/// **The budget binds a (connection, actor) pair**, which is the judgement call §6.4's
/// TOML leaves open. Two agents do not share a budget, and one agent's budget on one
/// connection is not spent by its traffic on another.
#[tokio::test]
async fn the_budget_is_per_connection_and_per_actor() {
    let h = harness(Some(60_000), Some(guard(Some(50_000), None, None))).await;

    run(&h, "lake", actor(ActorKind::Agent, "claude"))
        .await
        .expect("first");
    assert!(
        run(&h, "lake", actor(ActorKind::Agent, "claude"))
            .await
            .is_err(),
        "the same agent on the same connection is over budget"
    );

    assert_eq!(
        run(&h, "lake", actor(ActorKind::Agent, "other"))
            .await
            .expect("a different agent has its own budget"),
        Status::Ok
    );
    assert_eq!(
        run(&h, "lake-2", actor(ActorKind::Agent, "claude"))
            .await
            .expect("the same agent on a different connection has a different budget"),
        Status::Ok,
    );
}

/// A human past `human_warn` runs, and the sentence reaches the `Outcome` so that every
/// surface can show the same words.
#[tokio::test]
async fn a_human_past_the_warning_threshold_is_warned_and_still_runs() {
    let h = harness(Some(600_000), Some(guard(Some(1), None, Some(500_000)))).await;
    let ivy = actor(ActorKind::Human, "ivy");

    let first = execute(
        &h.engine,
        ExecuteRequest::new("lake", "SELECT n FROM events", ivy.clone()),
        &mut NullSink,
    )
    .await
    .expect("the first query is under the threshold");
    assert_eq!(first.cost_warning, None);

    let second = execute(
        &h.engine,
        ExecuteRequest::new("lake", "SELECT n FROM events", ivy),
        &mut NullSink,
    )
    .await
    .expect("a warning is not a refusal");
    let warning = second
        .cost_warning
        .expect("past 500 kB, there is a warning");
    assert!(warning.contains("600 kB"), "{warning}");
    assert!(warning.contains("lake"), "{warning}");
    assert_eq!(second.status, Status::Ok);
}

/// A connection with no `cost_guard` is never refused and never warned, however much it
/// has scanned. That is the default, and it must cost nothing.
#[tokio::test]
async fn a_connection_with_no_budget_is_never_refused() {
    let h = harness(Some(9_000_000_000_000), None).await;
    for _ in 0..4 {
        let outcome = execute(
            &h.engine,
            ExecuteRequest::new(
                "lake",
                "SELECT n FROM events",
                actor(ActorKind::Agent, "claude"),
            ),
            &mut NullSink,
        )
        .await
        .expect("no budget, no refusal");
        assert_eq!(outcome.cost_warning, None);
    }
    assert_eq!(events(&h).await.len(), 8);
}
