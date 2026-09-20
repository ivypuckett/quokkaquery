//! The second test CLAUDE.md asks for: no code path executes SQL without appending both
//! events — and the fail-closed rule, which says a query must not run at all when the
//! log cannot record that it started.
//!
//! The strongest form of the first claim is not in this file. `Driver::execute` takes an
//! `ExecutePermit` whose constructor is crate-private to `quokka-core`, so a surface
//! crate that got hold of a `Driver` still cannot call it: the compiler refuses. What
//! these tests add is the other half — that `execute()` itself never returns without
//! having written both events, whichever way the query ended.

use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;

use async_trait::async_trait;
use futures::StreamExt;
use quokka_core::{
    execute, Actor, ActorKind, AuditLog, Catalog, Column, ConnectionConfig, Driver, DriverError,
    DriverFactory, Engine, EventKind, ExecutePermit, ExecuteRequest, MetaHandle, NullSink, Outcome,
    Plan, QueryHandle, QueryRequest, QueryStream, Registry, Row, RowSink, Scope, Status, Value,
};
use sqlx::sqlite::SqliteConnectOptions;
use sqlx::{ConnectOptions, Executor};

/// What the fake driver should do when asked to run something.
#[derive(Debug, Clone, Copy)]
enum Behaviour {
    /// Yield this many rows and finish.
    Rows(usize),
    /// Fail before yielding anything, as a connection or a syntax error would.
    FailToStart,
    /// Yield some rows, then fail mid-stream.
    FailAfter(usize),
    /// Yield some rows, then report the query was cancelled.
    CancelAfter(usize),
}

struct FakeDriver {
    behaviour: Behaviour,
    executions: Arc<AtomicUsize>,
}

#[async_trait]
impl Driver for FakeDriver {
    fn dialect(&self) -> quokka_core::Dialect {
        quokka_core::Dialect::Sqlite
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
        self.executions.fetch_add(1, Ordering::SeqCst);

        let rows: Vec<Result<Row, DriverError>> = match self.behaviour {
            Behaviour::FailToStart => {
                return Err(DriverError::Execute {
                    detail: "no".to_string(),
                })
            }
            Behaviour::Rows(n) => (0..n).map(|i| Ok(row(i))).collect(),
            Behaviour::FailAfter(n) => (0..n)
                .map(|i| Ok(row(i)))
                .chain(std::iter::once(Err(DriverError::Execute {
                    detail: "the connection dropped".to_string(),
                })))
                .collect(),
            Behaviour::CancelAfter(n) => (0..n)
                .map(|i| Ok(row(i)))
                .chain(std::iter::once(Err(DriverError::Cancelled)))
                .collect(),
        };

        Ok(QueryStream {
            columns: vec![Column {
                name: "n".to_string(),
                driver_type: "INTEGER".to_string(),
                nullable: Some(false),
            }],
            rows: futures::stream::iter(rows).boxed(),
            meta: MetaHandle::new(),
        })
    }

    async fn cancel(&self, _handle: QueryHandle) -> Result<(), DriverError> {
        Ok(())
    }

    async fn explain(&self, _p: &ExecutePermit, _sql: &str) -> Result<Plan, DriverError> {
        Err(DriverError::Unsupported("not in this test".into()))
    }
}

fn row(i: usize) -> Row {
    Row(vec![Value::Int(i as i64)])
}

struct FakeFactory {
    behaviour: Behaviour,
    executions: Arc<AtomicUsize>,
}

#[async_trait]
impl DriverFactory for FakeFactory {
    fn name(&self) -> &'static str {
        "fake"
    }

    fn dialect(&self) -> quokka_core::Dialect {
        quokka_core::Dialect::Sqlite
    }

    async fn open(&self, _cfg: &ConnectionConfig) -> Result<Arc<dyn Driver>, DriverError> {
        Ok(Arc::new(FakeDriver {
            behaviour: self.behaviour,
            executions: self.executions.clone(),
        }))
    }
}

struct Harness {
    engine: Engine,
    executions: Arc<AtomicUsize>,
    _dir: tempfile::TempDir,
}

async fn harness(behaviour: Behaviour) -> Harness {
    harness_with(behaviour, quokka_core::SqlLogging::Fingerprint).await
}

async fn harness_with(behaviour: Behaviour, sql_logging: quokka_core::SqlLogging) -> Harness {
    let dir = tempfile::tempdir().expect("tempdir");
    let audit_path = dir.path().join("audit.db");
    let audit = AuditLog::open(&audit_path).await.expect("open audit log");

    let executions = Arc::new(AtomicUsize::new(0));
    let mut registry = Registry::builtin_only(&audit_path);
    registry.insert(ConnectionConfig {
        mode: quokka_core::AccessMode::ReadWrite,
        sql_logging,
        ..ConnectionConfig::new("fake", "fake")
    });

    let engine = Engine::new(
        registry,
        audit,
        vec![Arc::new(FakeFactory {
            behaviour,
            executions: executions.clone(),
        })],
    );

    Harness {
        engine,
        executions,
        _dir: dir,
    }
}

fn request(sql: &str) -> ExecuteRequest {
    ExecuteRequest::new(
        "fake",
        sql,
        Actor {
            kind: ActorKind::Agent,
            id: "claude".to_string(),
        },
    )
}

/// Both events, for every way a query can end. This is the property, stated once and
/// checked against each outcome rather than only the happy one.
#[tokio::test]
async fn every_outcome_writes_exactly_two_events() {
    let cases = [
        (Behaviour::Rows(0), Status::Ok),
        (Behaviour::Rows(3), Status::Ok),
        (Behaviour::FailToStart, Status::Error),
        (Behaviour::FailAfter(2), Status::Error),
        (Behaviour::CancelAfter(1), Status::Cancelled),
    ];

    for (behaviour, expected) in cases {
        let h = harness(behaviour).await;
        let outcome = execute(&h.engine, request("SELECT 1"), &mut NullSink)
            .await
            .expect("execute should report the outcome, not fail");

        assert_eq!(
            outcome.status, expected,
            "unexpected status for {behaviour:?}"
        );

        let events = quokka_core::events_for_query(&h.engine, outcome.query_id)
            .await
            .expect("read back the events");

        assert_eq!(
            events.len(),
            2,
            "{behaviour:?} produced {} events, not two",
            events.len()
        );
        assert_eq!(events[0].event.event_kind, EventKind::QueryStarted);
        assert_eq!(events[0].event.status, Status::Started);
        assert_eq!(events[1].event.event_kind, EventKind::QueryFinished);
        assert_eq!(events[1].event.status, expected);
        assert!(
            events[0].event.id < events[1].event.id,
            "the start must be appended before the finish"
        );
        assert!(
            h.engine.audit().verify().await.expect("verify").is_intact(),
            "the chain must still verify after {behaviour:?}"
        );
    }
}

/// A sink that fails on its first row, standing in for a closed pipe.
struct BrokenPipe;

impl RowSink for BrokenPipe {
    fn begin(&mut self, _columns: &[Column]) -> std::io::Result<()> {
        Ok(())
    }
    fn row(&mut self, _row: &Row) -> std::io::Result<()> {
        Err(std::io::Error::new(
            std::io::ErrorKind::BrokenPipe,
            "downstream went away",
        ))
    }
    fn end(&mut self, _outcome: &Outcome) -> std::io::Result<()> {
        Ok(())
    }
}

#[tokio::test]
async fn a_failing_sink_still_writes_both_events() {
    let h = harness(Behaviour::Rows(5)).await;
    let outcome = execute(&h.engine, request("SELECT 1"), &mut BrokenPipe)
        .await
        .expect("execute");

    assert_eq!(outcome.status, Status::Error);
    assert_eq!(outcome.error_code.as_deref(), Some("sink.io"));

    let events = quokka_core::events_for_query(&h.engine, outcome.query_id)
        .await
        .expect("events");
    assert_eq!(events.len(), 2);
}

#[tokio::test]
async fn the_cap_truncates_and_says_so() {
    let h = harness(Behaviour::Rows(10)).await;
    let mut req = request("SELECT 1");
    req.max_rows = 4;

    let outcome = execute(&h.engine, req, &mut NullSink)
        .await
        .expect("execute");

    assert_eq!(outcome.rows_returned, 4);
    assert!(outcome.truncated, "truncation must never be silent");

    let events = quokka_core::events_for_query(&h.engine, outcome.query_id)
        .await
        .expect("events");
    assert_eq!(events[1].event.truncated, Some(true));
    assert_eq!(events[1].event.rows_returned, Some(4));
}

/// Invariant 6. If `query_started` cannot be written, the query does not run — not
/// "runs and is logged later", not "runs unlogged".
#[tokio::test]
async fn a_query_does_not_run_when_the_start_cannot_be_logged() {
    let h = harness(Behaviour::Rows(3)).await;
    break_the_log(h.engine.audit().path(), "%").await;

    let err = execute(&h.engine, request("SELECT 1"), &mut NullSink)
        .await
        .expect_err("execute must refuse");

    assert!(
        matches!(err, quokka_core::CoreError::AuditWriteFailed { .. }),
        "expected a fail-closed refusal, got {err:?}"
    );
    assert_eq!(
        h.executions.load(Ordering::SeqCst),
        0,
        "the driver was reached even though the audit log had refused the query"
    );
}

/// The other half of §5: if `query_finished` cannot be written the query has already
/// run, so the failure is surfaced loudly and the dangling start is left as the honest
/// record of what happened.
#[tokio::test]
async fn a_failed_finish_is_loud_and_leaves_the_start_standing() {
    let h = harness(Behaviour::Rows(3)).await;
    break_the_log(h.engine.audit().path(), "query_finished").await;

    let err = execute(&h.engine, request("SELECT 1"), &mut NullSink)
        .await
        .expect_err("execute must report the failed write");

    let query_id = match err {
        quokka_core::CoreError::AuditFinishFailed { query_id, .. } => query_id,
        other => panic!("expected AuditFinishFailed, got {other:?}"),
    };

    assert_eq!(h.executions.load(Ordering::SeqCst), 1, "the query did run");

    let events = quokka_core::events_for_query(&h.engine, query_id)
        .await
        .expect("events");
    assert_eq!(events.len(), 1, "only the start should be in the log");
    assert_eq!(events[0].event.event_kind, EventKind::QueryStarted);
}

#[tokio::test]
async fn an_unknown_connection_reaches_no_database_and_logs_nothing() {
    let h = harness(Behaviour::Rows(1)).await;
    let mut req = request("SELECT 1");
    req.connection = "nowhere".to_string();

    let err = execute(&h.engine, req, &mut NullSink)
        .await
        .expect_err("must fail");
    assert!(matches!(err, quokka_core::CoreError::UnknownConnection(_)));
    assert_eq!(h.executions.load(Ordering::SeqCst), 0);

    let report = h.engine.audit().verify().await.expect("verify");
    assert_eq!(
        report.rows_checked, 0,
        "nothing reached a database, so nothing belongs in the log"
    );
}

/// Make appends fail the way a hostile or broken environment would: a trigger that
/// aborts the insert. `event_kind_pattern` is matched with LIKE, so `%` breaks every
/// append and `query_finished` breaks only the second one.
async fn break_the_log(path: &std::path::Path, event_kind_pattern: &str) {
    let mut conn = SqliteConnectOptions::new()
        .filename(path)
        .connect()
        .await
        .expect("connect");
    conn.execute(sqlx::raw_sql(sqlx::AssertSqlSafe(format!(
        "CREATE TRIGGER audit_log_broken BEFORE INSERT ON audit_log
         WHEN NEW.event_kind LIKE '{event_kind_pattern}'
         BEGIN SELECT RAISE(ABORT, 'the audit log is unavailable'); END"
    ))))
    .await
    .expect("install the failing trigger");
}

/// Invariant 8, seen from the log rather than from the fingerprinter: at the default
/// mode the query text simply is not there.
#[tokio::test]
async fn fingerprint_is_the_default_and_keeps_literals_out_of_the_log() {
    let h = harness(Behaviour::Rows(1)).await;
    let outcome = execute(
        &h.engine,
        request("SELECT * FROM users WHERE email = 'a@b.example'"),
        &mut NullSink,
    )
    .await
    .expect("execute");

    let events = quokka_core::events_for_query(&h.engine, outcome.query_id)
        .await
        .expect("events");

    for stored in &events {
        assert_eq!(
            stored.event.sql_logging,
            quokka_core::SqlLogging::Fingerprint,
            "the mode must be recorded on every row, or the row cannot be interpreted"
        );
        assert_eq!(
            stored.event.sql_text, None,
            "no sql_text at fingerprint, on either event"
        );
        assert_eq!(
            stored.event.sql_fingerprint, "SELECT * FROM users WHERE email = ?",
            "the fingerprint is recorded in every mode"
        );
    }

    let log = format!("{events:?}");
    assert!(
        !log.contains("a@b.example"),
        "a literal reached the audit log at the default mode"
    );
}

/// `full` is opt-in per connection, and even there the secret scrubber runs first.
#[tokio::test]
async fn full_logging_keeps_the_text_but_still_scrubs_secrets() {
    let h = harness_with(Behaviour::Rows(1), quokka_core::SqlLogging::Full).await;
    let outcome = execute(
        &h.engine,
        request("SELECT * FROM users WHERE email = 'a@b.example' AND password = 'hunter2'"),
        &mut NullSink,
    )
    .await
    .expect("execute");

    let events = quokka_core::events_for_query(&h.engine, outcome.query_id)
        .await
        .expect("events");

    let text = events[0]
        .event
        .sql_text
        .as_deref()
        .expect("full mode keeps the query text");
    assert!(
        text.contains("a@b.example"),
        "full mode is what you choose when you need the literals: {text}"
    );
    assert!(
        !text.contains("hunter2"),
        "scrubbing runs before every write, independent of sql_logging: {text}"
    );

    assert_eq!(
        events[1].event.sql_text, None,
        "the text lives on the start event only"
    );
}
