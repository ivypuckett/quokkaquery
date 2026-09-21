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
    /// Yield a row every `0` milliseconds forever — a query that never ends, which is
    /// the only thing a timeout has an opinion about.
    Endless { every_ms: u64 },
    /// Panic if reached. The strongest form of "a denied statement never runs": not an
    /// assertion about an outcome, but a driver that cannot be called without failing
    /// the test.
    Forbidden,
}

struct FakeDriver {
    behaviour: Behaviour,
    executions: Arc<AtomicUsize>,
    /// Set by `cancel`, so a test can see that a timeout asked the driver to stop rather
    /// than merely walking away from it.
    cancelled: Arc<std::sync::atomic::AtomicBool>,
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
            Behaviour::Forbidden => {
                panic!("a denied statement reached the driver")
            }
            Behaviour::Endless { every_ms } => {
                let cancelled = self.cancelled.clone();
                let stream = futures::stream::unfold(0usize, move |i| {
                    let cancelled = cancelled.clone();
                    async move {
                        tokio::time::sleep(std::time::Duration::from_millis(every_ms)).await;
                        if cancelled.load(Ordering::SeqCst) {
                            return Some((Err(DriverError::Cancelled), i + 1));
                        }
                        Some((Ok(row(i)), i + 1))
                    }
                });
                return Ok(QueryStream {
                    columns: vec![Column {
                        name: "n".to_string(),
                        driver_type: "INTEGER".to_string(),
                        nullable: Some(false),
                    }],
                    rows: stream.boxed(),
                    meta: MetaHandle::new(),
                });
            }
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
        self.cancelled.store(true, Ordering::SeqCst);
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
    cancelled: Arc<std::sync::atomic::AtomicBool>,
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
            cancelled: self.cancelled.clone(),
        }))
    }
}

struct Harness {
    engine: Engine,
    executions: Arc<AtomicUsize>,
    cancelled: Arc<std::sync::atomic::AtomicBool>,
    _dir: tempfile::TempDir,
}

async fn harness(behaviour: Behaviour) -> Harness {
    harness_with(behaviour, quokka_core::SqlLogging::Fingerprint).await
}

async fn harness_with(behaviour: Behaviour, sql_logging: quokka_core::SqlLogging) -> Harness {
    harness_configured(behaviour, |cfg| {
        cfg.mode = quokka_core::AccessMode::ReadWrite;
        cfg.sql_logging = sql_logging;
    })
    .await
}

/// A harness whose `fake` connection is configured by the caller.
///
/// Every policy test below differs only in how the connection is set up, which is the
/// point: the guardrail is the connection's configuration plus the call site, and
/// nothing else.
async fn harness_configured(
    behaviour: Behaviour,
    configure: impl FnOnce(&mut ConnectionConfig),
) -> Harness {
    let dir = tempfile::tempdir().expect("tempdir");
    let audit_path = dir.path().join("audit.db");
    let audit = AuditLog::open(&audit_path).await.expect("open audit log");

    let executions = Arc::new(AtomicUsize::new(0));
    let cancelled = Arc::new(std::sync::atomic::AtomicBool::new(false));
    let mut registry = Registry::builtin_only(&audit_path);
    let mut cfg = ConnectionConfig::new("fake", "fake");
    configure(&mut cfg);
    registry.insert(cfg);

    let engine = Engine::new(
        registry,
        audit,
        vec![Arc::new(FakeFactory {
            behaviour,
            executions: executions.clone(),
            cancelled: cancelled.clone(),
        })],
    );

    Harness {
        engine,
        executions,
        cancelled,
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

/// A sink that keeps nothing leaves `rows_spooled` NULL rather than claiming a cache
/// that does not exist, and a sink that keeps rows has its answer carried into the
/// outcome and into the log (§5).
#[tokio::test]
async fn the_log_records_what_the_sink_kept_and_nothing_more() {
    // The default `retained()` — a formatter writing to stdout.
    let h = harness(Behaviour::Rows(3)).await;
    let outcome = execute(&h.engine, request("SELECT 1"), &mut NullSink)
        .await
        .expect("execute");
    assert_eq!(outcome.rows_returned, 3);
    assert_eq!(outcome.rows_spooled, None);
    assert_eq!(outcome.spool_capped, None);
    assert!(!outcome.is_partial());

    let finished = quokka_core::events_for_query(&h.engine, outcome.query_id)
        .await
        .expect("read the log")
        .into_iter()
        .find(|e| e.event.event_kind == EventKind::QueryFinished)
        .expect("a finish event");
    assert_eq!(finished.event.rows_returned, Some(3));
    assert_eq!(
        finished.event.rows_spooled, None,
        "a sink that caches nothing must not claim a spool"
    );

    // A sink that does keep rows, and stops keeping them part way through.
    struct Caching {
        kept: u64,
        room: u64,
    }
    impl RowSink for Caching {
        fn begin(&mut self, _columns: &[Column]) -> std::io::Result<()> {
            Ok(())
        }
        fn row(&mut self, _row: &Row) -> std::io::Result<()> {
            // Full is not an error: the rows keep arriving and the cache stops growing.
            if self.kept < self.room {
                self.kept += 1;
            }
            Ok(())
        }
        fn end(&mut self, _outcome: &Outcome) -> std::io::Result<()> {
            Ok(())
        }
        fn retained(&self) -> Option<quokka_core::Retained> {
            Some(quokka_core::Retained {
                rows: self.kept,
                capped: (self.kept >= self.room).then_some(quokka_core::Cap::Rows),
            })
        }
    }

    let h = harness(Behaviour::Rows(5)).await;
    let mut sink = Caching { kept: 0, room: 2 };
    let outcome = execute(&h.engine, request("SELECT 1"), &mut sink)
        .await
        .expect("execute");

    assert_eq!(outcome.rows_returned, 5);
    assert_eq!(outcome.rows_spooled, Some(2));
    assert_eq!(outcome.spool_capped, Some(quokka_core::Cap::Rows));
    // The caller's cap never fired, and the result is still partial — which is what
    // §4.2 means by "marked truncated" on hitting the spool cap.
    assert!(!outcome.truncated);
    assert!(outcome.is_partial());

    let finished = quokka_core::events_for_query(&h.engine, outcome.query_id)
        .await
        .expect("read the log")
        .into_iter()
        .find(|e| e.event.event_kind == EventKind::QueryFinished)
        .expect("a finish event");
    assert_eq!(finished.event.truncated, Some(true));
    // The two caps stay apart in the log without a column of their own: fewer spooled
    // than returned is the spool's cap, equal is the caller's.
    assert_eq!(finished.event.rows_returned, Some(5));
    assert_eq!(finished.event.rows_spooled, Some(2));
}

// ---------------------------------------------------------------------------
// M3: the guardrail, inside the one execute path
// ---------------------------------------------------------------------------

/// The strongest form of "a denied statement never reaches a driver": not an assertion
/// about an outcome, but a driver that panics if it is called at all. Nothing gets as far
/// as opening a connection, either — `Forbidden` panics in `execute`, and `driver_for`
/// runs before that.
#[tokio::test]
async fn a_denied_statement_never_reaches_the_driver() {
    for (mode, write, sql) in [
        (quokka_core::AccessMode::ReadOnly, true, "DELETE FROM t"),
        (quokka_core::AccessMode::ReadWrite, false, "DELETE FROM t"),
        (
            quokka_core::AccessMode::ReadWrite,
            true,
            "SELECT 1; DROP TABLE t",
        ),
        (quokka_core::AccessMode::ReadWrite, true, "   -- nothing\n"),
    ] {
        let h = harness_configured(Behaviour::Forbidden, |cfg| cfg.mode = mode).await;
        let mut req = request(sql);
        req.write = write;

        let err = execute(&h.engine, req, &mut NullSink)
            .await
            .expect_err("{sql} should have been denied");
        assert!(
            matches!(err, quokka_core::CoreError::Denied { .. }),
            "expected a denial for {sql:?} on {mode}, got {err:?}"
        );
        assert_eq!(
            h.executions.load(Ordering::SeqCst),
            0,
            "the driver was reached for {sql:?}"
        );
    }
}

/// A denial leaves the *same* record shape as any other query: two events, one
/// `query_id`, and a finish — so the `queries` view reports `denied` rather than
/// `unfinished`. Inventing a third shape would make the view start lying.
#[tokio::test]
async fn a_denial_leaves_two_events_and_a_coherent_queries_row() {
    let h = harness_configured(Behaviour::Forbidden, |cfg| {
        cfg.mode = quokka_core::AccessMode::ReadOnly
    })
    .await;

    let err = execute(&h.engine, request("DELETE FROM t"), &mut NullSink)
        .await
        .expect_err("denied");
    let query_id = match err {
        quokka_core::CoreError::Denied { query_id, code, .. } => {
            assert_eq!(code, "policy.read_only");
            query_id
        }
        other => panic!("expected a denial, got {other:?}"),
    };

    let events = quokka_core::events_for_query(&h.engine, query_id)
        .await
        .expect("events");
    assert_eq!(events.len(), 2, "invariant 5 does not lift for a denial");
    assert_eq!(events[0].event.event_kind, EventKind::QueryStarted);
    assert_eq!(events[1].event.event_kind, EventKind::QueryFinished);
    assert_eq!(events[1].event.status, Status::Denied);
    assert_eq!(
        events[1].event.error_code.as_deref(),
        Some("policy.read_only")
    );
    // No result columns and no counts: nothing ran.
    assert_eq!(events[1].event.rows_returned, None);
    assert_eq!(events[1].event.truncated, None);
    assert!(h.engine.audit().verify().await.expect("verify").is_intact());
}

/// §6.3 says a denial is audited "with the SQL that triggered it", and §5.1 says literals
/// are PII. Both hold at once: the SQL is on the `query_started` row at whatever fidelity
/// the connection asked for, and a denial is not a reason to store more.
///
/// The reason it must not be: anyone who can get a statement refused on purpose could
/// otherwise write literals into the log of a connection whose owner asked for none — an
/// exfiltration channel *into* the audit trail, opened by the feature meant to close one.
#[tokio::test]
async fn a_denial_is_logged_at_the_connection_s_own_fidelity_and_no_more() {
    // Deliberately not spelled like a credential: §5's regex scrubbing runs before every
    // write whatever `sql_logging` says, and a needle it caught would prove the wrong
    // thing.
    const NEEDLE: &str = "zzq-marker-7c2e-do-not-log";

    let h = harness_configured(Behaviour::Forbidden, |cfg| {
        cfg.mode = quokka_core::AccessMode::ReadOnly;
        cfg.sql_logging = quokka_core::SqlLogging::Fingerprint;
    })
    .await;
    execute(
        &h.engine,
        request(&format!("DELETE FROM t WHERE label = '{NEEDLE}'")),
        &mut NullSink,
    )
    .await
    .expect_err("denied");

    let log = format!("{:?}", h.engine.audit().read_all().await.expect("log"));
    assert!(
        !log.contains(NEEDLE),
        "a denial stored a literal the connection's sql_logging forbids: {log}"
    );
    // What survives is what survives for every other query at this setting: the shape.
    assert!(log.contains("DELETE FROM t WHERE label = ?"));

    // And at `full`, the text is kept — because the connection asked for it, not because
    // the statement was refused.
    let h = harness_configured(Behaviour::Forbidden, |cfg| {
        cfg.mode = quokka_core::AccessMode::ReadOnly;
        cfg.sql_logging = quokka_core::SqlLogging::Full;
    })
    .await;
    execute(
        &h.engine,
        request(&format!("DELETE FROM t WHERE label = '{NEEDLE}'")),
        &mut NullSink,
    )
    .await
    .expect_err("denied");
    let log = format!("{:?}", h.engine.audit().read_all().await.expect("log"));
    assert!(log.contains(NEEDLE));
}

/// An allowed write records who turned the second key, in the column §5 already has for
/// it. No new column: `row_hash` covers a fixed field list whose length is hashed, so
/// adding one would break every existing chain.
#[tokio::test]
async fn an_allowed_write_records_who_opted_in() {
    let h = harness_configured(Behaviour::Rows(0), |cfg| {
        cfg.mode = quokka_core::AccessMode::ReadWrite
    })
    .await;

    let mut req = request("DELETE FROM t");
    req.write = true;
    let outcome = execute(&h.engine, req, &mut NullSink)
        .await
        .expect("execute");

    let events = quokka_core::events_for_query(&h.engine, outcome.query_id)
        .await
        .expect("events");
    assert_eq!(events[0].event.approved_by.as_deref(), Some("claude"));

    // A read does not claim to have been approved by anyone.
    let outcome = execute(&h.engine, request("SELECT 1"), &mut NullSink)
        .await
        .expect("execute");
    let events = quokka_core::events_for_query(&h.engine, outcome.query_id)
        .await
        .expect("events");
    assert_eq!(events[0].event.approved_by, None);
}

/// A surface may narrow a connection's mode and may never widen it — what lets
/// `quokka mcp` refuse writes on a `read_write` connection without becoming the
/// per-surface exemption invariant 9 forbids.
#[tokio::test]
async fn a_surface_posture_narrows_a_connection_and_never_widens_one() {
    // Narrowing: the connection allows it, the surface does not.
    let h = harness_configured(Behaviour::Forbidden, |cfg| {
        cfg.mode = quokka_core::AccessMode::ReadWrite
    })
    .await;
    let mut req = request("DELETE FROM t");
    req.write = true;
    req.surface_mode = quokka_core::AccessMode::ReadOnly;
    let err = execute(&h.engine, req, &mut NullSink)
        .await
        .expect_err("the surface refuses it");
    assert!(matches!(
        err,
        quokka_core::CoreError::Denied {
            code: "policy.read_only",
            ..
        }
    ));

    // Widening, which must not be possible: the surface says read_write and the
    // connection does not.
    let h = harness_configured(Behaviour::Forbidden, |cfg| {
        cfg.mode = quokka_core::AccessMode::ReadOnly
    })
    .await;
    let mut req = request("DELETE FROM t");
    req.write = true;
    req.surface_mode = quokka_core::AccessMode::ReadWrite;
    let err = execute(&h.engine, req, &mut NullSink)
        .await
        .expect_err("the connection refuses it");
    assert!(matches!(
        err,
        quokka_core::CoreError::Denied {
            code: "policy.read_only",
            ..
        }
    ));
}

/// §6.3's other server-side cap: a statement that outruns its budget is cancelled and
/// logged as a timeout, with the rows already read kept and reported as a prefix.
#[tokio::test(flavor = "multi_thread")]
async fn a_statement_that_outruns_its_timeout_is_cancelled_and_logged_as_one() {
    let h = harness_configured(Behaviour::Endless { every_ms: 5 }, |cfg| {
        cfg.mode = quokka_core::AccessMode::ReadOnly
    })
    .await;

    let mut req = request("SELECT * FROM forever");
    req.max_rows = u64::MAX;
    req.timeout = Some(std::time::Duration::from_millis(120));

    let outcome = execute(&h.engine, req, &mut NullSink)
        .await
        .expect("a timeout is an outcome, not a failure to report one");

    assert_eq!(outcome.status, Status::Timeout);
    assert_eq!(outcome.error_code.as_deref(), Some("policy.timeout"));
    assert!(
        outcome.truncated,
        "the rows in hand are a prefix, and the log must say so"
    );
    assert!(
        h.cancelled.load(Ordering::SeqCst),
        "the driver should have been asked to stop, not merely abandoned"
    );

    let events = quokka_core::events_for_query(&h.engine, outcome.query_id)
        .await
        .expect("events");
    assert_eq!(events.len(), 2);
    assert_eq!(events[1].event.status, Status::Timeout);
}

/// A connection's ceilings lower what a caller asked for and never raise it — invariant
/// 7, applied to the two numbers an agent would most like to change.
#[tokio::test(flavor = "multi_thread")]
async fn a_connection_s_caps_lower_a_request_and_never_raise_it() {
    // Rows: the caller asks for 100, the connection allows 3.
    let h = harness_configured(Behaviour::Rows(100), |cfg| {
        cfg.mode = quokka_core::AccessMode::ReadOnly;
        cfg.limits.max_rows = Some(3);
    })
    .await;
    let mut req = request("SELECT 1");
    req.max_rows = 100;
    let outcome = execute(&h.engine, req, &mut NullSink)
        .await
        .expect("execute");
    assert_eq!(outcome.rows_returned, 3);
    assert!(outcome.truncated);

    // And a caller asking for fewer than the ceiling still gets fewer.
    let mut req = request("SELECT 1");
    req.max_rows = 2;
    let outcome = execute(&h.engine, req, &mut NullSink)
        .await
        .expect("execute");
    assert_eq!(outcome.rows_returned, 2);

    // Time: the caller asks for an hour, the connection allows a moment.
    let h = harness_configured(Behaviour::Endless { every_ms: 5 }, |cfg| {
        cfg.mode = quokka_core::AccessMode::ReadOnly;
        cfg.limits.timeout = Some(std::time::Duration::from_millis(120));
    })
    .await;
    let mut req = request("SELECT * FROM forever");
    req.max_rows = u64::MAX;
    req.timeout = Some(std::time::Duration::from_secs(3600));
    let outcome = execute(&h.engine, req, &mut NullSink)
        .await
        .expect("execute");
    assert_eq!(outcome.status, Status::Timeout);
}

/// An allowlist, from the engine's side: the connection's own `schema` resolves an
/// unqualified name, and a table nobody listed does not run.
#[tokio::test]
async fn an_allowlist_binds_at_the_execute_path() {
    let h = harness_configured(Behaviour::Forbidden, |cfg| {
        cfg.allow = quokka_core::Allowlist::new([], ["orders".to_string()]).expect("valid");
    })
    .await;

    let err = execute(&h.engine, request("SELECT * FROM customers"), &mut NullSink)
        .await
        .expect_err("not allowlisted");
    assert!(matches!(
        err,
        quokka_core::CoreError::Denied {
            code: "policy.table_not_allowed",
            ..
        }
    ));
    assert_eq!(h.executions.load(Ordering::SeqCst), 0);

    let h = harness_configured(Behaviour::Rows(1), |cfg| {
        cfg.allow = quokka_core::Allowlist::new([], ["orders".to_string()]).expect("valid");
    })
    .await;
    execute(&h.engine, request("SELECT * FROM orders"), &mut NullSink)
        .await
        .expect("allowlisted");
}
