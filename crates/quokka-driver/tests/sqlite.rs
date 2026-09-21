//! SQLite driver tests.
//!
//! Note what these tests *cannot* do: call `SqliteDriver::execute` directly. It takes an
//! `ExecutePermit`, which only `quokka-core::execute()` can construct, so even the
//! driver's own test suite reaches the database through the audited path. That is
//! invariant 1 working — if this file could shortcut it, so could a surface.

// One crate and one cargo feature per driver (§3.0, hedge 2) means a build can ask for
// any one of them alone — `--no-default-features --features athena` is a real thing to
// want, and CI now runs it. A test file for a driver that is not in the build has
// nothing to test.
#![cfg(feature = "sqlite")]

use std::sync::Arc;

use quokka_core::{
    execute, AccessMode, Actor, ActorKind, AuditLog, Column, ConnectionConfig, Engine,
    ExecuteRequest, Outcome, Registry, Row, RowSink, Status, Value,
};

#[derive(Default)]
struct Collect {
    columns: Vec<Column>,
    rows: Vec<Row>,
}

impl RowSink for Collect {
    fn begin(&mut self, columns: &[Column]) -> std::io::Result<()> {
        self.columns = columns.to_vec();
        Ok(())
    }
    fn row(&mut self, row: &Row) -> std::io::Result<()> {
        self.rows.push(row.clone());
        Ok(())
    }
    fn end(&mut self, _outcome: &Outcome) -> std::io::Result<()> {
        Ok(())
    }
}

struct Fixture {
    engine: Arc<Engine>,
    _dir: tempfile::TempDir,
}

impl Fixture {
    async fn run(&self, connection: &str, sql: &str) -> (Outcome, Collect) {
        self.run_capped(connection, sql, u64::MAX).await
    }

    async fn run_capped(&self, connection: &str, sql: &str, max_rows: u64) -> (Outcome, Collect) {
        let mut sink = Collect::default();
        let mut request = ExecuteRequest::new(
            connection,
            sql,
            Actor {
                kind: ActorKind::Human,
                id: "tester".to_string(),
            },
        );
        request.max_rows = max_rows;
        // These are driver tests, not policy tests: what is under examination here is
        // what SQLite does with a statement, so the call-site opt-in is simply turned on
        // and the guardrail is exercised where it lives — `quokka-policy`'s corpus, and
        // the surface tests that check a denial is denied identically from each one.
        request.write = true;
        let outcome = execute(&self.engine, request, &mut sink)
            .await
            .expect("execute should report the outcome, not fail");
        (outcome, sink)
    }
}

/// A fixture with an `app` database, plus a second read-only connection to the same file.
async fn fixture(setup: &[&str]) -> Fixture {
    let dir = tempfile::tempdir().expect("tempdir");
    let app_db = dir.path().join("app.db");
    let audit_db = dir.path().join("audit.db");

    {
        // Create the file outside QuokkaQuery: the driver never conjures a database
        // because a path was mistyped.
        let opts = sqlx::sqlite::SqliteConnectOptions::new()
            .filename(&app_db)
            .create_if_missing(true);
        let pool = sqlx::SqlitePool::connect_with(opts)
            .await
            .expect("create app db");
        for sql in setup {
            sqlx::raw_sql(sqlx::AssertSqlSafe(sql.to_string()))
                .execute(&pool)
                .await
                .expect("setup");
        }
        pool.close().await;
    }

    let audit = AuditLog::open(&audit_db).await.expect("audit log");
    let mut registry = Registry::builtin_only(&audit_db);
    registry.insert(ConnectionConfig {
        path: Some(app_db.clone()),
        mode: AccessMode::ReadWrite,
        ..ConnectionConfig::new("app", "sqlite")
    });
    registry.insert(ConnectionConfig {
        path: Some(app_db),
        mode: AccessMode::ReadOnly,
        ..ConnectionConfig::new("app-ro", "sqlite")
    });

    Fixture {
        engine: Arc::new(Engine::new(
            registry,
            audit,
            quokka_driver::builtin_factories(),
        )),
        _dir: dir,
    }
}

#[tokio::test]
async fn every_storage_class_round_trips() {
    let f = fixture(&[
        "CREATE TABLE t (i INTEGER, r REAL, s TEXT, b BLOB, n TEXT)",
        "INSERT INTO t VALUES (42, 2.5, 'hello', X'00ff10', NULL)",
    ])
    .await;

    let (outcome, sink) = f.run("app", "SELECT i, r, s, b, n FROM t").await;
    assert_eq!(outcome.status, Status::Ok);
    assert_eq!(
        sink.rows[0].0,
        vec![
            Value::Int(42),
            Value::Float(2.5),
            Value::Text("hello".to_string()),
            Value::Blob(vec![0x00, 0xff, 0x10]),
            Value::Null,
        ]
    );
    assert_eq!(
        sink.columns
            .iter()
            .map(|c| c.name.as_str())
            .collect::<Vec<_>>(),
        vec!["i", "r", "s", "b", "n"]
    );
}

/// Hedge 1 of ARCHITECTURE §3.0, which says this belongs in the driver test suite from
/// M0: an unrecognized type renders as a string and must never abort a result set.
#[tokio::test]
async fn unknown_column_types_degrade_to_text_rather_than_failing() {
    let f = fixture(&[
        "CREATE TABLE weird (a QUOKKA_WIDGET, b GEOGRAPHY, c JSONB, d HSTORE)",
        "INSERT INTO weird VALUES ('shape', 'POINT(1 2)', '{\"k\":1}', 'a=>b')",
    ])
    .await;

    let (outcome, sink) = f.run("app", "SELECT a, b, c, d FROM weird").await;

    assert_eq!(
        outcome.status,
        Status::Ok,
        "an unrecognized type must not abort the result set: {:?}",
        outcome.error_message
    );
    assert_eq!(sink.rows.len(), 1);
    for value in &sink.rows[0].0 {
        assert!(
            matches!(value, Value::Text(_)),
            "expected a string, got {value:?}"
        );
    }
}

/// SQLite columns hold whatever was put in them, so one column can return four storage
/// classes. Every row must still come back.
#[tokio::test]
async fn a_column_holding_mixed_storage_classes_still_reads() {
    let f = fixture(&[
        "CREATE TABLE mixed (v)",
        "INSERT INTO mixed VALUES (1), (2.5), ('three'), (X'04'), (NULL)",
    ])
    .await;

    let (outcome, sink) = f.run("app", "SELECT v FROM mixed ORDER BY rowid").await;
    assert_eq!(outcome.status, Status::Ok);
    assert_eq!(sink.rows.len(), 5);
    assert_eq!(sink.rows[0].0[0], Value::Int(1));
    assert_eq!(sink.rows[1].0[0], Value::Float(2.5));
    assert_eq!(sink.rows[2].0[0], Value::Text("three".to_string()));
    assert_eq!(sink.rows[3].0[0], Value::Blob(vec![4]));
    assert_eq!(sink.rows[4].0[0], Value::Null);
}

#[tokio::test]
async fn a_write_reports_rows_affected_and_a_read_does_not() {
    let f = fixture(&[
        "CREATE TABLE t (a INTEGER)",
        "INSERT INTO t VALUES (1), (2)",
    ])
    .await;

    let (write, _) = f.run("app", "UPDATE t SET a = a + 1").await;
    assert_eq!(write.status, Status::Ok);
    assert_eq!(write.rows_affected, Some(2));

    let (read, _) = f.run("app", "SELECT a FROM t").await;
    assert_eq!(
        read.rows_affected, None,
        "SQLite's change counter is stale after a SELECT; reporting it would be worse \
         than reporting nothing"
    );
}

/// The mode is a property of the connection, so the database itself refuses the write —
/// no policy layer needed for this one.
#[tokio::test]
async fn a_read_only_connection_is_read_only_at_the_file_handle() {
    let f = fixture(&["CREATE TABLE t (a INTEGER)"]).await;

    // Past the policy engine on purpose. M3's classifier refuses a write on a
    // `read_only` connection before a driver is even opened, which is the layer an agent
    // meets — and it is emphatically *not* the only layer. This asserts the other one:
    // the file handle itself is read-only, so a write that somehow arrived would still
    // be refused, by SQLite rather than by us.
    let cfg = f
        .engine
        .registry()
        .get("app-ro")
        .cloned()
        .expect("the read-only connection");
    let driver = <quokka_driver::sqlite::SqliteDriver as quokka_core::Driver>::connect(&cfg)
        .await
        .expect("open the read-only connection");

    let err = sqlx::query("INSERT INTO t VALUES (1)")
        .execute(driver.pool())
        .await
        .expect_err("SQLite must refuse a write on a read-only handle");
    assert!(
        err.to_string().contains("readonly"),
        "the file handle should have refused it: {err}"
    );
}

/// And the layer above it: the same write never reaches the driver at all, and the
/// attempt is in the log as a denial rather than as an error.
#[tokio::test]
async fn a_write_to_a_read_only_connection_is_denied_before_any_driver_is_opened() {
    let f = fixture(&["CREATE TABLE t (a INTEGER)"]).await;

    let mut sink = Collect::default();
    let mut request = ExecuteRequest::new(
        "app-ro",
        "INSERT INTO t VALUES (1)",
        Actor {
            kind: ActorKind::Agent,
            id: "claude".to_string(),
        },
    );
    // Asking for it makes no difference: the mode is the authorization, and only a
    // human editing the config file can change that.
    request.write = true;

    let err = execute(&f.engine, request, &mut sink)
        .await
        .expect_err("a write on a read-only connection must not run");
    let query_id = match &err {
        quokka_core::CoreError::Denied { code, query_id, .. } => {
            assert_eq!(*code, "policy.read_only");
            *query_id
        }
        other => panic!("expected a denial, got {other:?}"),
    };

    // Invariant 5's shape, unchanged by the denial: two events, one query_id, and the
    // `queries` view sees a finish rather than an unfinished query.
    let events = quokka_core::events_for_query(&f.engine, query_id)
        .await
        .expect("events");
    assert_eq!(events.len(), 2);
    assert_eq!(events[1].event.status, Status::Denied);
    assert!(f.engine.audit().verify().await.expect("verify").is_intact());
}

/// The hole M3 closes, and why it needed closing twice.
///
/// The first assertion is the thing itself: `sqlx-sqlite` walks the statement tail even
/// on the prepared path, so a stacked body really does run all of it. That is what made
/// the old `raw_sql` route a hole rather than an inelegance, and it is why the driver
/// refuses a stacked body itself instead of trusting that preparing one is enough.
///
/// The second is the guardrail at its proper layer: through `execute()` the body never
/// reaches a driver at all, and the attempt is logged as a denial.
#[tokio::test]
async fn a_stacked_body_is_refused_by_the_driver_and_never_reaches_it_through_execute() {
    let f = fixture(&["CREATE TABLE t (a INTEGER)", "INSERT INTO t VALUES (1)"]).await;

    let cfg = f
        .engine
        .registry()
        .get("app")
        .cloned()
        .expect("the read-write connection");
    let driver = <quokka_driver::sqlite::SqliteDriver as quokka_core::Driver>::connect(&cfg)
        .await
        .expect("open");

    // Past both guardrails, straight at sqlx: this is the behaviour being defended
    // against, asserted so that a future sqlx release changing it is visible here rather
    // than silently making a comment wrong.
    sqlx::query("SELECT 1; DROP TABLE t")
        .execute(driver.pool())
        .await
        .expect("sqlx runs the whole body");
    let dropped = sqlx::query_scalar::<_, i64>("SELECT count(*) FROM t")
        .fetch_one(driver.pool())
        .await
        .is_err();
    assert!(
        dropped,
        "sqlx-sqlite no longer runs the tail of a stacked body — the driver's own check \
         may now be unnecessary, but check before removing it"
    );

    // And through the one execute path, on a fresh table, it does not get that far.
    let f = fixture(&["CREATE TABLE t (a INTEGER)", "INSERT INTO t VALUES (1)"]).await;
    let mut sink = Collect::default();
    let request = ExecuteRequest::new(
        "app",
        "SELECT 1; DROP TABLE t",
        Actor {
            kind: ActorKind::Agent,
            id: "claude".to_string(),
        },
    );
    let err = execute(&f.engine, request, &mut sink)
        .await
        .expect_err("a stacked body must be refused");
    assert!(
        matches!(&err, quokka_core::CoreError::Denied { code, .. }
                 if *code == "policy.multiple_statements"),
        "{err:?}"
    );

    let (still_there, _) = f.run("app", "SELECT count(*) FROM t").await;
    assert_eq!(still_there.rows_returned, 1);
}

/// `quokka explain`, end to end: the plan comes back, and asking for it leaves the two
/// events a query leaves (invariant 1 binds it, because it runs SQL).
#[tokio::test]
async fn explain_returns_a_plan_and_logs_a_query_pair() {
    let f = fixture(&[
        "CREATE TABLE t (a INTEGER PRIMARY KEY, b TEXT)",
        "INSERT INTO t VALUES (1, 'x')",
    ])
    .await;

    let outcome = quokka_core::explain(
        &f.engine,
        quokka_core::ExplainRequest::new(
            "app",
            "SELECT * FROM t WHERE a = 1",
            Actor {
                kind: ActorKind::Human,
                id: "tester".to_string(),
            },
        ),
    )
    .await
    .expect("explain");

    assert!(
        outcome.plan.text.to_uppercase().contains("T"),
        "the plan should mention the table: {:?}",
        outcome.plan.text
    );

    let events = quokka_core::events_for_query(&f.engine, outcome.query_id)
        .await
        .expect("events");
    assert_eq!(events.len(), 2);
    assert_eq!(events[0].event.statement_kind.as_deref(), Some("explain"));
    assert!(events[0]
        .event
        .sql_fingerprint
        .starts_with("EXPLAIN SELECT"));
    assert_eq!(events[1].event.status, Status::Ok);
}

/// Explaining a write needs the same authorization as running one — the decision
/// `quokka_core::explain` documents, asserted so it cannot drift.
#[tokio::test]
async fn explaining_a_write_on_a_read_only_connection_is_denied() {
    let f = fixture(&["CREATE TABLE t (a INTEGER)"]).await;

    let err = quokka_core::explain(
        &f.engine,
        quokka_core::ExplainRequest::new(
            "app-ro",
            "DELETE FROM t",
            Actor {
                kind: ActorKind::Agent,
                id: "claude".to_string(),
            },
        ),
    )
    .await
    .expect_err("explaining a delete on a read-only connection must be refused");

    assert!(
        matches!(&err, quokka_core::CoreError::Denied { code, .. } if *code == "policy.read_only"),
        "{err:?}"
    );
}

#[tokio::test]
async fn a_missing_database_file_is_an_error_not_a_new_database() {
    let dir = tempfile::tempdir().expect("tempdir");
    let audit_db = dir.path().join("audit.db");
    let audit = AuditLog::open(&audit_db).await.expect("audit log");

    let mut registry = Registry::builtin_only(&audit_db);
    registry.insert(ConnectionConfig {
        path: Some(dir.path().join("does-not-exist.db")),
        mode: AccessMode::ReadWrite,
        ..ConnectionConfig::new("typo", "sqlite")
    });

    let engine = Engine::new(registry, audit, quokka_driver::builtin_factories());
    let outcome = execute(
        &engine,
        ExecuteRequest::new(
            "typo",
            "SELECT 1",
            Actor {
                kind: ActorKind::Human,
                id: "tester".to_string(),
            },
        ),
        &mut quokka_core::NullSink,
    )
    .await
    .expect("the attempt is still logged");

    assert_eq!(outcome.status, Status::Error);
    assert_eq!(outcome.error_code.as_deref(), Some("driver.connect"));
    assert!(!dir.path().join("does-not-exist.db").exists());
}

/// Cancellation is in the trait from day one because a runaway scan costs real money
/// (§2.1). Here it costs only time, but the seam is the same one Athena will use.
#[tokio::test]
async fn an_in_flight_query_can_be_cancelled() {
    let f = fixture(&["CREATE TABLE t (a INTEGER)"]).await;

    let engine = f.engine.clone();
    let canceller = tokio::spawn(async move {
        // Poll rather than sleeping once: the query has to be in flight before
        // `cancel_all` has anything to find.
        for _ in 0..400 {
            tokio::time::sleep(std::time::Duration::from_millis(5)).await;
            engine.cancel_all().await;
        }
    });

    let (outcome, sink) = f
        .run(
            "app",
            "WITH RECURSIVE counter(n) AS (SELECT 1 UNION ALL SELECT n + 1 FROM counter \
             WHERE n < 20000000) SELECT n FROM counter",
        )
        .await;
    canceller.abort();

    assert_eq!(
        outcome.status,
        Status::Cancelled,
        "a cancelled query reports as cancelled, not as a success on a partial read"
    );
    assert!(
        sink.rows.len() < 20_000_000,
        "the scan should have stopped early"
    );

    // A cancellation is a fully logged query, not a gap in the record.
    let events = quokka_core::events_for_query(&f.engine, outcome.query_id)
        .await
        .expect("events");
    assert_eq!(events.len(), 2);
    assert_eq!(events[1].event.status, Status::Cancelled);
}

#[tokio::test]
async fn the_audit_connection_is_queryable_like_any_other() {
    let f = fixture(&["CREATE TABLE t (a INTEGER)"]).await;
    let (first, _) = f.run("app", "SELECT 1").await;

    let (outcome, sink) = f
        .run_capped(
            quokka_core::AUDIT_CONNECTION,
            &format!(
                "SELECT event_kind, status FROM audit_log WHERE query_id = '{}' ORDER BY id",
                first.query_id
            ),
            512,
        )
        .await;

    assert_eq!(outcome.status, Status::Ok);
    assert_eq!(sink.rows.len(), 2);
    assert_eq!(sink.rows[0].0[0], Value::Text("query_started".to_string()));
    assert_eq!(sink.rows[1].0[0], Value::Text("query_finished".to_string()));

    // Reading the log is itself a query, and it is in the log.
    let own = quokka_core::events_for_query(&f.engine, outcome.query_id)
        .await
        .expect("events");
    assert_eq!(own.len(), 2);
    assert_eq!(own[0].event.connection, quokka_core::AUDIT_CONNECTION);
}

// --- M1 -----------------------------------------------------------------------------

impl Fixture {
    async fn run_with_params(
        &self,
        connection: &str,
        sql: &str,
        params: Vec<Value>,
    ) -> (Outcome, Collect) {
        let mut sink = Collect::default();
        let mut request = ExecuteRequest::new(
            connection,
            sql,
            Actor {
                kind: ActorKind::Human,
                id: "tester".to_string(),
            },
        );
        request.max_rows = u64::MAX;
        request.params = params;
        request.write = true;
        let outcome = execute(&self.engine, request, &mut sink)
            .await
            .expect("execute should report the outcome, not fail");
        (outcome, sink)
    }

    async fn catalog(&self, connection: &str, table: Option<&str>) -> quokka_core::CatalogResult {
        quokka_core::introspect(
            &self.engine,
            quokka_core::IntrospectRequest::new(
                connection,
                quokka_core::Scope {
                    table: table.map(str::to_string),
                    ..quokka_core::Scope::default()
                },
                Actor {
                    kind: ActorKind::Human,
                    id: "tester".to_string(),
                },
            ),
        )
        .await
        .expect("introspect")
    }
}

/// The SQLite driver refused bound parameters at M0, because `params` has to reach the
/// audit log under the connection's `sql_logging` mode and that plumbing did not exist.
/// It does now, so every `Value` has to make the round trip.
#[tokio::test]
async fn every_value_binds_and_comes_back_unchanged() {
    let f = fixture(&["CREATE TABLE t (a)"]).await;

    let params = vec![
        Value::Int(42),
        Value::Float(2.5),
        Value::Text("hello".to_string()),
        Value::Blob(vec![0x00, 0xff, 0x10]),
        Value::Bool(true),
    ];
    let (outcome, sink) = f
        .run_with_params("app", "SELECT ?, ?, ?, ?, ?", params.clone())
        .await;

    assert_eq!(outcome.status, Status::Ok, "{:?}", outcome.error_message);
    assert_eq!(
        sink.rows[0].0,
        vec![
            Value::Int(42),
            Value::Float(2.5),
            Value::Text("hello".to_string()),
            Value::Blob(vec![0x00, 0xff, 0x10]),
            // SQLite has no boolean storage class; a bound `true` is stored and read
            // back as 1, which is the database's answer rather than a lossy one.
            Value::Int(1),
        ]
    );
}

#[tokio::test]
async fn a_bound_null_is_null_and_not_the_string_null() {
    let f = fixture(&["CREATE TABLE t (a)", "INSERT INTO t VALUES (NULL), (1)"]).await;

    let (_, sink) = f
        .run_with_params(
            "app",
            "SELECT count(*) FROM t WHERE a IS ?",
            vec![Value::Null],
        )
        .await;
    assert_eq!(sink.rows[0].0[0], Value::Int(1));
}

/// A parameter is only honestly bound if it cannot be confused with the SQL around it.
#[tokio::test]
async fn a_parameter_is_a_value_and_never_becomes_sql() {
    let f = fixture(&[
        "CREATE TABLE t (name TEXT)",
        "INSERT INTO t VALUES ('alice'), ('bob')",
    ])
    .await;

    let (outcome, sink) = f
        .run_with_params(
            "app",
            "SELECT count(*) FROM t WHERE name = ?",
            vec![Value::Text("' OR 1=1 --".to_string())],
        )
        .await;

    assert_eq!(outcome.status, Status::Ok);
    assert_eq!(
        sink.rows[0].0[0],
        Value::Int(0),
        "the value was interpolated into the statement rather than bound to it"
    );
}

#[tokio::test]
async fn introspection_reports_tables_views_and_their_column_types() {
    let f = fixture(&[
        "CREATE TABLE orders (id INTEGER PRIMARY KEY, email TEXT NOT NULL, total REAL)",
        "CREATE VIEW big AS SELECT * FROM orders WHERE total > 5",
        "CREATE TABLE empty_columns (x)",
    ])
    .await;

    let all = f.catalog("app", None).await;
    assert!(!all.from_cache);
    let names: Vec<&str> = all.catalog.tables.iter().map(|t| t.name.as_str()).collect();
    assert_eq!(names, ["big", "empty_columns", "orders"]);
    assert_eq!(all.catalog.tables[0].kind, "view");

    let one = f.catalog("app", Some("orders")).await;
    assert_eq!(one.catalog.tables.len(), 1);
    let orders = &one.catalog.tables[0];
    assert_eq!(orders.kind, "table");
    assert_eq!(
        orders
            .columns
            .iter()
            .map(|c| (c.name.as_str(), c.driver_type.as_str(), c.nullable))
            .collect::<Vec<_>>(),
        [
            ("id", "INTEGER", Some(true)),
            ("email", "TEXT", Some(false)),
            ("total", "REAL", Some(true)),
        ]
    );

    // SQLite's internal tables are not part of anybody's schema.
    assert!(!names.iter().any(|n| n.starts_with("sqlite_")));
}

/// Invariant 10 on the driver M0 shipped, restated now that two more implement it: an
/// unrecognized declared type renders as a string rather than aborting the result set.
#[tokio::test]
async fn an_unrecognized_declared_type_renders_as_text() {
    let f = fixture(&[
        "CREATE TABLE odd (a WIBBLE, b GEOMETRY, c JSONB, d DECIMAL(10,2))",
        "INSERT INTO odd VALUES ('x', 'POINT(1 2)', '{\"k\":1}', '9.99')",
    ])
    .await;

    let (outcome, sink) = f.run("app", "SELECT a, b, c, d FROM odd").await;
    assert_eq!(outcome.status, Status::Ok, "{:?}", outcome.error_message);
    assert_eq!(sink.rows.len(), 1, "the result set was not aborted");

    for value in &sink.rows[0].0[..3] {
        assert!(
            matches!(value, Value::Text(_)),
            "an unknown type must degrade to text: {value:?}"
        );
    }
    // `DECIMAL(10,2)` is the exception that shows what SQLite's declared types are: an
    // affinity, not a type. NUMERIC affinity means the string really was stored as a
    // real, so `Float(9.99)` is the database's own answer rather than a guess of ours.
    // Postgres and MySQL, where DECIMAL is exact, deliberately keep it as text.
    assert_eq!(sink.rows[0].0[3], Value::Float(9.99));
}

/// `@audit` stays SQLite and read-only however many drivers exist.
#[tokio::test]
async fn the_audit_connection_is_still_sqlite_and_read_only() {
    let f = fixture(&["CREATE TABLE t (a INTEGER)"]).await;
    let audit = f
        .engine
        .registry()
        .get(quokka_core::AUDIT_CONNECTION)
        .expect("@audit is built in");

    assert_eq!(audit.driver, "sqlite");
    assert_eq!(audit.mode, AccessMode::ReadOnly);
    assert!(audit.builtin);
    assert_eq!(
        audit.credential,
        quokka_core::CredentialRef::None,
        "it has nothing to authenticate to, so it looks nothing up"
    );
}
