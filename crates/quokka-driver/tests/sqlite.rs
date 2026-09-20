//! SQLite driver tests.
//!
//! Note what these tests *cannot* do: call `SqliteDriver::execute` directly. It takes an
//! `ExecutePermit`, which only `quokka-core::execute()` can construct, so even the
//! driver's own test suite reaches the database through the audited path. That is
//! invariant 1 working — if this file could shortcut it, so could a surface.

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
async fn a_read_only_connection_cannot_be_written_through() {
    let f = fixture(&["CREATE TABLE t (a INTEGER)"]).await;

    let (outcome, _) = f.run("app-ro", "INSERT INTO t VALUES (1)").await;
    assert_eq!(outcome.status, Status::Error);
    assert!(
        outcome
            .error_message
            .as_deref()
            .unwrap_or_default()
            .contains("readonly"),
        "{:?}",
        outcome.error_message
    );

    // And it is logged like any other attempt.
    let events = quokka_core::events_for_query(&f.engine, outcome.query_id)
        .await
        .expect("events");
    assert_eq!(events.len(), 2);
    assert_eq!(events[1].event.status, Status::Error);
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
