//! Container-backed tests for the wire-protocol drivers (§9).
//!
//! Behind the `docker-tests` feature, so the default `cargo test` still needs no Docker:
//!
//! ```console
//! $ cargo test -p quokka-driver --features docker-tests
//! ```
//!
//! These exist because the things most worth checking about a Postgres or MySQL driver
//! cannot be checked against a fake. Whether an `hstore` degrades to a string rather than
//! aborting a result set, whether `default_transaction_read_only` actually refuses a
//! write, whether a bound NULL reaches an `integer` column without a type error, and
//! whether a rejected password stays out of the error text — every one of those is a
//! claim about a real server.
//!
//! Note what these tests still cannot do: call a driver directly. `Driver::execute`
//! takes an `ExecutePermit` that only `quokka-core::execute()` can construct, so even
//! here the database is reached through the audited path.
#![cfg(feature = "docker-tests")]

use quokka_core::{
    execute, introspect, AccessMode, Actor, ActorKind, AuditLog, Catalog, Column, ConnectionConfig,
    CredentialRef, Engine, EventKind, ExecuteRequest, IntrospectRequest, Outcome, Registry, Row,
    RowSink, Scope, SqlLogging, Status, TlsMode, Value,
};
use testcontainers::runners::AsyncRunner;
use testcontainers::{ContainerAsync, ImageExt};

const PASSWORD: &str = "correct-horse-battery-staple";

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
    engine: Engine,
    _dir: tempfile::TempDir,
}

impl Fixture {
    /// One read-write connection named `db` and one read-only connection named `db-ro`
    /// to the same server.
    fn new(
        dir: tempfile::TempDir,
        driver: &str,
        port: u16,
        user: &str,
        database: &str,
        credential: CredentialRef,
        audit: AuditLog,
    ) -> Self {
        let base = |name: &str, mode: AccessMode| ConnectionConfig {
            host: Some("127.0.0.1".to_string()),
            port: Some(port),
            user: Some(user.to_string()),
            database: Some(database.to_string()),
            credential: credential.clone(),
            // The containers speak plaintext; TLS variance is not what these test.
            tls: TlsMode::Disable,
            mode,
            sql_logging: SqlLogging::Full,
            ..ConnectionConfig::new(name, driver)
        };

        let mut registry = Registry::builtin_only(dir.path().join("audit.db").as_path());
        registry.insert(base("db", AccessMode::ReadWrite));
        registry.insert(base("db-ro", AccessMode::ReadOnly));

        Fixture {
            engine: Engine::new(registry, audit, quokka_driver::builtin_factories()),
            _dir: dir,
        }
    }

    async fn run(&self, connection: &str, sql: &str) -> (Outcome, Collect) {
        self.run_with(connection, sql, Vec::new()).await
    }

    async fn run_with(
        &self,
        connection: &str,
        sql: &str,
        params: Vec<Value>,
    ) -> (Outcome, Collect) {
        let mut sink = Collect::default();
        let mut request = ExecuteRequest::new(connection, sql, actor());
        request.max_rows = u64::MAX;
        request.params = params;
        // Driver tests, not policy tests: the guardrail is exercised in
        // `quokka-policy`'s corpus and in the surface tests, and what is under
        // examination here is what a real server does with a statement.
        request.write = true;
        let outcome = execute(&self.engine, request, &mut sink)
            .await
            .expect("execute reports the outcome rather than failing");
        (outcome, sink)
    }

    async fn catalog(&self, connection: &str, table: Option<&str>) -> Catalog {
        introspect(
            &self.engine,
            IntrospectRequest::new(
                connection,
                Scope {
                    table: table.map(str::to_string),
                    ..Scope::default()
                },
                actor(),
            ),
        )
        .await
        .expect("introspect")
        .catalog
    }

    async fn events(&self) -> Vec<quokka_audit::StoredEvent> {
        self.engine.audit().read_all().await.expect("read the log")
    }
}

fn actor() -> Actor {
    Actor {
        kind: ActorKind::Agent,
        id: "claude".to_string(),
    }
}

/// Set a process-unique environment variable and hand back a reference to it.
///
/// The container's password has to reach the driver the way a real one would — through
/// `credential::resolve` — and an environment variable is the one store a test can plant
/// without touching the developer's actual keyring.
fn env_credential(var: &'static str) -> CredentialRef {
    std::env::set_var(var, PASSWORD);
    CredentialRef::Env {
        var: var.to_string(),
    }
}

// --- PostgreSQL ---------------------------------------------------------------------

async fn postgres(
    var: &'static str,
) -> (
    ContainerAsync<testcontainers_modules::postgres::Postgres>,
    Fixture,
) {
    let container = testcontainers_modules::postgres::Postgres::default()
        .with_user("quokka")
        .with_password(PASSWORD)
        .with_db_name("app")
        // Pinned rather than left to the module's default, so the compatibility matrix
        // in the README names a version somebody actually ran against (§3.0).
        .with_tag("16-alpine")
        .start()
        .await
        .expect("start postgres");
    let port = container
        .get_host_port_ipv4(5432)
        .await
        .expect("postgres port");

    let dir = tempfile::tempdir().expect("tempdir");
    let audit = AuditLog::open(dir.path().join("audit.db"))
        .await
        .expect("audit log");
    let fixture = Fixture::new(
        dir,
        "postgres",
        port,
        "quokka",
        "app",
        env_credential(var),
        audit,
    );
    (container, fixture)
}

#[tokio::test]
async fn postgres_runs_a_query_end_to_end_and_logs_both_events() {
    let (_c, f) = postgres("QUOKKA_TEST_PG_1").await;

    let (outcome, sink) = f.run("db", "SELECT 1 AS n, 'hello' AS s").await;
    assert_eq!(outcome.status, Status::Ok, "{:?}", outcome.error_message);
    assert_eq!(sink.rows[0].0[0], Value::Int(1));
    assert_eq!(sink.rows[0].0[1], Value::Text("hello".to_string()));
    assert_eq!(sink.columns[0].driver_type, "INT4");

    let events = f.events().await;
    assert_eq!(events.len(), 2, "one query, two events");
    assert_eq!(events[0].event.event_kind, EventKind::QueryStarted);
    assert_eq!(events[1].event.event_kind, EventKind::QueryFinished);
    assert_eq!(events[1].event.rows_returned, Some(1));
    assert_eq!(events[0].event.dialect, "postgres");
    assert!(f.engine.audit().verify().await.expect("verify").is_intact());
}

/// §3.0 hedge 1, on the driver where it actually bites. None of these types has a
/// `Value` variant; every one of them must come back as a string rather than aborting
/// the result set (invariant 10).
#[tokio::test]
async fn postgres_renders_every_exotic_type_as_text_rather_than_failing() {
    let (_c, f) = postgres("QUOKKA_TEST_PG_2").await;

    let (setup, _) = f
        .run(
            "db",
            "CREATE EXTENSION IF NOT EXISTS hstore; \
             CREATE TYPE mood AS ENUM ('sad', 'ok', 'happy'); \
             CREATE TYPE point3 AS (x int, y int, z int);",
        )
        .await;
    assert_eq!(setup.status, Status::Ok, "{:?}", setup.error_message);

    let (outcome, sink) = f
        .run(
            "db",
            "SELECT 'happy'::mood                         AS an_enum,
                    ARRAY[1,2,3]                          AS an_array,
                    int4range(1, 10)                      AS a_range,
                    'a=>1,b=>2'::hstore                   AS an_hstore,
                    ROW(1,2,3)::point3                    AS a_composite,
                    '1 day 3 hours'::interval             AS an_interval,
                    '{\"k\": [1,2]}'::jsonb               AS some_jsonb,
                    12345678901234567890.0987654321::numeric AS exact,
                    '192.168.0.1/24'::inet                AS an_inet,
                    to_tsvector('english', 'the quick fox') AS a_tsvector,
                    '11111111-2222-3333-4444-555555555555'::uuid AS a_uuid",
        )
        .await;

    assert_eq!(outcome.status, Status::Ok, "{:?}", outcome.error_message);
    assert_eq!(sink.rows.len(), 1, "the result set was not aborted");
    for (column, value) in sink.columns.iter().zip(&sink.rows[0].0) {
        assert!(
            matches!(value, Value::Text(_)),
            "{} ({}) did not degrade to text: {value:?}",
            column.name,
            column.driver_type
        );
    }

    // Degrading to text is only useful if the text is the server's own rendering.
    let by_name = |name: &str| {
        let i = sink
            .columns
            .iter()
            .position(|c| c.name == name)
            .unwrap_or_else(|| panic!("no column {name}"));
        sink.rows[0].0[i].to_string()
    };
    assert_eq!(by_name("an_enum"), "happy");
    assert_eq!(by_name("an_array"), "{1,2,3}");
    assert_eq!(by_name("a_range"), "[1,10)");
    assert_eq!(by_name("a_composite"), "(1,2,3)");
    assert_eq!(
        by_name("exact"),
        "12345678901234567890.0987654321",
        "an exact numeric must not be rounded through an f64"
    );

    // And the driver still names the type, even for one it cannot decode.
    let types: Vec<&str> = sink
        .columns
        .iter()
        .map(|c| c.driver_type.as_str())
        .collect();
    assert!(types.contains(&"mood"), "{types:?}");
    assert!(types.contains(&"hstore"), "{types:?}");
}

#[tokio::test]
async fn postgres_binds_parameters_including_a_null_of_inferred_type() {
    let (_c, f) = postgres("QUOKKA_TEST_PG_3").await;

    f.run(
        "db",
        "CREATE TABLE t (id int, name text, weight double precision, raw bytea)",
    )
    .await;
    let (insert, _) = f
        .run_with(
            "db",
            "INSERT INTO t VALUES ($1, $2, $3, $4)",
            vec![
                Value::Int(1),
                Value::Text("alice".to_string()),
                Value::Float(2.5),
                Value::Blob(vec![0x00, 0xff]),
            ],
        )
        .await;
    assert_eq!(insert.status, Status::Ok, "{:?}", insert.error_message);
    assert_eq!(insert.rows_affected, Some(1));

    let (outcome, sink) = f
        .run_with(
            "db",
            "SELECT name, weight, raw FROM t WHERE id = $1",
            vec![Value::Int(1)],
        )
        .await;
    assert_eq!(outcome.status, Status::Ok, "{:?}", outcome.error_message);
    assert_eq!(sink.rows[0].0[0], Value::Text("alice".to_string()));
    assert_eq!(sink.rows[0].0[1], Value::Float(2.5));
    assert_eq!(sink.rows[0].0[2], Value::Blob(vec![0x00, 0xff]));

    // The reason `InferredNull` exists: sqlx takes a parameter's type from what was
    // bound, so a NULL sent as `text` would fail here with "operator does not exist:
    // integer = text". Type OID 0 asks the server to work it out, which is what the
    // person who wrote NULL meant.
    let (nulls, sink) = f
        .run_with(
            "db",
            "SELECT count(*) FROM t WHERE id IS NOT DISTINCT FROM $1",
            vec![Value::Null],
        )
        .await;
    assert_eq!(nulls.status, Status::Ok, "{:?}", nulls.error_message);
    assert_eq!(sink.rows[0].0[0], Value::Int(0));

    // A parameter is a value, never SQL.
    let (injected, sink) = f
        .run_with(
            "db",
            "SELECT count(*) FROM t WHERE name = $1",
            vec![Value::Text("' OR 1=1 --".to_string())],
        )
        .await;
    assert_eq!(injected.status, Status::Ok);
    assert_eq!(sink.rows[0].0[0], Value::Int(0));
}

#[tokio::test]
async fn postgres_introspection_leaves_exactly_one_event() {
    let (_c, f) = postgres("QUOKKA_TEST_PG_4").await;

    f.run(
        "db",
        "CREATE TABLE orders (id serial PRIMARY KEY, email text NOT NULL, \
         total numeric(10,2), tags text[]); \
         CREATE VIEW big AS SELECT * FROM orders;",
    )
    .await;

    let before = f.events().await.len();
    let catalog = f.catalog("db", Some("orders")).await;
    let after = f.events().await;

    assert_eq!(
        after.len() - before,
        1,
        "a refresh appends one row, never a pair"
    );
    assert_eq!(
        after.last().expect("event").event.event_kind,
        EventKind::Introspect
    );

    assert_eq!(catalog.tables.len(), 1);
    let orders = &catalog.tables[0];
    assert_eq!(orders.name, "orders");
    assert_eq!(orders.schema.as_deref(), Some("public"));
    assert_eq!(orders.kind, "table");
    assert_eq!(
        orders
            .columns
            .iter()
            .map(|c| (c.name.as_str(), c.driver_type.as_str(), c.nullable))
            .collect::<Vec<_>>(),
        [
            ("id", "integer", Some(false)),
            ("email", "text", Some(false)),
            // format_type, not information_schema.data_type: the parameters survive.
            ("total", "numeric(10,2)", Some(true)),
            ("tags", "text[]", Some(true)),
        ]
    );

    let all = f.catalog("db", None).await;
    let kinds: Vec<(&str, &str)> = all
        .tables
        .iter()
        .map(|t| (t.name.as_str(), t.kind.as_str()))
        .collect();
    assert!(kinds.contains(&("big", "view")), "{kinds:?}");
}

/// Invariant 9's *lower* layer: the server refuses the write, not us declining to send
/// it.
///
/// This reaches past `quokka-policy` on purpose. M3's classifier refuses a write on a
/// `read_only` connection before a driver is opened, which is the layer an agent meets;
/// the guarantee is that both layers hold, so this one is asserted where it lives —
/// against a real server, with `default_transaction_read_only` doing the refusing.
#[tokio::test]
async fn postgres_read_only_is_refused_by_the_server_itself() {
    let (_c, f) = postgres("QUOKKA_TEST_PG_5").await;
    f.run("db", "CREATE TABLE t (a int)").await;

    let cfg = f
        .engine
        .registry()
        .get("db-ro")
        .cloned()
        .expect("the read-only connection");
    let driver = <quokka_driver::postgres::PostgresDriver as quokka_core::Driver>::connect(&cfg)
        .await
        .expect("open the read-only connection");

    let err = sqlx::query("INSERT INTO t VALUES (1)")
        .execute(driver.pool())
        .await
        .expect_err("the server must refuse a write on a read-only session");
    let message = err.to_string().to_lowercase();
    assert!(
        message.contains("read-only") || message.contains("read only"),
        "the server should refuse it, not the client: {message}"
    );

    postgres_read_only_is_also_refused_before_the_driver(&f).await;
}

/// And the layer above it, on the same connection and the same container: the write never
/// reaches the driver, and the attempt is a `denied` pair in the log rather than an error
/// from the server. Both halves in one test because the claim is that both hold.
async fn postgres_read_only_is_also_refused_before_the_driver(f: &Fixture) {
    let mut sink = Collect::default();
    let mut request = ExecuteRequest::new("db-ro", "INSERT INTO t VALUES (1)", actor());
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

    let events = f.events().await;
    let pair: Vec<_> = events
        .iter()
        .filter(|e| e.event.query_id == query_id)
        .collect();
    assert_eq!(pair.len(), 2);
    assert_eq!(pair[0].event.event_kind, EventKind::QueryStarted);
    assert_eq!(pair[1].event.event_kind, EventKind::QueryFinished);
    assert_eq!(pair[1].event.status, Status::Denied);
}

async fn mysql_read_only_is_also_refused_before_the_driver(f: &Fixture) {
    let mut sink = Collect::default();
    let mut request = ExecuteRequest::new("db-ro", "INSERT INTO t VALUES (1)", actor());
    request.write = true;

    let err = execute(&f.engine, request, &mut sink)
        .await
        .expect_err("a write on a read-only connection must not run");
    assert!(
        matches!(&err, quokka_core::CoreError::Denied { code, .. } if *code == "policy.read_only"),
        "{err:?}"
    );
}

/// `quokka explain` against a real Postgres: a plan comes back, and asking for it is a
/// query pair like any other (invariant 1).
#[tokio::test]
async fn postgres_explain_returns_a_plan_on_the_audited_path() {
    let (_c, f) = postgres("QUOKKA_TEST_PG_8").await;
    f.run("db", "CREATE TABLE t (a int)").await;

    let outcome = quokka_core::explain(
        &f.engine,
        quokka_core::ExplainRequest::new("db", "SELECT * FROM t WHERE a = 1", actor()),
    )
    .await
    .expect("explain");

    assert!(
        outcome.plan.text.to_lowercase().contains("scan"),
        "a Postgres plan should mention a scan: {:?}",
        outcome.plan.text
    );

    let events = f.events().await;
    let pair: Vec<_> = events
        .iter()
        .filter(|e| e.event.query_id == outcome.query_id)
        .collect();
    assert_eq!(pair.len(), 2);
    assert_eq!(pair[0].event.statement_kind.as_deref(), Some("explain"));
}

#[tokio::test]
async fn postgres_a_rejected_password_never_appears_in_the_error_or_the_log() {
    let (_c, mut f) = postgres("QUOKKA_TEST_PG_6").await;

    // Point a third connection at the same server with a credential that is wrong but
    // present, so the failure happens after the password was read rather than before.
    std::env::set_var("QUOKKA_TEST_PG_6_BAD", "definitely-the-wrong-password");
    let good = f.engine.registry().get("db").expect("db").clone();
    let mut registry = f.engine.registry().clone();
    registry.insert(ConnectionConfig {
        credential: CredentialRef::Env {
            var: "QUOKKA_TEST_PG_6_BAD".to_string(),
        },
        ..ConnectionConfig {
            name: "bad".to_string(),
            ..good
        }
    });
    let audit = f.engine.audit().clone();
    f = Fixture {
        engine: Engine::new(registry, audit, quokka_driver::builtin_factories()),
        _dir: f._dir,
    };

    let (outcome, _) = f.run("bad", "SELECT 1").await;
    assert_eq!(outcome.status, Status::Error);

    let message = outcome.error_message.clone().unwrap_or_default();
    assert!(
        !message.contains("definitely-the-wrong-password"),
        "the connection error carried the credential: {message}"
    );
    assert!(
        message.contains("quokka@127.0.0.1"),
        "it should still say what it could not reach: {message}"
    );

    let dump = format!("{:?}", f.events().await);
    assert!(
        !dump.contains("definitely-the-wrong-password"),
        "the audit log holds the credential"
    );
}

// --- MySQL --------------------------------------------------------------------------

async fn mysql(
    var: &'static str,
) -> (
    ContainerAsync<testcontainers_modules::mysql::Mysql>,
    Fixture,
) {
    let container = testcontainers_modules::mysql::Mysql::default()
        .with_tag("8.4")
        .with_env_var("MYSQL_ROOT_PASSWORD", PASSWORD)
        .start()
        .await
        .expect("start mysql");
    let port = container
        .get_host_port_ipv4(3306)
        .await
        .expect("mysql port");

    let dir = tempfile::tempdir().expect("tempdir");
    let audit = AuditLog::open(dir.path().join("audit.db"))
        .await
        .expect("audit log");
    let fixture = Fixture::new(
        dir,
        "mysql",
        port,
        "root",
        "test",
        env_credential(var),
        audit,
    );
    (container, fixture)
}

#[tokio::test]
async fn mysql_runs_a_query_end_to_end_and_logs_both_events() {
    let (_c, f) = mysql("QUOKKA_TEST_MY_1").await;

    let (outcome, sink) = f.run("db", "SELECT 1 AS n, 'hello' AS s").await;
    assert_eq!(outcome.status, Status::Ok, "{:?}", outcome.error_message);
    assert_eq!(sink.rows[0].0[0], Value::Int(1));
    assert_eq!(sink.rows[0].0[1], Value::Text("hello".to_string()));

    let events = f.events().await;
    assert_eq!(events.len(), 2);
    assert_eq!(events[0].event.dialect, "mysql");
    assert!(f.engine.audit().verify().await.expect("verify").is_intact());
}

#[tokio::test]
async fn mysql_renders_every_exotic_type_as_text_rather_than_failing() {
    let (_c, f) = mysql("QUOKKA_TEST_MY_2").await;

    let (outcome, sink) = f
        .run(
            "db",
            "SELECT CAST('9999999999.12345' AS DECIMAL(20,5)) AS exact,
                    CAST('{\"k\": [1,2]}' AS JSON)            AS some_json,
                    ST_GeomFromText('POINT(1 2)')             AS a_point,
                    CAST('2026-01-02' AS DATE)                AS a_date,
                    CAST('12:34:56' AS TIME)                  AS a_time,
                    b'1010'                                   AS some_bits,
                    CAST('x' AS CHAR(1))                      AS a_char",
        )
        .await;

    assert_eq!(outcome.status, Status::Ok, "{:?}", outcome.error_message);
    assert_eq!(sink.rows.len(), 1, "the result set was not aborted");

    let by_name = |name: &str| {
        let i = sink
            .columns
            .iter()
            .position(|c| c.name == name)
            .unwrap_or_else(|| panic!("no column {name}"));
        &sink.rows[0].0[i]
    };
    assert_eq!(
        by_name("exact"),
        &Value::Text("9999999999.12345".to_string()),
        "an exact decimal must not be rounded through an f64"
    );
    assert!(matches!(by_name("some_json"), Value::Text(_)));
    assert!(matches!(by_name("a_date"), Value::Text(_)));
    // A geometry is binary and not UTF-8, so it renders as hex rather than aborting.
    assert!(
        matches!(by_name("a_point"), Value::Text(t) if !t.is_empty()),
        "{:?}",
        by_name("a_point")
    );
}

#[tokio::test]
async fn mysql_binds_parameters() {
    let (_c, f) = mysql("QUOKKA_TEST_MY_3").await;

    f.run(
        "db",
        "CREATE TABLE t (id int, name varchar(64), weight double, raw varbinary(16))",
    )
    .await;
    let (insert, _) = f
        .run_with(
            "db",
            "INSERT INTO t VALUES (?, ?, ?, ?)",
            vec![
                Value::Int(1),
                Value::Text("alice".to_string()),
                Value::Float(2.5),
                Value::Blob(vec![0x00, 0xff]),
            ],
        )
        .await;
    assert_eq!(insert.status, Status::Ok, "{:?}", insert.error_message);
    assert_eq!(insert.rows_affected, Some(1));

    let (outcome, sink) = f
        .run_with(
            "db",
            "SELECT name, weight, raw FROM t WHERE id = ?",
            vec![Value::Int(1)],
        )
        .await;
    assert_eq!(outcome.status, Status::Ok, "{:?}", outcome.error_message);
    assert_eq!(sink.rows[0].0[0], Value::Text("alice".to_string()));
    assert_eq!(sink.rows[0].0[1], Value::Float(2.5));
    assert_eq!(sink.rows[0].0[2], Value::Blob(vec![0x00, 0xff]));

    let (nulls, sink) = f
        .run_with(
            "db",
            "SELECT count(*) FROM t WHERE id <=> ?",
            vec![Value::Null],
        )
        .await;
    assert_eq!(nulls.status, Status::Ok, "{:?}", nulls.error_message);
    assert_eq!(sink.rows[0].0[0], Value::Int(0));
}

#[tokio::test]
async fn mysql_introspection_leaves_exactly_one_event() {
    let (_c, f) = mysql("QUOKKA_TEST_MY_4").await;

    f.run(
        "db",
        "CREATE TABLE orders (id int PRIMARY KEY, email varchar(64) NOT NULL, \
         total decimal(10,2), mood enum('sad','ok','happy'))",
    )
    .await;

    let before = f.events().await.len();
    let catalog = f.catalog("db", Some("orders")).await;
    let after = f.events().await;

    assert_eq!(after.len() - before, 1, "one refresh, one row");
    assert_eq!(
        after.last().expect("event").event.event_kind,
        EventKind::Introspect
    );

    let orders = &catalog.tables[0];
    assert_eq!(orders.name, "orders");
    assert_eq!(orders.database.as_deref(), Some("test"));
    assert_eq!(
        orders
            .columns
            .iter()
            .map(|c| (c.name.as_str(), c.driver_type.as_str(), c.nullable))
            .collect::<Vec<_>>(),
        [
            ("id", "int", Some(false)),
            // COLUMN_TYPE, not DATA_TYPE: the parameters and the enum's labels survive.
            ("email", "varchar(64)", Some(false)),
            ("total", "decimal(10,2)", Some(true)),
            ("mood", "enum('sad','ok','happy')", Some(true)),
        ]
    );
}

/// The same pair of layers on MySQL, where the lower one is `SET SESSION TRANSACTION
/// READ ONLY` rather than `default_transaction_read_only`.
#[tokio::test]
async fn mysql_read_only_is_refused_by_the_server_itself() {
    let (_c, f) = mysql("QUOKKA_TEST_MY_5").await;
    f.run("db", "CREATE TABLE t (a int)").await;

    let cfg = f
        .engine
        .registry()
        .get("db-ro")
        .cloned()
        .expect("the read-only connection");
    let driver = <quokka_driver::mysql::MySqlDriver as quokka_core::Driver>::connect(&cfg)
        .await
        .expect("open the read-only connection");

    let err = sqlx::query("INSERT INTO t VALUES (1)")
        .execute(driver.pool())
        .await
        .expect_err("the server must refuse a write on a read-only session");
    let message = err.to_string().to_lowercase();
    assert!(
        message.contains("read only") || message.contains("read-only"),
        "the server should refuse it, not the client: {message}"
    );

    mysql_read_only_is_also_refused_before_the_driver(&f).await;
}

#[tokio::test]
async fn mysql_explain_returns_a_plan_on_the_audited_path() {
    let (_c, f) = mysql("QUOKKA_TEST_MY_7").await;
    f.run("db", "CREATE TABLE t (a int)").await;

    let outcome = quokka_core::explain(
        &f.engine,
        quokka_core::ExplainRequest::new("db", "SELECT * FROM t WHERE a = 1", actor()),
    )
    .await
    .expect("explain");

    assert!(
        !outcome.plan.text.is_empty(),
        "MySQL should have said something about the plan"
    );

    let events = f.events().await;
    let pair: Vec<_> = events
        .iter()
        .filter(|e| e.event.query_id == outcome.query_id)
        .collect();
    assert_eq!(pair.len(), 2);
    assert_eq!(pair[0].event.statement_kind.as_deref(), Some("explain"));
}
