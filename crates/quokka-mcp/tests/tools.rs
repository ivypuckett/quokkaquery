//! The four claims M3 makes about the MCP surface, each asserted against the log rather
//! than against a return value.
//!
//! The tools are called directly rather than over a pipe. What is under test is the
//! *behaviour* — one execution per result, a denial that is denied identically here and
//! at the CLI, a fingerprint connection's literals absent from the log — and a JSON-RPC
//! round trip would add a transport to every failure message without adding a claim.
//! The transport itself is `rmcp`'s and is tested there.

use std::sync::Arc;

use quokka_core::{AccessMode, Actor, ActorKind, AuditLog, ConnectionConfig, Engine, Registry};
use quokka_mcp::QuokkaMcp;
use rmcp::handler::server::wrapper::Parameters;
use serde_json::{json, Value as Json};

struct Harness {
    server: QuokkaMcp,
    engine: Arc<Engine>,
    _dir: tempfile::TempDir,
}

/// Two connections over one SQLite file: `app` is `read_write`, `app-ro` is not.
async fn harness(mode: AccessMode, setup: &[&str]) -> Harness {
    harness_logging(mode, setup, quokka_core::SqlLogging::Fingerprint).await
}

async fn harness_logging(
    surface_mode: AccessMode,
    setup: &[&str],
    sql_logging: quokka_core::SqlLogging,
) -> Harness {
    let dir = tempfile::tempdir().expect("tempdir");
    let app_db = dir.path().join("app.db");
    let audit_db = dir.path().join("audit.db");

    {
        let opts = sqlx::sqlite::SqliteConnectOptions::new()
            .filename(&app_db)
            .create_if_missing(true);
        let pool = sqlx::SqlitePool::connect_with(opts).await.expect("app db");
        for sql in setup {
            sqlx::query(sqlx::AssertSqlSafe(sql.to_string()))
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
        sql_logging,
        ..ConnectionConfig::new("app", "sqlite")
    });
    registry.insert(ConnectionConfig {
        path: Some(app_db),
        mode: AccessMode::ReadOnly,
        sql_logging,
        ..ConnectionConfig::new("app-ro", "sqlite")
    });

    let engine = Arc::new(Engine::new(
        registry,
        audit,
        quokka_driver::builtin_factories(),
    ));
    let spools = Arc::new(
        quokka_spool::SpoolSet::open(Some(&dir.path().join("cache")), Default::default())
            .await
            .expect("spool set"),
    );

    let server = QuokkaMcp::new(
        engine.clone(),
        spools,
        Actor {
            kind: ActorKind::Agent,
            id: "claude".to_string(),
        },
        surface_mode,
    );

    Harness {
        server,
        engine,
        _dir: dir,
    }
}

impl Harness {
    /// Call `query` with a JSON object, exactly as a client would send it.
    async fn query(&self, args: Json) -> Result<Json, rmcp::ErrorData> {
        let args = serde_json::from_value(args).expect("valid query arguments");
        self.server
            .query(Parameters(args))
            .await
            .map(|json| serde_json::to_value(json.0).expect("serializable response"))
    }

    async fn events(&self) -> Vec<quokka_audit::StoredEvent> {
        self.engine.audit().read_all().await.expect("read the log")
    }

    /// Every byte the log holds, as one string.
    async fn audit_bytes(&self) -> String {
        let events = self.events().await;
        serde_json::to_string(&events).expect("serializable log")
    }
}

fn rows(response: &Json) -> &Vec<Json> {
    response["rows"].as_array().expect("rows")
}

/// Seed enough rows that a result needs more than one page.
fn seed(rows: usize) -> Vec<String> {
    let mut sql = vec!["CREATE TABLE t (i INTEGER, label TEXT)".to_string()];
    for chunk in (0..rows).collect::<Vec<_>>().chunks(200) {
        let values: Vec<String> = chunk.iter().map(|i| format!("({i}, 'row-{i}')")).collect();
        sql.push(format!("INSERT INTO t VALUES {}", values.join(", ")));
    }
    sql
}

/// The M2 test, one layer up: paging a multi-page result over several tool calls runs
/// the query **once**, and the log holds exactly one query pair to prove it.
#[tokio::test(flavor = "multi_thread")]
async fn paging_across_tool_calls_runs_one_query() {
    let setup = seed(1200);
    let refs: Vec<&str> = setup.iter().map(String::as_str).collect();
    let h = harness(AccessMode::ReadOnly, &refs).await;

    let first = h
        .query(json!({"connection": "app", "sql": "SELECT * FROM t"}))
        .await
        .expect("first page");
    assert_eq!(rows(&first).len(), 512, "512 is the hard cap (§4.2)");
    assert_eq!(first["rows_in_view"], 1200);
    let query_id = first["query_id"].as_str().expect("query_id").to_string();

    let mut seen = rows(&first).len();
    let mut cursor = first["next_cursor"]
        .as_str()
        .expect("a next page")
        .to_string();
    let mut pages = 1;
    while let Some(next) = {
        let page = h
            .query(json!({"query_id": query_id, "cursor": cursor}))
            .await
            .expect("another page");
        seen += rows(&page).len();
        pages += 1;
        assert_eq!(
            page["query_id"].as_str(),
            Some(query_id.as_str()),
            "a page belongs to the query that produced it"
        );
        page["next_cursor"].as_str().map(str::to_string)
    } {
        cursor = next;
    }

    assert_eq!(seen, 1200, "every row was reachable, 512 at a time");
    assert_eq!(pages, 3);

    // The claim itself. Three pages, one execution.
    let events = h.events().await;
    let started = events
        .iter()
        .filter(|e| e.event.event_kind == quokka_audit::EventKind::QueryStarted)
        .count();
    let finished = events
        .iter()
        .filter(|e| e.event.event_kind == quokka_audit::EventKind::QueryFinished)
        .count();
    assert_eq!(
        (started, finished),
        (1, 1),
        "paging must read the spool, never the database: {} events",
        events.len()
    );
}

/// Sorting and filtering are reads of the spool too — `Filter`/`Op` earning the place
/// M2 built for them.
#[tokio::test(flavor = "multi_thread")]
async fn sorting_and_filtering_a_held_result_runs_nothing() {
    let setup = seed(50);
    let refs: Vec<&str> = setup.iter().map(String::as_str).collect();
    let h = harness(AccessMode::ReadOnly, &refs).await;

    let first = h
        .query(json!({"connection": "app", "sql": "SELECT * FROM t"}))
        .await
        .expect("run");
    let query_id = first["query_id"].as_str().expect("id").to_string();

    let sorted = h
        .query(json!({
            "query_id": query_id,
            "sort": [{"column": "i", "direction": "desc"}],
        }))
        .await
        .expect("sorted");
    assert_eq!(rows(&sorted)[0][0], json!(49), "sorted descending");

    let filtered = h
        .query(json!({
            "query_id": query_id,
            "filter": [{"column": "label", "op": "eq", "value": "row-7"}],
        }))
        .await
        .expect("filtered");
    assert_eq!(filtered["rows_in_view"], 1);
    assert_eq!(rows(&filtered)[0][0], json!(7));

    let events = h.events().await;
    assert_eq!(events.len(), 2, "one query pair, three reads of its spool");
}

/// A truncated result must never be handed over as though it were whole: the sentence
/// rides on the page whether the agent asked for it or not (§4.2).
#[tokio::test(flavor = "multi_thread")]
async fn a_capped_read_says_so_on_every_page() {
    let setup = seed(100);
    let refs: Vec<&str> = setup.iter().map(String::as_str).collect();
    let h = harness(AccessMode::ReadOnly, &refs).await;

    let page = h
        .query(json!({"connection": "app", "sql": "SELECT * FROM t", "max_rows": 10}))
        .await
        .expect("run");

    assert_eq!(page["whole_result"], json!(false));
    let note = page["scope_note"].as_str().expect("a scoping note");
    assert!(
        note.contains("prefix"),
        "the note must say these rows are a prefix: {note}"
    );
}

/// The mode binds both surfaces. The same write, denied identically from MCP as from the
/// CLI, against the same connection — and asking for it makes no difference.
#[tokio::test(flavor = "multi_thread")]
async fn a_write_to_a_read_only_connection_is_denied_with_the_same_code_as_the_cli() {
    let h = harness(AccessMode::ReadWrite, &["CREATE TABLE t (a INTEGER)"]).await;

    let err = h
        .query(json!({
            "connection": "app-ro",
            "sql": "INSERT INTO t VALUES (1)",
            "write": true,
        }))
        .await
        .expect_err("a write on a read-only connection must be refused");

    let data = err.data.expect("a denial carries its code");
    assert_eq!(data["denied"], json!(true));
    assert_eq!(data["code"], json!("policy.read_only"));

    // The same shape in the log as a CLI denial: two events, one query_id, and a finish
    // that says `denied` so the `queries` view does not report it unfinished.
    let events = h.events().await;
    assert_eq!(events.len(), 2);
    assert_eq!(
        events[1].event.status,
        quokka_audit::Status::Denied,
        "a denial is a finished query, not an abandoned one"
    );
    assert_eq!(events[1].event.client, quokka_audit::Client::Mcp);
    assert!(h.engine.audit().verify().await.expect("verify").is_intact());
}

/// The server's own posture narrows a connection and never widens it — the thing that
/// stops `write: true` being a permission an agent grants itself.
#[tokio::test(flavor = "multi_thread")]
async fn a_read_only_server_refuses_writes_on_a_read_write_connection() {
    let h = harness(AccessMode::ReadOnly, &["CREATE TABLE t (a INTEGER)"]).await;

    let err = h
        .query(json!({"connection": "app", "sql": "INSERT INTO t VALUES (1)", "write": true}))
        .await
        .expect_err("a read-only server must refuse the write");
    assert_eq!(
        err.data.expect("code")["code"],
        json!("policy.read_only"),
        "the connection allows it; this server does not"
    );

    // And with the posture a human chose instead, the same call goes through.
    let h = harness(AccessMode::ReadWrite, &["CREATE TABLE t (a INTEGER)"]).await;
    let ok = h
        .query(json!({"connection": "app", "sql": "INSERT INTO t VALUES (1)", "write": true}))
        .await
        .expect("a write a human allowed twice");
    assert_eq!(ok["status"], json!("ok"));
}

/// A write with no opt-in is refused even where one would have been allowed, so a
/// mis-generated statement cannot spend authority a human left in the lock.
#[tokio::test(flavor = "multi_thread")]
async fn a_write_without_the_opt_in_is_refused_on_a_writable_connection() {
    let h = harness(AccessMode::ReadWrite, &["CREATE TABLE t (a INTEGER)"]).await;

    let err = h
        .query(json!({"connection": "app", "sql": "INSERT INTO t VALUES (1)"}))
        .await
        .expect_err("no opt-in, no write");
    assert_eq!(
        err.data.expect("code")["code"],
        json!("policy.write_not_opted_in")
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn a_stacked_body_is_refused_over_mcp_too() {
    let h = harness(AccessMode::ReadWrite, &["CREATE TABLE t (a INTEGER)"]).await;

    let err = h
        .query(json!({"connection": "app", "sql": "SELECT 1; DROP TABLE t", "write": true}))
        .await
        .expect_err("stacked statements are refused whatever the mode");
    assert_eq!(
        err.data.expect("code")["code"],
        json!("policy.multiple_statements")
    );
}

/// A denial is logged under the connection's `sql_logging` like any other query — which
/// means a `fingerprint` connection's literals are absent from the log's bytes even when
/// the query was refused. This is the case where the rule would be quietly bent.
#[tokio::test(flavor = "multi_thread")]
async fn a_denial_does_not_write_literals_a_fingerprint_connection_would_not() {
    const NEEDLE: &str = "zzq-secret-4b1e9f-do-not-log";

    let h = harness(AccessMode::ReadWrite, &["CREATE TABLE t (a TEXT)"]).await;
    let err = h
        .query(json!({
            "connection": "app-ro",
            "sql": format!("INSERT INTO t VALUES ('{NEEDLE}')"),
            "write": true,
        }))
        .await
        .expect_err("denied");
    assert_eq!(err.data.expect("code")["code"], json!("policy.read_only"));

    let bytes = h.audit_bytes().await;
    assert!(
        !bytes.contains(NEEDLE),
        "a denial must not store what the connection's sql_logging forbids: {bytes}"
    );
    // And the shape still survived: the log knows what kind of statement it was and
    // against what.
    let events = h.events().await;
    assert_eq!(events[0].event.statement_kind.as_deref(), Some("insert"));
    assert!(events[0].event.sql_fingerprint.contains("INSERT INTO t"));
    assert_eq!(
        events[1].event.error_code.as_deref(),
        Some("policy.read_only")
    );
}

/// At `full`, the same denial keeps the text — because that is what the connection asked
/// for, not because it was denied.
#[tokio::test(flavor = "multi_thread")]
async fn a_full_connection_keeps_the_text_of_a_denied_statement() {
    const NEEDLE: &str = "zzq-visible-1a2b3c";

    let h = harness_logging(
        AccessMode::ReadWrite,
        &["CREATE TABLE t (a TEXT)"],
        quokka_core::SqlLogging::Full,
    )
    .await;
    h.query(json!({
        "connection": "app-ro",
        "sql": format!("INSERT INTO t VALUES ('{NEEDLE}')"),
        "write": true,
    }))
    .await
    .expect_err("denied");

    assert!(
        h.audit_bytes().await.contains(NEEDLE),
        "at sql_logging = full the denial keeps the statement, like any other query"
    );
}

/// The tools §6.2 names, all present and all reachable.
#[tokio::test(flavor = "multi_thread")]
async fn the_server_offers_exactly_the_tools_the_architecture_lists() {
    let h = harness(AccessMode::ReadOnly, &["CREATE TABLE t (a INTEGER)"]).await;
    let router = QuokkaMcp::tool_router();
    let mut names: Vec<String> = router
        .list_all()
        .into_iter()
        .map(|t| t.name.to_string())
        .collect();
    names.sort();
    assert_eq!(
        names,
        vec![
            "describe_table",
            "explain",
            "export",
            "list_connections",
            "list_schemas",
            "query",
            "search_audit",
        ]
    );

    // And nothing that changes configuration (invariant 7).
    for forbidden in ["set_mode", "set_sql_logging", "configure", "set_budget"] {
        assert!(
            !names.iter().any(|n| n == forbidden),
            "an agent must not be able to widen its own guardrail"
        );
    }
    drop(h);
}

#[tokio::test(flavor = "multi_thread")]
async fn describe_table_and_list_schemas_read_the_catalog() {
    let h = harness(
        AccessMode::ReadOnly,
        &["CREATE TABLE orders (id INTEGER, email TEXT)"],
    )
    .await;

    let schemas = h
        .server
        .list_schemas(Parameters(
            serde_json::from_value(json!({"connection": "app"})).expect("args"),
        ))
        .await
        .expect("list_schemas");
    let json = serde_json::to_value(schemas.0).expect("json");
    assert_eq!(json["schemas"][0]["tables"][0]["name"], json!("orders"));

    let described = h
        .server
        .describe_table(Parameters(
            serde_json::from_value(json!({"connection": "app", "table": "orders"})).expect("args"),
        ))
        .await
        .expect("describe_table");
    let json = serde_json::to_value(described.0).expect("json");
    assert_eq!(json["tables"][0]["columns"][1]["name"], json!("email"));

    // §5: one `introspect` event per refresh, never a query pair. Two so far, because
    // the catalog is cached per *scope* and those were two different scopes.
    let events = h.events().await;
    assert_eq!(events.len(), 2);
    assert!(events
        .iter()
        .all(|e| e.event.event_kind == quokka_audit::EventKind::Introspect));

    // And the rule that matters for a long-lived process: the same scope again is
    // answered from the cache, and **a cache hit appends nothing at all**. In a CLI this
    // never happens — the process is younger than the TTL — so the MCP server is the
    // first surface where it is more than a claim.
    let again = h
        .server
        .describe_table(Parameters(
            serde_json::from_value(json!({"connection": "app", "table": "orders"})).expect("args"),
        ))
        .await
        .expect("describe_table again");
    assert_eq!(
        serde_json::to_value(again.0).expect("json")["from_cache"],
        json!(true)
    );
    assert_eq!(
        h.events().await.len(),
        2,
        "a catalog cache hit reaches no database, so it describes nothing"
    );
}

/// `search_audit` is an ordinary audited query against `@audit`, which is the point of
/// shipping the log as a connection rather than as a second API.
#[tokio::test(flavor = "multi_thread")]
async fn search_audit_finds_a_denial_and_is_itself_logged() {
    let h = harness(AccessMode::ReadWrite, &["CREATE TABLE t (a INTEGER)"]).await;
    h.query(json!({"connection": "app-ro", "sql": "DELETE FROM t", "write": true}))
        .await
        .expect_err("denied");

    let found = h
        .server
        .search_audit(Parameters(
            serde_json::from_value(json!({"status": "denied"})).expect("args"),
        ))
        .await
        .expect("search_audit");
    let json = serde_json::to_value(found.0).expect("json");
    assert_eq!(json["rows_in_view"], 1, "the denial is findable");

    let events = h.events().await;
    let against_audit = events
        .iter()
        .filter(|e| e.event.connection == quokka_core::AUDIT_CONNECTION)
        .count();
    assert_eq!(against_audit, 2, "reading the log is a logged query");
}

/// `explain` over MCP: a plan, and a query pair, and no rows run.
#[tokio::test(flavor = "multi_thread")]
async fn explain_returns_a_plan_and_is_audited() {
    let h = harness(
        AccessMode::ReadOnly,
        &["CREATE TABLE t (a INTEGER PRIMARY KEY)"],
    )
    .await;

    let plan = h
        .server
        .explain(Parameters(
            serde_json::from_value(json!({"connection": "app", "sql": "SELECT * FROM t"}))
                .expect("args"),
        ))
        .await
        .expect("explain");
    let json = serde_json::to_value(plan.0).expect("json");
    assert!(!json["plan"].as_str().expect("plan text").is_empty());

    let events = h.events().await;
    assert_eq!(events.len(), 2);
    assert_eq!(events[0].event.statement_kind.as_deref(), Some("explain"));
}

/// An export over MCP goes through `record_export` — the trap does not stop applying
/// because the caller is an agent — and reads the spool rather than the database.
#[tokio::test(flavor = "multi_thread")]
async fn export_writes_the_whole_result_and_logs_one_event() {
    let setup = seed(600);
    let refs: Vec<&str> = setup.iter().map(String::as_str).collect();
    let h = harness(AccessMode::ReadOnly, &refs).await;

    let first = h
        .query(json!({"connection": "app", "sql": "SELECT * FROM t"}))
        .await
        .expect("run");
    let query_id = first["query_id"].as_str().expect("id").to_string();

    let out = h._dir.path().join("out.csv");
    let report = h
        .server
        .export(Parameters(
            serde_json::from_value(json!({
                "query_id": query_id,
                "path": out.to_string_lossy(),
                "format": "csv",
            }))
            .expect("args"),
        ))
        .await
        .expect("export");
    let json = serde_json::to_value(report.0).expect("json");
    assert_eq!(json["rows"], 600, "the file is not capped at a page");

    let written = std::fs::read_to_string(&out).expect("the file exists");
    assert_eq!(written.lines().count(), 601, "600 rows and a header");

    let events = h.events().await;
    let exports: Vec<_> = events
        .iter()
        .filter(|e| e.event.event_kind == quokka_audit::EventKind::Export)
        .collect();
    assert_eq!(exports.len(), 1, "one export event, after the fact (§5)");
    assert_eq!(
        exports[0].event.parent_id.map(|id| id.to_string()),
        Some(query_id),
        "linked to the query whose rows these are"
    );
    // Invariant 4: a count, never a row.
    let bytes = h.audit_bytes().await;
    assert!(!bytes.contains("row-599"), "no result data in the log");

    // Still one query pair: the export read the spool.
    let started = events
        .iter()
        .filter(|e| e.event.event_kind == quokka_audit::EventKind::QueryStarted)
        .count();
    assert_eq!(started, 1);
}

/// Asking for two things at once is refused rather than guessed at, because one of the
/// guesses would cost a second scan.
#[tokio::test(flavor = "multi_thread")]
async fn sql_and_a_query_id_together_are_refused() {
    let h = harness(AccessMode::ReadOnly, &["CREATE TABLE t (a INTEGER)"]).await;
    let first = h
        .query(json!({"connection": "app", "sql": "SELECT * FROM t"}))
        .await
        .expect("run");
    let query_id = first["query_id"].as_str().expect("id").to_string();

    let err = h
        .query(json!({"connection": "app", "sql": "SELECT * FROM t", "query_id": query_id}))
        .await
        .expect_err("ambiguous");
    assert!(err.message.contains("second scan"), "{}", err.message);
}

/// The bound the CLI never needed. A server that held every result would grow until the
/// disk did; the oldest goes, and the next call naming it is told so rather than being
/// handed an empty page.
#[tokio::test(flavor = "multi_thread")]
async fn the_oldest_held_result_is_released_and_says_so() {
    let h = harness(AccessMode::ReadOnly, &["CREATE TABLE t (a INTEGER)"]).await;

    let first = h
        .query(json!({"connection": "app", "sql": "SELECT 1 AS n"}))
        .await
        .expect("run");
    let oldest = first["query_id"].as_str().expect("id").to_string();

    // One more than the cache holds, so the first one is pushed out.
    for i in 0..quokka_mcp::MAX_HELD_RESULTS {
        h.query(json!({"connection": "app", "sql": format!("SELECT {i} AS n")}))
            .await
            .expect("run");
    }

    let err = h
        .query(json!({"query_id": oldest}))
        .await
        .expect_err("that result is gone");
    assert!(
        err.message.contains("most recent"),
        "the message should say what happened: {}",
        err.message
    );

    // And the newest is still there, which is the half that makes the bound useful.
    let newest = h
        .query(json!({"connection": "app", "sql": "SELECT 'last' AS n"}))
        .await
        .expect("run");
    let id = newest["query_id"].as_str().expect("id").to_string();
    assert_eq!(
        rows(&h.query(json!({"query_id": id})).await.expect("still held")).len(),
        1
    );
}
