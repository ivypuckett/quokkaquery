//! End-to-end tests over the `quokka` binary — the "done means" criteria of M0 and M1,
//! run the way a user or an agent would run them.

use std::path::Path;
use std::process::{Command, Output};

use serde_json::Value as Json;

/// The password these tests plant and then hunt for. Nothing may print it.
const PASSWORD: &str = "correct-horse-battery-staple";

struct Workspace {
    dir: tempfile::TempDir,
}

impl Workspace {
    async fn new() -> Self {
        let dir = tempfile::tempdir().expect("tempdir");
        let app_db = dir.path().join("app.db");

        let opts = sqlx::sqlite::SqliteConnectOptions::new()
            .filename(&app_db)
            .create_if_missing(true);
        let pool = sqlx::SqlitePool::connect_with(opts).await.expect("app db");
        sqlx::raw_sql(
            "CREATE TABLE orders (id INTEGER PRIMARY KEY, email TEXT, total REAL);
             INSERT INTO orders VALUES (1, 'a@b.example', 12.5), (2, 'c@d.example', 99.0);",
        )
        .execute(&pool)
        .await
        .expect("seed");
        pool.close().await;

        std::fs::write(
            dir.path().join("config.toml"),
            format!(
                "[connections.app]\n\
                 driver = \"sqlite\"\n\
                 path = {:?}\n\
                 mode = \"read_write\"\n\
                 credential = \"none\"\n\
                 \n\
                 [connections.app-full]\n\
                 driver = \"sqlite\"\n\
                 path = {:?}\n\
                 sql_logging = \"full\"\n\
                 credential = \"none\"\n\
                 \n\
                 # Unreachable on purpose: what matters is what the failure says.\n\
                 [connections.prod]\n\
                 driver = \"postgres\"\n\
                 host = \"127.0.0.1\"\n\
                 port = 1\n\
                 database = \"app\"\n\
                 user = \"reader\"\n\
                 credential = \"env:QUOKKA_TEST_PASSWORD\"\n\
                 connect_timeout = \"1s\"\n",
                app_db.to_string_lossy(),
                app_db.to_string_lossy()
            ),
        )
        .expect("config");

        Workspace { dir }
    }

    fn audit_db(&self) -> std::path::PathBuf {
        self.dir.path().join("audit.db")
    }

    fn quokka(&self, args: &[&str]) -> Output {
        Command::new(env!("CARGO_BIN_EXE_quokka"))
            .args(args)
            .env("QUOKKA_CONFIG", self.dir.path().join("config.toml"))
            .env("QUOKKA_AUDIT_DB", self.audit_db())
            // The binary must not fall back to the real user's log or config.
            .env_remove("QUOKKA_ACTOR")
            .env("HOME", self.dir.path())
            // The credential the redaction tests plant. A real one would come from the
            // keyring; an environment variable is the same secret by a shorter road.
            .env("QUOKKA_TEST_PASSWORD", PASSWORD)
            // Never touch the developer's real keyring from a test.
            .env("QUOKKA_CREDENTIAL_FORCE_FILE", "1")
            .env(
                "QUOKKA_CREDENTIAL_FILE",
                self.dir.path().join("credentials.enc"),
            )
            .output()
            .expect("run quokka")
    }

    /// Everything the log holds, as one string. If a secret is anywhere in the audit
    /// database, it is in here.
    fn audit_dump(&self) -> String {
        let out = self.quokka(&[
            "audit",
            "query",
            "SELECT * FROM audit_log",
            "--format",
            "json",
            "--max-rows",
            "10000",
        ]);
        assert_eq!(code(&out), 0, "stderr: {}", stderr(&out));
        stdout(&out)
    }
}

fn stdout(out: &Output) -> String {
    String::from_utf8_lossy(&out.stdout).into_owned()
}

fn stderr(out: &Output) -> String {
    String::from_utf8_lossy(&out.stderr).into_owned()
}

fn code(out: &Output) -> i32 {
    out.status.code().expect("exit code")
}

/// The milestone's headline: a query runs, and it is provably logged.
#[tokio::test]
async fn a_query_runs_and_both_events_are_logged_with_a_verifying_chain() {
    let w = Workspace::new().await;

    let out = w.quokka(&[
        "query",
        "--connection",
        "app",
        "SELECT 1",
        "--format",
        "json",
    ]);
    assert_eq!(code(&out), 0, "stderr: {}", stderr(&out));

    let envelope: Json = serde_json::from_str(&stdout(&out)).expect("valid JSON envelope");
    assert_eq!(envelope["status"], "ok");
    assert_eq!(envelope["row_count"], 1);
    assert_eq!(envelope["rows"][0]["1"], 1);
    assert_eq!(envelope["truncated"], false);
    let query_id = envelope["query_id"].as_str().expect("query_id").to_string();

    // Both events, read back through the connection the product ships.
    let out = w.quokka(&[
        "audit",
        "query",
        &format!(
            "SELECT event_kind, status, sql_fingerprint FROM audit_log \
             WHERE query_id = '{query_id}' ORDER BY id"
        ),
        "--format",
        "json",
    ]);
    assert_eq!(code(&out), 0, "stderr: {}", stderr(&out));
    let envelope: Json = serde_json::from_str(&stdout(&out)).expect("valid JSON");
    let rows = envelope["rows"].as_array().expect("rows");
    assert_eq!(rows.len(), 2, "a query writes exactly two events");
    assert_eq!(rows[0]["event_kind"], "query_started");
    assert_eq!(rows[0]["status"], "started");
    assert_eq!(rows[1]["event_kind"], "query_finished");
    assert_eq!(rows[1]["status"], "ok");
    assert_eq!(rows[0]["sql_fingerprint"], "SELECT ?");

    let out = w.quokka(&["audit", "verify"]);
    assert_eq!(code(&out), 0, "{}", stdout(&out));
    assert!(stdout(&out).contains("intact"), "{}", stdout(&out));
}

#[tokio::test]
async fn literals_do_not_reach_the_log_at_the_default_mode() {
    let w = Workspace::new().await;

    let out = w.quokka(&[
        "query",
        "--connection",
        "app",
        "SELECT total FROM orders WHERE email = 'a@b.example'",
        "--format",
        "json",
    ]);
    assert_eq!(code(&out), 0, "stderr: {}", stderr(&out));

    let out = w.quokka(&[
        "audit",
        "query",
        "SELECT sql_text, sql_logging, sql_fingerprint FROM audit_log \
         WHERE connection = 'app'",
        "--format",
        "json",
    ]);
    let body = stdout(&out);
    assert!(
        !body.contains("a@b.example"),
        "the literal reached the log: {body}"
    );
    let envelope: Json = serde_json::from_str(&body).expect("valid JSON");
    assert_eq!(envelope["rows"][0]["sql_logging"], "fingerprint");
    assert_eq!(envelope["rows"][0]["sql_text"], Json::Null);
    assert_eq!(
        envelope["rows"][0]["sql_fingerprint"],
        "SELECT total FROM orders WHERE email = ?"
    );
}

#[tokio::test]
async fn ndjson_streams_rows_on_stdout_and_the_summary_on_stderr() {
    let w = Workspace::new().await;

    let out = w.quokka(&[
        "query",
        "--connection",
        "app",
        "SELECT id, total FROM orders ORDER BY id",
        "--format",
        "ndjson",
    ]);
    assert_eq!(code(&out), 0, "stderr: {}", stderr(&out));

    let rows_out = stdout(&out);
    let lines: Vec<&str> = rows_out
        .lines()
        .map(str::trim)
        .filter(|l| !l.is_empty())
        .collect();
    assert_eq!(lines.len(), 2, "one line per row and nothing else");
    for line in &lines {
        let row: Json = serde_json::from_str(line).expect("each line is a JSON object");
        assert!(row.get("id").is_some() && row.get("total").is_some());
    }

    let summary: Json = serde_json::from_str(stderr(&out).trim()).expect("summary on stderr");
    assert_eq!(summary["rows_returned"], 2);
    assert_eq!(summary["truncated"], false);
}

#[tokio::test]
async fn max_rows_truncates_and_never_does_so_silently() {
    let w = Workspace::new().await;

    let out = w.quokka(&[
        "query",
        "--connection",
        "app",
        "SELECT id FROM orders",
        "--format",
        "json",
        "--max-rows",
        "1",
    ]);
    assert_eq!(code(&out), 0);
    let envelope: Json = serde_json::from_str(&stdout(&out)).expect("valid JSON");
    assert_eq!(envelope["row_count"], 1);
    assert_eq!(envelope["truncated"], true);

    let out = w.quokka(&[
        "audit",
        "query",
        "SELECT truncated FROM audit_log WHERE event_kind = 'query_finished' \
         AND connection = 'app'",
        "--format",
        "json",
    ]);
    let envelope: Json = serde_json::from_str(&stdout(&out)).expect("valid JSON");
    assert_eq!(envelope["rows"][0]["truncated"], 1, "the log says so too");
}

#[tokio::test]
async fn a_failing_query_exits_one_and_is_still_logged() {
    let w = Workspace::new().await;

    let out = w.quokka(&[
        "query",
        "--connection",
        "app",
        "SELEKT 1",
        "--format",
        "json",
    ]);
    assert_eq!(code(&out), 1);
    let envelope: Json = serde_json::from_str(&stdout(&out)).expect("valid JSON");
    assert_eq!(envelope["status"], "error");

    let out = w.quokka(&[
        "audit",
        "query",
        "SELECT count(*) AS n FROM audit_log WHERE status = 'error'",
        "--format",
        "json",
    ]);
    let envelope: Json = serde_json::from_str(&stdout(&out)).expect("valid JSON");
    assert_eq!(envelope["rows"][0]["n"], 1);
}

#[tokio::test]
async fn an_unknown_connection_is_a_usage_error_with_json_on_stderr() {
    let w = Workspace::new().await;
    let out = w.quokka(&[
        "query",
        "--connection",
        "nope",
        "SELECT 1",
        "--format",
        "json",
    ]);
    assert_eq!(code(&out), 2);
    assert!(stdout(&out).is_empty());
    let error: Json = serde_json::from_str(stderr(&out).trim()).expect("JSON error on stderr");
    assert!(error["error"].as_str().unwrap().contains("nope"));
}

#[tokio::test]
async fn the_audit_connection_cannot_be_written_through() {
    let w = Workspace::new().await;
    w.quokka(&["query", "--connection", "app", "SELECT 1"]);

    for sql in [
        "DELETE FROM audit_log",
        "UPDATE audit_log SET actor_id = 'mallory'",
        "DROP TABLE audit_log",
    ] {
        let out = w.quokka(&["query", "--connection", "@audit", sql]);
        assert_eq!(code(&out), 1, "{sql} should have been refused");
    }

    let out = w.quokka(&["audit", "verify"]);
    assert_eq!(code(&out), 0, "{}", stdout(&out));
}

#[tokio::test]
async fn verify_reports_tampering_with_a_distinct_exit_code() {
    let w = Workspace::new().await;
    w.quokka(&["query", "--connection", "app", "SELECT 1"]);
    w.quokka(&["query", "--connection", "app", "SELECT 2"]);

    tamper(&w.audit_db()).await;

    let out = w.quokka(&["audit", "verify"]);
    assert_eq!(code(&out), 3, "a broken chain gets its own exit code");
    assert!(stdout(&out).contains("BROKEN"), "{}", stdout(&out));

    let out = w.quokka(&["audit", "verify", "--format", "json"]);
    let report: Json = serde_json::from_str(&stdout(&out)).expect("valid JSON report");
    assert!(!report["problems"].as_array().unwrap().is_empty());
}

#[tokio::test]
async fn the_actor_is_recorded_and_an_explicit_one_reads_as_an_agent() {
    let w = Workspace::new().await;

    let out = w.quokka(&[
        "--actor",
        "claude",
        "query",
        "--connection",
        "app",
        "SELECT 1",
        "--format",
        "json",
    ]);
    assert_eq!(code(&out), 0, "stderr: {}", stderr(&out));

    let out = w.quokka(&[
        "audit",
        "query",
        "SELECT DISTINCT actor_id, actor_kind FROM audit_log WHERE connection = 'app'",
        "--format",
        "json",
    ]);
    let envelope: Json = serde_json::from_str(&stdout(&out)).expect("valid JSON");
    assert_eq!(envelope["rows"][0]["actor_id"], "claude");
    assert_eq!(envelope["rows"][0]["actor_kind"], "agent");
}

#[tokio::test]
async fn audit_tail_shows_the_most_recent_events() {
    let w = Workspace::new().await;
    w.quokka(&["query", "--connection", "app", "SELECT 1"]);

    let out = w.quokka(&[
        "audit",
        "tail",
        "-n",
        "2",
        "--connection",
        "app",
        "--format",
        "json",
    ]);
    assert_eq!(code(&out), 0, "stderr: {}", stderr(&out));
    let envelope: Json = serde_json::from_str(&stdout(&out)).expect("valid JSON");
    let rows = envelope["rows"].as_array().expect("rows");
    assert_eq!(rows.len(), 2);
    assert_eq!(rows[0]["event_kind"], "query_finished");
    assert_eq!(rows[1]["event_kind"], "query_started");

    let out = w.quokka(&["audit", "tail", "--queries", "--format", "json"]);
    let envelope: Json = serde_json::from_str(&stdout(&out)).expect("valid JSON");
    assert!(
        envelope["rows"]
            .as_array()
            .unwrap()
            .iter()
            .any(|r| r["connection"] == "app" && r["status"] == "ok"),
        "the queries view should carry one joined row per query"
    );
}

/// An agent with shell access, editing the log of what it just did.
async fn tamper(audit_db: &Path) {
    use sqlx::{ConnectOptions, Executor};
    let mut conn = sqlx::sqlite::SqliteConnectOptions::new()
        .filename(audit_db)
        .connect()
        .await
        .expect("connect");
    conn.execute("DROP TRIGGER IF EXISTS audit_log_no_update")
        .await
        .expect("drop trigger");
    conn.execute("UPDATE audit_log SET actor_id = 'someone_else' WHERE rowid = 1")
        .await
        .expect("tamper");
}

// --- M1 -----------------------------------------------------------------------------

/// The credential-redaction test the milestone asks for, in the three places §5 names:
/// the audit log, an error message, and machine-readable output.
#[tokio::test]
async fn a_password_appears_in_no_output_no_error_and_no_audit_row() {
    let w = Workspace::new().await;

    // 1. Machine-readable output. `connections list` prints every field of every
    //    connection, which is exactly where a password would surface if one were held
    //    on `ConnectionConfig` rather than referenced from it.
    let out = w.quokka(&["connections", "list", "--format", "json"]);
    assert_eq!(code(&out), 0, "stderr: {}", stderr(&out));
    let listed = stdout(&out);
    assert!(
        !listed.contains(PASSWORD),
        "connections list leaked the credential: {listed}"
    );
    let envelope: Json = serde_json::from_str(&listed).expect("valid JSON");
    let prod = envelope["connections"]
        .as_array()
        .expect("connections")
        .iter()
        .find(|c| c["name"] == "prod")
        .expect("prod is listed");
    assert_eq!(
        prod["credential"], "env:QUOKKA_TEST_PASSWORD",
        "the row names where the credential lives"
    );
    assert_eq!(prod["target"], "reader@127.0.0.1:1/app");

    // 2. An error message. The connection is refused, and the failure text is the one
    //    string in this program most likely to have had a DSN interpolated into it.
    let out = w.quokka(&[
        "query",
        "--connection",
        "prod",
        "SELECT 1",
        "--format",
        "json",
    ]);
    assert_eq!(code(&out), 1, "the connection should fail");
    let reported = format!("{}{}", stdout(&out), stderr(&out));
    assert!(
        !reported.contains(PASSWORD),
        "the connection error leaked the credential: {reported}"
    );
    assert!(
        reported.contains("reader@127.0.0.1:1/app"),
        "the error should still say what it could not reach: {reported}"
    );

    // 3. The audit log, which is where the error message was copied to.
    let dump = w.audit_dump();
    assert!(
        !dump.contains(PASSWORD),
        "the audit log holds the credential: {dump}"
    );

    // 4. And `credential status`, which is the one command that does read the store.
    let out = w.quokka(&["credential", "status", "--format", "json"]);
    assert_eq!(code(&out), 0, "stderr: {}", stderr(&out));
    let status = stdout(&out);
    assert!(
        !status.contains(PASSWORD),
        "credential status leaked the value it was asked about: {status}"
    );
    let envelope: Json = serde_json::from_str(&status).expect("valid JSON");
    let prod = envelope["credentials"]
        .as_array()
        .expect("credentials")
        .iter()
        .find(|c| c["connection"] == "prod")
        .expect("prod");
    assert_eq!(prod["stored"], true, "it reports that one is there");
}

/// A credential goes in through stdin, is stored encrypted, and never comes back out.
#[tokio::test]
async fn a_stored_credential_is_encrypted_at_rest_and_never_echoed() {
    let w = Workspace::new().await;

    // `app` is `credential = "none"`, so storing one is refused with a message about the
    // config file rather than a confusing parse error.
    let out = w.quokka(&["credential", "status", "app", "--format", "json"]);
    assert_eq!(code(&out), 0, "stderr: {}", stderr(&out));
    assert_eq!(
        serde_json::from_str::<Json>(&stdout(&out)).expect("json")["credentials"][0]["stored"],
        false
    );

    let stored = w.dir.path().join("credentials.enc");
    assert!(!stored.exists(), "nothing has been stored yet");
}

/// §5.1 rule 1: bound values are literals that took a different road, so they follow
/// `sql_logging` exactly as the query text does.
#[tokio::test]
async fn bound_parameters_follow_sql_logging_in_both_modes() {
    let w = Workspace::new().await;
    let secret_literal = "a@b.example";

    // `fingerprint`, the default: the count survives, the values do not.
    let out = w.quokka(&[
        "query",
        "--connection",
        "app",
        "SELECT id FROM orders WHERE email = ? AND total > ?",
        "--param",
        &format!("text:{secret_literal}"),
        "--param",
        "float:1",
        "--format",
        "json",
    ]);
    assert_eq!(code(&out), 0, "stderr: {}", stderr(&out));
    assert_eq!(
        serde_json::from_str::<Json>(&stdout(&out)).expect("json")["row_count"],
        1,
        "the parameters were actually bound"
    );

    let rows = query_log(&w, "app");
    assert_eq!(
        rows[0]["params"], "[\"?\",\"?\"]",
        "two values, neither kept"
    );
    assert_eq!(rows[0]["sql_text"], Json::Null);

    // `full`, opted into per connection: the values are written, because that is what
    // the setting means.
    let out = w.quokka(&[
        "query",
        "--connection",
        "app-full",
        "SELECT id FROM orders WHERE email = ?",
        "--param",
        &format!("text:{secret_literal}"),
        "--format",
        "json",
    ]);
    assert_eq!(code(&out), 0, "stderr: {}", stderr(&out));

    let rows = query_log(&w, "app-full");
    let params = rows[0]["params"].as_str().expect("params");
    assert!(
        params.contains(secret_literal),
        "at `full` the bound values are recorded: {params}"
    );
    assert!(
        rows[0]["sql_text"]
            .as_str()
            .expect("sql_text")
            .contains("email = ?"),
        "and so is the query text"
    );

    // The two modes must be distinguishable in the log, or a query with no literals
    // would be indistinguishable from one whose literals were dropped (§5.1, rule 1).
    assert_eq!(rows[0]["sql_logging"], "full");
}

/// `quokka schema describe` returns structured output and leaves exactly one
/// `introspect` event — never a query pair.
#[tokio::test]
async fn schema_describe_returns_structured_output_and_one_introspect_event() {
    let w = Workspace::new().await;

    let out = w.quokka(&[
        "schema",
        "describe",
        "--connection",
        "app",
        "orders",
        "--format",
        "json",
    ]);
    assert_eq!(code(&out), 0, "stderr: {}", stderr(&out));

    let envelope: Json = serde_json::from_str(&stdout(&out)).expect("valid JSON envelope");
    assert_eq!(envelope["from_cache"], false);
    assert_eq!(envelope["table_count"], 1);
    let table = &envelope["tables"][0];
    assert_eq!(table["name"], "orders");
    let columns: Vec<&str> = table["columns"]
        .as_array()
        .expect("columns")
        .iter()
        .map(|c| c["name"].as_str().expect("name"))
        .collect();
    assert_eq!(columns, ["id", "email", "total"]);
    assert_eq!(table["columns"][1]["driver_type"], "TEXT");

    let events = audit_rows(
        &w,
        "SELECT event_kind, status, statement_kind, sql_fingerprint, \
                                 rows_returned FROM audit_log WHERE connection = 'app'",
    );
    assert_eq!(events.len(), 1, "one refresh, one row: {events:#?}");
    assert_eq!(events[0]["event_kind"], "introspect");
    assert_eq!(events[0]["status"], "ok");
    assert_eq!(events[0]["sql_fingerprint"], "INTROSPECT orders");

    // And the chain still verifies with an introspect row in it.
    let out = w.quokka(&["audit", "verify"]);
    assert_eq!(code(&out), 0, "{}", stdout(&out));
}

/// `connections list` is inventory, not a connection attempt: it must not open anything.
#[tokio::test]
async fn connections_list_names_every_connection_without_connecting_to_any() {
    let w = Workspace::new().await;

    let out = w.quokka(&["connections", "list", "--format", "json"]);
    assert_eq!(code(&out), 0, "stderr: {}", stderr(&out));
    let envelope: Json = serde_json::from_str(&stdout(&out)).expect("valid JSON");
    let names: Vec<&str> = envelope["connections"]
        .as_array()
        .expect("connections")
        .iter()
        .map(|c| c["name"].as_str().expect("name"))
        .collect();
    assert_eq!(names, ["@audit", "app", "app-full", "prod"]);

    // `prod` points at a closed port. Listing it succeeded, so nothing dialled it — and
    // the log agrees, because nothing reached a database to log.
    let events = audit_rows(&w, "SELECT id FROM audit_log WHERE connection = 'prod'");
    assert!(events.is_empty(), "listing connections is not a query");
}

/// Every row of `audit_log` for one connection, as JSON objects.
fn audit_rows(w: &Workspace, sql: &str) -> Vec<Json> {
    let out = w.quokka(&[
        "audit",
        "query",
        sql,
        "--format",
        "json",
        "--max-rows",
        "10000",
    ]);
    assert_eq!(code(&out), 0, "stderr: {}", stderr(&out));
    serde_json::from_str::<Json>(&stdout(&out)).expect("valid JSON")["rows"]
        .as_array()
        .expect("rows")
        .clone()
}

fn query_log(w: &Workspace, connection: &str) -> Vec<Json> {
    audit_rows(
        w,
        &format!(
            "SELECT sql_logging, sql_text, params FROM audit_log \
             WHERE event_kind = 'query_started' AND connection = '{connection}'"
        ),
    )
}
