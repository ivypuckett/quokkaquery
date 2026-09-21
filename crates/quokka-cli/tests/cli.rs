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
                 # The same file, read-only: the default posture, and the one a\n\
                 # denial is asserted against.\n\
                 [connections.app-ro]\n\
                 driver = \"sqlite\"\n\
                 path = {:?}\n\
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

    /// The same connections, with the spool capped at one row — the config a test uses
    /// to make the spool's own cap bind before anything else does (§4.2).
    fn spool_capped_config(&self) -> std::path::PathBuf {
        let path = self.dir.path().join("config-tight.toml");
        if !path.exists() {
            let base =
                std::fs::read_to_string(self.dir.path().join("config.toml")).expect("config");
            std::fs::write(&path, format!("{base}\n[spool]\nmax_rows = 1\n"))
                .expect("tight config");
        }
        path
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
            // Spools live under the cache directory (§4.1), and a test must never write
            // to the developer's real one.
            .env("QUOKKA_CACHE_DIR", self.dir.path().join("cache"))
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

    // A statement the classifier reads perfectly well and the database refuses, so the
    // failure under test is the query's rather than the guardrail's — those exit
    // differently now, and on purpose (§6.1).
    let out = w.quokka(&[
        "query",
        "--connection",
        "app",
        "SELECT * FROM no_such_table",
        "--format",
        "json",
    ]);
    assert_eq!(code(&out), 1, "stderr: {}", stderr(&out));
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
        // `--write` and all: `@audit` is `read_only` and the opt-in cannot widen that.
        let out = w.quokka(&["query", "--connection", "@audit", sql, "--write"]);
        assert_eq!(
            code(&out),
            6,
            "{sql} should have been denied: {}",
            stderr(&out)
        );
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
    assert_eq!(names, ["@audit", "app", "app-full", "app-ro", "prod"]);

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

/// Everything in the audit database, as raw bytes.
///
/// Not a query: invariant 4 is about what is *in the file*, so the check reads the file
/// — the write-ahead log beside it included, because a row that has not been
/// checkpointed yet is still a row that reached the log.
fn audit_bytes(w: &Workspace) -> Vec<u8> {
    let mut bytes = Vec::new();
    for suffix in ["", "-wal", "-shm"] {
        let path = w.audit_db().with_file_name(format!("audit.db{suffix}"));
        if let Ok(mut content) = std::fs::read(&path) {
            bytes.append(&mut content);
        }
    }
    bytes
}

/// The one-invocation export of §4.1 and §6.1: the file is written, and the log holds a
/// `query_finished` plus an `export` linked to it by `parent_id`.
#[tokio::test]
async fn a_query_exports_in_one_invocation_and_the_export_is_its_own_audited_event() {
    let w = Workspace::new().await;
    let file = w.dir.path().join("orders.parquet");

    let out = w.quokka(&[
        "query",
        "--connection",
        "app",
        "SELECT * FROM orders",
        "--export",
        file.to_str().expect("path"),
        "--format",
        "json",
    ]);
    assert_eq!(code(&out), 0, "stderr: {}", stderr(&out));
    assert!(file.exists(), "no file was written");
    assert!(std::fs::metadata(&file).expect("metadata").len() > 0);

    // The summary of the export goes to stderr for the machine formats, so stdout stays
    // exactly one envelope.
    let envelope: Json = serde_json::from_str(&stdout(&out)).expect("one JSON envelope");
    let query_id = envelope["query_id"].as_str().expect("query_id").to_string();
    let summary: Json = serde_json::from_str(stderr(&out).trim()).expect("export summary");
    assert_eq!(summary["rows"], 2);
    assert_eq!(summary["format"], "parquet");
    assert_eq!(summary["whole_result"], true);

    let events = audit_rows(
        &w,
        &format!(
            "SELECT event_kind, status, rows_returned, rows_spooled, truncated, \
                    export_format, export_path, parent_id \
             FROM audit_log WHERE query_id = '{query_id}' OR parent_id = '{query_id}' \
             ORDER BY id"
        ),
    );
    let kinds: Vec<&str> = events
        .iter()
        .map(|e| e["event_kind"].as_str().expect("event_kind"))
        .collect();
    assert_eq!(kinds, ["query_started", "query_finished", "export"]);

    let finished = &events[1];
    assert_eq!(finished["rows_returned"], 2);
    // The rows were spooled, which is what made the export a read rather than a re-run.
    assert_eq!(finished["rows_spooled"], 2);

    let export = &events[2];
    assert_eq!(export["status"], "ok");
    assert_eq!(export["export_format"], "parquet");
    assert_eq!(export["rows_returned"], 2);
    assert_eq!(export["truncated"], 0);
    assert_eq!(
        export["parent_id"].as_str(),
        Some(query_id.as_str()),
        "an export links to the query that produced it (§5)"
    );

    // And the chain still verifies with the new event kind in it.
    let verify = w.quokka(&["audit", "verify"]);
    assert_eq!(code(&verify), 0, "{}", stdout(&verify));
}

/// Invariant 4, after the operation most likely to break it: no row, sample or digest of
/// a row reaches the log, even when ten million of them were just written to a file.
#[tokio::test]
async fn no_result_data_reaches_the_log_after_an_export() {
    let w = Workspace::new().await;
    // A value that exists nowhere else in the world, planted in the data rather than in
    // the SQL — the connection logs fingerprints, so a literal in the query would be a
    // different story from a value in a result.
    const NEEDLE: &str = "zzq-needle-9f3a1c7e-do-not-log";
    let seed = w.quokka(&[
        "query",
        "--connection",
        "app",
        "INSERT INTO orders (id, email, total) VALUES (99, ?, 1.0)",
        "--param",
        &format!("text:{NEEDLE}"),
        "--write",
    ]);
    assert_eq!(code(&seed), 0, "stderr: {}", stderr(&seed));

    let csv = w.dir.path().join("out.csv");
    let json = w.dir.path().join("out.json");
    for (path, format) in [(&csv, "csv"), (&json, "json")] {
        let out = w.quokka(&[
            "query",
            "--connection",
            "app",
            "SELECT * FROM orders",
            "--export",
            path.to_str().expect("path"),
            "--export-format",
            format,
        ]);
        assert_eq!(code(&out), 0, "stderr: {}", stderr(&out));
    }

    // The needle is in both files, so the export really did carry it.
    assert!(std::fs::read_to_string(&csv).expect("csv").contains(NEEDLE));
    assert!(std::fs::read_to_string(&json)
        .expect("json")
        .contains(NEEDLE));

    // And nowhere in the log. Bytes, not rows: a digest or a sample hidden in any
    // column would still be in the file.
    let bytes = audit_bytes(&w);
    let found = bytes.windows(NEEDLE.len()).any(|w| w == NEEDLE.as_bytes());
    assert!(
        !found,
        "a value from a result reached the audit log — invariant 4"
    );
}

/// §4.1 and §1.4 together: exporting by id costs a second scan, so without --rerun it
/// does not happen — and *nothing* happens, not even a lookup.
#[tokio::test]
async fn export_by_id_without_rerun_runs_nothing_at_all() {
    let w = Workspace::new().await;

    let first = w.quokka(&[
        "query",
        "--connection",
        "app-full",
        "SELECT * FROM orders",
        "--format",
        "json",
    ]);
    assert_eq!(code(&first), 0, "stderr: {}", stderr(&first));
    let envelope: Json = serde_json::from_str(&stdout(&first)).expect("envelope");
    let query_id = envelope["query_id"].as_str().expect("query_id").to_string();

    let before = audit_rows(&w, "SELECT id FROM audit_log").len();
    let file = w.dir.path().join("late.csv");

    let refused = w.quokka(&[
        "export",
        "--query-id",
        &query_id,
        "-o",
        file.to_str().expect("path"),
    ]);
    assert_eq!(code(&refused), 2, "stdout: {}", stdout(&refused));
    let message = stderr(&refused);
    assert!(message.contains("--rerun"), "{message}");
    assert!(message.contains("second scan"), "{message}");
    assert!(!file.exists(), "a file was written without --rerun");

    // The strong form: the log is unchanged. Not "it exited non-zero" — nothing ran.
    // (`audit_rows` is itself a query, so the count it reports afterwards includes the
    // events of the reading query. Comparing counts taken the same way is the point.)
    let after = audit_rows(&w, "SELECT id FROM audit_log").len();
    assert_eq!(
        after - before,
        2,
        "the refusal should leave the log holding only the two events of the query that \
         read it"
    );
}

/// The other half: --rerun works, is logged as a new query linked to the first, and is
/// refused outright where the log kept only a fingerprint.
#[tokio::test]
async fn rerun_needs_full_sql_logging_and_links_back_to_the_original() {
    let w = Workspace::new().await;

    // `app-full` logs the query verbatim, so the text to re-run exists.
    let first = w.quokka(&[
        "query",
        "--connection",
        "app-full",
        "SELECT * FROM orders",
        "--format",
        "json",
    ]);
    assert_eq!(code(&first), 0, "stderr: {}", stderr(&first));
    let full_id = serde_json::from_str::<Json>(&stdout(&first)).expect("envelope")["query_id"]
        .as_str()
        .expect("query_id")
        .to_string();

    let file = w.dir.path().join("again.csv");
    let out = w.quokka(&[
        "export",
        "--query-id",
        &full_id,
        "--rerun",
        "-o",
        file.to_str().expect("path"),
    ]);
    assert_eq!(code(&out), 0, "stderr: {}", stderr(&out));
    assert!(file.exists());
    assert_eq!(
        std::fs::read_to_string(&file).expect("csv").lines().count(),
        3,
        "a header and two rows"
    );

    // The re-run is its own query, and it points at the one being cited (§4.1).
    let rerun = audit_rows(
        &w,
        &format!(
            "SELECT query_id, event_kind FROM audit_log \
             WHERE parent_id = '{full_id}' AND event_kind = 'query_started'"
        ),
    );
    assert_eq!(
        rerun.len(),
        1,
        "the re-run should link back to the original"
    );

    // `app` logs fingerprints, which is the default, so the text was never written down.
    let fingerprinted = w.quokka(&[
        "query",
        "--connection",
        "app",
        "SELECT * FROM orders",
        "--format",
        "json",
    ]);
    let short_id = serde_json::from_str::<Json>(&stdout(&fingerprinted)).expect("envelope")
        ["query_id"]
        .as_str()
        .expect("query_id")
        .to_string();

    let refused = w.quokka(&[
        "export",
        "--query-id",
        &short_id,
        "--rerun",
        "-o",
        w.dir.path().join("never.csv").to_str().expect("path"),
    ]);
    assert_eq!(code(&refused), 2);
    let message = stderr(&refused);
    assert!(message.contains("fingerprint"), "{message}");
    assert!(message.contains("sql_logging"), "{message}");
    assert!(
        !w.dir.path().join("never.csv").exists(),
        "a fingerprint was turned into SQL and run"
    );
}

/// The spool's own cap and `--max-rows` are different things, say so differently, and
/// stay apart in the log.
#[tokio::test]
async fn both_caps_report_truncation_and_the_log_tells_them_apart() {
    let w = Workspace::new().await;

    // The caller's cap.
    let capped = w.quokka(&[
        "query",
        "--connection",
        "app",
        "SELECT * FROM orders",
        "--max-rows",
        "1",
        "--format",
        "json",
    ]);
    assert_eq!(code(&capped), 0, "stderr: {}", stderr(&capped));
    let envelope: Json = serde_json::from_str(&stdout(&capped)).expect("envelope");
    assert_eq!(envelope["truncated"], true);
    assert_eq!(envelope["rows_spooled"], 1);
    assert!(envelope.get("spool_capped").is_none());

    // The spool's, via a config that caps it at one row.
    let tight = w.quokka(&[
        "--config",
        w.spool_capped_config().to_str().expect("path"),
        "query",
        "--connection",
        "app",
        "SELECT * FROM orders",
        "--max-rows",
        "10",
        "--format",
        "json",
    ]);
    assert_eq!(code(&tight), 0, "stderr: {}", stderr(&tight));
    let envelope: Json = serde_json::from_str(&stdout(&tight)).expect("envelope");
    assert_eq!(envelope["row_count"], 2);
    assert_eq!(envelope["rows_spooled"], 1);
    assert_eq!(envelope["spool_capped"], "rows");

    // In the log: both are truncated, and the row counts say which cap it was — equal
    // for the caller's, fewer spooled than returned for the spool's.
    let finished = audit_rows(
        &w,
        "SELECT rows_returned, rows_spooled, truncated FROM audit_log \
         WHERE event_kind = 'query_finished' AND connection = 'app' ORDER BY id",
    );
    assert_eq!(finished[0]["truncated"], 1);
    assert_eq!(finished[0]["rows_returned"], finished[0]["rows_spooled"]);
    assert_eq!(finished[1]["truncated"], 1);
    assert_eq!(finished[1]["rows_returned"], 2);
    assert_eq!(finished[1]["rows_spooled"], 1);
}

/// A table footer must never let a prefix pass for the whole answer (§4.2).
#[tokio::test]
async fn the_table_footer_names_the_cap_that_stopped_it() {
    let w = Workspace::new().await;

    let out = w.quokka(&[
        "query",
        "--connection",
        "app",
        "SELECT * FROM orders",
        "--max-rows",
        "1",
    ]);
    assert!(
        stdout(&out).contains("TRUNCATED at --max-rows"),
        "{}",
        stdout(&out)
    );

    let tight = w.quokka(&[
        "--config",
        w.spool_capped_config().to_str().expect("path"),
        "query",
        "--connection",
        "app",
        "SELECT * FROM orders",
        "--max-rows",
        "10",
    ]);
    let text = stdout(&tight);
    assert!(text.contains("TRUNCATED at the spool's rows cap"), "{text}");
    assert!(text.contains("1 of 2 rows shown"), "{text}");
}

/// `--all` streams driver → file with no spool, which is how a dataset larger than
/// local disk gets out (§4.2) — and why it cannot then be paged.
#[tokio::test]
async fn all_streams_past_the_spool_cap_and_spools_nothing() {
    let w = Workspace::new().await;
    let file = w.dir.path().join("everything.ndjson");

    let out = w.quokka(&[
        "--config",
        w.spool_capped_config().to_str().expect("path"),
        "query",
        "--connection",
        "app",
        "SELECT * FROM orders",
        "--export",
        file.to_str().expect("path"),
        "--all",
        "--format",
        "json",
    ]);
    assert_eq!(code(&out), 0, "stderr: {}", stderr(&out));

    // Both rows reached the file even though the spool would have held one.
    assert_eq!(
        std::fs::read_to_string(&file)
            .expect("ndjson")
            .lines()
            .count(),
        2
    );

    // And nothing was spooled, so the log does not claim rows that can be paged.
    let finished = audit_rows(
        &w,
        "SELECT rows_returned, rows_spooled FROM audit_log \
         WHERE event_kind = 'query_finished' AND connection = 'app' ORDER BY id DESC LIMIT 1",
    );
    assert_eq!(finished[0]["rows_returned"], 2);
    assert!(finished[0]["rows_spooled"].is_null());

    // Parquet is refused on this path rather than half-written: its header declares a
    // type per column, which is not known until the rows have been seen.
    let refused = w.quokka(&[
        "query",
        "--connection",
        "app",
        "SELECT * FROM orders",
        "--export",
        w.dir.path().join("no.parquet").to_str().expect("path"),
        "--all",
    ]);
    assert_ne!(code(&refused), 0);
    assert!(stderr(&refused).contains("--all"), "{}", stderr(&refused));
}

/// §4.1: nothing survives the process. The cache directory holds no result between
/// invocations.
#[tokio::test]
async fn the_spool_does_not_outlive_the_invocation() {
    let w = Workspace::new().await;

    let out = w.quokka(&["query", "--connection", "app", "SELECT * FROM orders"]);
    assert_eq!(code(&out), 0, "stderr: {}", stderr(&out));

    let cache = w.dir.path().join("cache").join("spool");
    let left: Vec<std::path::PathBuf> = std::fs::read_dir(&cache)
        .map(|entries| entries.filter_map(|e| e.ok()).map(|e| e.path()).collect())
        .unwrap_or_default();
    assert!(
        left.is_empty(),
        "the spool outlived the invocation that made it: {left:?}"
    );
}

/// `--export -` makes stdout the file, so nothing else may be written there — a line of
/// prose in the middle of a pipeline is corruption of what was exported.
#[tokio::test]
async fn exporting_to_stdout_leaves_stdout_holding_only_the_export() {
    let w = Workspace::new().await;

    let out = w.quokka(&[
        "query",
        "--connection",
        "app",
        "SELECT id FROM orders ORDER BY id",
        "--export",
        "-",
        "--export-format",
        "ndjson",
    ]);
    assert_eq!(code(&out), 0, "stderr: {}", stderr(&out));

    let text = stdout(&out);
    let lines: Vec<&str> = text.lines().collect();
    assert_eq!(lines, ["{\"id\":1}", "{\"id\":2}"]);
    // The summary still happened — on the other stream.
    assert!(stderr(&out).contains("exported 2 rows"), "{}", stderr(&out));
}

/// An export that fails is not a usage error and not a failed query: the query ran and
/// is logged, and only the file did not appear. It gets its own exit code, and the log
/// records how far it got.
#[tokio::test]
async fn a_failed_export_has_its_own_exit_code_and_is_logged() {
    let w = Workspace::new().await;

    // A destination that cannot be created, because it is already a directory.
    let blocked = w.dir.path().join("out.csv");
    std::fs::create_dir(&blocked).expect("directory");

    let out = w.quokka(&[
        "query",
        "--connection",
        "app",
        "SELECT * FROM orders",
        "--export",
        blocked.to_str().expect("path"),
    ]);
    assert_eq!(
        code(&out),
        5,
        "a full disk is not the caller's usage error; stderr: {}",
        stderr(&out)
    );

    // The query itself still ran and was logged, and so was the export that failed —
    // silence would leave a file nobody could account for.
    let events = audit_rows(
        &w,
        "SELECT event_kind, status, error_code, rows_returned FROM audit_log \
         WHERE event_kind IN ('query_finished', 'export') ORDER BY id",
    );
    assert_eq!(events[0]["event_kind"], "query_finished");
    assert_eq!(events[0]["status"], "ok");
    assert_eq!(events[1]["event_kind"], "export");
    assert_eq!(events[1]["status"], "error");
    assert_eq!(events[1]["error_code"], "spool.io");
    // Nothing was opened, so nothing was written.
    assert_eq!(events[1]["rows_returned"], 0);
}

/// The other failure, and the one that matters more: a disk that fills up *part way*.
/// The file holds the rows written before it stopped, so the log says so rather than
/// claiming zero — an audit trail that disagreed with what is on disk would be worse
/// than no record at all.
///
/// Linux only: `/dev/full` is the cheapest honest `ENOSPC`, and the other platforms have
/// no equivalent that does not involve building a filesystem.
#[cfg(target_os = "linux")]
#[tokio::test]
async fn a_part_written_export_logs_the_rows_that_reached_the_file() {
    if !std::path::Path::new("/dev/full").exists() {
        eprintln!("skipped: this system has no /dev/full");
        return;
    }

    let w = Workspace::new().await;

    // Enough rows that the writer's buffer flushes mid-stream rather than only at the
    // end, which is what puts the failure part way through.
    let seed = w.quokka(&[
        "query",
        "--connection",
        "app",
        "WITH RECURSIVE n(i) AS (SELECT 1 UNION ALL SELECT i + 1 FROM n WHERE i < 2000) \
         INSERT INTO orders (id, email, total) SELECT i + 1000, 'x@y.example', i FROM n",
        "--write",
    ]);
    assert_eq!(code(&seed), 0, "stderr: {}", stderr(&seed));

    let out = w.quokka(&[
        "query",
        "--connection",
        "app",
        "SELECT * FROM orders",
        "--max-rows",
        "5000",
        "--export",
        "/dev/full",
        "--export-format",
        "csv",
    ]);
    assert_eq!(code(&out), 5, "stderr: {}", stderr(&out));

    let exports = audit_rows(
        &w,
        "SELECT status, error_code, rows_returned FROM audit_log \
         WHERE event_kind = 'export' ORDER BY id",
    );
    assert_eq!(exports.len(), 1);
    assert_eq!(exports[0]["status"], "error");

    let written = exports[0]["rows_returned"].as_i64().expect("a row count");
    assert!(
        written > 0,
        "a part-written export was logged as having written nothing"
    );
    assert!(
        written < 2002,
        "the export cannot have written more rows than the result holds"
    );
}

// ---------------------------------------------------------------------------
// M3: the guardrail, and the same guardrail from the other surface
// ---------------------------------------------------------------------------

/// The CLI half of "the mode binds every surface identically". The MCP half is below.
#[tokio::test]
async fn a_write_to_a_read_only_connection_is_denied_with_its_own_exit_code() {
    let w = Workspace::new().await;

    let out = w.quokka(&[
        "query",
        "--connection",
        "app-ro",
        "INSERT INTO orders (id) VALUES (3)",
        "--write",
        "--format",
        "json",
    ]);
    assert_eq!(
        code(&out),
        6,
        "a denial is neither a usage error nor a failed query: {}",
        stderr(&out)
    );

    let envelope: Json = serde_json::from_str(stderr(&out).trim()).expect("a JSON error");
    assert_eq!(envelope["denied"], Json::Bool(true));
    assert_eq!(envelope["code"], "policy.read_only");

    // And it is in the log as a denial rather than as an error.
    let out = w.quokka(&[
        "audit",
        "query",
        "SELECT count(*) AS n FROM audit_log WHERE status = 'denied'",
        "--format",
        "json",
    ]);
    let envelope: Json = serde_json::from_str(&stdout(&out)).expect("valid JSON");
    assert_eq!(envelope["rows"][0]["n"], 1);
}

/// The same write, against the same connection and the same audit log, refused with the
/// same code from the CLI and from the MCP server. One guardrail, two surfaces, and the
/// test says so in one place rather than leaving the reader to compare two.
#[tokio::test]
async fn the_mode_binds_the_cli_and_mcp_identically() {
    use std::sync::Arc;

    let w = Workspace::new().await;
    const SQL: &str = "INSERT INTO orders (id) VALUES (7)";

    // Through the binary.
    let out = w.quokka(&[
        "query",
        "--connection",
        "app-ro",
        SQL,
        "--write",
        "--format",
        "json",
    ]);
    assert_eq!(code(&out), 6);
    let from_cli: Json = serde_json::from_str(stderr(&out).trim()).expect("JSON");

    // Through the MCP server, over the same config and the same log.
    let audit = quokka_core::AuditLog::open(w.audit_db())
        .await
        .expect("audit log");
    let config = quokka_core::Config::load(Some(&w.dir.path().join("config.toml")), &w.audit_db())
        .expect("config");
    let engine = Arc::new(quokka_core::Engine::new(
        config.registry,
        audit,
        quokka_driver::builtin_factories(),
    ));
    let spools = Arc::new(
        quokka_spool::SpoolSet::open(
            Some(&w.dir.path().join("cache-mcp")),
            quokka_spool::Limits::from(config.spool),
        )
        .await
        .expect("spools"),
    );
    let server = quokka_mcp::QuokkaMcp::new(
        engine,
        spools,
        quokka_core::Actor {
            kind: quokka_core::ActorKind::Agent,
            id: "claude".to_string(),
        },
        // The most permissive posture an MCP server can have, so that what refuses the
        // write is the connection and nothing else.
        quokka_core::AccessMode::ReadWrite,
    );

    let args = serde_json::json!({
        "connection": "app-ro",
        "sql": SQL,
        "write": true,
    });
    let answer = server
        .query(rmcp::handler::server::wrapper::Parameters(
            serde_json::from_value(args).expect("arguments"),
        ))
        .await;
    let err = match answer {
        Err(e) => e,
        Ok(_) => panic!("the same write must be refused here too"),
    };
    let from_mcp = err.data.expect("a denial carries its code");

    assert_eq!(
        from_cli["code"], from_mcp["code"],
        "the same connection refused the same statement differently depending on who asked"
    );
    assert_eq!(from_mcp["code"], "policy.read_only");
}

/// `--write` is the other key, and it is only a key where a human already turned the
/// first one.
#[tokio::test]
async fn a_write_needs_the_flag_even_where_the_connection_allows_it() {
    let w = Workspace::new().await;

    let out = w.quokka(&[
        "query",
        "--connection",
        "app",
        "INSERT INTO orders (id, email, total) VALUES (42, 'x@y.example', 1.0)",
        "--format",
        "json",
    ]);
    assert_eq!(code(&out), 6, "{}", stderr(&out));
    assert!(stderr(&out).contains("policy.write_not_opted_in"));

    let out = w.quokka(&[
        "query",
        "--connection",
        "app",
        "INSERT INTO orders (id, email, total) VALUES (42, 'x@y.example', 1.0)",
        "--write",
        "--format",
        "json",
    ]);
    assert_eq!(code(&out), 0, "{}", stderr(&out));

    // And the log says who turned the key, in the column §5 already has for it.
    let out = w.quokka(&[
        "audit",
        "query",
        // Both attempts are in the log; only the authorized one names an approver, and
        // that difference is the assertion.
        "SELECT approved_by, count(*) AS n FROM audit_log \
         WHERE statement_kind = 'insert' AND event_kind = 'query_started' \
         GROUP BY approved_by ORDER BY approved_by",
        "--format",
        "json",
    ]);
    let envelope: Json = serde_json::from_str(&stdout(&out)).expect("valid JSON");
    let rows = envelope["rows"].as_array().expect("rows");
    assert_eq!(
        rows.len(),
        2,
        "one denied attempt and one authorized: {envelope}"
    );
    assert!(
        rows[0]["approved_by"].is_null(),
        "a denial authorizes nothing: {envelope}"
    );
    assert!(
        rows[1]["approved_by"].is_string(),
        "an authorized write records who authorized it: {envelope}"
    );
}

#[tokio::test]
async fn a_stacked_body_is_refused_from_the_cli() {
    let w = Workspace::new().await;

    let out = w.quokka(&[
        "query",
        "--connection",
        "app",
        "SELECT 1; DROP TABLE orders",
        "--write",
        "--format",
        "json",
    ]);
    assert_eq!(code(&out), 6, "{}", stderr(&out));
    assert!(stderr(&out).contains("policy.multiple_statements"));

    // The table is still there, which is the thing the rule is about.
    let out = w.quokka(&[
        "query",
        "--connection",
        "app",
        "SELECT count(*) AS n FROM orders",
        "--format",
        "json",
    ]);
    assert_eq!(code(&out), 0, "{}", stderr(&out));
}

/// A denial is logged under the connection's own `sql_logging`, so a `fingerprint`
/// connection's literals are absent from the log's bytes even when the query was refused.
#[tokio::test]
async fn a_denied_statement_leaves_no_literal_in_a_fingerprint_connection_s_log() {
    const NEEDLE: &str = "zzq-marker-3f8c-do-not-log";

    let w = Workspace::new().await;
    let out = w.quokka(&[
        "query",
        "--connection",
        "app-ro",
        &format!("DELETE FROM orders WHERE email = '{NEEDLE}'"),
        "--write",
    ]);
    assert_eq!(code(&out), 6, "{}", stderr(&out));

    let dump = w.audit_dump();
    assert!(
        !dump.contains(NEEDLE),
        "the denial stored a literal the connection's sql_logging forbids"
    );
    assert!(
        dump.contains("DELETE FROM orders WHERE email = ?"),
        "the shape must survive, or the denial is unreadable: {dump}"
    );
}

#[tokio::test]
async fn explain_shows_a_plan_and_leaves_a_query_pair() {
    let w = Workspace::new().await;

    let out = w.quokka(&[
        "explain",
        "--connection",
        "app",
        "SELECT * FROM orders WHERE id = 1",
        "--format",
        "json",
    ]);
    assert_eq!(code(&out), 0, "{}", stderr(&out));
    let envelope: Json = serde_json::from_str(&stdout(&out)).expect("valid JSON");
    assert!(
        !envelope["plan"].as_str().expect("plan").is_empty(),
        "{envelope}"
    );

    let out = w.quokka(&[
        "audit",
        "query",
        "SELECT count(*) AS n FROM audit_log WHERE statement_kind = 'explain'",
        "--format",
        "json",
    ]);
    let envelope: Json = serde_json::from_str(&stdout(&out)).expect("valid JSON");
    assert_eq!(envelope["rows"][0]["n"], 2, "a query pair, not one event");
}

/// Explaining a write needs the same access as running one — the decision
/// `quokka_core::explain` writes down, asserted from the surface a person meets it on.
#[tokio::test]
async fn explaining_a_write_on_a_read_only_connection_is_denied() {
    let w = Workspace::new().await;

    let out = w.quokka(&[
        "explain",
        "--connection",
        "app-ro",
        "DELETE FROM orders",
        "--format",
        "json",
    ]);
    assert_eq!(code(&out), 6, "{}", stderr(&out));
    assert!(stderr(&out).contains("policy.read_only"));
}

#[tokio::test]
async fn a_timeout_that_could_never_be_met_is_rejected_as_usage() {
    let w = Workspace::new().await;

    let out = w.quokka(&["query", "--connection", "app", "SELECT 1", "--timeout", "0"]);
    assert_eq!(code(&out), 2, "a bad flag is a usage error");

    // And a good one is simply accepted.
    let out = w.quokka(&[
        "query",
        "--connection",
        "app",
        "SELECT 1",
        "--timeout",
        "30s",
        "--format",
        "json",
    ]);
    assert_eq!(code(&out), 0, "{}", stderr(&out));
}

/// Invariant 7 at the command line: there is no flag that changes a connection's mode,
/// its logging fidelity or its caps. The only way is the config file.
#[tokio::test]
async fn no_flag_changes_what_only_a_human_may_change() {
    let w = Workspace::new().await;
    let help = stdout(&w.quokka(&["query", "--help"]));

    for forbidden in ["--mode", "--sql-logging", "--read-write", "--allow-write "] {
        assert!(
            !help.contains(forbidden),
            "`quokka query` offers {forbidden}, which would let a caller widen its own \
             guardrail: {help}"
        );
    }
}

/// `quokka mcp` exists, says what posture it is in, and is read-only unless a human
/// says otherwise.
#[tokio::test]
async fn the_mcp_subcommand_is_read_only_unless_a_human_says_otherwise() {
    let w = Workspace::new().await;
    let help = stdout(&w.quokka(&["mcp", "--help"]));
    assert!(help.contains("--allow-writes"), "{help}");

    let top = stdout(&w.quokka(&["--help"]));
    assert!(top.contains("mcp"), "{top}");
}

/// M4: the window is a subcommand of the same binary, with the same global flags and
/// the same registry behind it.
///
/// What is *not* asserted here is that it opens — an integration test that started a
/// window would need a display, and CI proves that in a job of its own under Xvfb (§9's
/// "smoke tests and manual passes"). What this checks is the seam: that `quokka ui`
/// exists, that §7's renderer choice is reachable from the command line, and that
/// nothing about it is a second way into the engine.
#[tokio::test]
async fn the_window_is_a_subcommand_with_the_renderer_choice_on_it() {
    let w = Workspace::new().await;

    let out = w.quokka(&["ui", "--help"]);
    assert_eq!(code(&out), 0, "stderr: {}", stderr(&out));
    let help = stdout(&out);
    assert!(
        help.contains("--renderer"),
        "§7's software fallback has to be selectable: {help}"
    );
    assert!(
        help.contains("gpu") && help.contains("software"),
        "both renderers should be named: {help}"
    );

    // And there is no posture flag here, deliberately — see the note at the top of
    // `quokka-ui`. `quokka mcp` has one because a human holds the second key for an
    // agent; at a window the person who would type it is the person already sitting
    // there, and a mode you can grant yourself is not a guardrail.
    assert!(
        !help.contains("--allow-writes"),
        "the window's authority is the connection's mode, not a flag: {help}"
    );
    let mcp = stdout(&w.quokka(&["mcp", "--help"]));
    assert!(
        mcp.contains("--allow-writes"),
        "the MCP server still has one, and for a reason that does not apply here"
    );
}

/// A window that never opened has nothing to record.
///
/// Asserted by counting `ui` events rather than by comparing the whole log: reading the
/// log is itself a logged query (§5), so the log is never the same twice — which is the
/// point of `@audit` rather than an inconvenience.
#[tokio::test]
async fn an_unknown_renderer_is_a_usage_error_that_runs_nothing() {
    let w = Workspace::new().await;
    let _ = w.quokka(&["query", "--connection", "app", "SELECT 1"]);

    let out = w.quokka(&["ui", "--renderer", "vulkan"]);
    assert_ne!(code(&out), 0, "an unknown renderer is not a renderer");

    let log: Json = serde_json::from_str(&w.audit_dump()).expect("the log");
    let from_the_window = log["rows"]
        .as_array()
        .expect("rows")
        .iter()
        .filter(|row| row["client"] == "ui")
        .count();
    assert_eq!(
        from_the_window, 0,
        "clap refused the arguments before anything opened, so the window ran nothing"
    );
}

// ---------------------------------------------------------------------------
// M5: the cost guard (§6.4), and the same refusal from every surface
// ---------------------------------------------------------------------------

/// Put a finished query in the log that scanned `bytes`, as an Athena query would have.
///
/// The budget sums `data_scanned_bytes` over `query_finished` rows, so this is what
/// having spent something looks like. Writing it directly rather than running a query is
/// the only way to test the accounting without an Athena to scan anything — and it is
/// the same append the engine makes, through the same API, so the chain stays intact.
async fn spend(
    audit_db: &Path,
    connection: &str,
    actor_id: &str,
    kind: quokka_audit::ActorKind,
    bytes: i64,
) {
    let audit = quokka_audit::AuditLog::open(audit_db)
        .await
        .expect("audit log");
    let event = quokka_audit::AuditEvent {
        id: uuid::Uuid::now_v7(),
        query_id: uuid::Uuid::now_v7(),
        parent_id: None,
        at: quokka_audit::now_rfc3339().expect("a timestamp"),
        duration_ms: Some(10),
        actor_kind: kind,
        actor_id: actor_id.to_string(),
        session_id: "seed".to_string(),
        client: quokka_audit::Client::Cli,
        connection: connection.to_string(),
        dialect: "athena".to_string(),
        database: None,
        schema_name: None,
        event_kind: quokka_audit::EventKind::QueryFinished,
        sql_logging: quokka_audit::SqlLogging::Fingerprint,
        sql_text: None,
        sql_fingerprint: "SELECT ?".to_string(),
        statement_kind: Some("query".to_string()),
        read_only: Some(true),
        params: None,
        status: quokka_audit::Status::Ok,
        error_code: None,
        error_message: None,
        rows_returned: Some(1),
        rows_affected: None,
        rows_spooled: None,
        truncated: Some(false),
        export_format: None,
        export_path: None,
        data_scanned_bytes: Some(bytes),
        cost_estimate_usd: None,
        approved_by: None,
        tags: None,
    };
    audit.append(event).await.expect("append");
    audit.close().await;
}

/// A workspace whose `app` connection carries a budget an agent has already spent.
async fn budgeted() -> Workspace {
    let w = Workspace::new().await;
    let base = std::fs::read_to_string(w.dir.path().join("config.toml")).expect("config");
    std::fs::write(
        w.dir.path().join("config.toml"),
        format!(
            "{base}\n\
             [connections.app.cost_guard]\n\
             window      = \"1d\"\n\
             agent_limit = \"50GB\"\n\
             human_limit = \"unlimited\"\n\
             human_warn  = \"500GB\"\n"
        ),
    )
    .expect("config with a budget");

    // The log has to exist before anything can be appended to it, and `audit verify` on
    // a fresh workspace creates it without running a query.
    w.quokka(&["audit", "verify"]);
    spend(
        &w.audit_db(),
        "app",
        "claude",
        quokka_audit::ActorKind::Agent,
        60_000_000_000,
    )
    .await;
    w
}

/// **A budget refusal is a denial**: exit code 6, the code in the JSON envelope, and two
/// events in the log with `denied` on the second.
#[tokio::test]
async fn an_agent_past_its_budget_is_refused_and_the_refusal_is_logged() {
    let w = budgeted().await;

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
    assert_eq!(
        code(&out),
        6,
        "a budget refusal is a denial, not a failed query: {}",
        stderr(&out)
    );

    let envelope: Json = serde_json::from_str(stderr(&out).trim()).expect("a JSON error");
    assert_eq!(envelope["denied"], Json::Bool(true));
    assert_eq!(envelope["code"], "policy.cost_budget");

    let message = envelope["error"].as_str().expect("a message");
    assert!(message.contains("50 GB"), "the budget: {message}");
    assert!(message.contains("1d"), "the window: {message}");
    assert!(message.contains("60 GB"), "the spend: {message}");
    assert!(
        message.contains("after the one that crossed the line"),
        "the message must not promise a pre-execution cap: {message}"
    );

    // In the log as the fourth shape, and the chain still verifies.
    let out = w.quokka(&[
        "audit",
        "query",
        "SELECT count(*) AS n FROM audit_log WHERE status = 'denied' \
         AND error_code = 'policy.cost_budget'",
        "--format",
        "json",
    ]);
    let envelope: Json = serde_json::from_str(&stdout(&out)).expect("valid JSON");
    assert_eq!(envelope["rows"][0]["n"], 1);

    assert_eq!(code(&w.quokka(&["audit", "verify"])), 0);
}

/// The asymmetry, at the binary: the same connection, the same budget, a human instead
/// of an agent.
#[tokio::test]
async fn a_human_is_not_refused_by_the_agent_cap() {
    let w = budgeted().await;
    // The human's own spend, which is well under `human_warn` and uncapped anyway.
    spend(
        &w.audit_db(),
        "app",
        "ivy",
        quokka_audit::ActorKind::Human,
        60_000_000_000,
    )
    .await;

    let out = w.quokka(&[
        "--actor",
        "ivy",
        "--actor-kind",
        "human",
        "query",
        "--connection",
        "app",
        "SELECT 1 AS n",
        "--format",
        "json",
    ]);
    assert_eq!(
        code(&out),
        0,
        "a human on an uncapped connection runs: {}",
        stderr(&out)
    );
}

/// A human past `human_warn` runs, and is told — in the envelope and on stderr.
#[tokio::test]
async fn a_human_past_the_warning_threshold_is_told_without_being_stopped() {
    let w = budgeted().await;
    spend(
        &w.audit_db(),
        "app",
        "ivy",
        quokka_audit::ActorKind::Human,
        600_000_000_000,
    )
    .await;

    let out = w.quokka(&[
        "--actor",
        "ivy",
        "--actor-kind",
        "human",
        "query",
        "--connection",
        "app",
        "SELECT 1 AS n",
        "--format",
        "json",
    ]);
    assert_eq!(
        code(&out),
        0,
        "a warning is not a refusal: {}",
        stderr(&out)
    );

    let envelope: Json = serde_json::from_str(&stdout(&out)).expect("valid JSON");
    let warning = envelope["cost_warning"]
        .as_str()
        .expect("the envelope carries the warning");
    assert!(warning.contains("600 GB"), "{warning}");
    assert!(
        stderr(&out).contains("600 GB"),
        "and a person reading a terminal sees it too: {}",
        stderr(&out)
    );
}

/// The budget check reads the log before every query on a budgeted connection, and
/// leaves nothing behind when it does. A log that fills with its own bookkeeping is a
/// log nobody reads.
#[tokio::test]
async fn the_budget_check_adds_no_events_of_its_own() {
    let w = Workspace::new().await;
    let base = std::fs::read_to_string(w.dir.path().join("config.toml")).expect("config");
    std::fs::write(
        w.dir.path().join("config.toml"),
        format!("{base}\n[connections.app.cost_guard]\nwindow = \"1d\"\nagent_limit = \"50GB\"\n"),
    )
    .expect("config");

    for _ in 0..3 {
        let out = w.quokka(&[
            "--actor",
            "claude",
            "query",
            "--connection",
            "app",
            "SELECT 1 AS n",
            "--format",
            "json",
        ]);
        assert_eq!(code(&out), 0, "{}", stderr(&out));
    }

    let out = w.quokka(&[
        "audit",
        "query",
        "SELECT count(*) AS n FROM audit_log WHERE connection = 'app'",
        "--format",
        "json",
    ]);
    let envelope: Json = serde_json::from_str(&stdout(&out)).expect("valid JSON");
    assert_eq!(
        envelope["rows"][0]["n"], 6,
        "three queries, two events each, and nothing the budget check wrote"
    );
}

/// **The parity test grows again.** A budget denial reads identically from the CLI and
/// from MCP, the way a read-only refusal already does. The window's half of this is in
/// `quokka-ui/tests/window.rs`, which asserts the same code and the same three facts —
/// there is one place these words are composed, and it is `quokka-policy`.
#[tokio::test]
async fn a_budget_denial_reads_the_same_from_the_cli_and_from_mcp() {
    use std::sync::Arc;

    let w = budgeted().await;

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
    assert_eq!(code(&out), 6);
    let from_cli: Json = serde_json::from_str(stderr(&out).trim()).expect("JSON");

    // The same config and the same log, through the MCP server.
    let audit = quokka_core::AuditLog::open(w.audit_db())
        .await
        .expect("audit log");
    let config = quokka_core::Config::load(Some(&w.dir.path().join("config.toml")), &w.audit_db())
        .expect("config");
    let engine = Arc::new(quokka_core::Engine::new(
        config.registry,
        audit,
        quokka_driver::builtin_factories(),
    ));
    let spools = Arc::new(
        quokka_spool::SpoolSet::open(
            Some(&w.dir.path().join("cache-mcp")),
            quokka_spool::Limits::from(config.spool),
        )
        .await
        .expect("spools"),
    );
    let server = quokka_mcp::QuokkaMcp::new(
        engine,
        spools,
        quokka_core::Actor {
            kind: quokka_core::ActorKind::Agent,
            id: "claude".to_string(),
        },
        quokka_core::AccessMode::ReadWrite,
    );

    let answer = server
        .query(rmcp::handler::server::wrapper::Parameters(
            serde_json::from_value(serde_json::json!({
                "connection": "app",
                "sql": "SELECT 1",
            }))
            .expect("arguments"),
        ))
        .await;
    let err = answer
        .err()
        .expect("the same budget refuses the same query");
    let from_mcp = err.data.expect("a denial carries its code");

    assert_eq!(from_cli["code"], from_mcp["code"]);
    assert_eq!(from_mcp["code"], "policy.cost_budget");
    assert_eq!(
        from_cli["error"].as_str(),
        Some(err.message.as_ref()),
        "the same budget refused the same query in different words depending on who asked"
    );
}

/// A driver that measures nothing says nothing. The envelope carries
/// `data_scanned_bytes` only when there is a number, so a script summing the field
/// across connections is never handed a 0 that means "not measured".
#[tokio::test]
async fn a_driver_that_scans_nothing_reports_no_cost_field() {
    let w = Workspace::new().await;
    let out = w.quokka(&[
        "query",
        "--connection",
        "app",
        "SELECT 1 AS n",
        "--format",
        "json",
    ]);
    assert_eq!(code(&out), 0, "{}", stderr(&out));

    let envelope: Json = serde_json::from_str(&stdout(&out)).expect("valid JSON");
    assert!(
        envelope.get("data_scanned_bytes").is_none(),
        "SQLite measures nothing, so the field should be absent rather than 0: {envelope}"
    );
    assert!(envelope.get("cost_warning").is_none());
    // And the table format's footer says nothing about scanning either.
    let out = w.quokka(&["query", "--connection", "app", "SELECT 1 AS n"]);
    assert!(!stdout(&out).contains("scanned"), "{}", stdout(&out));
}
