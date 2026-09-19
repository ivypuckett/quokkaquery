//! End-to-end tests over the `quokka` binary — M0's "done means" criteria, run the way
//! a user or an agent would run them.

use std::path::Path;
use std::process::{Command, Output};

use serde_json::Value as Json;

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
                "[connections.app]\ndriver = \"sqlite\"\npath = {:?}\n",
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
            .output()
            .expect("run quokka")
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
