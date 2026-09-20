//! The test CLAUDE.md asks for first: the hash chain must detect *every* single-row edit
//! and *every* single-row deletion.
//!
//! The tampering below drops the append-only triggers before it edits anything, because
//! that is what the threat model actually looks like: not SQL issued through
//! QuokkaQuery, but an agent with shell access and a `sqlite3` prompt, editing the log
//! of what it just did.

use std::path::{Path, PathBuf};

use quokka_audit::{
    ActorKind, AuditEvent, AuditLog, Client, EventKind, SqlLogging, Status, VerifyReport,
};
use sqlx::sqlite::SqliteConnectOptions;
use sqlx::{ConnectOptions, Executor};
use uuid::Uuid;

/// How many events the reference log holds. Every case below tampers with one of them.
const EVENTS: usize = 8;

/// Columns a tamperer might plausibly rewrite, with a value that differs from anything
/// [`sample_events`] produces.
const TAMPERED_COLUMNS: &[(&str, &str)] = &[
    ("actor_id", "'mallory'"),
    ("actor_kind", "'automation'"),
    ("at", "'2000-01-01T00:00:00Z'"),
    ("connection", "'somewhere-else'"),
    ("event_kind", "'connect'"),
    ("status", "'denied'"),
    ("sql_fingerprint", "'SELECT ?'"),
    ("statement_kind", "'insert'"),
    ("read_only", "NULL"),
    ("rows_returned", "-1"),
    ("duration_ms", "-1"),
    ("cost_estimate_usd", "0.5"),
    ("sql_text", "'select * from somewhere_else'"),
    ("tags", "'benign'"),
    ("prev_hash", "'00'"),
    ("query_id", "'00000000-0000-0000-0000-000000000000'"),
];

#[tokio::test]
async fn an_untouched_chain_verifies() {
    let dir = tempfile::tempdir().expect("tempdir");
    let path = build_reference_log(dir.path()).await;

    let log = AuditLog::open(&path).await.expect("open");
    let report = log.verify().await.expect("verify");
    assert!(
        report.is_intact(),
        "a log nobody touched must verify: {:?}",
        report.problems
    );
    assert_eq!(report.rows_checked, EVENTS);
}

#[tokio::test]
async fn every_single_row_edit_is_detected() {
    let dir = tempfile::tempdir().expect("tempdir");
    let reference = build_reference_log(dir.path()).await;
    let ids = row_ids(&reference).await;
    assert_eq!(ids.len(), EVENTS);

    let mut edits_made = vec![0usize; TAMPERED_COLUMNS.len()];

    for (row_index, id) in ids.iter().enumerate() {
        for (column_index, (column, replacement)) in TAMPERED_COLUMNS.iter().enumerate() {
            let target = copy_log(
                &reference,
                dir.path(),
                &format!("edit-{row_index}-{column}"),
            );

            let before = column_value(&target, id, column).await;
            tamper(
                &target,
                &format!("UPDATE audit_log SET {column} = {replacement} WHERE id = '{id}'"),
            )
            .await;
            let after = column_value(&target, id, column).await;
            if before == after {
                // SQLite counts a row as changed even when the new value equals the old
                // one, so "did anything actually change?" has to be asked directly.
                continue;
            }
            edits_made[column_index] += 1;

            let report = verify(&target).await;
            assert!(
                !report.is_intact(),
                "editing {column} of row {row_index} (from {before:?} to {after:?}) \
                 went undetected"
            );
        }
    }

    // A replacement value that happened to match every row would make this test pass by
    // doing nothing at all.
    for (i, (column, _)) in TAMPERED_COLUMNS.iter().enumerate() {
        assert!(
            edits_made[i] > 0,
            "no row was actually edited for {column}: the test proved nothing about it"
        );
    }
}

#[tokio::test]
async fn every_single_row_deletion_is_detected() {
    let dir = tempfile::tempdir().expect("tempdir");
    let reference = build_reference_log(dir.path()).await;
    let ids = row_ids(&reference).await;

    for (row_index, id) in ids.iter().enumerate() {
        let target = copy_log(&reference, dir.path(), &format!("delete-{row_index}"));
        let deleted = tamper(&target, &format!("DELETE FROM audit_log WHERE id = '{id}'")).await;
        assert_eq!(deleted, 1);

        let report = verify(&target).await;
        assert!(
            !report.is_intact(),
            "deleting row {row_index} of {EVENTS} went undetected — \
             the chain missed it and so would `quokka audit verify`"
        );
    }
}

/// Removing the tail is the case a plain back-link chain cannot see, which is why the
/// head is checkpointed separately. Worth its own test so the reason does not get
/// refactored away.
#[tokio::test]
async fn truncating_the_tail_is_detected() {
    let dir = tempfile::tempdir().expect("tempdir");
    let reference = build_reference_log(dir.path()).await;
    let target = copy_log(&reference, dir.path(), "truncate-tail");

    tamper(
        &target,
        "DELETE FROM audit_log WHERE id = (SELECT max(id) FROM audit_log)",
    )
    .await;

    let report = verify(&target).await;
    assert!(!report.is_intact(), "a truncated tail went undetected");
}

#[tokio::test]
async fn the_triggers_refuse_updates_and_deletes() {
    let dir = tempfile::tempdir().expect("tempdir");
    let path = build_reference_log(dir.path()).await;

    let mut conn = SqliteConnectOptions::new()
        .filename(&path)
        .connect()
        .await
        .expect("connect");

    let update = conn
        .execute("UPDATE audit_log SET actor_id = 'mallory'")
        .await;
    assert!(update.is_err(), "UPDATE must be refused by the trigger");
    assert!(update.unwrap_err().to_string().contains("append-only"));

    let delete = conn.execute("DELETE FROM audit_log").await;
    assert!(delete.is_err(), "DELETE must be refused by the trigger");
    assert!(delete.unwrap_err().to_string().contains("append-only"));
}

#[tokio::test]
async fn the_queries_view_joins_the_two_events_of_a_query() {
    let dir = tempfile::tempdir().expect("tempdir");
    let path = dir.path().join("audit.db");
    let log = AuditLog::open(&path).await.expect("open");

    let query_id = Uuid::now_v7();
    log.append(event(EventKind::QueryStarted, Status::Started, query_id))
        .await
        .expect("started");
    log.append(event(EventKind::QueryFinished, Status::Ok, query_id))
        .await
        .expect("finished");

    // A second query that never finished — the process was killed mid-flight.
    let orphan = Uuid::now_v7();
    log.append(event(EventKind::QueryStarted, Status::Started, orphan))
        .await
        .expect("orphan start");
    log.close().await;

    let mut conn = SqliteConnectOptions::new()
        .filename(&path)
        .connect()
        .await
        .expect("connect");

    let rows: Vec<(String, String)> =
        sqlx::query_as("SELECT query_id, status FROM queries ORDER BY started_at")
            .fetch_all(&mut conn)
            .await
            .expect("select from queries");

    assert_eq!(rows.len(), 2, "one row per query, not per event");
    assert_eq!(rows[0], (query_id.to_string(), "ok".to_string()));
    assert_eq!(
        rows[1],
        (orphan.to_string(), "unfinished".to_string()),
        "a start with no finish must be visible as exactly that"
    );
}

// ---------------------------------------------------------------------------
// helpers
// ---------------------------------------------------------------------------

async fn build_reference_log(dir: &Path) -> PathBuf {
    let path = dir.join("reference.db");
    let log = AuditLog::open(&path).await.expect("open");
    for e in sample_events() {
        log.append(e).await.expect("append");
    }
    // Close before copying so the WAL is checkpointed into the main file.
    log.close().await;
    path
}

/// Four queries' worth of events, varying the fields the hash covers.
fn sample_events() -> Vec<AuditEvent> {
    let mut out = Vec::new();
    for i in 0..(EVENTS / 2) {
        let query_id = Uuid::now_v7();
        let mut started = event(EventKind::QueryStarted, Status::Started, query_id);
        started.actor_kind = if i % 2 == 0 {
            ActorKind::Agent
        } else {
            ActorKind::Human
        };
        started.actor_id = format!("actor-{i}");
        started.sql_fingerprint = format!("SELECT ? FROM t{i}");
        started.sql_logging = if i % 2 == 0 {
            SqlLogging::Fingerprint
        } else {
            SqlLogging::Full
        };
        started.sql_text = (i % 2 == 1).then(|| format!("select 1 from t{i}"));
        started.read_only = Some(i % 2 == 0);

        let mut finished = event(EventKind::QueryFinished, Status::Ok, query_id);
        finished.actor_kind = started.actor_kind;
        finished.actor_id = started.actor_id.clone();
        finished.sql_fingerprint = started.sql_fingerprint.clone();
        finished.duration_ms = Some(i as i64 * 7);
        finished.rows_returned = Some(i as i64);
        finished.truncated = Some(i % 2 == 1);
        finished.cost_estimate_usd = Some(i as f64 * 1.25);

        out.push(started);
        out.push(finished);
    }
    out
}

fn event(kind: EventKind, status: Status, query_id: Uuid) -> AuditEvent {
    AuditEvent {
        id: Uuid::now_v7(),
        query_id,
        parent_id: None,
        at: quokka_audit::now_rfc3339().expect("timestamp"),
        duration_ms: None,
        actor_kind: ActorKind::Agent,
        actor_id: "claude".to_string(),
        session_id: "session".to_string(),
        client: Client::Cli,
        connection: "app".to_string(),
        dialect: "sqlite".to_string(),
        database: None,
        schema_name: None,
        event_kind: kind,
        sql_logging: SqlLogging::Fingerprint,
        sql_text: None,
        sql_fingerprint: "SELECT ?".to_string(),
        statement_kind: Some("select".to_string()),
        read_only: Some(true),
        params: None,
        status,
        error_code: None,
        error_message: None,
        rows_returned: None,
        rows_affected: None,
        rows_spooled: None,
        truncated: None,
        export_format: None,
        export_path: None,
        data_scanned_bytes: None,
        cost_estimate_usd: None,
        approved_by: None,
        tags: None,
    }
}

async fn row_ids(path: &Path) -> Vec<String> {
    let mut conn = SqliteConnectOptions::new()
        .filename(path)
        .connect()
        .await
        .expect("connect");
    sqlx::query_scalar("SELECT id FROM audit_log ORDER BY id")
        .fetch_all(&mut conn)
        .await
        .expect("ids")
}

/// The column's stored value rendered as text, so "did this change?" is answerable
/// without knowing the column's type.
async fn column_value(path: &Path, id: &str, column: &str) -> Option<String> {
    let mut conn = SqliteConnectOptions::new()
        .filename(path)
        .connect()
        .await
        .expect("connect");
    sqlx::query_scalar(sqlx::AssertSqlSafe(format!(
        "SELECT CAST({column} AS TEXT) FROM audit_log WHERE id = '{id}'"
    )))
    .fetch_one(&mut conn)
    .await
    .expect("read column")
}

fn copy_log(reference: &Path, dir: &Path, name: &str) -> PathBuf {
    let target = dir.join(format!("{name}.db"));
    std::fs::copy(reference, &target).expect("copy");
    target
}

/// Do what an agent with shell access would do: drop the guards, then edit.
async fn tamper(path: &Path, sql: &str) -> u64 {
    let mut conn = SqliteConnectOptions::new()
        .filename(path)
        .connect()
        .await
        .expect("connect");
    conn.execute("DROP TRIGGER IF EXISTS audit_log_no_update")
        .await
        .expect("drop update trigger");
    conn.execute("DROP TRIGGER IF EXISTS audit_log_no_delete")
        .await
        .expect("drop delete trigger");
    let result = conn
        .execute(sqlx::raw_sql(sqlx::AssertSqlSafe(sql.to_string())))
        .await
        .expect("tamper");
    result.rows_affected()
}

async fn verify(path: &Path) -> VerifyReport {
    let log = AuditLog::open(path).await.expect("open");
    let report = log.verify().await.expect("verify");
    log.close().await;
    report
}
