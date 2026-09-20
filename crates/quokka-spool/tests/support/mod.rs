//! Shared scaffolding: a spool written by hand, and an engine over a real SQLite file.

#![allow(dead_code)]

use std::path::PathBuf;
use std::sync::Arc;

use quokka_core::{Cap, Outcome, RowSink, Status};
use quokka_spool::{Limits, SpoolWriter};
use uuid::Uuid;

/// A writer over a fresh spool file in a temporary directory.
pub fn spool_writer(limits: Limits) -> (tempfile::TempDir, SpoolWriter, PathBuf) {
    let dir = tempfile::tempdir().expect("tempdir");
    let path = dir.path().join("result.db");
    let writer = SpoolWriter::create(&path, Uuid::now_v7(), "test", limits).expect("spool");
    (dir, writer, path)
}

/// Close a spool the way `execute()` would, with the outcome it would have built.
pub fn finish(writer: &mut SpoolWriter, rows_returned: u64, truncated: bool) {
    let retained = writer.retained();
    let outcome = Outcome {
        query_id: Uuid::now_v7(),
        connection: "test".to_string(),
        status: Status::Ok,
        columns: Vec::new(),
        rows_returned,
        rows_affected: None,
        truncated,
        rows_spooled: retained.map(|r| r.rows),
        spool_capped: retained.and_then(|r| r.capped),
        duration_ms: 1,
        error_code: None,
        error_message: None,
    };
    writer.end(&outcome).expect("end");
}

/// What the spool reported keeping.
pub fn capped(writer: &SpoolWriter) -> Option<Cap> {
    writer.retained().and_then(|r| r.capped)
}

/// An engine over a real SQLite database and a real audit log, in one directory.
pub struct Harness {
    pub dir: tempfile::TempDir,
    pub engine: Arc<quokka_core::Engine>,
    pub audit_path: PathBuf,
}

impl Harness {
    /// A database holding `rows` rows of `(id, name, amount)`.
    pub async fn with_rows(rows: usize) -> Self {
        let dir = tempfile::tempdir().expect("tempdir");
        let db = dir.path().join("app.db");

        let pool = sqlx::SqlitePool::connect_with(
            sqlx::sqlite::SqliteConnectOptions::new()
                .filename(&db)
                .create_if_missing(true),
        )
        .await
        .expect("app db");
        sqlx::raw_sql("CREATE TABLE items (id INTEGER PRIMARY KEY, name TEXT, amount REAL)")
            .execute(&pool)
            .await
            .expect("schema");
        for i in 1..=rows {
            sqlx::query("INSERT INTO items (id, name, amount) VALUES (?, ?, ?)")
                .bind(i as i64)
                .bind(format!("item-{i:05}"))
                .bind(i as f64 * 1.5)
                .execute(&pool)
                .await
                .expect("seed");
        }
        pool.close().await;

        let audit_path = dir.path().join("audit.db");
        let audit = quokka_core::AuditLog::open(&audit_path)
            .await
            .expect("audit log");

        let mut registry = quokka_core::Registry::builtin_only(&audit_path);
        let mut cfg = quokka_core::ConnectionConfig::new("app", "sqlite");
        cfg.path = Some(db);
        cfg.credential = quokka_core::CredentialRef::None;
        registry.insert(cfg);

        let engine = Arc::new(quokka_core::Engine::new(
            registry,
            audit,
            quokka_driver::builtin_factories(),
        ));

        Harness {
            dir,
            engine,
            audit_path,
        }
    }

    /// Every event in the log, oldest first.
    pub async fn events(&self) -> Vec<quokka_core::AuditEvent> {
        let log = quokka_core::AuditLog::open(&self.audit_path)
            .await
            .expect("reopen audit");
        let events = log
            .read_all()
            .await
            .expect("read audit")
            .into_iter()
            .map(|e| e.event)
            .collect();
        log.close().await;
        events
    }
}
