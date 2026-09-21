//! Opening, appending to, and verifying the append-only log.

use std::path::{Path, PathBuf};

use sqlx::sqlite::{SqliteConnectOptions, SqlitePoolOptions, SqliteRow};
use sqlx::{Executor, Row, SqlitePool};
use time::format_description::well_known::Rfc3339;
use time::OffsetDateTime;
use uuid::Uuid;

use crate::event::{ActorKind, AuditEvent, Client, EventKind, SqlLogging, Status, StoredEvent};
use crate::hash::row_hash;

const SCHEMA: &str = include_str!("schema.sql");

#[derive(Debug, thiserror::Error)]
pub enum AuditError {
    #[error("audit log I/O at {path}: {source}")]
    Io {
        path: PathBuf,
        #[source]
        source: std::io::Error,
    },
    #[error("audit log database error: {0}")]
    Sqlx(#[from] sqlx::Error),
    #[error("audit log row {id} is unreadable: {detail}")]
    Corrupt { id: String, detail: String },
    #[error("could not format a timestamp: {0}")]
    Time(#[from] time::error::Format),
}

/// The append-only audit log: SQLite in WAL mode, at the XDG data dir by default.
#[derive(Debug, Clone)]
pub struct AuditLog {
    pool: SqlitePool,
    path: PathBuf,
}

impl AuditLog {
    /// Open (creating if absent) the log at `path`.
    pub async fn open(path: impl AsRef<Path>) -> Result<Self, AuditError> {
        let path = path.as_ref().to_path_buf();
        if let Some(dir) = path.parent() {
            if !dir.as_os_str().is_empty() {
                std::fs::create_dir_all(dir).map_err(|source| AuditError::Io {
                    path: dir.to_path_buf(),
                    source,
                })?;
            }
        }

        let opts = SqliteConnectOptions::new()
            .filename(&path)
            .create_if_missing(true)
            // WAL so that a reader on the @audit connection never blocks the writer
            // appending the event for the very query doing the reading.
            .journal_mode(sqlx::sqlite::SqliteJournalMode::Wal)
            // A log that loses its last few events on a power cut is not a log. The
            // fsync per append is the price of the fail-closed promise.
            .synchronous(sqlx::sqlite::SqliteSynchronous::Full)
            .foreign_keys(true)
            .busy_timeout(std::time::Duration::from_secs(5));

        let pool = SqlitePoolOptions::new()
            .max_connections(4)
            .connect_with(opts)
            .await?;

        pool.execute(sqlx::raw_sql(SCHEMA)).await?;

        Ok(Self { pool, path })
    }

    pub fn path(&self) -> &Path {
        &self.path
    }

    /// Close the pool. Called on clean shutdown so WAL is checkpointed promptly.
    pub async fn close(&self) {
        self.pool.close().await;
    }

    /// Append one event, sealing it against the current chain head.
    ///
    /// The insert and the head checkpoint share one `BEGIN IMMEDIATE` transaction, so
    /// two writers cannot interleave and produce two rows claiming the same `prev_hash`.
    pub async fn append(&self, event: AuditEvent) -> Result<StoredEvent, AuditError> {
        let mut conn = self.pool.acquire().await?;

        // `BEGIN IMMEDIATE` rather than sqlx's deferred transaction: the read of the
        // chain head must already hold the write lock, or two appends could read the
        // same head.
        sqlx::query("BEGIN IMMEDIATE").execute(&mut *conn).await?;

        let result = async {
            let head: Option<(Option<String>, i64)> =
                sqlx::query_as("SELECT head_hash, row_count FROM audit_chain_head WHERE id = 0")
                    .fetch_optional(&mut *conn)
                    .await?;
            let (prev_hash, row_count) = head.unwrap_or((None, 0));

            let hash = row_hash(&event, prev_hash.as_deref());

            sqlx::query(INSERT_SQL)
                .bind(event.id.to_string())
                .bind(event.query_id.to_string())
                .bind(event.parent_id.map(|u| u.to_string()))
                .bind(&event.at)
                .bind(event.duration_ms)
                .bind(event.actor_kind.as_str())
                .bind(&event.actor_id)
                .bind(&event.session_id)
                .bind(event.client.as_str())
                .bind(&event.connection)
                .bind(&event.dialect)
                .bind(event.database.as_deref())
                .bind(event.schema_name.as_deref())
                .bind(event.event_kind.as_str())
                .bind(event.sql_logging.as_str())
                .bind(event.sql_text.as_deref())
                .bind(&event.sql_fingerprint)
                .bind(event.statement_kind.as_deref())
                .bind(event.read_only.map(i64::from))
                .bind(event.params.as_deref())
                .bind(event.status.as_str())
                .bind(event.error_code.as_deref())
                .bind(event.error_message.as_deref())
                .bind(event.rows_returned)
                .bind(event.rows_affected)
                .bind(event.rows_spooled)
                .bind(event.truncated.map(i64::from))
                .bind(event.export_format.as_deref())
                .bind(event.export_path.as_deref())
                .bind(event.data_scanned_bytes)
                .bind(event.cost_estimate_usd)
                .bind(event.approved_by.as_deref())
                .bind(event.tags.as_deref())
                .bind(prev_hash.as_deref())
                .bind(&hash)
                .execute(&mut *conn)
                .await?;

            sqlx::query(
                "UPDATE audit_chain_head SET head_id = ?, head_hash = ?, row_count = ? \
                 WHERE id = 0",
            )
            .bind(event.id.to_string())
            .bind(&hash)
            .bind(row_count + 1)
            .execute(&mut *conn)
            .await?;

            Ok::<_, AuditError>((prev_hash, hash))
        }
        .await;

        match result {
            Ok((prev_hash, hash)) => {
                sqlx::query("COMMIT").execute(&mut *conn).await?;
                Ok(StoredEvent {
                    event,
                    prev_hash,
                    row_hash: hash,
                })
            }
            Err(e) => {
                // Best effort: if the rollback itself fails the connection is dropped,
                // which rolls the transaction back anyway.
                let _ = sqlx::query("ROLLBACK").execute(&mut *conn).await;
                Err(e)
            }
        }
    }

    /// Read every row in chain order.
    pub async fn read_all(&self) -> Result<Vec<StoredEvent>, AuditError> {
        let rows = sqlx::query("SELECT * FROM audit_log ORDER BY id ASC")
            .fetch_all(&self.pool)
            .await?;
        rows.iter().map(stored_from_row).collect()
    }

    /// Every event sharing `query_id`, oldest first.
    pub async fn events_for_query(&self, query_id: Uuid) -> Result<Vec<StoredEvent>, AuditError> {
        let rows = sqlx::query("SELECT * FROM audit_log WHERE query_id = ? ORDER BY id ASC")
            .bind(query_id.to_string())
            .fetch_all(&self.pool)
            .await?;
        rows.iter().map(stored_from_row).collect()
    }

    /// Bytes this actor has scanned on one connection since `since` (§6.4).
    ///
    /// **Why this is a method here rather than a query through `execute()`.** §6.4 says
    /// "a budget check is a query against `@audit`", and that is true of where the
    /// number lives. Routing the check through the one execute path is a different
    /// claim, and it does not survive contact with §5: `@audit` is an ordinary
    /// connection, so a query against it appends `query_started` and `query_finished` —
    /// and *that* query would then need a budget check of its own, which appends two
    /// more. Even bounded, a log that fills with its own bookkeeping is a log nobody
    /// reads, and the events would be indistinguishable from queries a person ran.
    ///
    /// The standing this takes instead is the one `quokka export --query-id` already
    /// claimed and `quokka audit verify` has always had: **this program consulting its
    /// own record.** It is a structured lookup with no caller-supplied SQL — one
    /// aggregate over fixed columns, with every value bound — rather than SQL somebody
    /// asked to run. Invariant 1 is about reaching *a database* on a caller's behalf;
    /// `quokka-audit` reading the file it owns and writes is not that, which is why
    /// `verify()` above needs no permit either. A query a person writes against the log
    /// still goes through `@audit` and is logged like any other.
    ///
    /// Counts `query_finished` rows only, since that is where the column is filled, and
    /// filters by `actor_id` *and* `actor_kind` so that a human and an agent sharing a
    /// name do not pool their spending.
    pub async fn data_scanned_since(
        &self,
        connection: &str,
        actor_id: &str,
        actor_kind: ActorKind,
        since: &str,
    ) -> Result<u64, AuditError> {
        // NULL and 0 are different things everywhere else in this file; here they are
        // the same, because a driver that reports no bytes scanned has scanned none
        // that we know of and cannot be charged for what it did not report.
        let total: Option<i64> = sqlx::query_scalar(
            "SELECT sum(data_scanned_bytes) FROM audit_log \
             WHERE event_kind = 'query_finished' \
               AND connection = ? AND actor_id = ? AND actor_kind = ? \
               AND at >= ?",
        )
        .bind(connection)
        .bind(actor_id)
        .bind(actor_kind.as_str())
        .bind(since)
        .fetch_one(&self.pool)
        .await?;

        Ok(total.unwrap_or(0).max(0) as u64)
    }

    /// Recompute the chain and compare it with what is stored.
    ///
    /// Detects any edited row (its own hash no longer matches its contents), any excised
    /// row (the next row's `prev_hash` no longer matches its predecessor), and a
    /// truncated tail (the checkpointed head no longer matches the last row).
    pub async fn verify(&self) -> Result<VerifyReport, AuditError> {
        let rows = self.read_all().await?;

        let mut problems = Vec::new();
        let mut prev: Option<String> = None;

        for stored in &rows {
            let id = stored.event.id.to_string();
            if stored.prev_hash.as_deref() != prev.as_deref() {
                problems.push(Problem::BrokenLink {
                    id: id.clone(),
                    expected_prev: prev.clone(),
                    found_prev: stored.prev_hash.clone(),
                });
            }
            let recomputed = row_hash(&stored.event, stored.prev_hash.as_deref());
            if recomputed != stored.row_hash {
                problems.push(Problem::AlteredRow {
                    id: id.clone(),
                    expected: recomputed.clone(),
                    found: stored.row_hash.clone(),
                });
            }
            // Continue from what is *stored*, so one bad row reports once rather than
            // cascading a mismatch onto every row after it.
            prev = Some(stored.row_hash.clone());
        }

        let head: Option<(Option<String>, Option<String>, i64)> = sqlx::query_as(
            "SELECT head_id, head_hash, row_count FROM audit_chain_head WHERE id = 0",
        )
        .fetch_optional(&self.pool)
        .await?;
        let (head_id, head_hash, row_count) = head.unwrap_or((None, None, 0));

        let actual_head = rows.last();
        if head_hash.as_deref() != actual_head.map(|r| r.row_hash.as_str()) {
            problems.push(Problem::HeadMismatch {
                expected_head_id: head_id,
                expected_head_hash: head_hash,
                found_head_hash: actual_head.map(|r| r.row_hash.clone()),
            });
        }
        if row_count != rows.len() as i64 {
            problems.push(Problem::CountMismatch {
                expected: row_count,
                found: rows.len() as i64,
            });
        }

        Ok(VerifyReport {
            rows_checked: rows.len(),
            problems,
        })
    }
}

/// What `quokka audit verify` found.
#[derive(Debug, Clone, serde::Serialize)]
pub struct VerifyReport {
    pub rows_checked: usize,
    pub problems: Vec<Problem>,
}

impl VerifyReport {
    pub fn is_intact(&self) -> bool {
        self.problems.is_empty()
    }
}

/// One way the chain failed to verify.
#[derive(Debug, Clone, serde::Serialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum Problem {
    /// The row's contents no longer hash to its stored `row_hash`.
    AlteredRow {
        id: String,
        expected: String,
        found: String,
    },
    /// The row does not link to its predecessor — a row before it was removed or reordered.
    BrokenLink {
        id: String,
        expected_prev: Option<String>,
        found_prev: Option<String>,
    },
    /// The checkpointed head is not the last row — the tail was truncated.
    HeadMismatch {
        expected_head_id: Option<String>,
        expected_head_hash: Option<String>,
        found_head_hash: Option<String>,
    },
    /// The checkpointed row count disagrees with the number of rows present.
    CountMismatch { expected: i64, found: i64 },
}

impl std::fmt::Display for Problem {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Problem::AlteredRow { id, .. } => {
                write!(f, "row {id} was altered: its contents no longer match its hash")
            }
            Problem::BrokenLink { id, .. } => write!(
                f,
                "row {id} does not link to its predecessor: a row before it was removed or reordered"
            ),
            Problem::HeadMismatch { .. } => {
                write!(f, "the chain head does not match the last row: the log was truncated")
            }
            Problem::CountMismatch { expected, found } => {
                write!(f, "the log holds {found} rows but {expected} were appended")
            }
        }
    }
}

/// The current UTC time in the form the `at` column stores.
pub fn now_rfc3339() -> Result<String, AuditError> {
    Ok(OffsetDateTime::now_utc().format(&Rfc3339)?)
}

fn stored_from_row(row: &SqliteRow) -> Result<StoredEvent, AuditError> {
    let id_str: String = row.try_get("id")?;
    let bad = |detail: String| AuditError::Corrupt {
        id: id_str.clone(),
        detail,
    };

    let uuid = |s: &str| Uuid::parse_str(s).map_err(|e| bad(format!("bad uuid {s:?}: {e}")));
    let opt_uuid = |s: Option<String>| -> Result<Option<Uuid>, AuditError> {
        s.as_deref().map(uuid).transpose()
    };
    let opt_bool = |v: Option<i64>| v.map(|i| i != 0);

    let event = AuditEvent {
        id: uuid(&id_str)?,
        query_id: uuid(&row.try_get::<String, _>("query_id")?)?,
        parent_id: opt_uuid(row.try_get("parent_id")?)?,
        at: row.try_get("at")?,
        duration_ms: row.try_get("duration_ms")?,
        actor_kind: {
            let s: String = row.try_get("actor_kind")?;
            ActorKind::parse(&s).ok_or_else(|| bad(format!("unknown actor_kind {s:?}")))?
        },
        actor_id: row.try_get("actor_id")?,
        session_id: row.try_get("session_id")?,
        client: {
            let s: String = row.try_get("client")?;
            Client::parse(&s).ok_or_else(|| bad(format!("unknown client {s:?}")))?
        },
        connection: row.try_get("connection")?,
        dialect: row.try_get("dialect")?,
        database: row.try_get("database")?,
        schema_name: row.try_get("schema_name")?,
        event_kind: {
            let s: String = row.try_get("event_kind")?;
            EventKind::parse(&s).ok_or_else(|| bad(format!("unknown event_kind {s:?}")))?
        },
        sql_logging: {
            let s: String = row.try_get("sql_logging")?;
            SqlLogging::parse(&s).ok_or_else(|| bad(format!("unknown sql_logging {s:?}")))?
        },
        sql_text: row.try_get("sql_text")?,
        sql_fingerprint: row.try_get("sql_fingerprint")?,
        statement_kind: row.try_get("statement_kind")?,
        read_only: opt_bool(row.try_get("read_only")?),
        params: row.try_get("params")?,
        status: {
            let s: String = row.try_get("status")?;
            Status::parse(&s).ok_or_else(|| bad(format!("unknown status {s:?}")))?
        },
        error_code: row.try_get("error_code")?,
        error_message: row.try_get("error_message")?,
        rows_returned: row.try_get("rows_returned")?,
        rows_affected: row.try_get("rows_affected")?,
        rows_spooled: row.try_get("rows_spooled")?,
        truncated: opt_bool(row.try_get("truncated")?),
        export_format: row.try_get("export_format")?,
        export_path: row.try_get("export_path")?,
        data_scanned_bytes: row.try_get("data_scanned_bytes")?,
        cost_estimate_usd: row.try_get("cost_estimate_usd")?,
        approved_by: row.try_get("approved_by")?,
        tags: row.try_get("tags")?,
    };

    Ok(StoredEvent {
        event,
        prev_hash: row.try_get("prev_hash")?,
        row_hash: row.try_get("row_hash")?,
    })
}

const INSERT_SQL: &str = "INSERT INTO audit_log (
    id, query_id, parent_id, at, duration_ms,
    actor_kind, actor_id, session_id, client,
    connection, dialect, database, schema_name,
    event_kind, sql_logging, sql_text, sql_fingerprint, statement_kind, read_only, params,
    status, error_code, error_message,
    rows_returned, rows_affected, rows_spooled, truncated,
    export_format, export_path, data_scanned_bytes, cost_estimate_usd,
    approved_by, tags,
    prev_hash, row_hash
) VALUES (
    ?, ?, ?, ?, ?,
    ?, ?, ?, ?,
    ?, ?, ?, ?,
    ?, ?, ?, ?, ?, ?, ?,
    ?, ?, ?,
    ?, ?, ?, ?,
    ?, ?, ?, ?,
    ?, ?,
    ?, ?
)";
