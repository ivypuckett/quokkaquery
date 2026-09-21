//! Writing a result into its spool — the [`RowSink`] seam M0 built for this.
//!
//! The spool becomes `execute()`'s sink; it does not become a second execute path. It
//! never holds an [`ExecutePermit`](quokka_core::ExecutePermit) and never could: it
//! writes a SQLite file it created, and the only rows it ever sees are the ones the one
//! execute path hands it.

use std::path::{Path, PathBuf};

use quokka_core::{Cap, Column, Outcome, Retained, Row, RowSink};
use sqlx::sqlite::{SqliteConnectOptions, SqliteJournalMode, SqliteSynchronous};
use uuid::Uuid;

use crate::blocking::Worker;
use crate::codec;
use crate::error::SpoolError;
use crate::meta;

/// How many rows the writer gathers before handing a batch to its thread.
///
/// The bound is what keeps "never buffered in memory" true while still paying the
/// channel round-trip once per batch rather than once per row.
const BATCH_ROWS: usize = 512;

/// And the batch's other bound, so a result of very wide rows does not turn 512 rows
/// into hundreds of megabytes held at once.
const BATCH_BYTES: u64 = 4 * 1024 * 1024;

/// The limits a spool stops at (§4.2), and what the config file sets.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Limits {
    pub max_rows: u64,
    pub max_bytes: u64,
}

impl Default for Limits {
    fn default() -> Self {
        Self {
            max_rows: quokka_core::DEFAULT_SPOOL_MAX_ROWS,
            max_bytes: quokka_core::DEFAULT_SPOOL_MAX_BYTES,
        }
    }
}

impl From<quokka_core::SpoolConfig> for Limits {
    fn from(c: quokka_core::SpoolConfig) -> Self {
        Limits {
            max_rows: c.max_rows,
            max_bytes: c.max_bytes,
        }
    }
}

/// Writes one result into one spool file.
///
/// Hand it to `execute()` as the sink; read the finished spool back with
/// [`crate::Spool::open`] afterwards. The two are separate objects on purpose: a spool
/// is written once and read many times, and nothing should be able to write to one that
/// is being paged.
pub struct SpoolWriter {
    path: PathBuf,
    worker: Option<Worker>,
    limits: Limits,
    columns: Vec<Column>,
    pending: Vec<Row>,
    pending_bytes: u64,
    rows: u64,
    bytes: u64,
    capped: Option<Cap>,
    created_at: String,
    query_id: Uuid,
    connection: String,
    /// Set once `begin()` has created the tables.
    began: bool,
    /// Set once `end()` has finalized the file, so a double `end()` cannot corrupt it.
    finished: bool,
}

impl std::fmt::Debug for SpoolWriter {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SpoolWriter")
            .field("path", &self.path)
            .field("rows", &self.rows)
            .field("capped", &self.capped)
            .finish_non_exhaustive()
    }
}

impl SpoolWriter {
    /// Create the spool file for one query.
    ///
    /// Called before the query runs, so a spool that cannot be created stops the query
    /// from running at all rather than discovering it once rows are arriving.
    pub fn create(
        path: &Path,
        query_id: Uuid,
        connection: &str,
        limits: Limits,
    ) -> Result<Self, SpoolError> {
        let options = SqliteConnectOptions::new()
            .filename(path)
            .create_if_missing(true)
            // A cache we delete on exit has no durability to protect, and the cost of
            // pretending otherwise is an fsync per commit on a file nobody will ever
            // read again. The audit log makes the opposite choice for the opposite
            // reason.
            .synchronous(SqliteSynchronous::Off)
            .journal_mode(SqliteJournalMode::Memory);

        let worker = Worker::open(options)?;

        Ok(SpoolWriter {
            path: path.to_path_buf(),
            worker: Some(worker),
            limits,
            columns: Vec::new(),
            pending: Vec::new(),
            pending_bytes: 0,
            rows: 0,
            bytes: 0,
            capped: None,
            created_at: quokka_audit_now()?,
            query_id,
            connection: connection.to_string(),
            began: false,
            finished: false,
        })
    }

    pub fn path(&self) -> &Path {
        &self.path
    }

    /// Rows kept so far.
    pub fn rows(&self) -> u64 {
        self.rows
    }

    fn worker(&self) -> Result<&Worker, SpoolError> {
        self.worker
            .as_ref()
            .ok_or_else(|| SpoolError::Thread("this spool has already been finished".to_string()))
    }

    fn create_tables(&mut self, columns: &[Column]) -> Result<(), SpoolError> {
        let widths: String = (0..columns.len()).map(|i| format!(",\n  c{i}")).collect();
        let ddl = include_str!("schema.sql").replace("{columns}", &widths);

        // `Executor::execute` rather than `RawSql::execute`: the latter returns after
        // the first statement's result, which quietly leaves a three-table schema file
        // with one table in it. `quokka-audit` opens its schema the same way.
        self.worker()?.call(move |conn| {
            Box::pin(async move {
                use sqlx::Executor as _;
                conn.execute(sqlx::raw_sql(sqlx::AssertSqlSafe(ddl)))
                    .await
                    .map(|_| ())
            })
        })??;

        let rows: Vec<(i64, String, String, Option<i64>)> = columns
            .iter()
            .enumerate()
            .map(|(i, c)| {
                (
                    i as i64,
                    c.name.clone(),
                    c.driver_type.clone(),
                    c.nullable.map(i64::from),
                )
            })
            .collect();

        self.worker()?.call(move |conn| {
            Box::pin(async move {
                for (ordinal, name, driver_type, nullable) in rows {
                    sqlx::query(
                        "INSERT INTO schema (ordinal, name, driver_type, nullable) \
                         VALUES (?, ?, ?, ?)",
                    )
                    .bind(ordinal)
                    .bind(name)
                    .bind(driver_type)
                    .bind(nullable)
                    .execute(&mut *conn)
                    .await?;
                }
                Ok::<_, sqlx::Error>(())
            })
        })??;

        Ok(())
    }

    /// Would this row fit? Sets `capped` the first time it would not.
    fn room_for(&mut self, row: &Row) -> bool {
        if self.capped.is_some() {
            return false;
        }
        if self.rows >= self.limits.max_rows {
            self.capped = Some(Cap::Rows);
            return false;
        }
        let size: u64 = row.0.iter().map(|v| codec::encode(v).payload_bytes()).sum();
        if self.bytes.saturating_add(size) > self.limits.max_bytes {
            self.capped = Some(Cap::Bytes);
            return false;
        }
        self.bytes += size;
        true
    }

    fn flush(&mut self) -> Result<(), SpoolError> {
        if self.pending.is_empty() {
            return Ok(());
        }
        let rows = std::mem::take(&mut self.pending);
        self.pending_bytes = 0;
        let width = self.columns.len();
        let placeholders = vec!["?"; width].join(", ");
        let names: String = (0..width)
            .map(|i| format!("c{i}"))
            .collect::<Vec<_>>()
            .join(", ");
        let sql = format!("INSERT INTO result ({names}) VALUES ({placeholders})");

        self.worker()?.call(move |conn| {
            Box::pin(async move {
                // One transaction per batch: the spool is written once and read once,
                // so there is nothing to protect between batches, and a single
                // transaction around a million rows would only grow the journal.
                sqlx::query("BEGIN").execute(&mut *conn).await?;
                for row in &rows {
                    let mut query = sqlx::query(sqlx::AssertSqlSafe(sql.clone()));
                    for value in &row.0 {
                        query = codec::bind(query, codec::encode(value));
                    }
                    query.execute(&mut *conn).await?;
                }
                sqlx::query("COMMIT").execute(&mut *conn).await?;
                Ok::<_, sqlx::Error>(())
            })
        })??;

        Ok(())
    }

    fn write_meta(&mut self, outcome: &Outcome) -> Result<(), SpoolError> {
        let entries = meta::entries_for(
            &self.created_at,
            self.query_id,
            &self.connection,
            self.rows,
            self.capped,
            outcome,
        );

        self.worker()?.call(move |conn| {
            Box::pin(async move {
                for (key, value) in entries {
                    sqlx::query("INSERT OR REPLACE INTO meta (key, value) VALUES (?, ?)")
                        .bind(key)
                        .bind(value)
                        .execute(&mut *conn)
                        .await?;
                }
                // Arrival order is the rowid, so paging needs no index at all. A sort
                // over a column does, and building one per column up front would cost
                // more than the sorts most results never get — so ordering is left to
                // SQLite's temp b-tree, over a table bounded at a million rows.
                Ok::<_, sqlx::Error>(())
            })
        })??;

        Ok(())
    }
}

impl RowSink for SpoolWriter {
    fn begin(&mut self, columns: &[Column]) -> std::io::Result<()> {
        self.columns = columns.to_vec();
        self.create_tables(columns)?;
        self.began = true;
        Ok(())
    }

    fn row(&mut self, row: &Row) -> std::io::Result<()> {
        if !self.room_for(row) {
            // Full. Not an error: the rows keep coming, the cache stops growing, and
            // `retained()` below is what makes the difference visible in the outcome
            // and in the log (§4.2 — truncation is reported, never silent).
            return Ok(());
        }
        self.pending_bytes += row
            .0
            .iter()
            .map(|v| codec::encode(v).payload_bytes())
            .sum::<u64>();
        self.pending.push(row.clone());
        self.rows += 1;
        if self.pending.len() >= BATCH_ROWS || self.pending_bytes >= BATCH_BYTES {
            self.flush()?;
        }
        Ok(())
    }

    fn end(&mut self, outcome: &Outcome) -> std::io::Result<()> {
        if self.finished {
            return Ok(());
        }
        self.finished = true;

        // A query that failed before its shape was known never got a `begin()`, so
        // there are no tables to finish. Leave the file empty rather than inventing a
        // schema for a result that does not exist.
        //
        // A statement that returned *no columns* — an INSERT, a DDL — is a different
        // case and does get its meta written: the spool is empty because the result
        // was, which is a fact about the query rather than a missing file.
        if !self.began {
            if let Some(w) = self.worker.as_mut() {
                w.close();
            }
            return Ok(());
        }

        self.flush()?;
        self.write_meta(outcome)?;
        // Closing here rather than at drop is what releases the file: everything
        // downstream opens the spool for reading, and it should find a committed
        // database rather than one still held open by a writer.
        if let Some(w) = self.worker.as_mut() {
            w.close();
        }
        Ok(())
    }

    fn retained(&self) -> Option<Retained> {
        Some(Retained {
            rows: self.rows,
            capped: self.capped,
        })
    }
}

fn quokka_audit_now() -> Result<String, SpoolError> {
    use time::format_description::well_known::Rfc3339;
    Ok(time::OffsetDateTime::now_utc().format(&Rfc3339)?)
}
