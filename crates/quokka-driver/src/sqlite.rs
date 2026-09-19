//! The SQLite driver, over sqlx 0.9.
//!
//! Note the asymmetry ARCHITECTURE §3.1 calls out: `sqlx-sqlite` binds `libsqlite3-sys`,
//! so this one driver is a bundled C library and needs a C compiler to build. "Pure
//! Rust" is a claim about Postgres and MySQL, not about this.

use std::collections::HashMap;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};

use async_trait::async_trait;
use futures::StreamExt;
use quokka_core::{
    Catalog, Column, ConnectionConfig, Driver, DriverError, DriverFactory, ExecutePermit,
    MetaHandle, Plan, QueryHandle, QueryRequest, QueryStream, Row, Scope, Value,
};
use sqlx::sqlite::{SqliteConnectOptions, SqlitePoolOptions, SqliteRow};
use sqlx::{
    AssertSqlSafe, Column as _, Either, Executor, Row as _, SqlSafeStr, SqlitePool, Statement as _,
    TypeInfo, ValueRef,
};
use uuid::Uuid;

/// How many rows may sit between the database and the consumer.
///
/// Bounded on purpose: the channel is the backpressure, so a large result never buffers
/// in memory ahead of whoever is reading it.
const ROW_CHANNEL_DEPTH: usize = 64;

/// Opens SQLite connections.
pub struct SqliteFactory;

#[async_trait]
impl DriverFactory for SqliteFactory {
    fn name(&self) -> &'static str {
        "sqlite"
    }

    fn dialect(&self) -> quokka_core::Dialect {
        quokka_core::Dialect::Sqlite
    }

    async fn open(&self, cfg: &ConnectionConfig) -> Result<Arc<dyn Driver>, DriverError> {
        Ok(Arc::new(SqliteDriver::connect(cfg).await?))
    }
}

/// A pool of connections to one SQLite file.
pub struct SqliteDriver {
    pool: SqlitePool,
    connection: String,
    /// Cancellation flags for in-flight queries, keyed by `query_id`.
    cancels: Arc<Mutex<HashMap<Uuid, Arc<AtomicBool>>>>,
}

impl std::fmt::Debug for SqliteDriver {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SqliteDriver")
            .field("connection", &self.connection)
            .finish_non_exhaustive()
    }
}

#[async_trait]
impl Driver for SqliteDriver {
    fn dialect(&self) -> quokka_core::Dialect {
        quokka_core::Dialect::Sqlite
    }

    async fn connect(cfg: &ConnectionConfig) -> Result<Self, DriverError> {
        let path = cfg.path.as_ref().ok_or_else(|| DriverError::Connect {
            connection: cfg.name.clone(),
            detail: "a sqlite connection needs a `path` to a database file".to_string(),
        })?;

        let read_only = cfg.mode.is_read_only();
        let mut opts = SqliteConnectOptions::new()
            .filename(path)
            // A read-only connection is opened read-only at the file handle, so SQLite
            // itself refuses a write. Invariant 9 — the mode binds every surface — is
            // enforced by `quokka-policy` at M3; this is the same answer arrived at one
            // layer lower, and it is why `@audit` cannot be written through.
            .read_only(read_only)
            // Never conjure a database because a path was mistyped.
            .create_if_missing(false)
            .busy_timeout(std::time::Duration::from_secs(5));

        if !read_only {
            opts = opts.journal_mode(sqlx::sqlite::SqliteJournalMode::Wal);
        }

        let pool = SqlitePoolOptions::new()
            .max_connections(4)
            .connect_with(opts)
            .await
            .map_err(|e| DriverError::Connect {
                connection: cfg.name.clone(),
                detail: format!("{} ({})", e, path.display()),
            })?;

        Ok(SqliteDriver {
            pool,
            connection: cfg.name.clone(),
            cancels: Arc::new(Mutex::new(HashMap::new())),
        })
    }

    async fn introspect(
        &self,
        _permit: &ExecutePermit,
        _scope: Scope,
    ) -> Result<Catalog, DriverError> {
        // Introspection is an M1 deliverable, and it runs SQL — which means it needs an
        // audit story of its own before it exists, not after. Until `quokka-core` grows
        // an audited introspection path, this returns nothing rather than quietly
        // becoming a second, unlogged route to the database.
        Err(DriverError::Unsupported(
            "schema introspection arrives at M1".to_string(),
        ))
    }

    async fn execute(
        &self,
        _permit: &ExecutePermit,
        req: QueryRequest,
    ) -> Result<QueryStream, DriverError> {
        if !req.params.is_empty() {
            // Binding parameters is straightforward, but `params` also has to be written
            // to the audit log under the connection's `sql_logging` mode, and the CLI has
            // no way to supply them yet. Refusing beats accepting values that would go
            // unrecorded.
            return Err(DriverError::Unsupported(
                "bound parameters are not supported yet".to_string(),
            ));
        }

        // SQLite executes every statement in a multi-statement body, and the column
        // list below describes only the first. Rejecting stacked queries is
        // `quokka-policy`'s job at M3 (ARCHITECTURE §6.3); until then the log records
        // the whole body's fingerprint, so what ran is visible even where the result
        // shape is not.
        let columns = self.describe_columns(&req.sql).await?;

        let cancel = Arc::new(AtomicBool::new(false));
        {
            let mut map = self.cancels.lock().expect("cancel map poisoned");
            map.insert(req.handle.0, cancel.clone());
        }

        let meta = MetaHandle::new();
        let (tx, mut rx) =
            tokio::sync::mpsc::channel::<Result<Row, DriverError>>(ROW_CHANNEL_DEPTH);

        let pool = self.pool.clone();
        let sql = req.sql.clone();
        let task_meta = meta.clone();
        let task_cancel = cancel.clone();
        let cancels = self.cancels.clone();
        let handle = req.handle;

        tokio::spawn(async move {
            let mut stream = sqlx::raw_sql(AssertSqlSafe(sql)).fetch_many(&pool);
            while let Some(step) = stream.next().await {
                if task_cancel.load(Ordering::Relaxed) {
                    let _ = tx.send(Err(DriverError::Cancelled)).await;
                    break;
                }
                let message = match step {
                    // A statement that returned no rows still reports how many it changed.
                    Ok(Either::Left(result)) => {
                        let affected = result.rows_affected() as i64;
                        task_meta.update(|m| {
                            m.rows_affected = Some(m.rows_affected.unwrap_or(0) + affected)
                        });
                        continue;
                    }
                    Ok(Either::Right(row)) => Ok(row_from_sqlite(&row)),
                    Err(e) => Err(DriverError::Execute {
                        detail: e.to_string(),
                    }),
                };
                let is_err = message.is_err();
                // A closed receiver means the consumer stopped reading — the cap was
                // reached, or the caller went away. Either way, stop scanning.
                if tx.send(message).await.is_err() || is_err {
                    break;
                }
            }
            // Dropping the statement here is what actually stops SQLite; the flag only
            // gets us to the next row boundary.
            drop(stream);
            if let Ok(mut map) = cancels.lock() {
                map.remove(&handle.0);
            }
        });

        let rows = futures::stream::poll_fn(move |cx| rx.poll_recv(cx)).boxed();

        Ok(QueryStream {
            columns,
            rows,
            meta,
        })
    }

    async fn cancel(&self, handle: QueryHandle) -> Result<(), DriverError> {
        let flag = {
            let map = self.cancels.lock().expect("cancel map poisoned");
            map.get(&handle.0).cloned()
        };
        match flag {
            Some(f) => {
                f.store(true, Ordering::Relaxed);
                Ok(())
            }
            // Already finished. Cancelling a query that is no longer running is not an
            // error — the caller got what it asked for.
            None => Ok(()),
        }
    }

    async fn explain(&self, _permit: &ExecutePermit, _sql: &str) -> Result<Plan, DriverError> {
        // Same reasoning as `introspect`: it executes SQL, so it waits for the audited
        // path that M3's `quokka explain` will call.
        Err(DriverError::Unsupported(
            "EXPLAIN arrives with the policy engine at M3".to_string(),
        ))
    }
}

impl SqliteDriver {
    /// The result's shape, known before the first row so that a sink can be opened even
    /// for a query that returns nothing.
    ///
    /// `nullable` stays `None`: SQLite reports nullability for a plain table column and
    /// nothing useful for an expression, and a column list that is confidently wrong
    /// half the time is worse than one that says it does not know.
    async fn describe_columns(&self, sql: &str) -> Result<Vec<Column>, DriverError> {
        let statement = <&SqlitePool as Executor>::prepare(
            &self.pool,
            AssertSqlSafe(sql.to_string()).into_sql_str(),
        )
        .await
        .map_err(|e| DriverError::Execute {
            detail: e.to_string(),
        })?;

        Ok(statement
            .columns()
            .iter()
            .map(|c| Column {
                name: c.name().to_string(),
                driver_type: c.type_info().name().to_string(),
                nullable: None,
            })
            .collect())
    }

    /// Exposed for tests that need to reach the file this driver opened.
    pub fn pool(&self) -> &SqlitePool {
        &self.pool
    }
}

fn row_from_sqlite(row: &SqliteRow) -> Row {
    Row((0..row.len()).map(|i| value_at(row, i)).collect())
}

/// Decode one cell.
///
/// Invariant 10: an unrecognized type degrades to text and never aborts a result set.
/// Every branch below has a text fallback for exactly that reason — SQLite's dynamic
/// typing means a column declared `TEXT` may hold an integer, and a `DATETIME` column
/// holds whatever was put in it.
fn value_at(row: &SqliteRow, i: usize) -> Value {
    let raw = match row.try_get_raw(i) {
        Ok(r) => r,
        Err(_) => return Value::Null,
    };
    if raw.is_null() {
        return Value::Null;
    }
    let type_name = raw.type_info().name().to_ascii_uppercase();

    match type_name.as_str() {
        "INTEGER" | "INT" | "BIGINT" | "INT8" => row
            .try_get::<i64, _>(i)
            .map(Value::Int)
            .unwrap_or_else(|_| as_text(row, i)),
        "REAL" | "FLOAT" | "DOUBLE" | "NUMERIC" => row
            .try_get::<f64, _>(i)
            .map(Value::Float)
            .unwrap_or_else(|_| as_text(row, i)),
        "BOOLEAN" | "BOOL" => row
            .try_get::<bool, _>(i)
            .map(Value::Bool)
            .unwrap_or_else(|_| as_text(row, i)),
        "BLOB" => row
            .try_get::<Vec<u8>, _>(i)
            .map(Value::Blob)
            .unwrap_or_else(|_| as_text(row, i)),
        _ => as_text(row, i),
    }
}

fn as_text(row: &SqliteRow, i: usize) -> Value {
    if let Ok(s) = row.try_get::<String, _>(i) {
        return Value::Text(s);
    }
    if let Ok(b) = row.try_get::<Vec<u8>, _>(i) {
        return Value::Text(String::from_utf8_lossy(&b).into_owned());
    }
    // Nothing decoded, but the row still has this many columns — an empty string keeps
    // the shape rather than dropping a cell.
    Value::Text(String::new())
}
