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
    MetaHandle, Plan, QueryHandle, QueryRequest, QueryStream, Row, Scope, TableInfo, Value,
};
use sqlx::sqlite::{SqliteConnectOptions, SqlitePoolOptions, SqliteRow};
use sqlx::{
    AssertSqlSafe, Column as _, Either, Executor, Row as _, SqlSafeStr, SqlitePool, Statement as _,
    TypeInfo, ValueRef,
};
use uuid::Uuid;

use crate::common::{self, ROW_CHANNEL_DEPTH};

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

    /// SQLite's catalog: `sqlite_master` for the objects, `pragma_table_info` for the
    /// columns of each (§3.1).
    ///
    /// Only reachable through `quokka_core::introspect()`, which appends the single
    /// `introspect` event afterwards (§5) — the [`ExecutePermit`] is what makes that
    /// structural rather than a convention.
    async fn introspect(
        &self,
        _permit: &ExecutePermit,
        scope: Scope,
    ) -> Result<Catalog, DriverError> {
        let objects: Vec<(String, String)> = sqlx::query_as(
            "SELECT name, type FROM sqlite_master \
             WHERE type IN ('table','view') AND name NOT LIKE 'sqlite\\_%' ESCAPE '\\' \
               AND (?1 IS NULL OR name = ?1) \
             ORDER BY name",
        )
        .bind(scope.table.as_deref())
        .fetch_all(&self.pool)
        .await
        .map_err(execute_error)?;

        let mut tables = Vec::with_capacity(objects.len());
        for (name, kind) in objects {
            // One `pragma_table_info` per object. N+1 against a local file is cheap, and
            // it is the only way SQLite reports column types at all.
            let columns: Vec<(String, String, i64)> = sqlx::query_as(
                "SELECT name, type, \"notnull\" FROM pragma_table_info(?) ORDER BY cid",
            )
            .bind(&name)
            .fetch_all(&self.pool)
            .await
            .map_err(execute_error)?;

            tables.push(TableInfo {
                database: scope.database.clone(),
                // SQLite has attached databases rather than schemas, and `main` is the
                // only one a connection of ours opens.
                schema: None,
                name,
                kind: if kind == "view" { "view" } else { "table" }.to_string(),
                columns: columns
                    .into_iter()
                    .map(|(name, driver_type, notnull)| Column {
                        name,
                        // An empty declared type is SQLite's "no affinity", not a
                        // missing answer — it is reported as written.
                        driver_type,
                        nullable: Some(notnull == 0),
                    })
                    .collect(),
            });
        }

        Ok(Catalog { tables })
    }

    async fn execute(
        &self,
        _permit: &ExecutePermit,
        req: QueryRequest,
    ) -> Result<QueryStream, DriverError> {
        // The stacked-query surprise §6.3 names, closed from the driver's own side.
        //
        // Until M3 this driver had a real hole: with nothing bound, execution went
        // through `sqlx::raw_sql`, which runs a whole multi-statement body, while
        // `describe_columns` described only the first statement of it — so a stacked body
        // ran in full and came back wearing the shape of its opening `SELECT`.
        //
        // Rejecting stacked bodies is `quokka-policy`'s rule and it now runs inside
        // `execute()`, before anything reaches here. This check is the second layer, and
        // it is not redundant: `sqlx-sqlite` walks the statement tail *even on the
        // prepared path*, so unifying the two protocols below made the describe and the
        // execution agree without making "only one statement runs" true. Only this does.
        // Postgres and MySQL need no equivalent — their servers refuse to prepare a
        // multi-statement body, which is the same guarantee arriving from the other end.
        let statements =
            quokka_policy::summarize(&req.sql, quokka_core::Dialect::Sqlite).statement_count;
        if statements > 1 {
            return Err(DriverError::Unsupported(format!(
                "this body holds {statements} statements and SQLite would run all of \
                 them; QuokkaQuery runs one statement per query (§6.3)"
            )));
        }

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
        let params = req.params.clone();
        let task_meta = meta.clone();
        let task_cancel = cancel.clone();
        let cancels = self.cancels.clone();
        let handle = req.handle;

        tokio::spawn(async move {
            // One protocol, whether or not anything is bound, so that the statement
            // `describe_columns` described is the statement that runs. The road not
            // taken is `sqlx::raw_sql`, which is how this driver used to handle the
            // unparameterized case: it is the natural way to run a `.sql` file, and that
            // is exactly the problem — a file is several statements, one query is one
            // statement, and the audit log's two events describe one query. Running a
            // file is a feature that needs its own shape (a query pair per statement),
            // not a side effect of leaving a parameter list empty.
            let query = common::bind_all_sqlite(sqlx::query(AssertSqlSafe(sql)), &params);
            let mut stream = <&SqlitePool as Executor>::fetch_many(&pool, query).boxed();
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

    /// `EXPLAIN QUERY PLAN`, not bare `EXPLAIN`.
    ///
    /// SQLite's `EXPLAIN` lists virtual-machine bytecode, which is a debugging aid for
    /// SQLite itself and tells a person nothing about their query. `EXPLAIN QUERY PLAN`
    /// is the one that answers "will this use the index", which is the question being
    /// asked. Neither executes the statement.
    ///
    /// Only reachable through `quokka_core::explain()`, which writes the two events
    /// around it — the [`ExecutePermit`] is what makes that structural (invariant 1).
    async fn explain(&self, _permit: &ExecutePermit, sql: &str) -> Result<Plan, DriverError> {
        let rows = sqlx::query(AssertSqlSafe(format!("EXPLAIN QUERY PLAN {sql}")))
            .fetch_all(&self.pool)
            .await
            .map_err(execute_error)?;

        // Four columns — id, parent, notused, detail — of which `detail` is the sentence
        // a person reads. Indentation by parent would be prettier and would mean
        // reconstructing SQLite's tree; the details in order are what the shell prints.
        let text = rows
            .iter()
            .map(|row| row.try_get::<String, _>("detail").unwrap_or_default())
            .collect::<Vec<_>>()
            .join("\n");

        Ok(Plan {
            dialect: quokka_core::Dialect::Sqlite,
            text,
        })
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

fn execute_error(e: sqlx::Error) -> DriverError {
    DriverError::Execute {
        detail: e.to_string(),
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
