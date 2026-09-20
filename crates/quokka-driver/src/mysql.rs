//! The MySQL / MariaDB driver, over sqlx 0.9.
//!
//! Pure Rust wire protocol, and here that is a licensing decision as much as a technical
//! one: Oracle's `libmysqlclient` is GPLv2 and this project is MIT, so linking it is not
//! an option however convenient it would be (§3.0). sqlx's implementation sidesteps the
//! question entirely, and `rustls` keeps the TLS side free of a system library too.
//!
//! The same two properties as the Postgres driver hold, for the same reasons:
//!
//! - **Unknown types render as text, never fail** (§3.0 hedge 1, invariant 10). The
//!   unparameterized path uses MySQL's *text* protocol, in which every column arrives as
//!   the server's own string rendering — so a `GEOMETRY`, a `JSON`, a `DECIMAL(38,10)`
//!   or a type this build has never seen degrades to a string rather than aborting.
//! - **A connection error never carries a credential.** Options are set field by field
//!   rather than parsed from a URL, and the failure text names
//!   `ConnectionConfig::target()`.

use std::collections::HashMap;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};

use async_trait::async_trait;
use futures::stream::BoxStream;
use futures::StreamExt;
use quokka_core::{
    credential, Catalog, Column, ConnectionConfig, Driver, DriverError, DriverFactory,
    ExecutePermit, MetaHandle, Plan, QueryHandle, QueryRequest, QueryStream, Row, Scope, TableInfo,
    TlsMode, Value,
};
use sqlx::mysql::{MySqlConnectOptions, MySqlPoolOptions, MySqlRow, MySqlSslMode};
use sqlx::{
    AssertSqlSafe, Column as _, Either, Executor, Row as _, SqlSafeStr, Statement as _, TypeInfo,
    ValueRef,
};
use uuid::Uuid;

use crate::common::{self, ROW_CHANNEL_DEPTH};

/// Opens MySQL connections.
pub struct MySqlFactory;

#[async_trait]
impl DriverFactory for MySqlFactory {
    fn name(&self) -> &'static str {
        "mysql"
    }

    fn dialect(&self) -> quokka_core::Dialect {
        quokka_core::Dialect::MySql
    }

    async fn open(&self, cfg: &ConnectionConfig) -> Result<Arc<dyn Driver>, DriverError> {
        Ok(Arc::new(MySqlDriver::connect(cfg).await?))
    }
}

/// A pool of connections to one MySQL server.
pub struct MySqlDriver {
    pool: sqlx::MySqlPool,
    connection: String,
    cancels: Arc<Mutex<HashMap<Uuid, Arc<AtomicBool>>>>,
}

impl std::fmt::Debug for MySqlDriver {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("MySqlDriver")
            .field("connection", &self.connection)
            .finish_non_exhaustive()
    }
}

#[async_trait]
impl Driver for MySqlDriver {
    fn dialect(&self) -> quokka_core::Dialect {
        quokka_core::Dialect::MySql
    }

    async fn connect(cfg: &ConnectionConfig) -> Result<Self, DriverError> {
        let host = cfg.host.as_deref().ok_or_else(|| DriverError::Connect {
            connection: cfg.name.clone(),
            detail: "a mysql connection needs a `host`".to_string(),
        })?;

        let mut opts = MySqlConnectOptions::new().ssl_mode(ssl_mode(cfg.tls));
        opts = if host.starts_with('/') {
            opts.socket(host)
        } else {
            opts.host(host)
        };
        if let Some(port) = cfg.effective_port() {
            opts = opts.port(port);
        }
        if let Some(user) = &cfg.user {
            opts = opts.username(user);
        }
        if let Some(database) = &cfg.database {
            opts = opts.database(database);
        }

        let secret = credential::resolve_async(&cfg.credential)
            .await
            .map_err(|e| DriverError::Connect {
                connection: cfg.name.clone(),
                detail: e.to_string(),
            })?;
        if let Some(secret) = &secret {
            opts = opts.password(secret.expose());
        }

        let mut pool = MySqlPoolOptions::new().max_connections(4);
        if cfg.mode.is_read_only() {
            // Invariant 9 one layer below the policy engine, as in the Postgres driver —
            // except that MySQL has no startup parameter for it, so it costs one
            // statement per physical connection. That statement is the driver's own
            // connection setup, not a caller's query: it is the same kind of thing as
            // opening a SQLite file with the read-only flag, and nothing about it is
            // reachable from a surface.
            pool = pool.after_connect(|conn, _meta| {
                Box::pin(async move {
                    conn.execute("SET SESSION TRANSACTION READ ONLY").await?;
                    Ok(())
                })
            });
        }

        let pool = pool
            .connect_with(opts)
            .await
            .map_err(|e| connect_error(cfg, e))?;

        Ok(MySqlDriver {
            pool,
            connection: cfg.name.clone(),
            cancels: Arc::new(Mutex::new(HashMap::new())),
        })
    }

    /// The catalog from `information_schema` (§3.1).
    ///
    /// `COLUMN_TYPE` rather than `DATA_TYPE`, because the former keeps the parameters a
    /// user would recognize — `varchar(64)`, `decimal(10,2)`, `enum('a','b')` — and a
    /// catalog exists to tell you exactly that.
    async fn introspect(
        &self,
        _permit: &ExecutePermit,
        scope: Scope,
    ) -> Result<Catalog, DriverError> {
        // MySQL's "schema" and "database" are the same thing. A scope may name it either
        // way; absent both, the connection's own database is the sensible default, and a
        // whole-server catalog is available by asking for it explicitly.
        let schema = scope
            .schema
            .clone()
            .or_else(|| scope.database.clone())
            .or_else(|| self.pool.connect_options().get_database().map(String::from));

        let rows: Vec<(
            String,
            String,
            String,
            Option<String>,
            Option<String>,
            Option<String>,
        )> = sqlx::query_as(CATALOG_SQL)
            // MySQL has positional placeholders with no reuse, so each `?` in the
            // `(? IS NULL OR col = ?)` pairs below is bound separately.
            .bind(schema.as_deref())
            .bind(schema.as_deref())
            .bind(scope.table.as_deref())
            .bind(scope.table.as_deref())
            .fetch_all(&self.pool)
            .await
            .map_err(execute_error)?;

        let mut tables: Vec<TableInfo> = Vec::new();
        for (schema, name, kind, column, driver_type, nullable) in rows {
            let same = tables
                .last()
                .map(|t: &TableInfo| {
                    t.database.as_deref() == Some(schema.as_str()) && t.name == name
                })
                .unwrap_or(false);
            if !same {
                tables.push(TableInfo {
                    database: Some(schema.clone()),
                    // Reported as the database rather than duplicated into `schema`:
                    // MySQL has one level of namespace, and pretending otherwise would
                    // make a catalog from MySQL and one from Postgres disagree about
                    // what the fields mean.
                    schema: None,
                    name,
                    kind: if kind.eq_ignore_ascii_case("VIEW") {
                        "view".to_string()
                    } else {
                        "table".to_string()
                    },
                    columns: Vec::new(),
                });
            }
            if let (Some(column), Some(driver_type)) = (column, driver_type) {
                if let Some(t) = tables.last_mut() {
                    t.columns.push(Column {
                        name: column,
                        driver_type,
                        nullable: nullable.map(|n| n.eq_ignore_ascii_case("YES")),
                    });
                }
            }
        }

        Ok(Catalog { tables })
    }

    async fn execute(
        &self,
        _permit: &ExecutePermit,
        req: QueryRequest,
    ) -> Result<QueryStream, DriverError> {
        let described = self.describe_columns(&req.sql).await;

        let cancel = Arc::new(AtomicBool::new(false));
        {
            let mut map = self.cancels.lock().expect("cancel map poisoned");
            map.insert(req.handle.0, cancel.clone());
        }

        let meta = MetaHandle::new();
        let (tx, mut rx) =
            tokio::sync::mpsc::channel::<Result<MySqlRow, DriverError>>(ROW_CHANNEL_DEPTH);

        let pool = self.pool.clone();
        let sql = req.sql.clone();
        let params = req.params.clone();
        let task_meta = meta.clone();
        let task_cancel = cancel.clone();
        let cancels = self.cancels.clone();
        let handle = req.handle;

        tokio::spawn(async move {
            let mut stream: BoxStream<'_, _> = if params.is_empty() {
                sqlx::raw_sql(AssertSqlSafe(sql)).fetch_many(&pool).boxed()
            } else {
                let query = common::bind_all_mysql(sqlx::query(AssertSqlSafe(sql)), &params);
                <&sqlx::MySqlPool as Executor>::fetch_many(&pool, query).boxed()
            };

            while let Some(step) = stream.next().await {
                if task_cancel.load(Ordering::Relaxed) {
                    let _ = tx.send(Err(DriverError::Cancelled)).await;
                    break;
                }
                let message = match step {
                    Ok(Either::Left(result)) => {
                        let affected = result.rows_affected() as i64;
                        task_meta.update(|m| {
                            m.rows_affected = Some(m.rows_affected.unwrap_or(0) + affected)
                        });
                        continue;
                    }
                    Ok(Either::Right(row)) => Ok(row),
                    Err(e) => Err(execute_error(e)),
                };
                let is_err = message.is_err();
                if tx.send(message).await.is_err() || is_err {
                    break;
                }
            }
            drop(stream);
            if let Ok(mut map) = cancels.lock() {
                map.remove(&handle.0);
            }
        });

        let (columns, buffered) = match described {
            Some(columns) => (columns, None),
            None => {
                let first = rx.recv().await;
                let columns = match &first {
                    Some(Ok(row)) => columns_of(row),
                    _ => Vec::new(),
                };
                (columns, Some(first))
            }
        };

        let tail = futures::stream::poll_fn(move |cx| rx.poll_recv(cx));
        let rows = match buffered {
            Some(first) => futures::stream::iter(first).chain(tail).boxed(),
            None => tail.boxed(),
        };
        let rows = rows.map(|r| r.map(|row| row_from_mysql(&row))).boxed();

        Ok(QueryStream {
            columns,
            rows,
            meta,
        })
    }

    /// Stop reading and let the statement go.
    ///
    /// As with Postgres: sqlx 0.9 gives no access to the connection id, so the `KILL
    /// QUERY <id>` that would stop the server is out of reach and this stops the
    /// consumer instead. Stated rather than implied, because a cancel that only looks
    /// like one is worse than none.
    async fn cancel(&self, handle: QueryHandle) -> Result<(), DriverError> {
        let flag = {
            let map = self.cancels.lock().expect("cancel map poisoned");
            map.get(&handle.0).cloned()
        };
        if let Some(f) = flag {
            f.store(true, Ordering::Relaxed);
        }
        Ok(())
    }

    async fn explain(&self, _permit: &ExecutePermit, _sql: &str) -> Result<Plan, DriverError> {
        Err(DriverError::Unsupported(
            "EXPLAIN arrives with the policy engine at M3".to_string(),
        ))
    }
}

impl MySqlDriver {
    /// The result's shape, or `None` when the server would not describe the statement —
    /// a multi-statement body, most often, which the text protocol runs happily.
    async fn describe_columns(&self, sql: &str) -> Option<Vec<Column>> {
        let statement = <&sqlx::MySqlPool as Executor>::prepare(
            &self.pool,
            AssertSqlSafe(sql.to_string()).into_sql_str(),
        )
        .await
        .ok()?;

        Some(
            statement
                .columns()
                .iter()
                .map(|c| Column {
                    name: c.name().to_string(),
                    driver_type: c.type_info().name().to_string(),
                    nullable: None,
                })
                .collect(),
        )
    }

    /// Exposed for tests that need to reach the database this driver opened.
    pub fn pool(&self) -> &sqlx::MySqlPool {
        &self.pool
    }
}

fn ssl_mode(tls: TlsMode) -> MySqlSslMode {
    match tls {
        TlsMode::Disable => MySqlSslMode::Disabled,
        TlsMode::Prefer => MySqlSslMode::Preferred,
        TlsMode::Require => MySqlSslMode::Required,
        TlsMode::VerifyCa => MySqlSslMode::VerifyCa,
        TlsMode::VerifyFull => MySqlSslMode::VerifyIdentity,
    }
}

fn connect_error(cfg: &ConnectionConfig, e: sqlx::Error) -> DriverError {
    DriverError::Connect {
        connection: cfg.name.clone(),
        detail: format!(
            "{} (mysql {})",
            quokka_core::redact::scrub(&e.to_string()),
            cfg.target()
        ),
    }
}

fn execute_error(e: sqlx::Error) -> DriverError {
    DriverError::Execute {
        detail: e.to_string(),
    }
}

fn columns_of(row: &MySqlRow) -> Vec<Column> {
    row.columns()
        .iter()
        .map(|c| Column {
            name: c.name().to_string(),
            driver_type: c.type_info().name().to_string(),
            nullable: None,
        })
        .collect()
}

fn row_from_mysql(row: &MySqlRow) -> Row {
    Row((0..row.len()).map(|i| value_at(row, i)).collect())
}

/// Decode one cell. The `_` arm is hedge 1: anything unrecognized becomes a string.
fn value_at(row: &MySqlRow, i: usize) -> Value {
    let raw = match row.try_get_raw(i) {
        Ok(r) => r,
        Err(_) => return Value::Null,
    };
    if raw.is_null() {
        return Value::Null;
    }

    match raw.type_info().name().to_ascii_uppercase().as_str() {
        "BOOLEAN" | "BOOL" => row
            .try_get::<bool, _>(i)
            .map(Value::Bool)
            .unwrap_or_else(|_| as_text(row, i)),
        "TINYINT" | "SMALLINT" | "MEDIUMINT" | "INT" | "INTEGER" | "BIGINT" => row
            .try_get::<i64, _>(i)
            .map(Value::Int)
            .unwrap_or_else(|_| as_text(row, i)),
        "TINYINT UNSIGNED" | "SMALLINT UNSIGNED" | "MEDIUMINT UNSIGNED" | "INT UNSIGNED" => row
            .try_get::<u32, _>(i)
            .map(|v| Value::Int(i64::from(v)))
            .unwrap_or_else(|_| as_text(row, i)),
        // `BIGINT UNSIGNED` past i64::MAX has no home in `Value::Int`, and silently
        // wrapping it would be a lie about the data. It renders as text instead.
        "FLOAT" | "DOUBLE" => row
            .try_get::<f64, _>(i)
            .map(Value::Float)
            .unwrap_or_else(|_| as_text(row, i)),
        "BLOB" | "TINYBLOB" | "MEDIUMBLOB" | "LONGBLOB" | "BINARY" | "VARBINARY" => row
            .try_get::<Vec<u8>, _>(i)
            .map(Value::Blob)
            .unwrap_or_else(|_| as_text(row, i)),
        // DECIMAL stays text for the same reason NUMERIC does on Postgres: it is exact,
        // and an f64 is not.
        _ => as_text(row, i),
    }
}

/// The text fallback, which must never fail.
///
/// `try_get_unchecked` skips sqlx's type-compatibility check, which is what turns an
/// unrecognized column type from an aborted result set into a string (invariant 10).
fn as_text(row: &MySqlRow, i: usize) -> Value {
    if let Ok(s) = row.try_get_unchecked::<String, _>(i) {
        return Value::Text(s);
    }
    if let Ok(bytes) = row.try_get_unchecked::<Vec<u8>, _>(i) {
        return Value::Text(format!("0x{}", common::hex(&bytes)));
    }
    Value::Text(String::new())
}

/// One row per column, with a row per table that has none.
///
/// `?` narrows to a schema and the second to a table; either may be NULL for "all".
const CATALOG_SQL: &str = "\
SELECT t.TABLE_SCHEMA       AS `schema`,
       t.TABLE_NAME         AS `name`,
       t.TABLE_TYPE         AS `kind`,
       c.COLUMN_NAME        AS `column`,
       c.COLUMN_TYPE        AS `driver_type`,
       c.IS_NULLABLE        AS `nullable`
  FROM information_schema.TABLES t
  LEFT JOIN information_schema.COLUMNS c
         ON c.TABLE_SCHEMA = t.TABLE_SCHEMA AND c.TABLE_NAME = t.TABLE_NAME
 WHERE t.TABLE_SCHEMA NOT IN ('information_schema', 'mysql', 'performance_schema', 'sys')
   AND (? IS NULL OR t.TABLE_SCHEMA = ?)
   AND (? IS NULL OR t.TABLE_NAME = ?)
 ORDER BY t.TABLE_SCHEMA, t.TABLE_NAME, c.ORDINAL_POSITION";
