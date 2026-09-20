//! The PostgreSQL driver, over sqlx 0.9.
//!
//! Pure Rust wire protocol: no `libpq`, no OpenSSL, no system client library (§3.0).
//! TLS is `rustls`, so a musl static build and a cross-compile both still work.
//!
//! Two things here are worth reading before changing anything.
//!
//! **Unknown types render as text, never fail** (§3.0, hedge 1; invariant 10). Postgres
//! is where that bites — ranges, arrays, enums, `hstore`, PostGIS geometry, any OID this
//! build has never heard of. The unparameterized path gets it for free and structurally:
//! sqlx sends a statement with no arguments through the *simple query* protocol, and
//! Postgres answers a simple query in `PgValueFormat::Text` for every column whatever
//! its type. So a `geometry` column arrives as the string the server would have printed,
//! and there is no decode to fail. The bound-parameter path uses the extended protocol,
//! which is binary, and [`value_at`] handles that case explicitly.
//!
//! **Connection errors must not leak credentials.** A sqlx error can carry the
//! connection string it was built from, so this driver never builds one: options are set
//! field by field, the password comes from a [`Secret`](quokka_core::Secret) that cannot
//! be formatted, and [`connect_error`] reports `ConnectionConfig::target()` — user, host,
//! port and database, and nothing else.

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
use sqlx::postgres::{PgConnectOptions, PgPoolOptions, PgRow, PgSslMode};
use sqlx::{
    AssertSqlSafe, Column as _, Either, Executor, Row as _, SqlSafeStr, Statement as _, TypeInfo,
    ValueRef,
};
use uuid::Uuid;

use crate::common::{self, ROW_CHANNEL_DEPTH};

/// Opens PostgreSQL connections.
pub struct PostgresFactory;

#[async_trait]
impl DriverFactory for PostgresFactory {
    fn name(&self) -> &'static str {
        "postgres"
    }

    fn dialect(&self) -> quokka_core::Dialect {
        quokka_core::Dialect::Postgres
    }

    async fn open(&self, cfg: &ConnectionConfig) -> Result<Arc<dyn Driver>, DriverError> {
        Ok(Arc::new(PostgresDriver::connect(cfg).await?))
    }
}

/// A pool of connections to one PostgreSQL database.
pub struct PostgresDriver {
    pool: sqlx::PgPool,
    connection: String,
    cancels: Arc<Mutex<HashMap<Uuid, Arc<AtomicBool>>>>,
}

impl std::fmt::Debug for PostgresDriver {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("PostgresDriver")
            .field("connection", &self.connection)
            .finish_non_exhaustive()
    }
}

#[async_trait]
impl Driver for PostgresDriver {
    fn dialect(&self) -> quokka_core::Dialect {
        quokka_core::Dialect::Postgres
    }

    async fn connect(cfg: &ConnectionConfig) -> Result<Self, DriverError> {
        let host = cfg.host.as_deref().ok_or_else(|| DriverError::Connect {
            connection: cfg.name.clone(),
            detail: "a postgres connection needs a `host`".to_string(),
        })?;

        let mut opts = PgConnectOptions::new()
            .ssl_mode(ssl_mode(cfg.tls))
            // Named so a DBA looking at `pg_stat_activity` can see which tool is
            // connected, and which connection of ours it is.
            .application_name(&format!("quokkaquery ({})", cfg.name));

        // A host starting with `/` is a unix socket directory, exactly as libpq reads it.
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
        if cfg.mode.is_read_only() {
            // Invariant 9, one layer below the policy engine: the session starts
            // read-only, so the *server* refuses a write on this connection whichever
            // surface issued it. Sent in the startup packet, so it costs no round trip
            // and there is no window before it takes effect. `quokka-policy` still owns
            // classification and denial at M3; this is the belt to that braces, and it
            // is what makes `mode = "read_only"` true rather than merely recorded.
            opts = opts.options([("default_transaction_read_only", "on")]);
        }

        // The password exists only between these two lines and inside the pool.
        // `Secret` has no `Display` and does not serialize, so it cannot reach a log.
        let secret = credential::resolve_async(&cfg.credential)
            .await
            .map_err(|e| DriverError::Connect {
                connection: cfg.name.clone(),
                detail: e.to_string(),
            })?;
        if let Some(secret) = &secret {
            opts = opts.password(secret.expose());
        }

        let pool = PgPoolOptions::new()
            .max_connections(4)
            // Otherwise a typo in `host` is thirty seconds of silence rather than a
            // message: sqlx's pool keeps retrying a refused server until this expires.
            .acquire_timeout(cfg.connect_timeout)
            .connect_with(opts)
            .await
            .map_err(|e| connect_error(cfg, e))?;

        Ok(PostgresDriver {
            pool,
            connection: cfg.name.clone(),
            cancels: Arc::new(Mutex::new(HashMap::new())),
        })
    }

    /// The catalog from `pg_catalog` (§3.1).
    ///
    /// `pg_catalog` rather than `information_schema` for one reason: `format_type` gives
    /// the type name a user would write — `numeric(10,2)`, `timestamptz`, `text[]`,
    /// `geometry` — where `information_schema.columns.data_type` flattens every extension
    /// type to `USER-DEFINED`. A catalog that cannot name a column's type is not much of
    /// a catalog.
    async fn introspect(
        &self,
        _permit: &ExecutePermit,
        scope: Scope,
    ) -> Result<Catalog, DriverError> {
        let rows: Vec<(
            String,
            String,
            String,
            Option<String>,
            Option<String>,
            Option<bool>,
        )> = sqlx::query_as(CATALOG_SQL)
            .bind(scope.schema.as_deref())
            .bind(scope.table.as_deref())
            .fetch_all(&self.pool)
            .await
            .map_err(execute_error)?;

        let mut tables: Vec<TableInfo> = Vec::new();
        for (schema, name, kind, column, driver_type, nullable) in rows {
            let last = tables
                .last()
                .map(|t: &TableInfo| t.schema.as_deref() == Some(schema.as_str()) && t.name == name)
                .unwrap_or(false);
            if !last {
                tables.push(TableInfo {
                    database: scope
                        .database
                        .clone()
                        .or_else(|| current_database(&self.pool)),
                    schema: Some(schema),
                    name,
                    kind: relkind(&kind).to_string(),
                    columns: Vec::new(),
                });
            }
            // A table with no columns at all still yields one row, with NULLs here.
            if let (Some(column), Some(driver_type)) = (column, driver_type) {
                if let Some(t) = tables.last_mut() {
                    t.columns.push(Column {
                        name: column,
                        driver_type,
                        nullable,
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
            tokio::sync::mpsc::channel::<Result<PgRow, DriverError>>(ROW_CHANNEL_DEPTH);

        let pool = self.pool.clone();
        let sql = req.sql.clone();
        let params = req.params.clone();
        let task_meta = meta.clone();
        let task_cancel = cancel.clone();
        let cancels = self.cancels.clone();
        let handle = req.handle;

        tokio::spawn(async move {
            // No arguments means sqlx uses the simple query protocol, which runs a whole
            // multi-statement body and answers in text — the two properties this driver
            // leans on. Bound values force the extended protocol, and with it one
            // statement and binary results.
            let mut stream: BoxStream<'_, _> = if params.is_empty() {
                sqlx::raw_sql(AssertSqlSafe(sql)).fetch_many(&pool).boxed()
            } else {
                let query = common::bind_all_pg(sqlx::query(AssertSqlSafe(sql)), &params);
                <&sqlx::PgPool as Executor>::fetch_many(&pool, query).boxed()
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

        // When `prepare` could not describe the statement — a multi-statement body is
        // the usual reason, since Postgres will not prepare one — the shape is taken
        // from the first row instead, which is held back and re-emitted. It costs one
        // row of buffering and never a second execution (§1.4).
        let (columns, buffered) = match described {
            Some(columns) => (columns, None),
            None => {
                let first = rx.recv().await;
                let columns = match &first {
                    Some(Ok(row)) => columns_of(row),
                    // Nothing came back and nothing described it: an empty column list
                    // is the honest answer, and there are no rows for it to mis-shape.
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
        let rows = rows.map(|r| r.map(|row| row_from_pg(&row))).boxed();

        Ok(QueryStream {
            columns,
            rows,
            meta,
        })
    }

    /// Stop reading and let the statement go.
    ///
    /// Be precise about what this does: sqlx 0.9 exposes neither the backend PID nor the
    /// secret key of a pooled connection, so the protocol-level `CancelRequest` that
    /// would stop the *server* is not reachable from here. What happens instead is that
    /// the consumer stops at the next row boundary and the stream is dropped, which
    /// closes the portal. For a scan already in flight the server may do a little more
    /// work before it notices. Athena, where a cancel is money rather than manners, gets
    /// a real `StopQueryExecution` at M5.
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

impl PostgresDriver {
    /// The result's shape, or `None` when the server would not describe the statement.
    ///
    /// A failure here is not reported as the query's failure: Postgres refuses to
    /// prepare a multi-statement body, and running a `.sql` file is a thing a daily
    /// driver has to do. The caller falls back to the first row.
    async fn describe_columns(&self, sql: &str) -> Option<Vec<Column>> {
        let statement = <&sqlx::PgPool as Executor>::prepare(
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
                    // Postgres does not report nullability in a row description, and
                    // deriving it from the catalog would be confidently wrong for any
                    // expression. `None` says "not known", which is true.
                    nullable: None,
                })
                .collect(),
        )
    }

    /// Exposed for tests that need to reach the database this driver opened.
    pub fn pool(&self) -> &sqlx::PgPool {
        &self.pool
    }
}

fn ssl_mode(tls: TlsMode) -> PgSslMode {
    match tls {
        TlsMode::Disable => PgSslMode::Disable,
        TlsMode::Prefer => PgSslMode::Prefer,
        TlsMode::Require => PgSslMode::Require,
        TlsMode::VerifyCa => PgSslMode::VerifyCa,
        TlsMode::VerifyFull => PgSslMode::VerifyFull,
    }
}

/// The one place a connection failure becomes a string.
///
/// The M1 trap in full: `DriverError::Connect` carries its detail into the audit log's
/// `error_message`, and a sqlx connection error built from a URL can contain the DSN —
/// password included. So the detail is the sqlx message plus
/// [`ConnectionConfig::target`], which is assembled from the parts and holds no
/// credential. `quokka_core::execute()` scrubs it again on the way into the log; this is
/// the layer that means there is nothing left to scrub.
fn connect_error(cfg: &ConnectionConfig, e: sqlx::Error) -> DriverError {
    DriverError::Connect {
        connection: cfg.name.clone(),
        detail: format!(
            "{} (postgres {})",
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

fn relkind(k: &str) -> &'static str {
    match k {
        "v" => "view",
        "m" => "materialized view",
        "f" => "foreign table",
        "p" => "partitioned table",
        _ => "table",
    }
}

/// Best effort: the catalog rows already name their schema, and the database name is
/// context rather than content, so failing to learn it is not worth failing a refresh.
fn current_database(_pool: &sqlx::PgPool) -> Option<String> {
    None
}

fn columns_of(row: &PgRow) -> Vec<Column> {
    row.columns()
        .iter()
        .map(|c| Column {
            name: c.name().to_string(),
            driver_type: c.type_info().name().to_string(),
            nullable: None,
        })
        .collect()
}

fn row_from_pg(row: &PgRow) -> Row {
    Row((0..row.len()).map(|i| value_at(row, i)).collect())
}

/// Decode one cell.
///
/// Hedge 1 in code. The `_` arm is the important one: anything this build does not
/// recognize becomes a string rather than an error, so an `hstore`, a `tstzrange`, an
/// enum or a PostGIS `geometry` degrades to what the server would have printed instead
/// of aborting the result set.
fn value_at(row: &PgRow, i: usize) -> Value {
    let raw = match row.try_get_raw(i) {
        Ok(r) => r,
        Err(_) => return Value::Null,
    };
    if raw.is_null() {
        return Value::Null;
    }

    match raw.type_info().name().to_ascii_uppercase().as_str() {
        "BOOL" => row
            .try_get::<bool, _>(i)
            .map(Value::Bool)
            .unwrap_or_else(|_| as_text(row, i)),
        "INT2" | "INT4" | "INT8" | "SMALLINT" | "INT" | "BIGINT" | "OID" => row
            .try_get::<i64, _>(i)
            .or_else(|_| row.try_get::<i32, _>(i).map(i64::from))
            .or_else(|_| row.try_get::<i16, _>(i).map(i64::from))
            .map(Value::Int)
            .unwrap_or_else(|_| as_text(row, i)),
        "FLOAT4" | "FLOAT8" | "REAL" | "DOUBLE PRECISION" => row
            .try_get::<f64, _>(i)
            .or_else(|_| row.try_get::<f32, _>(i).map(f64::from))
            .map(Value::Float)
            .unwrap_or_else(|_| as_text(row, i)),
        "BYTEA" => row
            .try_get::<Vec<u8>, _>(i)
            .map(Value::Blob)
            .unwrap_or_else(|_| as_text(row, i)),
        // NUMERIC is deliberately here rather than above: it is arbitrary precision, and
        // routing it through an f64 would lose digits silently. The text the server
        // produced is the exact value.
        _ => as_text(row, i),
    }
}

/// The text fallback, which must never fail.
///
/// `try_get_unchecked` is the point of this function: the checked `try_get` refuses a
/// type it does not recognize, which is exactly the abort invariant 10 forbids. Skipping
/// the check hands the bytes to `String`'s decoder, and on the unparameterized path
/// those bytes are already the server's own text rendering of the value — whatever the
/// type. Non-UTF-8 bytes (a binary-format value from the bound-parameter path) are
/// rendered the way Postgres itself renders `bytea`, which is legible and, crucially,
/// is not an error.
fn as_text(row: &PgRow, i: usize) -> Value {
    if let Ok(s) = row.try_get_unchecked::<String, _>(i) {
        return Value::Text(s);
    }
    if let Ok(bytes) = row.try_get_unchecked::<Vec<u8>, _>(i) {
        return Value::Text(format!("\\x{}", common::hex(&bytes)));
    }
    // Nothing decoded, but the row still has this many columns — an empty string keeps
    // the shape rather than dropping a cell.
    Value::Text(String::new())
}

/// One row per column, with a row per table that has none, so an empty table still
/// appears in the catalog.
///
/// `$1` narrows to a schema and `$2` to a table; either may be NULL for "all".
const CATALOG_SQL: &str = "\
SELECT n.nspname::text                                   AS schema,
       c.relname::text                                   AS name,
       c.relkind::text                                   AS kind,
       a.attname::text                                   AS column,
       format_type(a.atttypid, a.atttypmod)::text        AS driver_type,
       CASE WHEN a.attnum IS NULL THEN NULL ELSE NOT a.attnotnull END AS nullable
  FROM pg_catalog.pg_class c
  JOIN pg_catalog.pg_namespace n ON n.oid = c.relnamespace
  LEFT JOIN pg_catalog.pg_attribute a
         ON a.attrelid = c.oid AND a.attnum > 0 AND NOT a.attisdropped
 WHERE c.relkind IN ('r','v','m','f','p')
   AND n.nspname NOT IN ('pg_catalog', 'information_schema')
   AND n.nspname NOT LIKE 'pg\\_toast%'
   AND ($1::text IS NULL OR n.nspname = $1::text)
   AND ($2::text IS NULL OR c.relname = $2::text)
 ORDER BY n.nspname, c.relname, a.attnum";
