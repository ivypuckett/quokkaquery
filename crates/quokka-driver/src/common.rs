//! What the drivers share: the backpressure bound, and how a [`Value`] is bound.
//!
//! Binding is per-dialect because the argument types are, but the rule is one rule and
//! belongs in one file: **bound values are literals that took a different road** (§5.1,
//! rule 1). `quokka_core::execute()` has already written them to the audit log under the
//! connection's `sql_logging` mode by the time any function here runs — at `full` the
//! values, at `fingerprint` only how many there were. A driver that accepted parameters
//! the engine had not recorded would be a hole in the log, which is why the SQLite
//! driver refused them until the plumbing existed.

// Everything here belongs to a driver, so a build with every driver switched off —
// `cargo build -p quokka-driver --no-default-features`, which is a legitimate way to ask
// "what does the trait seam cost on its own" — compiles to nothing rather than to a pile
// of dead-code warnings.
#![cfg(any(
    feature = "sqlite",
    feature = "postgres",
    feature = "mysql",
    feature = "athena"
))]

// Athena has no parameter binding to share (its `ExecutionParameters` are textual
// substitution, which `athena::execute` refuses), so a build with only that driver uses
// nothing from here but the channel depth.
#[cfg(any(feature = "sqlite", feature = "postgres", feature = "mysql"))]
use quokka_core::Value;

/// How many rows may sit between a database and the consumer.
///
/// Bounded on purpose: the channel is the backpressure, so a large result never buffers
/// in memory ahead of whoever is reading it.
pub const ROW_CHANNEL_DEPTH: usize = 64;

#[cfg(feature = "sqlite")]
pub type SqliteQuery<'q> =
    sqlx::query::Query<'q, sqlx::Sqlite, <sqlx::Sqlite as sqlx::Database>::Arguments>;

/// SQLite is dynamically typed, so a null needs no type to go with it.
#[cfg(feature = "sqlite")]
pub fn bind_all_sqlite<'q>(mut query: SqliteQuery<'q>, params: &'q [Value]) -> SqliteQuery<'q> {
    for value in params {
        query = match value {
            Value::Null => query.bind(Option::<String>::None),
            Value::Bool(b) => query.bind(*b),
            Value::Int(i) => query.bind(*i),
            Value::Float(f) => query.bind(*f),
            Value::Text(s) => query.bind(s.as_str()),
            Value::Blob(b) => query.bind(b.as_slice()),
        };
    }
    query
}

#[cfg(feature = "postgres")]
pub type PgQuery<'q> =
    sqlx::query::Query<'q, sqlx::Postgres, <sqlx::Postgres as sqlx::Database>::Arguments>;

/// A NULL whose type Postgres is asked to infer.
///
/// Worth the twelve lines. Postgres takes parameter types from the `Parse` message, and
/// sqlx derives them from what is bound — so binding `Option::<String>::None` would
/// declare `$1` to be `text`, and `WHERE id = $1` against an `integer` column would fail
/// with "operator does not exist: integer = text". Type OID 0 is the protocol's own way
/// of saying "you work it out", which is what a user who wrote `NULL` meant.
#[cfg(feature = "postgres")]
struct InferredNull;

#[cfg(feature = "postgres")]
impl sqlx::Type<sqlx::Postgres> for InferredNull {
    fn type_info() -> sqlx::postgres::PgTypeInfo {
        sqlx::postgres::PgTypeInfo::with_oid(sqlx::postgres::types::Oid(0))
    }
}

#[cfg(feature = "postgres")]
impl sqlx::Encode<'_, sqlx::Postgres> for InferredNull {
    fn encode_by_ref(
        &self,
        _buf: &mut sqlx::postgres::PgArgumentBuffer,
    ) -> Result<sqlx::encode::IsNull, sqlx::error::BoxDynError> {
        Ok(sqlx::encode::IsNull::Yes)
    }
}

#[cfg(feature = "postgres")]
pub fn bind_all_pg<'q>(mut query: PgQuery<'q>, params: &'q [Value]) -> PgQuery<'q> {
    for value in params {
        query = match value {
            Value::Null => query.bind(InferredNull),
            Value::Bool(b) => query.bind(*b),
            Value::Int(i) => query.bind(*i),
            Value::Float(f) => query.bind(*f),
            Value::Text(s) => query.bind(s.as_str()),
            Value::Blob(b) => query.bind(b.as_slice()),
        };
    }
    query
}

#[cfg(feature = "mysql")]
pub type MySqlQuery<'q> =
    sqlx::query::Query<'q, sqlx::MySql, <sqlx::MySql as sqlx::Database>::Arguments>;

/// MySQL's prepared-statement protocol carries a null bitmap rather than a typed null,
/// so there is no equivalent of the Postgres problem above.
#[cfg(feature = "mysql")]
pub fn bind_all_mysql<'q>(mut query: MySqlQuery<'q>, params: &'q [Value]) -> MySqlQuery<'q> {
    for value in params {
        query = match value {
            Value::Null => query.bind(Option::<String>::None),
            Value::Bool(b) => query.bind(*b),
            Value::Int(i) => query.bind(*i),
            Value::Float(f) => query.bind(*f),
            Value::Text(s) => query.bind(s.as_str()),
            Value::Blob(b) => query.bind(b.as_slice()),
        };
    }
    query
}

/// The hexadecimal a driver falls back to when bytes are not text.
#[cfg(any(feature = "postgres", feature = "mysql"))]
pub fn hex(bytes: &[u8]) -> String {
    use std::fmt::Write as _;
    let mut out = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        let _ = write!(out, "{b:02x}");
    }
    out
}
