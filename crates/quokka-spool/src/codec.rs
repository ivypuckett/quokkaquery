//! How a [`Value`] becomes a SQLite cell and comes back unchanged.
//!
//! The spool's columns are declared with no type, so they take BLOB affinity and SQLite
//! converts nothing (see `schema.sql`). That gets four of the six `Value` variants home
//! for free: an integer stays INTEGER, a finite float stays REAL, text stays TEXT —
//! including an exact `numeric` that a driver deliberately kept as text — and a blob
//! stays BLOB. NULL is NULL.
//!
//! Two variants have nowhere to land, and both were found by asking SQLite rather than
//! by reasoning about it (`tests/round_trip.rs` pins the answers, so a bundled-SQLite
//! upgrade that changes them fails a test rather than corrupting a result):
//!
//! - **`Value::Bool`.** SQLite has no boolean storage class. A bound `true` is stored as
//!   INTEGER 1, which reads back as `Value::Int(1)` — a different value.
//! - **`Value::Float(NaN)`.** SQLite stores NaN as NULL. Not as a quiet approximation:
//!   `typeof()` on the stored cell answers `null`, and the float is simply gone.
//!   (The infinities are fine — they store and read back as REAL. We do not lean on
//!   that anywhere; the test says so out loud because the assumption is otherwise
//!   invisible.)
//!
//! So those two — and only those two — are written as *tagged blobs*. Every blob this
//! module writes carries a one-byte tag, including a plain `Value::Blob`, because a
//! tagging scheme where some blobs are tagged and some are not is a scheme where a
//! user's bytes can impersonate a tag.
//!
//! This is exactly the evidence §11.2 asked for on "SQLite spool versus Arrow IPC
//! spool": two variants need an escape, the escape is six lines, and nothing else in
//! the vocabulary round-trips badly. That is not enough to move the spool to Arrow, and
//! the finding is recorded here rather than acted on.

use quokka_core::Value;

/// A blob's first byte. `Bytes` is the ordinary case and still gets a tag.
mod tag {
    pub const BYTES: u8 = 0x00;
    pub const FALSE: u8 = 0x01;
    pub const TRUE: u8 = 0x02;
    pub const NAN: u8 = 0x03;
}

/// One cell, in the form the spool binds and stores.
#[derive(Debug, Clone, PartialEq)]
pub enum Cell {
    Null,
    Int(i64),
    Real(f64),
    Text(String),
    Blob(Vec<u8>),
}

impl Cell {
    /// Roughly how many bytes this cell asks SQLite to store.
    ///
    /// What the spool's byte cap counts (§4.2). Deliberately the payload rather than the
    /// file on disk: inside one long transaction the file size lags far behind what has
    /// been inserted, so a cap that watched the file would not bind until it was much
    /// too late.
    pub fn payload_bytes(&self) -> u64 {
        match self {
            Cell::Null => 1,
            Cell::Int(_) | Cell::Real(_) => 8,
            Cell::Text(s) => s.len() as u64,
            Cell::Blob(b) => b.len() as u64,
        }
    }
}

/// Encode one value for storage.
pub fn encode(value: &Value) -> Cell {
    match value {
        Value::Null => Cell::Null,
        Value::Int(i) => Cell::Int(*i),
        Value::Text(s) => Cell::Text(s.clone()),
        Value::Bool(b) => Cell::Blob(vec![if *b { tag::TRUE } else { tag::FALSE }]),
        Value::Float(x) if x.is_nan() => Cell::Blob(vec![tag::NAN]),
        Value::Float(x) => Cell::Real(*x),
        Value::Blob(b) => {
            let mut out = Vec::with_capacity(b.len() + 1);
            out.push(tag::BYTES);
            out.extend_from_slice(b);
            Cell::Blob(out)
        }
    }
}

/// Decode one stored cell.
///
/// A blob with an unknown tag decodes to the bytes after it rather than failing:
/// invariant 10's rule — degrade, never abort a result set — applies to our own storage
/// as much as to a driver's types.
pub fn decode(cell: Cell) -> Value {
    match cell {
        Cell::Null => Value::Null,
        Cell::Int(i) => Value::Int(i),
        Cell::Real(x) => Value::Float(x),
        Cell::Text(s) => Value::Text(s),
        Cell::Blob(bytes) => match bytes.split_first() {
            Some((&tag::FALSE, [])) => Value::Bool(false),
            Some((&tag::TRUE, [])) => Value::Bool(true),
            Some((&tag::NAN, [])) => Value::Float(f64::NAN),
            Some((_, rest)) => Value::Blob(rest.to_vec()),
            // A zero-length blob was not written by `encode`, which always writes at
            // least a tag. Empty bytes is the honest reading of it.
            None => Value::Blob(Vec::new()),
        },
    }
}

/// Bind one encoded cell onto a query.
pub fn bind<'q>(
    query: sqlx::query::Query<'q, sqlx::Sqlite, <sqlx::Sqlite as sqlx::Database>::Arguments>,
    cell: Cell,
) -> sqlx::query::Query<'q, sqlx::Sqlite, <sqlx::Sqlite as sqlx::Database>::Arguments> {
    match cell {
        Cell::Null => query.bind(Option::<Vec<u8>>::None),
        Cell::Int(i) => query.bind(i),
        Cell::Real(x) => query.bind(x),
        Cell::Text(s) => query.bind(s),
        Cell::Blob(b) => query.bind(b),
    }
}

/// Read one cell back out of a row, by its storage class.
pub fn cell_at(row: &sqlx::sqlite::SqliteRow, index: usize) -> Cell {
    use sqlx::{Row as _, TypeInfo, ValueRef};

    let Ok(raw) = row.try_get_raw(index) else {
        return Cell::Null;
    };
    if raw.is_null() {
        return Cell::Null;
    }
    match raw.type_info().name() {
        "INTEGER" => row.try_get::<i64, _>(index).map(Cell::Int),
        "REAL" => row.try_get::<f64, _>(index).map(Cell::Real),
        "TEXT" => row.try_get::<String, _>(index).map(Cell::Text),
        _ => row.try_get::<Vec<u8>, _>(index).map(Cell::Blob),
    }
    // Nothing decoded where the storage class said it should. Keeping the row's shape
    // beats dropping a cell.
    .unwrap_or(Cell::Null)
}

/// Read one value back out of a row.
pub fn value_at(row: &sqlx::sqlite::SqliteRow, index: usize) -> Value {
    decode(cell_at(row, index))
}

/// Compare two values the way a round-trip test has to: `NaN != NaN` under IEEE, but a
/// NaN that went in and came out is the same value for our purposes.
pub fn same_value(a: &Value, b: &Value) -> bool {
    match (a, b) {
        (Value::Float(x), Value::Float(y)) if x.is_nan() && y.is_nan() => true,
        // `-0.0 == 0.0` is true and we let it be: the bits survive storage, and a spool
        // that called them different would be reporting on IEEE rather than on itself.
        _ => a == b,
    }
}
