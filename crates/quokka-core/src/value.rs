//! The row vocabulary every driver speaks.
//!
//! A plain `Value` enum rather than Arrow: simpler, and Athena returns everything as
//! strings anyway (ARCHITECTURE §2.1).

use std::fmt;

/// One cell.
#[derive(Debug, Clone, PartialEq)]
pub enum Value {
    Null,
    Bool(bool),
    Int(i64),
    Float(f64),
    Text(String),
    Blob(Vec<u8>),
}

impl Value {
    /// The name this value would report as a type, for diagnostics.
    pub fn type_name(&self) -> &'static str {
        match self {
            Value::Null => "null",
            Value::Bool(_) => "bool",
            Value::Int(_) => "int",
            Value::Float(_) => "float",
            Value::Text(_) => "text",
            Value::Blob(_) => "blob",
        }
    }
}

impl fmt::Display for Value {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Value::Null => f.write_str(""),
            Value::Bool(b) => write!(f, "{b}"),
            Value::Int(i) => write!(f, "{i}"),
            Value::Float(x) => write!(f, "{x}"),
            Value::Text(s) => f.write_str(s),
            Value::Blob(b) => write!(f, "0x{}", hex_encode(b)),
        }
    }
}

impl serde::Serialize for Value {
    fn serialize<S: serde::Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
        use serde::ser::SerializeMap;
        match self {
            Value::Null => s.serialize_none(),
            Value::Bool(b) => s.serialize_bool(*b),
            Value::Int(i) => s.serialize_i64(*i),
            // JSON has no NaN or infinity. Emitting the IEEE name as a string keeps the
            // value visible rather than quietly turning it into null.
            Value::Float(x) if x.is_finite() => s.serialize_f64(*x),
            Value::Float(x) => s.serialize_str(&format!("{x}")),
            Value::Text(t) => s.serialize_str(t),
            Value::Blob(b) => {
                let mut m = s.serialize_map(Some(1))?;
                m.serialize_entry("$blob_hex", &hex_encode(b))?;
                m.end()
            }
        }
    }
}

fn hex_encode(bytes: &[u8]) -> String {
    let mut out = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        use std::fmt::Write as _;
        let _ = write!(out, "{b:02x}");
    }
    out
}

/// One row, positional, matching the result's [`Column`] list.
#[derive(Debug, Clone, PartialEq, serde::Serialize)]
pub struct Row(pub Vec<Value>);

impl Row {
    pub fn len(&self) -> usize {
        self.0.len()
    }

    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }

    pub fn get(&self, i: usize) -> Option<&Value> {
        self.0.get(i)
    }
}

/// A result column, carrying the driver's own type name.
///
/// The name is kept verbatim rather than mapped onto a closed set, because invariant 10
/// says an unrecognized type degrades to text and must never abort a result set — so
/// there is no "unknown type" failure to report, only a type name we render as a string.
#[derive(Debug, Clone, PartialEq, serde::Serialize)]
pub struct Column {
    pub name: String,
    pub driver_type: String,
    pub nullable: Option<bool>,
}

/// The SQL dialect a connection speaks lives in `quokka-policy`, which is the crate
/// that owns every parse of SQL, and is re-exported here so `quokka_core::Dialect`
/// still resolves.
pub use quokka_policy::Dialect;
