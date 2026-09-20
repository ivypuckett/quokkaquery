//! Parquet export, behind the default-on `parquet` feature.
//!
//! Two passes over the spool, both streams, neither holding the result:
//!
//! 1. **Learn the types.** Parquet declares a type per column; a SQLite spool's types
//!    are per *cell*, because SQLite is dynamically typed and a driver may hand back an
//!    integer in one row and a string in the next. So the first pass reads the column
//!    values and records which `Value` variants actually occurred — a handful of bytes
//!    per column, whatever the row count.
//! 2. **Write.** The second pass builds record batches and hands them to the writer.
//!
//! A column that held more than one kind of value becomes a string column, which is the
//! same answer invariant 10 gives everywhere else: degrade to text rather than fail. The
//! driver's own type name rides along in each field's metadata, so an exact `numeric`
//! that arrived as text — and must stay text, because an `f64` is not exact — is still
//! identifiable as a `numeric` in the file.

use std::sync::Arc;

use arrow_array::builder::{
    BinaryBuilder, BooleanBuilder, Float64Builder, Int64Builder, StringBuilder,
};
use arrow_array::{ArrayRef, RecordBatch};
use arrow_schema::{DataType, Field, Schema};
use parquet::arrow::ArrowWriter;
use parquet::basic::Compression;
use parquet::file::properties::WriterProperties;
use quokka_core::Value;

use crate::error::SpoolError;
use crate::export::{Destination, ExportReport, Format};
use crate::read::Spool;
use crate::view::View;

/// How many rows go into one record batch, and so into one row group's worth of
/// buffering. Bounded for the same reason the spool writer's batch is.
const BATCH_ROWS: usize = 4096;

/// Which `Value` variants a column actually held.
#[derive(Debug, Default, Clone, Copy)]
struct Seen {
    int: bool,
    float: bool,
    text: bool,
    blob: bool,
    boolean: bool,
}

impl Seen {
    fn note(&mut self, value: &Value) {
        match value {
            Value::Null => {}
            Value::Int(_) => self.int = true,
            Value::Float(_) => self.float = true,
            Value::Text(_) => self.text = true,
            Value::Blob(_) => self.blob = true,
            Value::Bool(_) => self.boolean = true,
        }
    }

    fn data_type(&self) -> DataType {
        match (self.int, self.float, self.text, self.blob, self.boolean) {
            // A column nothing was ever seen in — all NULLs — is a string column: the
            // narrowest claim we can make about values we never saw.
            (false, false, false, false, false) => DataType::Utf8,
            (true, false, false, false, false) => DataType::Int64,
            (false, true, false, false, false) => DataType::Float64,
            // Integers and floats in one column is the one mixture with an honest
            // widening: every i64 that SQLite produced fits a f64 well enough for the
            // analytics this format exists for, and the alternative is a string column
            // nobody can sum.
            (true, true, false, false, false) => DataType::Float64,
            (false, false, true, false, false) => DataType::Utf8,
            (false, false, false, true, false) => DataType::Binary,
            (false, false, false, false, true) => DataType::Boolean,
            _ => DataType::Utf8,
        }
    }
}

pub(crate) async fn export(
    spool: &Spool,
    destination: &Destination,
    view: &View,
) -> Result<ExportReport, SpoolError> {
    let started = std::time::Instant::now();

    let path = match destination {
        Destination::Path(p) => p.clone(),
        Destination::Stdout => {
            return Err(SpoolError::Unsupported(
                "a parquet file is written with a footer and seeks back to fix it up, \
                 so it needs a real file rather than stdout. Give --export a path, or \
                 export ndjson to a pipe."
                    .to_string(),
            ))
        }
    };

    // Pass one: what is actually in each column.
    let width = spool.columns().len();
    let mut seen = vec![Seen::default(); width];
    spool
        .stream(view, |row| {
            for (i, value) in row.0.iter().enumerate() {
                if let Some(s) = seen.get_mut(i) {
                    s.note(value);
                }
            }
            Ok(())
        })
        .await?;

    let fields: Vec<Field> = spool
        .columns()
        .iter()
        .zip(&seen)
        .map(|(column, seen)| {
            let mut field = Field::new(&column.name, seen.data_type(), true);
            field.set_metadata(
                [("quokka.driver_type".to_string(), column.driver_type.clone())]
                    .into_iter()
                    .collect(),
            );
            field
        })
        .collect();
    let schema = Arc::new(Schema::new(fields));

    let file = std::fs::File::create(&path).map_err(|source| SpoolError::Io {
        path: path.clone(),
        source,
    })?;
    let properties = WriterProperties::builder()
        // Snappy: pure Rust (the `snap` crate), and the codec every Parquet reader
        // supports. `zstd` would compress better and would link C.
        .set_compression(Compression::SNAPPY)
        .build();
    let mut writer = ArrowWriter::try_new(file, schema.clone(), Some(properties))
        .map_err(|e| SpoolError::Export(e.to_string()))?;

    // Pass two: write.
    let mut batch: Vec<Vec<Value>> = Vec::with_capacity(BATCH_ROWS);
    let mut rows = 0u64;
    let mut pending: Option<SpoolError> = None;

    let flush = |batch: &mut Vec<Vec<Value>>,
                 writer: &mut ArrowWriter<std::fs::File>|
     -> Result<(), SpoolError> {
        if batch.is_empty() {
            return Ok(());
        }
        let columns = build_columns(batch, &seen)?;
        let record = RecordBatch::try_new(schema.clone(), columns)
            .map_err(|e| SpoolError::Export(e.to_string()))?;
        writer
            .write(&record)
            .map_err(|e| SpoolError::Export(e.to_string()))?;
        batch.clear();
        Ok(())
    };

    let stream = spool
        .stream(view, |row| {
            batch.push(row.0.clone());
            rows += 1;
            if batch.len() >= BATCH_ROWS {
                if let Err(e) = flush(&mut batch, &mut writer) {
                    pending = Some(e);
                    return Err(SpoolError::Export("writing a record batch failed".into()));
                }
            }
            Ok(())
        })
        .await;

    if let Some(e) = pending {
        return Err(e);
    }
    stream?;
    flush(&mut batch, &mut writer)?;

    writer
        .close()
        .map_err(|e| SpoolError::Export(e.to_string()))?;

    let bytes = std::fs::metadata(&path).map(|m| m.len()).unwrap_or(0);

    Ok(ExportReport {
        path: path.display().to_string(),
        format: Format::Parquet,
        rows,
        bytes,
        duration_ms: started.elapsed().as_millis().min(i64::MAX as u128) as i64,
        scope: spool.scoping(),
    })
}

fn build_columns(batch: &[Vec<Value>], seen: &[Seen]) -> Result<Vec<ArrayRef>, SpoolError> {
    let mut columns: Vec<ArrayRef> = Vec::with_capacity(seen.len());

    for (index, seen) in seen.iter().enumerate() {
        let cells = batch
            .iter()
            .map(|row| row.get(index).unwrap_or(&Value::Null));
        let array: ArrayRef = match seen.data_type() {
            DataType::Int64 => {
                let mut b = Int64Builder::with_capacity(batch.len());
                for value in cells {
                    match value {
                        Value::Int(i) => b.append_value(*i),
                        _ => b.append_null(),
                    }
                }
                Arc::new(b.finish())
            }
            DataType::Float64 => {
                let mut b = Float64Builder::with_capacity(batch.len());
                for value in cells {
                    match value {
                        Value::Float(x) => b.append_value(*x),
                        Value::Int(i) => b.append_value(*i as f64),
                        _ => b.append_null(),
                    }
                }
                Arc::new(b.finish())
            }
            DataType::Boolean => {
                let mut b = BooleanBuilder::with_capacity(batch.len());
                for value in cells {
                    match value {
                        Value::Bool(v) => b.append_value(*v),
                        _ => b.append_null(),
                    }
                }
                Arc::new(b.finish())
            }
            DataType::Binary => {
                let mut b = BinaryBuilder::new();
                for value in cells {
                    match value {
                        Value::Blob(bytes) => b.append_value(bytes),
                        _ => b.append_null(),
                    }
                }
                Arc::new(b.finish())
            }
            // Utf8, and every mixed column that widened into it.
            _ => {
                let mut b = StringBuilder::new();
                for value in cells {
                    match value {
                        Value::Null => b.append_null(),
                        // `Display` renders a blob as hexadecimal and a NaN as `NaN`,
                        // which is the same text the CSV export writes for them.
                        other => b.append_value(other.to_string()),
                    }
                }
                Arc::new(b.finish())
            }
        };
        columns.push(array);
    }

    Ok(columns)
}
