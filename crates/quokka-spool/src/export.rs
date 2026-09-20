//! Streamed export: CSV, TSV, JSON, NDJSON and Parquet (§4).
//!
//! Unbounded by the display cap and never buffered: a writer receives rows as they come
//! off the spool's cursor (or, with `--all`, as they come off the driver) and pushes
//! bytes at a `BufWriter`. Nothing here ever holds the result.

use std::io::Write;
use std::path::{Path, PathBuf};

use quokka_core::{Column, Outcome, Retained, Row, RowSink, Value};

use crate::error::SpoolError;
use crate::read::Spool;
use crate::view::{Scoping, View};

/// The formats an export may be written in.
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize)]
#[serde(rename_all = "snake_case")]
pub enum Format {
    Csv,
    Tsv,
    Json,
    Ndjson,
    #[cfg(feature = "parquet")]
    Parquet,
}

impl Format {
    pub fn as_str(self) -> &'static str {
        match self {
            Format::Csv => "csv",
            Format::Tsv => "tsv",
            Format::Json => "json",
            Format::Ndjson => "ndjson",
            #[cfg(feature = "parquet")]
            Format::Parquet => "parquet",
        }
    }

    pub fn parse(s: &str) -> Option<Self> {
        Some(match s.trim().to_ascii_lowercase().as_str() {
            "csv" => Format::Csv,
            "tsv" | "tab" => Format::Tsv,
            "json" => Format::Json,
            "ndjson" | "jsonl" => Format::Ndjson,
            #[cfg(feature = "parquet")]
            "parquet" | "pq" => Format::Parquet,
            #[cfg(not(feature = "parquet"))]
            "parquet" | "pq" => return None,
            _ => return None,
        })
    }

    /// The format a filename implies. `orders.parquet` is not ambiguous, so making the
    /// user say it twice would be ceremony.
    pub fn from_path(path: &Path) -> Option<Self> {
        let ext = path.extension()?.to_str()?;
        Format::parse(ext)
    }

    /// Every format this build can write, for an error message that lists them.
    pub fn names() -> &'static [&'static str] {
        #[cfg(feature = "parquet")]
        {
            &["csv", "tsv", "json", "ndjson", "parquet"]
        }
        #[cfg(not(feature = "parquet"))]
        {
            &["csv", "tsv", "json", "ndjson"]
        }
    }

    /// Whether this format can be written without knowing the whole result first.
    ///
    /// Parquet cannot: its file header declares a type per column, and a spool's types
    /// are per cell, so the writer has to have seen the rows before it can name them.
    /// That is the whole reason `--all` — which streams driver → file with no spool —
    /// refuses it rather than guessing from the first batch and failing on row 900,000.
    pub fn is_streamable(self) -> bool {
        match self {
            Format::Csv | Format::Tsv | Format::Json | Format::Ndjson => true,
            #[cfg(feature = "parquet")]
            Format::Parquet => false,
        }
    }
}

impl std::fmt::Display for Format {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_str())
    }
}

/// What one export did. Carries the scoping, like every other read of a spool.
#[derive(Debug, Clone, serde::Serialize)]
pub struct ExportReport {
    pub path: String,
    pub format: Format,
    pub rows: u64,
    pub bytes: u64,
    pub duration_ms: i64,
    pub scope: Scoping,
}

impl ExportReport {
    /// True when the file holds the query's whole result.
    pub fn is_whole_result(&self) -> bool {
        self.scope.is_whole_result()
    }
}

/// Where an export's bytes go. `-` is stdout, which is what makes an unbounded
/// pipeline possible without a temporary file.
pub enum Destination {
    Path(PathBuf),
    Stdout,
}

impl Destination {
    pub fn parse(text: &str) -> Self {
        if text == "-" {
            Destination::Stdout
        } else {
            Destination::Path(PathBuf::from(text))
        }
    }

    pub fn display(&self) -> String {
        match self {
            Destination::Path(p) => p.display().to_string(),
            Destination::Stdout => "-".to_string(),
        }
    }

    fn open(&self) -> Result<Box<dyn Write>, SpoolError> {
        match self {
            Destination::Path(path) => {
                if let Some(dir) = path.parent() {
                    if !dir.as_os_str().is_empty() && !dir.exists() {
                        std::fs::create_dir_all(dir).map_err(|source| SpoolError::Io {
                            path: dir.to_path_buf(),
                            source,
                        })?;
                    }
                }
                let file = std::fs::File::create(path).map_err(|source| SpoolError::Io {
                    path: path.clone(),
                    source,
                })?;
                Ok(Box::new(std::io::BufWriter::new(file)))
            }
            Destination::Stdout => Ok(Box::new(std::io::BufWriter::new(std::io::stdout()))),
        }
    }
}

/// Export a view of a spool.
///
/// Reads the spool and nothing else: no database is touched, whatever the file's size
/// (§4). The rows are the spool's, so the report says how much of the result that is.
pub async fn export(
    spool: &Spool,
    destination: &Destination,
    format: Format,
    view: &View,
) -> Result<ExportReport, SpoolError> {
    let started = std::time::Instant::now();

    #[cfg(feature = "parquet")]
    if format == Format::Parquet {
        let report = crate::parquet::export(spool, destination, view).await?;
        return Ok(report);
    }

    let mut writer = TextWriter::new(format, destination.open()?);
    writer.begin(spool.columns())?;
    let rows = spool.stream(view, |row| writer.row(row)).await?;
    let bytes = writer.finish()?;

    Ok(ExportReport {
        path: destination.display(),
        format,
        rows,
        bytes,
        duration_ms: started.elapsed().as_millis().min(i64::MAX as u128) as i64,
        scope: spool.scoping(),
    })
}

/// A sink that writes rows straight to a file as the driver yields them.
///
/// The `--all` path of §4.2: for a dataset larger than local disk there is no spool to
/// put it in, so the export becomes the sink and the display cap never applies. Nothing
/// is cached, which is exactly the trade — the rows cannot then be paged, sorted or
/// re-exported without running the query again.
pub struct ExportSink {
    writer: TextWriter,
    rows: u64,
    path: String,
    format: Format,
    started: std::time::Instant,
    duration_ms: i64,
    bytes: u64,
    finished: bool,
}

impl ExportSink {
    pub fn create(destination: &Destination, format: Format) -> Result<Self, SpoolError> {
        if !format.is_streamable() {
            return Err(SpoolError::Unsupported(format!(
                "a {format} file declares a type for every column, which is only known \
                 once the rows have been seen, so it cannot be written straight from a \
                 running query. Drop --all to export {format} through the spool, or \
                 export csv, tsv, json or ndjson."
            )));
        }
        Ok(ExportSink {
            writer: TextWriter::new(format, destination.open()?),
            rows: 0,
            path: destination.display(),
            format,
            started: std::time::Instant::now(),
            duration_ms: 0,
            bytes: 0,
            finished: false,
        })
    }

    /// What was written, once the query is done.
    pub fn report(&self, outcome: &Outcome) -> ExportReport {
        ExportReport {
            path: self.path.clone(),
            format: self.format,
            rows: self.rows,
            bytes: self.bytes,
            duration_ms: self.duration_ms,
            scope: Scoping {
                spooled_rows: self.rows,
                rows_returned: outcome.rows_returned,
                // Nothing was spooled, so no spool cap could have bound. The only cap
                // in play on this path is the caller's own.
                spool_capped: None,
                truncated_by_max_rows: outcome.truncated,
            },
        }
    }
}

impl RowSink for ExportSink {
    fn begin(&mut self, columns: &[Column]) -> std::io::Result<()> {
        self.writer.begin(columns)?;
        Ok(())
    }

    fn row(&mut self, row: &Row) -> std::io::Result<()> {
        self.writer.row(row)?;
        self.rows += 1;
        Ok(())
    }

    fn end(&mut self, _outcome: &Outcome) -> std::io::Result<()> {
        if self.finished {
            return Ok(());
        }
        self.finished = true;
        self.duration_ms = self.started.elapsed().as_millis().min(i64::MAX as u128) as i64;
        self.bytes = self.writer.finish()?;
        Ok(())
    }

    fn retained(&self) -> Option<Retained> {
        // Nothing is cached, so `rows_spooled` stays NULL rather than claiming a spool
        // that a later `quokka export` could read.
        None
    }
}

/// CSV, TSV, JSON and NDJSON over one output stream.
struct TextWriter {
    format: Format,
    out: Option<Box<dyn Write>>,
    columns: Vec<Column>,
    /// JSON only: whether an element has been written, so commas land between rows and
    /// not before the first.
    wrote_one: bool,
    bytes: u64,
}

impl TextWriter {
    fn new(format: Format, out: Box<dyn Write>) -> Self {
        TextWriter {
            format,
            out: Some(out),
            columns: Vec::new(),
            wrote_one: false,
            bytes: 0,
        }
    }

    fn write(&mut self, bytes: &[u8]) -> Result<(), SpoolError> {
        let out = self
            .out
            .as_mut()
            .ok_or_else(|| SpoolError::Export("the export has already been closed".into()))?;
        out.write_all(bytes)
            .map_err(|e| SpoolError::Export(e.to_string()))?;
        self.bytes += bytes.len() as u64;
        Ok(())
    }

    fn begin(&mut self, columns: &[Column]) -> Result<(), SpoolError> {
        self.columns = columns.to_vec();
        match self.format {
            Format::Csv | Format::Tsv => {
                let sep = self.separator();
                let header: Vec<String> =
                    columns.iter().map(|c| self.quote(&c.name, sep)).collect();
                let line = format!("{}\n", header.join(&sep.to_string()));
                self.write(line.as_bytes())?;
            }
            Format::Json => self.write(b"[")?,
            Format::Ndjson => {}
            #[cfg(feature = "parquet")]
            Format::Parquet => unreachable!("parquet is written by its own module"),
        }
        Ok(())
    }

    fn row(&mut self, row: &Row) -> Result<(), SpoolError> {
        match self.format {
            Format::Csv | Format::Tsv => {
                let sep = self.separator();
                let cells: Vec<String> = (0..self.columns.len())
                    .map(|i| {
                        let value = row.get(i).unwrap_or(&Value::Null);
                        self.quote(&flat(value), sep)
                    })
                    .collect();
                let line = format!("{}\n", cells.join(&sep.to_string()));
                self.write(line.as_bytes())
            }
            Format::Json => {
                let prefix = if self.wrote_one { "," } else { "" };
                let json = serde_json::to_string(&row_object(&self.columns, row))
                    .map_err(|e| SpoolError::Export(e.to_string()))?;
                self.wrote_one = true;
                self.write(format!("{prefix}{json}").as_bytes())
            }
            Format::Ndjson => {
                let json = serde_json::to_string(&row_object(&self.columns, row))
                    .map_err(|e| SpoolError::Export(e.to_string()))?;
                self.write(format!("{json}\n").as_bytes())
            }
            #[cfg(feature = "parquet")]
            Format::Parquet => unreachable!("parquet is written by its own module"),
        }
    }

    fn finish(&mut self) -> Result<u64, SpoolError> {
        if self.out.is_none() {
            return Ok(self.bytes);
        }
        if self.format == Format::Json {
            self.write(b"]\n")?;
        }
        let mut out = self.out.take().expect("checked above");
        out.flush().map_err(|e| SpoolError::Export(e.to_string()))?;
        Ok(self.bytes)
    }

    fn separator(&self) -> char {
        match self.format {
            Format::Tsv => '\t',
            _ => ',',
        }
    }

    /// RFC 4180 quoting for CSV. For TSV the same rule applies to the tab, because a
    /// TSV cell containing a tab is otherwise two cells.
    fn quote(&self, text: &str, sep: char) -> String {
        if text.contains(sep) || text.contains('"') || text.contains('\n') || text.contains('\r') {
            format!("\"{}\"", text.replace('"', "\"\""))
        } else {
            text.to_string()
        }
    }
}

/// A value as one delimited cell.
///
/// `NULL` is an empty field, which is the convention every spreadsheet and loader
/// expects, and a blob is hexadecimal — the same rendering `Value`'s own `Display` uses,
/// so a cell reads the same in a table on screen and in a file.
fn flat(value: &Value) -> String {
    match value {
        Value::Null => String::new(),
        other => other.to_string(),
    }
}

/// One row as a JSON object, keeping every column even when two share a name.
fn row_object(columns: &[Column], row: &Row) -> serde_json::Value {
    let mut map = serde_json::Map::with_capacity(columns.len());
    for (i, col) in columns.iter().enumerate() {
        let value = row
            .get(i)
            .map(|v| serde_json::to_value(v).unwrap_or(serde_json::Value::Null))
            .unwrap_or(serde_json::Value::Null);
        let mut key = col.name.clone();
        let mut n = 2;
        // `SELECT a.id, b.id` really does return two columns called `id`. Dropping one
        // would be data loss in a file meant to be machine-read.
        while map.contains_key(&key) {
            key = format!("{}_{n}", col.name);
            n += 1;
        }
        map.insert(key, value);
    }
    serde_json::Value::Object(map)
}
