//! Output formats: `json`, `ndjson`, `table`.
//!
//! Each is a [`RowSink`], which is how the CLI stays on the one execute path — the
//! formatter never asks the database for anything, it is handed rows as they arrive
//! (ARCHITECTURE §2).
//!
//! At M2 the spool becomes the sink and these read from it instead. Nothing about the
//! formats changes; only where the rows come from.

use std::io::Write;

use quokka_core::{Column, Outcome, Row, RowSink, Value};
use serde_json::{Map, Value as Json};

#[derive(Debug, Clone, Copy, PartialEq, Eq, clap::ValueEnum)]
#[value(rename_all = "lower")]
pub enum Format {
    /// One JSON envelope holding the columns, the rows and the outcome.
    Json,
    /// One JSON object per row on stdout; the summary goes to stderr so a pipeline sees
    /// rows and nothing else.
    Ndjson,
    /// An aligned text table for a human.
    Table,
}

/// How many characters of a cell the table format prints before eliding.
const TABLE_CELL_WIDTH: usize = 80;

pub fn sink_for(format: Format) -> Box<dyn RowSink> {
    match format {
        Format::Json => Box::new(JsonSink::default()),
        Format::Ndjson => Box::new(NdjsonSink::default()),
        Format::Table => Box::new(TableSink::default()),
    }
}

/// Build a JSON object for one row, keeping every column even when two share a name.
fn row_object(columns: &[Column], row: &Row) -> Json {
    let mut map = Map::with_capacity(columns.len());
    for (i, col) in columns.iter().enumerate() {
        let value = row
            .get(i)
            .map(|v| serde_json::to_value(v).unwrap_or(Json::Null))
            .unwrap_or(Json::Null);
        let mut key = col.name.clone();
        let mut n = 2;
        // `SELECT a.id, b.id` really does return two columns called `id`. Dropping one
        // would be data loss in a format meant to be machine-read.
        while map.contains_key(&key) {
            key = format!("{}_{n}", col.name);
            n += 1;
        }
        map.insert(key, value);
    }
    Json::Object(map)
}

fn outcome_json(outcome: &Outcome) -> Json {
    serde_json::to_value(outcome).unwrap_or(Json::Null)
}

/// One envelope, written when the query finishes.
#[derive(Default)]
struct JsonSink {
    columns: Vec<Column>,
    rows: Vec<Json>,
}

impl RowSink for JsonSink {
    fn begin(&mut self, columns: &[Column]) -> std::io::Result<()> {
        self.columns = columns.to_vec();
        Ok(())
    }

    fn row(&mut self, row: &Row) -> std::io::Result<()> {
        self.rows.push(row_object(&self.columns, row));
        Ok(())
    }

    fn end(&mut self, outcome: &Outcome) -> std::io::Result<()> {
        let mut envelope = Map::new();
        envelope.insert(
            "query_id".into(),
            Json::String(outcome.query_id.to_string()),
        );
        envelope.insert(
            "connection".into(),
            Json::String(outcome.connection.clone()),
        );
        envelope.insert("status".into(), Json::String(outcome.status.to_string()));
        envelope.insert(
            "columns".into(),
            serde_json::to_value(&self.columns).unwrap_or(Json::Null),
        );
        envelope.insert("rows".into(), Json::Array(std::mem::take(&mut self.rows)));
        envelope.insert("row_count".into(), Json::from(outcome.rows_returned));
        envelope.insert("truncated".into(), Json::Bool(outcome.truncated));
        envelope.insert("duration_ms".into(), Json::from(outcome.duration_ms));
        if let Some(n) = outcome.rows_affected {
            envelope.insert("rows_affected".into(), Json::from(n));
        }
        if let Some(code) = &outcome.error_code {
            envelope.insert("error_code".into(), Json::String(code.clone()));
        }
        if let Some(msg) = &outcome.error_message {
            envelope.insert("error_message".into(), Json::String(msg.clone()));
        }

        let mut out = std::io::stdout().lock();
        serde_json::to_writer(&mut out, &Json::Object(envelope))?;
        out.write_all(b"\n")?;
        out.flush()
    }
}

/// One object per row, flushed as it arrives.
#[derive(Default)]
struct NdjsonSink {
    columns: Vec<Column>,
}

impl RowSink for NdjsonSink {
    fn begin(&mut self, columns: &[Column]) -> std::io::Result<()> {
        self.columns = columns.to_vec();
        Ok(())
    }

    fn row(&mut self, row: &Row) -> std::io::Result<()> {
        let mut out = std::io::stdout().lock();
        serde_json::to_writer(&mut out, &row_object(&self.columns, row))?;
        out.write_all(b"\n")?;
        // Flushed per row: this format exists to be read by something downstream while
        // the query is still running.
        out.flush()
    }

    fn end(&mut self, outcome: &Outcome) -> std::io::Result<()> {
        std::io::stdout().lock().flush()?;
        // stdout stays a pure stream of rows, so the summary — truncation included —
        // goes to stderr rather than becoming a row-shaped line that is not a row.
        let mut err = std::io::stderr().lock();
        serde_json::to_writer(&mut err, &outcome_json(outcome))?;
        err.write_all(b"\n")?;
        err.flush()
    }
}

/// An aligned table, printed once the widths are known.
#[derive(Default)]
struct TableSink {
    columns: Vec<Column>,
    rows: Vec<Vec<String>>,
}

impl RowSink for TableSink {
    fn begin(&mut self, columns: &[Column]) -> std::io::Result<()> {
        self.columns = columns.to_vec();
        Ok(())
    }

    fn row(&mut self, row: &Row) -> std::io::Result<()> {
        self.rows.push(
            (0..self.columns.len())
                .map(|i| cell(row.get(i).unwrap_or(&Value::Null)))
                .collect(),
        );
        Ok(())
    }

    fn end(&mut self, outcome: &Outcome) -> std::io::Result<()> {
        let mut out = std::io::stdout().lock();

        if !self.columns.is_empty() {
            let mut widths: Vec<usize> = self
                .columns
                .iter()
                .map(|c| c.name.chars().count())
                .collect();
            for row in &self.rows {
                for (i, cell) in row.iter().enumerate() {
                    if let Some(w) = widths.get_mut(i) {
                        *w = (*w).max(cell.chars().count());
                    }
                }
            }

            let header: Vec<String> = self
                .columns
                .iter()
                .enumerate()
                .map(|(i, c)| pad(&c.name, widths[i]))
                .collect();
            writeln!(out, "{}", header.join("  "))?;
            writeln!(
                out,
                "{}",
                widths
                    .iter()
                    .map(|w| "-".repeat(*w))
                    .collect::<Vec<_>>()
                    .join("  ")
            )?;

            for row in &self.rows {
                let line: Vec<String> = row
                    .iter()
                    .enumerate()
                    .map(|(i, c)| pad(c, widths.get(i).copied().unwrap_or(0)))
                    .collect();
                writeln!(out, "{}", line.join("  ").trim_end())?;
            }
        }

        writeln!(out, "{}", footer(outcome))?;
        out.flush()?;

        // The JSON formats carry the failure inside the envelope; the table has to say
        // it out loud or a non-zero exit code is all the user gets.
        if let Some(message) = &outcome.error_message {
            let code = outcome.error_code.as_deref().unwrap_or("error");
            eprintln!("{}: {code}: {message}", outcome.status);
        }
        Ok(())
    }
}

fn footer(outcome: &Outcome) -> String {
    let mut parts = vec![format!(
        "{} row{}",
        outcome.rows_returned,
        if outcome.rows_returned == 1 { "" } else { "s" }
    )];
    if let Some(affected) = outcome.rows_affected {
        parts.push(format!("{affected} affected"));
    }
    if outcome.truncated {
        // Never silent (§4.2): a prefix that looks like the whole answer is the failure
        // mode this line exists to prevent.
        parts.push("TRUNCATED at --max-rows; the result has more".to_string());
    }
    parts.push(format!("{} ms", outcome.duration_ms));
    parts.push(format!("query {}", outcome.query_id));
    format!("({})", parts.join(" · "))
}

fn pad(s: &str, width: usize) -> String {
    let len = s.chars().count();
    if len >= width {
        s.to_string()
    } else {
        format!("{s}{}", " ".repeat(width - len))
    }
}

fn cell(value: &Value) -> String {
    let text = match value {
        Value::Null => "NULL".to_string(),
        other => other.to_string(),
    };
    let text = text.replace(['\n', '\r', '\t'], " ");
    if text.chars().count() > TABLE_CELL_WIDTH {
        let kept: String = text.chars().take(TABLE_CELL_WIDTH - 1).collect();
        format!("{kept}…")
    } else {
        text
    }
}

/// Print a list of records that are not query rows — connections, catalog tables.
///
/// Kept beside the [`RowSink`] formats rather than folded into them, because these do
/// not come from a database and must not look as though they did: `quokka connections
/// list` reads the config file, and `quokka schema describe` reads a catalog that may
/// have been cached, which is a distinction the `--format json` envelope makes explicit.
///
/// `columns` is the table format's column order and nothing more; the JSON forms print
/// whatever the records hold.
pub fn print_records(
    format: Format,
    envelope: Map<String, Json>,
    key: &str,
    records: Vec<Json>,
    columns: &[&str],
) -> std::io::Result<()> {
    let mut out = std::io::stdout().lock();
    match format {
        Format::Json => {
            let mut envelope = envelope;
            envelope.insert(key.to_string(), Json::Array(records));
            serde_json::to_writer(&mut out, &Json::Object(envelope))?;
            out.write_all(b"\n")?;
            out.flush()
        }
        Format::Ndjson => {
            for record in &records {
                serde_json::to_writer(&mut out, record)?;
                out.write_all(b"\n")?;
            }
            out.flush()?;
            // Same rule as the row sink: stdout stays a pure stream of records, so the
            // envelope — which is not one — goes to stderr.
            let mut err = std::io::stderr().lock();
            serde_json::to_writer(&mut err, &Json::Object(envelope))?;
            err.write_all(b"\n")?;
            err.flush()
        }
        Format::Table => {
            let rows: Vec<Vec<String>> = records
                .iter()
                .map(|r| columns.iter().map(|c| scalar(r.get(*c))).collect())
                .collect();
            write_table(&mut out, columns, &rows)?;
            out.flush()
        }
    }
}

/// One aligned table. Shared by every `--format table` that is not a query result.
pub fn write_table(
    out: &mut impl Write,
    headers: &[&str],
    rows: &[Vec<String>],
) -> std::io::Result<()> {
    if headers.is_empty() {
        return Ok(());
    }
    let mut widths: Vec<usize> = headers.iter().map(|h| h.chars().count()).collect();
    for row in rows {
        for (i, cell) in row.iter().enumerate() {
            if let Some(w) = widths.get_mut(i) {
                *w = (*w).max(cell.chars().count());
            }
        }
    }

    let header: Vec<String> = headers
        .iter()
        .enumerate()
        .map(|(i, h)| pad(h, widths[i]))
        .collect();
    writeln!(out, "{}", header.join("  "))?;
    writeln!(
        out,
        "{}",
        widths
            .iter()
            .map(|w| "-".repeat(*w))
            .collect::<Vec<_>>()
            .join("  ")
    )?;
    for row in rows {
        let line: Vec<String> = row
            .iter()
            .enumerate()
            .map(|(i, c)| pad(c, widths.get(i).copied().unwrap_or(0)))
            .collect();
        writeln!(out, "{}", line.join("  ").trim_end())?;
    }
    Ok(())
}

/// A JSON value as one table cell. Nested values are printed compactly rather than
/// elided, because a column list is exactly the thing you wanted to see.
fn scalar(value: Option<&Json>) -> String {
    match value {
        None | Some(Json::Null) => String::new(),
        Some(Json::String(s)) => s.clone(),
        Some(Json::Bool(b)) => b.to_string(),
        Some(Json::Number(n)) => n.to_string(),
        Some(other) => other.to_string(),
    }
}
