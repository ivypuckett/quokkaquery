//! `quokka query` and `quokka export`, both reading through the spool.
//!
//! The shape of a query at M2 (ARCHITECTURE §4):
//!
//! 1. A spool is created for the query *before* it runs, so a cache that cannot be
//!    written stops the query rather than losing its rows halfway.
//! 2. `execute()` streams the rows into it. The spool is the sink; it is not a second
//!    execute path.
//! 3. Everything after that is a read of the spool — the preview on stdout, page by
//!    page, and the export. Neither costs a second execution (invariant 2).
//!
//! The one path that skips the spool is `--all`, which §4.2 puts there on purpose: a
//! dataset larger than local disk streams driver → file and is not cached, so it cannot
//! afterwards be paged, sorted or re-exported without running the query again.
//!
//! **Exports are logged even though they touch no database.** That is §5, and it is the
//! opposite of the rule for a catalog cache hit one page earlier; the reasoning lives in
//! `quokka_core::export`.

use anyhow::{bail, Context, Result};
use quokka_core::{
    execute, record_export, summarize, Actor, Client, Engine, ExecuteRequest, ExportRecord,
    Outcome, Status, Value, DEFAULT_MAX_ROWS,
};
use quokka_spool::{
    Destination, ExportReport, ExportSink, Format as ExportFormat, Position, Scoping, SortKey,
    Spool, SpoolSet, SpoolWriter, View, MAX_PAGE_ROWS,
};
use serde_json::{json, Map, Value as Json};
use uuid::Uuid;

use crate::exit;
use crate::format::{sink_for, Format};

/// The query ran and was logged; writing its export did not work.
///
/// A type of its own purely so [`crate::exit::EXPORT_FAILED`] can be told apart from a
/// usage error. Written by hand rather than with `thiserror`, which is a library
/// dependency this crate does not otherwise carry.
#[derive(Debug)]
pub struct ExportFailed(pub quokka_spool::SpoolError);

impl std::fmt::Display for ExportFailed {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // No interpolation of the source: it is the next line of the chain already, and
        // printing it twice reads like two failures.
        f.write_str("the export could not be written")
    }
}

impl std::error::Error for ExportFailed {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        Some(&self.0)
    }
}

/// Everything `quokka query` was asked for.
pub struct QueryPlan {
    pub connection: String,
    pub sql: String,
    pub params: Vec<Value>,
    pub format: Format,
    /// `None` means "the default", which differs depending on whether a file is being
    /// written — see [`QueryPlan::read_bound`].
    pub max_rows: Option<u64>,
    pub export: Option<ExportTarget>,
    pub sort: Vec<String>,
    pub parent_id: Option<Uuid>,
}

/// Where an export goes and in what form.
pub struct ExportTarget {
    pub destination: Destination,
    pub format: ExportFormat,
    /// Stream driver → file with no spool at all (§4.2).
    pub all: bool,
}

impl ExportTarget {
    /// Resolve `--export` and `--export-format` into a destination and a format.
    pub fn resolve(path: &str, format: Option<&str>, all: bool) -> Result<Self> {
        let destination = Destination::parse(path);
        let format = match format {
            Some(name) => ExportFormat::parse(name).ok_or_else(|| {
                anyhow::anyhow!(
                    "unknown export format {name:?}; this build writes {}",
                    ExportFormat::names().join(", ")
                )
            })?,
            None => match &destination {
                Destination::Path(p) => ExportFormat::from_path(p).ok_or_else(|| {
                    anyhow::anyhow!(
                        "cannot tell what {} should be written as; name the format with \
                         --export-format ({})",
                        p.display(),
                        ExportFormat::names().join(", ")
                    )
                })?,
                Destination::Stdout => bail!(
                    "exporting to stdout needs --export-format ({}), because there is no \
                     file name to read it from",
                    ExportFormat::names().join(", ")
                ),
            },
        };
        Ok(ExportTarget {
            destination,
            format,
            all,
        })
    }
}

impl QueryPlan {
    /// How many rows to read from the database.
    ///
    /// `--max-rows` when it was given. Otherwise 512 — except when a file is being
    /// written, where the default becomes the spool's own cap, because a file is not a
    /// screen and §4 promises an export unbounded by the display cap.
    fn read_bound(&self, spool_rows: u64) -> u64 {
        match self.max_rows {
            Some(n) => n,
            // One row past the spool's own cap, for the same reason `execute()` reads
            // one row past `max_rows`: it is how the cap becomes *known*. Stopping
            // exactly at the cap would leave "the spool is full" and "the result was
            // exactly this long" indistinguishable, and the file would be a prefix that
            // called itself complete.
            None if self.export.is_some() => spool_rows.saturating_add(1),
            None => DEFAULT_MAX_ROWS,
        }
    }

    /// How many rows stdout shows.
    fn preview_rows(&self) -> u64 {
        self.max_rows.unwrap_or(DEFAULT_MAX_ROWS)
    }
}

/// Run a query, then read its preview and its export out of the spool.
pub async fn query(
    engine: &Engine,
    spools: &SpoolSet,
    plan: QueryPlan,
    actor: Actor,
) -> Result<u8> {
    let query_id_hint = Uuid::now_v7();

    let mut request = ExecuteRequest::new(&plan.connection, &plan.sql, actor.clone());
    request.client = Client::Cli;
    request.max_rows = plan.read_bound(spools.limits().max_rows);
    request.params = plan.params.clone();
    request.parent_id = plan.parent_id;

    // `--all`: the export is the sink, and nothing is cached.
    if let Some(target) = plan.export.as_ref().filter(|t| t.all) {
        let mut sink =
            ExportSink::create(&target.destination, target.format).context("opening the export")?;
        let outcome = execute(engine, request, &mut sink).await?;
        let report = sink.report(&outcome);

        record(engine, &plan, &outcome, &report, &actor, None).await?;
        summarize_export(plan.format, &outcome, &report, true)?;
        return Ok(code_for(&outcome));
    }

    let mut writer: SpoolWriter = spools
        .writer(query_id_hint, &plan.connection)
        .context("creating the spool for this query")?;
    let path = writer.path().to_path_buf();

    let outcome = execute(engine, request, &mut writer).await?;

    // A query that failed has no rows to page or export. The formatter still gets the
    // outcome, so the failure is reported exactly as it was at M1.
    if !outcome.is_ok() {
        let mut sink = sink_for(plan.format);
        sink.begin(&outcome.columns)?;
        sink.end(&outcome)?;
        return Ok(code_for(&outcome));
    }

    let spool = Spool::open(&path)
        .await
        .context("opening the spool this query just wrote")?;
    let view = parse_sort(&spool, &plan.sort)?;

    let showing_on_stdout = matches!(
        plan.export.as_ref().map(|t| &t.destination),
        Some(Destination::Stdout)
    );
    if !showing_on_stdout {
        preview(&spool, &view, plan.format, &outcome, plan.preview_rows()).await?;
    }

    let mut status = code_for(&outcome);
    if let Some(target) = &plan.export {
        let report = quokka_spool::export(&spool, &target.destination, target.format, &view).await;
        status = finish_export(engine, &plan, &outcome, report, &actor, status).await?;
    }

    spool.close().await;
    Ok(status)
}

/// Everything `quokka export` was asked for.
pub struct ExportById {
    pub query_id: Uuid,
    pub rerun: bool,
    pub target: ExportTarget,
    pub max_rows: Option<u64>,
    pub sort: Vec<String>,
    /// How to print the summary — not what to write the file as.
    pub format: Format,
}

/// `quokka export --query-id <id>`.
///
/// Without `--rerun` this runs nothing at all — not even a lookup. That is §1.4 and
/// §4.1 together: the spool from the earlier invocation is gone, so producing the file
/// means paying for the scan a second time, and a cost-bearing re-run is never implicit.
/// The check comes before the log is read so that the refusal leaves the log exactly as
/// it was.
pub async fn export_by_id(
    engine: &Engine,
    spools: &SpoolSet,
    request: ExportById,
    actor: Actor,
) -> Result<u8> {
    let ExportById {
        query_id,
        rerun,
        target,
        max_rows,
        sort,
        format,
    } = request;

    if !rerun {
        bail!(
            "refusing to export query {query_id} without --rerun.\n\
             \n\
             A spool does not survive the process that made it (§4.1), so the rows from \
             that invocation are gone. Producing this file means executing the query \
             again, which costs a second scan — on Athena, real money — and QuokkaQuery \
             never spends that implicitly.\n\
             \n\
             Add --rerun to run it again. The new run is logged as its own query, with \
             parent_id pointing at {query_id}.\n\
             \n\
             To export without a second scan, do it in the same invocation as the \
             query: quokka query --connection <name> \"…\" --export <path>"
        );
    }

    // Reading the log to find out what to re-run is this program consulting its own
    // record, the same standing `quokka audit verify` has: it is a structured lookup of
    // one row, not SQL somebody asked to run. A query someone writes against the log
    // still goes through `@audit` and is logged like any other.
    let events = quokka_core::events_for_query(engine, query_id)
        .await
        .context("reading the audit log")?;

    let started = events
        .iter()
        .find(|e| matches!(e.event.event_kind, quokka_core::EventKind::QueryStarted))
        .ok_or_else(|| {
            anyhow::anyhow!(
                "no query {query_id} in the audit log. `quokka audit tail --queries` \
                 lists the queries this log holds."
            )
        })?;

    let sql = started.event.sql_text.clone().ok_or_else(|| {
        anyhow::anyhow!(
            "cannot re-run query {query_id}: connection {:?} logs SQL as {:?}, which \
             stores the query's shape with its literals replaced by `?` (§5.1). The \
             text needed to run it again was never written down.\n\
             \n\
             Reconstructing SQL from a fingerprint would run a *different* query from \
             the one you are citing, so QuokkaQuery will not do it.\n\
             \n\
             For queries you may want to re-run, set sql_logging = \"full\" on that \
             connection — a human-only setting in the config file (invariant 7), and one \
             that applies to future queries only, since literals dropped at write time \
             are gone.",
            started.event.connection,
            started.event.sql_logging.as_str(),
        )
    })?;

    if engine.registry().get(&started.event.connection).is_none() {
        bail!(
            "query {query_id} ran against connection {:?}, which is not in the config \
             file any more, so there is nothing to re-run it against.",
            started.event.connection
        );
    }

    let plan = QueryPlan {
        connection: started.event.connection.clone(),
        sql,
        params: Vec::new(),
        format,
        max_rows,
        export: Some(target),
        sort,
        // The re-run is a new query whose parent is the one being cited (§4.1).
        parent_id: Some(query_id),
    };

    query(engine, spools, plan, actor).await
}

/// Print the first rows, page by page, out of the spool.
///
/// Paging is what this is: `MAX_PAGE_ROWS` at a time through
/// [`Spool::page`], which is §4's `WHERE rowid > ? LIMIT 512`. It looks like overkill
/// for a CLI preview and is the point — the surfaces at M3 and M4 page the same way,
/// over something already proven here.
async fn preview(
    spool: &Spool,
    view: &View,
    format: Format,
    outcome: &Outcome,
    rows_wanted: u64,
) -> Result<()> {
    let mut sink = sink_for(format);
    sink.begin(spool.columns())?;

    let mut at = Position::start();
    let mut shown = 0u64;
    while shown < rows_wanted {
        let want = (rows_wanted - shown).min(MAX_PAGE_ROWS);
        let page = spool.page(view, at, want).await?;
        for row in &page.rows {
            sink.row(row)?;
            shown += 1;
        }
        match page.next {
            Some(next) if !page.rows.is_empty() => at = next,
            _ => break,
        }
    }

    sink.end(outcome)?;

    // The sentence §4.2 exists to make unmissable: a sort over a truncated spool orders
    // the spooled prefix, not the result.
    if !view.is_arrival_order() {
        if let Some(note) = spool.scoping().note() {
            eprintln!("note: {note}");
        }
    }
    Ok(())
}

/// Turn `--sort name` / `--sort total:desc` into a view over this spool's columns.
fn parse_sort(spool: &Spool, sort: &[String]) -> Result<View> {
    let mut keys = Vec::with_capacity(sort.len());
    for spec in sort {
        let (name, direction) = match spec.rsplit_once(':') {
            Some((n, "desc")) => (n, true),
            Some((n, "asc")) => (n, false),
            Some((_, other)) => {
                bail!("--sort {spec:?}: {other:?} is not a direction; write `asc` or `desc`")
            }
            None => (spec.as_str(), false),
        };
        let index = spool.column_index(name).ok_or_else(|| {
            anyhow::anyhow!(
                "--sort {spec:?}: this result has no column called {name:?}. Its columns \
                 are: {}",
                spool
                    .columns()
                    .iter()
                    .map(|c| c.name.as_str())
                    .collect::<Vec<_>>()
                    .join(", ")
            )
        })?;
        keys.push(if direction {
            SortKey::desc(index)
        } else {
            SortKey::asc(index)
        });
    }
    Ok(View::sorted_by(keys))
}

/// Log the export, then say what it did.
async fn finish_export(
    engine: &Engine,
    plan: &QueryPlan,
    outcome: &Outcome,
    report: Result<ExportReport, quokka_spool::ExportFailure>,
    actor: &Actor,
    status_so_far: u8,
) -> Result<u8> {
    let target = plan
        .export
        .as_ref()
        .expect("an export was attempted, so one was asked for");

    match report {
        Ok(report) => {
            record(engine, plan, outcome, &report, actor, None).await?;
            summarize_export(plan.format, outcome, &report, false)?;
            Ok(status_so_far)
        }
        Err(failure) => {
            // A failed export can still have left a partial file behind, so it is
            // logged as what it was: an export that happened, went wrong, and put this
            // many rows on disk before it did. Logging zero would have the audit trail
            // disagreeing with the file.
            let partial = ExportReport {
                path: target.destination.display(),
                format: target.format,
                rows: failure.rows,
                bytes: failure.bytes,
                duration_ms: 0,
                scope: Scoping {
                    spooled_rows: outcome.rows_spooled.unwrap_or(0),
                    rows_returned: outcome.rows_returned,
                    spool_capped: outcome.spool_capped.map(|c| c.as_str().to_string()),
                    truncated_by_max_rows: outcome.truncated,
                },
            };
            record(engine, plan, outcome, &partial, actor, Some(&failure.error)).await?;
            Err(anyhow::Error::new(ExportFailed(failure.error)))
        }
    }
}

/// Append the one `export` event (§5).
async fn record(
    engine: &Engine,
    plan: &QueryPlan,
    outcome: &Outcome,
    report: &ExportReport,
    actor: &Actor,
    failure: Option<&quokka_spool::SpoolError>,
) -> Result<Uuid> {
    let dialect = engine
        .registry()
        .get(&plan.connection)
        .map(|c| c.dialect())
        .unwrap_or(quokka_core::Dialect::Sqlite);

    Ok(record_export(
        engine,
        ExportRecord {
            connection: plan.connection.clone(),
            // The query whose rows these are. `parent_id` is how §5 links an export to
            // it, and how a reviewer gets from "this file exists" to "this filled it".
            parent_query_id: outcome.query_id,
            sql_fingerprint: summarize(&plan.sql, dialect).fingerprint,
            actor: actor.clone(),
            client: Client::Cli,
            format: report.format.as_str().to_string(),
            path: report.path.clone(),
            rows: report.rows,
            truncated: !report.is_whole_result(),
            duration_ms: report.duration_ms,
            status: match failure {
                None => Status::Ok,
                Some(_) => Status::Error,
            },
            error_code: failure.map(|e| e.code().to_string()),
            error_message: failure.map(|e| e.to_string()),
            tags: None,
        },
    )
    .await?)
}

/// Say what the export did.
///
/// For the machine formats this goes to stderr, for the same reason the ndjson summary
/// does: stdout stays exactly one envelope, or exactly the rows, and nothing else.
fn summarize_export(
    format: Format,
    outcome: &Outcome,
    report: &ExportReport,
    streamed: bool,
) -> Result<()> {
    // When the export *is* stdout, the summary cannot go there whatever the format was:
    // a line of prose in the middle of a pipeline is corruption of the file.
    let to_stderr = matches!(format, Format::Json | Format::Ndjson) || report.path == "-";

    let mut envelope = Map::new();
    envelope.insert("export".into(), Json::Bool(true));
    envelope.insert("query_id".into(), json!(outcome.query_id.to_string()));
    envelope.insert("path".into(), json!(report.path));
    envelope.insert("format".into(), json!(report.format.as_str()));
    envelope.insert("rows".into(), json!(report.rows));
    envelope.insert("bytes".into(), json!(report.bytes));
    envelope.insert("duration_ms".into(), json!(report.duration_ms));
    envelope.insert("whole_result".into(), json!(report.is_whole_result()));
    envelope.insert("streamed".into(), json!(streamed));
    if let Some(note) = report.scope.note() {
        envelope.insert("note".into(), json!(note));
    }

    if to_stderr && !matches!(format, Format::Table) {
        eprintln!("{}", Json::Object(envelope));
        return Ok(());
    }

    let line = format!(
        "exported {} row{} to {} ({}, {} byte{})",
        report.rows,
        if report.rows == 1 { "" } else { "s" },
        report.path,
        report.format,
        report.bytes,
        if report.bytes == 1 { "" } else { "s" }
    );
    let note = report
        .scope
        .note()
        .map(|note| format!("note: the file holds what the spool held — {note}"));

    if to_stderr {
        eprintln!("{line}");
        if let Some(note) = note {
            eprintln!("{note}");
        }
    } else {
        println!("{line}");
        if let Some(note) = note {
            println!("{note}");
        }
    }
    Ok(())
}

fn code_for(outcome: &Outcome) -> u8 {
    match outcome.status {
        Status::Ok => exit::OK,
        _ => exit::QUERY_FAILED,
    }
}
