//! `quokka` — the CLI, and at M0 the only surface.
//!
//! Stable, machine-first output: `--format json` for a single envelope, `--format
//! ndjson` for streaming, errors as JSON on stderr with meaningful exit codes
//! (ARCHITECTURE §6.1).
//!
//! Every subcommand that runs SQL goes through `quokka_core::execute()` — including the
//! `audit` subcommands, which are wrappers over queries against the built-in `@audit`
//! connection rather than a second way into the log (§5). Reading the audit log is
//! itself an audited query, which is the point.

mod format;

use std::path::PathBuf;
use std::process::ExitCode;
use std::sync::Arc;

use anyhow::{Context, Result};
use clap::{Args, Parser, Subcommand};
use quokka_core::{
    execute, Actor, ActorKind, AuditLog, Client, Engine, ExecuteRequest, Registry, Status,
    AUDIT_CONNECTION, DEFAULT_MAX_ROWS,
};

use crate::format::{sink_for, Format};

/// Exit codes, so a script can tell the failures apart (§6.1).
mod exit {
    /// The query ran and the log recorded it.
    pub const OK: u8 = 0;
    /// The query ran and failed, or was cancelled.
    pub const QUERY_FAILED: u8 = 1;
    /// Bad configuration, an unknown connection, unreadable input.
    pub const USAGE: u8 = 2;
    /// `audit verify` found the chain broken.
    pub const CHAIN_BROKEN: u8 = 3;
    /// The audit log could not be written. Either the query was refused before it ran
    /// (invariant 6) or it ran and its outcome went unrecorded.
    pub const AUDIT_FAILED: u8 = 4;
}

#[derive(Debug, Parser)]
#[command(
    name = "quokka",
    version,
    about = "A database client for agents and humans, with one append-only log of every query",
    long_about = "Every query runs through one code path and leaves two rows in an \
                  append-only audit log. Read the log with `quokka audit`, or query it \
                  like any other connection as @audit."
)]
struct Cli {
    /// Config file. Defaults to $QUOKKA_CONFIG, else <XDG config dir>/quokkaquery/config.toml.
    #[arg(long, global = true, value_name = "PATH")]
    config: Option<PathBuf>,

    /// Audit database. Defaults to $QUOKKA_AUDIT_DB, else <XDG data dir>/quokkaquery/audit.db.
    #[arg(long, global = true, value_name = "PATH")]
    audit_db: Option<PathBuf>,

    /// Name this run in the log. Agents should set it; humans usually need not.
    #[arg(long, global = true, env = "QUOKKA_ACTOR", value_name = "NAME")]
    actor: Option<String>,

    /// Whether this run is a human, an agent or an automation. Inferred from --actor.
    #[arg(long, global = true, value_enum, value_name = "KIND")]
    actor_kind: Option<ActorKindArg>,

    #[command(subcommand)]
    command: Command,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, clap::ValueEnum)]
#[value(rename_all = "lower")]
enum ActorKindArg {
    Human,
    Agent,
    Automation,
}

impl From<ActorKindArg> for ActorKind {
    fn from(a: ActorKindArg) -> Self {
        match a {
            ActorKindArg::Human => ActorKind::Human,
            ActorKindArg::Agent => ActorKind::Agent,
            ActorKindArg::Automation => ActorKind::Automation,
        }
    }
}

#[derive(Debug, Subcommand)]
enum Command {
    /// Run SQL against a connection.
    Query(QueryArgs),
    /// Read and check the audit log.
    #[command(subcommand)]
    Audit(AuditCommand),
}

#[derive(Debug, Args)]
struct QueryArgs {
    /// The connection to run against, as named in the config file. `@audit` is built in.
    #[arg(short, long, value_name = "NAME")]
    connection: String,

    /// The SQL to run. Omit it and pass --file instead.
    #[arg(value_name = "SQL")]
    sql: Option<String>,

    /// Read the SQL from a file. `-` reads stdin.
    #[arg(short = 'f', long, value_name = "PATH", conflicts_with = "sql")]
    file: Option<PathBuf>,

    #[arg(long, value_enum, default_value = "table")]
    format: Format,

    /// Stop after this many rows and say so. 512 is the UI's hard ceiling; a shell
    /// pipeline is not a context window, so here it may be raised.
    #[arg(long, value_name = "N", default_value_t = DEFAULT_MAX_ROWS)]
    max_rows: u64,
}

#[derive(Debug, Subcommand)]
enum AuditCommand {
    /// Show the most recent events.
    Tail(TailArgs),
    /// Run SQL against the audit log. Shorthand for `--connection @audit`.
    Query(AuditQueryArgs),
    /// Recompute the hash chain and report anything that does not match.
    Verify(VerifyArgs),
}

#[derive(Debug, Args)]
struct TailArgs {
    /// How many events to show.
    #[arg(short = 'n', long, value_name = "N", default_value_t = 20)]
    limit: u64,

    /// Only events from this actor.
    #[arg(long, value_name = "NAME")]
    actor: Option<String>,

    /// Only events for this connection.
    #[arg(long, value_name = "NAME")]
    connection: Option<String>,

    /// One row per query rather than one per event: the `queries` view, which joins the
    /// start and the finish.
    #[arg(long)]
    queries: bool,

    #[arg(long, value_enum, default_value = "table")]
    format: Format,
}

#[derive(Debug, Args)]
struct AuditQueryArgs {
    #[arg(value_name = "SQL")]
    sql: String,

    #[arg(long, value_enum, default_value = "table")]
    format: Format,

    #[arg(long, value_name = "N", default_value_t = DEFAULT_MAX_ROWS)]
    max_rows: u64,
}

#[derive(Debug, Args)]
struct VerifyArgs {
    #[arg(long, value_enum, default_value = "table")]
    format: Format,
}

#[tokio::main]
async fn main() -> ExitCode {
    let cli = Cli::parse();
    let json_errors = matches!(error_format(&cli), Format::Json | Format::Ndjson);

    match run(cli).await {
        Ok(code) => ExitCode::from(code),
        Err(e) => {
            report_error(&e, json_errors);
            ExitCode::from(classify(&e))
        }
    }
}

/// Which format the failing subcommand was asked for, so an error is shaped like the
/// output would have been.
fn error_format(cli: &Cli) -> Format {
    match &cli.command {
        Command::Query(a) => a.format,
        Command::Audit(AuditCommand::Tail(a)) => a.format,
        Command::Audit(AuditCommand::Query(a)) => a.format,
        Command::Audit(AuditCommand::Verify(a)) => a.format,
    }
}

async fn run(cli: Cli) -> Result<u8> {
    let audit_path = match &cli.audit_db {
        Some(p) => p.clone(),
        None => quokka_audit::default_audit_path()
            .context("locating the audit log; set --audit-db or $QUOKKA_AUDIT_DB")?,
    };

    let audit = AuditLog::open(&audit_path)
        .await
        .with_context(|| format!("opening the audit log at {}", audit_path.display()))?;

    let registry = Registry::load(cli.config.as_deref(), &audit_path)?;
    let engine = Arc::new(Engine::new(
        registry,
        audit,
        quokka_driver::builtin_factories(),
    ));

    watch_for_interrupt(engine.clone());

    let actor = resolve_actor(cli.actor.clone(), cli.actor_kind);

    let code = match cli.command {
        Command::Query(args) => {
            let sql = read_sql(&args)?;
            run_query(
                &engine,
                &args.connection,
                &sql,
                args.format,
                args.max_rows,
                actor,
            )
            .await?
        }
        Command::Audit(AuditCommand::Query(args)) => {
            run_query(
                &engine,
                AUDIT_CONNECTION,
                &args.sql,
                args.format,
                args.max_rows,
                actor,
            )
            .await?
        }
        Command::Audit(AuditCommand::Tail(args)) => {
            let sql = tail_sql(&args);
            run_query(
                &engine,
                AUDIT_CONNECTION,
                &sql,
                args.format,
                args.limit,
                actor,
            )
            .await?
        }
        Command::Audit(AuditCommand::Verify(args)) => verify(&engine, args.format).await?,
    };

    engine.audit().close().await;
    Ok(code)
}

/// Ctrl-C asks the driver to stop, rather than killing the process.
///
/// The difference matters: a cancelled query still writes `query_finished` with
/// `status = 'cancelled'`, so the log says what happened instead of holding a start with
/// no finish.
fn watch_for_interrupt(engine: Arc<Engine>) {
    tokio::spawn(async move {
        if tokio::signal::ctrl_c().await.is_ok() {
            eprintln!("cancelling…");
            engine.cancel_all().await;
        }
    });
}

async fn run_query(
    engine: &Engine,
    connection: &str,
    sql: &str,
    format: Format,
    max_rows: u64,
    actor: Actor,
) -> Result<u8> {
    let mut sink = sink_for(format);
    let mut request = ExecuteRequest::new(connection, sql, actor);
    request.client = Client::Cli;
    request.max_rows = max_rows;

    let outcome = execute(engine, request, sink.as_mut()).await?;

    Ok(match outcome.status {
        Status::Ok => exit::OK,
        _ => exit::QUERY_FAILED,
    })
}

/// Verification reads the log's own rows rather than going through `execute()`.
///
/// That is not a shortcut around invariant 1. `@audit` is the driver-mediated path for
/// running *SQL* against the log, and `quokka audit query` uses it. Checking the chain
/// is `quokka-audit` inspecting the file it owns and writes — the same access the log
/// uses to append — and its answer is a list of problems, not a result set.
async fn verify(engine: &Engine, format: Format) -> Result<u8> {
    let report = engine.audit().verify().await?;

    match format {
        Format::Json | Format::Ndjson => {
            println!("{}", serde_json::to_string(&report)?);
        }
        Format::Table => {
            if report.is_intact() {
                println!(
                    "the chain is intact: {} event{} verified",
                    report.rows_checked,
                    if report.rows_checked == 1 { "" } else { "s" }
                );
            } else {
                println!(
                    "the chain is BROKEN: {} problem{} across {} event{}",
                    report.problems.len(),
                    if report.problems.len() == 1 { "" } else { "s" },
                    report.rows_checked,
                    if report.rows_checked == 1 { "" } else { "s" }
                );
                for p in &report.problems {
                    println!("  - {p}");
                }
                println!(
                    "\nNote: the chain detects tampering by something running as you — an \
                     agent editing the record of what it just did. It is not a defence \
                     against you, who can rebuild it at will."
                );
            }
        }
    }

    Ok(if report.is_intact() {
        exit::OK
    } else {
        exit::CHAIN_BROKEN
    })
}

fn read_sql(args: &QueryArgs) -> Result<String> {
    if let Some(sql) = &args.sql {
        return Ok(sql.clone());
    }
    let path = args.file.as_ref().ok_or_else(|| {
        anyhow::anyhow!("no SQL given: pass it as an argument or with --file (`-` for stdin)")
    })?;
    if path.as_os_str() == "-" {
        let mut buf = String::new();
        std::io::Read::read_to_string(&mut std::io::stdin().lock(), &mut buf)
            .context("reading SQL from stdin")?;
        return Ok(buf);
    }
    std::fs::read_to_string(path).with_context(|| format!("reading SQL from {}", path.display()))
}

fn tail_sql(args: &TailArgs) -> String {
    let source = if args.queries { "queries" } else { "audit_log" };
    let ordering = if args.queries { "started_at" } else { "id" };
    let columns = if args.queries {
        "started_at, status, actor_kind, actor_id, client, connection, statement_kind, \
         duration_ms, rows_returned, truncated, sql_fingerprint"
    } else {
        "at, event_kind, status, actor_kind, actor_id, client, connection, statement_kind, \
         duration_ms, rows_returned, sql_fingerprint"
    };

    let mut where_clauses = Vec::new();
    if let Some(actor) = &args.actor {
        where_clauses.push(format!("actor_id = {}", sql_literal(actor)));
    }
    if let Some(connection) = &args.connection {
        where_clauses.push(format!("connection = {}", sql_literal(connection)));
    }
    let filter = if where_clauses.is_empty() {
        String::new()
    } else {
        format!(" WHERE {}", where_clauses.join(" AND "))
    };

    format!(
        "SELECT {columns} FROM {source}{filter} ORDER BY {ordering} DESC LIMIT {}",
        args.limit
    )
}

/// Quote a filter value as a SQL literal.
///
/// Bound parameters are not supported yet — they need an audit story of their own, since
/// `params` follows `sql_logging` — so the one place the CLI builds SQL from user input
/// escapes it here. The value lands in the log as `?` either way: the fingerprint
/// replaces literals before anything is written.
fn sql_literal(value: &str) -> String {
    format!("'{}'", value.replace('\'', "''"))
}

/// An explicit `--actor` means something is naming itself, and the thing that bothers to
/// is an agent. A human at a terminal gets their OS user and `actor_kind = human`.
/// `--actor-kind` settles it either way.
fn resolve_actor(actor: Option<String>, kind: Option<ActorKindArg>) -> Actor {
    match actor {
        Some(id) => Actor {
            kind: kind.map(Into::into).unwrap_or(ActorKind::Agent),
            id,
        },
        None => Actor {
            kind: kind.map(Into::into).unwrap_or(ActorKind::Human),
            id: os_user(),
        },
    }
}

fn os_user() -> String {
    std::env::var("USER")
        .or_else(|_| std::env::var("USERNAME"))
        .unwrap_or_else(|_| "unknown".to_string())
}

fn classify(e: &anyhow::Error) -> u8 {
    match e.downcast_ref::<quokka_core::CoreError>() {
        Some(quokka_core::CoreError::AuditWriteFailed { .. })
        | Some(quokka_core::CoreError::AuditFinishFailed { .. })
        | Some(quokka_core::CoreError::Audit(_)) => exit::AUDIT_FAILED,
        Some(quokka_core::CoreError::Driver(_)) => exit::QUERY_FAILED,
        _ => exit::USAGE,
    }
}

fn report_error(e: &anyhow::Error, as_json: bool) {
    if as_json {
        let chain: Vec<String> = e.chain().map(|c| c.to_string()).collect();
        let payload = serde_json::json!({
            "error": e.to_string(),
            "causes": chain,
        });
        eprintln!("{payload}");
    } else {
        eprintln!("error: {e}");
        for cause in e.chain().skip(1) {
            eprintln!("  caused by: {cause}");
        }
    }
}
