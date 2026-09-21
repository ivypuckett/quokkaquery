//! `quokka` — the CLI, and until M3's MCP server the only surface.
//!
//! Stable, machine-first output: `--format json` for a single envelope, `--format
//! ndjson` for streaming, errors as JSON on stderr with meaningful exit codes
//! (ARCHITECTURE §6.1).
//!
//! Every subcommand that reaches a database goes through `quokka-core` — `execute()`
//! for SQL, `introspect()` for a catalog — including the `audit` subcommands, which are
//! wrappers over queries against the built-in `@audit` connection rather than a second
//! way into the log (§5). Reading the audit log is itself an audited query, which is the
//! point.
//!
//! `connections list` and `credential` are the exceptions that prove it: neither reaches
//! a database at all. One reads the config file and the other the OS keyring, so neither
//! has anything to log.

mod connections;
mod credential;
mod format;
mod schema;
mod spool;

use std::path::PathBuf;
use std::process::ExitCode;
use std::sync::Arc;

use anyhow::{Context, Result};
use clap::{Args, Parser, Subcommand};
use quokka_core::{
    Actor, ActorKind, AuditLog, Config, Engine, Value, AUDIT_CONNECTION, DEFAULT_MAX_ROWS,
};
use quokka_spool::SpoolSet;
use uuid::Uuid;

use crate::format::Format;
use crate::spool::{ExportTarget, QueryPlan};

/// Exit codes, so a script can tell the failures apart (§6.1).
pub mod exit {
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
    /// The query ran and was logged; writing its export did not work.
    ///
    /// Its own code because neither of the neighbouring ones is true: a full disk is
    /// not the caller's usage error, and the query really did run. A script that sees
    /// this should retry the file, not re-examine its arguments — and the rows are in
    /// the log either way.
    pub const EXPORT_FAILED: u8 = 5;
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
    /// Write an earlier query's rows to a file. Needs --rerun, and says why.
    Export(ExportArgs),
    /// Show the configured connections.
    #[command(subcommand)]
    Connections(ConnectionsCommand),
    /// Read a connection's catalog.
    #[command(subcommand)]
    Schema(SchemaCommand),
    /// Store, remove and check connection credentials.
    #[command(subcommand)]
    Credential(CredentialCommand),
    /// Read and check the audit log.
    #[command(subcommand)]
    Audit(AuditCommand),
}

#[derive(Debug, Subcommand)]
enum ConnectionsCommand {
    /// List every connection this build can reach, and where each keeps its credential.
    List(ConnectionsListArgs),
}

#[derive(Debug, Args)]
struct ConnectionsListArgs {
    #[arg(long, value_enum, default_value = "table")]
    format: Format,
}

#[derive(Debug, Subcommand)]
enum SchemaCommand {
    /// Describe a table, or the whole catalog when no table is named.
    ///
    /// Leaves exactly one `introspect` event in the audit log — never a
    /// query_started/query_finished pair (§5).
    Describe(SchemaDescribeArgs),
}

#[derive(Debug, Args)]
struct SchemaDescribeArgs {
    #[arg(short, long, value_name = "NAME")]
    connection: String,

    /// `table`, `schema.table` or `database.schema.table`. Omit it to describe
    /// everything the connection can see.
    #[arg(value_name = "TABLE")]
    table: Option<String>,

    /// Narrow to a schema. Also the way to reach a table whose name contains a dot.
    #[arg(long, value_name = "NAME")]
    schema: Option<String>,

    #[arg(long, value_name = "NAME")]
    database: Option<String>,

    /// Query the server even if this process cached the answer less than
    /// `catalog_ttl` ago. Refreshing is an explicit action, never an implicit one (§1.4).
    #[arg(long)]
    refresh: bool,

    #[arg(long, value_enum, default_value = "table")]
    format: Format,
}

#[derive(Debug, Subcommand)]
enum CredentialCommand {
    /// Store a connection's credential. Read from a terminal without echo, or from
    /// stdin — never from the command line, where it would land in shell history.
    Set(CredentialOneArgs),
    /// Remove a connection's stored credential.
    Delete(CredentialOneArgs),
    /// Say where each credential lives and whether one is stored. Never the value.
    Status(CredentialStatusArgs),
}

#[derive(Debug, Args)]
struct CredentialOneArgs {
    #[arg(value_name = "CONNECTION")]
    connection: String,
}

#[derive(Debug, Args)]
struct CredentialStatusArgs {
    #[arg(value_name = "CONNECTION")]
    connection: Option<String>,

    #[arg(long, value_enum, default_value = "table")]
    format: Format,
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

    /// Stop after this many rows and say so, and show that many on stdout.
    ///
    /// Defaults to 512 — the UI's hard ceiling, which a shell pipeline may raise — or,
    /// when --export is given, to the spool's own row cap, because a file is not a
    /// screen (§4.2). stdout still shows 512.
    #[arg(long, value_name = "N")]
    max_rows: Option<u64>,

    /// Also write the whole result to a file, in this one invocation (§4.1). `-` is
    /// stdout. The format comes from the extension unless --export-format says.
    ///
    /// Exports are audited events in their own right, linked to this query by
    /// parent_id (§5).
    #[arg(long, value_name = "PATH")]
    export: Option<String>,

    /// What to write the export as: csv, tsv, json, ndjson or parquet.
    #[arg(long, value_name = "FORMAT")]
    export_format: Option<String>,

    /// Stream the result straight to the export file, with no spool and no cap (§4.2).
    ///
    /// For a dataset larger than local disk. Nothing is cached, so the rows cannot
    /// afterwards be paged, sorted or re-exported without running the query again — and
    /// parquet, which declares a type per column before the rows are seen, is not
    /// available this way.
    #[arg(long, requires = "export")]
    all: bool,

    /// Sort the result by a column, reading the spool rather than re-running anything.
    /// `--sort total:desc`. Repeat for more keys.
    ///
    /// When the result was truncated this sorts the *spooled* rows and says so: the top
    /// of the first million is not the top of twelve million (§4.2).
    #[arg(long = "sort", value_name = "COLUMN[:desc]")]
    sort: Vec<String>,

    /// Bind a value, in order. `[type:]value`, where type is one of `text`, `int`,
    /// `float`, `bool`, `blob` (hex) or `null`; anything else is text.
    ///
    /// Bound values follow the connection's `sql_logging` exactly as the query text
    /// does (§5.1, rule 1): at `full` they are written to the log, at `fingerprint`
    /// only how many there were.
    #[arg(long = "param", value_name = "[TYPE:]VALUE")]
    params: Vec<String>,
}

#[derive(Debug, Args)]
struct ExportArgs {
    /// The query to export, as `quokka query` reported its id.
    #[arg(long, value_name = "ID")]
    query_id: Uuid,

    /// Run the query again. Required, because the spool died with the invocation that
    /// made it and the rows can only come back by paying for a second scan (§1.4).
    #[arg(long)]
    rerun: bool,

    /// Where to write it. `-` is stdout.
    #[arg(short = 'o', long, value_name = "PATH")]
    output: String,

    /// What to write it as: csv, tsv, json, ndjson or parquet. Inferred from the file
    /// name when it can be.
    #[arg(long, value_name = "FORMAT")]
    export_format: Option<String>,

    /// Stream straight to the file with no spool (§4.2).
    #[arg(long)]
    all: bool,

    #[arg(long, value_name = "N")]
    max_rows: Option<u64>,

    #[arg(long = "sort", value_name = "COLUMN[:desc]")]
    sort: Vec<String>,

    /// How to print the summary of what was written.
    #[arg(long, value_enum, default_value = "table")]
    format: Format,
}

/// Parse one `--param`.
///
/// The prefix has to be explicit because a query tool cannot guess: `42` is a perfectly
/// good string and `'42'` is a perfectly good integer, and picking wrong turns an index
/// scan into a sequential one, or a match into a type error. A value with no recognized
/// prefix is text, which is both the common case and the safe one; a literal string
/// starting with `int:` is written `text:int:…`.
fn parse_param(text: &str) -> Result<Value> {
    let (kind, rest) = match text.split_once(':') {
        Some((k, r)) => (k, r),
        None => ("", text),
    };
    Ok(match kind {
        "text" | "str" => Value::Text(rest.to_string()),
        "int" => Value::Int(
            rest.trim()
                .parse()
                .with_context(|| format!("--param {text:?}: {rest:?} is not an integer"))?,
        ),
        "float" => Value::Float(
            rest.trim()
                .parse()
                .with_context(|| format!("--param {text:?}: {rest:?} is not a number"))?,
        ),
        "bool" => Value::Bool(match rest.trim() {
            "true" | "1" | "yes" => true,
            "false" | "0" | "no" => false,
            other => anyhow::bail!("--param {text:?}: {other:?} is not true or false"),
        }),
        "blob" => Value::Blob(decode_hex(rest.trim()).with_context(|| {
            format!("--param {text:?}: a blob is written as hexadecimal, e.g. blob:0badc0de")
        })?),
        _ if text == "null" => Value::Null,
        // Not a prefix we know, so the whole thing — colon included — is the value.
        _ => Value::Text(text.to_string()),
    })
}

fn decode_hex(text: &str) -> Result<Vec<u8>> {
    let text = text.strip_prefix("0x").unwrap_or(text);
    if !text.len().is_multiple_of(2) {
        anyhow::bail!("hexadecimal needs an even number of digits");
    }
    (0..text.len())
        .step_by(2)
        .map(|i| {
            u8::from_str_radix(&text[i..i + 2], 16)
                .with_context(|| format!("{:?} is not hexadecimal", &text[i..i + 2]))
        })
        .collect()
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
        Command::Export(a) => a.format,
        Command::Connections(ConnectionsCommand::List(a)) => a.format,
        Command::Schema(SchemaCommand::Describe(a)) => a.format,
        Command::Credential(CredentialCommand::Status(a)) => a.format,
        // `credential set` and `delete` have no output format to match: they print a
        // sentence to stderr and nothing to stdout, on purpose.
        Command::Credential(_) => Format::Table,
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

    let config = Config::load(cli.config.as_deref(), &audit_path)?;
    let spool_limits = quokka_spool::Limits::from(config.spool);
    let engine = Arc::new(Engine::new(
        config.registry,
        audit,
        quokka_driver::builtin_factories(),
    ));

    watch_for_interrupt(engine.clone());

    let actor = resolve_actor(cli.actor.clone(), cli.actor_kind);

    // The spool directory is claimed — and orphans swept (§4.1) — only for the
    // subcommands that will actually spool something. `connections list` reaching a
    // database is not a thing that happens, and neither is it leaving a directory
    // behind in the cache.
    let mut spools: Option<SpoolSet> = None;

    let code = match cli.command {
        Command::Query(args) => {
            let sql = read_sql(&args)?;
            let params = args
                .params
                .iter()
                .map(|p| parse_param(p))
                .collect::<Result<Vec<_>>>()?;
            let export = match &args.export {
                Some(path) => Some(ExportTarget::resolve(
                    path,
                    args.export_format.as_deref(),
                    args.all,
                )?),
                None => None,
            };
            let set = spools.insert(SpoolSet::open(None, spool_limits).await.context(
                "preparing the result spool; set $QUOKKA_CACHE_DIR to choose where \
                 spools live",
            )?);
            spool::query(
                &engine,
                set,
                QueryPlan {
                    connection: args.connection,
                    sql,
                    params,
                    format: args.format,
                    max_rows: args.max_rows,
                    export,
                    sort: args.sort,
                    parent_id: None,
                },
                actor,
            )
            .await?
        }
        Command::Export(args) => {
            let target =
                ExportTarget::resolve(&args.output, args.export_format.as_deref(), args.all)?;
            let set = spools.insert(SpoolSet::open(None, spool_limits).await.context(
                "preparing the result spool; set $QUOKKA_CACHE_DIR to choose where \
                 spools live",
            )?);
            spool::export_by_id(
                &engine,
                set,
                spool::ExportById {
                    query_id: args.query_id,
                    rerun: args.rerun,
                    target,
                    max_rows: args.max_rows,
                    sort: args.sort,
                    format: args.format,
                },
                actor,
            )
            .await?
        }
        Command::Connections(ConnectionsCommand::List(args)) => {
            connections::list(&engine, args.format)?
        }
        Command::Schema(SchemaCommand::Describe(args)) => {
            let scope = schema::parse_scope(
                args.table.as_deref(),
                args.database.as_deref(),
                args.schema.as_deref(),
            );
            schema::describe(
                &engine,
                &args.connection,
                scope,
                args.refresh,
                args.format,
                actor,
            )
            .await?
        }
        Command::Credential(CredentialCommand::Set(args)) => {
            credential::set(&engine, &args.connection)?
        }
        Command::Credential(CredentialCommand::Delete(args)) => {
            credential::delete(&engine, &args.connection)?
        }
        Command::Credential(CredentialCommand::Status(args)) => {
            credential::status(&engine, args.connection.as_deref(), args.format)?
        }
        // The audit subcommands spool like every other query: they are queries against
        // `@audit`, and nothing about reading the log makes them a different kind of
        // thing (§5).
        Command::Audit(AuditCommand::Query(args)) => {
            let set = spools.insert(SpoolSet::open(None, spool_limits).await?);
            spool::query(
                &engine,
                set,
                QueryPlan {
                    connection: AUDIT_CONNECTION.to_string(),
                    sql: args.sql,
                    params: Vec::new(),
                    format: args.format,
                    max_rows: Some(args.max_rows),
                    export: None,
                    sort: Vec::new(),
                    parent_id: None,
                },
                actor,
            )
            .await?
        }
        Command::Audit(AuditCommand::Tail(args)) => {
            let sql = tail_sql(&args);
            let set = spools.insert(SpoolSet::open(None, spool_limits).await?);
            spool::query(
                &engine,
                set,
                QueryPlan {
                    connection: AUDIT_CONNECTION.to_string(),
                    sql,
                    params: Vec::new(),
                    format: args.format,
                    max_rows: Some(args.limit),
                    export: None,
                    sort: Vec::new(),
                    parent_id: None,
                },
                actor,
            )
            .await?
        }
        Command::Audit(AuditCommand::Verify(args)) => verify(&engine, args.format).await?,
    };

    // The clean exit of §4.1: the spool directory goes, so nothing of this result
    // survives the process that made it.
    if let Some(set) = spools {
        set.close().await;
    }
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
    // Checked before the core errors, because an export failure is the more specific
    // claim: the query it names ran, and only the file did not.
    if e.downcast_ref::<spool::ExportFailed>().is_some() {
        return exit::EXPORT_FAILED;
    }
    match e.downcast_ref::<quokka_core::CoreError>() {
        Some(quokka_core::CoreError::AuditWriteFailed { .. })
        | Some(quokka_core::CoreError::AuditFinishFailed { .. })
        | Some(quokka_core::CoreError::IntrospectNotRecorded { .. })
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
