//! Everything the window asks the engine to do, and nothing about how it is drawn.
//!
//! Each function here is an ordinary `async fn` that an iced `Task` runs and whose
//! result comes back as a [`Message`](crate::Message). None of them is reachable from
//! `update` or `view` except as a task, and none of them can reach a database except
//! through `quokka-core` — [`ExecutePermit`](quokka_core::ExecutePermit)'s constructor
//! is crate-private to that crate, so the compiler enforces it rather than this comment.
//!
//! ## What runs these futures, and why it matters
//!
//! iced's `tokio` feature makes its executor a `tokio::runtime::Runtime` — multi-thread,
//! built by iced at startup — and every `Task` future is spawned onto it as an ordinary
//! tokio task. Two things follow, and both are load-bearing:
//!
//! 1. **A tokio reactor is in scope inside these functions.** It has to be: `sqlx`, the
//!    drivers and `quokka-core` are all written against tokio, and iced's default
//!    executor without that feature is a plain futures thread pool, where the first
//!    database call would fail rather than merely be slow. That is why the manifest
//!    takes iced with `default-features = false` and names `tokio` itself.
//! 2. **`block_in_place` is available, and needed.** The spool's writer blocks whoever
//!    feeds it while a batch lands (§4), and `execute()` feeds it per row. The window
//!    itself is safe either way — winit's event loop is the main thread and these run on
//!    worker threads — but a worker blocked without telling tokio is every other task
//!    this window has in flight, waiting. [`execute_blocking`] is `execute()` with the
//!    runtime told; the reasoning lives on that function in `quokka-core`, because M3
//!    met the same problem behind a request handler.

use std::path::PathBuf;
use std::sync::Arc;

use quokka_core::{
    execute_blocking, introspect, record_export, summarize, Actor, AuditLog, Catalog, Client,
    Config, CoreError, DriverFactory, Engine, ExecuteRequest, ExportRecord, IntrospectRequest,
    Outcome, Registry, Scope, SpoolConfig, Status,
};
use quokka_spool::{
    Destination, Format, Page, Pager, Position, Spool, SpoolSet, View, MAX_PAGE_ROWS,
};
use uuid::Uuid;

/// What `quokka ui` was started with: everything needed to build an engine, and nothing
/// that needs a runtime to produce.
///
/// The engine is *not* built here. `AuditLog::open` and `SpoolSet::open` are async and
/// every sqlx pool they make belongs to the runtime it was made on, so they run inside
/// iced's runtime as the window's first task — which is also why the window appears
/// before the audit log is open rather than after.
pub struct Boot {
    pub config_path: Option<PathBuf>,
    pub audit_path: PathBuf,
    pub actor: Actor,
    pub factories: Vec<Arc<dyn DriverFactory>>,
}

/// One connection, as the tree and the editor chrome need it.
///
/// A flattened copy rather than a borrow of the registry, because `view` is handed `&State`
/// and the registry lives behind an `Arc<Engine>`. Nothing here is a secret: a
/// `ConnectionConfig` never holds a password (§5).
#[derive(Debug, Clone)]
pub struct ConnectionRow {
    pub name: String,
    pub driver: String,
    pub dialect: quokka_core::Dialect,
    pub target: String,
    pub mode: quokka_core::AccessMode,
    pub sql_logging: quokka_core::SqlLogging,
    pub builtin: bool,
}

/// The engine, the spools and the connection list — the window's half of the program.
#[derive(Clone)]
pub struct Session {
    pub engine: Arc<Engine>,
    pub spools: Arc<SpoolSet>,
    /// `[spool]` from the config file, for the row cap a query reads to and the
    /// `stale_after` a result tab flags itself past (§4.1).
    pub spool: SpoolConfig,
    pub actor: Actor,
    pub connections: Vec<ConnectionRow>,
}

impl std::fmt::Debug for Session {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Session")
            .field("connections", &self.connections.len())
            .finish_non_exhaustive()
    }
}

/// Open the audit log, read the config file, and claim a spool directory.
///
/// Fails loudly rather than opening a window that cannot run anything: an audit log that
/// will not open is invariant 6 arriving early — if the log cannot be written, nothing
/// runs — so the window says so instead of pretending.
pub async fn boot(boot: &Boot) -> Result<Session, String> {
    let audit = AuditLog::open(&boot.audit_path).await.map_err(|e| {
        format!(
            "opening the audit log at {}: {e}",
            boot.audit_path.display()
        )
    })?;

    let config =
        Config::load(boot.config_path.as_deref(), &boot.audit_path).map_err(|e| e.to_string())?;
    let spool = config.spool;
    let connections = connection_rows(&config.registry);

    let spools = SpoolSet::open(None, quokka_spool::Limits::from(spool))
        .await
        .map_err(|e| {
            format!(
                "preparing the result spool ({e}); set $QUOKKA_CACHE_DIR to choose where \
                 spools live"
            )
        })?;

    let engine = Engine::new(config.registry, audit, boot.factories.clone());

    Ok(Session {
        engine: Arc::new(engine),
        spools: Arc::new(spools),
        spool,
        actor: boot.actor.clone(),
        connections,
    })
}

/// Flatten a registry for the tree and the editor chrome.
///
/// Public so a test can build a [`Session`] without a config file on disk — the window's
/// own boot reads one, and a test that had to would be testing `Config::load` again.
pub fn connection_rows(registry: &Registry) -> Vec<ConnectionRow> {
    registry
        .iter()
        .map(|cfg| ConnectionRow {
            name: cfg.name.clone(),
            driver: cfg.driver.clone(),
            dialect: cfg.dialect(),
            target: cfg.target(),
            mode: cfg.mode,
            sql_logging: cfg.sql_logging,
            builtin: cfg.builtin,
        })
        .collect()
}

/// A finished result, open for paging.
#[derive(Debug, Clone)]
pub struct Loaded {
    pub query_id: Uuid,
    pub connection: String,
    pub sql: String,
    pub spool: Spool,
    pub outcome: Outcome,
    pub page: Page,
    /// Exact, from `count(*)` over the spool (§7).
    pub rows_in_view: u64,
}

/// How a run ended, in the four shapes a surface has to draw differently.
#[derive(Debug, Clone)]
pub enum Ran {
    /// Rows came back and are in a spool.
    Loaded(Box<Loaded>),
    /// The query reached a database and failed, timed out or was cancelled. It is in the
    /// log as a finished query, so the error is the engine's to report.
    Failed {
        connection: String,
        outcome: Box<Outcome>,
    },
    /// The policy engine refused it (§6.3). Nothing ran, and the log holds the attempt.
    ///
    /// The message is `CoreError::Denied`'s, rendered verbatim: it already names the
    /// setting and where to change it, in the same words the CLI and MCP use, and
    /// composing a second wording here would make one refusal read three ways.
    Denied {
        connection: String,
        code: &'static str,
        message: String,
        query_id: Uuid,
    },
    /// It never got as far as a query: an unknown connection, a spool that could not be
    /// created, an audit log that would not take the `query_started` row (invariant 6).
    Broken { connection: String, message: String },
}

/// Run one statement, spool it, and read back its first page.
///
/// The shape M2 proved on the CLI and M3 repeated over MCP: the spool is created
/// *before* the query runs, `execute()` streams into it, and everything after that —
/// this page, the next one, the export — is a read of a local file (§4, invariant 2).
pub async fn run(session: Session, connection: String, sql: String, write: bool) -> Ran {
    let query_id_hint = Uuid::now_v7();
    let mut writer = match session.spools.writer(query_id_hint, &connection) {
        Ok(w) => w,
        Err(e) => {
            return Ran::Broken {
                connection,
                message: format!("creating the spool for this query: {e}"),
            }
        }
    };
    let path = writer.path().to_path_buf();

    let mut request = ExecuteRequest::new(&connection, &sql, session.actor.clone());
    request.client = Client::Ui;
    request.write = write;
    // The window is a human's, and a human's posture is the connection's own: see the
    // note on `surface_mode` in `lib.rs` for why `quokka ui` has no `--allow-writes`.
    request.surface_mode = quokka_core::AccessMode::ReadWrite;
    // Read to the spool's own cap rather than to the grid's 512. The grid shows a page;
    // the pager's count and `[Export all]` are about the result, and both would be lies
    // if the read had stopped at what the screen holds. One row past the cap, for the
    // same reason `execute()` reads one past `max_rows`: it is how truncation becomes
    // known rather than looking like a result that happened to end there.
    request.max_rows = session.spool.max_rows.saturating_add(1);

    let outcome = match execute_blocking(&session.engine, request, &mut writer).await {
        Ok(outcome) => outcome,
        Err(CoreError::Denied {
            connection,
            query_id,
            code,
            message,
        }) => {
            return Ran::Denied {
                connection,
                code,
                message,
                query_id,
            }
        }
        Err(e) => {
            return Ran::Broken {
                connection,
                message: e.to_string(),
            }
        }
    };

    if !outcome.is_ok() {
        return Ran::Failed {
            connection,
            outcome: Box::new(outcome),
        };
    }

    let spool = match Spool::open(&path).await {
        Ok(s) => s,
        Err(e) => {
            return Ran::Broken {
                connection,
                message: format!("opening the spool this query just wrote: {e}"),
            }
        }
    };

    let view = View::arrival_order();
    match read_page(&spool, &view, Position::start()).await {
        Ok((page, rows_in_view)) => Ran::Loaded(Box::new(Loaded {
            query_id: outcome.query_id,
            connection,
            sql,
            spool,
            outcome,
            page,
            rows_in_view,
        })),
        Err(message) => Ran::Broken {
            connection,
            message,
        },
    }
}

/// One page and the exact count that goes beside it. Reads the spool; reaches nothing.
pub async fn read_page(spool: &Spool, view: &View, at: Position) -> Result<(Page, u64), String> {
    let rows_in_view = spool
        .count(view)
        .await
        .map_err(|e| format!("counting the result: {e}"))?;
    let page = spool
        .page(view, at, MAX_PAGE_ROWS)
        .await
        .map_err(|e| format!("reading the spool: {e}"))?;
    Ok((page, rows_in_view))
}

/// A page, delivered back to `update` with the tab it belongs to.
#[derive(Debug, Clone)]
pub struct Paged {
    pub query_id: Uuid,
    pub page: Page,
    pub rows_in_view: u64,
}

/// Read a page of a result already run — never a second execution (invariant 2).
pub async fn page(spool: Spool, view: View, at: Position, query_id: Uuid) -> Result<Paged, String> {
    let (page, rows_in_view) = read_page(&spool, &view, at).await?;
    Ok(Paged {
        query_id,
        page,
        rows_in_view,
    })
}

/// Refresh one connection's catalog, on the audited path (§5).
///
/// **This is the only thing in the UI that queries a database without a statement**, and
/// it is here because a human pressed something: selecting a connection for the first
/// time, or pressing Refresh. §1.4 is explicit that refreshing is an explicit action —
/// so `refresh` is set only when the user asked for one, and otherwise a catalog still
/// inside its TTL is answered from memory and appends nothing to the log at all.
pub async fn catalog(
    session: Session,
    connection: String,
    refresh: bool,
) -> Result<Catalog, String> {
    let mut request = IntrospectRequest::new(&connection, Scope::default(), session.actor.clone());
    request.client = Client::Ui;
    request.refresh = refresh;
    introspect(&session.engine, request)
        .await
        .map(|result| result.catalog)
        .map_err(|e| e.to_string())
}

/// What an export did, for the line the window shows afterwards.
#[derive(Debug, Clone)]
pub struct Exported {
    pub path: String,
    pub rows: u64,
    pub bytes: u64,
    pub whole_result: bool,
    pub note: Option<String>,
}

/// Write a result to a file, and record the event that says so (§5).
///
/// An export is audited even though it touches no database — the thing being recorded is
/// that data left the tool — and clicking rather than typing does not make it optional.
pub async fn export(
    session: Session,
    spool: Spool,
    view: View,
    outcome: Outcome,
    sql: String,
    path: String,
    format: Format,
) -> Result<Exported, String> {
    let destination = Destination::parse(&path);
    let report = quokka_spool::export(&spool, &destination, format, &view).await;

    let dialect = session
        .engine
        .registry()
        .get(&outcome.connection)
        .map(|c| c.dialect())
        .unwrap_or(quokka_core::Dialect::Sqlite);

    let (rows, bytes, whole, note, failure) = match &report {
        Ok(r) => (
            r.rows,
            r.bytes,
            r.is_whole_result(),
            r.scope.note(),
            None::<String>,
        ),
        // A failed export can still have left a partial file behind, so it is logged as
        // what it was rather than as nothing: the log must not disagree with the disk.
        Err(f) => (f.rows, f.bytes, false, None, Some(f.error.to_string())),
    };

    let record = record_export(
        &session.engine,
        ExportRecord {
            connection: outcome.connection.clone(),
            parent_query_id: outcome.query_id,
            sql_fingerprint: summarize(&sql, dialect).fingerprint,
            actor: session.actor.clone(),
            client: Client::Ui,
            format: format.as_str().to_string(),
            path: destination.display(),
            rows,
            truncated: !whole,
            duration_ms: report.as_ref().map(|r| r.duration_ms).unwrap_or(0),
            status: if failure.is_none() {
                Status::Ok
            } else {
                Status::Error
            },
            error_code: report.as_ref().err().map(|f| f.error.code().to_string()),
            error_message: failure.clone(),
            tags: None,
        },
    )
    .await;

    if let Some(message) = failure {
        return Err(format!("the export could not be written: {message}"));
    }
    // The file exists and the log does not say so — §5 calls for shouting about that
    // rather than reporting a clean export.
    record.map_err(|e| e.to_string())?;

    Ok(Exported {
        path: destination.display(),
        rows,
        bytes,
        whole_result: whole,
        note,
    })
}

/// Ask the engine to stop whatever is running.
///
/// **Labelled honestly.** sqlx 0.9 exposes neither the backend PID nor the secret key of
/// a pooled connection, so this is not "the server stopped": the consumer stops at the
/// next row boundary and the statement is dropped. The query is still a fully logged one
/// — `query_finished` records `status = 'cancelled'` — and the server may still be
/// finishing the work it was asked for.
///
/// `cancel_all()` rather than `cancel(query_id)` because the id is minted inside
/// `execute()` and a surface only learns it from the `Outcome`. The window runs one
/// query at a time (see `Running` in `state.rs`), which makes "all" exactly one.
pub async fn cancel(session: Session) {
    session.engine.cancel_all().await;
}

/// Close everything this window holds, in the order §4.1 wants it closed.
///
/// Called when the window is asked to close, before `iced::exit()`: the spool directory
/// goes, so nothing of any result survives the process that made it. Anything still
/// holding a handle leaves the files for the next process's sweep instead, which is the
/// safe way round.
pub async fn shut_down(session: Session, spools: Vec<Spool>) {
    session.engine.cancel_all().await;
    for spool in spools {
        spool.close().await;
    }
    let Session { engine, spools, .. } = session;
    if let Ok(spools) = Arc::try_unwrap(spools) {
        spools.close().await;
    }
    engine.audit().close().await;
}

/// The line above a result grid (§7), assembled from the page and its spool's meta.
pub fn pager(
    page: &Page,
    rows_in_view: u64,
    spool: &Spool,
    stale_after: Option<std::time::Duration>,
) -> Pager {
    Pager::new(
        page,
        rows_in_view,
        spool.meta(),
        time::OffsetDateTime::now_utc(),
        stale_after,
    )
}
