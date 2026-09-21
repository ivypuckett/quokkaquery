//! What the window is, and what each message does to it.
//!
//! §9 asks for the iced layer to stay thin enough that its test story is smoke tests:
//! anything worth a unit test belongs in a crate that does not need a window. So the
//! decisions here are wiring — which task to start, which tab to show — and the things
//! that are genuinely *logic* live elsewhere and are tested there:
//! [`WriteConfirmation`](quokka_core::WriteConfirmation) in `quokka-core`,
//! [`Pager`](quokka_spool::Pager) in `quokka-spool`, and this crate's own
//! [`complete`](crate::complete) and [`results`](crate::results), neither of which
//! mentions iced.
//!
//! Three rules run through every branch below, and each is invariant 2 in a different
//! disguise (§1.4):
//!
//! - **Nothing starts a query except [`Message::RunRequested`] and
//!   [`Message::RerunRequested`]**, and both come from a button. Selecting a tab does
//!   not re-run it; the grid does not refresh on focus; the clock tick that moves the
//!   elapsed-time counter touches nothing.
//! - **Paging, sorting and filtering are reads of the spool.** They take the same road
//!   as `[Next]`: a `SELECT` against a local SQLite file this process wrote.
//! - **Autocomplete reads a `Catalog` this struct is holding**, never the engine. It
//!   could not query if it wanted to: [`crate::complete::suggest`] is handed a catalog,
//!   not a connection.

use std::collections::BTreeMap;
use std::sync::Arc;
use std::time::Instant;

use iced::widget::{text_editor, Id};
use iced::{keyboard, Task, Theme};
use quokka_core::{summarize, AccessMode, Catalog, WriteConfirmation};
use quokka_spool::{Filter, Op, Position, SortKey, View};

use crate::complete::{self, Candidate, Word};
use crate::message::{AuditView, Message, Step};
use crate::results::{ExportDraft, FilterDraft, Open, Selection, Slots, Tab};
use crate::work::{self, Boot, ConnectionRow, Ran, Session};

/// A query in flight. There is at most one.
///
/// **One at a time**, which is a decision rather than a simplification. `execute()`
/// mints the `query_id` itself — a surface only learns it from the `Outcome` — so a
/// window cannot name a running query to [`Engine::cancel`](quokka_core::Engine::cancel)
/// and has to reach for `cancel_all()`. Bounding the window to one run makes "all"
/// exactly one, which is the difference between a Stop button that stops what you were
/// looking at and one that stops something else as well.
#[derive(Debug, Clone)]
pub struct Running {
    pub connection: String,
    pub sql: String,
    pub started: Instant,
    pub cancelling: bool,
}

/// A write waiting on a human (§7).
#[derive(Debug, Clone)]
pub struct Pending {
    pub connection: String,
    pub sql: String,
    pub confirmation: WriteConfirmation,
}

/// What the strip under the editor is saying.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NoticeKind {
    Info,
    /// The policy engine refused the statement. Rendered in its own words (§6.3).
    Denied,
    Error,
}

#[derive(Debug, Clone)]
pub struct Notice {
    pub kind: NoticeKind,
    pub text: String,
    pub detail: Option<String>,
}

impl Notice {
    pub fn info(text: impl Into<String>) -> Self {
        Notice {
            kind: NoticeKind::Info,
            text: text.into(),
            detail: None,
        }
    }

    pub fn error(text: impl Into<String>) -> Self {
        Notice {
            kind: NoticeKind::Error,
            text: text.into(),
            detail: None,
        }
    }
}

pub struct State {
    pub boot: Arc<Boot>,
    pub session: Option<Session>,
    /// Set when the engine could not be built at all. The window says so and runs
    /// nothing — invariant 6 arriving before there is anything to refuse.
    pub broken: Option<String>,
    pub theme: Theme,

    pub connection: Option<String>,
    /// One catalog per connection, from an explicit refresh. **This** is what
    /// autocomplete reads.
    pub catalogs: BTreeMap<String, Catalog>,
    pub catalog_loading: Option<String>,

    pub editor: text_editor::Content,
    pub word: Word,
    pub suggestions: Vec<Candidate>,

    pub running: Option<Running>,
    pub pending: Option<Pending>,
    pub notice: Option<Notice>,

    pub slots: Slots,
    pub tabs: Open,

    pub modifiers: keyboard::Modifiers,
    /// Moved by the clock tick, so elapsed time and "45m ago" are live without anything
    /// being re-read.
    pub now: Instant,
    pub shutting_down: bool,
}

impl State {
    pub fn new(boot: Arc<Boot>) -> Self {
        State {
            boot,
            session: None,
            broken: None,
            theme: Theme::Dark,
            connection: None,
            catalogs: BTreeMap::new(),
            catalog_loading: None,
            editor: text_editor::Content::new(),
            word: Word::default(),
            suggestions: Vec::new(),
            running: None,
            pending: None,
            notice: None,
            slots: Slots::new(),
            tabs: Open::new(),
            modifiers: keyboard::Modifiers::default(),
            now: Instant::now(),
            shutting_down: false,
        }
    }

    /// The connection the editor is pointed at, if one is selected.
    pub fn selected(&self) -> Option<&ConnectionRow> {
        let name = self.connection.as_deref()?;
        let session = self.session.as_ref()?;
        session.connections.iter().find(|c| c.name == name)
    }

    pub fn active_tab(&self) -> Option<&Tab> {
        self.tabs.get(&self.slots.active()?)
    }

    pub fn active_tab_mut(&mut self) -> Option<&mut Tab> {
        let id = self.slots.active()?;
        self.tabs.get_mut(&id)
    }

    /// True when pressing Run would do something. Never false *because of the
    /// connection's mode*: a greyed-out Run is chrome, and the guardrail lives in
    /// `execute()` (§6.3). What disables it is having nothing to run, or already
    /// running something.
    pub fn can_run(&self) -> bool {
        self.session.is_some()
            && self.connection.is_some()
            && self.running.is_none()
            && !self.editor.text().trim().is_empty()
    }
}

pub fn update(state: &mut State, message: Message) -> Task<Message> {
    match message {
        Message::Booted(result) => match *result {
            Ok(session) => {
                // Pick something so the window is usable on arrival. `@audit` is always
                // there; a real connection is more likely to be what was wanted.
                let first = session
                    .connections
                    .iter()
                    .find(|c| !c.builtin)
                    .or_else(|| session.connections.first())
                    .map(|c| c.name.clone());
                state.session = Some(session);
                match first {
                    Some(name) => select_connection(state, name),
                    None => Task::none(),
                }
            }
            Err(message) => {
                state.broken = Some(message);
                Task::none()
            }
        },

        Message::SystemTheme(mode) => {
            state.theme = match mode {
                iced::theme::Mode::Light => Theme::Light,
                _ => Theme::Dark,
            };
            Task::none()
        }

        Message::Tick => {
            state.now = Instant::now();
            Task::none()
        }

        Message::ModifiersChanged(modifiers) => {
            state.modifiers = modifiers;
            Task::none()
        }

        Message::CloseRequested => {
            // §4.1's clean exit: the spools go before the process does. Everything is
            // taken out of the state first so the `Arc<SpoolSet>` has one owner left.
            if state.shutting_down {
                return Task::none();
            }
            state.shutting_down = true;
            let spools: Vec<_> = std::mem::take(&mut state.tabs)
                .into_values()
                .map(|tab| tab.spool)
                .collect();
            match state.session.take() {
                Some(session) => Task::future(work::shut_down(session, spools))
                    .map(|()| Message::ShutDownFinished),
                None => Task::done(Message::ShutDownFinished),
            }
        }

        Message::ShutDownFinished => iced::exit(),

        Message::ConnectionSelected(name) => select_connection(state, name),

        Message::CatalogRefreshRequested => {
            let (Some(session), Some(connection)) =
                (state.session.clone(), state.connection.clone())
            else {
                return Task::none();
            };
            state.catalog_loading = Some(connection.clone());
            // The one `refresh = true` in this crate. §1.4: refreshing is an explicit
            // action, and this is the button.
            Task::future(work::catalog(session, connection.clone(), true)).map(move |result| {
                Message::CatalogLoaded {
                    connection: connection.clone(),
                    result: Box::new(result),
                }
            })
        }

        Message::CatalogLoaded { connection, result } => {
            if state.catalog_loading.as_deref() == Some(connection.as_str()) {
                state.catalog_loading = None;
            }
            match *result {
                Ok(catalog) => {
                    state.catalogs.insert(connection, catalog);
                    refresh_suggestions(state);
                }
                Err(message) => {
                    state.notice = Some(Notice::error(format!(
                        "could not read {connection}'s catalog: {message}"
                    )))
                }
            }
            Task::none()
        }

        Message::Edit(action) => {
            state.editor.perform(action);
            refresh_suggestions(state);
            Task::none()
        }

        Message::CompletionAccepted(index) => {
            let Some(candidate) = state.suggestions.get(index).cloned() else {
                return Task::none();
            };
            for _ in 0..state.word.replace {
                state
                    .editor
                    .perform(text_editor::Action::Edit(text_editor::Edit::Backspace));
            }
            state
                .editor
                .perform(text_editor::Action::Edit(text_editor::Edit::Paste(
                    Arc::new(candidate.text),
                )));
            state.suggestions.clear();
            Task::none()
        }

        Message::CompletionsDismissed => {
            state.suggestions.clear();
            Task::none()
        }

        Message::RunRequested => run_requested(state),

        Message::WriteConfirmed => match state.pending.take() {
            // The human turned the call-site key. The *authorization* is still the
            // connection's mode, and `execute()` is still the thing that checks it.
            Some(pending) => start(state, pending.connection, pending.sql, true),
            None => Task::none(),
        },

        Message::WriteDeclined => {
            state.pending = None;
            Task::none()
        }

        Message::CancelRequested => {
            let Some(session) = state.session.clone() else {
                return Task::none();
            };
            if let Some(running) = state.running.as_mut() {
                running.cancelling = true;
            }
            Task::future(work::cancel(session)).map(|()| Message::Cancelled)
        }

        Message::Cancelled => {
            // Nothing to do but wait: the query is still in flight until `execute()`
            // returns, and it will return with `status = 'cancelled'` in the log.
            Task::none()
        }

        Message::Ran(ran) => finished(state, *ran),

        Message::TabSelected(id) => {
            state.slots.select(id);
            Task::none()
        }

        Message::TabClosed(id) => {
            state.slots.close(id);
            match state.tabs.remove(&id) {
                // Closing a tab closes its spool and takes the file with it (§4.1).
                Some(tab) => Task::future(release(tab)).map(|()| Message::NoticeDismissed),
                None => Task::none(),
            }
        }

        Message::PageRequested(step) => page(state, step),

        Message::Paged(result) => {
            match *result {
                Ok(paged) => {
                    if let Some(tab) = state.tabs.get_mut(&paged.query_id) {
                        tab.page = paged.page;
                        tab.rows_in_view = paged.rows_in_view;
                        // A cell reference means nothing in a page that has changed
                        // under it.
                        tab.selection = None;
                        tab.inspecting = None;
                        tab.sync();
                    }
                }
                Err(message) => state.notice = Some(Notice::error(message)),
            }
            Task::none()
        }

        Message::SortRequested(column) => {
            let Some(tab) = state.active_tab_mut() else {
                return Task::none();
            };
            let direction = match tab.view.sort.first() {
                Some(key)
                    if key.column == column && key.direction == quokka_spool::Direction::Asc =>
                {
                    quokka_spool::Direction::Desc
                }
                _ => quokka_spool::Direction::Asc,
            };
            tab.view = View {
                filters: tab.view.filters.clone(),
                sort: vec![SortKey { column, direction }],
            };
            tab.sync();
            restart_paging(state)
        }

        Message::FilterColumnSelected(column) => {
            if let Some(tab) = state.active_tab_mut() {
                tab.filter.column = Some(column);
            }
            Task::none()
        }

        Message::FilterOpSelected(op) => {
            if let Some(tab) = state.active_tab_mut() {
                tab.filter.op = Some(op);
            }
            Task::none()
        }

        Message::FilterValueChanged(value) => {
            if let Some(tab) = state.active_tab_mut() {
                tab.filter.value = value;
            }
            Task::none()
        }

        Message::FilterApplied => {
            let Some(tab) = state.active_tab_mut() else {
                return Task::none();
            };
            let (Some(column), Some(op)) = (tab.filter.column, tab.filter.op) else {
                return Task::none();
            };
            let value = quokka_spool::filter_value(&tab.filter.value);
            tab.view.filters = vec![Filter::new(column, op, value)];
            tab.sync();
            restart_paging(state)
        }

        Message::FilterCleared => {
            let Some(tab) = state.active_tab_mut() else {
                return Task::none();
            };
            tab.view.filters.clear();
            tab.filter = FilterDraft::default();
            restart_paging(state)
        }

        Message::CellPressed(row, column) => {
            let extend = state.modifiers.shift();
            if let Some(tab) = state.active_tab_mut() {
                tab.selection = Some(match (extend, tab.selection) {
                    (true, Some(mut selection)) => {
                        selection.focus = (row, column);
                        selection
                    }
                    _ => Selection::cell(row, column),
                });
                tab.inspecting = Some((row, column));
                tab.sync();
            }
            Task::none()
        }

        Message::SelectionCopied => match state.active_tab().and_then(Tab::selection_as_tsv) {
            Some(tsv) => iced::clipboard::write(tsv),
            None => Task::none(),
        },

        Message::InspectorClosed => {
            if let Some(tab) = state.active_tab_mut() {
                tab.inspecting = None;
            }
            Task::none()
        }

        Message::ColumnResizing(column, offset) => {
            if let Some(tab) = state.active_tab_mut() {
                tab.resizing = Some((column, offset));
                tab.sync();
            }
            Task::none()
        }

        Message::ColumnResized => {
            if let Some(tab) = state.active_tab_mut() {
                tab.finish_resize();
            }
            Task::none()
        }

        Message::HeaderSynced(offset) => match state.active_tab() {
            Some(tab) => iced::widget::operation::scroll_to(tab.header_id.clone(), offset),
            None => Task::none(),
        },

        Message::ExportPathChanged(path) => {
            if let Some(tab) = state.active_tab_mut() {
                tab.export.path = path;
            }
            Task::none()
        }

        Message::ExportFormatChanged(format) => {
            if let Some(tab) = state.active_tab_mut() {
                tab.export.format = format;
            }
            Task::none()
        }

        Message::ExportRequested => export(state),

        Message::Exported(result) => {
            state.notice = Some(match *result {
                Ok(done) => {
                    let mut notice = Notice::info(format!(
                        "exported {} row{} to {} ({} bytes)",
                        done.rows,
                        if done.rows == 1 { "" } else { "s" },
                        done.path,
                        done.bytes
                    ));
                    notice.detail = done.note;
                    notice
                }
                Err(message) => Notice::error(message),
            });
            Task::none()
        }

        Message::NoticeDismissed => {
            state.notice = None;
            Task::none()
        }

        Message::AuditRequested(view) => {
            // §5: the audit view *is* a result tab over a saved query on `@audit`. This
            // fills the editor with that query and runs it like any other — which is
            // why reading the log leaves its own pair of events in the log.
            state.connection = Some(quokka_core::AUDIT_CONNECTION.to_string());
            state.editor = text_editor::Content::with_text(audit_sql(view));
            state.suggestions.clear();
            run_requested(state)
        }

        Message::RerunRequested => {
            let Some((connection, sql)) = state
                .active_tab()
                .map(|tab| (tab.connection.clone(), tab.sql.clone()))
            else {
                return Task::none();
            };
            // A re-run is an ordinary run of the same statement: same confirmation, same
            // policy check, a new pair of events in the log. §1.4 wants the control,
            // never the behaviour.
            state.connection = Some(connection);
            state.editor = text_editor::Content::with_text(&sql);
            run_requested(state)
        }
    }
}

/// Point the editor at a connection, and read its catalog if this window has not.
///
/// The catalog read is an `introspect` on the audited path, and it is *not* a refresh:
/// a catalog still inside its TTL is answered from memory and appends nothing at all
/// (§5). What it is not, ever, is a peek at the table's rows — that is the helpful thing
/// §1.4 forbids.
fn select_connection(state: &mut State, name: String) -> Task<Message> {
    state.connection = Some(name.clone());
    state.suggestions.clear();

    let Some(session) = state.session.clone() else {
        return Task::none();
    };
    if state.catalogs.contains_key(&name) {
        return Task::none();
    }
    state.catalog_loading = Some(name.clone());
    Task::future(work::catalog(session, name.clone(), false)).map(move |result| {
        Message::CatalogLoaded {
            connection: name.clone(),
            result: Box::new(result),
        }
    })
}

/// Recompute the completion list from the catalog already in memory.
///
/// Called on every keystroke, which is fine precisely because it reaches nothing.
fn refresh_suggestions(state: &mut State) {
    let cursor = state.editor.cursor().position;
    let line = state
        .editor
        .line(cursor.line)
        .map(|l| l.text.to_string())
        .unwrap_or_default();
    state.word = complete::word_at(&line, cursor.column);

    let catalog = state
        .connection
        .as_deref()
        .and_then(|name| state.catalogs.get(name));
    state.suggestions = match catalog {
        Some(catalog) => complete::suggest(catalog, &state.word),
        None => Vec::new(),
    };
}

/// Run was pressed. Decides only whether a human is asked first.
fn run_requested(state: &mut State) -> Task<Message> {
    state.suggestions.clear();
    state.notice = None;

    let (Some(connection), Some(session)) = (state.connection.clone(), state.session.clone())
    else {
        state.notice = Some(Notice::error("pick a connection first"));
        return Task::none();
    };
    let sql = state.editor.text();
    if sql.trim().is_empty() {
        return Task::none();
    }
    if state.running.is_some() {
        state.notice = Some(Notice::info(
            "a query is already running; stop it or wait for it to finish",
        ));
        return Task::none();
    }

    let dialect = session
        .connections
        .iter()
        .find(|c| c.name == connection)
        .map(|c| c.dialect)
        .unwrap_or(quokka_core::Dialect::Sqlite);
    let mode = session
        .connections
        .iter()
        .find(|c| c.name == connection)
        .map(|c| c.mode)
        .unwrap_or(AccessMode::ReadOnly);

    // One parse, M3's, on text this function does not read again.
    let summary = summarize(&sql, dialect);

    match WriteConfirmation::for_statement(&summary) {
        // §7's confirmation — and only on a connection that could actually run it. On a
        // `read_only` connection there is nothing to confirm: the statement goes to
        // `execute()`, which refuses it, and the refusal is rendered inline in the words
        // the CLI and MCP already use (§6.3, deliverable 6). Asking "are you sure?"
        // before answering "you may not" would be theatre.
        Some(confirmation) if mode == AccessMode::ReadWrite => {
            state.pending = Some(Pending {
                connection,
                sql,
                confirmation,
            });
            Task::none()
        }
        _ => start(state, connection, sql, false),
    }
}

fn start(state: &mut State, connection: String, sql: String, write: bool) -> Task<Message> {
    let Some(session) = state.session.clone() else {
        return Task::none();
    };
    state.running = Some(Running {
        connection: connection.clone(),
        sql: sql.clone(),
        started: Instant::now(),
        cancelling: false,
    });
    state.now = Instant::now();
    Task::future(work::run(session, connection, sql, write)).map(|ran| Message::Ran(Box::new(ran)))
}

fn finished(state: &mut State, ran: Ran) -> Task<Message> {
    state.running = None;
    match ran {
        Ran::Loaded(loaded) => {
            let audit = loaded.connection == quokka_core::AUDIT_CONNECTION;
            let columns = Tab::columns_for(&loaded.page);
            let tab = Tab {
                query_id: loaded.query_id,
                connection: loaded.connection,
                sql: loaded.sql,
                spool: loaded.spool,
                outcome: loaded.outcome,
                view: View::arrival_order(),
                page: loaded.page,
                rows_in_view: loaded.rows_in_view,
                history: vec![Position::start()],
                at: 0,
                columns,
                resizing: None,
                selection: None,
                inspecting: None,
                filter: FilterDraft::default(),
                export: ExportDraft::default(),
                audit,
                header_id: Id::unique(),
                body_id: Id::unique(),
            };
            let id = tab.query_id;
            let evicted = state.slots.open(id);
            state.tabs.insert(id, tab);

            // §6.4's warning, rendered verbatim like a denial: the words are the policy
            // engine's, so the window, the CLI and MCP say the same thing. A person
            // watching a spend climb should read the same sentence wherever they are.
            if let Some(warning) = &state.tabs[&id].outcome.cost_warning {
                state.notice = Some(Notice {
                    kind: NoticeKind::Denied,
                    text: warning.clone(),
                    detail: Some(
                        "a warning, not a refusal \u{2014} this query ran. The threshold is \
                         `human_warn` under [cost_guard] in the config file."
                            .to_string(),
                    ),
                });
            }

            match evicted.and_then(|id| state.tabs.remove(&id)) {
                Some(old) => {
                    state.notice = Some(Notice::info(format!(
                        "closed the oldest result tab to make room. Its rows are gone \
                         \u{2014} getting them back means running that query again, which \
                         costs a second scan, so QuokkaQuery did not do it for you. \
                         ({} tabs is the limit.)",
                        crate::results::MAX_RESULT_TABS
                    )));
                    Task::future(release(old)).map(|()| Message::Tick)
                }
                None => Task::none(),
            }
        }
        Ran::Failed {
            connection,
            outcome,
        } => {
            let mut notice = Notice::error(
                outcome
                    .error_message
                    .clone()
                    .unwrap_or_else(|| format!("the query on {connection} did not finish")),
            );
            notice.detail = outcome.error_code.clone().map(|code| {
                let mut detail = format!(
                    "{code} \u{b7} recorded in the audit log as {}",
                    outcome.status
                );
                // A query that failed can still have been paid for. Saying so here is
                // the only place a person would find out before the invoice.
                if let Some(bytes) = outcome.data_scanned_bytes {
                    detail.push_str(&format!(
                        " \u{b7} {} scanned before it stopped",
                        quokka_spool::bytes_scanned(bytes)
                    ));
                }
                detail
            });
            state.notice = Some(notice);
            Task::none()
        }
        Ran::Denied {
            connection,
            code,
            message,
            query_id,
        } => {
            // Rendered verbatim (§6.3). The message already names the setting and where
            // to change it, in the same words the CLI and MCP use; composing another
            // here would make one refusal read three ways.
            state.notice = Some(Notice {
                kind: NoticeKind::Denied,
                text: message,
                detail: Some(format!(
                    "{code} \u{b7} {connection} \u{b7} logged as denied, query {query_id}"
                )),
            });
            Task::none()
        }
        Ran::Broken {
            connection,
            message,
        } => {
            state.notice = Some(Notice::error(format!("{connection}: {message}")));
            Task::none()
        }
    }
}

/// Go back to the first page under the current view, and read it.
fn restart_paging(state: &mut State) -> Task<Message> {
    if let Some(tab) = state.active_tab_mut() {
        tab.history = vec![Position::start()];
        tab.at = 0;
    }
    page(state, Step::First)
}

fn page(state: &mut State, step: Step) -> Task<Message> {
    let Some(tab) = state.active_tab_mut() else {
        return Task::none();
    };
    let at = match step {
        Step::First => {
            tab.at = 0;
            Position::start()
        }
        Step::Next => {
            let Some(next) = tab.page.next else {
                return Task::none();
            };
            tab.at += 1;
            if tab.history.len() <= tab.at {
                tab.history.push(next);
            } else {
                tab.history[tab.at] = next;
            }
            next
        }
        Step::Previous => {
            if tab.at == 0 {
                return Task::none();
            }
            tab.at -= 1;
            tab.history[tab.at]
        }
    };
    let (spool, view, id) = (tab.spool.clone(), tab.view.clone(), tab.query_id);
    Task::future(work::page(spool, view, at, id)).map(|r| Message::Paged(Box::new(r)))
}

fn export(state: &mut State) -> Task<Message> {
    let (Some(session), Some(tab)) = (state.session.clone(), state.active_tab()) else {
        return Task::none();
    };
    if tab.export.path.trim().is_empty() {
        state.notice = Some(Notice::error("name a file to export to"));
        return Task::none();
    }
    let (spool, view, outcome, sql, path, format) = (
        tab.spool.clone(),
        tab.view.clone(),
        tab.outcome.clone(),
        tab.sql.clone(),
        tab.export.path.trim().to_string(),
        tab.export.format,
    );
    Task::future(work::export(
        session, spool, view, outcome, sql, path, format,
    ))
    .map(|r| Message::Exported(Box::new(r)))
}

/// Close a tab's spool and delete its file.
async fn release(tab: Tab) {
    let path = tab.spool.path().to_path_buf();
    tab.spool.close().await;
    let _ = std::fs::remove_file(path);
}

/// The saved queries the audit tab opens with (§5).
///
/// Ordinary SQL against `@audit`, which is an ordinary connection: it goes through
/// `execute()`, it is capped and classified like anything else, and reading the log is
/// itself logged. That is the point of shipping the log as a connection rather than as a
/// second API.
fn audit_sql(view: AuditView) -> &'static str {
    match view {
        AuditView::Queries => {
            "SELECT started_at, status, actor_kind, actor_id, client, connection,\n\
             \x20      statement_kind, duration_ms, rows_returned, truncated, sql_fingerprint\n\
             FROM queries\n\
             ORDER BY started_at DESC\n\
             LIMIT 512"
        }
        AuditView::Events => {
            "SELECT at, event_kind, status, actor_kind, actor_id, client, connection,\n\
             \x20      statement_kind, duration_ms, rows_returned, sql_fingerprint\n\
             FROM audit_log\n\
             ORDER BY id DESC\n\
             LIMIT 512"
        }
        AuditView::Denials => {
            "SELECT at, actor_kind, actor_id, client, connection, statement_kind,\n\
             \x20      error_code, error_message, sql_fingerprint\n\
             FROM audit_log\n\
             WHERE status = 'denied'\n\
             ORDER BY id DESC\n\
             LIMIT 512"
        }
    }
}

/// Every filter operator, for the grid's filter row.
pub const FILTER_OPS: &[Op] = &[
    Op::Eq,
    Op::Ne,
    Op::Contains,
    Op::StartsWith,
    Op::Lt,
    Op::Le,
    Op::Gt,
    Op::Ge,
    Op::IsNull,
    Op::IsNotNull,
];

/// How an operator reads in a picker.
pub fn op_label(op: Op) -> &'static str {
    match op {
        Op::Eq => "=",
        Op::Ne => "≠",
        Op::Lt => "<",
        Op::Le => "≤",
        Op::Gt => ">",
        Op::Ge => "≥",
        Op::Contains => "contains",
        Op::StartsWith => "starts with",
        Op::IsNull => "is null",
        Op::IsNotNull => "is not null",
    }
}
