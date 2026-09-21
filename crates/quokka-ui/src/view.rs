//! Drawing the window. No decisions here that are not about pixels.
//!
//! Two things in this file are load-bearing rather than cosmetic, and both are §7:
//!
//! - **The mode is in two places at once** — beside every connection in the tree, and in
//!   the editor chrome above the statement being written. §6.3 says the cost of the
//!   guardrail binding humans is that you will hit it while sitting at a database
//!   client, and that the UI earns its keep by making the mode impossible to be
//!   surprised by. A setting you have to go and look for does not do that.
//! - **The note about a sort over a truncated spool sits beside the sort control**
//!   (§4.2). Not in a status bar: the confidently-wrong answer happens at the moment
//!   someone clicks a header, and that is where the sentence has to be.
//!
//! What is *not* here: any path from a click to a database except Run, Re-run and
//! Refresh catalog. Selecting a tab, sorting, filtering, paging, typing and opening the
//! inspector are all reads of memory or of a local file.

use iced::widget::{
    button, column, container, pick_list, responsive, row, rule, scrollable, space, text,
    text_editor, text_input,
};
use iced::{Center, Element, Fill, Length, Theme};
use quokka_core::AccessMode;
use quokka_spool::{Format, Op};

use crate::fonts;
use crate::grid;
use crate::message::{AuditView, Message, Step};
use crate::results::Tab;
use crate::state::{self, NoticeKind, State};
use crate::work::ConnectionRow;

pub use crate::grid::{default_column_width, MIN_COLUMN_WIDTH};

const SIDEBAR_WIDTH: f32 = 260.0;

pub fn view(state: &State) -> Element<'_, Message> {
    if let Some(broken) = &state.broken {
        return fatal(broken);
    }
    let Some(session) = state.session.as_ref() else {
        return container(
            text("opening the audit log…")
                .font(fonts::UI)
                .style(text::secondary),
        )
        .center(Fill)
        .into();
    };

    let body: Element<'_, Message> = row![
        sidebar(state, &session.connections),
        rule::vertical(1),
        workspace(state),
    ]
    .into();

    // The write confirmation is a layer over the window rather than a second window:
    // §7 wants it in front of the statement it is about.
    match state.pending.as_ref() {
        Some(pending) => iced::widget::stack![body, confirmation(pending)].into(),
        None => body,
    }
}

/// The window could not be built. Said plainly, with nothing pretending to work.
fn fatal(detail: &str) -> Element<'_, Message> {
    container(
        column![
            text("QuokkaQuery could not start").font(fonts::UI).size(18),
            text(detail.to_string()).font(fonts::UI).size(13),
            text(
                "Nothing has run. QuokkaQuery does not execute when it cannot record \
                 (invariant 6)."
            )
            .font(fonts::UI)
            .size(12)
            .style(text::secondary),
        ]
        .spacing(12)
        .max_width(560),
    )
    .center(Fill)
    .padding(24)
    .into()
}

// ---------------------------------------------------------------------------
// The connection tree
// ---------------------------------------------------------------------------

fn sidebar<'a>(state: &'a State, connections: &'a [ConnectionRow]) -> Element<'a, Message> {
    let mut list = column![].spacing(2);
    for connection in connections {
        let selected = state.connection.as_deref() == Some(connection.name.as_str());
        list = list.push(connection_entry(connection, selected));
    }

    let catalog = state
        .connection
        .as_deref()
        .and_then(|name| state.catalogs.get(name));

    let mut objects = column![].spacing(1);
    match catalog {
        Some(catalog) if !catalog.tables.is_empty() => {
            for table in &catalog.tables {
                let name = match &table.schema {
                    Some(schema) => format!("{schema}.{}", table.name),
                    None => table.name.clone(),
                };
                objects = objects.push(
                    column![
                        text(name).font(fonts::MONO).size(12),
                        text(format!(
                            "{} · {} column{}",
                            table.kind,
                            table.columns.len(),
                            if table.columns.len() == 1 { "" } else { "s" }
                        ))
                        .font(fonts::UI)
                        .size(10)
                        .style(text::secondary),
                    ]
                    .spacing(0)
                    .padding([2, 0]),
                );
            }
        }
        Some(_) => {
            objects = objects.push(
                text("no tables in this catalog")
                    .font(fonts::UI)
                    .size(11)
                    .style(text::secondary),
            );
        }
        None => {
            let message = match state.catalog_loading.is_some() {
                true => "reading the catalog…",
                false => "no catalog read yet",
            };
            objects = objects.push(
                text(message)
                    .font(fonts::UI)
                    .size(11)
                    .style(text::secondary),
            );
        }
    }

    let refresh = button(text("Refresh catalog").font(fonts::UI).size(11))
        .on_press_maybe(
            (state.connection.is_some() && state.catalog_loading.is_none())
                .then_some(Message::CatalogRefreshRequested),
        )
        .style(button::secondary);

    container(
        column![
            heading("Connections"),
            list,
            rule::horizontal(1),
            row![heading("Objects"), space().width(Fill), refresh].align_y(Center),
            scrollable(objects).height(Fill),
            rule::horizontal(1),
            heading("Audit"),
            // §5: the audit view is a saved query against `@audit`, run through
            // `execute()` like any other. These are the saved queries.
            audit_button("Queries", AuditView::Queries),
            audit_button("All events", AuditView::Events),
            audit_button("Denials", AuditView::Denials),
            text("reading the log is itself a logged query")
                .font(fonts::UI)
                .size(10)
                .style(text::secondary),
        ]
        .spacing(6)
        .padding(10),
    )
    .width(Length::Fixed(SIDEBAR_WIDTH))
    .height(Fill)
    .into()
}

fn connection_entry(connection: &ConnectionRow, selected: bool) -> Element<'_, Message> {
    let detail = text(format!(
        "{} · {}",
        connection.dialect.as_str(),
        connection.sql_logging.as_str()
    ))
    .font(fonts::UI)
    .size(10);
    // Inside the selected row the button supplies the contrast, and a secondary or
    // danger tint on top of it only makes the mode harder to read — which is the one
    // thing this line may not be (§7).
    let detail = if selected {
        detail
    } else {
        detail.style(text::secondary)
    };

    let label = column![
        text(connection.name.clone()).font(fonts::UI).size(13),
        row![mode_badge(connection.mode, selected), detail]
            .spacing(6)
            .align_y(Center),
    ]
    .spacing(1);

    button(label)
        .width(Fill)
        .padding([4, 6])
        .style(if selected {
            button::primary
        } else {
            button::text
        })
        .on_press(Message::ConnectionSelected(connection.name.clone()))
        .into()
}

/// read-only / read-write, in the tree — one of the two places §7 puts it.
///
/// `plain` drops the tint for a row that already has a background of its own; the words
/// stay, because the words are the point.
fn mode_badge<'a>(mode: AccessMode, plain: bool) -> Element<'a, Message> {
    let (label, style): (_, fn(&Theme) -> text::Style) = match mode {
        AccessMode::ReadOnly => ("read-only", text::secondary),
        AccessMode::ReadWrite => ("read-write", text::danger),
    };
    let badge = text(label).font(fonts::UI).size(10);
    if plain {
        badge.into()
    } else {
        badge.style(style).into()
    }
}

fn audit_button<'a>(label: &'a str, view: AuditView) -> Element<'a, Message> {
    button(text(label).font(fonts::UI).size(11))
        .width(Fill)
        .padding([3, 6])
        .style(button::secondary)
        .on_press(Message::AuditRequested(view))
        .into()
}

fn heading<'a>(label: &'a str) -> Element<'a, Message> {
    text(label)
        .font(fonts::UI)
        .size(11)
        .style(text::secondary)
        .into()
}

// ---------------------------------------------------------------------------
// The editor and everything under it
// ---------------------------------------------------------------------------

fn workspace(state: &State) -> Element<'_, Message> {
    column![
        chrome(state),
        editor(state),
        completions(state),
        notice(state),
        rule::horizontal(1),
        results(state),
    ]
    .spacing(6)
    .padding(10)
    .width(Fill)
    .height(Fill)
    .into()
}

/// The strip above the editor. The mode lives here permanently (§7).
fn chrome(state: &State) -> Element<'_, Message> {
    let selected = state.selected();
    let target: Element<'_, Message> = match selected {
        Some(connection) => row![
            text(connection.name.clone()).font(fonts::UI).size(13),
            mode_badge(connection.mode, false),
            text(format!(
                "{} · sql_logging={}",
                connection.target, connection.sql_logging
            ))
            .font(fonts::UI)
            .size(10)
            .style(text::secondary),
        ]
        .spacing(8)
        .align_y(Center)
        .into(),
        None => text("no connection selected")
            .font(fonts::UI)
            .size(12)
            .style(text::secondary)
            .into(),
    };

    // Run is disabled only for having nothing to run, or for already running something
    // — never because of the connection's mode. A greyed-out Run would be a second
    // policy, and the real one lives in `execute()` (§6.3).
    let run = button(text("Run").font(fonts::UI).size(12))
        .on_press_maybe(state.can_run().then_some(Message::RunRequested))
        .style(button::primary);

    let running: Element<'_, Message> = match state.running.as_ref() {
        Some(running) => {
            let elapsed = state.now.saturating_duration_since(running.started);
            let label = if running.cancelling {
                format!("stopping… {}", seconds(elapsed))
            } else {
                format!("running {} on {}", seconds(elapsed), running.connection)
            };
            row![
                text(label).font(fonts::UI).size(12),
                button(text("Stop").font(fonts::UI).size(12))
                    .style(button::danger)
                    .on_press_maybe((!running.cancelling).then_some(Message::CancelRequested)),
                // Said out loud, because it is less than it sounds: sqlx exposes no way
                // to reach the running statement on a pooled connection, so this stops
                // the read rather than the server.
                text("stops reading; the server may still be finishing")
                    .font(fonts::UI)
                    .size(10)
                    .style(text::secondary),
            ]
            .spacing(8)
            .align_y(Center)
            .into()
        }
        None => space().into(),
    };

    row![target, space().width(Fill), running, run]
        .spacing(10)
        .align_y(Center)
        .into()
}

fn seconds(elapsed: std::time::Duration) -> String {
    let secs = elapsed.as_secs_f32();
    if secs < 10.0 {
        format!("{secs:.1}s")
    } else {
        format!("{:.0}s", secs)
    }
}

fn editor(state: &State) -> Element<'_, Message> {
    let highlight = if state.theme.extended_palette().is_dark {
        iced::highlighter::Theme::Base16Mocha
    } else {
        iced::highlighter::Theme::InspiredGitHub
    };

    container(
        text_editor(&state.editor)
            .font(fonts::MONO)
            .size(13)
            .height(Length::Fixed(160.0))
            .placeholder("SELECT …")
            .highlight("sql", highlight)
            .on_action(Message::Edit)
            // Ctrl/Cmd+Enter runs, which is what every query tool does, and Escape
            // dismisses the completion overlay.
            .key_binding(|press| {
                use iced::keyboard::{key, Key};
                match press.key.as_ref() {
                    Key::Named(key::Named::Enter) if press.modifiers.command() => {
                        Some(text_editor::Binding::Custom(Message::RunRequested))
                    }
                    Key::Named(key::Named::Escape) => {
                        Some(text_editor::Binding::Custom(Message::CompletionsDismissed))
                    }
                    _ => text_editor::Binding::from_key_press(press),
                }
            }),
    )
    .into()
}

/// The completion overlay. Reads a catalog in memory; reaches nothing (§1.4).
fn completions(state: &State) -> Element<'_, Message> {
    if state.suggestions.is_empty() {
        return space().height(0).into();
    }
    let mut items = row![].spacing(4);
    for (index, candidate) in state.suggestions.iter().enumerate() {
        items = items.push(
            button(
                row![
                    text(candidate.text.clone()).font(fonts::MONO).size(11),
                    text(candidate.detail.clone())
                        .font(fonts::UI)
                        .size(9)
                        .style(text::secondary),
                ]
                .spacing(4)
                .align_y(Center),
            )
            .padding([2, 6])
            .style(button::secondary)
            .on_press(Message::CompletionAccepted(index)),
        );
    }
    scrollable(items)
        .direction(scrollable::Direction::Horizontal(
            scrollable::Scrollbar::new().width(4).scroller_width(4),
        ))
        .into()
}

/// The inline strip where a refusal appears (§7, deliverable 6).
fn notice(state: &State) -> Element<'_, Message> {
    let Some(notice) = state.notice.as_ref() else {
        return space().height(0).into();
    };
    let style: fn(&Theme) -> text::Style = match notice.kind {
        NoticeKind::Info => text::secondary,
        NoticeKind::Denied => text::warning,
        NoticeKind::Error => text::danger,
    };
    let mut body = column![text(notice.text.clone())
        .font(fonts::UI)
        .size(12)
        .style(style)];
    if let Some(detail) = &notice.detail {
        body = body.push(
            text(detail.clone())
                .font(fonts::UI)
                .size(10)
                .style(text::secondary),
        );
    }

    container(
        row![
            body.spacing(2).width(Fill),
            button(text("dismiss").font(fonts::UI).size(10))
                .style(button::text)
                .on_press(Message::NoticeDismissed),
        ]
        .align_y(Center),
    )
    .padding(6)
    .width(Fill)
    .style(container::bordered_box)
    .into()
}

// ---------------------------------------------------------------------------
// Result tabs
// ---------------------------------------------------------------------------

fn results(state: &State) -> Element<'_, Message> {
    if state.slots.is_empty() {
        return container(
            text("no results yet — write a statement and press Run")
                .font(fonts::UI)
                .size(12)
                .style(text::secondary),
        )
        .center(Fill)
        .into();
    }

    let mut bar = row![].spacing(4);
    for id in state.slots.ids() {
        let Some(tab) = state.tabs.get(id) else {
            continue;
        };
        let active = state.slots.active() == Some(*id);
        bar = bar.push(
            row![
                button(text(tab.title()).font(fonts::UI).size(11))
                    .padding([3, 6])
                    .style(if active {
                        button::primary
                    } else {
                        button::secondary
                    })
                    .on_press(Message::TabSelected(*id)),
                button(text("×").font(fonts::UI).size(11))
                    .padding([3, 5])
                    .style(button::text)
                    .on_press(Message::TabClosed(*id)),
            ]
            .spacing(0),
        );
    }

    let Some(tab) = state.active_tab() else {
        return scrollable(bar).into();
    };

    column![
        scrollable(bar).direction(scrollable::Direction::Horizontal(
            scrollable::Scrollbar::new().width(3).scroller_width(3)
        )),
        pager(state, tab),
        controls(tab),
        grid_of(tab),
        inspector(tab),
    ]
    .spacing(6)
    .height(Fill)
    .into()
}

/// §7's pager, in as many words: `rows 1–512 of 12,481 · as of 10:00 (45m ago) ·
/// [Next] [Re-run] [Export all]`.
fn pager<'a>(state: &'a State, tab: &'a Tab) -> Element<'a, Message> {
    let stale_after = state.session.as_ref().and_then(|s| s.spool.stale_after);
    let pager = crate::work::pager(&tab.page, tab.rows_in_view, &tab.spool, stale_after);

    let line = text(pager.line())
        .font(fonts::UI)
        .size(12)
        .style(if pager.stale {
            text::warning
        } else {
            text::default
        });

    let prev = button(text("Prev").font(fonts::UI).size(11))
        .style(button::secondary)
        .on_press_maybe(
            pager
                .has_previous
                .then_some(Message::PageRequested(Step::Previous)),
        );
    let next = button(text("Next").font(fonts::UI).size(11))
        .style(button::secondary)
        .on_press_maybe(pager.has_next.then_some(Message::PageRequested(Step::Next)));
    // The only button on this line that costs a second execution, and the only one that
    // could (§1.4). Nothing on screen re-runs itself.
    let rerun = button(text("Re-run").font(fonts::UI).size(11))
        .style(button::secondary)
        .on_press_maybe(state.running.is_none().then_some(Message::RerunRequested));

    let export = row![
        text_input("export to…", &tab.export.path)
            .font(fonts::MONO)
            .size(11)
            .width(Length::Fixed(220.0))
            .on_input(Message::ExportPathChanged),
        pick_list(export_formats(), Some(tab.export.format), |format| {
            Message::ExportFormatChanged(format)
        })
        .font(fonts::UI)
        .text_size(11),
        button(text("Export all").font(fonts::UI).size(11))
            .style(button::primary)
            .on_press(Message::ExportRequested),
    ]
    .spacing(4)
    .align_y(Center);

    column![
        row![line, space().width(Fill), prev, next, rerun]
            .spacing(6)
            .align_y(Center),
        export,
    ]
    .spacing(4)
    .into()
}

fn export_formats() -> Vec<Format> {
    Format::names()
        .iter()
        .filter_map(|name| Format::parse(name))
        .collect()
}

/// Sort and filter, with §4.2's sentence right beside them.
fn controls(tab: &Tab) -> Element<'_, Message> {
    let columns: Vec<ColumnChoice> = tab
        .page
        .columns
        .iter()
        .enumerate()
        .map(|(index, c)| ColumnChoice {
            index,
            name: c.name.clone(),
        })
        .collect();
    let selected = tab
        .filter
        .column
        .and_then(|index| columns.get(index).cloned());
    let op = tab.filter.op.map(OpChoice);
    let needs_value = !matches!(tab.filter.op, Some(Op::IsNull) | Some(Op::IsNotNull));

    let filter = row![
        text("filter")
            .font(fonts::UI)
            .size(11)
            .style(text::secondary),
        pick_list(columns, selected, |choice| Message::FilterColumnSelected(
            choice.index
        ))
        .placeholder("column")
        .font(fonts::UI)
        .text_size(11),
        pick_list(OP_CHOICES.to_vec(), op, |choice| {
            Message::FilterOpSelected(choice.0)
        })
        .placeholder("op")
        .font(fonts::UI)
        .text_size(11),
        text_input("value", &tab.filter.value)
            .font(fonts::MONO)
            .size(11)
            .width(Length::Fixed(160.0))
            .on_input_maybe(needs_value.then_some(Message::FilterValueChanged)),
        button(text("Apply").font(fonts::UI).size(11))
            .style(button::secondary)
            .on_press(Message::FilterApplied),
        button(text("Clear").font(fonts::UI).size(11))
            .style(button::text)
            .on_press(Message::FilterCleared),
        space().width(Fill),
        button(text("Copy selection as TSV").font(fonts::UI).size(11))
            .style(button::secondary)
            .on_press_maybe(tab.selection.map(|_| Message::SelectionCopied)),
    ]
    .spacing(4)
    .align_y(Center);

    // §4.2's trap: sorting a spool that holds the first million of twelve million rows
    // orders the prefix, not the result — a confidently wrong answer. The sentence
    // belongs where the sort and filter controls are, not in a status bar nobody reads.
    match tab.spool.scoping().note() {
        Some(note) => column![
            filter,
            text(note)
                .font(fonts::UI)
                .size(11)
                .style(text::warning)
                .width(Fill),
        ]
        .spacing(4)
        .into(),
        None => filter.into(),
    }
}

fn grid_of(tab: &Tab) -> Element<'_, Message> {
    if tab.page.columns.is_empty() {
        let affected = match tab.outcome.rows_affected {
            Some(n) => format!("{n} row{} affected", if n == 1 { "" } else { "s" }),
            None => "the statement returned no columns".to_string(),
        };
        return container(text(affected).font(fonts::UI).size(12))
            .center_x(Fill)
            .padding(20)
            .into();
    }

    // The columns live on the tab, not here: `iced_table` borrows them, and a dragged
    // width is state rather than something to recompute per frame.
    responsive(move |size| {
        iced_table::table(
            tab.header_id.clone(),
            tab.body_id.clone(),
            &tab.columns,
            &tab.page.rows,
            Message::HeaderSynced,
        )
        .on_column_resize(Message::ColumnResizing, Message::ColumnResized)
        .min_width(size.width)
        .into()
    })
    .into()
}

/// The cell inspector §7 asks for: long text, JSON and BLOBs, which is where a
/// fixed-height grid actually hurts.
fn inspector(tab: &Tab) -> Element<'_, Message> {
    let Some((row_index, column_index)) = tab.inspecting else {
        return space().height(0).into();
    };
    let Some(value) = tab
        .page
        .rows
        .get(row_index)
        .and_then(|row| row.0.get(column_index))
    else {
        return space().height(0).into();
    };
    let name = tab
        .page
        .columns
        .get(column_index)
        .map(|c| format!("{} · {}", c.name, c.driver_type))
        .unwrap_or_default();

    container(
        column![
            row![
                text(name).font(fonts::UI).size(11).style(text::secondary),
                space().width(Fill),
                button(text("close").font(fonts::UI).size(10))
                    .style(button::text)
                    .on_press(Message::InspectorClosed),
            ]
            .align_y(Center),
            scrollable(
                text(grid::inspect_text(value))
                    .font(fonts::MONO)
                    .size(12)
                    .width(Fill)
            )
            .height(Length::Fixed(120.0)),
        ]
        .spacing(4),
    )
    .padding(6)
    .width(Fill)
    .style(container::bordered_box)
    .into()
}

// ---------------------------------------------------------------------------
// The write confirmation (§7)
// ---------------------------------------------------------------------------

/// Names the statement kind and the target table, and flags an unfiltered write
/// specifically — every word of it a rendering of
/// [`WriteConfirmation`](quokka_core::WriteConfirmation), which is where the wording is
/// tested.
///
/// **It is not the guardrail.** Declining does not make the statement safe and
/// confirming does not make it allowed: `execute()` still checks the connection's mode.
fn confirmation(pending: &state::Pending) -> Element<'_, Message> {
    let mut body = column![
        text(pending.confirmation.headline())
            .font(fonts::UI)
            .size(15),
        text(format!("on {}", pending.connection))
            .font(fonts::UI)
            .size(11)
            .style(text::secondary),
    ]
    .spacing(4);

    for warning in pending.confirmation.warnings() {
        body = body.push(text(warning).font(fonts::UI).size(12).style(text::danger));
    }

    body = body.push(
        container(
            scrollable(
                text(pending.sql.clone())
                    .font(fonts::MONO)
                    .size(12)
                    .width(Fill),
            )
            .height(Length::Fixed(120.0)),
        )
        .padding(6)
        .style(container::bordered_box),
    );

    body = body.push(
        row![
            space().width(Fill),
            button(text("Cancel").font(fonts::UI).size(12))
                .style(button::secondary)
                .on_press(Message::WriteDeclined),
            button(text("Run it").font(fonts::UI).size(12))
                .style(button::danger)
                .on_press(Message::WriteConfirmed),
        ]
        .spacing(8),
    );

    container(
        container(body.spacing(10))
            .max_width(660)
            .padding(18)
            .style(container::bordered_box),
    )
    .center(Fill)
    .style(|theme: &Theme| container::Style {
        background: Some(
            iced::Color {
                a: 0.7,
                ..theme.extended_palette().background.base.color
            }
            .into(),
        ),
        ..container::Style::default()
    })
    .into()
}

// ---------------------------------------------------------------------------
// Pick-list wrappers
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, PartialEq, Eq)]
struct ColumnChoice {
    index: usize,
    name: String,
}

impl std::fmt::Display for ColumnChoice {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.name)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct OpChoice(Op);

impl std::fmt::Display for OpChoice {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(state::op_label(self.0))
    }
}

const OP_CHOICES: &[OpChoice] = &[
    OpChoice(Op::Eq),
    OpChoice(Op::Ne),
    OpChoice(Op::Contains),
    OpChoice(Op::StartsWith),
    OpChoice(Op::Lt),
    OpChoice(Op::Le),
    OpChoice(Op::Gt),
    OpChoice(Op::Ge),
    OpChoice(Op::IsNull),
    OpChoice(Op::IsNotNull),
];
