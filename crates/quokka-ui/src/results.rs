//! Result tabs: how many there are, which one is showing, and what closing one does.
//!
//! ## How many spools stay open, and why the answer differs from M3's
//!
//! `quokka mcp` holds thirty-two results and releases the oldest when a thirty-third
//! arrives. It has to guess, because an agent never says it is finished with a result:
//! the only signal available is age.
//!
//! A window has a better signal — the user closes a tab — so this is a different
//! problem, and it gets three rules rather than one:
//!
//! 1. **Closing a tab closes its spool and deletes the file, immediately.** The user
//!    said they were done. §4.1 keeps nothing longer than it must, and a file left for
//!    the exit sweep is a file sitting on someone's disk for the rest of the session.
//! 2. **Every open tab keeps its spool open.** No eviction behind the user's back: a tab
//!    whose rows silently vanished is a tab that lies, and the grid would have nothing
//!    to draw the next time it was selected. What the MCP server can do quietly to an
//!    agent, a window may not do to a person watching it.
//! 3. **So the number of tabs is what is bounded**, at [`MAX_RESULT_TABS`], and running
//!    a query when the last slot is full closes the least recently *viewed* tab and says
//!    so out loud. Smaller than M3's thirty-two because each of these is a thing on
//!    screen — sixteen tabs is already more than anyone can read — and because a window
//!    keeping a gigabyte of spool per tab is a real cost on a real laptop.
//!
//! Losing a result is never silent, here or at M3: getting the rows back means running
//! the query again, which costs a second scan and therefore never happens by itself
//! (§1.4).

use std::collections::HashMap;

use quokka_core::Outcome;
use quokka_spool::{Direction, Format, Page, Position, Spool, View};

use crate::grid::{default_column_width, GridColumn};
use uuid::Uuid;

/// How many result tabs a window keeps. See the module docs for why it is not
/// thirty-two.
pub const MAX_RESULT_TABS: usize = 16;

/// Which tabs exist, in what order, and which is on screen.
///
/// Deliberately knows nothing about spools, grids or iced: it is the bookkeeping, so it
/// can be tested without a database, a window or a file.
#[derive(Debug, Default, Clone)]
pub struct Slots {
    /// Tab order, left to right: the order they were opened in.
    ids: Vec<Uuid>,
    /// Least recently viewed first. What decides who makes room.
    seen: Vec<Uuid>,
    active: Option<Uuid>,
}

impl Slots {
    pub fn new() -> Self {
        Slots::default()
    }

    pub fn ids(&self) -> &[Uuid] {
        &self.ids
    }

    pub fn active(&self) -> Option<Uuid> {
        self.active
    }

    pub fn is_empty(&self) -> bool {
        self.ids.is_empty()
    }

    pub fn position_of(&self, id: Uuid) -> Option<usize> {
        self.ids.iter().position(|i| *i == id)
    }

    /// Open a tab and show it. Returns the tab that had to be closed to make room, if
    /// any — the caller closes its spool and tells the user.
    #[must_use = "the tab this pushed out owns an open spool; close it and say so"]
    pub fn open(&mut self, id: Uuid) -> Option<Uuid> {
        let evicted = (self.ids.len() >= MAX_RESULT_TABS)
            .then(|| self.seen.first().copied())
            .flatten()
            .filter(|oldest| *oldest != id);
        if let Some(oldest) = evicted {
            self.forget(oldest);
        }
        if !self.ids.contains(&id) {
            self.ids.push(id);
        }
        self.select(id);
        evicted
    }

    /// Mark a tab as the one being looked at.
    pub fn select(&mut self, id: Uuid) {
        if !self.ids.contains(&id) {
            return;
        }
        self.seen.retain(|i| *i != id);
        self.seen.push(id);
        self.active = Some(id);
    }

    /// Close a tab. Returns the tab to show instead, or `None` when that was the last.
    ///
    /// The next tab is the one to the right, then the one to the left — what every
    /// tabbed thing does, and the only choice that does not make closing feel like a
    /// jump to somewhere unrelated.
    pub fn close(&mut self, id: Uuid) -> Option<Uuid> {
        let Some(index) = self.position_of(id) else {
            return self.active;
        };
        let was_active = self.active == Some(id);
        self.forget(id);
        if !was_active {
            return self.active;
        }
        let next = self
            .ids
            .get(index)
            .or_else(|| index.checked_sub(1).and_then(|i| self.ids.get(i)))
            .copied();
        match next {
            Some(next) => {
                self.select(next);
                Some(next)
            }
            None => {
                self.active = None;
                None
            }
        }
    }

    fn forget(&mut self, id: Uuid) {
        self.ids.retain(|i| *i != id);
        self.seen.retain(|i| *i != id);
        if self.active == Some(id) {
            self.active = None;
        }
    }
}

/// What the user is drawing in a grid's filter row before they apply it.
///
/// A draft rather than a [`quokka_spool::Filter`] because a half-typed filter is not a
/// filter: nothing is read until Apply, which is also what keeps a keystroke from
/// costing a query. (It could not cost one anyway — a filter is a read of the spool —
/// but a re-read per keystroke is still work nobody asked for.)
#[derive(Debug, Clone, Default)]
pub struct FilterDraft {
    pub column: Option<usize>,
    pub op: Option<quokka_spool::Op>,
    pub value: String,
}

/// Where an export is going, before it goes there.
#[derive(Debug, Clone)]
pub struct ExportDraft {
    pub path: String,
    pub format: Format,
}

impl Default for ExportDraft {
    fn default() -> Self {
        ExportDraft {
            path: String::new(),
            format: Format::Csv,
        }
    }
}

/// A rectangle of cells, for copy-as-TSV (§7).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Selection {
    pub anchor: (usize, usize),
    pub focus: (usize, usize),
}

impl Selection {
    pub fn cell(row: usize, column: usize) -> Self {
        Selection {
            anchor: (row, column),
            focus: (row, column),
        }
    }

    pub fn rows(&self) -> std::ops::RangeInclusive<usize> {
        self.anchor.0.min(self.focus.0)..=self.anchor.0.max(self.focus.0)
    }

    pub fn columns(&self) -> std::ops::RangeInclusive<usize> {
        self.anchor.1.min(self.focus.1)..=self.anchor.1.max(self.focus.1)
    }

    pub fn contains(&self, row: usize, column: usize) -> bool {
        self.rows().contains(&row) && self.columns().contains(&column)
    }
}

/// One result, open for reading.
pub struct Tab {
    pub query_id: Uuid,
    pub connection: String,
    /// The statement that produced these rows. Kept for `[Re-run]` and for the export
    /// event's fingerprint — never shown in the log by this crate.
    pub sql: String,
    pub spool: Spool,
    pub outcome: Outcome,
    pub view: View,
    pub page: Page,
    pub rows_in_view: u64,
    /// Where each page visited so far began, so `[Prev]` is a read of the spool rather
    /// than arithmetic on an offset that only means something in one ordering.
    pub history: Vec<Position>,
    pub at: usize,
    /// The grid's columns, held here rather than rebuilt per frame because `iced_table`
    /// borrows them — and because a dragged width is state, not a derivation.
    pub columns: Vec<GridColumn>,
    pub resizing: Option<(usize, f32)>,
    pub selection: Option<Selection>,
    pub inspecting: Option<(usize, usize)>,
    pub filter: FilterDraft,
    pub export: ExportDraft,
    /// Whether this tab is the audit view (§5): a result tab over a query on `@audit`,
    /// which is what the audit view *is*.
    pub audit: bool,
    /// The grid's two scrollables. `iced_table` keeps the header and the body in step
    /// by scrolling one when the other moves, which needs a name for each.
    pub header_id: iced::widget::Id,
    pub body_id: iced::widget::Id,
}

impl Tab {
    /// The grid columns for a freshly opened result.
    pub fn columns_for(page: &Page) -> Vec<GridColumn> {
        page.columns
            .iter()
            .enumerate()
            .map(|(index, column)| GridColumn {
                index,
                width: default_column_width(&column.name),
                column: column.clone(),
                resize_offset: None,
                sort: None,
                selection: None,
            })
            .collect()
    }

    /// Push the tab's current sort, selection and drag into the columns the grid draws.
    ///
    /// The columns are what `iced_table` reads, and they are owned rather than derived
    /// per frame, so anything that changes what a cell looks like has to reach them.
    pub fn sync(&mut self) {
        let sort: Option<(usize, Direction)> = self
            .view
            .sort
            .first()
            .map(|key| (key.column, key.direction));
        for column in &mut self.columns {
            column.sort = sort
                .filter(|(index, _)| *index == column.index)
                .map(|(_, d)| d);
            column.selection = self.selection;
            column.resize_offset = self
                .resizing
                .and_then(|(index, offset)| (index == column.index).then_some(offset));
        }
    }

    /// Apply a finished drag to the column's stored width.
    pub fn finish_resize(&mut self) {
        if let Some((index, offset)) = self.resizing.take() {
            if let Some(column) = self.columns.iter_mut().find(|c| c.index == index) {
                column.width = (column.width + offset).max(crate::grid::MIN_COLUMN_WIDTH);
            }
        }
        self.sync();
    }

    pub fn title(&self) -> String {
        if self.audit {
            return "audit".to_string();
        }
        let kind = if self.outcome.columns.is_empty() {
            "statement"
        } else {
            "rows"
        };
        format!("{} · {kind}", self.connection)
    }

    /// The rows of the current selection, as TSV with a header for the columns it
    /// covers. `None` when nothing is selected.
    ///
    /// Tabs and newlines inside a value are escaped rather than emitted, because a
    /// clipboard payload whose rows do not line up is worse than one that is slightly
    /// unfaithful — and a spreadsheet would read the raw form as extra cells.
    pub fn selection_as_tsv(&self) -> Option<String> {
        let selection = self.selection?;
        let columns: Vec<usize> = selection
            .columns()
            .filter(|c| *c < self.page.columns.len())
            .collect();
        if columns.is_empty() {
            return None;
        }

        let mut out = String::new();
        let header: Vec<&str> = columns
            .iter()
            .map(|c| self.page.columns[*c].name.as_str())
            .collect();
        out.push_str(&header.join("\t"));
        for row in selection.rows() {
            let Some(row) = self.page.rows.get(row) else {
                continue;
            };
            out.push('\n');
            let cells: Vec<String> = columns
                .iter()
                .map(|c| row.0.get(*c).map(escape_cell).unwrap_or_default())
                .collect();
            out.push_str(&cells.join("\t"));
        }
        Some(out)
    }
}

/// A value as one TSV cell: its display form with the delimiters spelled out.
fn escape_cell(value: &quokka_core::Value) -> String {
    value
        .to_string()
        .replace('\\', "\\\\")
        .replace('\t', "\\t")
        .replace('\r', "\\r")
        .replace('\n', "\\n")
}

/// Every open result, by id.
pub type Open = HashMap<Uuid, Tab>;

#[cfg(test)]
mod tests {
    use super::*;

    fn ids(n: usize) -> Vec<Uuid> {
        (0..n).map(|_| Uuid::now_v7()).collect()
    }

    #[test]
    fn opening_a_tab_shows_it() {
        let mut slots = Slots::new();
        let id = Uuid::now_v7();
        assert_eq!(slots.open(id), None);
        assert_eq!(slots.active(), Some(id));
        assert_eq!(slots.ids(), &[id]);
    }

    #[test]
    fn nothing_is_evicted_until_the_last_slot_is_full() {
        let mut slots = Slots::new();
        let ids = ids(MAX_RESULT_TABS);
        for id in &ids {
            assert_eq!(slots.open(*id), None, "there was still room");
        }
        assert_eq!(slots.ids().len(), MAX_RESULT_TABS);

        let one_more = Uuid::now_v7();
        assert_eq!(
            slots.open(one_more),
            Some(ids[0]),
            "the least recently viewed tab makes room, and the caller is told which"
        );
        assert_eq!(slots.ids().len(), MAX_RESULT_TABS);
        assert!(!slots.ids().contains(&ids[0]));
    }

    #[test]
    fn the_tab_that_makes_room_is_the_one_nobody_has_looked_at() {
        let mut slots = Slots::new();
        let ids = ids(MAX_RESULT_TABS);
        for id in &ids {
            let _ = slots.open(*id);
        }
        // Look at the oldest tab again: it is no longer the one to lose.
        slots.select(ids[0]);
        assert_eq!(slots.open(Uuid::now_v7()), Some(ids[1]));
        assert!(slots.ids().contains(&ids[0]));
    }

    #[test]
    fn closing_the_active_tab_shows_its_neighbour() {
        let mut slots = Slots::new();
        let ids = ids(3);
        for id in &ids {
            let _ = slots.open(*id);
        }
        slots.select(ids[1]);
        assert_eq!(slots.close(ids[1]), Some(ids[2]), "the one to the right");

        slots.select(ids[2]);
        assert_eq!(
            slots.close(ids[2]),
            Some(ids[0]),
            "then the one to the left"
        );
        assert_eq!(slots.close(ids[0]), None, "and then there were none");
        assert!(slots.is_empty());
    }

    #[test]
    fn closing_a_tab_in_the_background_leaves_the_view_alone() {
        let mut slots = Slots::new();
        let ids = ids(3);
        for id in &ids {
            let _ = slots.open(*id);
        }
        slots.select(ids[2]);
        assert_eq!(slots.close(ids[0]), Some(ids[2]));
        assert_eq!(slots.active(), Some(ids[2]));
    }

    #[test]
    fn a_selection_covers_the_rectangle_between_its_corners() {
        let mut selection = Selection::cell(4, 2);
        selection.focus = (1, 5);
        assert_eq!(selection.rows().collect::<Vec<_>>(), vec![1, 2, 3, 4]);
        assert_eq!(selection.columns().collect::<Vec<_>>(), vec![2, 3, 4, 5]);
        assert!(selection.contains(2, 3));
        assert!(!selection.contains(0, 3));
    }

    #[test]
    fn a_tab_and_a_newline_in_a_value_do_not_become_extra_cells() {
        let value = quokka_core::Value::Text("a\tb\nc".to_string());
        assert_eq!(escape_cell(&value), "a\\tb\\nc");
    }
}
