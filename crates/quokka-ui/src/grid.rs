//! The result grid: one page, 512 rows, and no virtualization (§1.3, §4.2).
//!
//! **The widget this deliberately is not.** §1.3 says the 512-row ceiling "deletes the
//! single hardest widget in the project", and the way to keep that true is to build the
//! naive thing: every row on this page becomes an element, every time. At 512 rows that
//! is fine. At a million it would be catastrophic — which is the point. A grid that
//! coped with a million rows would invite someone to put a million rows in it, and the
//! ceiling would quietly become a default.
//!
//! **Why `iced_table` and not the built-in one.** iced 0.14 ships `iced::widget::table`,
//! and it is a better fit for everything except the one thing §7 asks for by name:
//! column resize. Its columns take a fixed `Length` and there is no divider to drag. The
//! trade-off §7 leaves open bites exactly there — resize means a custom widget with
//! pointer capture, a hover region and a live offset, which is a real widget however
//! small the grid is. `iced_table` is that widget (MIT, ~1k lines, pinned to iced 0.14)
//! plus the header/body scroll sync it needs, and it does not virtualize, so it makes
//! the paragraph above true rather than working around it.

use iced::widget::{container, mouse_area, row, text, tooltip};
use iced::{Element, Length, Theme};
use quokka_core::{Column, Row, Value};
use quokka_spool::Direction;

use crate::fonts;
use crate::message::Message;
use crate::results::Selection;

/// How narrow a column may be dragged.
pub const MIN_COLUMN_WIDTH: f32 = 48.0;

/// How wide a column starts, from its name alone.
///
/// The values decide nothing here: measuring them would mean walking the page before
/// laying it out, and the user can drag. What the name buys is that a column called
/// `id` does not start as wide as one called `shipping_address_line_2`.
pub fn default_column_width(name: &str) -> f32 {
    let by_name = 24.0 + name.chars().count() as f32 * 8.0;
    by_name.clamp(96.0, 280.0)
}

/// Longer than this and a cell shows a prefix; the inspector shows the rest (§7).
const CELL_CHARS: usize = 120;

/// One column of the grid, as `iced_table` wants it.
pub struct GridColumn {
    pub index: usize,
    pub column: Column,
    pub width: f32,
    pub resize_offset: Option<f32>,
    pub sort: Option<Direction>,
    pub selection: Option<Selection>,
}

impl<'a> iced_table::table::Column<'a, Message, Theme, iced::Renderer> for GridColumn {
    type Row = Row;

    fn header(&'a self, _col_index: usize) -> Element<'a, Message> {
        let arrow = match self.sort {
            Some(Direction::Asc) => " ▲",
            Some(Direction::Desc) => " ▼",
            None => "",
        };
        let label = text(format!("{}{arrow}", self.column.name))
            .font(fonts::UI)
            .size(12);
        let kind = text(self.column.driver_type.clone())
            .font(fonts::UI)
            .size(10)
            .style(text::secondary);

        // Clicking a header sorts — a read of the spool, never a re-run (§4). The note
        // that says what a sort over a truncated spool means lives beside the control,
        // in `view.rs`, rather than in a status bar nobody reads (§4.2).
        mouse_area(
            container(iced::widget::column![label, kind].spacing(1))
                .width(Length::Fill)
                .padding([2, 0]),
        )
        .on_press(Message::SortRequested(self.index))
        .into()
    }

    fn cell(&'a self, _col_index: usize, row_index: usize, row: &'a Row) -> Element<'a, Message> {
        let value = row.0.get(self.index);
        let (body, is_null) = cell_text(value);
        let selected = self
            .selection
            .map(|s| s.contains(row_index, self.index))
            .unwrap_or(false);

        let label = text(body).font(fonts::MONO).size(12);
        let label = if is_null {
            label.style(text::secondary)
        } else {
            label
        };

        let cell = container(label)
            .width(Length::Fill)
            .style(move |theme: &Theme| {
                if selected {
                    let palette = theme.extended_palette();
                    container::Style {
                        background: Some(palette.primary.weak.color.into()),
                        text_color: Some(palette.primary.weak.text),
                        ..container::Style::default()
                    }
                } else {
                    container::Style::default()
                }
            });

        mouse_area(cell)
            .on_press(Message::CellPressed(row_index, self.index))
            .into()
    }

    fn width(&self) -> f32 {
        self.width
    }

    fn resize_offset(&self) -> Option<f32> {
        self.resize_offset
    }
}

/// What one cell shows, and whether it is a NULL.
///
/// Three rules, all of them about not lying:
///
/// - **`NULL` is a word, not an empty cell.** An empty string and an absent value are
///   different facts about a database and must not look the same.
/// - **A long value is cut and marked**, because a cell that silently shows the first
///   line of a JSON document reads like the whole document. The inspector has the rest.
/// - **A blob is its length and a hex prefix.** Invariant 10's neighbour: an
///   unrecognized type renders as text rather than aborting the result set, and bytes
///   render as bytes rather than as mojibake.
pub fn cell_text(value: Option<&Value>) -> (String, bool) {
    let Some(value) = value else {
        return (String::new(), true);
    };
    match value {
        Value::Null => ("NULL".to_string(), true),
        Value::Blob(bytes) => (
            format!(
                "{} byte{}{}",
                bytes.len(),
                if bytes.len() == 1 { "" } else { "s" },
                blob_preview(bytes)
            ),
            false,
        ),
        other => {
            let text = other.to_string();
            let flat = text.replace(['\n', '\r'], " ");
            if flat.chars().count() > CELL_CHARS {
                let head: String = flat.chars().take(CELL_CHARS).collect();
                (format!("{head}…"), false)
            } else {
                (flat, false)
            }
        }
    }
}

fn blob_preview(bytes: &[u8]) -> String {
    if bytes.is_empty() {
        return String::new();
    }
    let head: String = bytes
        .iter()
        .take(8)
        .map(|b| format!("{b:02x}"))
        .collect::<Vec<_>>()
        .join("");
    let ellipsis = if bytes.len() > 8 { "…" } else { "" };
    format!(" · 0x{head}{ellipsis}")
}

/// What the cell inspector shows for one value (§7).
///
/// JSON is pretty-printed when it parses, because a one-line document in a fixed-height
/// grid is the case §7 says the inspector exists for. When it does not parse, the text
/// is shown exactly as it came back — guessing twice would be worse than not guessing.
pub fn inspect_text(value: &Value) -> String {
    match value {
        Value::Null => "NULL".to_string(),
        Value::Blob(bytes) => {
            let hex: String = bytes
                .chunks(16)
                .map(|chunk| {
                    chunk
                        .iter()
                        .map(|b| format!("{b:02x}"))
                        .collect::<Vec<_>>()
                        .join(" ")
                })
                .collect::<Vec<_>>()
                .join("\n");
            format!("{} bytes\n\n{hex}", bytes.len())
        }
        Value::Text(text) => match serde_json::from_str::<serde_json::Value>(text) {
            Ok(json) if text.trim_start().starts_with(['{', '[']) => {
                serde_json::to_string_pretty(&json).unwrap_or_else(|_| text.clone())
            }
            _ => text.clone(),
        },
        other => other.to_string(),
    }
}

/// A header cell's tooltip: the driver's own type name, kept verbatim (invariant 10).
pub fn type_tooltip<'a>(
    content: impl Into<Element<'a, Message>>,
    driver_type: &str,
) -> Element<'a, Message> {
    tooltip(
        content,
        container(text(driver_type.to_string()).font(fonts::UI).size(11)).padding(4),
        tooltip::Position::Bottom,
    )
    .into()
}

/// A horizontal strip of elements with a little air between them.
pub fn strip<'a>(
    items: impl IntoIterator<Item = Element<'a, Message>>,
) -> iced::widget::Row<'a, Message> {
    row(items).spacing(8).align_y(iced::Center)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn null_is_a_word_and_an_empty_string_is_not() {
        assert_eq!(cell_text(Some(&Value::Null)), ("NULL".to_string(), true));
        assert_eq!(
            cell_text(Some(&Value::Text(String::new()))),
            (String::new(), false),
            "an empty string is a value; it must not read as an absent one"
        );
    }

    #[test]
    fn a_long_value_is_cut_and_says_so() {
        let long = "x".repeat(500);
        let (shown, _) = cell_text(Some(&Value::Text(long)));
        assert!(shown.ends_with('…'));
        assert_eq!(shown.chars().count(), CELL_CHARS + 1);
    }

    #[test]
    fn a_newline_does_not_turn_one_row_into_two() {
        let (shown, _) = cell_text(Some(&Value::Text("a\nb".to_string())));
        assert_eq!(shown, "a b");
    }

    #[test]
    fn a_blob_is_a_length_and_a_prefix_rather_than_mojibake() {
        let (shown, _) = cell_text(Some(&Value::Blob(vec![0x0b, 0xad, 0xc0, 0xde])));
        assert_eq!(shown, "4 bytes · 0x0badc0de");
    }

    #[test]
    fn the_inspector_pretty_prints_json_and_leaves_everything_else_alone() {
        let json = Value::Text("{\"a\":1}".to_string());
        assert_eq!(inspect_text(&json), "{\n  \"a\": 1\n}");

        let not_json = Value::Text("42".to_string());
        assert_eq!(
            inspect_text(&not_json),
            "42",
            "a bare number is not a document to reformat"
        );
    }

    #[test]
    fn a_column_starts_wide_enough_for_its_name_and_no_wider_than_a_screen() {
        assert!(default_column_width("id") < default_column_width("shipping_address_line_2"));
        assert_eq!(default_column_width(&"x".repeat(200)), 280.0);
    }
}
