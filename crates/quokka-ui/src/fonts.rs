//! The fonts the window draws with, bundled so rendering is identical everywhere (§7).
//!
//! A database client is mostly a grid of values and a SQL editor, and both want a
//! monospace face: columns that line up, and a `0` that is not an `O`. Asking the
//! operating system for "monospace" gets Menlo on one machine, Consolas on another and
//! whatever fontconfig picks on a third — so a screenshot from one machine would not
//! match another, and a column width measured on one would not fit on the next.
//!
//! ## What is bundled, and under what licence
//!
//! Both faces are **Fira**, and both are SIL Open Font License 1.1 — a permissive
//! licence with no copyleft reach into the binary that embeds them. CLAUDE.md forbids
//! GPL code in the tree; OFL 1.1 is not GPL, and its only real obligations are that the
//! font keeps its licence and that a derivative font is not passed off under a reserved
//! name. We embed the file unmodified and ship its licence alongside, which satisfies
//! both.
//!
//! - **Fira Sans** for the interface, which iced itself vendors behind its `fira-sans`
//!   feature. Taking it from there rather than vendoring a second copy keeps one file of
//!   one family in the binary.
//! - **Fira Mono** for the editor, the grid and the cell inspector, vendored in
//!   `assets/` because iced does not ship it. Same family, same foundry, same licence —
//!   so the licence audit is one question rather than two, and the two faces were drawn
//!   to sit beside each other.

use iced::Font;

/// Fira Mono, embedded in the binary. Registered at startup by [`crate::run`].
pub const MONO_BYTES: &[u8] = include_bytes!("../assets/FiraMono-Regular.ttf");

/// The interface face: Fira Sans, which iced's `fira-sans` feature has already loaded
/// into the font system by the time a window exists.
pub const UI: Font = Font::with_name("Fira Sans");

/// The face for anything the user typed or the database returned.
pub const MONO: Font = Font::with_name("Fira Mono");
