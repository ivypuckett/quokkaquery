//! Everything that can happen to the window, as one enum.
//!
//! Payloads that are expensive or not `Clone` ride in a `Box`, because iced needs a
//! message to be `Clone` and `Debug` and a `Spool` in a message would otherwise be
//! copied on every redraw.

use quokka_core::Catalog;
use quokka_spool::{Format, Op};
use uuid::Uuid;

use crate::work::{Exported, Paged, Ran, Session};

/// Which saved query the audit tab opens with (§5).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AuditView {
    /// One row per query: the `queries` view, which joins a start to its finish.
    Queries,
    /// Every event, newest first.
    Events,
    /// What was refused. §6.3: what an agent *tried* to run is as valuable as what ran.
    Denials,
}

/// Which page to read next.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Step {
    First,
    Next,
    Previous,
}

#[derive(Debug, Clone)]
pub enum Message {
    // The window exists before the engine does; this is the engine arriving.
    Booted(Box<Result<Session, String>>),
    SystemTheme(iced::theme::Mode),
    /// A clock tick. Moves the elapsed-time counter and ages the pager's "45m ago";
    /// it never asks a database anything (§1.4).
    Tick,
    ModifiersChanged(iced::keyboard::Modifiers),
    CloseRequested,
    ShutDownFinished,

    ConnectionSelected(String),
    /// The explicit refresh §1.4 requires. Autocomplete never sends this.
    CatalogRefreshRequested,
    CatalogLoaded {
        connection: String,
        result: Box<Result<Catalog, String>>,
    },

    Edit(iced::widget::text_editor::Action),
    CompletionAccepted(usize),
    CompletionsDismissed,

    RunRequested,
    /// The human answered the write confirmation (§7). This is not an authorization —
    /// `execute()` decides — it is the call-site opt-in a write needs on top of the
    /// connection's mode.
    WriteConfirmed,
    WriteDeclined,
    Ran(Box<Ran>),
    CancelRequested,
    Cancelled,

    TabSelected(Uuid),
    TabClosed(Uuid),
    PageRequested(Step),
    Paged(Box<Result<Paged, String>>),
    /// Sort by a column, which is a read of the spool and never a re-run (§4).
    SortRequested(usize),
    FilterColumnSelected(usize),
    FilterOpSelected(Op),
    FilterValueChanged(String),
    FilterApplied,
    FilterCleared,
    CellPressed(usize, usize),
    SelectionCopied,
    InspectorClosed,
    ColumnResizing(usize, f32),
    ColumnResized,
    HeaderSynced(iced::widget::scrollable::AbsoluteOffset),
    ExportPathChanged(String),
    ExportFormatChanged(Format),
    ExportRequested,
    Exported(Box<Result<Exported, String>>),
    NoticeDismissed,
    AuditRequested(AuditView),
    /// Run this tab's statement again — the control §1.4 asks for beside a stale result,
    /// and the only thing that will ever re-run one.
    RerunRequested,
}
