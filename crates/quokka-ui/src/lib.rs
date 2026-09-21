//! `quokka ui` — the human surface, over the same engine the CLI and the MCP server use
//! (ARCHITECTURE §7).
//!
//! Read `docs/ARCHITECTURE.md` before changing anything here. This crate is a *view*:
//! it draws a window, and every question it has about a database it asks
//! `quokka-core`. There is no path from an `update` function to a driver, and the
//! compiler is what says so — [`ExecutePermit`](quokka_core::ExecutePermit)'s
//! constructor is crate-private to `quokka-core`, so a surface cannot make one however
//! it came by a `Driver`.
//!
//! # Four decisions this milestone had to make
//!
//! ## 1. `quokka ui` has no `--allow-writes`, and that is not an inconsistency
//!
//! `quokka mcp` refuses writes unless a human started it with `--allow-writes`, and the
//! symmetric question here has the opposite answer for a reason worth writing down.
//!
//! That flag is a *second human key*: the agent is not the one who launched the server,
//! so a human writing `--allow-writes` into an MCP client's configuration file is a
//! decision the agent cannot make for itself. Both keys that matter — `mode =
//! "read_write"` in the config file and the posture at launch — are held by someone who
//! is not the caller, which is what makes the agent's own `write: true` more than
//! theatre (§6.3).
//!
//! At a window, the person who would type the flag is the person already sitting there.
//! A posture they can set themselves is not a second key; it is a speed bump they would
//! learn to always pass, and then it protects nothing while training them to ignore a
//! refusal. Worse, it would add a *third* way for a write to fail, when §6.3 names
//! precisely the friction this surface must design out — "you will hit your own
//! guardrail while sitting at a database client" — and answers it with a mode you cannot
//! be surprised by, not with another mode.
//!
//! So `quokka ui` runs at `surface_mode = ReadWrite`, which means the connection's own
//! mode governs, unmodified. That is invariant 9 exactly: the mode binds the human at the
//! UI as it binds an agent, with no per-surface exemption in either direction. What the
//! UI *does* have is the call-site opt-in — `ExecuteRequest::write`, supplied by the
//! write confirmation (§7) — and it is per statement rather than per session, which is
//! strictly stronger than a launch flag would have been.
//!
//! ## 2. `iced_table`, not the built-in table and not a hand-rolled grid
//!
//! See [`grid`]. Short version: iced 0.14 ships `iced::widget::table`, which cannot
//! resize a column, and resize is where §7's open question actually bites.
//!
//! ## 3. The audit view is a result tab over a saved `@audit` query
//!
//! §5 says the UI's audit view *is* a saved query against the log, and it is: pressing
//! "Queries" in the sidebar fills the editor with SQL against the `queries` view and
//! runs it through `execute()` like anything else — so it is capped at 512 rows, pages
//! from a spool, exports through the audited export path, and leaves its own pair of
//! events in the log. Reading the log is a logged query, which is the point of shipping
//! the log as a connection rather than as a second API.
//!
//! A bespoke view would read a little better and cost a great deal: a second reader of
//! the log that can disagree with `quokka audit`, its own paging, its own sorting, its
//! own export — and a blind spot where the product's own dogfood used to be. The one
//! concession to legibility is that the saved queries are buttons, so nobody has to
//! remember the schema to see their own trail.
//!
//! ## 4. Sixteen result tabs, and closing one takes its spool with it
//!
//! See [`results`].
//!
//! # What the window may not do
//!
//! Invariant 2 is harder here than on any other surface, because every violation of it
//! is the helpful thing. None of the following happens, and each was a decision:
//!
//! - Clicking a table in the tree does **not** preview its rows.
//! - Selecting a result tab does **not** re-run its query; a stale tab offers `[Re-run]`
//!   and never takes one.
//! - Nothing refreshes on window focus, on a timer, or on a reconnect.
//! - Autocomplete reads a catalog already in memory and cannot reach a database: see
//!   [`complete`].
//!
//! The only three controls that reach a database are Run, Re-run and Refresh catalog.

pub mod complete;
pub mod fonts;
pub mod grid;
pub mod message;
pub mod results;
pub mod state;
pub mod view;
pub mod work;

use std::sync::Arc;

use iced::{Subscription, Task};

pub use message::Message;
pub use state::State;
pub use work::{Boot, Session};

/// Which renderer to ask iced for (§7).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum Renderer {
    /// `wgpu`, falling back to the software renderer by itself if it cannot initialize.
    #[default]
    Gpu,
    /// `tiny-skia`, chosen deliberately — for a remote desktop or a VM where GPU access
    /// is unreliable enough that failing over once per start is not good enough.
    Software,
}

impl Renderer {
    /// iced selects its backend from `ICED_BACKEND`, so "selectable" is this variable.
    ///
    /// Set only for the software renderer: leaving it unset is what lets iced try wgpu
    /// and fall back on its own, which is the default §7 asks for.
    fn apply(self) {
        if self == Renderer::Software {
            // SAFETY: called before any window, any renderer and any thread that reads
            // the environment — `run` is the first thing `quokka ui` does.
            unsafe { std::env::set_var("ICED_BACKEND", "tiny-skia") };
        }
    }
}

/// Open the window and run until it closes.
///
/// **The engine is built inside iced's runtime, not before it.** `quokka ui` is the one
/// subcommand that must not be entered from a `#[tokio::main]` runtime: iced builds its
/// own (that is what its `tokio` feature means) and a runtime inside a runtime is a
/// panic. So `run` is called from an ordinary thread, and the first thing the window
/// does is a `Task` that opens the audit log, reads the config file and claims a spool
/// directory — which also means every sqlx pool belongs to the runtime that will drive
/// it.
pub fn run(boot: Boot, renderer: Renderer) -> iced::Result {
    renderer.apply();

    let boot = Arc::new(boot);
    let start = boot.clone();

    iced::application(
        move || {
            let state = State::new(start.clone());
            let boot = start.clone();
            let task = Task::batch([
                Task::future(async move { work::boot(&boot).await })
                    .map(|result| Message::Booted(Box::new(result))),
                iced::system::theme().map(Message::SystemTheme),
            ]);
            (state, task)
        },
        state::update,
        view::view,
    )
    .title(title)
    .theme(|state: &State| state.theme.clone())
    .subscription(subscription)
    // The bundled monospace face (§7). Fira Sans arrives with iced's `fira-sans`
    // feature; this is its monospace half. See `fonts.rs` for the licence.
    .font(fonts::MONO_BYTES)
    .default_font(fonts::UI)
    // So the spool directory can be deleted before the process ends (§4.1) rather than
    // left for the next process to sweep.
    .exit_on_close_request(false)
    .window_size((1280.0, 820.0))
    .run()
}

fn title(state: &State) -> String {
    match state.connection.as_deref() {
        Some(connection) => format!("QuokkaQuery — {connection}"),
        None => "QuokkaQuery".to_string(),
    }
}

/// **Every subscription here is an input or a clock. None of them is a poller.**
///
/// §1.4 forbids anything that re-executes on its own, and the timer below is the place
/// that rule would be easiest to break. It exists to move the elapsed-time counter on a
/// running query and to age the pager's "45m ago"; it produces [`Message::Tick`], which
/// sets a clock field and nothing else. When no query is running and no result is open,
/// there is no timer at all.
fn subscription(state: &State) -> Subscription<Message> {
    let mut subscriptions = vec![
        iced::window::close_requests().map(|_| Message::CloseRequested),
        // Shift, for extending a grid selection to a rectangle (§7's copy-as-TSV).
        iced::event::listen_with(|event, _status, _window| match event {
            iced::Event::Keyboard(iced::keyboard::Event::ModifiersChanged(modifiers)) => {
                Some(Message::ModifiersChanged(modifiers))
            }
            _ => None,
        }),
        iced::system::theme_changes().map(Message::SystemTheme),
    ];

    if state.running.is_some() {
        subscriptions
            .push(iced::time::every(std::time::Duration::from_millis(200)).map(|_| Message::Tick));
    } else if !state.slots.is_empty() {
        subscriptions
            .push(iced::time::every(std::time::Duration::from_secs(30)).map(|_| Message::Tick));
    }

    Subscription::batch(subscriptions)
}
