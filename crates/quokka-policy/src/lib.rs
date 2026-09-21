//! QuokkaQuery's policy engine: what a statement is, and whether it may run.
//!
//! This is the security boundary (ARCHITECTURE §6.3), so it is built as a library of
//! **pure functions over SQL and a dialect** — no I/O of its own, no database, no log,
//! no filesystem, no clock. Everything it knows arrives as an argument and everything it
//! decides leaves as a return value, which is what makes it testable against a corpus
//! rather than against a running system, and what makes CLAUDE.md's first testing
//! priority achievable.
//!
//! It sits *below* `quokka-core` in the dependency graph, because
//! `quokka-core::execute()` consults it before issuing the
//! [`ExecutePermit`](quokka_core::ExecutePermit) — inside the one execute path, not in a
//! surface and not in a driver. A guardrail a surface could forget is not one.
//!
//! ## The rules
//!
//! 1. **One statement per query.** Stacked bodies are rejected (§6.3).
//! 2. **A write needs two keys**: `mode = "read_write"` in the connection's
//!    configuration, which only a human can set (invariant 7), *and* an explicit opt-in
//!    at the call site.
//! 3. **Anything not certainly a read is a write.** See below.
//! 4. **An optional per-connection allowlist** of schemas and tables.
//! 5. **Server-side caps** on rows and time ([`Limits`]), which a request may lower and
//!    never raise.
//! 6. **A cumulative cost budget** per actor over a rolling window ([`CostGuard`], §6.4).
//!    The spend is *gathered by the caller* and passed in as a value — see the note at
//!    the top of `cost.rs`, because that constraint is the whole reason this crate can
//!    stay a library of pure functions.
//!
//! ## Parsing is not classification, and a parse failure is a decision
//!
//! sqlparser does not know every dialect's syntax, so this crate has to say what happens
//! to a statement it cannot read. Failing open would make the guardrail advisory: every
//! corner of syntax sqlparser has not caught up with becomes a hole a `DELETE` can be
//! driven through, and "read-only" would mean "read-only for statements we recognized".
//! Failing closed makes some legitimate queries unrunnable.
//!
//! **We fail closed, and we do it without a special case.** A statement whose read-only
//! status the classifier cannot establish is treated exactly as a statement it knows to
//! be a write — [`SqlSummary::read_only`] is `None` rather than an optimistic `true`,
//! and [`Policy::decide`] branches on "not certainly a read" rather than on "is a write".
//! Three consequences follow, and together they are why this is the right trade:
//!
//! - On a `read_only` connection, unreadable text is denied. That is the guarantee the
//!   product sells, kept whole.
//! - On a `read_write` connection with the call-site opt-in, unreadable text runs. The
//!   human has already said writes are allowed here and has said so again for this
//!   call; refusing on top of that would be the tool substituting its own judgement for
//!   an authorization it was given.
//! - There is no `--force`, and no per-dialect escape hatch. The way out is the config
//!   file, which is human-only — so an agent cannot widen this on its own, which is the
//!   property that makes the whole thing worth having.
//!
//! The alternative — a per-dialect list of "syntax we fail open for" — was rejected
//! because it is a list that only ever grows, and every entry on it is a hole nobody
//! reviews again.
//!
//! What we do instead, to keep the cost off the common case, is classify unreadable text
//! a second time from the **token stream**: a body that begins with a reading keyword and
//! contains no writing word anywhere is a read, and everything else is a write. This is
//! not the keyword scan the corpus exists to reject — that one runs over *text*, where a
//! `--` comment, a string literal and the identifier `deleted_at` all look like keywords.
//! By the time there are tokens, comments are gone, a literal is one token, and
//! `deleted_at` is one word. The rule is unchanged; only the evidence is weaker, and it
//! is weaker in the safe direction.

mod analyze;
mod cost;
mod dialect;
mod policy;

pub use analyze::{summarize, SqlSummary, TableRef, UNFINGERPRINTABLE};
pub use cost::{
    bytes as cost_bytes, window as cost_window, ActorClass, CostContext, CostGuard, CostWarning,
};
pub use dialect::Dialect;
pub use policy::{AccessMode, Allowlist, Denial, Limits, Outcome, Policy};
