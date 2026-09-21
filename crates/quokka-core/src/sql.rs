//! Fingerprinting and statement classification — now `quokka-policy`'s, re-exported here.
//!
//! This module used to hold the implementation. It moved when the policy engine arrived
//! at M3, for a reason worth keeping: the log's `statement_kind` and `read_only` columns
//! and the guardrail's read/write decision must come from the *same* parse, or the log
//! can record `select` for a statement the engine denied as a write. One parse, one
//! answer, one place — and `quokka-policy` has to be the place, because it sits below
//! `quokka-core` so that `execute()` can consult it.
//!
//! `quokka_core::summarize` and `quokka_core::SqlSummary` still resolve, which is why
//! nothing above this crate had to change.

pub use quokka_policy::{summarize, SqlSummary, TableRef, UNFINGERPRINTABLE};
