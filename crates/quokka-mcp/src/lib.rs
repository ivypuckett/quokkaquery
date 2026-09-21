//! `quokka mcp` — the audited query path, as tools an agent can call (ARCHITECTURE §6.2).
//!
//! An agent client attaches over stdio and gets `list_connections`, `list_schemas`,
//! `describe_table`, `query`, `explain`, `export` and `search_audit`. No shelling out, no
//! output parsing, and schema introspection as structured context instead of guesswork.
//!
//! Three things about this crate are load-bearing, and each is a decision rather than an
//! implementation detail.
//!
//! **It is a view, not a second engine.** Every tool here goes through
//! `quokka-core::execute()`, `introspect()`, `explain()` or `record_export()` — the same
//! four doors the CLI uses. There is no path from this crate to a driver:
//! [`ExecutePermit`](quokka_core::ExecutePermit)'s constructor is crate-private to
//! `quokka-core`, so the compiler refuses one. That is what makes "every query an agent
//! runs is logged" a property of the program rather than a promise about this file.
//!
//! **It holds one spool set for its lifetime.** `quokka mcp` is a long-lived process, so
//! a query runs once and every page, re-sort and export after it is a read of a local
//! file (§4, §6.2). A `query` tool that re-executed to serve page 2 would defeat the
//! milestone — and on Athena it would bill for it twice.
//!
//! **It can only ever be stricter than the connection.** The server is started read-only
//! unless a human passes `--allow-writes`, and that posture narrows a connection's mode
//! and never widens it. Invariant 9 forbids a surface that gets *more* than the mode
//! allows; one that takes less is not an exemption, and it is what stops an agent's
//! `write: true` from being a permission it grants itself.

mod params;
mod server;
mod state;

use std::sync::Arc;

use quokka_core::{AccessMode, Actor, Engine};
use quokka_spool::SpoolSet;
use rmcp::transport::stdio;
use rmcp::ServiceExt;

pub use server::{QuokkaMcp, DEFAULT_FETCH_ROWS};

/// Errors from running the server itself, as distinct from anything a tool answered.
#[derive(Debug, thiserror::Error)]
pub enum McpServeError {
    #[error("the MCP server could not start: {0}")]
    Start(String),
    #[error("the MCP server stopped: {0}")]
    Stopped(String),
}

/// Serve MCP over stdio until the client disconnects.
///
/// Stdio, and therefore **nothing may print to stdout** while this runs: the transport is
/// the protocol. Anything a surface wants to say goes to stderr.
pub async fn serve_stdio(
    engine: Arc<Engine>,
    spools: Arc<SpoolSet>,
    actor: Actor,
    surface_mode: AccessMode,
) -> Result<(), McpServeError> {
    let server = QuokkaMcp::new(engine, spools, actor, surface_mode);
    let running = server
        .serve(stdio())
        .await
        .map_err(|e| McpServeError::Start(e.to_string()))?;
    running
        .waiting()
        .await
        .map_err(|e| McpServeError::Stopped(e.to_string()))?;
    Ok(())
}
