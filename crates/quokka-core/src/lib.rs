//! QuokkaQuery's core: the value vocabulary, the connection registry, and the one code
//! path that may execute SQL.
//!
//! The load-bearing item here is [`execute()`]. Every surface — CLI, UI, MCP — goes
//! through it, which is what makes "every query is logged" a property of the program
//! rather than a promise about its authors' discipline (ARCHITECTURE §2, invariant 1).
//!
//! Read `docs/ARCHITECTURE.md` before changing anything in this crate.

pub mod config;
pub mod driver;
pub mod engine;
pub mod error;
pub mod redact;
pub mod sql;
pub mod value;

pub use config::{
    default_config_path, dialect_hint, AccessMode, ConnectionConfig, Registry, AUDIT_CONNECTION,
};
pub use driver::{
    Catalog, Driver, DriverFactory, ExecutePermit, MetaHandle, Plan, QueryHandle, QueryRequest,
    QueryStream, ResultMeta, Scope, TableInfo,
};
pub use engine::{
    events_for_query, execute, Actor, Engine, ExecuteRequest, NullSink, Outcome, RowSink,
    DEFAULT_MAX_ROWS,
};
pub use error::{CoreError, DriverError};
pub use sql::{summarize, SqlSummary};
pub use value::{Column, Dialect, Row, Value};

// Re-exported so surfaces and drivers speak one audit vocabulary without depending on
// `quokka-audit` directly.
pub use quokka_audit::{ActorKind, AuditEvent, AuditLog, Client, EventKind, SqlLogging, Status};
