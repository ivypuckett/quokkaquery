//! QuokkaQuery's core: the value vocabulary, the connection registry, and the one code
//! path that may execute SQL.
//!
//! The load-bearing item here is [`execute()`]. Every surface — CLI, UI, MCP — goes
//! through it, which is what makes "every query is logged" a property of the program
//! rather than a promise about its authors' discipline (ARCHITECTURE §2, invariant 1).
//!
//! Read `docs/ARCHITECTURE.md` before changing anything in this crate.

pub mod catalog;
pub mod config;
pub mod credential;
pub mod driver;
pub mod engine;
pub mod error;
pub mod export;
pub mod redact;
pub mod secret;
pub mod sql;
pub mod value;

pub use catalog::CatalogCache;
pub use config::{
    default_config_path, default_port, dialect_hint, AccessMode, Config, ConnectionConfig,
    Registry, SpoolConfig, TlsMode, AUDIT_CONNECTION, DEFAULT_CATALOG_TTL, DEFAULT_CONNECT_TIMEOUT,
    DEFAULT_SPOOL_MAX_BYTES, DEFAULT_SPOOL_MAX_ROWS,
};
pub use credential::{Backend as CredentialBackend, CredentialError, CredentialRef};
pub use driver::{
    Catalog, Driver, DriverFactory, ExecutePermit, MetaHandle, Plan, QueryHandle, QueryRequest,
    QueryStream, ResultMeta, Scope, TableInfo,
};
pub use engine::{
    events_for_query, execute, introspect, Actor, Cap, CatalogResult, Engine, ExecuteRequest,
    IntrospectRequest, NullSink, Outcome, Retained, RowSink, DEFAULT_MAX_ROWS,
};
pub use error::{CoreError, DriverError};
pub use export::{record_export, ExportRecord};
pub use secret::Secret;
pub use sql::{summarize, SqlSummary};
pub use value::{Column, Dialect, Row, Value};

// Re-exported so surfaces and drivers speak one audit vocabulary without depending on
// `quokka-audit` directly.
pub use quokka_audit::{ActorKind, AuditEvent, AuditLog, Client, EventKind, SqlLogging, Status};
