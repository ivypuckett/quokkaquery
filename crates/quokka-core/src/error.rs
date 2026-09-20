//! Error types. `thiserror` in the libraries, `anyhow` at the CLI boundary.

use std::path::PathBuf;

/// A failure inside a driver.
#[derive(Debug, thiserror::Error)]
pub enum DriverError {
    #[error("cannot connect to {connection}: {detail}")]
    Connect { connection: String, detail: String },

    #[error("{detail}")]
    Execute { detail: String },

    #[error("query was cancelled")]
    Cancelled,

    #[error("{0}")]
    Unsupported(String),

    #[error("driver protocol error: {0}")]
    Protocol(String),
}

impl DriverError {
    /// A stable, machine-readable code for the audit log's `error_code` column.
    pub fn code(&self) -> &'static str {
        match self {
            DriverError::Connect { .. } => "driver.connect",
            DriverError::Execute { .. } => "driver.execute",
            DriverError::Cancelled => "driver.cancelled",
            DriverError::Unsupported(_) => "driver.unsupported",
            DriverError::Protocol(_) => "driver.protocol",
        }
    }
}

/// A failure in the core: configuration, dispatch, or the audit log.
#[derive(Debug, thiserror::Error)]
pub enum CoreError {
    #[error("no connection named {0:?}; check your config file")]
    UnknownConnection(String),

    #[error("connection {connection:?} uses driver {driver:?}, which this build does not include")]
    UnknownDriver { connection: String, driver: String },

    #[error("config file {path}: {detail}")]
    Config { path: PathBuf, detail: String },

    #[error("could not locate the config file: {0}")]
    ConfigPath(String),

    /// Invariant 6. The query did not run.
    #[error(
        "refusing to run the query: the audit log could not record that it started ({source}). \
         QuokkaQuery does not execute when it cannot record."
    )]
    AuditWriteFailed {
        #[source]
        source: quokka_audit::AuditError,
    },

    /// The query already ran, so this is surfaced loudly rather than swallowed (§5).
    /// The dangling `query_started` row is the honest record of what happened.
    #[error(
        "the query ran but the audit log could not record how it finished ({source}). \
         The log holds a start with no finish for query {query_id}."
    )]
    AuditFinishFailed {
        query_id: uuid::Uuid,
        #[source]
        source: quokka_audit::AuditError,
    },

    #[error("audit log: {0}")]
    Audit(#[from] quokka_audit::AuditError),

    #[error(transparent)]
    Driver(#[from] DriverError),

    #[error("writing results failed: {0}")]
    Sink(#[from] std::io::Error),

    #[error("no query {0} is running on this connection")]
    NotRunning(uuid::Uuid),
}
