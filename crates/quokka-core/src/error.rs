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

    /// §5: fail-closed does not apply to introspection — there is no "before" event to
    /// fail — so the refresh has already happened by the time this can be raised. It is
    /// surfaced loudly rather than swallowed, exactly as a failed `query_finished` is,
    /// and the catalog is dropped rather than cached: a refresh the log never heard
    /// about must not go on to answer questions.
    #[error(
        "the catalog was refreshed but the audit log could not record it ({source}). \
         The refresh has been discarded rather than cached."
    )]
    IntrospectNotRecorded {
        #[source]
        source: quokka_audit::AuditError,
    },

    /// §5 again: an export is a logged event even though it touched no database, so a
    /// failed append means a file exists that the log does not mention. The file is
    /// already written by the time this can be raised, so — like a failed
    /// `query_finished` — it is surfaced loudly rather than swallowed.
    #[error(
        "the export was written but the audit log could not record it ({source}). \
         The file exists and the log does not say so."
    )]
    ExportNotRecorded {
        #[source]
        source: quokka_audit::AuditError,
    },

    #[error(transparent)]
    Credential(#[from] crate::credential::CredentialError),

    #[error("audit log: {0}")]
    Audit(#[from] quokka_audit::AuditError),

    #[error(transparent)]
    Driver(#[from] DriverError),

    #[error("writing results failed: {0}")]
    Sink(#[from] std::io::Error),

    /// The policy engine refused the statement (§6.3). Nothing reached a database — not
    /// even a connection attempt — and the log holds the attempt as a `query_started`
    /// with a `query_finished` whose status is `denied`.
    #[error("{message}")]
    Denied {
        connection: String,
        query_id: uuid::Uuid,
        /// A stable code for scripts and for the log's `error_code` column.
        code: &'static str,
        message: String,
    },

    #[error("no query {0} is running on this connection")]
    NotRunning(uuid::Uuid),
}
