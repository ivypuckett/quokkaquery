//! What can go wrong with a spool. `thiserror` in the library, `anyhow` at the CLI
//! boundary (CLAUDE.md).

use std::path::PathBuf;

#[derive(Debug, thiserror::Error)]
pub enum SpoolError {
    #[error("could not open the spool: {detail}")]
    Open { detail: String },

    #[error("spool database error: {0}")]
    Sqlx(#[from] sqlx::Error),

    #[error("spool I/O at {path}: {source}")]
    Io {
        path: PathBuf,
        #[source]
        source: std::io::Error,
    },

    #[error("could not locate the cache directory: {0}")]
    CacheDir(String),

    #[error("the spool's writer thread failed: {0}")]
    Thread(String),

    #[error("this spool holds {columns} columns, so there is no column {index}")]
    NoSuchColumn { index: usize, columns: usize },

    #[error("{0}")]
    Unsupported(String),

    #[error("writing the export failed: {0}")]
    Export(String),

    #[error("could not format a timestamp: {0}")]
    Time(#[from] time::error::Format),
}

impl SpoolError {
    /// A stable, machine-readable code, for the audit log's `error_code` column on a
    /// failed export.
    pub fn code(&self) -> &'static str {
        match self {
            SpoolError::Open { .. } => "spool.open",
            SpoolError::Sqlx(_) => "spool.database",
            SpoolError::Io { .. } => "spool.io",
            SpoolError::CacheDir(_) => "spool.cache_dir",
            SpoolError::Thread(_) => "spool.thread",
            SpoolError::NoSuchColumn { .. } => "spool.no_such_column",
            SpoolError::Unsupported(_) => "spool.unsupported",
            SpoolError::Export(_) => "spool.export",
            SpoolError::Time(_) => "spool.time",
        }
    }
}

impl From<SpoolError> for std::io::Error {
    /// [`quokka_core::RowSink`]'s methods answer in `std::io::Result`, so a spool
    /// failure while rows are arriving has to become one. The engine turns it into a
    /// `sink.io` failure on the query, which is the honest outcome: the query ran and
    /// its rows had nowhere to go.
    fn from(e: SpoolError) -> Self {
        std::io::Error::other(e.to_string())
    }
}
