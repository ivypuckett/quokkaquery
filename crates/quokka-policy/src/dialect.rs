//! Which SQL a connection speaks.
//!
//! This type lives here rather than in `quokka-core` for the reason the whole crate
//! does: `quokka-core::execute()` consults the policy engine, so the policy engine has
//! to sit *below* it in the dependency graph, and a classifier's first argument is the
//! dialect it is classifying for. `quokka_core::Dialect` still resolves — core
//! re-exports it — so nothing above this crate had to change.

use std::fmt;

use sqlparser::dialect::{
    Dialect as SqlDialect, GenericDialect, MySqlDialect, PostgreSqlDialect, SQLiteDialect,
};

/// The SQL dialect a connection speaks.
///
/// Distinct from the driver name: two connections may share a driver and be recorded
/// separately, and the dialect is what the classifier and the fingerprint need.
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Dialect {
    Sqlite,
    Postgres,
    MySql,
    Athena,
}

impl Dialect {
    pub fn as_str(self) -> &'static str {
        match self {
            Dialect::Sqlite => "sqlite",
            Dialect::Postgres => "postgres",
            Dialect::MySql => "mysql",
            Dialect::Athena => "athena",
        }
    }

    /// The `sqlparser` dialect to parse with.
    pub(crate) fn parser(self) -> Box<dyn SqlDialect> {
        match self {
            Dialect::Sqlite => Box::new(SQLiteDialect {}),
            Dialect::Postgres => Box::new(PostgreSqlDialect {}),
            Dialect::MySql => Box::new(MySqlDialect {}),
            // Athena is Presto/Trino-flavoured; the generic dialect is the closest fit
            // sqlparser offers. It only affects parsing and normalization, never what
            // is sent to the engine.
            Dialect::Athena => Box::new(GenericDialect {}),
        }
    }
}

impl fmt::Display for Dialect {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}
