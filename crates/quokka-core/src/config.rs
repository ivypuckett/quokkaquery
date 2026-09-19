//! The connection registry and the file it is read from.
//!
//! Invariant 7: config is human-only. Nothing in this module is writable from a surface,
//! and no CLI flag overrides `sql_logging`, `mode` or a cost budget. An agent that can
//! lower the fidelity of its own audit trail defeats the log's purpose.

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

use quokka_audit::SqlLogging;
use serde::Deserialize;

use crate::error::CoreError;
use crate::value::Dialect;

/// The name of the built-in connection that exposes the audit log itself (§5).
pub const AUDIT_CONNECTION: &str = "@audit";

/// Whether a connection may be written to.
///
/// The mode binds every surface identically (invariant 9): read-only means read-only for
/// the human at the UI as much as for an agent. Statement classification and denial land
/// with `quokka-policy` at M3; at M0 the mode is recorded on every audit row, and a
/// read-only SQLite connection is opened read-only by the driver, which the database
/// itself then enforces.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, serde::Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AccessMode {
    #[default]
    ReadOnly,
    ReadWrite,
}

impl AccessMode {
    pub fn is_read_only(self) -> bool {
        matches!(self, AccessMode::ReadOnly)
    }

    pub fn as_str(self) -> &'static str {
        match self {
            AccessMode::ReadOnly => "read_only",
            AccessMode::ReadWrite => "read_write",
        }
    }
}

/// One configured connection.
#[derive(Debug, Clone, PartialEq)]
pub struct ConnectionConfig {
    pub name: String,
    /// Matches a [`crate::DriverFactory::name`], e.g. `"sqlite"`.
    pub driver: String,
    /// SQLite: the database file.
    pub path: Option<PathBuf>,
    pub mode: AccessMode,
    pub sql_logging: SqlLogging,
    /// Recorded on every audit row for this connection.
    pub database: Option<String>,
    pub schema: Option<String>,
    /// True for `@audit`, which the registry supplies rather than the config file.
    pub builtin: bool,
}

/// A connection as the TOML file spells it.
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
struct ConnectionFile {
    driver: String,
    #[serde(default)]
    path: Option<PathBuf>,
    #[serde(default)]
    mode: AccessMode,
    /// `fingerprint` unless the connection opted in — invariant 8.
    #[serde(default, deserialize_with = "de_sql_logging")]
    sql_logging: SqlLogging,
    #[serde(default)]
    database: Option<String>,
    #[serde(default)]
    schema: Option<String>,
}

#[derive(Debug, Clone, Default, Deserialize)]
#[serde(deny_unknown_fields)]
struct ConfigFile {
    #[serde(default)]
    connections: BTreeMap<String, ConnectionFile>,
}

/// `redacted` is an M7 deliverable (§5.1). Accepting it silently would mean writing
/// literals to the log under a setting the user believes masks them, so it is refused
/// by name rather than ignored.
fn de_sql_logging<'de, D>(d: D) -> Result<SqlLogging, D::Error>
where
    D: serde::Deserializer<'de>,
{
    let s = String::deserialize(d)?;
    match s.as_str() {
        "redacted" => Err(serde::de::Error::custom(
            "sql_logging = \"redacted\" is not implemented yet (it arrives at M7). \
             Use \"fingerprint\" (the default) or \"full\".",
        )),
        other => SqlLogging::parse(other).ok_or_else(|| {
            serde::de::Error::custom(format!(
                "unknown sql_logging {other:?}; expected \"fingerprint\" or \"full\""
            ))
        }),
    }
}

/// Every connection this process can reach.
#[derive(Debug, Clone, Default)]
pub struct Registry {
    connections: BTreeMap<String, ConnectionConfig>,
}

impl Registry {
    /// Read the config file, then register the built-in `@audit` connection over it.
    ///
    /// A missing config file is not an error: it yields a registry holding `@audit`
    /// alone, which is enough to inspect the log on a fresh install.
    pub fn load(config_path: Option<&Path>, audit_db: &Path) -> Result<Self, CoreError> {
        let path = match config_path {
            Some(p) => p.to_path_buf(),
            None => default_config_path()?,
        };

        let mut registry = Registry::default();

        if path.exists() {
            let text = std::fs::read_to_string(&path).map_err(|e| CoreError::Config {
                path: path.clone(),
                detail: e.to_string(),
            })?;
            let file: ConfigFile = toml::from_str(&text).map_err(|e| CoreError::Config {
                path: path.clone(),
                detail: e.to_string(),
            })?;
            for (name, c) in file.connections {
                if name.starts_with('@') {
                    return Err(CoreError::Config {
                        path: path.clone(),
                        detail: format!(
                            "connection {name:?}: names starting with '@' are reserved for \
                             built-in connections"
                        ),
                    });
                }
                registry.connections.insert(
                    name.clone(),
                    ConnectionConfig {
                        name,
                        driver: c.driver,
                        path: c.path,
                        mode: c.mode,
                        sql_logging: c.sql_logging,
                        database: c.database,
                        schema: c.schema,
                        builtin: false,
                    },
                );
            }
        }

        registry
            .connections
            .insert(AUDIT_CONNECTION.to_string(), audit_connection(audit_db));

        Ok(registry)
    }

    /// A registry with no config file behind it. Used by tests and by the audit
    /// subcommands, which need only `@audit`.
    pub fn builtin_only(audit_db: &Path) -> Self {
        let mut connections = BTreeMap::new();
        connections.insert(AUDIT_CONNECTION.to_string(), audit_connection(audit_db));
        Registry { connections }
    }

    pub fn insert(&mut self, cfg: ConnectionConfig) {
        self.connections.insert(cfg.name.clone(), cfg);
    }

    pub fn get(&self, name: &str) -> Option<&ConnectionConfig> {
        self.connections.get(name)
    }

    pub fn names(&self) -> impl Iterator<Item = &str> {
        self.connections.keys().map(String::as_str)
    }

    pub fn iter(&self) -> impl Iterator<Item = &ConnectionConfig> {
        self.connections.values()
    }
}

/// The audit database, registered as an ordinary connection (§5).
///
/// Read-only, because a surface that could write to the log could rewrite it, and
/// `fingerprint`, because queries against the log are queries like any other. Reads of
/// `@audit` are themselves audited — that is the point of shipping it as a connection
/// rather than a second API.
fn audit_connection(audit_db: &Path) -> ConnectionConfig {
    ConnectionConfig {
        name: AUDIT_CONNECTION.to_string(),
        driver: "sqlite".to_string(),
        path: Some(audit_db.to_path_buf()),
        mode: AccessMode::ReadOnly,
        sql_logging: SqlLogging::Fingerprint,
        database: Some("audit".to_string()),
        schema: None,
        builtin: true,
    }
}

/// `$QUOKKA_CONFIG`, else `<XDG config dir>/quokkaquery/config.toml`.
pub fn default_config_path() -> Result<PathBuf, CoreError> {
    if let Some(p) = std::env::var_os("QUOKKA_CONFIG") {
        return Ok(PathBuf::from(p));
    }
    let dirs = directories::ProjectDirs::from("", "", "quokkaquery").ok_or_else(|| {
        CoreError::ConfigPath(
            "no home directory; set QUOKKA_CONFIG to point at a config file".to_string(),
        )
    })?;
    Ok(dirs.config_dir().join("config.toml"))
}

/// The dialect a driver name implies, for connections the engine has not opened yet.
pub fn dialect_hint(driver: &str) -> Dialect {
    match driver {
        "postgres" => Dialect::Postgres,
        "mysql" => Dialect::MySql,
        "athena" => Dialect::Athena,
        _ => Dialect::Sqlite,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn write(dir: &std::path::Path, toml: &str) -> PathBuf {
        let path = dir.join("config.toml");
        std::fs::write(&path, toml).expect("write config");
        path
    }

    #[test]
    fn a_connection_defaults_to_read_only_and_fingerprint() {
        let dir = tempfile::tempdir().expect("tempdir");
        let config = write(
            dir.path(),
            "[connections.app]\ndriver = \"sqlite\"\npath = \"/tmp/app.db\"\n",
        );
        let registry = Registry::load(Some(&config), &dir.path().join("audit.db")).expect("load");

        let app = registry.get("app").expect("app");
        assert_eq!(app.mode, AccessMode::ReadOnly);
        assert_eq!(app.sql_logging, SqlLogging::Fingerprint);
    }

    #[test]
    fn full_logging_must_be_written_down_to_take_effect() {
        let dir = tempfile::tempdir().expect("tempdir");
        let config = write(
            dir.path(),
            "[connections.app]\ndriver = \"sqlite\"\npath = \"/tmp/app.db\"\n\
             sql_logging = \"full\"\nmode = \"read_write\"\n",
        );
        let registry = Registry::load(Some(&config), &dir.path().join("audit.db")).expect("load");

        let app = registry.get("app").expect("app");
        assert_eq!(app.sql_logging, SqlLogging::Full);
        assert_eq!(app.mode, AccessMode::ReadWrite);
    }

    #[test]
    fn redacted_is_refused_by_name_rather_than_ignored() {
        let dir = tempfile::tempdir().expect("tempdir");
        let config = write(
            dir.path(),
            "[connections.app]\ndriver = \"sqlite\"\npath = \"/tmp/app.db\"\n\
             sql_logging = \"redacted\"\n",
        );
        let err = Registry::load(Some(&config), &dir.path().join("audit.db"))
            .expect_err("redacted is an M7 deliverable");
        assert!(
            err.to_string().contains("M7"),
            "the error should say when it arrives: {err}"
        );
    }

    #[test]
    fn the_audit_connection_is_built_in_read_only_and_unshadowable() {
        let dir = tempfile::tempdir().expect("tempdir");
        let audit_db = dir.path().join("audit.db");

        let registry = Registry::load(None, &audit_db).expect("load with no config file");
        let audit = registry.get(AUDIT_CONNECTION).expect("@audit is built in");
        assert_eq!(audit.mode, AccessMode::ReadOnly);
        assert_eq!(audit.path.as_deref(), Some(audit_db.as_path()));
        assert!(audit.builtin);

        let config = write(
            dir.path(),
            "[connections.\"@audit\"]\ndriver = \"sqlite\"\npath = \"/tmp/elsewhere.db\"\n",
        );
        let err = Registry::load(Some(&config), &audit_db)
            .expect_err("a config file must not be able to redirect @audit");
        assert!(err.to_string().contains("reserved"), "{err}");
    }

    #[test]
    fn a_missing_config_file_is_not_an_error() {
        let dir = tempfile::tempdir().expect("tempdir");
        let registry = Registry::load(
            Some(&dir.path().join("nope.toml")),
            &dir.path().join("audit.db"),
        )
        .expect("a fresh install has no config file yet");
        assert_eq!(registry.names().collect::<Vec<_>>(), vec![AUDIT_CONNECTION]);
    }
}
