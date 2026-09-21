//! The connection registry and the file it is read from.
//!
//! Invariant 7: config is human-only. Nothing in this module is writable from a surface,
//! and no CLI flag overrides `sql_logging`, `mode` or a cost budget. An agent that can
//! lower the fidelity of its own audit trail defeats the log's purpose.

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use std::time::Duration;

use quokka_audit::SqlLogging;
use serde::Deserialize;

use crate::credential::CredentialRef;
use crate::error::CoreError;
use crate::value::Dialect;

/// The name of the built-in connection that exposes the audit log itself (§5).
pub const AUDIT_CONNECTION: &str = "@audit";

/// How long a catalog refresh stays fresh before the next one is allowed to query
/// (§3.1). Per-connection, `catalog_ttl` in the config file.
///
/// Sixty seconds is short enough that a migration you just ran shows up and long enough
/// that autocomplete never waits — and a cache *hit* costs nothing at all, including in
/// the log, because nothing reached a database (§5).
pub const DEFAULT_CATALOG_TTL: Duration = Duration::from_secs(60);

/// How many rows a single result may spool before it is truncated (§4.2).
///
/// Bounds local disk rather than anything the user can see: the grid's ceiling is 512
/// and the CLI's preview default is the same, so this number only ever binds an export
/// or a long page-through. Configurable in either direction — unlike the display cap,
/// which is configurable downward only — because what it protects is the disk under
/// the cache directory, and only the person whose disk it is knows how much there is.
pub const DEFAULT_SPOOL_MAX_ROWS: u64 = 1_000_000;

/// How many bytes of row payload a single result may spool before it is truncated
/// (§4.2).
pub const DEFAULT_SPOOL_MAX_BYTES: u64 = 1024 * 1024 * 1024;

/// How long a connection attempt may keep trying before it is called a failure.
///
/// sqlx's pool retries a refused or unreachable server until its acquire timeout, which
/// defaults to thirty seconds. That is sensible for a long-lived service riding out a
/// restart and wrong for a CLI: a typo in `host` should be a message, not half a minute
/// of silence. Ten seconds is long enough to cross a slow VPN and short enough to feel
/// like an answer.
pub const DEFAULT_CONNECT_TIMEOUT: Duration = Duration::from_secs(10);

/// What TLS the driver asks for on a network connection.
///
/// The names are libpq's, because that is the vocabulary anyone configuring a Postgres
/// client already has. `prefer` is the default for the same reason it is libpq's: a
/// local development database with no TLS at all must still connect, and a tool that
/// refused would be uninstalled rather than configured.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, serde::Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum TlsMode {
    Disable,
    #[default]
    Prefer,
    Require,
    VerifyCa,
    VerifyFull,
}

impl TlsMode {
    pub fn as_str(self) -> &'static str {
        match self {
            TlsMode::Disable => "disable",
            TlsMode::Prefer => "prefer",
            TlsMode::Require => "require",
            TlsMode::VerifyCa => "verify-ca",
            TlsMode::VerifyFull => "verify-full",
        }
    }
}

/// Whether a connection may be written to, and the guardrails that ride with it, live
/// in `quokka-policy` — the crate `execute()` consults before it issues a permit — and
/// are re-exported here so `quokka_core::AccessMode` still resolves.
pub use quokka_policy::{AccessMode, Allowlist, Limits};

/// One configured connection.
///
/// Note what is *not* here: a password. The config file holds a [`CredentialRef`] — the
/// name of a keyring entry or an environment variable — and the value is fetched inside
/// a driver's `connect` as a [`Secret`](crate::Secret), which cannot be printed or
/// serialized (§5). That is why this struct can derive `Debug` and be handed to
/// `quokka connections list` without a redaction pass.
#[derive(Debug, Clone, PartialEq)]
pub struct ConnectionConfig {
    pub name: String,
    /// Matches a [`crate::DriverFactory::name`], e.g. `"sqlite"`.
    pub driver: String,
    /// SQLite: the database file.
    pub path: Option<PathBuf>,
    /// Postgres / MySQL: the server. A value starting with `/` is a unix socket
    /// directory rather than a hostname.
    pub host: Option<String>,
    /// Defaults to the driver's standard port when absent.
    pub port: Option<u16>,
    /// The login role. Defaults to the OS user for the wire-protocol drivers.
    pub user: Option<String>,
    /// Where the password lives — never the password.
    pub credential: CredentialRef,
    pub tls: TlsMode,
    pub mode: AccessMode,
    pub sql_logging: SqlLogging,
    /// Server-side caps on rows and time (§6.3), which a request may lower and never
    /// raise. Human-only, like everything else here (invariant 7): a cap an agent can
    /// raise is a cap it does not have.
    pub limits: Limits,
    /// Which schemas and tables this connection's statements may name (§6.3). Empty by
    /// default, in which case the mode alone governs.
    pub allow: Allowlist,
    /// Recorded on every audit row for this connection, and, for the wire-protocol
    /// drivers, the database actually connected to.
    pub database: Option<String>,
    pub schema: Option<String>,
    /// How long a catalog refresh stays fresh (§3.1).
    pub catalog_ttl: Duration,
    /// How long to keep trying to connect before reporting a failure.
    pub connect_timeout: Duration,
    /// True for `@audit`, which the registry supplies rather than the config file.
    pub builtin: bool,
}

impl ConnectionConfig {
    /// A connection with everything at its default: read-only, `fingerprint`, its own
    /// name in the keyring, and no network details.
    ///
    /// Invariants 8 and 9 both live in this function — a connection that says nothing is
    /// the safe one — so a caller building a config by hand cannot accidentally opt out
    /// of either by forgetting a field.
    pub fn new(name: impl Into<String>, driver: impl Into<String>) -> Self {
        let name = name.into();
        let credential = CredentialRef::default_for(&name);
        Self {
            name,
            driver: driver.into(),
            path: None,
            host: None,
            port: None,
            user: None,
            credential,
            tls: TlsMode::default(),
            mode: AccessMode::default(),
            sql_logging: SqlLogging::default(),
            limits: Limits::default(),
            allow: Allowlist::none(),
            database: None,
            schema: None,
            catalog_ttl: DEFAULT_CATALOG_TTL,
            connect_timeout: DEFAULT_CONNECT_TIMEOUT,
            builtin: false,
        }
    }

    /// The port to dial: what was configured, else the driver's standard one.
    pub fn effective_port(&self) -> Option<u16> {
        self.port.or_else(|| default_port(&self.driver))
    }

    /// The dialect implied by the driver name.
    pub fn dialect(&self) -> Dialect {
        dialect_hint(&self.driver)
    }

    /// A human-readable target, for error messages and `connections list`.
    ///
    /// Assembled from the parts rather than from a DSN on purpose: there is no string
    /// anywhere in this program that holds both the host and the password, so none can
    /// leak into a log line (§5, and the M1 trap that a sqlx connection error can carry
    /// a DSN).
    pub fn target(&self) -> String {
        if let Some(path) = &self.path {
            return path.display().to_string();
        }
        let Some(host) = &self.host else {
            return self.name.clone();
        };
        let user = self.user.as_deref().unwrap_or("");
        let at = if user.is_empty() { "" } else { "@" };
        let port = match self.effective_port() {
            Some(p) => format!(":{p}"),
            None => String::new(),
        };
        let database = match &self.database {
            Some(d) => format!("/{d}"),
            None => String::new(),
        };
        format!("{user}{at}{host}{port}{database}")
    }
}

/// The port a driver uses when the config file does not say.
pub fn default_port(driver: &str) -> Option<u16> {
    match driver {
        "postgres" => Some(5432),
        "mysql" => Some(3306),
        _ => None,
    }
}

/// The spool's limits, as `[spool]` in the config file sets them (§4.2).
///
/// Human-only, like everything else in this module (invariant 7). There is no flag that
/// raises them, not because raising them is dangerous but because a spool that grows
/// past the disk it lives on is a problem for the person at the machine, not for the
/// agent that asked for the rows.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SpoolConfig {
    pub max_rows: u64,
    pub max_bytes: u64,
}

impl Default for SpoolConfig {
    fn default() -> Self {
        Self {
            max_rows: DEFAULT_SPOOL_MAX_ROWS,
            max_bytes: DEFAULT_SPOOL_MAX_BYTES,
        }
    }
}

/// `[spool]` as the TOML file spells it.
#[derive(Debug, Clone, Default, Deserialize)]
#[serde(deny_unknown_fields)]
struct SpoolFile {
    #[serde(default)]
    max_rows: Option<u64>,
    /// `"1GiB"`, `"512MB"`, or a plain byte count.
    #[serde(default)]
    max_bytes: Option<String>,
}

/// A connection as the TOML file spells it.
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
struct ConnectionFile {
    driver: String,
    #[serde(default)]
    path: Option<PathBuf>,
    #[serde(default)]
    host: Option<String>,
    #[serde(default)]
    port: Option<u16>,
    #[serde(default)]
    user: Option<String>,
    /// `keyring` | `keyring:<service>/<account>` | `env:<VAR>` | `none`.
    /// Absent means this connection's own name in the default keyring service.
    #[serde(default)]
    credential: Option<String>,
    #[serde(default)]
    tls: TlsMode,
    #[serde(default)]
    mode: AccessMode,
    /// `fingerprint` unless the connection opted in — invariant 8.
    #[serde(default, deserialize_with = "de_sql_logging")]
    sql_logging: SqlLogging,
    /// Most rows any one query on this connection may read. A request may ask for
    /// fewer and can never ask for more.
    #[serde(default)]
    max_rows: Option<u64>,
    /// How long a statement may run before it is cancelled. `"30s"`, `"5m"`.
    #[serde(default)]
    timeout: Option<String>,
    /// Schemas this connection's statements may name. Empty means no allowlist.
    #[serde(default)]
    allow_schemas: Vec<String>,
    /// Tables this connection's statements may name, as `table` or `schema.table`.
    #[serde(default)]
    allow_tables: Vec<String>,
    #[serde(default)]
    database: Option<String>,
    #[serde(default)]
    schema: Option<String>,
    /// `"60s"`, `"5m"`, `"0"` to cache nothing.
    #[serde(default)]
    catalog_ttl: Option<String>,
    /// `"10s"` by default.
    #[serde(default)]
    connect_timeout: Option<String>,
}

#[derive(Debug, Clone, Default, Deserialize)]
#[serde(deny_unknown_fields)]
struct ConfigFile {
    #[serde(default)]
    connections: BTreeMap<String, ConnectionFile>,
    #[serde(default)]
    spool: SpoolFile,
}

/// Everything the config file says: the connections, and the settings that are not
/// per-connection.
#[derive(Debug, Clone, Default)]
pub struct Config {
    pub registry: Registry,
    pub spool: SpoolConfig,
}

impl Config {
    /// Read the config file once, for both halves of what it holds.
    pub fn load(config_path: Option<&Path>, audit_db: &Path) -> Result<Self, CoreError> {
        let path = match config_path {
            Some(p) => p.to_path_buf(),
            None => default_config_path()?,
        };

        let file = read_config_file(&path)?;
        let spool = spool_config(&path, &file.spool)?;
        let mut registry = Registry::from_file(&path, file.connections)?;
        // Registered over the file, so a config that tried to name a connection
        // `@audit` could not shadow the log. (It cannot try: the loop above refuses
        // every name starting with '@'.)
        registry.insert(audit_connection(audit_db));

        Ok(Config { registry, spool })
    }
}

fn read_config_file(path: &Path) -> Result<ConfigFile, CoreError> {
    if !path.exists() {
        return Ok(ConfigFile::default());
    }
    let text = std::fs::read_to_string(path).map_err(|e| CoreError::Config {
        path: path.to_path_buf(),
        detail: e.to_string(),
    })?;
    toml::from_str(&text).map_err(|e| CoreError::Config {
        path: path.to_path_buf(),
        detail: e.to_string(),
    })
}

fn spool_config(path: &Path, file: &SpoolFile) -> Result<SpoolConfig, CoreError> {
    let mut spool = SpoolConfig::default();
    if let Some(rows) = file.max_rows {
        if rows == 0 {
            return Err(CoreError::Config {
                path: path.to_path_buf(),
                detail: "[spool] max_rows = 0 would spool nothing at all; remove the \
                         setting to use the default"
                    .to_string(),
            });
        }
        spool.max_rows = rows;
    }
    if let Some(text) = &file.max_bytes {
        spool.max_bytes = parse_bytes(text).ok_or_else(|| CoreError::Config {
            path: path.to_path_buf(),
            detail: format!(
                "[spool] max_bytes {text:?} is not a size; write it as \"1GiB\", \
                 \"512MB\" or a plain number of bytes"
            ),
        })?;
    }
    Ok(spool)
}

/// `"1GiB"`, `"512MB"`, `"1048576"`. Both the binary and the decimal spellings, because
/// people write both and guessing which one they meant is worse than accepting each.
fn parse_bytes(text: &str) -> Option<u64> {
    let t = text.trim();
    let (number, unit) = match t.find(|c: char| !c.is_ascii_digit() && c != '.') {
        Some(i) => (t[..i].trim(), t[i..].trim().to_ascii_lowercase()),
        None => (t, String::new()),
    };
    let n: f64 = number.parse().ok()?;
    if n < 0.0 {
        return None;
    }
    let scale: f64 = match unit.as_str() {
        "" | "b" => 1.0,
        "k" | "kb" => 1e3,
        "kib" => 1024.0,
        "m" | "mb" => 1e6,
        "mib" => 1024.0 * 1024.0,
        "g" | "gb" => 1e9,
        "gib" => 1024.0 * 1024.0 * 1024.0,
        "t" | "tb" => 1e12,
        "tib" => 1024.0 * 1024.0 * 1024.0 * 1024.0,
        _ => return None,
    };
    let bytes = n * scale;
    if !bytes.is_finite() || bytes < 1.0 || bytes > u64::MAX as f64 {
        return None;
    }
    Some(bytes as u64)
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
    /// Read the config file's connections, then register the built-in `@audit`
    /// connection over them.
    ///
    /// A missing config file is not an error: it yields a registry holding `@audit`
    /// alone, which is enough to inspect the log on a fresh install.
    ///
    /// Callers that also need the settings outside `[connections]` — the spool's limits
    /// — read the file once with [`Config::load`] instead.
    pub fn load(config_path: Option<&Path>, audit_db: &Path) -> Result<Self, CoreError> {
        Ok(Config::load(config_path, audit_db)?.registry)
    }

    fn from_file(
        path: &Path,
        connections: BTreeMap<String, ConnectionFile>,
    ) -> Result<Self, CoreError> {
        let mut registry = Registry::default();

        for (name, c) in connections {
            if name.starts_with('@') {
                return Err(CoreError::Config {
                    path: path.to_path_buf(),
                    detail: format!(
                        "connection {name:?}: names starting with '@' are reserved for \
                         built-in connections"
                    ),
                });
            }
            let bad = |detail: String| CoreError::Config {
                path: path.to_path_buf(),
                detail: format!("connection {name:?}: {detail}"),
            };

            let credential = match &c.credential {
                Some(text) => CredentialRef::parse(text, &name).map_err(|e| bad(e.to_string()))?,
                None => CredentialRef::default_for(&name),
            };
            let catalog_ttl = match &c.catalog_ttl {
                Some(text) => parse_duration(text).ok_or_else(|| {
                    bad(format!(
                        "catalog_ttl {text:?} is not a duration; write it as \"60s\", \
                         \"5m\", \"1h\", or \"0\" to cache nothing"
                    ))
                })?,
                None => DEFAULT_CATALOG_TTL,
            };
            let connect_timeout = match &c.connect_timeout {
                Some(text) => parse_duration(text).ok_or_else(|| {
                    bad(format!(
                        "connect_timeout {text:?} is not a duration; write it as \"10s\" \
                         or \"1m\""
                    ))
                })?,
                None => DEFAULT_CONNECT_TIMEOUT,
            };

            let timeout = match &c.timeout {
                Some(text) => Some(parse_duration(text).ok_or_else(|| {
                    bad(format!(
                        "timeout {text:?} is not a duration; write it as \"30s\", \"5m\" \
                         or \"1h\""
                    ))
                })?),
                None => None,
            };
            if c.max_rows == Some(0) {
                return Err(bad(
                    "max_rows = 0 would read nothing at all; remove the setting to leave \
                     the caller's own bound in force"
                        .to_string(),
                ));
            }
            let allow =
                Allowlist::new(c.allow_schemas.clone(), c.allow_tables.clone()).map_err(bad)?;

            let cfg = ConnectionConfig {
                name: name.clone(),
                driver: c.driver,
                path: c.path,
                host: c.host,
                port: c.port,
                user: c.user,
                credential,
                tls: c.tls,
                mode: c.mode,
                sql_logging: c.sql_logging,
                limits: Limits {
                    max_rows: c.max_rows,
                    timeout,
                },
                allow,
                database: c.database,
                schema: c.schema,
                catalog_ttl,
                connect_timeout,
                builtin: false,
            };
            if let Err(detail) = check(&cfg) {
                return Err(bad(detail));
            }

            registry.connections.insert(name, cfg);
        }

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
        host: None,
        port: None,
        user: None,
        // Invariant: `@audit` stays SQLite and read-only however many drivers exist, so
        // it has nothing to authenticate to and nothing to look up.
        credential: CredentialRef::None,
        tls: TlsMode::Disable,
        mode: AccessMode::ReadOnly,
        sql_logging: SqlLogging::Fingerprint,
        // No caps and no allowlist: reading the log is the cheapest query in the
        // program, and an allowlist over `audit_log` and `queries` would only stop
        // someone reviewing their own trail.
        limits: Limits::default(),
        allow: Allowlist::none(),
        database: Some("audit".to_string()),
        schema: None,
        catalog_ttl: DEFAULT_CATALOG_TTL,
        connect_timeout: DEFAULT_CONNECT_TIMEOUT,
        builtin: true,
    }
}

/// What a connection must have for its driver to stand a chance.
///
/// Caught here rather than at connect time so that a typo in the config file is a
/// message about the config file, not a connection error twenty seconds later.
fn check(cfg: &ConnectionConfig) -> Result<(), String> {
    match cfg.driver.as_str() {
        "sqlite" => {
            if cfg.path.is_none() {
                return Err("a sqlite connection needs `path` to a database file".to_string());
            }
            if cfg.host.is_some() {
                return Err("a sqlite connection has no `host`; it has a `path`".to_string());
            }
        }
        "postgres" | "mysql" => {
            if cfg.host.is_none() {
                return Err(format!(
                    "a {} connection needs a `host` (a path starting with `/` means a \
                     unix socket directory)",
                    cfg.driver
                ));
            }
            if cfg.path.is_some() {
                return Err(format!(
                    "a {} connection has no `path`; set `host`, `port`, `database` and \
                     `user` instead",
                    cfg.driver
                ));
            }
        }
        // An unknown driver is the engine's error to report, with the list of what this
        // build includes. Guessing at its required fields here would be worse.
        _ => {}
    }
    Ok(())
}

/// `"90s"`, `"5m"`, `"2h"`, or a bare number of seconds. `0` disables caching.
fn parse_duration(text: &str) -> Option<Duration> {
    let text = text.trim();
    let (digits, scale) = match text.strip_suffix(|c: char| c.is_ascii_alphabetic()) {
        Some(rest) => {
            let unit = &text[rest.len()..];
            let scale = match unit {
                "s" => 1,
                "m" => 60,
                "h" => 3600,
                "d" => 86_400,
                _ => return None,
            };
            (rest, scale)
        }
        None => (text, 1),
    };
    let n: u64 = digits.trim().parse().ok()?;
    Some(Duration::from_secs(n.checked_mul(scale)?))
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
