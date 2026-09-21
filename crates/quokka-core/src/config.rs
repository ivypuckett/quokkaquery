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

/// How old a spool may get before a result tab flags itself stale (§4.1).
///
/// Ephemerality bounds staleness to one process lifetime; it does not eliminate it. A
/// result spooled at 10:00 and read at 10:45 is forty-five minutes old, and a query
/// tool that shows you stale data without saying so has failed at its one job. So a
/// result tab always shows how old its rows are, and past this it says so loudly.
///
/// Thirty minutes because that is roughly when "I ran this a moment ago" stops being
/// true. Nothing re-runs when it expires — §1.4 forbids that — the tab only becomes
/// honest about its age.
pub const DEFAULT_SPOOL_STALE_AFTER: Duration = Duration::from_secs(30 * 60);

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
pub use quokka_policy::{AccessMode, Allowlist, CostGuard, Limits};

/// What an Athena connection needs that the wire-protocol drivers do not (§3.2).
///
/// Its own struct rather than five more `Option`s on [`ConnectionConfig`], because they
/// travel together: a connection either is an Athena connection or has none of them, and
/// [`check`] refuses a `workgroup` on a Postgres connection for exactly that reason.
///
/// Note what is *not* here: a credential. Athena authenticates through the AWS SDK's own
/// chain — an `sso_session` profile in `~/.aws/config` and the token cache `aws sso
/// login` writes — so there is no secret for QuokkaQuery to store. See
/// [`CredentialRef::for_driver`](crate::CredentialRef::for_driver).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AthenaConfig {
    /// The AWS region, e.g. `eu-west-1`. Required: a region-less Athena client fails at
    /// the first call with an SDK error rather than a message about the config file.
    pub region: String,
    /// The named profile in `~/.aws/config` whose credentials to use. `None` leaves the
    /// SDK's default chain — `AWS_PROFILE`, environment credentials, an instance role.
    pub profile: Option<String>,
    /// The workgroup to run in. **Part of the cost story rather than a detail**: §6.4's
    /// layer 1 is the workgroup's `BytesScannedCutoffPerQuery`, which is the only
    /// control that can stop a single query mid-flight.
    pub workgroup: String,
    /// `s3://bucket/prefix/` for query results. Optional, because a workgroup may
    /// enforce its own output location — and when neither does, Athena says so.
    pub output_location: Option<String>,
    /// The data catalog. `AwsDataCatalog` unless a federated catalog is named.
    pub catalog: String,
}

/// The data catalog an Athena connection uses when the config file does not say.
pub const DEFAULT_ATHENA_CATALOG: &str = "AwsDataCatalog";

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
    /// Athena's own settings (§3.2). `Some` exactly for `driver = "athena"`.
    pub athena: Option<AthenaConfig>,
    /// The cumulative cost budget for this connection (§6.4, layer 2).
    ///
    /// `None` — the default — means no budget, and therefore no read of the audit log
    /// before a query runs. Human-only like everything else here (invariant 7): there
    /// is no flag, and no agent-callable tool, that sets or raises one.
    pub cost_guard: Option<CostGuard>,
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
            athena: None,
            cost_guard: None,
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
        if let Some(athena) = &self.athena {
            // What a person needs to recognize the connection, in the order they think
            // about it. No credential appears here because there is none to appear.
            let profile = match &athena.profile {
                Some(p) => format!("{p}@"),
                None => String::new(),
            };
            return format!("{profile}{}/{}", athena.region, athena.workgroup);
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
    /// How old a spool may get before a surface calls it stale (§4.1). `None` when the
    /// config file asked for no staleness flag at all.
    ///
    /// §4.1 names this setting `spool_stale_after`; under `[spool]` it is spelled
    /// `stale_after`, which is the same name with the table's prefix factored out.
    /// Human-only like everything else here: a surface that could extend its own
    /// freshness window would be a surface that decides when its rows stop being old.
    pub stale_after: Option<Duration>,
}

impl Default for SpoolConfig {
    fn default() -> Self {
        Self {
            max_rows: DEFAULT_SPOOL_MAX_ROWS,
            max_bytes: DEFAULT_SPOOL_MAX_BYTES,
            stale_after: Some(DEFAULT_SPOOL_STALE_AFTER),
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
    /// `"30m"`, `"2h"`, or `"0"` to never flag a result as stale (§4.1).
    #[serde(default)]
    stale_after: Option<String>,
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

    // Athena (§3.2). `deny_unknown_fields` on this struct is what makes a typo here a
    // message about the config file rather than an AWS error twenty seconds later —
    // and `check()` below is what makes `workgroup` on a Postgres connection one too.
    /// Athena: the AWS region, e.g. `"eu-west-1"`.
    #[serde(default)]
    region: Option<String>,
    /// Athena: the named profile in `~/.aws/config`. Ordinary configuration rather than
    /// a credential — see `CredentialRef::for_driver`.
    #[serde(default)]
    profile: Option<String>,
    /// Athena: the workgroup to run in, and where §6.4's layer 1 lives.
    #[serde(default)]
    workgroup: Option<String>,
    /// Athena: `"s3://bucket/prefix/"`. Optional when the workgroup enforces one.
    #[serde(default)]
    output_location: Option<String>,
    /// Athena: the data catalog; `"AwsDataCatalog"` unless a federated one is named.
    #[serde(default)]
    catalog: Option<String>,

    /// `[connections.<name>.cost_guard]` (§6.4). Absent means no budget.
    #[serde(default)]
    cost_guard: Option<CostGuardFile>,
}

/// `[connections.x.cost_guard]` as §6.4 spells it.
///
/// Four keys, and the asymmetry between two of them is the point rather than an
/// oversight to tidy away: a person running an expensive query is awake and watching,
/// an agent looping at 3am is the invoice. So agents get a limit and humans get a
/// warning, and there is no `agent_warn` because a warning is a sentence somebody reads.
#[derive(Debug, Clone, Default, Deserialize)]
#[serde(deny_unknown_fields)]
struct CostGuardFile {
    /// The rolling window: `"1d"`, `"12h"`. Defaults to a day.
    #[serde(default)]
    window: Option<String>,
    /// `"50GB"`, or `"unlimited"` for no cap.
    #[serde(default)]
    agent_limit: Option<String>,
    #[serde(default)]
    human_limit: Option<String>,
    /// Where a human is warned rather than stopped.
    #[serde(default)]
    human_warn: Option<String>,
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
    if let Some(text) = &file.stale_after {
        let duration = parse_duration(text).ok_or_else(|| CoreError::Config {
            path: path.to_path_buf(),
            detail: format!(
                "[spool] stale_after {text:?} is not a duration; write it as \"30m\", \
                 \"2h\", or \"0\" to never flag a result as stale"
            ),
        })?;
        // Zero turns the flag off rather than making everything instantly stale, which
        // is the only reading under which the setting is useful at zero.
        spool.stale_after = (!duration.is_zero()).then_some(duration);
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
                // Driver-aware, for one driver: Athena has no password to keep
                // anywhere, so its default is `none` rather than a keyring entry that
                // would never hold anything.
                None => CredentialRef::for_driver(&c.driver, &name),
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

            let athena = athena_config(&c).map_err(&bad)?;
            let cost_guard = match &c.cost_guard {
                Some(file) => Some(cost_guard(file).map_err(&bad)?),
                None => None,
            };

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
                athena,
                cost_guard,
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
        athena: None,
        // No budget on the log itself. Reading your own audit trail is the cheapest
        // query in the program and scans nothing, and a budget here would be a way for
        // a busy connection to stop you reviewing it.
        cost_guard: None,
        builtin: true,
    }
}

/// Assemble an Athena connection's settings, or refuse an Athena setting on a
/// connection that is not one.
///
/// The second half is the part that earns its keep. `deny_unknown_fields` catches
/// `workgrp = "…"`; only this catches `workgroup = "…"` on a Postgres connection, which
/// parses perfectly and means nothing — the setting the user believed in would simply
/// never be read.
fn athena_config(c: &ConnectionFile) -> Result<Option<AthenaConfig>, String> {
    let elsewhere = [
        ("region", c.region.is_some()),
        ("profile", c.profile.is_some()),
        ("workgroup", c.workgroup.is_some()),
        ("output_location", c.output_location.is_some()),
        ("catalog", c.catalog.is_some()),
    ];

    if c.driver != "athena" {
        if let Some((key, _)) = elsewhere.iter().find(|(_, set)| *set) {
            return Err(format!(
                "`{key}` is an athena setting and this connection is `driver = \
                 \"{}\"`, so nothing would ever read it",
                c.driver
            ));
        }
        return Ok(None);
    }

    let region = c.region.clone().ok_or_else(|| {
        "an athena connection needs a `region` (e.g. region = \"eu-west-1\"); without \
         one the AWS SDK fails at the first call rather than here"
            .to_string()
    })?;
    let workgroup = c.workgroup.clone().ok_or_else(|| {
        "an athena connection needs a `workgroup`. Name it explicitly even if it is \
         \"primary\": a workgroup carrying `BytesScannedCutoffPerQuery` is the only \
         control that can stop a single runaway query mid-flight (§6.4), so which one \
         you are in is not a detail to inherit silently"
            .to_string()
    })?;

    if let Some(location) = &c.output_location {
        if !location.starts_with("s3://") {
            return Err(format!(
                "output_location {location:?} is not an S3 URI; write it as \
                 \"s3://bucket/prefix/\""
            ));
        }
    }

    Ok(Some(AthenaConfig {
        region,
        profile: c.profile.clone(),
        workgroup,
        output_location: c.output_location.clone(),
        catalog: c
            .catalog
            .clone()
            .unwrap_or_else(|| DEFAULT_ATHENA_CATALOG.to_string()),
    }))
}

/// Read `[connections.x.cost_guard]` (§6.4).
fn cost_guard(file: &CostGuardFile) -> Result<CostGuard, String> {
    let defaults = CostGuard::default();

    let window = match &file.window {
        Some(text) => {
            let window = parse_duration(text).ok_or_else(|| {
                format!(
                    "cost_guard window {text:?} is not a duration; write it as \"1d\", \
                     \"12h\" or \"30m\""
                )
            })?;
            if window.is_zero() {
                return Err(
                    "cost_guard window = \"0\" would sum nothing at all; remove \
                            the whole [cost_guard] block to have no budget"
                        .to_string(),
                );
            }
            window
        }
        None => defaults.window,
    };

    // A limit is a size, `"unlimited"`, or absent. The last two differ: absent takes
    // §6.4's proposed default for that actor kind, and `"unlimited"` says the person
    // looked at the default and does not want it. Silently treating a missing key as
    // unlimited would hand an agent an uncapped budget by omission.
    let limit = |key: &str, text: &Option<String>, fallback: Option<u64>| match text {
        None => Ok(fallback),
        Some(text) if is_unlimited(text) => Ok(None),
        Some(text) => parse_bytes(text).map(Some).ok_or_else(|| {
            format!(
                "cost_guard {key} {text:?} is not a size; write it as \"50GB\", \
                 \"500GB\", a plain number of bytes, or \"unlimited\""
            )
        }),
    };

    let guard = CostGuard {
        window,
        agent_limit: limit("agent_limit", &file.agent_limit, defaults.agent_limit)?,
        human_limit: limit("human_limit", &file.human_limit, defaults.human_limit)?,
        human_warn: limit("human_warn", &file.human_warn, defaults.human_warn)?,
    };

    // A warning threshold above the limit never fires: the denial arrives first. Said
    // here rather than left to be noticed, because the failure mode is a person
    // believing they will be warned.
    if let (Some(warn), Some(limit)) = (guard.human_warn, guard.human_limit) {
        if warn >= limit {
            return Err(format!(
                "cost_guard human_warn ({warn} bytes) is not below human_limit ({limit} \
                 bytes), so the warning could never appear — the query would be denied \
                 first"
            ));
        }
    }

    Ok(guard)
}

fn is_unlimited(text: &str) -> bool {
    let t = text.trim();
    t.eq_ignore_ascii_case("unlimited") || t.eq_ignore_ascii_case("none")
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
        "athena" => {
            if cfg.path.is_some() || cfg.host.is_some() || cfg.port.is_some() {
                return Err(
                    "an athena connection has no `path`, `host` or `port`; it has a \
                     `region`, a `workgroup` and an `output_location`"
                        .to_string(),
                );
            }
            if cfg.user.is_some() {
                return Err(
                    "an athena connection has no `user`; it authenticates through an AWS \
                     profile — set `profile = \"…\"` and sign in with `aws sso login`"
                        .to_string(),
                );
            }
            if !matches!(cfg.credential, CredentialRef::None) {
                return Err(
                    "an athena connection stores no credential here, so it needs \
                     `credential = \"none\"` (or no `credential` line at all). AWS \
                     credentials come from the SDK's own chain — an `sso_session` \
                     profile in ~/.aws/config and the token cache `aws sso login` \
                     writes — which belongs to the AWS CLI rather than to QuokkaQuery"
                        .to_string(),
                );
            }
            // `region` and `workgroup` are checked while the config is assembled, which
            // is where the value can be turned into the message.
            debug_assert!(cfg.athena.is_some());
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
    fn stale_after_is_a_duration_and_zero_means_never() {
        let dir = tempfile::tempdir().expect("tempdir");
        let audit_db = dir.path().join("audit.db");

        let default = Config::load(None, &audit_db).expect("load").spool;
        assert_eq!(default.stale_after, Some(DEFAULT_SPOOL_STALE_AFTER));

        let config = write(dir.path(), "[spool]\nstale_after = \"5m\"\n");
        let spool = Config::load(Some(&config), &audit_db).expect("load").spool;
        assert_eq!(spool.stale_after, Some(Duration::from_secs(300)));

        let config = write(dir.path(), "[spool]\nstale_after = \"0\"\n");
        let spool = Config::load(Some(&config), &audit_db).expect("load").spool;
        assert_eq!(
            spool.stale_after, None,
            "zero turns the flag off; it does not make every result instantly stale"
        );

        let config = write(dir.path(), "[spool]\nstale_after = \"soon\"\n");
        let err = Config::load(Some(&config), &audit_db).expect_err("not a duration");
        assert!(err.to_string().contains("stale_after"), "{err}");
    }

    // -----------------------------------------------------------------------
    // Athena (§3.2) and the cost guard (§6.4)
    // -----------------------------------------------------------------------

    const ATHENA: &str = "[connections.lake]\n\
                          driver = \"athena\"\n\
                          region = \"eu-west-1\"\n\
                          workgroup = \"quokka\"\n\
                          output_location = \"s3://bucket/results/\"\n\
                          profile = \"analytics\"\n\
                          database = \"analytics\"\n";

    #[test]
    fn an_athena_connection_reads_its_four_settings() {
        let dir = tempfile::tempdir().expect("tempdir");
        let config = write(dir.path(), ATHENA);
        let registry = Registry::load(Some(&config), &dir.path().join("audit.db")).expect("load");

        let lake = registry.get("lake").expect("lake");
        let athena = lake.athena.as_ref().expect("athena settings");
        assert_eq!(athena.region, "eu-west-1");
        assert_eq!(athena.workgroup, "quokka");
        assert_eq!(
            athena.output_location.as_deref(),
            Some("s3://bucket/results/")
        );
        assert_eq!(athena.profile.as_deref(), Some("analytics"));
        assert_eq!(athena.catalog, DEFAULT_ATHENA_CATALOG);
        assert_eq!(lake.dialect(), Dialect::Athena);
        // The AWS profile is ordinary configuration; the SSO token cache belongs to the
        // AWS CLI, so there is no credential for QuokkaQuery to keep.
        assert_eq!(lake.credential, CredentialRef::None);
        // And it stays read-only by default like every other connection (invariant 9).
        assert_eq!(lake.mode, AccessMode::ReadOnly);
    }

    /// The point of teaching `check()` about `athena`: a typo is a message about the
    /// config file rather than an AWS error twenty seconds later.
    #[test]
    fn an_athena_connection_missing_a_required_setting_says_which() {
        let dir = tempfile::tempdir().expect("tempdir");
        let audit_db = dir.path().join("audit.db");

        let cases = [
            (
                "[connections.lake]\ndriver = \"athena\"\nworkgroup = \"quokka\"\n",
                "region",
            ),
            (
                "[connections.lake]\ndriver = \"athena\"\nregion = \"eu-west-1\"\n",
                "workgroup",
            ),
            (
                "[connections.lake]\ndriver = \"athena\"\nregion = \"eu-west-1\"\n\
                 workgroup = \"q\"\nhost = \"athena.example.com\"\n",
                "host",
            ),
            (
                "[connections.lake]\ndriver = \"athena\"\nregion = \"eu-west-1\"\n\
                 workgroup = \"q\"\nuser = \"reader\"\n",
                "user",
            ),
            (
                "[connections.lake]\ndriver = \"athena\"\nregion = \"eu-west-1\"\n\
                 workgroup = \"q\"\noutput_location = \"/tmp/results\"\n",
                "s3://",
            ),
            (
                "[connections.lake]\ndriver = \"athena\"\nregion = \"eu-west-1\"\n\
                 workgroup = \"q\"\ncredential = \"keyring\"\n",
                "credential",
            ),
        ];

        for (toml, needle) in cases {
            let config = write(dir.path(), toml);
            let err = Registry::load(Some(&config), &audit_db)
                .expect_err("this config should be refused");
            assert!(
                err.to_string().contains(needle),
                "the message should name {needle:?}: {err}"
            );
        }
    }

    /// The other half, and the one only `check()` can catch: a setting that parses
    /// perfectly and would never be read.
    #[test]
    fn an_athena_setting_on_another_driver_is_refused_rather_than_ignored() {
        let dir = tempfile::tempdir().expect("tempdir");
        let config = write(
            dir.path(),
            "[connections.prod]\ndriver = \"postgres\"\nhost = \"db\"\n\
             workgroup = \"quokka\"\n",
        );
        let err = Registry::load(Some(&config), &dir.path().join("audit.db"))
            .expect_err("a workgroup on Postgres means nothing");
        assert!(err.to_string().contains("workgroup"), "{err}");
        assert!(err.to_string().contains("postgres"), "{err}");
    }

    /// A misspelled key is caught by `deny_unknown_fields`, which is why the struct has
    /// it — the same protection every other connection setting already had.
    #[test]
    fn a_misspelled_athena_key_is_a_message_about_the_config_file() {
        let dir = tempfile::tempdir().expect("tempdir");
        let config = write(
            dir.path(),
            "[connections.lake]\ndriver = \"athena\"\nregion = \"eu-west-1\"\n\
             work_group = \"quokka\"\n",
        );
        let err = Registry::load(Some(&config), &dir.path().join("audit.db"))
            .expect_err("work_group is not a key");
        assert!(err.to_string().contains("work_group"), "{err}");
    }

    #[test]
    fn a_cost_guard_reads_as_section_6_4_spells_it() {
        let dir = tempfile::tempdir().expect("tempdir");
        let config = write(
            dir.path(),
            "[connections.prod]\ndriver = \"sqlite\"\npath = \"/tmp/a.db\"\n\
             \n\
             [connections.prod.cost_guard]\n\
             window       = \"1d\"\n\
             agent_limit  = \"50GB\"\n\
             human_limit  = \"unlimited\"\n\
             human_warn   = \"500GB\"\n",
        );
        let registry = Registry::load(Some(&config), &dir.path().join("audit.db")).expect("load");
        let guard = registry
            .get("prod")
            .expect("prod")
            .cost_guard
            .expect("a cost guard");

        assert_eq!(guard.window, Duration::from_secs(86_400));
        assert_eq!(guard.agent_limit, Some(50_000_000_000));
        assert_eq!(
            guard.human_limit, None,
            "\"unlimited\" means no cap, which is §6.4's proposed default for a human"
        );
        assert_eq!(guard.human_warn, Some(500_000_000_000));
    }

    /// A connection with no `[cost_guard]` has no budget, which is the default and the
    /// case where nothing is read from the log before a query.
    #[test]
    fn no_cost_guard_block_means_no_budget() {
        let dir = tempfile::tempdir().expect("tempdir");
        let config = write(
            dir.path(),
            "[connections.prod]\ndriver = \"sqlite\"\npath = \"/tmp/a.db\"\n",
        );
        let registry = Registry::load(Some(&config), &dir.path().join("audit.db")).expect("load");
        assert_eq!(registry.get("prod").expect("prod").cost_guard, None);
    }

    /// An omitted key takes §6.4's proposed default rather than silently becoming
    /// unlimited: an agent uncapped by omission is the failure this block exists to
    /// prevent.
    #[test]
    fn an_omitted_limit_takes_the_proposed_default_not_unlimited() {
        let dir = tempfile::tempdir().expect("tempdir");
        let config = write(
            dir.path(),
            "[connections.prod]\ndriver = \"sqlite\"\npath = \"/tmp/a.db\"\n\
             \n[connections.prod.cost_guard]\nwindow = \"12h\"\n",
        );
        let registry = Registry::load(Some(&config), &dir.path().join("audit.db")).expect("load");
        let guard = registry
            .get("prod")
            .expect("prod")
            .cost_guard
            .expect("a cost guard");
        assert_eq!(guard.window, Duration::from_secs(12 * 3600));
        assert_eq!(guard.agent_limit, CostGuard::default().agent_limit);
        assert!(guard.agent_limit.is_some(), "an agent is capped by default");
    }

    #[test]
    fn a_nonsensical_cost_guard_is_refused_with_a_reason() {
        let dir = tempfile::tempdir().expect("tempdir");
        let audit_db = dir.path().join("audit.db");
        let base = "[connections.prod]\ndriver = \"sqlite\"\npath = \"/tmp/a.db\"\n\
                    \n[connections.prod.cost_guard]\n";

        for (extra, needle) in [
            ("agent_limit = \"fifty gigabytes\"\n", "agent_limit"),
            ("window = \"soon\"\n", "window"),
            ("window = \"0\"\n", "window"),
            // A warning above the limit could never appear; a person who set it would
            // believe in a warning they will never get.
            (
                "human_limit = \"100GB\"\nhuman_warn = \"200GB\"\n",
                "human_warn",
            ),
            ("agent_warn = \"1GB\"\n", "agent_warn"),
        ] {
            let config = write(dir.path(), &format!("{base}{extra}"));
            let err = Registry::load(Some(&config), &audit_db).expect_err("should be refused");
            assert!(
                err.to_string().contains(needle),
                "the message should name {needle:?}: {err}"
            );
        }
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
