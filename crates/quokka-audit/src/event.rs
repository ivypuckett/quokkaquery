//! The vocabulary of the audit log.
//!
//! These types live here rather than in `quokka-core` because `quokka-audit` is the
//! bottom of the dependency graph: `quokka-core` depends on it so that `execute()` can
//! append events, so the log's own vocabulary cannot be borrowed from above.

use std::fmt;

use uuid::Uuid;

/// What a single row of `audit_log` records.
///
/// A query writes exactly two of these — [`EventKind::QueryStarted`] before execution
/// and [`EventKind::QueryFinished`] after — sharing one `query_id` (ARCHITECTURE §5).
/// They are never collapsed into one mutable row, because the table is append-only.
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum EventKind {
    QueryStarted,
    QueryFinished,
    /// One per catalog refresh, appended after the fact (§5).
    ///
    /// Not a query pair: introspection runs the driver's own bounded SQL on a TTL, so
    /// there is no outcome to hold open and no caller statement to record having
    /// attempted. Emitted from M1, when introspection exists.
    Introspect,
    Export,
    Connect,
    Auth,
    Scrub,
}

impl EventKind {
    pub fn as_str(self) -> &'static str {
        match self {
            EventKind::QueryStarted => "query_started",
            EventKind::QueryFinished => "query_finished",
            EventKind::Introspect => "introspect",
            EventKind::Export => "export",
            EventKind::Connect => "connect",
            EventKind::Auth => "auth",
            EventKind::Scrub => "scrub",
        }
    }

    pub fn parse(s: &str) -> Option<Self> {
        Some(match s {
            "query_started" => EventKind::QueryStarted,
            "query_finished" => EventKind::QueryFinished,
            "introspect" => EventKind::Introspect,
            "export" => EventKind::Export,
            "connect" => EventKind::Connect,
            "auth" => EventKind::Auth,
            "scrub" => EventKind::Scrub,
            _ => return None,
        })
    }
}

impl fmt::Display for EventKind {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

/// How an event ended.
///
/// `Started` exists because `status` is `NOT NULL` and a `query_started` row has no
/// outcome yet; the remaining variants are the outcomes ARCHITECTURE §5 enumerates.
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Status {
    Started,
    Ok,
    Error,
    Cancelled,
    Denied,
    Timeout,
}

impl Status {
    pub fn as_str(self) -> &'static str {
        match self {
            Status::Started => "started",
            Status::Ok => "ok",
            Status::Error => "error",
            Status::Cancelled => "cancelled",
            Status::Denied => "denied",
            Status::Timeout => "timeout",
        }
    }

    pub fn parse(s: &str) -> Option<Self> {
        Some(match s {
            "started" => Status::Started,
            "ok" => Status::Ok,
            "error" => Status::Error,
            "cancelled" => Status::Cancelled,
            "denied" => Status::Denied,
            "timeout" => Status::Timeout,
            _ => return None,
        })
    }
}

impl fmt::Display for Status {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

/// Per-connection SQL logging fidelity (ARCHITECTURE §5.1).
///
/// `fingerprint` is the default because literals are PII; `full` is opt-in, chosen
/// explicitly when a connection is created. `redacted` is an M7 deliverable and is
/// deliberately absent: the column tolerates the value, this enum does not yet produce it.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SqlLogging {
    /// Normalized shape, literals replaced by `?`.
    #[default]
    Fingerprint,
    /// The query verbatim, literals included.
    Full,
}

impl SqlLogging {
    pub fn as_str(self) -> &'static str {
        match self {
            SqlLogging::Fingerprint => "fingerprint",
            SqlLogging::Full => "full",
        }
    }

    pub fn parse(s: &str) -> Option<Self> {
        Some(match s {
            "fingerprint" => SqlLogging::Fingerprint,
            "full" => SqlLogging::Full,
            _ => return None,
        })
    }

    /// Whether `sql_text` may be written at all. At `fingerprint` the column stays NULL.
    pub fn stores_sql_text(self) -> bool {
        matches!(self, SqlLogging::Full)
    }
}

impl fmt::Display for SqlLogging {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

/// Who ran the query. Budgets and review both key off this (ARCHITECTURE §6.4).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ActorKind {
    #[default]
    Human,
    Agent,
    Automation,
}

impl ActorKind {
    pub fn as_str(self) -> &'static str {
        match self {
            ActorKind::Human => "human",
            ActorKind::Agent => "agent",
            ActorKind::Automation => "automation",
        }
    }

    pub fn parse(s: &str) -> Option<Self> {
        Some(match s {
            "human" => ActorKind::Human,
            "agent" => ActorKind::Agent,
            "automation" => ActorKind::Automation,
            _ => return None,
        })
    }
}

impl fmt::Display for ActorKind {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

/// Which surface issued the query.
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Client {
    Cli,
    Ui,
    Mcp,
}

impl Client {
    pub fn as_str(self) -> &'static str {
        match self {
            Client::Cli => "cli",
            Client::Ui => "ui",
            Client::Mcp => "mcp",
        }
    }

    pub fn parse(s: &str) -> Option<Self> {
        Some(match s {
            "cli" => Client::Cli,
            "ui" => Client::Ui,
            "mcp" => Client::Mcp,
            _ => return None,
        })
    }
}

impl fmt::Display for Client {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

/// One row of `audit_log`, minus the chain columns the log computes on append.
///
/// There are no result-data fields here, and there never will be: the log records that a
/// query ran, by whom, against what, and how it went — never what came back (§5.1).
#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
pub struct AuditEvent {
    pub id: Uuid,
    pub query_id: Uuid,
    pub parent_id: Option<Uuid>,
    pub at: String,
    pub duration_ms: Option<i64>,

    pub actor_kind: ActorKind,
    pub actor_id: String,
    pub session_id: String,
    pub client: Client,

    pub connection: String,
    pub dialect: String,
    pub database: Option<String>,
    pub schema_name: Option<String>,

    pub event_kind: EventKind,
    pub sql_logging: SqlLogging,
    pub sql_text: Option<String>,
    pub sql_fingerprint: String,
    pub statement_kind: Option<String>,
    pub read_only: Option<bool>,
    pub params: Option<String>,

    pub status: Status,
    pub error_code: Option<String>,
    pub error_message: Option<String>,

    pub rows_returned: Option<i64>,
    pub rows_affected: Option<i64>,
    pub rows_spooled: Option<i64>,
    pub truncated: Option<bool>,
    pub export_format: Option<String>,
    pub export_path: Option<String>,
    pub data_scanned_bytes: Option<i64>,
    pub cost_estimate_usd: Option<f64>,

    pub approved_by: Option<String>,
    pub tags: Option<String>,
}

/// An [`AuditEvent`] as it came back out of the database, with its chain columns.
#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
pub struct StoredEvent {
    #[serde(flatten)]
    pub event: AuditEvent,
    pub prev_hash: Option<String>,
    pub row_hash: String,
}
