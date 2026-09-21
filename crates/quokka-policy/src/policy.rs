//! The rules themselves (ARCHITECTURE §6.3).
//!
//! A [`Policy`] is the connection's configuration plus what the caller asked for, and
//! [`Policy::decide`] answers with an [`Outcome`]. It reads nothing, writes nothing and
//! talks to nothing: the caller hands it a [`SqlSummary`] and it hands back a verdict.
//! `quokka-core::execute()` is the only caller, which is what makes the guardrail bind
//! every surface identically (invariant 9) rather than being something a surface
//! remembers to do.

use std::time::Duration;

use crate::analyze::{SqlSummary, TableRef};

/// Whether a connection may be written to.
///
/// The mode binds every surface identically (invariant 9): read-only means read-only
/// for the human at the UI as much as for an agent. Changing it is ordinary human-only
/// configuration (invariant 7) — there is no flag, and no agent-callable tool, that
/// moves a connection from one to the other.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, serde::Serialize, serde::Deserialize)]
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

    /// The stricter of two modes.
    ///
    /// A surface may narrow what a connection allows and may never widen it — which is
    /// what lets `quokka mcp` refuse writes on a `read_write` connection without
    /// becoming the per-surface exemption invariant 9 forbids. An exemption is a surface
    /// that gets *more* than the mode allows; taking less is not one.
    pub fn narrowest(self, other: AccessMode) -> AccessMode {
        if self.is_read_only() || other.is_read_only() {
            AccessMode::ReadOnly
        } else {
            AccessMode::ReadWrite
        }
    }
}

impl std::fmt::Display for AccessMode {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_str())
    }
}

/// Which schemas and tables a connection's statements may name (§6.3).
///
/// Optional and empty by default: a connection with no allowlist is governed by its
/// mode alone. What it governs is *statements* — the SQL a caller wrote. Catalog reads
/// go through `introspect()`, which runs the driver's own bounded SQL and never the
/// caller's, so a table left off this list is still visible to `schema describe`. That
/// is a boundary worth stating rather than implying: this list stops a query, not a
/// listing.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Allowlist {
    schemas: Vec<String>,
    tables: Vec<TablePattern>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct TablePattern {
    schema: Option<String>,
    table: String,
}

impl Allowlist {
    /// No allowlist: the mode alone governs.
    pub fn none() -> Self {
        Allowlist::default()
    }

    /// Build from the config file's two lists.
    ///
    /// An entry is `table` or `schema.table`; anything with more parts is rejected here
    /// rather than silently never matching, because an allowlist entry that matches
    /// nothing is a guardrail the user believes in and does not have.
    pub fn new(
        schemas: impl IntoIterator<Item = String>,
        tables: impl IntoIterator<Item = String>,
    ) -> Result<Self, String> {
        let schemas: Vec<String> = schemas.into_iter().map(|s| lower(s.trim())).collect();
        let mut patterns = Vec::new();
        for entry in tables {
            let entry = entry.trim().to_string();
            let parts: Vec<&str> = entry.split('.').collect();
            let pattern = match parts.as_slice() {
                [table] if !table.is_empty() => TablePattern {
                    schema: None,
                    table: lower(table),
                },
                [schema, table] if !schema.is_empty() && !table.is_empty() => TablePattern {
                    schema: Some(lower(schema)),
                    table: lower(table),
                },
                _ => {
                    return Err(format!(
                        "allow_tables entry {entry:?} is not a table name; write it as \
                         `table` or `schema.table`"
                    ))
                }
            };
            patterns.push(pattern);
        }
        Ok(Allowlist {
            schemas,
            tables: patterns,
        })
    }

    pub fn is_empty(&self) -> bool {
        self.schemas.is_empty() && self.tables.is_empty()
    }

    /// Whether one reference is allowed, given the connection's default schema.
    fn allows(&self, table: &TableRef, default_schema: Option<&str>) -> bool {
        let name = lower(table.name());
        let qualifier = table
            .qualifier()
            .map(lower)
            .or_else(|| default_schema.map(lower));

        let listed_by_table = self.tables.iter().any(|p| {
            p.table == name
                && match (&p.schema, &qualifier) {
                    (None, _) => true,
                    (Some(s), Some(q)) => s == q,
                    (Some(_), None) => false,
                }
        });
        if listed_by_table {
            return true;
        }
        match &qualifier {
            Some(q) => self.schemas.iter().any(|s| s == q),
            None => false,
        }
    }
}

fn lower(s: &str) -> String {
    s.to_ascii_lowercase()
}

/// Server-side caps, as §6.3 puts them: enforced by us, never by trusting a `LIMIT` in
/// the text.
///
/// Both are ceilings a request may lower and may never raise. That direction is the
/// whole point — a cap an agent can raise is a cap it does not have — and it is why
/// these live in the connection's configuration, which is human-only (invariant 7).
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct Limits {
    /// Rows the engine will read before it stops and reports truncation. `None` leaves
    /// the caller's own bound in force.
    pub max_rows: Option<u64>,
    /// How long a statement may run before it is cancelled and logged as `timeout`.
    pub timeout: Option<Duration>,
}

impl Limits {
    /// The row bound to actually use: the lower of what was asked for and what the
    /// connection allows.
    pub fn cap_rows(&self, requested: u64) -> u64 {
        match self.max_rows {
            Some(cap) => requested.min(cap),
            None => requested,
        }
    }

    /// The deadline to actually use: the shorter of the two, and the connection's when
    /// the caller named none.
    pub fn cap_timeout(&self, requested: Option<Duration>) -> Option<Duration> {
        match (self.timeout, requested) {
            (Some(cap), Some(want)) => Some(cap.min(want)),
            (Some(cap), None) => Some(cap),
            (None, want) => want,
        }
    }
}

/// Everything the engine needs in order to decide about one statement.
#[derive(Debug, Clone)]
pub struct Policy<'a> {
    /// The connection's own mode, as its configuration sets it.
    pub mode: AccessMode,
    /// The posture the surface was started with.
    ///
    /// Narrows [`Policy::mode`] and can never widen it. Kept separate rather than
    /// pre-combined so that a denial can say *which* of the two refused — "this
    /// connection is read-only" and "this server is read-only" send a person to
    /// different files.
    pub surface_mode: AccessMode,
    /// The call-site opt-in: `--write` on the CLI, `write: true` over MCP.
    ///
    /// This never widens anything. `mode` is the authorization, set by a human in a
    /// config file; this says the caller *meant* to use it. Both are required (§6.3),
    /// so the flag on its own buys nothing — which is exactly what stops an agent
    /// granting itself a write by asking.
    pub write_requested: bool,
    pub allow: &'a Allowlist,
    /// The connection's `schema`, used to resolve an unqualified table name against the
    /// allowlist.
    pub default_schema: Option<&'a str>,
}

impl<'a> Policy<'a> {
    /// A read-only connection with no allowlist — the default posture of everything.
    pub fn read_only(allow: &'a Allowlist) -> Self {
        Policy {
            mode: AccessMode::ReadOnly,
            surface_mode: AccessMode::ReadWrite,
            write_requested: false,
            allow,
            default_schema: None,
        }
    }

    /// The mode that actually applies: the stricter of the connection's and the
    /// surface's.
    pub fn effective_mode(&self) -> AccessMode {
        self.mode.narrowest(self.surface_mode)
    }

    /// Allow it, or say why not.
    ///
    /// The order of the checks is deliberate: a stacked body is reported as a stacked
    /// body rather than as a write, because that is the thing the caller has to fix.
    pub fn decide(&self, summary: &SqlSummary) -> Outcome {
        if summary.statement_count == 0 {
            return Outcome::Deny(Denial::NothingToRun);
        }
        if summary.statement_count > 1 {
            return Outcome::Deny(Denial::MultipleStatements {
                count: summary.statement_count,
            });
        }

        // Invariant: anything not *certainly* a read is handled as a write. A statement
        // sqlparser could not classify and a statement it classified as a `DELETE` are
        // the same question — "may this connection be written to?" — and answering them
        // with one rule is what keeps the guardrail from having a shape an unusual
        // dialect can slip through.
        if !summary.is_certainly_read_only() {
            let kind = summary.statement_kind.clone();
            let certain = summary.read_only == Some(false);
            if self.effective_mode().is_read_only() {
                return Outcome::Deny(Denial::WriteOnReadOnlyConnection {
                    kind,
                    certain,
                    // Which of the two said no. Both can, and a message that named the
                    // wrong one would send someone to edit a file that already says what
                    // they want it to say.
                    by_surface: !self.mode.is_read_only(),
                });
            }
            if !self.write_requested {
                return Outcome::Deny(Denial::WriteNotOptedIn { kind, certain });
            }
        }

        if !self.allow.is_empty() {
            // An allowlist can only check what the classifier enumerated in full.
            // Text that did not parse names nothing it can see; `DROP TABLE t` names a
            // table sqlparser does not report as a relation; `COPY`, `UNLOAD` and
            // `VACUUM` carry their target somewhere else again. Each of those would
            // otherwise sail past a check that found nothing to object to, so an
            // allowlisted connection admits only the statement kinds whose object list
            // is known to be complete — queries, DML and `EXPLAIN`.
            if !summary.objects_enumerated {
                return Outcome::Deny(Denial::UnknownTables);
            }
            for table in &summary.tables {
                if !self.allow.allows(table, self.default_schema) {
                    return Outcome::Deny(Denial::TableNotAllowed {
                        table: table.to_string(),
                    });
                }
            }
        }

        Outcome::Allow {
            writes: !summary.is_certainly_read_only(),
        }
    }
}

/// What [`Policy::decide`] answered.
#[derive(Debug, Clone, PartialEq)]
pub enum Outcome {
    Allow {
        /// True when the statement was allowed *as a write*, so the engine can record
        /// who authorized it in `approved_by` (§5).
        writes: bool,
    },
    Deny(Denial),
}

impl Outcome {
    pub fn denial(&self) -> Option<&Denial> {
        match self {
            Outcome::Deny(d) => Some(d),
            Outcome::Allow { .. } => None,
        }
    }
}

/// Why a statement was refused.
///
/// Every variant's message names the *rule* and, at most, an identifier. None of them
/// quotes the statement: a denial is logged under the connection's `sql_logging` like
/// any other query (§5.1), and a message that embedded the text would put literals in
/// the log of a `fingerprint` connection by the back door — reachable by anyone who can
/// get a statement denied on purpose.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Denial {
    /// The body holds no statement at all: whitespace, or only a comment.
    NothingToRun,
    /// Stacked statements (§6.3). Rejected whatever they are, and whatever the mode.
    MultipleStatements { count: usize },
    /// A write — or something that could be one — against a `read_only` connection.
    WriteOnReadOnlyConnection {
        kind: Option<String>,
        /// False when the classifier could not read the statement and treated it as a
        /// write on principle.
        certain: bool,
        /// True when the connection allows writes and the *surface* does not — a
        /// `quokka mcp` started without `--allow-writes`, say.
        by_surface: bool,
    },
    /// A write against a `read_write` connection, with no opt-in at the call site.
    WriteNotOptedIn { kind: Option<String>, certain: bool },
    /// The statement names something the connection's allowlist does not.
    TableNotAllowed { table: String },
    /// An allowlist is configured and the statement could not be parsed, so what it
    /// names is unknown.
    UnknownTables,
}

impl Denial {
    /// A stable, machine-readable code for the audit log's `error_code` column and for
    /// a surface's JSON error envelope.
    pub fn code(&self) -> &'static str {
        match self {
            Denial::NothingToRun => "policy.no_statement",
            Denial::MultipleStatements { .. } => "policy.multiple_statements",
            Denial::WriteOnReadOnlyConnection { .. } => "policy.read_only",
            Denial::WriteNotOptedIn { .. } => "policy.write_not_opted_in",
            Denial::TableNotAllowed { .. } => "policy.table_not_allowed",
            Denial::UnknownTables => "policy.unknown_tables",
        }
    }

    /// The sentence a surface shows and the log records, given the connection's name.
    ///
    /// Takes the connection rather than baking it in so that the same denial reads the
    /// same from the CLI, from MCP and from the UI — the mode binds all three, and so
    /// should the wording.
    pub fn explain(&self, connection: &str) -> String {
        match self {
            Denial::NothingToRun => {
                "there is no statement to run here: the text holds only whitespace or a \
                 comment."
                    .to_string()
            }
            Denial::MultipleStatements { count } => format!(
                "refusing a body of {count} statements: QuokkaQuery runs one statement \
                 per query (§6.3). Stacked statements hide writes behind reads and make \
                 the audit log's one-query-two-events record ambiguous. Send them one \
                 at a time. (A statement whose own body holds semicolons — a trigger or \
                 a stored procedure — counts as several here when this build's parser \
                 cannot read it, which is the conservative way round.)"
            ),
            Denial::WriteOnReadOnlyConnection {
                kind,
                certain,
                by_surface: false,
            } => format!(
                "refusing {} on connection {connection:?}, which is \
                 `mode = \"read_only\"`.{} The mode binds every surface identically — the \
                 human at the UI as much as an agent — and it is human-only \
                 configuration: change it in the config file, not from here.",
                describe(kind),
                caveat(*certain),
            ),
            Denial::WriteOnReadOnlyConnection { kind, certain, .. } => format!(
                "refusing {} on connection {connection:?}. The connection allows writes; \
                 this server was started read-only and so refuses them anyway.{} A \
                 surface may be stricter than a connection and never more permissive — \
                 restarting it differently is a human's decision, not one available from \
                 here.",
                describe(kind),
                caveat(*certain),
            ),
            Denial::WriteNotOptedIn { kind, certain } => format!(
                "refusing {} on connection {connection:?}.{} The connection allows \
                 writes, but a write also needs an explicit opt-in at the call site: \
                 `--write` from the CLI, `write: true` over MCP. Two keys, so a \
                 mis-generated statement cannot spend the one a human left in the lock.",
                describe(kind),
                caveat(*certain),
            ),
            Denial::TableNotAllowed { table } => format!(
                "connection {connection:?} has an allowlist and it does not name \
                 {table:?}. Add it to `allow_tables` (or its schema to `allow_schemas`) \
                 in the config file, or qualify the name if the connection has no \
                 default schema."
            ),
            Denial::UnknownTables => format!(
                "connection {connection:?} has an allowlist, and the classifier could \
                 not enumerate every table this statement names — it did not parse, or \
                 it is a kind of statement (DDL, DCL, `COPY`, `VACUUM`) whose target is \
                 not reported as a table reference. An allowlisted connection admits \
                 queries, DML and EXPLAIN, whose object lists are complete. An \
                 allowlist that passed what it could not read would not be one."
            ),
        }
    }
}

fn describe(kind: &Option<String>) -> String {
    match kind {
        Some(k) => {
            let article = match k.chars().next() {
                Some('a' | 'e' | 'i' | 'o' | 'u') => "an",
                _ => "a",
            };
            format!("{article} `{k}` statement")
        }
        None => "a statement this build's parser could not read".to_string(),
    }
}

/// The half-sentence that separates "this is a write" from "this might be".
///
/// Worth spelling out at the point of refusal rather than only in the docs: a user who
/// is told their `SELECT` was refused as a write deserves to know it is because nothing
/// could prove otherwise, not because the tool thinks a `SELECT` writes.
fn caveat(certain: bool) -> &'static str {
    if certain {
        ""
    } else {
        " Nothing could prove it only reads, and anything the classifier cannot prove is \
         a read is handled as a write."
    }
}

impl std::fmt::Display for Denial {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.explain("this connection"))
    }
}
