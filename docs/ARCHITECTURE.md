# QuokkaQuery — Architecture

A free, open-source database management platform: **a CLI for agents, a native UI for
humans, and one audit trail of every query that both can query.**

Targets SQLite, PostgreSQL, MySQL and Amazon Athena (SSO credentials). Cross-platform and
installable with `cargo install`.

---

## 1. Guiding constraints

| Constraint | Consequence |
| --- | --- |
| Agents and humans are first-class, equally | One core engine; CLI, UI and MCP are thin surfaces over it |
| Every query is audited | Exactly one code path may execute SQL, so there is one place the record is written |
| The audit trail must be queryable by both | Store it in SQLite and expose it as a normal connection (`@audit`) |
| Distributable without a notarized app bundle | Ship a plain binary, never a browser-downloaded `.app`/`.dmg` |
| Distributable via Cargo | Pure Rust, no JS toolchain, no system webview |
| **Promise only what we're good at** | A bounded, excellent result viewer plus first-class export — not a spreadsheet |
| **No query runs without consent** | Queries cost money and touch production; nothing executes implicitly (§1.4) |
| Single user, local only | One person and their agents on one machine. No server, no shared state, no accounts |

### 1.1 macOS quarantine follows the distribution channel, not the toolkit

`com.apple.quarantine` is an extended attribute set by quarantine-aware downloaders
(browsers, Mail, Messages, AirDrop). Gatekeeper's notarization check applies only to files
carrying that attribute. It does **not** apply to:

- `cargo install quokkaquery` — compiled locally, never quarantined;
- a Homebrew **formula** — installed by curl, which does not set the attribute
  (a Homebrew **cask** does apply quarantine by default, so we ship a formula);
- a `curl | sh` tarball installer — same reason.

This is a property of how the file arrives, not of what built it. A native GUI is
therefore straightforward to distribute as long as we never ship a browser-downloaded app
bundle.

Two related notes:

- arm64 macOS requires at least an *ad-hoc* signature to execute. Building on GitHub's
  macOS runners applies one via the linker automatically; `rcodesign` covers it if we ever
  cross-compile from Linux. Ad-hoc signing is unrelated to notarization.
- A bare executable with no `.app` bundle has no `Info.plist`: generic Dock icon, the
  menu bar shows the executable name, no file associations. Cosmetic for this tool. The
  one to watch is TCC — reading SQLite files under protected paths like `~/Library` may
  need Full Disk Access, which is granted to the binary rather than declared in a plist.

### 1.2 Why iced

`iced` 0.14 is pure Rust, renders via `wgpu` with a `tiny-skia` software fallback for
VMs and older hardware, and produces an ordinary executable. Concretely it means:

- **No JS toolchain.** No npm at package time, no pre-built web assets smuggled into the
  crate tarball, no `build.rs` conditional. `cargo install quokkaquery` just works — this
  was the sharpest practical problem with an embedded web UI.
- **No local HTTP server.** No listening socket, no session token, no origin checks, no
  CORS. An entire security surface stops existing.
- **No system webview.** Tauri's `webkit2gtk` dependency on Linux is what makes static
  binaries and `cargo install` awkward there.

What we give up, stated honestly:

- **Remote and headless use.** A native window does not work over an SSH port-forward or
  in a devcontainer. Mitigation: the CLI is the first-class remote interface, and stays
  fully featured. A `quokka ui --serve` web mode remains possible later behind the same core.
- **Accessibility.** iced's AccessKit integration is partial; screen reader support is
  well behind the browser. Mitigation: design keyboard-first, document the gap plainly.
- **Widget maturity.** Which §1.3 turns from a cost into a constraint.

### 1.3 Scope discipline — what QuokkaQuery is not

The UI promises a bounded set of things and does them well:

- **The grid shows one page — 512 rows, and that is a hard ceiling.** Page size is
  configurable downward, never upward. Because the grid never holds more than a page, we
  never build a virtualized million-row table. This deletes the single hardest widget in
  the project.
- **The full dataset goes to a file.** Export is first-class, streamed, and never capped
  by what the screen can hold. "Show me a page, give me the file" is the contract.
- **No inline cell editing.** Not a widget we're avoiding — a stance. Inline editing
  generates hidden `UPDATE`s, which is precisely what an audit-first tool should not do.
  Writes are SQL you can read, review and find in the log.
- **No ER diagrams, no visual query builder, no data modelling.** DBeaver does those.
  We do queries, agents, and an audit trail.

The README should say this in the first paragraph. Being narrow and honest about it is a
feature of the product, not an apology for it.

### 1.4 No query runs without consent

Every query may cost money — Athena bills by data scanned — and every query touches
production. So the tool never issues one the user did not ask for:

- No auto-refresh, no background polling, no periodic re-runs of an open result.
- No speculative prefetch. Paging reads the spool, which is already paid for, and never
  reaches the database.
- Autocomplete reads the cached catalog; it never queries to fill a suggestion. Refreshing
  the catalog is an explicit action.
- A stale result tab offers a re-run control. It does not re-run itself.
- `quokka export --query-id <id>` requires an explicit `--rerun`, because the spool is
  gone and producing the file means paying for the scan a second time. Without the flag it
  errors and explains why.
- Result diffing, if built, is an explicit action on an explicit second run — never an
  automatic refresh behind a diff view.

This binds the agent surfaces too: the MCP server exposes no tool that re-executes
implicitly, and a cost-bearing re-run is always a distinct, audited call.

---

## 2. Workspace layout

The published package is `quokkaquery`; the binary it installs is `quokka`. (The bare
`quokka` name on crates.io belongs to an unrelated crate, which constrains the package
name only, not the binary.)

```
crates/
  quokka-core     Value/Row types, connection registry, config, secret redaction
  quokka-driver   `trait Driver` + sqlite / postgres / mysql / athena impls
  quokka-spool    result cache: one execution -> paging, sorting, export (§4)
  quokka-audit    append-only SQLite log: schema, hash chain, search API
  quokka-policy   sqlparser-based statement classification and guardrails
  quokka-cli      clap CLI — the human and agent entry point (bin: `quokka`)
  quokka-mcp      stdio MCP server (rmcp) for agent clients
  quokka-ui       iced application (feature-gated, default on)
```

There is no HTTP server crate. Every surface calls `quokka-core::execute()`, which
consults `quokka-policy`, dispatches to a `Driver`, spools the result, and writes to
`quokka-audit`. There is no way to run SQL that skips it.

`quokka-ui` sits behind a default-on `ui` feature. `cargo install quokkaquery
--no-default-features` yields a lean headless CLI with no `wgpu`/`winit` dependency tree —
which is what you want in a container, in CI, or on an agent's box.

### 2.1 The driver trait

```rust
#[async_trait]
pub trait Driver: Send + Sync {
    fn dialect(&self) -> Dialect;
    async fn connect(cfg: &ConnectionConfig) -> Result<Self> where Self: Sized;
    async fn introspect(&self, scope: Scope) -> Result<Catalog>;
    async fn execute(&self, req: QueryRequest) -> Result<QueryStream>;
    async fn cancel(&self, handle: QueryHandle) -> Result<()>;
    async fn explain(&self, sql: &str) -> Result<Plan>;
}
```

`QueryStream` yields batches of `Row(Vec<Value>)` plus a `ResultMeta` carrying rows
affected, bytes scanned, and engine timings. Rows use a plain `Value` enum rather than
Arrow — simpler, and Athena returns everything as strings anyway.

Cancellation is in the trait from day one: a runaway Athena scan costs real money.

---

## 3. Drivers

### 3.0 Why compiled-in drivers rather than a pluggable driver model

DBeaver's "drivers" are JDBC: a standardized API with per-vendor implementations,
downloaded as jars at first connect and loaded at runtime. The vendor writes and maintains
the driver, which is why DBeaver reaches ~100 databases — it delegates rather than
implements. We take the opposite approach: wire-protocol implementations compiled into the
binary.

**What that buys:**

- **The distribution story only works this way.** One binary, no runtime download, no JVM,
  no driver-management UI, no "driver not found" support burden, and it works offline.
  Given `cargo install` is the primary channel, a runtime-pluggable model would undo most
  of §1.
- **No linking against system client libraries** for the wire-protocol drivers, so
  cross-compilation and musl static builds work; `rustls` avoids system TLS variance.
- **Licensing.** Oracle's `libmysqlclient` is GPLv2, which an MIT project cannot link
  casually. sqlx's pure-Rust MySQL implementation sidesteps the question entirely.
- **Async to the bottom.** JDBC is blocking and libpq's async mode is awkward.
  Cancellation, streaming into the spool, and a responsive UI all depend on this.
- **It is what makes the audit claim true.** "Every query is logged" holds only if every
  path to the database runs through `quokka-core::execute()`. A user-supplied driver
  with arbitrary connection properties is a path we do not control. Compiled-in drivers
  make the guarantee structural rather than aspirational — the driver choice and the
  product's central promise are the same decision.

**What we give up, stated plainly:**

- **The long tail, which is the big one.** Snowflake, BigQuery, Oracle, SQL Server,
  Redshift, Databricks — each is a driver we write, not a jar a user downloads. We will be
  asked for them and the answer will be "not yet".
- **Type and feature fidelity.** Postgres ranges, composite types, `hstore`, PostGIS
  geometry, `COPY`, `LISTEN/NOTIFY`: sqlx covers a common subset well and the exotica not
  at all.
- **Auth methods.** Kerberos/GSSAPI, RDS IAM auth, Azure AD, SCRAM channel binding —
  vendor drivers ship these; we implement each one.
- **Release coupling.** A DBeaver user hits a driver bug and swaps in a newer jar. Ours
  waits for a QuokkaQuery release, so server-version drift lands on our schedule.
- **Introspection is hand-written.** JDBC offers `DatabaseMetaData` uniformly; we maintain
  catalog queries per dialect and per server version.
- **Compile time and binary size.** Four drivers plus `wgpu` makes `cargo install` a
  multi-minute affair.

**Three hedges, committed now rather than retrofitted:**

1. **Unknown types render as text, never fail.** Postgres returns a text representation for
   any OID; an unrecognized type must degrade to a string in the grid rather than aborting
   the result set. This one rule turns most fidelity gaps from breakage into mild ugliness,
   and it belongs in the driver test suite from M0.
2. **One crate and one cargo feature per driver**, keeping the `trait Driver` seam honest
   and slim builds possible. Athena already demonstrates the trait tolerates a
   non-wire-protocol backend, which is the same shape BigQuery or Snowflake would take.
3. **An optional ODBC escape hatch** (`odbc-api`), off by default, bring-your-own DSN,
   documented as second-class. It recovers long-tail reach without owning a hundred
   drivers, and the audit path still wraps it because we remain the caller.

A README compatibility matrix states tested server versions per driver. Claiming support
for a database nobody has run against is the failure mode this section exists to avoid.

### 3.1 SQLite / PostgreSQL / MySQL

`sqlx` 0.9 (async, `rustls`) covers all three with one connection-pool model and one
type-mapping story. Note the asymmetry: the Postgres and MySQL drivers are pure Rust wire
protocol implementations, but `sqlx-sqlite` binds `libsqlite3-sys`, so SQLite is a bundled
C library and a C compiler is required to build. "Pure Rust" is a claim about two of the
three, not all of them. Introspection is per-dialect SQL against `information_schema`
/ `pg_catalog` / `pragma`, cached with a TTL so editor autocomplete stays instant.

### 3.2 Athena

Athena is not a wire-protocol database, so it gets a hand-written driver over
`aws-sdk-athena` 1.x:

1. `StartQueryExecution` with the configured workgroup and output location;
2. poll `GetQueryExecution` with capped exponential backoff;
3. page results via `GetQueryResults`, typing columns from `ResultSetMetadata`
   (optionally reading the S3 result object directly for large sets);
4. `StopQueryExecution` on cancel.

**SSO credentials.** `aws-config` 1.x resolves `sso_session` profiles from `~/.aws/config`
and the token cache written by `aws sso login`, including automatic refresh. v1 leans on
that: pick a profile, get credentials, and emit a clear "run `aws sso login --profile X`"
error when the token is expired. Implementing the OIDC device-authorization flow
in-process with `aws-sdk-ssooidc` (so the AWS CLI isn't required) is a well-scoped
follow-up, not a prerequisite.

**Cost visibility.** `DataScannedInBytes` and `EngineExecutionTimeInMillis` come back on
every execution and land in the audit record. Per-query cost attribution by actor —
including which agent burned the budget — is a genuine differentiator over DBeaver.

---

## 4. The result spool

The mechanism behind "512 rows on screen, the whole dataset to a file". This is the piece
that makes the bounded UI honest rather than limiting.

**Never page by re-running the query.** `LIMIT 512 OFFSET n` against an arbitrary user
query re-executes it per page: on Athena you pay for every scan again, on Postgres deep
offsets degrade badly, and without a total ordering page 2 can repeat rows from page 1.

Instead, **execute once and spool**. As `QueryStream` yields batches, `quokka-spool`
writes them into a per-result SQLite database:

```
result(rowid INTEGER PRIMARY KEY, c0, c1, … cN)   -- rows in arrival order
schema(ordinal, name, driver_type, nullable)      -- SQLite loses type info; keep it here
meta(key, value)                                  -- row count, truncation, timings
```

Everything downstream is then a read of the spool:

- **Paging** is `SELECT … WHERE rowid > ? LIMIT 512` — O(1) per page, stable ordering,
  no re-execution, no additional cost.
- **Sort and filter over the result** come free, because the spool is a table we can
  query. Re-sorting a result set without re-running the query against production is a
  better feature than the virtualized grid we chose not to build.
- **Export** streams the spool out as CSV, TSV, JSON, NDJSON or Parquet, unbounded by
  the display cap and never buffered in memory. Progress and cancel included.

### 4.1 The spool is ephemeral

**It does not survive the process.** A cache that outlives the session serves rows that
silently no longer match the database, and a query tool that shows you stale data has
failed at its one job.

- Spools live in a PID-scoped directory under the XDG cache dir, deleted on clean exit.
  Not `/tmp`: it is tmpfs on many systems, and a 1 GiB spool would land in RAM.
- Crashes leave orphans, so startup sweeps any spool directory whose owning PID is no
  longer alive.
- Because nothing persists, the cache dir never accumulates query results — the
  data-handling story is simply "we don't keep them".

Ephemerality bounds staleness to one process lifetime; it does not eliminate it. A result
spooled at 10:00 and paged at 10:45 is still 45 minutes old. So a result tab always shows
`as of 10:00 (45m ago)` with a re-run control, and flags itself past a configurable
`spool_stale_after`. Bounded and visible beats invisible.

**Consequence for the CLI.** A `quokka` invocation is short-lived, so its spool dies with
it and cannot be paged or exported by a *later* invocation. Export therefore happens in
the same invocation (`quokka query … --export out.parquet`). Exporting by id afterwards
means re-running the original query, which costs a second scan, so per §1.4 it never
happens implicitly: `quokka export --query-id <id>` errors and explains unless given
`--rerun`, and the re-run is logged as a new event whose `parent_id` points at the first.
Serving cached rows from the earlier run instead would be exactly the staleness this
section exists to prevent.

The MCP server and the UI are long-lived processes, so both page and export from a live
spool normally.

### 4.2 Limits

| Limit | Value | Configurable | Why |
| --- | --- | --- | --- |
| Grid page | **512 rows** | downward only | Hard ceiling — nothing to virtualize |
| MCP tool response | **512 rows** | no | Hard ceiling — protects the agent's context window |
| CLI preview | 512 rows default | `--max-rows`, may exceed | A shell pipeline is not a context window |
| Spool | 1M rows / 1 GiB | yes | Bounds local disk |
| Export | unbounded | — | Streams driver → file, never buffered |

On hitting the spool cap the result is marked truncated, and the UI says so explicitly
rather than silently showing a prefix. `quokka export --all` bypasses the spool entirely,
streaming driver → file for datasets larger than local disk.

The ceiling counts **rows, not cells**. A 200-column result at 512 rows is far more spool
traffic and far less readable than a 3-column one, and a cell budget that silently lowered
the page size for wide results would make the ceiling unpredictable. Predictable beats
optimal here; wide tables get horizontal scrolling and column hiding instead. If wide
results turn out to hurt in practice, a secondary cell budget is the known escape hatch.

**The truncation trap to get right:** sort and filter operate on the *spooled subset*. If
1M of 12M rows were spooled, sorting yields the top of the first million, not of the
result — which looks authoritative and is wrong. So when a result is truncated the UI
labels sort and filter as scoped to the spooled rows, and offers "re-run with ORDER BY"
as the correct alternative. Getting this wrong produces confidently incorrect answers,
which is worse than refusing.

Type fidelity is the known cost of a SQLite spool: five storage classes, so exact numerics
and timestamps round-trip through the `schema` sidecar rather than natively. If that
proves painful, an Arrow IPC spool is the drop-in alternative — random-access record
batches, native Parquet export — at the price of a heavier dependency and more conversion
code. Starting with SQLite reuses a dependency we already have and gets sorting for free.

---

## 5. The audit trail

SQLite (WAL) at the XDG data dir, e.g. `~/.local/share/quokkaquery/audit.db`.

```sql
CREATE TABLE audit_log (
  id                TEXT PRIMARY KEY,   -- event id, UUIDv7: sorts by time
  query_id          TEXT NOT NULL,      -- groups the events of one query
  parent_id         TEXT,               -- retries, re-runs, exports of an earlier query
  at                TEXT NOT NULL,      -- when this event was appended
  duration_ms       INTEGER,            -- query_finished only

  actor_kind        TEXT NOT NULL,      -- human | agent | automation
  actor_id          TEXT NOT NULL,      -- OS user, or agent name via --actor / QUOKKA_ACTOR
  session_id        TEXT NOT NULL,
  client            TEXT NOT NULL,      -- cli | ui | mcp

  connection        TEXT NOT NULL,
  dialect           TEXT NOT NULL,
  database          TEXT,
  schema_name       TEXT,

  event_kind        TEXT NOT NULL,      -- query_started | query_finished
                                        -- | introspect | export | connect | auth | scrub
  sql_logging       TEXT NOT NULL,      -- fingerprint | redacted | full  (§5.1)
  sql_text          TEXT,               -- present only when sql_logging <> 'fingerprint'
  sql_fingerprint   TEXT NOT NULL,      -- normalized via sqlparser; always recorded
  statement_kind    TEXT,               -- select | insert | update | delete | ddl | ...
  read_only         INTEGER,
  params            TEXT,               -- JSON; bound values follow sql_logging

  status            TEXT NOT NULL,      -- ok | error | cancelled | denied | timeout
  error_code        TEXT,
  error_message     TEXT,

  rows_returned     INTEGER,
  rows_affected     INTEGER,
  rows_spooled      INTEGER,
  truncated         INTEGER,
  export_format     TEXT,               -- csv | parquet | ... for event_kind='export'
  export_path       TEXT,
  data_scanned_bytes INTEGER,           -- Athena
  cost_estimate_usd REAL,

  approved_by       TEXT,               -- who authorized a write
  tags              TEXT,

  prev_hash         TEXT,
  row_hash          TEXT NOT NULL
);
```

### 5.1 What the audit log never stores

**No result data. Not rows, not samples, not digests or hashes of rows.** The log records
that a query ran, by whom, against what, and how it went — never what came back. Result
data exists only in the ephemeral spool (§4.1) and in files the user explicitly exported.

The remaining PII surface is the query text itself: `WHERE email = 'a@b.example'` puts a
literal in the SQL. So full text is **opt-in per connection**, never the default.

`sql_logging` is a per-connection setting with three values:

| Mode | Stores | Status |
| --- | --- | --- |
| `fingerprint` | Normalized shape, literals replaced by `?` | **Default** |
| `full` | The query verbatim, literals included | Opt-in, chosen per connection |
| `redacted` | The query as written, with only literal values masked | Later version |

`fingerprint` and `redacted` differ more than they look. A fingerprint is normalized for
grouping — whitespace collapsed, literals to `?` — which is fine for a one-liner and hard
to read for a 200-line CTE. `redacted` keeps the query you actually wrote, comments and
formatting intact, masking values only. It needs an AST round-trip through `sqlparser`
rather than a normalization pass, which is why it lands later rather than at M0.

Three rules make this work:

1. **The mode is recorded on every row.** Without `sql_logging` in the row, a query with no
   literals is indistinguishable from one whose literals were dropped — and an audit trail
   you cannot interpret is not one. Bound `params` follow the same setting, since a bound
   value is a literal that took a different road.
2. **The fingerprint is always stored, in every mode.** This is what keeps privacy-first
   from gutting the product: normalization replaces literals, not identifiers, so *which
   tables an agent touched, when, how often, and with what kind of statement* survives at
   the safest setting. What you lose at `fingerprint` is which **records** were reached —
   so an exfiltration review gets coarser, and a connection you would want that detail for
   is exactly the one to set to `full`.
3. **Only a human changes it.** Logging verbosity is human-only configuration. An agent
   that can lower the fidelity of its own audit trail defeats the threat model this log
   exists for.

New connections ask once, at creation, rather than inheriting a silent default — the
choice is too consequential to bury in a config file, and §5's hash chain makes it
effectively forward-only.

**Changing your mind, in either direction.** Literals dropped at write time are gone; a
switch to `full` applies to future queries only. The reverse is also constrained: rewriting
past rows to remove literals breaks the hash chain. `quokka audit scrub --before <date>`
therefore masks literals in older rows, re-seals the chain from that point, and records the
scrub as an event in the log itself — so verification still passes and the discontinuity is
visible and explained rather than silent.

**Exports are audited events.** Someone writing ten million rows to a file is exactly what
an audit trail exists to record, so an export is a logged event in its own right, linked
to the query that produced it via `parent_id`.

**Introspection is logged, but not as a query.** Catalog reads run SQL, so invariant 1
binds them: they go through `execute()` like everything else. But they are *our* SQL, not
the caller's — `Driver::introspect` takes a `Scope`, never a statement, so the text that
reaches the database is one the driver wrote — and they run on a TTL refresh (§3.1)
rather than when a person asks. Recording a `query_started`/`query_finished` pair per
autocomplete refresh would bury the record that review exists to read, and would make
"which tables did this agent touch" ambiguous between reading a table and describing it.

So a catalog refresh appends **one `introspect` event, after the fact**, naming the scope
it covered, how long it took and how it went. One event rather than two because there is
no outcome to hold open: the statement is bounded and ours, so a refresh that dies leaves
a stale cache rather than a half-written record of something unknown. For the same reason
fail-closed does not apply — there is no "before" event to fail — and a failed write is
surfaced loudly rather than swallowed, exactly as a failed `query_finished` is. The
saving is real: at a one-minute TTL this is the difference between a handful of rows a
day and thousands.

This holds only while introspection cannot carry caller-supplied SQL. The day a surface
wants to run its own catalog query, that is a `query_started`/`query_finished` pair like
any other, because it is one.

**Two events per query, never one mutable row.** A row cannot record both "started at"
and "finished at" in an append-only table — writing the outcome would mean updating the
row, which the triggers below forbid. So `query_started` is appended *before* execution
and `query_finished` after, sharing a `query_id`. This is strictly better for the threat
model: a start with no finish is visible as exactly that, so killing the process mid-query
no longer erases the attempt. Reconstructing a query's full story is a join on `query_id`,
and the `@audit` connection ships a `queries` view that does it for you.

**Fail closed.** If the `query_started` event cannot be written, the query does not run.
An audit-first tool that executes when it cannot record is not audit-first. If the
`query_finished` event fails to write, the query has already run, so the failure is
surfaced loudly rather than swallowed — and the dangling start is the honest record of
what happened.

**Append-only.** `BEFORE UPDATE` and `BEFORE DELETE` triggers `RAISE(ABORT)`. Each row's
`row_hash` covers its own fields plus `prev_hash`, so any excision or edit breaks the chain
and `quokka audit verify` detects it.

Worth being precise about what that buys a single-user tool. The threat model is not a
colleague disputing the record — there is no colleague. It is **an agent with shell access
quietly editing the log of what it just did.** The chain makes that detectable, which is
the whole reason the audit trail is trustworthy enough to review. It is emphatically not a
defense against the machine's owner, who can rebuild the chain at will, and the docs must
say so plainly rather than implying a guarantee that isn't there.

**Denials are logged too.** What an agent *tried* to run and was blocked from running is
as valuable as the successes.

**Queryable by both surfaces, without a second API.** The audit database registers as a
built-in connection named `@audit`. Agents query it through the ordinary `query` tool; the
UI's audit view is a saved query against it; `quokka audit …` subcommands are ergonomic
wrappers over the same SQL. Dogfooding the product is the feature.

```bash
quokka audit tail -f --actor claude
quokka audit query "SELECT actor_id, count(*), sum(data_scanned_bytes)/1e12 * 5 AS usd
                FROM audit_log WHERE event_kind = 'query_finished'
                  AND at > date('now','-7 days')
                GROUP BY 1 ORDER BY 3 DESC"
quokka query --connection @audit "SELECT * FROM audit_log WHERE status='denied'"
```

**Hygiene.** The log is kept indefinitely for now — with `fingerprint` as the default
mode the file grows slowly, and a complete history is what makes review worth doing.
Retention policies arrive in a later version (M7) rather than as a premature default.
Regex-based secret scrubbing runs before every write,
independent of `sql_logging`, so a password pasted into a query never lands even at `full`.
Credentials never enter the log — they live in the OS keyring via `keyring` 4.x, with an
encrypted file fallback for headless Linux.

---

## 6. Agent interface

### 6.1 CLI

Stable, machine-first output. `--format json` for a single envelope, `--format ndjson` for
streaming large results, errors as JSON on stderr with meaningful exit codes.

```bash
quokka connections list --format json
quokka schema describe orders --connection prod --format json
quokka query --connection prod --max-rows 1000 --timeout 30s -f ./q.sql --format ndjson
quokka query --connection prod -f ./q.sql --export ./orders.parquet     # one invocation
quokka export --query-id 018f… --rerun -o ./orders.parquet          # costs a 2nd scan
```

### 6.2 MCP server

`quokka mcp` runs a stdio MCP server (`rmcp` 3.x) exposing `list_connections`, `list_schemas`,
`describe_table`, `query`, `explain`, `export` and `search_audit`. Agent clients attach
directly — no shelling out, no output parsing, and schema introspection arrives as
structured context instead of guesswork.

Tool responses are hard-capped at 512 rows — the same ceiling the grid uses, for the same
reason: an unbounded result set dumped into a context window is a failure mode, not a
feature. Beyond that the agent pages, refines, or exports to a file.

The spool pays off here too. `quokka mcp` is a long-lived process, so an agent runs a query
once, gets a bounded preview, and can then page, sort or export from the spool without
re-scanning the source — and without paying Athena twice.

### 6.3 Guardrails (`quokka-policy`)

Every statement is parsed with `sqlparser` before execution:

- connections are **read-only by default**; writes need `mode = read_write` in config
  *and* an explicit `--write` at the call site;
- statement classification denies DDL/DML outside that mode;
- multi-statement bodies rejected (no stacked-query surprises);
- row caps and statement timeouts enforced server-side, not by trusting a `LIMIT`;
- optional schema/table allowlists per connection;
- every denial is audited with the SQL that triggered it.

**The mode binds both surfaces identically.** A connection's `read_only` / `read_write`
mode governs the UI exactly as it governs an agent. Exempting the human would turn "one
execute path" from a structural property into a per-surface policy, and a guarantee with
an exception is not one.

The cost is real and worth naming: you will hit your own guardrail while sitting at a
database client, which is precisely the friction people uninstall over. So the UI earns
its keep by making the mode impossible to be surprised by (§7) rather than by being
exempt from it, and switching a connection to `read_write` is ordinary human-only
configuration — not a privilege escalation flow.

This layer matters more than any driver. An agent with a raw `psql` shell is a liability;
an agent with a classified, capped, logged query tool is a teammate.

### 6.4 Cost guard

Athena bills by data scanned, so a runaway query is a bill rather than an error. Two
layers, because neither is sufficient alone:

1. **Per-query, server-side.** Athena workgroups support `BytesScannedCutoffPerQuery`,
   which aborts a single query mid-flight once it exceeds a limit. This is the only
   control that can stop the query currently running, so a workgroup carrying one is part
   of the recommended Athena setup rather than an afterthought.
2. **Cumulative, ours.** A per-actor budget over a rolling window, checked before
   execution and enforced by denying the query — logged as `status='denied'` like any
   other refusal, with a message stating the budget, the window, and what has been spent.

**Separate caps for agents and humans**, because the failure modes differ. A person
running an expensive query is awake, watching it, and will notice the bill; an agent
looping on a bad query at 3am is the scenario that actually generates a surprise invoice.
Proposed defaults: agents capped conservatively out of the box, humans uncapped with a
warning threshold, both per-connection and tunable.

```toml
[connections.prod.cost_guard]
window       = "1d"
agent_limit  = "50GB"     # denies past this
human_limit  = "unlimited"
human_warn   = "500GB"
```

The accounting needs no new storage: `data_scanned_bytes` and `actor_kind` are already
columns in the audit log, so a budget check is a query against `@audit`. The audit trail
stops being only a record and becomes load-bearing — which is a good argument for keeping
it correct.

**What this cannot do, stated plainly.** Athena reports bytes scanned *after* execution,
and no reliable pre-execution estimate exists. Our budget therefore stops the query
*after* the one that crossed the line, not the one that crossed it. Layer 1 is what
bounds a single catastrophic query; layer 2 bounds the drift. Promising a hard
pre-execution cost cap would be a lie.

The mechanism is generic — a per-actor budget over an audited metric — so it extends to
row or query counts on other drivers. It is Athena-first because Athena is where a query
costs money.

---

## 7. Human UI (iced)

`quokka ui` opens a native window. Layout: connection tree on the left, SQL editor top-right,
result grid bottom-right, audit view as a sibling tab.

- **Editor** — `iced::widget::text_editor` with `iced_highlighter` (syntect) for SQL
  highlighting. Schema-aware autocomplete is a custom overlay over the introspection
  cache; keep it to identifier completion and resist building an IDE.
- **Grid** — `iced_table`, or a hand-rolled `scrollable` + `row`/`column`. With a 512-row
  page there is nothing to virtualize. Column resize, sort (a spool query, §4), and
  copy-as-TSV for a selected range. A cell inspector panel handles long text, JSON and
  BLOBs, which is where a fixed-height grid actually hurts.
- **Pager** — explicit "rows 1–512 of 12,481 · as of 10:00 (45m ago) · [Next] [Re-run]
  [Export all]". The count comes from the spool, so it is exact rather than estimated, and
  the export button is always the next thing your eye lands on. The cap should read as a
  deliberate choice, not a limit we hit.
- **Mode indicator** — the connection's read-only / read-write state is visible in the
  connection tree and persistently in the editor chrome, not buried in settings. A write
  attempted against a read-only connection fails inline, naming the setting and where to
  change it. Since the guardrail binds humans too (§6.3), being surprised by it is the
  failure to design out.
- **Write confirmation** — on a `read_write` connection, DML and DDL confirm before
  running, naming the statement kind and target table, and flagging an `UPDATE` or
  `DELETE` with no `WHERE` clause specifically. The classifier already knows all of this;
  surfacing it costs nothing and catches the classic disaster.
- **Async** — driver work runs on tokio; iced `Task`s deliver results as messages. Long
  queries show elapsed time and a cancel button wired to `Driver::cancel`.
- **Rendering** — `wgpu` by default, `tiny-skia` fallback selectable for remote desktops
  and VMs where GPU access is unreliable.
- Bundle a font with the binary so rendering is identical across platforms.

---

## 8. Distribution

| Channel | Notes |
| --- | --- |
| `cargo install quokkaquery` | Primary, and now genuinely frictionless — pure Rust, no npm |
| GitHub Releases + `curl \| sh` | `cargo-dist` 0.32 generates installers and CI |
| Homebrew **formula** (own tap) | Not a cask — formulae are not quarantined |
| Scoop / WinGet | Windows |
| Nix, Docker | Build the headless variant: `--no-default-features` |

Build dependencies to document:

- **A C compiler on every platform**, because `sqlx-sqlite` builds bundled SQLite through
  `libsqlite3-sys` (§3.1). Present by default on macOS with the Command Line Tools and on
  most Linux images; Windows needs the MSVC build tools.
- **Linux additionally needs the `winit` stack** (`libxkbcommon`, Wayland or X11
  development headers) for the UI build.

The headless build (`--no-default-features`) drops the `winit` stack but still needs the C
compiler, which is what makes it the right default for containers and CI.

CI: GitHub Actions matrix over macOS (arm64 + x86_64), Linux (gnu + musl) and Windows.
macOS runners produce ad-hoc-signed binaries automatically.

---

## 9. Testing

- SQLite: in-memory, fast, runs everywhere.
- Postgres / MySQL: `testcontainers`, gated behind a feature so the default `cargo test`
  needs no Docker.
- Athena: trait-level fakes plus recorded HTTP fixtures (`wiremock`). LocalStack's Athena
  support is not in its community edition, so an opt-in live test against a real workgroup,
  run manually, is the honest fallback.
- Policy engine: table-driven tests over a corpus of SQL, including the nasty cases
  (comments, CTEs that hide writes, dialect quirks). This is the security boundary and
  deserves the densest tests in the repo.
- Spool: round-trip property tests per driver type — every `Value` that goes in comes back
  out equal, and every export format reproduces the spool exactly. Truncation must be
  reported, never silent.
- Audit: property test that the hash chain detects every single-row edit or deletion.
- UI: keep logic in `quokka-core` and out of the iced `update`/`view` functions, so the UI
  layer is thin enough that its test story is smoke tests and manual passes.

---

## 10. Milestones

| # | Scope | Outcome |
| --- | --- | --- |
| M0 | Workspace, `Driver` trait, SQLite, audit log, `quokka query --format json` | End-to-end skeleton: a query runs and is provably logged |
| M1 | Postgres + MySQL, connection registry, keyring, introspection | Real daily-driver CLI |
| M2 | `quokka-spool`, paging, export formats, `quokka export` | The bounded-view contract, proven on the CLI first |
| M3 | `quokka-policy`, read-only defaults, `quokka mcp` | Safe for agents — the actual differentiator |
| M4 | `quokka-ui`: iced window, editor, 512-row grid, audit tab | The human UI |
| M5 | Athena driver, SSO, cost fields in the audit log, cost guard (§6.4) | Full connector set |
| M6 | `cargo-dist`, Homebrew tap, Scoop/WinGet, docs site | Installable by strangers |
| M7 | `redacted` SQL logging mode, audit retention policies, saved queries, in-process SSO device flow, opt-in result diffing | Quality of life |

The spool lands at M2, before both the policy engine and the UI, because paging and export
are core semantics rather than UI decoration — the CLI needs them just as much, and
proving them there means the UI is only ever a view over something already correct.

M3 still precedes the UI on purpose: the agent story is what this project has that DBeaver
and Azure Data Studio do not, and it should be real before any pixels are pushed.

---

## 11. Decisions and remaining questions

### 11.1 Decided

| Question | Decision | Why |
| --- | --- | --- |
| Binary name | `quokka` (package `quokkaquery`) | Readable and unambiguous; the package name is the only thing crates.io constrains |
| Result digests in the audit log | **Never stored** | Result contents are PII. The log describes queries, not their output (§5.1) |
| Multi-user / shared audit sink | **Out of scope** | One person and their agents on one machine. No server, no accounts, no shared state |
| 512 by rows or by cells | **Rows** | A predictable ceiling beats an optimal one; wide tables get scrolling and column hiding. Revisit only if real wide-table use hurts |
| Result diffing | Explicit action only | A diff needs a second run, and a second run costs money (§1.4) |
| Logging full SQL text | **Opt-in per connection**, `fingerprint` by default | Literals are PII. The fingerprint still shows which tables were touched, so the safe default stays useful (§5.1) |
| Athena cost guard | **Yes, with separate agent and human caps** | A person running an expensive query is watching it; an agent looping at 3am is not (§6.4) |
| Read-only default in the UI | **Binds both surfaces identically** | An exception would make "one execute path" a per-surface policy rather than a property. The UI earns it back by making the mode unmissable |
| Logging schema introspection | **One `introspect` event per catalog refresh**, not a query pair | Catalog reads are the driver's own bounded SQL on a TTL, not the caller's. Two events per autocomplete refresh would bury the log review exists to read (§5) |
| Audit retention | **Keep everything, for now** | `fingerprint` keeps the file small and complete history makes review worthwhile. Policies land at M7 |

The single-user decision is load-bearing in more places than it looks: it removes the
shared Postgres sink, accounts, and any notion of non-repudiation between people, and it
re-points the hash chain at its real threat model — an agent editing its own trail.

### 11.2 Still open

1. **Spool type fidelity.** SQLite's five storage classes versus an Arrow IPC spool (§4.2).
   Deliberately deferred until a real type round-trips badly — the evidence should drive
   this rather than taste.
