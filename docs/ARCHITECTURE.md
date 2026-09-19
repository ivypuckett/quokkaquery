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
  fully featured. A `qq ui --serve` web mode remains possible later behind the same core.
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

---

## 2. Workspace layout

```
crates/
  qq-core      Value/Row types, connection registry, config, secret redaction
  qq-driver    `trait Driver` + sqlite / postgres / mysql / athena implementations
  qq-spool     result cache: one execution -> paging, sorting, export (§4)
  qq-audit     append-only SQLite log: schema, hash chain, search API
  qq-policy    sqlparser-based statement classification and guardrails
  qq-cli       clap CLI — the human and agent entry point (bin: `qq`)
  qq-mcp       stdio MCP server (rmcp) for agent clients
  qq-ui        iced application (feature-gated, default on)
```

There is no HTTP server crate. Every surface calls `qq-core::execute()`, which consults
`qq-policy`, dispatches to a `Driver`, spools the result, and writes to `qq-audit`. There
is no way to run SQL that skips it.

`qq-ui` sits behind a default-on `ui` feature. `cargo install quokkaquery
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
  path to the database runs through `qq-core::execute()`. A user-supplied driver with
  arbitrary connection properties is a path we do not control. Compiled-in drivers make
  the guarantee structural rather than aspirational — the driver choice and the product's
  central promise are the same decision.

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

Instead, **execute once and spool**. As `QueryStream` yields batches, `qq-spool` writes
them into a per-result SQLite database:

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

**Consequence for the CLI.** A `qq` invocation is short-lived, so its spool dies with it
and cannot be paged or exported by a *later* invocation. Export therefore happens in the
same invocation (`qq query … --export out.parquet`), and `qq export --query-id <id>`
**re-runs** the original query, logged as a new event whose `parent_id` points at the
first. It costs a second scan and says so. Serving cached rows from a previous run would
be exactly the staleness this section exists to prevent.

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
rather than silently showing a prefix. `qq export --all` bypasses the spool entirely,
streaming driver → file for datasets larger than local disk.

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
CREATE TABLE query_log (
  id                TEXT PRIMARY KEY,   -- UUIDv7: sorts by time
  parent_id         TEXT,               -- retries, follow-ups, exports of a result
  started_at        TEXT NOT NULL,
  finished_at       TEXT,
  duration_ms       INTEGER,

  actor_kind        TEXT NOT NULL,      -- human | agent | automation
  actor_id          TEXT NOT NULL,      -- OS user, or agent name via --actor / QQ_ACTOR
  session_id        TEXT NOT NULL,
  client            TEXT NOT NULL,      -- cli | ui | mcp

  connection        TEXT NOT NULL,
  dialect           TEXT NOT NULL,
  database          TEXT,
  schema_name       TEXT,

  event_kind        TEXT NOT NULL,      -- query | export | connect | auth
  sql_text          TEXT,
  sql_fingerprint   TEXT,               -- normalized via sqlparser, for grouping
  statement_kind    TEXT,               -- select | insert | update | delete | ddl | ...
  read_only         INTEGER,
  params            TEXT,               -- JSON, redacted

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

**Exports are audited events.** Someone writing ten million rows to a file is exactly what
an audit trail exists to record, so an export is a logged event in its own right, linked
to the query that produced it via `parent_id`.

**Append-only.** `BEFORE UPDATE` and `BEFORE DELETE` triggers `RAISE(ABORT)`. Each row's
`row_hash` covers its own fields plus `prev_hash`, so any excision or edit breaks the
chain and `qq audit verify` detects it. This is tamper-*evidence*, not tamper-proofing —
anyone with the file can rebuild the chain — and the docs must say so plainly. Teams
needing more point the optional audit sink at a shared Postgres they don't own.

**Denials are logged too.** What an agent *tried* to run and was blocked from running is
as valuable as the successes.

**Queryable by both surfaces, without a second API.** The audit database registers as a
built-in connection named `@audit`. Agents query it through the ordinary `query` tool; the
UI's audit view is a saved query against it; `qq audit …` subcommands are ergonomic
wrappers over the same SQL. Dogfooding the product is the feature.

```bash
qq audit tail -f --actor claude
qq audit query "SELECT actor_id, count(*), sum(data_scanned_bytes)/1e12 * 5 AS usd
                FROM query_log WHERE started_at > date('now','-7 days')
                GROUP BY 1 ORDER BY 3 DESC"
qq query --connection @audit "SELECT * FROM query_log WHERE status='denied'"
```

**Hygiene.** Configurable retention; regex-based secret scrubbing before write; opt-out of
storing full SQL text for sensitive connections (fingerprint only). Credentials never
enter the log — they live in the OS keyring via `keyring` 4.x, with an encrypted file
fallback for headless Linux.

---

## 6. Agent interface

### 6.1 CLI

Stable, machine-first output. `--format json` for a single envelope, `--format ndjson` for
streaming large results, errors as JSON on stderr with meaningful exit codes.

```bash
qq connections list --format json
qq schema describe orders --connection prod --format json
qq query --connection prod --max-rows 1000 --timeout 30s -f ./q.sql --format ndjson
qq query --connection prod -f ./q.sql --export ./orders.parquet     # one invocation
qq export --query-id 018f… -o ./orders.parquet                      # re-runs; says so
```

### 6.2 MCP server

`qq mcp` runs a stdio MCP server (`rmcp` 3.x) exposing `list_connections`, `list_schemas`,
`describe_table`, `query`, `explain`, `export` and `search_audit`. Agent clients attach
directly — no shelling out, no output parsing, and schema introspection arrives as
structured context instead of guesswork.

Tool responses are hard-capped at 512 rows — the same ceiling the grid uses, for the same
reason: an unbounded result set dumped into a context window is a failure mode, not a
feature. Beyond that the agent pages, refines, or exports to a file.

The spool pays off here too. `qq mcp` is a long-lived process, so an agent runs a query
once, gets a bounded preview, and can then page, sort or export from the spool without
re-scanning the source — and without paying Athena twice.

### 6.3 Guardrails (`qq-policy`)

Every statement is parsed with `sqlparser` before execution:

- connections are **read-only by default**; writes need `mode = read_write` in config
  *and* an explicit `--write` at the call site;
- statement classification denies DDL/DML outside that mode;
- multi-statement bodies rejected (no stacked-query surprises);
- row caps and statement timeouts enforced server-side, not by trusting a `LIMIT`;
- optional schema/table allowlists per connection;
- every denial is audited with the SQL that triggered it.

This layer matters more than any driver. An agent with a raw `psql` shell is a liability;
an agent with a classified, capped, logged query tool is a teammate.

---

## 7. Human UI (iced)

`qq ui` opens a native window. Layout: connection tree on the left, SQL editor top-right,
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
- UI: keep logic in `qq-core` and out of the iced `update`/`view` functions, so the UI
  layer is thin enough that its test story is smoke tests and manual passes.

---

## 10. Milestones

| # | Scope | Outcome |
| --- | --- | --- |
| M0 | Workspace, `Driver` trait, SQLite, audit log, `qq query --format json` | End-to-end skeleton: a query runs and is provably logged |
| M1 | Postgres + MySQL, connection registry, keyring, introspection | Real daily-driver CLI |
| M2 | `qq-spool`, paging, export formats, `qq export` | The bounded-view contract, proven on the CLI first |
| M3 | `qq-policy`, read-only defaults, `qq mcp` | Safe for agents — the actual differentiator |
| M4 | `qq-ui`: iced window, editor, 512-row grid, audit tab | The human UI |
| M5 | Athena driver, SSO, cost fields in the audit log | Full connector set |
| M6 | `cargo-dist`, Homebrew tap, Scoop/WinGet, docs site | Installable by strangers |
| M7 | Shared Postgres audit sink, saved queries, in-process SSO device flow | Team features |

The spool lands at M2, before both the policy engine and the UI, because paging and export
are core semantics rather than UI decoration — the CLI needs them just as much, and
proving them there means the UI is only ever a view over something already correct.

M3 still precedes the UI on purpose: the agent story is what this project has that DBeaver
and Azure Data Studio do not, and it should be real before any pixels are pushed.

---

## 11. Open questions

1. Binary name — `qq` is short and pleasant but collides on some systems; `quokka` as the
   canonical name with `qq` as an alias is the safer default.
2. Does the audit log store result digests? Useful for reproducibility, a leak vector for
   sensitive tables. Proposed: off by default, per-connection opt-in.
3. Multi-user teams: is the shared Postgres sink append-only from clients, or does a small
   server own it? The latter is the only way to make the chain genuinely non-repudiable,
   and it is a much larger project.
4. Does the 512-row ceiling hold by rows or by cells? A 200-column result at 512 rows is
   far more spool traffic and far less readable than a 3-column one. A secondary cell
   budget that lowers the effective page size for very wide results may be worth it —
   deferred until we have seen real wide-table behaviour.
5. Should a UI re-run diff against the previous result ("3 rows changed since 10:00")?
   Cheap to do from two spools, genuinely useful when watching a table, and a natural
   answer to the staleness the ephemeral spool leaves on the table.
