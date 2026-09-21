# QuokkaQuery

A single-user database client: **a CLI for agents, a native UI for humans, and one
append-only audit log of every query that both can query as an ordinary connection.**

Targets SQLite, PostgreSQL, MySQL and Amazon Athena. Pure Rust where the wire protocol
allows it, installable with `cargo install`, and shipped as a plain binary rather than an
app bundle.

Package: `quokkaquery`. Binary: `quokka`.

## What it is not

Being narrow about this is a feature of the product, not an apology for it.

- **No inline cell editing.** Not a widget we are avoiding — a stance. Inline editing
  generates hidden `UPDATE`s, which is exactly what an audit-first tool must not do.
  Writes are SQL you can read, review and find in the log.
- **No ER diagrams, no visual query builder, no data modelling.** DBeaver does those.
  We do queries, agents, and an audit trail.
- **No accounts, no server, no shared state.** One person and their agents, one machine.
- **The grid shows one page — 512 rows, a hard ceiling.** The full dataset goes to a file
  through streamed export, never through a bigger grid.
- **Nothing runs without you asking.** No auto-refresh, no polling, no speculative
  prefetch. Paging reads a local cache of rows you already paid for, never the database.
  Queries cost money; you decide when to spend it.

## Status: M3 — safe for agents

What works today:

- `quokka query --connection <name> "SELECT …" --format json|ndjson|table --max-rows N`,
  with `--param` for bound values, `--write` for a write and `--timeout 30s`
- **The policy engine**: every statement classified before it runs, connections read-only
  by default, stacked bodies refused, optional per-connection table allowlists, and every
  denial in the log
- **`quokka mcp`**: a stdio MCP server for agent clients — `list_connections`,
  `list_schemas`, `describe_table`, `query`, `explain`, `export`, `search_audit`
- `quokka explain`, on the audited path like everything else
- **The result spool**: one execution, then paging, sorting and export as reads of a
  local cache — `--export ./orders.parquet` in the same invocation, `--sort`, and
  `quokka export --query-id <id> --rerun`
- `quokka connections list` and `quokka schema describe <table>`
- `quokka credential set | delete | status`
- `quokka audit tail | query | verify`
- **SQLite, PostgreSQL and MySQL**
- The audit log: SQLite in WAL mode, append-only triggers, a hash chain, and the built-in
  `@audit` connection with a `queries` view

The iced UI arrives at M4 and Athena at M5. See `docs/ARCHITECTURE.md` §10.

## Safe for agents

This is the thing QuokkaQuery has that DBeaver and Azure Data Studio do not. An agent
with a raw `psql` shell is a liability; an agent with a classified, capped, logged query
tool is a teammate.

Every statement is parsed before it runs — not scanned for keywords, parsed — and the
same parse fills the audit log's `statement_kind` and `read_only` columns, so the log
cannot say `select` for something the guardrail refused as a write.

**A write needs two keys.** `mode = "read_write"` in the connection's configuration,
which only a human can set, *and* an explicit opt-in at the call site: `--write` from the
CLI, `write: true` over MCP. The second key widens nothing — it cannot make a read-only
connection writable — so an agent cannot grant itself a write by asking. What it buys is
that a write is always something someone meant, rather than something a generated
statement turned out to be.

**Writes hidden inside reads are still writes.**

```console
$ quokka query --connection prod \
    "WITH moved AS (DELETE FROM archive RETURNING *) SELECT * FROM moved"
error: refusing a `delete` statement on connection "prod", which is `mode = "read_only"`.
```

**Stacked statements are refused**, whatever the mode — they hide writes behind reads and
make the log's one-query-two-events record ambiguous.

**Anything the classifier cannot prove is a read is handled as a write.** `sqlparser`
does not know every dialect, so a statement it cannot read has to be treated as
something, and failing open would make the guardrail advisory: every corner of syntax it
is behind on would become a hole. So there is one rule rather than two, and no `--force`
— the way out is the config file, which is human-only. Text the parser cannot read is
classified a second time from the *token* stream, where a `--` comment, a string literal
and the identifier `deleted_at` no longer look like keywords, so the cost of failing
closed falls on genuinely ambiguous statements rather than on every quirk of syntax.

**Row caps and timeouts are enforced here, not by trusting a `LIMIT` in the text.**
`max_rows` and `timeout` are per-connection ceilings a request may lower and never raise.
A statement that outruns its budget is cancelled and logged as `timeout`, with the rows
already read reported as the prefix they are.

**Every denial is audited** — two events sharing a `query_id`, exactly like a query that
ran, with `status = 'denied'` on the second. A denial that left one event would make the
`queries` view report it as a query killed mid-flight, which it was not.

**And a denial is logged at the connection's own fidelity, not at a denial's.** §6.3 says
a denial is audited "with the SQL that triggered it" and §5.1 says literals are PII, and
both hold at once: the SQL is on the `query_started` row at whatever `sql_logging` the
connection asked for. Storing full text *because* a query was refused would mean anyone
who can get a statement denied on purpose can write literals into the log of a connection
whose owner asked for none — an exfiltration channel into the audit trail, opened by the
feature meant to close one.

Exit codes tell the failures apart: `0` ok, `1` the query ran and failed, `2` usage,
`3` a broken chain, `4` the log could not be written, `5` the export failed, and `6` the
policy engine refused it. A script that sees `6` should stop and ask a human, not retry.

### `quokka mcp`

```jsonc
// in your MCP client's configuration
{
  "mcpServers": {
    "quokka": { "command": "quokka", "args": ["mcp"] }
  }
}
```

Seven tools: `list_connections`, `list_schemas`, `describe_table`, `query`, `explain`,
`export`, `search_audit`. Nothing that changes configuration — an agent that can lower
the fidelity of its own audit trail, or raise its own cap, does not have one.

**The server is read-only unless a human starts it with `--allow-writes`**, whatever a
connection's own mode says. That flag lives in the MCP client's configuration file, which
a person writes, so an agent's `write: true` is confined to what two human decisions
already allowed. It can only ever make a connection stricter, never more permissive,
which is why it is not an exception to "the mode binds every surface identically": an
exception would be a surface that gets *more* than the mode allows.

**One query, then pages.** `quokka mcp` is a long-lived process, so a statement runs once
and every page, re-sort, filter and export afterwards is a read of the local cache it
filled. The same query paged three times leaves exactly one pair of events in the log.
Responses are hard-capped at 512 rows; `scope_note` is on every page that holds a prefix
rather than a whole result, because an agent handed the top of a truncated cache as
though it were the top of the result will not notice.

The server keeps the 32 most recent results open and releases the oldest past that — a
bound the CLI never needed, since a spool died with the invocation that made it, and one a
server does, or "long-lived" would mean "grows until the disk does". A result that has
been released is not a silent empty page: the call naming it is told the rows are gone and
that getting them back means running the query again.

**The agent sees every connection the CLI does.** Hiding one would be a second, weaker
guardrail competing with the real one: a connection an agent cannot see is a connection
it cannot reach, the name leaks through the first error message that mentions it, and a
hidden-but-reachable connection is worse than a visible read-only one. Visibility is
documentation; the mode is the guardrail.

Two boundaries worth stating rather than implying. An allowlist governs *statements*, not
catalog reads — `describe_table` still describes a table the allowlist would not let you
query. And `export` writes to the path it is given, anywhere the process can write; the
guarantee is that the export is an audited event, not that the filesystem is fenced off.

### `quokka explain`

```console
$ quokka explain --connection prod "SELECT * FROM orders WHERE email = 'a@b.example'"
SEARCH orders USING INDEX orders_email (email=?)
(sqlite plan · 3 ms · query 018f…)
```

`EXPLAIN` runs SQL, so it is a query like any other: the same policy check, the same two
events. Explaining a write needs the same access as running one. A plain `EXPLAIN` does
not execute the statement on any engine here, so it is tempting to let a read-only
connection explain a `DELETE` — but the relaxation would rest on a per-engine claim about
whether `EXPLAIN` executes, inherited silently by every driver added later, and this
project does not make claims it has not tested. `EXPLAIN ANALYZE`, which does execute, is
not reachable at all: the prefix is written by the driver, never taken from the caller.

## The result spool

A query runs **once**. As its rows arrive they are written into a per-result SQLite cache,
and everything after that — the preview on screen, the next page, a re-sort, the export —
is a read of that cache:

```console
$ quokka query --connection prod "SELECT * FROM orders" --export ./orders.parquet
… 512 rows …
(512 of 48,120 rows shown · 91 ms · query 018f…)
exported 48120 rows to ./orders.parquet (parquet, 184122 bytes)
```

One execution, one bill. Paging never re-runs the query, which matters most where it
costs money: `LIMIT 512 OFFSET n` against an arbitrary query re-scans per page, and
without a total ordering page 2 can repeat rows from page 1.

Export streams — CSV, TSV, JSON, NDJSON and Parquet — and is never bounded by what the
screen can hold. `-` writes to stdout; `--all` streams straight from the driver to the
file with no cache at all, for a dataset larger than local disk.

**The spool is ephemeral.** It lives in a PID-scoped directory under the XDG *cache*
directory (`$QUOKKA_CACHE_DIR` overrides it) — not `/tmp`, which is tmpfs on many systems
and would put a 1 GiB spool in RAM. It is deleted on clean exit, and a crash's leftovers
are swept at the next startup. A cache that outlived the session would serve rows that no
longer match the database, which is the one thing a query tool must not do.

So a `quokka` invocation cannot page or export an *earlier* invocation's result — the
rows died with it. `quokka export --query-id <id>` therefore refuses unless you add
`--rerun`, and says why:

```console
$ quokka export --query-id 018f… -o ./orders.csv
error: refusing to export query 018f… without --rerun.

A spool does not survive the process that made it (§4.1), so the rows from that
invocation are gone. Producing this file means executing the query again, which costs a
second scan — on Athena, real money — and QuokkaQuery never spends that implicitly.
```

`--rerun` needs the connection's `sql_logging` to be `full`. At the default,
`fingerprint`, the log kept the query's *shape* with literals replaced by `?`, so the text
needed to run it again was never written down — and reconstructing SQL from a fingerprint
would run a different query from the one you are citing, so we refuse rather than guess.

**Exports are audited events in their own right**, linked to the query that produced them
by `parent_id` — including the ones that fail. An export that filled a disk part way
through is logged with the rows that reached the file, because a log that disagreed with
what is on disk would be worse than no record at all, and it exits `5` rather than the
usage code: the query ran, only the file did not. Note that this is the opposite of the rule for a catalog cache hit, and
deliberately: a cache hit logs nothing because nothing was read, while an export logs
because "someone wrote ten million rows to a file" is exactly what an audit trail exists
to catch.

**Truncation is always reported, never silent.** Two caps can stop a result being whole,
they say so differently, and the log tells them apart: at `--max-rows` every row that came
back was kept (`rows_spooled = rows_returned`), while at the spool's own cap the rows kept
coming and the cache stopped growing (`rows_spooled < rows_returned`). Sorting or
filtering a truncated result orders the *spooled* rows — the top of the first million is
not the top of twelve million — so every page and every export says so in as many words.

### Drivers

| Driver | Implementation | Tested against |
| --- | --- | --- |
| `sqlite` | sqlx 0.9 over bundled SQLite (`libsqlite3-sys`, a C library) | in-memory and on-disk, every platform CI builds |
| `postgres` | sqlx 0.9, pure Rust wire protocol, `rustls` | PostgreSQL 16 |
| `mysql` | sqlx 0.9, pure Rust wire protocol, `rustls` | MySQL 8.4 |

`libmysqlclient` is never linked: it is GPLv2 and this project is MIT.

**MySQL 8 and `caching_sha2_password`.** That is MySQL 8's default authentication plugin,
and on a connection with no TLS it requires the client to fetch the server's RSA public
key and encrypt the password with it. QuokkaQuery enables sqlx's `mysql-rsa` feature so
this works out of the box — the alternative is a driver that cannot log in to a default
MySQL 8 unless you turn TLS on. The `rsa` crate it pulls is RustCrypto: pure Rust,
MIT/Apache-2.0. Note that only the *public-key encryption* half is used here, to send the
password; if you would rather the key exchange never happened at all, set `tls =
"require"` on the connection, which is the better answer anyway. MariaDB still defaults
to `mysql_native_password` and never reaches this path.

The "tested against" column is not a claim, it is the version the container-backed tests
pin and CI runs on every pull request (`cargo test -p quokka-driver --features
docker-tests`). Claiming support for a database nobody has run against is the failure
this project's architecture doc exists to avoid, so the table is meant to be read as
"this, and nothing else yet".

**Unknown types render as text, never fail.** A Postgres range, array, enum, `hstore`,
composite or any OID this build has never heard of comes back as the string the server
would have printed, rather than aborting the result set. Exact numerics (`numeric`,
`decimal`) stay text deliberately, because they are exact and an `f64` is not.

### Credentials

Passwords never go in the config file. A connection names *where* its credential lives,
and QuokkaQuery fetches it at connect time:

```console
$ quokka credential set prod          # prompts without echo, or reads stdin
$ quokka credential status
connection  credential                backend     stored
----------  ------------------------  ----------  ------
prod        keyring:quokkaquery/prod  os_keyring  true
```

The store is the OS keyring — Keychain, Credential Manager, Secret Service. Where there
is none, which is most headless Linux, there is an encrypted file behind it:
XChaCha20-Poly1305 under an Argon2id-derived key. Be clear about that key. With
`$QUOKKA_CREDENTIAL_PASSPHRASE` set, the file is useless to someone who copies it.
Without one, the key sits in a `0600` file beside it and **file permissions are the
security boundary** — the same boundary `~/.pgpass` and `~/.ssh/id_ed25519` have always
relied on.

A resolved credential is a `Secret`: no `Display`, no `Serialize`, a `Debug` that prints
`***`, and zeroized on drop. That is what keeps a password out of a log line, rather than
the discipline of whoever writes the next `format!`. Connection errors name
`user@host:port/database` and nothing else.

### Schema introspection

`quokka schema describe` reads the catalog and leaves **exactly one `introspect` event**
in the log — never a `query_started`/`query_finished` pair, because the SQL that ran is
the driver's own and bounded rather than the caller's.

Catalogs are cached with a per-connection TTL (`catalog_ttl`, 60s by default) so that
editor autocomplete never waits. **A cache hit logs nothing at all**: nothing reached a
database, so there is nothing to describe. At a one-minute TTL, a row per hit would be
thousands a day asserting reads that never happened.

## The audit log

Every query leaves exactly two rows — `query_started` before execution and
`query_finished` after — sharing a `query_id`. If the start cannot be written, the query
does not run.

The log records **which** queries ran, by whom, against what, and how they went. It never
records **what came back**: no rows, no samples, no digests of rows. The remaining PII
surface is the query text itself, so `sql_logging` defaults to `fingerprint` — the
statement's shape with literals replaced by `?` — and full text is opt-in per connection.

```console
$ quokka audit verify
the chain is intact: 148 events verified
```

The chain makes an edit or an excision detectable. Be clear about what that buys a
single-user tool: the threat model is **an agent with shell access quietly editing the
log of what it just did**, not a colleague disputing the record. It is emphatically not a
defence against the machine's owner, who can rebuild the chain at will.

## Configuration

`$QUOKKA_CONFIG`, else `<XDG config dir>/quokkaquery/config.toml`:

```toml
[connections.app]
driver      = "sqlite"
path        = "/path/to/app.db"
mode        = "read_only"     # read_only (default) | read_write
sql_logging = "fingerprint"   # fingerprint (default) | full

[connections.prod]
driver          = "postgres"  # or "mysql"
host            = "db.example.com"   # a value starting with / is a unix socket directory
port            = 5432               # defaults to the driver's standard port
database        = "app"
user            = "reader"
credential      = "keyring"   # keyring (default) | keyring:<service>/<account>
                              # | env:<VAR> | none
tls             = "prefer"    # disable | prefer (default) | require | verify-ca | verify-full
catalog_ttl     = "60s"       # "0" to cache nothing
connect_timeout = "10s"

# Optional guardrails (§6.3). Every one of them is a ceiling a request may lower and
# can never raise.
[connections.reporting]
driver        = "postgres"
host          = "db.example.com"
database      = "app"
schema        = "analytics"   # resolves an unqualified name against the allowlist
credential    = "keyring"
max_rows      = 100000        # most rows any one query may read
timeout       = "30s"         # cancelled and logged as `timeout` past this
allow_schemas = ["analytics"] # statements may only name these...
allow_tables  = ["public.orders", "public.customers"]   # ...or these

[spool]
max_rows  = 1000000           # 1M rows / 1 GiB by default; both bound local disk
max_bytes = "1GiB"            # "512MB", "1GiB", or a plain byte count
```

An allowlisted connection admits queries, DML and `EXPLAIN` — the statement kinds whose
object lists the classifier can enumerate in full. DDL, `COPY` and `VACUUM` are refused
outright rather than waved through: `DROP TABLE t` reports no table reference at all and
`COPY t FROM '…'` carries its target somewhere a check would never look, so an allowlist
that passed them would be finding nothing to object to rather than finding them
acceptable.

`mode = "read_only"` holds at two layers, and the guarantee is that both do. The
classifier refuses a write before a driver is opened — that is the layer an agent meets,
and the one that produces a `denied` row in the log. Underneath it, the server itself
refuses: Postgres gets `default_transaction_read_only` in its startup packet, MySQL a
`SET SESSION TRANSACTION READ ONLY` per connection, and SQLite is opened read-only at the
file handle. The mode binds every surface identically — the human at the UI as much as an
agent.

Configuration is human-only. There is no CLI flag and no agent-callable tool that changes
`sql_logging`, a connection's mode, or a cost budget — an agent that can lower the
fidelity of its own audit trail defeats the point of the log.

## Building

Needs a C compiler on every platform, because `sqlx-sqlite` builds bundled SQLite through
`libsqlite3-sys`. That is still the only one: Parquet export pulls `arrow`/`parquet`
(Apache-2.0) and the pure-Rust `snap` codec (BSD-3-Clause), none of which is a `-sys`
crate, and the compression codecs that would link C — `zstd`, `lz4` — stay switched off.
Nothing in the tree is GPL. `cargo test` runs everywhere and needs no Docker.

```console
$ cargo build
$ cargo test
```

Parquet is a default-on feature of `quokka-spool`, and the CLI asks for it by name — so
`cargo install quokkaquery --no-default-features`, which exists to drop the GUI stack for
a container or an agent's box, still writes Parquet. A library consumer that only needs
CSV can drop ~60 crates with `quokka-spool = { …, default-features = false }`.

The container-backed tests for Postgres and MySQL are behind a feature, so they only run
when you ask for them and Docker is there:

```console
$ cargo test --package quokka-driver --features docker-tests
```

The densest tests in the repo are `quokka-policy`'s corpus, because that is the security
boundary and a miss there is a hole rather than a bug: comments and string literals that
say `DELETE`, writes buried two CTEs deep, semicolons inside strings, stacked statements
in text the parser cannot read, and every one of those traps aimed a second time at the
weaker token classifier that handles what `sqlparser` cannot parse.

CLAUDE.md asks for `cargo fmt` and `cargo clippy -- -D warnings` clean before every
commit. A hook that enforces it is checked in; opt into it once per clone:

```console
$ git config core.hooksPath .githooks
```

CI is the authority — it runs fmt, clippy and the tests on Linux, macOS and Windows,
checks that `--no-default-features` pulls no GUI dependencies, and pins the declared
`rust-version`. The full release matrix arrives with `cargo-dist` at M6.

`docs/ARCHITECTURE.md` is the source of truth for every decision here, and `CLAUDE.md`
lists the invariants that must not be eroded.

## Licence

MIT.
