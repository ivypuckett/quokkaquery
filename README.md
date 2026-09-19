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
  prefetch. Queries cost money; you decide when to spend it.

## Status: M0

This is the end-to-end skeleton — a query runs and is provably logged. What works today:

- `quokka query --connection <name> "SELECT …" --format json|ndjson|table --max-rows N`
- `quokka audit tail | query | verify`
- SQLite connections, read-only by default
- The audit log: SQLite in WAL mode, append-only triggers, a hash chain, and the built-in
  `@audit` connection with a `queries` view

Postgres and MySQL arrive at M1, the result spool at M2, the policy engine and the MCP
server at M3, the iced UI at M4, and Athena at M5. See `docs/ARCHITECTURE.md` §10.

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
```

Configuration is human-only. There is no CLI flag and no agent-callable tool that changes
`sql_logging`, a connection's mode, or a cost budget — an agent that can lower the
fidelity of its own audit trail defeats the point of the log.

## Building

Needs a C compiler on every platform, because `sqlx-sqlite` builds bundled SQLite through
`libsqlite3-sys`. `cargo test` runs everywhere and needs no Docker.

```console
$ cargo build
$ cargo test
```

`docs/ARCHITECTURE.md` is the source of truth for every decision here, and `CLAUDE.md`
lists the invariants that must not be eroded.

## Licence

MIT.
