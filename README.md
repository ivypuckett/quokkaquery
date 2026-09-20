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

## Status: M1 — the daily-driver CLI

What works today:

- `quokka query --connection <name> "SELECT …" --format json|ndjson|table --max-rows N`,
  with `--param` for bound values
- `quokka connections list` and `quokka schema describe <table>`
- `quokka credential set | delete | status`
- `quokka audit tail | query | verify`
- **SQLite, PostgreSQL and MySQL**, read-only by default
- The audit log: SQLite in WAL mode, append-only triggers, a hash chain, and the built-in
  `@audit` connection with a `queries` view

The result spool arrives at M2, the policy engine and the MCP server at M3, the iced UI
at M4, and Athena at M5. See `docs/ARCHITECTURE.md` §10.

### Drivers

| Driver | Implementation | Tested against |
| --- | --- | --- |
| `sqlite` | sqlx 0.9 over bundled SQLite (`libsqlite3-sys`, a C library) | in-memory and on-disk, every platform CI builds |
| `postgres` | sqlx 0.9, pure Rust wire protocol, `rustls` | PostgreSQL 16 |
| `mysql` | sqlx 0.9, pure Rust wire protocol, `rustls` | MySQL 8.4 |

`libmysqlclient` is never linked: it is GPLv2 and this project is MIT.

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
```

`mode = "read_only"` is enforced by the server, not by us declining to send the write:
Postgres gets `default_transaction_read_only` in its startup packet and MySQL a `SET
SESSION TRANSACTION READ ONLY` per connection. The mode binds every surface identically —
the human at the UI as much as an agent.

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

The container-backed tests for Postgres and MySQL are behind a feature, so they only run
when you ask for them and Docker is there:

```console
$ cargo test --package quokka-driver --features docker-tests
```

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
