# QuokkaQuery

A single-user database client: a CLI for agents, a native iced UI for humans, and one
append-only audit log of every query that both can query as an ordinary connection.
SQLite, PostgreSQL, MySQL and Athena. Binary: `quokka`. Package: `quokkaquery`.

**`docs/ARCHITECTURE.md` is the source of truth.** Read it before designing anything.
Every decision there carries its rationale; this file is only the set of rules that must
not be re-litigated or quietly eroded.

---

## Invariants

These are load-bearing. Breaking one silently breaks a promise the product makes.

1. **One execute path.** Nothing reaches a database except through
   `quokka-core::execute()`. It consults the policy engine, dispatches to a `Driver`,
   spools the result, and writes the audit events. No surface — CLI, UI, MCP — gets its
   own shortcut, and no driver is callable directly from a surface crate.

2. **No query runs without consent.** No auto-refresh, no polling, no speculative
   prefetch, no autocomplete that queries to fill a suggestion. Paging reads the spool,
   never the database. Anything that costs a second execution needs an explicit action
   (`--rerun`, a button press). Queries cost money; the user decides when to spend it.

3. **512 rows is a ceiling, not a default.** Hard cap for the UI grid and for MCP tool
   responses; configurable downward only. It counts rows, not cells. The full dataset
   reaches the user through streamed export, never through a bigger grid.

4. **No result data in the audit log. Ever.** Not rows, not samples, not digests or
   hashes of rows. The log describes queries — who, what, when, against which connection,
   how it went — never what came back.

5. **The audit log is append-only.** Never `UPDATE` or `DELETE` a row; triggers enforce
   it. A query writes two events (`query_started` before execution, `query_finished`
   after) sharing a `query_id`. Never collapse them into one mutable row.

6. **Fail closed.** If `query_started` cannot be written, the query does not run.

7. **Config is human-only.** An agent cannot change `sql_logging`, a connection's
   read-only mode, or its own cost budget. An agent that can lower the fidelity of its
   own audit trail defeats the log's purpose.

8. **`fingerprint` is the default logging mode.** Full SQL text is opt-in per connection,
   chosen explicitly at connection creation. Literals are PII.

9. **The connection mode binds every surface identically.** Read-only means read-only for
   the human at the UI as much as for an agent. No per-surface exemptions — that would
   turn a structural property into a policy.

10. **Unknown column types degrade to text, never fail.** An unrecognized type renders as
    a string; it must never abort a result set.

---

## Scope stance

Say no to these, and say it in the README:

- **No inline cell editing.** Not a missing feature — a stance. It generates hidden
  `UPDATE`s, which is exactly what an audit-first tool must not do. Writes are SQL you can
  read and find in the log.
- **No ER diagrams, no visual query builder, no data modelling.** DBeaver does those.
- **No accounts, no server, no shared state.** One person and their agents, one machine.
- **No app bundle.** Ship a plain binary; never a browser-downloaded `.app`/`.dmg`.

When a request would widen scope, the answer is a bounded version of it or a no — not a
quiet yes.

---

## Layout

```
crates/
  quokka-core     Value/Row, connection registry, config, execute(), redaction
  quokka-driver   trait Driver + sqlite / postgres / mysql / athena
  quokka-spool    per-result SQLite cache: paging, sorting, export
  quokka-audit    append-only log: schema, hash chain, search
  quokka-policy   sqlparser classification, read-only enforcement, cost guard
  quokka-cli      clap CLI (bin: quokka)
  quokka-mcp      stdio MCP server
  quokka-ui       iced app, behind a default-on `ui` feature
```

`--no-default-features` must always yield a working headless CLI with no `wgpu`/`winit`
in the tree. Keep logic in `quokka-core`, not in iced `update`/`view` functions.

## Conventions

- Rust 2021+, `cargo fmt` and `cargo clippy -- -D warnings` clean before every commit.
- `cargo test` must pass with no Docker; container-backed tests go behind a feature.
- One crate and one cargo feature per driver.
- Errors: `thiserror` in libraries, `anyhow` at the CLI boundary.
- Never add a dependency that pulls a system webview, a JS toolchain, or GPL code.
- Commit messages explain *why*, not just what. No model identifiers in anything pushed.

## Testing priorities

Densest tests belong where a bug is worst:

1. `quokka-policy` — the security boundary. Table-driven over a SQL corpus including
   comments, CTEs that hide writes, and dialect quirks.
2. `quokka-audit` — property test that the hash chain detects every single-row edit or
   deletion, and that no path executes SQL without appending both events.
3. `quokka-spool` — round-trip per driver type; truncation is always reported, never
   silent.
