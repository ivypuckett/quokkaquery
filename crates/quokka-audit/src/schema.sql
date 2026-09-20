-- The audit log (ARCHITECTURE §5). One row per event; a query writes two.
CREATE TABLE IF NOT EXISTS audit_log (
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

  status            TEXT NOT NULL,      -- started | ok | error | cancelled | denied | timeout
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

CREATE INDEX IF NOT EXISTS audit_log_query_id ON audit_log (query_id);
CREATE INDEX IF NOT EXISTS audit_log_at ON audit_log (at);
CREATE INDEX IF NOT EXISTS audit_log_actor ON audit_log (actor_id, at);

-- Append-only, enforced by the database rather than by convention (§5).
CREATE TRIGGER IF NOT EXISTS audit_log_no_update
BEFORE UPDATE ON audit_log
BEGIN
  SELECT RAISE(ABORT, 'audit_log is append-only: UPDATE is forbidden');
END;

CREATE TRIGGER IF NOT EXISTS audit_log_no_delete
BEFORE DELETE ON audit_log
BEGIN
  SELECT RAISE(ABORT, 'audit_log is append-only: DELETE is forbidden');
END;

-- The chain's head, checkpointed on every append.
--
-- A pure back-link chain detects edits and mid-log excisions, but truncating the *tail*
-- leaves a shorter chain that still verifies. Recording the head separately closes that
-- gap, so `quokka audit verify` detects the removal of any single row, including the
-- last one. It is a checkpoint, not a log, so it is the one table here that is mutable.
CREATE TABLE IF NOT EXISTS audit_chain_head (
  id         INTEGER PRIMARY KEY CHECK (id = 0),
  head_id    TEXT,
  head_hash  TEXT,
  row_count  INTEGER NOT NULL
);

INSERT OR IGNORE INTO audit_chain_head (id, head_id, head_hash, row_count)
VALUES (0, NULL, NULL, 0);

-- Reconstructing a query's full story is a join on query_id, so the @audit connection
-- ships the join rather than making every caller write it (§5).
CREATE VIEW IF NOT EXISTS queries AS
SELECT
  s.query_id                              AS query_id,
  s.parent_id                             AS parent_id,
  s.at                                    AS started_at,
  f.at                                    AS finished_at,
  f.duration_ms                           AS duration_ms,
  s.actor_kind                            AS actor_kind,
  s.actor_id                              AS actor_id,
  s.session_id                            AS session_id,
  s.client                                AS client,
  s.connection                            AS connection,
  s.dialect                               AS dialect,
  s.database                              AS database,
  s.schema_name                           AS schema_name,
  s.sql_logging                           AS sql_logging,
  s.sql_text                              AS sql_text,
  s.sql_fingerprint                       AS sql_fingerprint,
  s.statement_kind                        AS statement_kind,
  s.read_only                             AS read_only,
  s.params                                AS params,
  -- A start with no finish is visible as exactly that: killing the process mid-query
  -- no longer erases the attempt (§5).
  COALESCE(f.status, 'unfinished')        AS status,
  f.error_code                            AS error_code,
  f.error_message                         AS error_message,
  f.rows_returned                         AS rows_returned,
  f.rows_affected                         AS rows_affected,
  f.rows_spooled                          AS rows_spooled,
  f.truncated                             AS truncated,
  f.data_scanned_bytes                    AS data_scanned_bytes,
  f.cost_estimate_usd                     AS cost_estimate_usd,
  s.approved_by                           AS approved_by,
  s.tags                                  AS tags,
  s.id                                    AS started_event_id,
  f.id                                    AS finished_event_id
FROM audit_log s
LEFT JOIN audit_log f
  ON f.query_id = s.query_id AND f.event_kind = 'query_finished'
WHERE s.event_kind = 'query_started';
