-- The three tables ARCHITECTURE §4 names. The result table's column list is filled in
-- for the result's actual width: c0, c1, … cN.
--
-- Note what the result columns are declared as: nothing at all. A column with no
-- declared type takes BLOB affinity, which is SQLite's one affinity that converts
-- nothing — an exact `numeric` arriving from Postgres as text stays text, and an
-- integer stays an integer. Declaring them `TEXT` or `NUMERIC` here would silently
-- convert values on the way in, which is precisely the failure §4.2 calls the known
-- cost of a SQLite spool and precisely the one we refuse to pay.
CREATE TABLE result (
  rowid INTEGER PRIMARY KEY{columns}
);

-- SQLite has five storage classes and a database has hundreds of types, so the driver's
-- own type name travels beside the rows rather than in them. This is what carries
-- `numeric`, `timestamptz` or `hstore` across to an export or a grid header.
CREATE TABLE schema (
  ordinal     INTEGER PRIMARY KEY,
  name        TEXT NOT NULL,
  driver_type TEXT NOT NULL,
  nullable    INTEGER
);

-- Row count, truncation and timings (§4). Also the spool's creation time, which is what
-- lets a result tab say "as of 10:00 (45m ago)" at M4.
CREATE TABLE meta (
  key   TEXT PRIMARY KEY,
  value TEXT NOT NULL
);
