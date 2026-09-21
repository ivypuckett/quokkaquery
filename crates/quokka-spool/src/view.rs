//! What a caller may ask a spool for: an ordering, a filter, a page.
//!
//! Note what a filter is *not*: a fragment of SQL. The spool is a table we can query,
//! but a caller-supplied `WHERE` clause would be a second way to get SQL executed and
//! a way to reach the `meta` and `schema` tables from a grid's filter box. So a filter
//! is a column, an operator and a value, bound as a parameter — which is everything a
//! grid filter needs and nothing else.

use quokka_core::Value;

/// Which way a column sorts.
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize)]
#[serde(rename_all = "snake_case")]
pub enum Direction {
    Asc,
    Desc,
}

impl Direction {
    pub fn as_sql(self) -> &'static str {
        match self {
            Direction::Asc => "ASC",
            Direction::Desc => "DESC",
        }
    }
}

/// One sort key: a column's ordinal and a direction.
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize)]
pub struct SortKey {
    pub column: usize,
    pub direction: Direction,
}

impl SortKey {
    pub fn asc(column: usize) -> Self {
        SortKey {
            column,
            direction: Direction::Asc,
        }
    }

    pub fn desc(column: usize) -> Self {
        SortKey {
            column,
            direction: Direction::Desc,
        }
    }
}

/// How a filter compares.
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize)]
#[serde(rename_all = "snake_case")]
pub enum Op {
    Eq,
    Ne,
    Lt,
    Le,
    Gt,
    Ge,
    /// Substring, case-sensitive. `instr`, not `LIKE`: a value containing `%` should
    /// match itself rather than becoming a wildcard.
    Contains,
    StartsWith,
    IsNull,
    IsNotNull,
}

/// One filter over one column.
#[derive(Debug, Clone, PartialEq)]
pub struct Filter {
    pub column: usize,
    pub op: Op,
    pub value: Value,
}

impl Filter {
    pub fn new(column: usize, op: Op, value: Value) -> Self {
        Filter { column, op, value }
    }
}

/// An ordering and a set of filters over one spool.
#[derive(Debug, Clone, Default, PartialEq)]
pub struct View {
    pub filters: Vec<Filter>,
    pub sort: Vec<SortKey>,
}

impl View {
    /// The result as it arrived, unfiltered — what a first page shows.
    pub fn arrival_order() -> Self {
        View::default()
    }

    pub fn sorted_by(sort: Vec<SortKey>) -> Self {
        View {
            filters: Vec::new(),
            sort,
        }
    }

    pub fn with_filter(mut self, filter: Filter) -> Self {
        self.filters.push(filter);
        self
    }

    /// True when rows come back in the order they arrived, which is the case where
    /// paging can use the rowid rather than an offset.
    pub fn is_arrival_order(&self) -> bool {
        self.sort.is_empty()
    }
}

/// Where the next page starts.
///
/// Opaque because the two cases are not the same: in arrival order a page resumes from
/// the last rowid, which is O(1) whatever the page number; under a sort it resumes from
/// an offset, because "the next 512 rows in this ordering" has no cheaper answer over a
/// table that has no index on the sort column. Both read the spool, and neither reaches
/// a database.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Position {
    pub(crate) after_rowid: i64,
    pub(crate) offset: u64,
}

impl Position {
    /// The first page.
    pub fn start() -> Self {
        Position {
            after_rowid: 0,
            offset: 0,
        }
    }

    /// How many rows precede this position, for a "rows 513–1024 of 12,481" pager.
    pub fn rows_before(&self) -> u64 {
        self.offset
    }
}

impl Default for Position {
    fn default() -> Self {
        Position::start()
    }
}

/// How much of the query's result the rows in hand actually are.
///
/// Carried by every read of a spool — every page, every export report — because the
/// trap §4.2 names is a sort that looks authoritative and is not: sorting a spool that
/// holds the first million rows of twelve million yields the top of the first million,
/// which is a confidently wrong answer to the question the user asked. A surface cannot
/// get that wrong by omission here, because the scoping arrives whether it asked or not
/// and [`Scoping::note`] writes the sentence for it.
#[derive(Debug, Clone, PartialEq, serde::Serialize)]
pub struct Scoping {
    /// Rows the spool holds.
    pub spooled_rows: u64,
    /// Rows the query returned to the engine.
    pub rows_returned: u64,
    /// `rows` or `bytes` when the spool's own cap stopped it (§4.2).
    pub spool_capped: Option<String>,
    /// Whether the caller's `max_rows` stopped the read.
    pub truncated_by_max_rows: bool,
}

impl Scoping {
    /// True when these rows are the query's whole result.
    pub fn is_whole_result(&self) -> bool {
        self.spool_capped.is_none() && !self.truncated_by_max_rows
    }

    /// The sentence a surface should show beside a sort or a filter over these rows.
    ///
    /// `None` when there is nothing to say, so a caller can print it unconditionally.
    pub fn note(&self) -> Option<String> {
        match (&self.spool_capped, self.truncated_by_max_rows) {
            (Some(cap), _) => Some(format!(
                "scoped to the {} row{} in the spool: the spool's {cap} cap stopped it, \
                 and the query returned at least {}. Sorting or filtering these rows \
                 orders the spooled prefix, not the result — re-run with ORDER BY to \
                 sort the whole thing.",
                self.spooled_rows,
                if self.spooled_rows == 1 { "" } else { "s" },
                self.rows_returned,
            )),
            (None, true) => Some(format!(
                "scoped to the {} row{} that were read: --max-rows stopped the read \
                 before the result was exhausted, so these are a prefix of it.",
                self.spooled_rows,
                if self.spooled_rows == 1 { "" } else { "s" },
            )),
            (None, false) => None,
        }
    }
}
