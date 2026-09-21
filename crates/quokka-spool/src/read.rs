//! Reading a finished spool: paging, sorting, filtering and counting.
//!
//! Everything here is a `SELECT` against a local SQLite file this process wrote. None of
//! it reaches a database, none of it costs a second execution, and none of it needs an
//! [`ExecutePermit`](quokka_core::ExecutePermit) — the one reaching for a permit here
//! would be a sign of having taken a wrong turn (§1.4, §4).

use std::path::{Path, PathBuf};

use futures::StreamExt;
use quokka_core::{Column, Row, Value};
use sqlx::sqlite::{SqliteConnectOptions, SqlitePoolOptions};
use sqlx::{Row as _, SqlitePool};
use uuid::Uuid;

use crate::codec;
use crate::error::SpoolError;
use crate::meta::{Meta, MetaKey};
use crate::view::{Filter, Op, Position, Scoping, View};

/// The page size nothing may exceed at the UI or over MCP (§4.2). Configurable
/// downward, never upward — which is why this is a constant and not a setting.
pub const MAX_PAGE_ROWS: u64 = 512;

/// One page of a result.
#[derive(Debug, Clone)]
pub struct Page {
    pub columns: Vec<Column>,
    pub rows: Vec<Row>,
    /// Where the next page starts, or `None` when this was the last one.
    pub next: Option<Position>,
    /// How many rows precede the first row here, under this view.
    pub rows_before: u64,
    /// What these rows are a part of. Never optional: see [`Scoping`].
    pub scope: Scoping,
}

/// A finished spool, open for reading.
#[derive(Debug, Clone)]
pub struct Spool {
    pool: SqlitePool,
    path: PathBuf,
    columns: Vec<Column>,
    meta: Meta,
}

impl Spool {
    /// Open a spool written by [`crate::SpoolWriter`].
    pub async fn open(path: impl AsRef<Path>) -> Result<Self, SpoolError> {
        let path = path.as_ref().to_path_buf();
        let options = SqliteConnectOptions::new()
            .filename(&path)
            .create_if_missing(false)
            // Read-only at the file handle. The spool is written once, by the sink; a
            // reader that could write to it is a reader that could disagree with the
            // query that filled it.
            .read_only(true);

        let pool = SqlitePoolOptions::new()
            .max_connections(2)
            .connect_with(options)
            .await
            .map_err(|e| SpoolError::Open {
                detail: format!("{e} ({})", path.display()),
            })?;

        let columns = read_columns(&pool).await?;
        let meta = read_meta(&pool).await?;

        Ok(Spool {
            pool,
            path,
            columns,
            meta,
        })
    }

    pub fn path(&self) -> &Path {
        &self.path
    }

    /// The result's shape, with each driver's own type name intact.
    pub fn columns(&self) -> &[Column] {
        &self.columns
    }

    pub fn meta(&self) -> &Meta {
        &self.meta
    }

    /// What these rows are a part of (§4.2).
    pub fn scoping(&self) -> Scoping {
        self.meta.scoping()
    }

    pub async fn close(&self) {
        self.pool.close().await;
    }

    /// How many rows this view selects. Exact, because the spool is a table — which is
    /// what lets a pager say "rows 1–512 of 12,481" rather than estimating (§7).
    pub async fn count(&self, view: &View) -> Result<u64, SpoolError> {
        let (where_sql, filters) = self.where_clause(&view.filters)?;
        let sql = format!("SELECT count(*) FROM result{where_sql}");
        let mut query = sqlx::query(sqlx::AssertSqlSafe(sql));
        for filter in &filters {
            query = bind_filter(query, filter);
        }
        let row = query.fetch_one(&self.pool).await?;
        Ok(row.try_get::<i64, _>(0)?.max(0) as u64)
    }

    /// One page, from `at`.
    ///
    /// In arrival order this is §4's `SELECT … WHERE rowid > ? LIMIT 512`: O(1) per
    /// page whatever the page number, stable because the rowid is the arrival order,
    /// and never a second execution.
    pub async fn page(&self, view: &View, at: Position, limit: u64) -> Result<Page, SpoolError> {
        let limit = limit.max(1);
        // A statement that returns no columns — an INSERT, a DDL — spools no rows, and
        // `SELECT rowid,  FROM result` is not SQL. There is nothing to page.
        if self.columns.is_empty() {
            return Ok(Page {
                columns: Vec::new(),
                rows: Vec::new(),
                next: None,
                rows_before: at.offset,
                scope: self.scoping(),
            });
        }
        let (where_sql, filters) = self.where_clause(&view.filters)?;
        let select = self.select_list();

        // One row more than asked for, so "is there a next page" is answered by the
        // same query rather than by a second one.
        let probe = limit.saturating_add(1);

        let sql = if view.is_arrival_order() {
            let and = if where_sql.is_empty() {
                " WHERE"
            } else {
                " AND"
            };
            format!(
                "SELECT rowid, {select} FROM result{where_sql}{and} rowid > ? \
                 ORDER BY rowid ASC LIMIT ?"
            )
        } else {
            format!(
                "SELECT rowid, {select} FROM result{where_sql} ORDER BY {} LIMIT ? OFFSET ?",
                self.order_by(view)?
            )
        };

        let mut query = sqlx::query(sqlx::AssertSqlSafe(sql));
        for filter in &filters {
            query = bind_filter(query, filter);
        }
        if view.is_arrival_order() {
            query = query.bind(at.after_rowid).bind(probe as i64);
        } else {
            query = query.bind(probe as i64).bind(at.offset as i64);
        }

        let mut rows = Vec::with_capacity(limit as usize);
        let mut last_rowid = at.after_rowid;
        let mut seen = 0u64;
        let mut more = false;

        let mut stream = query.fetch(&self.pool);
        while let Some(row) = stream.next().await {
            let row = row?;
            seen += 1;
            if seen > limit {
                more = true;
                break;
            }
            last_rowid = row.try_get::<i64, _>(0)?;
            rows.push(Row((0..self.columns.len())
                .map(|i| codec::value_at(&row, i + 1))
                .collect()));
        }
        drop(stream);

        let next = more.then(|| Position {
            after_rowid: last_rowid,
            offset: at.offset + rows.len() as u64,
        });

        Ok(Page {
            columns: self.columns.clone(),
            rows,
            next,
            rows_before: at.offset,
            scope: self.scoping(),
        })
    }

    /// Every row this view selects, streamed to `sink` in order.
    ///
    /// The shape export is written on: rows are handed over as they come off the
    /// cursor, so a spool larger than memory streams out of the process rather than
    /// through it.
    pub(crate) async fn stream<F>(&self, view: &View, mut sink: F) -> Result<u64, SpoolError>
    where
        F: FnMut(&Row) -> Result<(), SpoolError>,
    {
        if self.columns.is_empty() {
            return Ok(0);
        }
        let (where_sql, filters) = self.where_clause(&view.filters)?;
        let select = self.select_list();
        let order = if view.is_arrival_order() {
            "rowid ASC".to_string()
        } else {
            self.order_by(view)?
        };
        let sql = format!("SELECT {select} FROM result{where_sql} ORDER BY {order}");

        let mut query = sqlx::query(sqlx::AssertSqlSafe(sql));
        for filter in &filters {
            query = bind_filter(query, filter);
        }

        let mut written = 0u64;
        let mut stream = query.fetch(&self.pool);
        while let Some(row) = stream.next().await {
            let row = row?;
            let values = (0..self.columns.len())
                .map(|i| codec::value_at(&row, i))
                .collect();
            sink(&Row(values))?;
            written += 1;
        }
        Ok(written)
    }

    fn select_list(&self) -> String {
        (0..self.columns.len())
            .map(|i| format!("c{i}"))
            .collect::<Vec<_>>()
            .join(", ")
    }

    /// `ORDER BY c2 DESC, rowid ASC` — the trailing rowid is what makes an ordering
    /// total, so two rows that tie on every sort key still come back in the same order
    /// on every page.
    fn order_by(&self, view: &View) -> Result<String, SpoolError> {
        let mut parts = Vec::with_capacity(view.sort.len() + 1);
        for key in &view.sort {
            self.check_column(key.column)?;
            parts.push(format!("c{} {}", key.column, key.direction.as_sql()));
        }
        parts.push("rowid ASC".to_string());
        Ok(parts.join(", "))
    }

    fn where_clause(&self, filters: &[Filter]) -> Result<(String, Vec<Filter>), SpoolError> {
        if filters.is_empty() {
            return Ok((String::new(), Vec::new()));
        }
        let mut parts = Vec::with_capacity(filters.len());
        let mut bound = Vec::with_capacity(filters.len());
        for filter in filters {
            self.check_column(filter.column)?;
            let c = format!("c{}", filter.column);
            parts.push(match filter.op {
                Op::Eq => format!("{c} IS ?"),
                Op::Ne => format!("{c} IS NOT ?"),
                Op::Lt => format!("{c} < ?"),
                Op::Le => format!("{c} <= ?"),
                Op::Gt => format!("{c} > ?"),
                Op::Ge => format!("{c} >= ?"),
                Op::Contains => format!("instr({c}, ?) > 0"),
                Op::StartsWith => format!("substr({c}, 1, length(?)) = ?"),
                Op::IsNull => format!("{c} IS NULL"),
                Op::IsNotNull => format!("{c} IS NOT NULL"),
            });
            if !matches!(filter.op, Op::IsNull | Op::IsNotNull) {
                bound.push(filter.clone());
            }
        }
        Ok((format!(" WHERE {}", parts.join(" AND ")), bound))
    }

    fn check_column(&self, index: usize) -> Result<(), SpoolError> {
        if index >= self.columns.len() {
            return Err(SpoolError::NoSuchColumn {
                index,
                columns: self.columns.len(),
            });
        }
        Ok(())
    }

    /// The ordinal of a column by name, for a surface whose user typed one.
    pub fn column_index(&self, name: &str) -> Option<usize> {
        self.columns
            .iter()
            .position(|c| c.name.eq_ignore_ascii_case(name))
    }
}

type SqliteQuery<'q> =
    sqlx::query::Query<'q, sqlx::Sqlite, <sqlx::Sqlite as sqlx::Database>::Arguments>;

/// Bind a filter's value in the same encoding the rows were stored in, so a `Bool` or a
/// blob compares against what is actually in the column rather than against what an
/// untagged value would have been.
fn bind_filter<'q>(query: SqliteQuery<'q>, filter: &Filter) -> SqliteQuery<'q> {
    let cell = codec::encode(&filter.value);
    match filter.op {
        // `StartsWith` binds its value twice: once for `length(?)` and once for the
        // comparison.
        Op::StartsWith => {
            let first = codec::bind(query, cell.clone());
            codec::bind(first, cell)
        }
        _ => codec::bind(query, cell),
    }
}

async fn read_columns(pool: &SqlitePool) -> Result<Vec<Column>, SpoolError> {
    let rows = sqlx::query("SELECT name, driver_type, nullable FROM schema ORDER BY ordinal")
        .fetch_all(pool)
        .await?;
    rows.iter()
        .map(|r| {
            Ok(Column {
                name: r.try_get("name")?,
                driver_type: r.try_get("driver_type")?,
                nullable: r.try_get::<Option<i64>, _>("nullable")?.map(|n| n != 0),
            })
        })
        .collect()
}

async fn read_meta(pool: &SqlitePool) -> Result<Meta, SpoolError> {
    let rows = sqlx::query("SELECT key, value FROM meta")
        .fetch_all(pool)
        .await?;
    let mut map = std::collections::HashMap::new();
    for row in &rows {
        map.insert(
            row.try_get::<String, _>("key")?,
            row.try_get::<String, _>("value")?,
        );
    }
    let get = |k: MetaKey| map.get(k.as_str()).cloned();

    Ok(Meta {
        created_at: get(MetaKey::CreatedAt),
        query_id: get(MetaKey::QueryId).and_then(|s| Uuid::parse_str(&s).ok()),
        connection: get(MetaKey::Connection),
        rows: get(MetaKey::Rows).and_then(|s| s.parse().ok()).unwrap_or(0),
        rows_returned: get(MetaKey::RowsReturned)
            .and_then(|s| s.parse().ok())
            .unwrap_or(0),
        spool_capped: get(MetaKey::SpoolCapped),
        truncated_by_max_rows: get(MetaKey::TruncatedByMaxRows).as_deref() == Some("true"),
        query_duration_ms: get(MetaKey::QueryDurationMs).and_then(|s| s.parse().ok()),
        status: get(MetaKey::Status),
    })
}

/// A value as a filter would be given one on a command line: everything is text unless
/// it parses as a number, which is the same guess a grid's filter box makes.
pub fn filter_value(text: &str) -> Value {
    if let Ok(i) = text.parse::<i64>() {
        return Value::Int(i);
    }
    if let Ok(x) = text.parse::<f64>() {
        if x.is_finite() {
            return Value::Float(x);
        }
    }
    Value::Text(text.to_string())
}
