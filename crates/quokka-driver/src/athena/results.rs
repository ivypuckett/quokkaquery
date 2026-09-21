//! Step 3 of §3.2: page `GetQueryResults`, typing columns from `ResultSetMetadata`.

use aws_sdk_athena::types::{ColumnInfo, ColumnNullable, ResultSet};
use aws_sdk_athena::Client;
use quokka_core::{Column, DriverError, Row, Value};

pub use super::convert::value_for_type;

/// One page of a result: its shape, and its rows already converted.
#[derive(Debug, Clone)]
pub struct Page {
    pub columns: Vec<Column>,
    pub rows: Vec<Row>,
}

/// A result set being paged out of Athena.
///
/// Holds the token rather than a stream, because the first page has to be read by
/// `execute()` itself — that is where `ResultSetMetadata` arrives, and the result's
/// shape has to be known before `RowSink::begin` is called.
pub struct Pages {
    client: Client,
    execution_id: String,
    token: Option<String>,
    /// False until the first page has been read. It is the page whose leading row may be
    /// a header — see [`Pages::next_page`].
    started: bool,
    columns: Vec<Column>,
}

/// How many rows to ask for per `GetQueryResults` call.
///
/// Athena's own maximum. Fewer would mean more round trips for the same rows and no
/// benefit: the rows are already paid for by the time they can be fetched, and the
/// channel between this and the consumer is what provides backpressure.
const PAGE_SIZE: i32 = 1000;

impl Pages {
    pub fn start(client: Client, execution_id: String) -> Self {
        Pages {
            client,
            execution_id,
            token: None,
            started: false,
            columns: Vec::new(),
        }
    }

    /// Whether another `GetQueryResults` call would return anything.
    pub fn has_more(&self) -> bool {
        self.token.is_some()
    }

    /// The result's shape, known from the first page onwards.
    pub fn columns(&self) -> &[Column] {
        &self.columns
    }

    /// Read the next page.
    ///
    /// **The header row.** For a `SELECT`, Athena puts the column *names* in the first
    /// row of the first page — a quirk of `GetQueryResults` rather than of the data, and
    /// one that has bitten every Athena client ever written. It is not present for every
    /// statement kind (`SHOW`, `DESCRIBE` and DDL do not have it), and there is no flag
    /// saying which you got. So the rule here is the conservative one: on the first page
    /// only, drop the leading row if every one of its cells is exactly the name of the
    /// column it sits under. A genuine first row of data that happens to hold each
    /// column's own name is lost, which is a row that almost certainly does not exist;
    /// the alternative — trusting the statement kind — loses a real row for every
    /// statement kind this build has not met.
    pub async fn next_page(&mut self) -> Result<Page, DriverError> {
        let answer = self
            .client
            .get_query_results()
            .query_execution_id(&self.execution_id)
            .max_results(PAGE_SIZE)
            .set_next_token(self.token.clone())
            .send()
            .await
            .map_err(|e| DriverError::Execute {
                detail: format!(
                    "reading the result of query {}: {}",
                    self.execution_id,
                    aws_smithy_types::error::display::DisplayErrorContext(&e)
                ),
            })?;

        self.token = answer.next_token;
        let result_set = answer
            .result_set
            .unwrap_or_else(|| ResultSet::builder().build());

        if !self.started {
            self.columns = result_set
                .result_set_metadata
                .as_ref()
                .and_then(|m| m.column_info.as_ref())
                .map(|info| info.iter().map(column_from_info).collect())
                .unwrap_or_default();
        }

        let raw = result_set.rows.unwrap_or_default();
        let mut rows = Vec::with_capacity(raw.len());
        for (index, row) in raw.into_iter().enumerate() {
            let cells = row.data.unwrap_or_default();
            if !self.started && index == 0 && is_header(&cells, &self.columns) {
                continue;
            }
            rows.push(Row(self
                .columns
                .iter()
                .enumerate()
                .map(|(i, column)| match cells.get(i) {
                    // A datum with no `VarCharValue` is a NULL, which is how Athena
                    // says it over the wire.
                    Some(datum) => match &datum.var_char_value {
                        Some(text) => value_for_type(&column.driver_type, text),
                        None => Value::Null,
                    },
                    // Athena sent fewer cells than columns. Keeping the shape beats
                    // a short row that a positional consumer would misread.
                    None => Value::Null,
                })
                .collect()));
        }

        self.started = true;
        Ok(Page {
            columns: self.columns.clone(),
            rows,
        })
    }
}

/// Whether this row is Athena's echo of the column names rather than data.
fn is_header(cells: &[aws_sdk_athena::types::Datum], columns: &[Column]) -> bool {
    if cells.is_empty() || cells.len() != columns.len() {
        return false;
    }
    cells
        .iter()
        .zip(columns)
        .all(|(cell, column)| cell.var_char_value.as_deref() == Some(column.name.as_str()))
}

/// One column, as `ResultSetMetadata` describes it.
///
/// The type name is kept verbatim (invariant 10) — it is what the grid shows and what
/// the spool's `schema` sidecar stores, and mapping it onto a closed set here would be
/// the "unknown type" failure that invariant exists to forbid.
pub fn column_from_info(info: &ColumnInfo) -> Column {
    Column {
        // `label` is the alias the query asked for, `name` the underlying column.
        // `SELECT total AS revenue` should read `revenue`, which is what a person wrote.
        name: if info.label.is_some() {
            info.label.clone().unwrap_or_else(|| info.name.clone())
        } else {
            info.name.clone()
        },
        driver_type: info.r#type.clone(),
        nullable: match &info.nullable {
            Some(ColumnNullable::Nullable) => Some(true),
            Some(ColumnNullable::NotNull) => Some(false),
            // `UNKNOWN`, absent, or a value added since this build: all of them mean
            // "Athena did not say", and a guess would be worse than a `None`.
            _ => None,
        },
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use aws_sdk_athena::types::Datum;

    fn column(name: &str) -> Column {
        Column {
            name: name.to_string(),
            driver_type: "varchar".to_string(),
            nullable: None,
        }
    }

    fn datum(text: &str) -> Datum {
        Datum::builder().var_char_value(text).build()
    }

    #[test]
    fn the_first_row_of_a_select_is_the_header_and_is_recognized() {
        let columns = vec![column("id"), column("email")];
        assert!(is_header(&[datum("id"), datum("email")], &columns));
        assert!(!is_header(&[datum("1"), datum("a@b.example")], &columns));
        assert!(
            !is_header(&[datum("id")], &columns),
            "a row of the wrong width is not a header"
        );
        assert!(!is_header(&[], &columns));
    }

    /// A NULL in the leading position is data, not a header. Athena's header row never
    /// holds a NULL, because a column has a name.
    #[test]
    fn a_row_holding_a_null_is_never_a_header() {
        let columns = vec![column("id"), column("email")];
        let cells = vec![datum("id"), Datum::builder().build()];
        assert!(!is_header(&cells, &columns));
    }

    #[test]
    fn a_column_takes_its_alias_and_keeps_its_type_verbatim() {
        let info = ColumnInfo::builder()
            .name("total")
            .label("revenue")
            .r#type("decimal(38,2)")
            .nullable(ColumnNullable::Nullable)
            .build()
            .expect("a column");
        let column = column_from_info(&info);
        assert_eq!(column.name, "revenue");
        assert_eq!(column.driver_type, "decimal(38,2)");
        assert_eq!(column.nullable, Some(true));
    }

    #[test]
    fn an_unknown_nullability_is_reported_as_unknown() {
        let info = ColumnInfo::builder()
            .name("x")
            .r#type("varchar")
            .nullable(ColumnNullable::UnknownValue)
            .build()
            .expect("a column");
        assert_eq!(column_from_info(&info).nullable, None);
    }
}
