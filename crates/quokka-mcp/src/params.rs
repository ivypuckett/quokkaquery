//! The shapes a tool call arrives in, and what they become inside.
//!
//! Kept apart from the tools themselves because these are an *interface*: an agent's
//! client generates its call from the JSON Schema these derive, so a field renamed here
//! is a breaking change for every agent already using it.

use quokka_core::Value;
use quokka_spool::{Direction, Filter, Op, SortKey, Spool, View};
use rmcp::ErrorData as McpError;
use schemars::JsonSchema;
use serde::Deserialize;

/// One bound parameter, as ordinary JSON.
///
/// A scalar rather than a tagged `{type, value}` object, because an agent writing
/// `["a@b.example", 30]` is doing the obvious thing and a schema that demanded
/// `[{"type":"text","value":"a@b.example"}]` would be answered with mistakes. The cost
/// is that a JSON number has to be sorted into an integer or a float, which is done
/// below, and that a blob has no JSON spelling at all — the CLI's `blob:` prefix is the
/// way to bind one, and this says so rather than guessing at a hex string.
pub fn value_from_json(json: &serde_json::Value) -> Result<Value, McpError> {
    Ok(match json {
        serde_json::Value::Null => Value::Null,
        serde_json::Value::Bool(b) => Value::Bool(*b),
        serde_json::Value::Number(n) => match n.as_i64() {
            Some(i) => Value::Int(i),
            None => Value::Float(n.as_f64().unwrap_or(f64::NAN)),
        },
        serde_json::Value::String(s) => Value::Text(s.clone()),
        other => {
            return Err(McpError::invalid_params(
                format!(
                    "a bound parameter is a string, a number, a boolean or null; {other} is \
                     neither. A binary value has no JSON spelling — bind it from the CLI \
                     with `--param blob:<hex>`."
                ),
                None,
            ))
        }
    })
}

/// Which way to sort one column of a spooled result.
#[derive(Debug, Clone, Deserialize, JsonSchema)]
pub struct SortSpec {
    /// The column's name, as the result reported it.
    pub column: String,
    /// `asc` (the default) or `desc`.
    #[serde(default)]
    pub direction: Option<String>,
}

/// One filter over one column of a spooled result.
///
/// A column, an operator and a value — never a fragment of SQL. The spool is a table we
/// could query, and a caller-supplied `WHERE` clause would be a second way to get SQL
/// executed and a way to reach the spool's own `meta` and `schema` tables. This is
/// everything a filter needs and nothing else.
#[derive(Debug, Clone, Deserialize, JsonSchema)]
pub struct FilterSpec {
    pub column: String,
    /// `eq`, `ne`, `lt`, `le`, `gt`, `ge`, `contains`, `starts_with`, `is_null`,
    /// `is_not_null`.
    pub op: String,
    /// The value to compare against. Omitted for `is_null` and `is_not_null`.
    #[serde(default)]
    pub value: Option<serde_json::Value>,
}

/// Turn the sort and filter specs into a view over one spool.
///
/// Column *names* rather than ordinals, because an agent has the names and not the
/// ordinals — and because a name that does not exist can be reported with the list of
/// ones that do, which an out-of-range index cannot.
pub fn view_for(
    spool: &Spool,
    sort: &[SortSpec],
    filters: &[FilterSpec],
) -> Result<View, McpError> {
    let index = |name: &str| -> Result<usize, McpError> {
        spool.column_index(name).ok_or_else(|| {
            McpError::invalid_params(
                format!(
                    "this result has no column called {name:?}. Its columns are: {}",
                    spool
                        .columns()
                        .iter()
                        .map(|c| c.name.as_str())
                        .collect::<Vec<_>>()
                        .join(", ")
                ),
                None,
            )
        })
    };

    let mut keys = Vec::with_capacity(sort.len());
    for spec in sort {
        let column = index(&spec.column)?;
        keys.push(match spec.direction.as_deref() {
            None | Some("asc") => SortKey::asc(column),
            Some("desc") => SortKey::desc(column),
            Some(other) => {
                return Err(McpError::invalid_params(
                    format!("{other:?} is not a direction; use \"asc\" or \"desc\""),
                    None,
                ))
            }
        });
    }

    let mut view = View::sorted_by(keys);
    for spec in filters {
        let column = index(&spec.column)?;
        let (op, needs_value) = match spec.op.as_str() {
            "eq" => (Op::Eq, true),
            "ne" => (Op::Ne, true),
            "lt" => (Op::Lt, true),
            "le" => (Op::Le, true),
            "gt" => (Op::Gt, true),
            "ge" => (Op::Ge, true),
            "contains" => (Op::Contains, true),
            "starts_with" => (Op::StartsWith, true),
            "is_null" => (Op::IsNull, false),
            "is_not_null" => (Op::IsNotNull, false),
            other => {
                return Err(McpError::invalid_params(
                    format!(
                        "{other:?} is not a filter operator; use one of eq, ne, lt, le, gt, \
                         ge, contains, starts_with, is_null, is_not_null"
                    ),
                    None,
                ))
            }
        };
        let value = match (&spec.value, needs_value) {
            (Some(v), _) => value_from_json(v)?,
            (None, false) => Value::Null,
            (None, true) => {
                return Err(McpError::invalid_params(
                    format!(
                        "the {:?} filter on {:?} needs a value",
                        spec.op, spec.column
                    ),
                    None,
                ))
            }
        };
        view = view.with_filter(Filter::new(column, op, value));
    }
    Ok(view)
}

/// `asc`/`desc` back out again, for a response that says what it did.
pub fn direction_name(direction: Direction) -> &'static str {
    match direction {
        Direction::Asc => "asc",
        Direction::Desc => "desc",
    }
}
