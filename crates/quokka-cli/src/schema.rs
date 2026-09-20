//! `quokka schema describe <table>` (ARCHITECTURE §6.1).
//!
//! A thin wrapper over `quokka_core::introspect()`, which is what makes it audited: one
//! `introspect` event per refresh, appended after the fact, and nothing at all when the
//! answer came from the cache (§5).
//!
//! In a CLI the cache never hits, because the process is younger than the TTL — so every
//! invocation is a refresh and leaves exactly one event. That is the shape to hold on to
//! when the MCP server and the UI arrive at M3 and M4: they are long-lived, they *will*
//! hit the cache, and a hit must stay silent.

use anyhow::Result;
use quokka_core::{introspect, Actor, Client, Engine, IntrospectRequest, Scope, TableInfo};
use serde_json::{Map, Value as Json};

use crate::format::{print_records, Format};

const COLUMNS: &[&str] = &["schema", "table", "kind", "column", "type", "nullable"];

/// Split `[[database.]schema.]table` the way a person writes it.
///
/// Quoted identifiers are not handled, and deliberately so: a table whose name contains
/// a dot is real but rare, and guessing at quoting rules per dialect here would be a
/// small parser with three dialects' worth of edge cases. Such a table is reachable by
/// naming its schema with `--schema` and the rest with `--table`.
pub fn parse_scope(qualified: Option<&str>, database: Option<&str>, schema: Option<&str>) -> Scope {
    let mut scope = Scope {
        database: database.map(str::to_string),
        schema: schema.map(str::to_string),
        table: None,
    };

    if let Some(q) = qualified {
        let parts: Vec<&str> = q.split('.').collect();
        match parts.as_slice() {
            [table] => scope.table = Some((*table).to_string()),
            [schema_part, table] => {
                scope
                    .schema
                    .get_or_insert_with(|| (*schema_part).to_string());
                scope.table = Some((*table).to_string());
            }
            [db, schema_part, table, ..] => {
                scope.database.get_or_insert_with(|| (*db).to_string());
                scope
                    .schema
                    .get_or_insert_with(|| (*schema_part).to_string());
                scope.table = Some((*table).to_string());
            }
            [] => {}
        }
    }

    scope
}

pub async fn describe(
    engine: &Engine,
    connection: &str,
    scope: Scope,
    refresh: bool,
    format: Format,
    actor: Actor,
) -> Result<u8> {
    let mut request = IntrospectRequest::new(connection, scope.clone(), actor);
    request.client = Client::Cli;
    request.refresh = refresh;

    let result = introspect(engine, request).await?;

    let mut envelope = Map::new();
    envelope.insert("connection".into(), Json::String(connection.to_string()));
    envelope.insert("scope".into(), scope_json(&scope));
    // Said out loud because it is the difference between a fact about the database and a
    // fact about the last minute, and because it is exactly the case that left no row in
    // the log.
    envelope.insert("from_cache".into(), Json::Bool(result.from_cache));
    envelope.insert(
        "introspect_event_id".into(),
        result
            .event_id
            .map(|id| Json::String(id.to_string()))
            .unwrap_or(Json::Null),
    );
    envelope.insert("duration_ms".into(), Json::from(result.duration_ms));
    envelope.insert(
        "table_count".into(),
        Json::from(result.catalog.tables.len()),
    );

    match format {
        // The tabular form is one row per column, because that is what "describe a
        // table" means; the JSON forms nest columns inside their table, because that is
        // what a program wants to walk.
        Format::Table => {
            let records: Vec<Json> = result
                .catalog
                .tables
                .iter()
                .flat_map(flatten_columns)
                .collect();
            let found = !records.is_empty();
            print_records(format, envelope, "tables", records, COLUMNS)?;
            if !found {
                eprintln!("nothing matched on {connection}");
            }
        }
        Format::Json | Format::Ndjson => {
            let records: Vec<Json> = result
                .catalog
                .tables
                .iter()
                .map(|t| serde_json::to_value(t).unwrap_or(Json::Null))
                .collect();
            print_records(format, envelope, "tables", records, COLUMNS)?;
        }
    }

    Ok(crate::exit::OK)
}

fn scope_json(scope: &Scope) -> Json {
    let mut m = Map::new();
    let field = |v: &Option<String>| v.clone().map(Json::String).unwrap_or(Json::Null);
    m.insert("database".into(), field(&scope.database));
    m.insert("schema".into(), field(&scope.schema));
    m.insert("table".into(), field(&scope.table));
    Json::Object(m)
}

fn flatten_columns(table: &TableInfo) -> Vec<Json> {
    if table.columns.is_empty() {
        // A table with no columns is a real thing and must not vanish from the listing.
        let mut m = Map::new();
        m.insert(
            "schema".into(),
            namespace(table).map(Json::String).unwrap_or(Json::Null),
        );
        m.insert("table".into(), Json::String(table.name.clone()));
        m.insert("kind".into(), Json::String(table.kind.clone()));
        return vec![Json::Object(m)];
    }

    table
        .columns
        .iter()
        .map(|c| {
            let mut m = Map::new();
            m.insert(
                "schema".into(),
                namespace(table).map(Json::String).unwrap_or(Json::Null),
            );
            m.insert("table".into(), Json::String(table.name.clone()));
            m.insert("kind".into(), Json::String(table.kind.clone()));
            m.insert("column".into(), Json::String(c.name.clone()));
            m.insert("type".into(), Json::String(c.driver_type.clone()));
            m.insert(
                "nullable".into(),
                c.nullable.map(Json::Bool).unwrap_or(Json::Null),
            );
            Json::Object(m)
        })
        .collect()
}

/// Postgres reports a schema, MySQL a database, SQLite neither. One column shows
/// whichever the driver filled in, because a `schema` column that is empty for every
/// MySQL row would look like missing information rather than a different data model.
fn namespace(table: &TableInfo) -> Option<String> {
    table.schema.clone().or_else(|| table.database.clone())
}
