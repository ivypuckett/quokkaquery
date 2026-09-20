//! `quokka connections list` (ARCHITECTURE §6.1).
//!
//! Reads the registry and prints it. What it deliberately does not do is resolve a
//! credential: listing connections should not unlock a keychain, and a password has no
//! business in a machine-readable inventory. Each row names *where* its credential lives
//! and which store would answer — never the value. `quokka credential status` is the
//! command that asks whether one is actually there, because that is a question worth
//! having to ask for.

use anyhow::Result;
use quokka_core::{ConnectionConfig, Engine};
use serde_json::{Map, Value as Json};

use crate::format::{print_records, Format};

/// Table columns, in the order a person reads them: what it is, then how it is guarded.
const COLUMNS: &[&str] = &[
    "name",
    "driver",
    "target",
    "mode",
    "sql_logging",
    "credential",
];

pub fn list(engine: &Engine, format: Format) -> Result<u8> {
    let records: Vec<Json> = engine.registry().iter().map(record).collect();

    let mut envelope = Map::new();
    envelope.insert("count".into(), Json::from(records.len()));

    print_records(format, envelope, "connections", records, COLUMNS)?;
    Ok(crate::exit::OK)
}

fn record(cfg: &ConnectionConfig) -> Json {
    let mut m = Map::new();
    m.insert("name".into(), Json::String(cfg.name.clone()));
    m.insert("driver".into(), Json::String(cfg.driver.clone()));
    m.insert("dialect".into(), Json::String(cfg.dialect().to_string()));
    m.insert("target".into(), Json::String(cfg.target()));
    m.insert("mode".into(), Json::String(cfg.mode.as_str().into()));
    m.insert(
        "sql_logging".into(),
        Json::String(cfg.sql_logging.as_str().into()),
    );
    // Meaningless for a file, so `null` rather than a default nobody chose.
    m.insert(
        "tls".into(),
        if cfg.host.is_some() {
            Json::String(cfg.tls.as_str().into())
        } else {
            Json::Null
        },
    );
    m.insert(
        "path".into(),
        cfg.path
            .as_ref()
            .map(|p| Json::String(p.display().to_string()))
            .unwrap_or(Json::Null),
    );
    m.insert(
        "host".into(),
        cfg.host.clone().map(Json::String).unwrap_or(Json::Null),
    );
    m.insert(
        "port".into(),
        cfg.effective_port().map(Json::from).unwrap_or(Json::Null),
    );
    m.insert(
        "user".into(),
        cfg.user.clone().map(Json::String).unwrap_or(Json::Null),
    );
    m.insert(
        "database".into(),
        cfg.database.clone().map(Json::String).unwrap_or(Json::Null),
    );
    m.insert(
        "schema".into(),
        cfg.schema.clone().map(Json::String).unwrap_or(Json::Null),
    );
    // A location and a store, never a value.
    m.insert(
        "credential".into(),
        Json::String(cfg.credential.as_config_string()),
    );
    m.insert(
        "credential_backend".into(),
        Json::String(cfg.credential.backend().as_str().into()),
    );
    m.insert(
        "catalog_ttl_seconds".into(),
        Json::from(cfg.catalog_ttl.as_secs()),
    );
    m.insert("builtin".into(), Json::Bool(cfg.builtin));
    Json::Object(m)
}
