//! The hash chain that makes an excision or an edit detectable.
//!
//! Each row's `row_hash` covers its own fields plus the `prev_hash` it was sealed
//! against, so rewriting or removing a row anywhere in the middle desynchronizes every
//! row after it (ARCHITECTURE §5).
//!
//! The threat model is narrow and worth restating: this defends against *an agent with
//! shell access quietly editing the log of what it just did*. It is not a defense against
//! the machine's owner, who can rebuild the chain at will.

use sha2::{Digest, Sha256};

use crate::event::AuditEvent;

/// Domain separator. Bumping it invalidates every existing chain, so it changes only
/// when the canonical encoding below changes.
const DOMAIN: &[u8] = b"quokkaquery.audit_log.v1";

/// A field's contribution to the digest: `NULL` and the string `"NULL"` must not collide.
enum Field<'a> {
    Null,
    Text(&'a str),
    Owned(String),
}

impl Field<'_> {
    fn write(&self, h: &mut Sha256) {
        match self {
            Field::Null => h.update([0u8]),
            Field::Text(s) => {
                h.update([1u8]);
                h.update((s.len() as u64).to_be_bytes());
                h.update(s.as_bytes());
            }
            Field::Owned(s) => {
                h.update([1u8]);
                h.update((s.len() as u64).to_be_bytes());
                h.update(s.as_bytes());
            }
        }
    }
}

fn opt_str(v: Option<&str>) -> Field<'_> {
    match v {
        Some(s) => Field::Text(s),
        None => Field::Null,
    }
}

fn opt_i64(v: Option<i64>) -> Field<'static> {
    match v {
        Some(i) => Field::Owned(i.to_string()),
        None => Field::Null,
    }
}

fn opt_bool(v: Option<bool>) -> Field<'static> {
    match v {
        // Mirrors the storage form: SQLite holds these as INTEGER 0/1.
        Some(b) => Field::Owned(if b { "1".into() } else { "0".into() }),
        None => Field::Null,
    }
}

fn opt_f64(v: Option<f64>) -> Field<'static> {
    match v {
        // `{:?}` round-trips an f64 exactly, so a value read back out of SQLite hashes
        // to what it hashed to on the way in.
        Some(x) => Field::Owned(format!("{x:?}")),
        None => Field::Null,
    }
}

/// Compute the `row_hash` for `event` sealed against `prev_hash`.
///
/// Every column of `audit_log` participates except `row_hash` itself. Field order is
/// fixed and each field is length-prefixed and tagged, so no rearrangement of content
/// between adjacent fields produces the same digest.
pub fn row_hash(event: &AuditEvent, prev_hash: Option<&str>) -> String {
    let e = event;
    let id = e.id.to_string();
    let query_id = e.query_id.to_string();
    let parent_id = e.parent_id.map(|u| u.to_string());

    let fields = [
        opt_str(prev_hash),
        Field::Owned(id),
        Field::Owned(query_id),
        match &parent_id {
            Some(s) => Field::Text(s),
            None => Field::Null,
        },
        Field::Text(&e.at),
        opt_i64(e.duration_ms),
        Field::Text(e.actor_kind.as_str()),
        Field::Text(&e.actor_id),
        Field::Text(&e.session_id),
        Field::Text(e.client.as_str()),
        Field::Text(&e.connection),
        Field::Text(&e.dialect),
        opt_str(e.database.as_deref()),
        opt_str(e.schema_name.as_deref()),
        Field::Text(e.event_kind.as_str()),
        Field::Text(e.sql_logging.as_str()),
        opt_str(e.sql_text.as_deref()),
        Field::Text(&e.sql_fingerprint),
        opt_str(e.statement_kind.as_deref()),
        opt_bool(e.read_only),
        opt_str(e.params.as_deref()),
        Field::Text(e.status.as_str()),
        opt_str(e.error_code.as_deref()),
        opt_str(e.error_message.as_deref()),
        opt_i64(e.rows_returned),
        opt_i64(e.rows_affected),
        opt_i64(e.rows_spooled),
        opt_bool(e.truncated),
        opt_str(e.export_format.as_deref()),
        opt_str(e.export_path.as_deref()),
        opt_i64(e.data_scanned_bytes),
        opt_f64(e.cost_estimate_usd),
        opt_str(e.approved_by.as_deref()),
        opt_str(e.tags.as_deref()),
    ];

    let mut h = Sha256::new();
    h.update(DOMAIN);
    h.update((fields.len() as u64).to_be_bytes());
    for f in &fields {
        f.write(&mut h);
    }
    hex::encode(h.finalize())
}
