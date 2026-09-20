//! The catalog cache behind autocomplete (§3.1), and the rule that makes it honest.
//!
//! §1.4: nothing queries a database to fill a suggestion. Autocomplete reads whatever is
//! cached; only a refresh past the TTL reaches the server.
//!
//! The load-bearing consequence is in the audit log rather than here. §5 records one
//! `introspect` event per catalog *refresh* — so **a cache hit logs nothing at all**,
//! because nothing reached a database and there is no event to describe. A hit that
//! appended a row would make the log claim a database read that did not happen, and at a
//! one-minute TTL it would do so thousands of times a day.

use std::collections::HashMap;
use std::sync::Mutex;
use std::time::{Duration, Instant};

use crate::driver::{Catalog, Scope};

/// One cached answer, keyed by the exact scope that produced it.
#[derive(Debug, Clone)]
struct Entry {
    at: Instant,
    catalog: Catalog,
}

/// Per-connection, per-scope catalogs with a TTL.
///
/// Keyed by the *exact* scope rather than by something cleverer. A cache that answered a
/// request for one table out of an earlier whole-database refresh would be faster and
/// occasionally wrong — the table may have been created since — and a schema tool that
/// is occasionally wrong is worse than one that is occasionally slow.
#[derive(Debug, Default)]
pub struct CatalogCache {
    entries: Mutex<HashMap<(String, ScopeKey), Entry>>,
}

/// A [`Scope`] in a form that can be a map key.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct ScopeKey(Option<String>, Option<String>, Option<String>);

impl From<&Scope> for ScopeKey {
    fn from(s: &Scope) -> Self {
        ScopeKey(s.database.clone(), s.schema.clone(), s.table.clone())
    }
}

impl CatalogCache {
    pub fn new() -> Self {
        Self::default()
    }

    /// The cached catalog, if one is present and still within `ttl`.
    ///
    /// A zero TTL caches nothing, which is how a connection opts out.
    pub fn get(&self, connection: &str, scope: &Scope, ttl: Duration) -> Option<Catalog> {
        if ttl.is_zero() {
            return None;
        }
        let entries = self.entries.lock().ok()?;
        let entry = entries.get(&(connection.to_string(), ScopeKey::from(scope)))?;
        (entry.at.elapsed() < ttl).then(|| entry.catalog.clone())
    }

    pub fn put(&self, connection: &str, scope: &Scope, catalog: Catalog) {
        if let Ok(mut entries) = self.entries.lock() {
            entries.insert(
                (connection.to_string(), ScopeKey::from(scope)),
                Entry {
                    at: Instant::now(),
                    catalog,
                },
            );
        }
    }

    /// Drop everything cached for one connection.
    pub fn invalidate(&self, connection: &str) {
        if let Ok(mut entries) = self.entries.lock() {
            entries.retain(|(name, _), _| name != connection);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn catalog() -> Catalog {
        Catalog::default()
    }

    #[test]
    fn a_zero_ttl_caches_nothing() {
        let cache = CatalogCache::new();
        let scope = Scope::default();
        cache.put("prod", &scope, catalog());
        assert!(cache.get("prod", &scope, Duration::ZERO).is_none());
    }

    #[test]
    fn scopes_do_not_answer_for_one_another() {
        let cache = CatalogCache::new();
        let whole = Scope::default();
        let one_table = Scope {
            table: Some("orders".to_string()),
            ..Scope::default()
        };
        cache.put("prod", &whole, catalog());

        assert!(cache.get("prod", &whole, Duration::from_secs(60)).is_some());
        assert!(
            cache
                .get("prod", &one_table, Duration::from_secs(60))
                .is_none(),
            "a narrower scope must not be served from a wider refresh: the table may \
             have been created since"
        );
        assert!(cache
            .get("other", &whole, Duration::from_secs(60))
            .is_none());
    }
}
