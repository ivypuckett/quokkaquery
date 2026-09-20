//! The introspect audit path — the M1 test that matters most.
//!
//! §5 settles three things about it, and each is easy to get subtly wrong:
//!
//! 1. **One event, never a pair.** A `query_started`/`query_finished` pair per catalog
//!    refresh would bury the record review exists to read, and would make "which tables
//!    did this agent touch" ambiguous between reading a table and describing it.
//! 2. **Nothing at all on a cache hit.** At a one-minute TTL, a row per hit would be
//!    thousands a day asserting database reads that never happened.
//! 3. **Fail-closed does not apply, but a failed write is loud.** There is no "before"
//!    event to fail; a refresh the log could not record is discarded rather than served.

use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::Duration;

use async_trait::async_trait;
use quokka_core::{
    introspect, Actor, ActorKind, AuditLog, Catalog, Column, ConnectionConfig, Driver, DriverError,
    DriverFactory, Engine, EventKind, ExecutePermit, IntrospectRequest, Plan, QueryHandle,
    QueryRequest, QueryStream, Registry, Scope, Status, TableInfo,
};

/// Counts every call that would have reached a database.
struct CountingDriver {
    refreshes: Arc<AtomicUsize>,
    fail: bool,
}

#[async_trait]
impl Driver for CountingDriver {
    fn dialect(&self) -> quokka_core::Dialect {
        quokka_core::Dialect::Postgres
    }

    async fn connect(_cfg: &ConnectionConfig) -> Result<Self, DriverError> {
        unreachable!("the factory builds this driver directly")
    }

    async fn introspect(&self, _p: &ExecutePermit, scope: Scope) -> Result<Catalog, DriverError> {
        self.refreshes.fetch_add(1, Ordering::SeqCst);
        if self.fail {
            return Err(DriverError::Execute {
                detail: "the catalog query failed".to_string(),
            });
        }
        Ok(Catalog {
            tables: vec![TableInfo {
                database: None,
                schema: Some("public".to_string()),
                name: scope.table.unwrap_or_else(|| "orders".to_string()),
                kind: "table".to_string(),
                columns: vec![Column {
                    name: "id".to_string(),
                    driver_type: "int4".to_string(),
                    nullable: Some(false),
                }],
            }],
        })
    }

    async fn execute(
        &self,
        _p: &ExecutePermit,
        _req: QueryRequest,
    ) -> Result<QueryStream, DriverError> {
        Err(DriverError::Unsupported("not in this test".into()))
    }

    async fn cancel(&self, _handle: QueryHandle) -> Result<(), DriverError> {
        Ok(())
    }

    async fn explain(&self, _p: &ExecutePermit, _sql: &str) -> Result<Plan, DriverError> {
        Err(DriverError::Unsupported("not in this test".into()))
    }
}

struct CountingFactory {
    refreshes: Arc<AtomicUsize>,
    fail: bool,
}

#[async_trait]
impl DriverFactory for CountingFactory {
    fn name(&self) -> &'static str {
        "counting"
    }

    fn dialect(&self) -> quokka_core::Dialect {
        quokka_core::Dialect::Postgres
    }

    async fn open(&self, _cfg: &ConnectionConfig) -> Result<Arc<dyn Driver>, DriverError> {
        Ok(Arc::new(CountingDriver {
            refreshes: self.refreshes.clone(),
            fail: self.fail,
        }))
    }
}

struct Harness {
    engine: Engine,
    refreshes: Arc<AtomicUsize>,
    _dir: tempfile::TempDir,
}

impl Harness {
    async fn new(ttl: Duration, fail: bool) -> Self {
        let dir = tempfile::tempdir().expect("tempdir");
        let audit_path = dir.path().join("audit.db");
        let audit = AuditLog::open(&audit_path).await.expect("open audit log");

        let refreshes = Arc::new(AtomicUsize::new(0));
        let mut registry = Registry::builtin_only(&audit_path);
        registry.insert(ConnectionConfig {
            host: Some("db.example".to_string()),
            catalog_ttl: ttl,
            ..ConnectionConfig::new("prod", "counting")
        });

        let engine = Engine::new(
            registry,
            audit,
            vec![Arc::new(CountingFactory {
                refreshes: refreshes.clone(),
                fail,
            })],
        );

        Harness {
            engine,
            refreshes,
            _dir: dir,
        }
    }

    fn request(&self, table: Option<&str>) -> IntrospectRequest {
        IntrospectRequest::new(
            "prod",
            Scope {
                table: table.map(str::to_string),
                ..Scope::default()
            },
            Actor {
                kind: ActorKind::Agent,
                id: "claude".to_string(),
            },
        )
    }

    async fn events(&self) -> Vec<quokka_audit::StoredEvent> {
        self.engine.audit().read_all().await.expect("read the log")
    }

    fn refreshes(&self) -> usize {
        self.refreshes.load(Ordering::SeqCst)
    }
}

#[tokio::test]
async fn a_refresh_appends_exactly_one_event_and_never_a_pair() {
    let h = Harness::new(Duration::from_secs(60), false).await;

    let result = introspect(&h.engine, h.request(Some("orders")))
        .await
        .expect("introspect");
    assert!(!result.from_cache);
    assert!(result.event_id.is_some(), "a refresh records itself");

    let events = h.events().await;
    assert_eq!(events.len(), 1, "one refresh, one row: {events:#?}");

    let e = &events[0].event;
    assert_eq!(e.event_kind, EventKind::Introspect);
    assert_eq!(e.status, Status::Ok);
    assert_eq!(e.statement_kind.as_deref(), Some("introspect"));
    assert_eq!(e.read_only, Some(true));
    assert!(e.duration_ms.is_some(), "how long it took (§5)");
    assert!(
        e.sql_fingerprint.contains("orders"),
        "the row names the scope it covered: {}",
        e.sql_fingerprint
    );
    assert_eq!(
        e.sql_text, None,
        "the SQL that ran is the driver's own, not the caller's, so it is not recorded"
    );
    assert!(
        !events.iter().any(|s| matches!(
            s.event.event_kind,
            EventKind::QueryStarted | EventKind::QueryFinished
        )),
        "introspection must never write a query pair"
    );

    assert!(
        h.engine.audit().verify().await.expect("verify").is_intact(),
        "the chain still verifies with an introspect row in it"
    );
}

#[tokio::test]
async fn a_cache_hit_logs_nothing_at_all() {
    let h = Harness::new(Duration::from_secs(60), false).await;

    introspect(&h.engine, h.request(Some("orders")))
        .await
        .expect("first");
    let second = introspect(&h.engine, h.request(Some("orders")))
        .await
        .expect("second");

    assert!(second.from_cache);
    assert_eq!(
        second.event_id, None,
        "nothing reached a database, so there is nothing to describe"
    );
    assert_eq!(h.refreshes(), 1, "the second call must not query");
    assert_eq!(
        h.events().await.len(),
        1,
        "a hit that appended a row would make the log claim a read that never happened"
    );
}

#[tokio::test]
async fn an_explicit_refresh_queries_again_and_logs_again() {
    let h = Harness::new(Duration::from_secs(60), false).await;

    introspect(&h.engine, h.request(Some("orders")))
        .await
        .expect("first");

    let mut forced = h.request(Some("orders"));
    forced.refresh = true;
    let second = introspect(&h.engine, forced).await.expect("forced");

    assert!(!second.from_cache);
    assert_eq!(h.refreshes(), 2);
    assert_eq!(h.events().await.len(), 2, "two refreshes, two rows");
}

#[tokio::test]
async fn a_zero_ttl_caches_nothing_so_every_call_is_a_refresh() {
    let h = Harness::new(Duration::ZERO, false).await;

    for _ in 0..3 {
        introspect(&h.engine, h.request(None))
            .await
            .expect("introspect");
    }

    assert_eq!(h.refreshes(), 3);
    assert_eq!(h.events().await.len(), 3);
}

/// Different scopes are different questions. Serving "describe orders" from an earlier
/// whole-database refresh would be faster and occasionally wrong.
#[tokio::test]
async fn a_narrower_scope_is_not_served_from_a_wider_refresh() {
    let h = Harness::new(Duration::from_secs(60), false).await;

    introspect(&h.engine, h.request(None)).await.expect("all");
    let narrowed = introspect(&h.engine, h.request(Some("orders")))
        .await
        .expect("one table");

    assert!(!narrowed.from_cache);
    assert_eq!(h.refreshes(), 2);
    assert_eq!(h.events().await.len(), 2);
}

#[tokio::test]
async fn a_failed_refresh_is_still_one_event_and_is_not_cached() {
    let h = Harness::new(Duration::from_secs(60), true).await;

    let err = introspect(&h.engine, h.request(Some("orders")))
        .await
        .expect_err("the driver failed");
    assert!(err.to_string().contains("catalog query failed"), "{err}");

    let events = h.events().await;
    assert_eq!(events.len(), 1, "a failure is recorded, once");
    assert_eq!(events[0].event.event_kind, EventKind::Introspect);
    assert_eq!(events[0].event.status, Status::Error);
    assert_eq!(
        events[0].event.rows_returned, None,
        "nothing came back, so there is no count"
    );

    // Nothing was cached, so the next attempt tries again rather than serving a failure.
    let _ = introspect(&h.engine, h.request(Some("orders"))).await;
    assert_eq!(h.refreshes(), 2);
    assert_eq!(h.events().await.len(), 2);
}
