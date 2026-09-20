//! `trait Driver` — the seam between the one execute path and a database.
//!
//! ARCHITECTURE §2.1 fixes this shape. It is declared here, in `quokka-core`, rather
//! than in `quokka-driver`, for one reason: `quokka-core::execute()` must name the trait
//! in order to dispatch to it, and the trait must name `Value`, `Row` and
//! `ConnectionConfig`, which live here. One of the two crates has to be below the other,
//! and the crate that owns the single execute path is the one that has to see both
//! sides. `quokka-driver` owns every implementation and re-exports the trait, so
//! `quokka_driver::Driver` still resolves.
//!
//! One addition to §2.1's signatures: the database-touching methods take an
//! [`ExecutePermit`], which only `quokka-core::execute()` can construct. That turns
//! invariant 1 — "nothing reaches a database except through `quokka-core::execute()`" —
//! from a convention into a compile error. A surface crate holding a `Driver` cannot
//! call it.

use std::sync::{Arc, Mutex};

use async_trait::async_trait;
use futures::stream::BoxStream;
use uuid::Uuid;

use crate::config::ConnectionConfig;
use crate::error::DriverError;
use crate::value::{Column, Dialect, Row, Value};

/// Proof that the caller is `quokka-core::execute()`.
///
/// The field is private and the constructor is crate-private, so no crate outside
/// `quokka-core` can produce one — and therefore no crate outside `quokka-core` can
/// reach a database, however it came by a `Driver`.
#[derive(Debug)]
pub struct ExecutePermit(());

impl ExecutePermit {
    pub(crate) fn issue() -> Self {
        ExecutePermit(())
    }
}

/// Identifies an in-flight query so it can be cancelled.
///
/// It is the query's `query_id`, so a cancel in the UI and the row in the audit log name
/// the same thing.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct QueryHandle(pub Uuid);

/// What a driver is asked to run.
#[derive(Debug, Clone)]
pub struct QueryRequest {
    pub handle: QueryHandle,
    pub sql: String,
    pub params: Vec<Value>,
}

/// Rows affected, bytes scanned and engine timings — everything about the execution
/// that is not a row.
///
/// Most of it only becomes known as the stream drains (rows affected) or when it ends
/// (Athena's `DataScannedInBytes`), so drivers publish it through a [`MetaHandle`]
/// rather than returning it up front.
#[derive(Debug, Clone, Default, PartialEq, serde::Serialize)]
pub struct ResultMeta {
    pub rows_affected: Option<i64>,
    pub data_scanned_bytes: Option<i64>,
    pub engine_time_ms: Option<i64>,
}

/// A shared, writable view of a query's [`ResultMeta`].
#[derive(Debug, Clone, Default)]
pub struct MetaHandle(Arc<Mutex<ResultMeta>>);

impl MetaHandle {
    pub fn new() -> Self {
        Self::default()
    }

    /// Mutate the meta in place. A poisoned lock is treated as "no meta": a panic in
    /// another task must not take down a query that already ran.
    pub fn update(&self, f: impl FnOnce(&mut ResultMeta)) {
        if let Ok(mut m) = self.0.lock() {
            f(&mut m);
        }
    }

    pub fn snapshot(&self) -> ResultMeta {
        self.0.lock().map(|m| m.clone()).unwrap_or_default()
    }
}

/// A result in flight: its shape, its rows, and the meta that fills in as it drains.
pub struct QueryStream {
    pub columns: Vec<Column>,
    pub rows: BoxStream<'static, Result<Row, DriverError>>,
    pub meta: MetaHandle,
}

impl std::fmt::Debug for QueryStream {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("QueryStream")
            .field("columns", &self.columns)
            .field("meta", &self.meta)
            .finish_non_exhaustive()
    }
}

/// What part of a catalog to introspect.
#[derive(Debug, Clone, Default, PartialEq)]
pub struct Scope {
    pub database: Option<String>,
    pub schema: Option<String>,
    pub table: Option<String>,
}

/// A slice of a database's catalog.
#[derive(Debug, Clone, Default, PartialEq, serde::Serialize)]
pub struct Catalog {
    pub tables: Vec<TableInfo>,
}

#[derive(Debug, Clone, PartialEq, serde::Serialize)]
pub struct TableInfo {
    pub database: Option<String>,
    pub schema: Option<String>,
    pub name: String,
    pub kind: String,
    pub columns: Vec<Column>,
}

/// An execution plan, as the engine renders it.
#[derive(Debug, Clone, PartialEq, serde::Serialize)]
pub struct Plan {
    pub dialect: Dialect,
    pub text: String,
}

/// A connection to one database.
///
/// Implementations live in `quokka-driver`, one crate module and one cargo feature per
/// database (ARCHITECTURE §3.0, hedge 2).
#[async_trait]
pub trait Driver: Send + Sync {
    fn dialect(&self) -> Dialect;

    /// Open a connection. Not callable through `dyn Driver`; surfaces reach it via
    /// [`DriverFactory`], which hands the resulting driver to the engine.
    async fn connect(cfg: &ConnectionConfig) -> Result<Self, DriverError>
    where
        Self: Sized;

    async fn introspect(
        &self,
        permit: &ExecutePermit,
        scope: Scope,
    ) -> Result<Catalog, DriverError>;

    async fn execute(
        &self,
        permit: &ExecutePermit,
        req: QueryRequest,
    ) -> Result<QueryStream, DriverError>;

    /// Cancel an in-flight query.
    ///
    /// In the trait from day one, not bolted on later: a runaway Athena scan costs real
    /// money (§2.1).
    async fn cancel(&self, handle: QueryHandle) -> Result<(), DriverError>;

    async fn explain(&self, permit: &ExecutePermit, sql: &str) -> Result<Plan, DriverError>;
}

/// Opens drivers of one kind.
///
/// `Driver::connect` is `where Self: Sized` per §2.1 and so cannot be called through a
/// trait object. This is the object-safe door the engine uses instead.
#[async_trait]
pub trait DriverFactory: Send + Sync {
    /// The value a connection's `driver = "..."` setting must hold.
    fn name(&self) -> &'static str;

    fn dialect(&self) -> Dialect;

    async fn open(&self, cfg: &ConnectionConfig) -> Result<Arc<dyn Driver>, DriverError>;
}
