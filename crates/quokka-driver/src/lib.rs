//! QuokkaQuery's drivers.
//!
//! One module and one cargo feature per database (ARCHITECTURE §3.0, hedge 2), so a
//! slim build is possible and the `trait Driver` seam stays honest. M0 shipped SQLite;
//! M1 added Postgres and MySQL and M5 adds Athena — each its own module and its own
//! feature rather than a branch inside this one.
//!
//! Athena is the one that proves hedge 2 was worth committing to: it is not a wire
//! protocol at all but a submit-poll-page REST API, and it reaches the rest of the
//! program through exactly the same `trait Driver` the other three do.
//!
//! Postgres and MySQL are pure Rust wire-protocol implementations over sqlx with
//! `rustls`. SQLite is the exception §3.1 names: `sqlx-sqlite` binds `libsqlite3-sys`,
//! so "pure Rust" is a claim about two of the three. `libmysqlclient` is never linked —
//! it is GPLv2 and this project is MIT.
//!
//! `trait Driver` itself is declared in `quokka-core` — see the note at the top of
//! `quokka_core::driver` for why — and re-exported here, so `quokka_driver::Driver`
//! resolves as ARCHITECTURE §2 describes.
//!
//! Nothing in this crate is reachable from a surface: every database-touching method
//! takes a `quokka_core::ExecutePermit`, which only `quokka-core::execute()` can make.

use std::sync::Arc;

pub use quokka_core::{Driver, DriverFactory};

mod common;

#[cfg(feature = "athena")]
pub mod athena;
#[cfg(feature = "mysql")]
pub mod mysql;
#[cfg(feature = "postgres")]
pub mod postgres;
#[cfg(feature = "sqlite")]
pub mod sqlite;

#[cfg(feature = "athena")]
pub use athena::{AthenaDriver, AthenaSettings};
#[cfg(feature = "mysql")]
pub use mysql::MySqlDriver;
#[cfg(feature = "postgres")]
pub use postgres::PostgresDriver;
#[cfg(feature = "sqlite")]
pub use sqlite::SqliteDriver;

/// Every driver this build includes.
///
/// The engine matches a connection's `driver = "..."` against
/// [`DriverFactory::name`](quokka_core::DriverFactory::name); a connection naming a
/// driver that was compiled out fails with a message saying so, rather than silently
/// falling back to another one.
// Built one push at a time rather than as a `vec![]`, because each entry is gated on its
// own driver feature and `#[cfg]` cannot be applied to an expression inside the macro.
#[allow(clippy::vec_init_then_push)]
pub fn builtin_factories() -> Vec<Arc<dyn DriverFactory>> {
    #[allow(unused_mut)]
    let mut factories: Vec<Arc<dyn DriverFactory>> = Vec::new();
    #[cfg(feature = "sqlite")]
    factories.push(Arc::new(sqlite::SqliteFactory));
    #[cfg(feature = "postgres")]
    factories.push(Arc::new(postgres::PostgresFactory));
    #[cfg(feature = "mysql")]
    factories.push(Arc::new(mysql::MySqlFactory));
    #[cfg(feature = "athena")]
    factories.push(Arc::new(athena::AthenaFactory));
    factories
}
