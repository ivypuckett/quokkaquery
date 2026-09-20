//! QuokkaQuery's drivers.
//!
//! One module and one cargo feature per database (ARCHITECTURE §3.0, hedge 2), so a
//! slim build is possible and the `trait Driver` seam stays honest. M0 ships SQLite;
//! Postgres and MySQL arrive at M1 and Athena at M5, each as its own module and feature
//! rather than as a branch inside this one.
//!
//! `trait Driver` itself is declared in `quokka-core` — see the note at the top of
//! `quokka_core::driver` for why — and re-exported here, so `quokka_driver::Driver`
//! resolves as ARCHITECTURE §2 describes.
//!
//! Nothing in this crate is reachable from a surface: every database-touching method
//! takes a `quokka_core::ExecutePermit`, which only `quokka-core::execute()` can make.

use std::sync::Arc;

pub use quokka_core::{Driver, DriverFactory};

#[cfg(feature = "sqlite")]
pub mod sqlite;

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
    factories
}
