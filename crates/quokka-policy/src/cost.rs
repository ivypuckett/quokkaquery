//! The cumulative cost budget (ARCHITECTURE §6.4, layer 2).
//!
//! Athena bills by data scanned, so a runaway query is a bill rather than an error. §6.4
//! answers that with two layers, and this file is the second one: a per-actor budget over
//! a rolling window, checked before execution and enforced by denying.
//!
//! ## Why the spend arrives as an argument
//!
//! §6.4 says the accounting needs no new storage, because `data_scanned_bytes` and
//! `actor_kind` are already columns in the audit log — "so a budget check is a query
//! against `@audit`". That is true of *where the number lives* and must not become true
//! of *who reads it*. This crate is a library of pure functions over SQL and a dialect:
//! no I/O, no database, no log, no clock. A [`Policy`](crate::Policy) that opened the
//! audit database would put I/O below `quokka-core::execute()` in the dependency graph
//! and end the corpus testing that CLAUDE.md's first testing priority rests on.
//!
//! So the caller gathers the spend and passes it in as a value. `quokka-core` does that
//! — it is the crate that already holds the log — and the number reaching
//! [`CostContext`] is just a `u64`. The decision here stays a pure function of
//! (budget, spend, who is asking), which is exactly what makes the table below possible.
//!
//! ## What this cannot do, said here rather than only in the docs
//!
//! Athena reports bytes scanned *after* execution, and there is no reliable
//! pre-execution estimate. This budget therefore stops the query *after* the one that
//! crossed the line, never the one that crossed it. Only layer 1 — the workgroup's
//! `BytesScannedCutoffPerQuery` — can stop what is already running. Every message this
//! module produces says so, because a cost control that is believed to be a hard cap is
//! worse than none.

use std::time::Duration;

/// Which cap applies to the caller.
///
/// Two classes rather than three, because the question a budget asks is "is somebody
/// watching this?". `automation` joins `agent`: a cron job at 3am is no more awake than
/// an agent is. This is deliberately *not* `quokka_audit::ActorKind` — that type lives
/// in the log's crate, and this one has no dependencies to spend on borrowing it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ActorClass {
    /// A person at a terminal or a window, who will notice the bill.
    Human,
    /// An agent or an automation, which will not.
    Agent,
}

impl ActorClass {
    pub fn as_str(self) -> &'static str {
        match self {
            ActorClass::Human => "human",
            ActorClass::Agent => "agent",
        }
    }
}

/// A connection's `[connections.x.cost_guard]`, in bytes and seconds (§6.4).
///
/// Human-only configuration like everything else in the config file (invariant 7). There
/// is no flag and no agent-callable tool that raises a limit, lengthens a window or
/// switches a guard off — an agent that could set its own budget does not have one.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CostGuard {
    /// The rolling window the spend is summed over.
    pub window: Duration,
    /// Bytes an agent may scan in the window. `None` is unlimited.
    pub agent_limit: Option<u64>,
    /// Bytes a human may scan in the window. `None` is unlimited, which is §6.4's
    /// proposed default.
    pub human_limit: Option<u64>,
    /// Where a human is warned, short of being stopped.
    ///
    /// There is no `agent_warn`, and its absence is the asymmetry rather than an
    /// omission: a warning is a sentence someone reads and decides about, and the actor
    /// this guard exists for is the one that is not reading. An agent gets a limit; a
    /// person gets a number and their own judgement.
    pub human_warn: Option<u64>,
}

impl Default for CostGuard {
    /// §6.4's proposed defaults, for a connection whose `cost_guard` block omits a key:
    /// a day's window, agents capped conservatively, humans uncapped with a warning.
    fn default() -> Self {
        CostGuard {
            window: Duration::from_secs(24 * 60 * 60),
            agent_limit: Some(50 * 1_000_000_000),
            human_limit: None,
            human_warn: Some(500 * 1_000_000_000),
        }
    }
}

impl CostGuard {
    /// The cap that binds this caller, if any.
    pub fn limit_for(&self, actor: ActorClass) -> Option<u64> {
        match actor {
            ActorClass::Agent => self.agent_limit,
            ActorClass::Human => self.human_limit,
        }
    }

    /// The threshold at which this caller is warned but not stopped.
    pub fn warn_for(&self, actor: ActorClass) -> Option<u64> {
        match actor {
            ActorClass::Agent => None,
            ActorClass::Human => self.human_warn,
        }
    }
}

/// The budget, the caller, and what the caller has already spent.
///
/// `spend` is `None` when the audit log could not be read. That is not the same as zero
/// and must never be treated as it: see [`Denial::CostSpendUnknown`](crate::Denial).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CostContext {
    pub guard: CostGuard,
    pub actor: ActorClass,
    /// Bytes this actor has scanned on this connection inside the window, as the caller
    /// read it out of the log. `None` means the log could not be read at all.
    pub spend: Option<u64>,
}

/// A budget a query is close to, said in words a surface renders verbatim.
///
/// Below the surface for the reason `WriteConfirmation` and `Pager` are: the words a
/// surface renders live where they can be table-tested (§9). A cost warning is the same
/// shape as a staleness flag — a sentence about a number, not a behaviour.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CostWarning {
    pub spent: u64,
    pub threshold: u64,
    pub limit: Option<u64>,
    pub window: Duration,
    pub actor: ActorClass,
}

impl CostWarning {
    /// `data scanned on this connection is past …` — the line a surface shows.
    pub fn message(&self, connection: &str) -> String {
        let limit = match self.limit {
            Some(limit) => format!(
                "; this connection stops {}s at {}",
                self.actor.as_str(),
                bytes(limit)
            ),
            None => format!(
                "; there is no limit for {}s on this connection, only this warning",
                self.actor.as_str()
            ),
        };
        format!(
            "cost warning: {} scanned on connection {connection:?} in the last {} — past \
             the {} warning threshold{limit}. Bytes scanned are reported after a query \
             runs, so this counts what has already been spent, not what the next query \
             will cost.",
            bytes(self.spent),
            window(self.window),
            bytes(self.threshold),
        )
    }
}

/// `50000000000` → `50 GB`. Decimal units, because that is how the bill is denominated
/// and how §6.4 writes the config (`"50GB"`).
pub fn bytes(n: u64) -> String {
    const UNITS: [(u64, &str); 4] = [
        (1_000_000_000_000, "TB"),
        (1_000_000_000, "GB"),
        (1_000_000, "MB"),
        (1_000, "kB"),
    ];
    for (scale, unit) in UNITS {
        if n >= scale {
            let value = n as f64 / scale as f64;
            // One decimal below ten, none above: `1.2 GB` and `512 GB` both read as a
            // size, `1.234 GB` and `512.0 GB` read as a measurement.
            return if value < 10.0 {
                format!("{value:.1} {unit}")
            } else {
                format!("{} {unit}", value.round() as u64)
            };
        }
    }
    format!("{n} bytes")
}

/// `86400s` → `1d`. The spelling the config file uses, so a message and the setting it
/// is about read the same.
pub fn window(w: Duration) -> String {
    let secs = w.as_secs();
    for (scale, unit) in [(86_400u64, "d"), (3_600, "h"), (60, "m")] {
        if secs >= scale && secs.is_multiple_of(scale) {
            return format!("{}{unit}", secs / scale);
        }
    }
    format!("{secs}s")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sizes_read_as_sizes() {
        assert_eq!(bytes(0), "0 bytes");
        assert_eq!(bytes(999), "999 bytes");
        assert_eq!(bytes(1_500), "1.5 kB");
        assert_eq!(bytes(50_000_000_000), "50 GB");
        assert_eq!(bytes(1_200_000_000), "1.2 GB");
        assert_eq!(bytes(2_500_000_000_000), "2.5 TB");
    }

    #[test]
    fn a_window_is_spelled_the_way_the_config_file_spells_it() {
        assert_eq!(window(Duration::from_secs(86_400)), "1d");
        assert_eq!(window(Duration::from_secs(7 * 86_400)), "7d");
        assert_eq!(window(Duration::from_secs(3_600)), "1h");
        assert_eq!(window(Duration::from_secs(90)), "90s");
    }

    /// The asymmetry §6.4 exists for, asserted rather than assumed.
    #[test]
    fn agents_and_humans_are_capped_separately_under_one_config() {
        let guard = CostGuard {
            window: Duration::from_secs(86_400),
            agent_limit: Some(50_000_000_000),
            human_limit: None,
            human_warn: Some(500_000_000_000),
        };

        assert_eq!(guard.limit_for(ActorClass::Agent), Some(50_000_000_000));
        assert_eq!(guard.limit_for(ActorClass::Human), None);
        assert_eq!(guard.warn_for(ActorClass::Human), Some(500_000_000_000));
        assert_eq!(
            guard.warn_for(ActorClass::Agent),
            None,
            "an agent gets a limit, not a sentence it will not read"
        );
    }

    #[test]
    fn a_warning_names_the_spend_the_window_and_what_stops_next() {
        let warning = CostWarning {
            spent: 600_000_000_000,
            threshold: 500_000_000_000,
            limit: None,
            window: Duration::from_secs(86_400),
            actor: ActorClass::Human,
        };
        let message = warning.message("prod");
        assert!(message.contains("600 GB"), "{message}");
        assert!(message.contains("1d"), "{message}");
        assert!(message.contains("500 GB"), "{message}");
        assert!(
            message.contains("after a query runs"),
            "the warning must not imply a pre-execution estimate: {message}"
        );
    }
}
