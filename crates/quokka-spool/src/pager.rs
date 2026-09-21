//! The sentence a result tab puts above its rows (ARCHITECTURE §7).
//!
//! > `rows 1–512 of 12,481 · 1.2 GB scanned · as of 10:00 (45m ago) · [Next] [Re-run]`
//!
//! The words are here rather than in an iced `view` function for §9's reason: logic
//! inside a widget is logic that cannot be tested, and every number in that line is one
//! the spool already knows. The count is exact because it comes from `count(*)` over a
//! table this process wrote (§7) — not an estimate, and not "512+".
//!
//! The buttons are the surface's: what this produces is the prose to the left of them.
//! `[Re-run]` in particular is a *control*, never a behaviour — §1.4 is explicit that a
//! stale tab offers a re-run and does not take one.
//!
//! ## Why staleness is a number and not a refresh
//!
//! §4.1: a spool does not outlive its process, which bounds staleness to one process
//! lifetime without eliminating it. A result spooled at 10:00 and paged at 10:45 is
//! forty-five minutes old however ephemeral the file is. So the age is always on screen,
//! and past `spool_stale_after` (`[spool] stale_after`) the tab says so. Bounded and
//! visible beats invisible — and beats a tab that quietly re-runs a query that costs
//! money.

use std::time::Duration;

use time::format_description::well_known::Rfc3339;
use time::OffsetDateTime;

use crate::meta::Meta;
use crate::read::Page;

/// Everything the line above a result grid says.
#[derive(Debug, Clone, PartialEq)]
pub struct Pager {
    /// 1-based index of the first row on this page; 0 when the page is empty.
    pub first_row: u64,
    /// 1-based index of the last row on this page; 0 when the page is empty.
    pub last_row: u64,
    /// How many rows this view selects, exactly (§7).
    pub rows_in_view: u64,
    /// Whether there is a page after this one.
    pub has_next: bool,
    /// Whether there is a page before this one.
    pub has_previous: bool,
    /// When the query ran, as the spool recorded it.
    pub as_of: Option<OffsetDateTime>,
    /// How long ago that was. `None` when the spool recorded no time, or when the
    /// clock has gone backwards since — a negative age is a bug to stay quiet about,
    /// not to render.
    pub age: Option<Duration>,
    /// True once [`Pager::age`] is past `spool_stale_after`.
    pub stale: bool,
    /// Bytes the engine reported scanning for this result (§3.2, §6.4).
    ///
    /// **Here rather than in a `view` function**, for the reason the rest of this file
    /// exists: M4 put the pager's words in `quokka-spool` because that is where they can
    /// be table-tested, and bytes scanned belongs beside them. It is the number a person
    /// looking at an Athena result most wants and is least able to work out — the one
    /// that says what the query on screen cost.
    ///
    /// `None` when the driver reported none, which is every driver but Athena. A result
    /// that genuinely scanned nothing reports `Some(0)` and says "0 bytes scanned",
    /// because on Athena that is worth knowing: it means the result came from the cache.
    pub data_scanned_bytes: Option<i64>,
}

impl Pager {
    /// Read the line's numbers off one page and its spool's meta.
    ///
    /// `rows_in_view` comes from [`Spool::count`](crate::Spool::count) — the caller's,
    /// because counting is async and this is not.
    pub fn new(
        page: &Page,
        rows_in_view: u64,
        meta: &Meta,
        now: OffsetDateTime,
        stale_after: Option<Duration>,
    ) -> Self {
        let shown = page.rows.len() as u64;
        let (first_row, last_row) = if shown == 0 {
            (0, 0)
        } else {
            (page.rows_before + 1, page.rows_before + shown)
        };

        let as_of = meta
            .created_at
            .as_deref()
            .and_then(|text| OffsetDateTime::parse(text, &Rfc3339).ok());
        let age = as_of.and_then(|at| (now - at).try_into().ok());

        Pager {
            first_row,
            last_row,
            rows_in_view,
            has_next: page.next.is_some() && shown > 0,
            has_previous: page.rows_before > 0,
            as_of,
            age,
            stale: match (age, stale_after) {
                (Some(age), Some(limit)) => age >= limit,
                _ => false,
            },
            data_scanned_bytes: meta.data_scanned_bytes,
        }
    }

    /// `rows 1–512 of 12,481 · 1.2 GB scanned · as of 10:00 (45m ago)`.
    pub fn line(&self) -> String {
        let mut line = self.rows_phrase();
        if let Some(scanned) = self.scanned_phrase() {
            line.push_str(" · ");
            line.push_str(&scanned);
        }
        if let Some(freshness) = self.freshness() {
            line.push_str(" · ");
            line.push_str(&freshness);
        }
        line
    }

    /// `1.2 GB scanned`, or nothing at all when the driver does not measure it.
    ///
    /// Said plainly rather than as a currency: the rate is region-dependent and changes,
    /// so the log stores bytes and this reports bytes. A person who knows their rate can
    /// multiply; a number that was wrong when it was written cannot be corrected.
    pub fn scanned_phrase(&self) -> Option<String> {
        let bytes = self.data_scanned_bytes?;
        Some(format!("{} scanned", bytes_scanned(bytes)))
    }

    /// `rows 1–512 of 12,481`, or `no rows` when the view selects none.
    pub fn rows_phrase(&self) -> String {
        if self.rows_in_view == 0 {
            return "no rows".to_string();
        }
        if self.first_row == 0 {
            // A page past the end of a non-empty view: the count still means something.
            return format!("no rows here · {} in view", thousands(self.rows_in_view));
        }
        format!(
            "rows {}–{} of {}",
            thousands(self.first_row),
            thousands(self.last_row),
            thousands(self.rows_in_view)
        )
    }

    /// `as of 10:00 (45m ago)`, with `— stale` appended past `spool_stale_after`.
    pub fn freshness(&self) -> Option<String> {
        let at = self.as_of?;
        let clock = format!("{:02}:{:02}", at.hour(), at.minute());
        let mut text = match self.age {
            Some(age) => format!("as of {clock} ({} ago)", ago(age)),
            None => format!("as of {clock}"),
        };
        if self.stale {
            // Named rather than merely coloured: §4.1 wants staleness visible, and a
            // tint is not a sentence.
            text.push_str(" — stale");
        }
        Some(text)
    }
}

/// `1234567` → `1.2 MB`. Decimal units, because that is how the bill is denominated
/// (`$5 per TB` means 10^12 bytes) and how `[cost_guard]` writes its limits.
///
/// Shared with the cost guard's own messages: this is `quokka_policy::CostGuard`'s
/// spelling, re-exported rather than written twice, so a warning and the line above the
/// grid say the same size the same way.
pub fn bytes_scanned(bytes: i64) -> String {
    if bytes < 0 {
        // Nothing should produce this; saying so beats rendering a negative size.
        return "an unknown amount".to_string();
    }
    quokka_core::cost_bytes(bytes as u64)
}

/// `45m`, `2h 05m`, `3d`. Coarse on purpose: the question a result tab answers is "is
/// this from a minute ago or from this morning", not "how many seconds".
fn ago(age: Duration) -> String {
    let secs = age.as_secs();
    match secs {
        0..=59 => format!("{secs}s"),
        60..=3599 => format!("{}m", secs / 60),
        3600..=86_399 => {
            let (h, m) = (secs / 3600, (secs % 3600) / 60);
            if m == 0 {
                format!("{h}h")
            } else {
                format!("{h}h {m:02}m")
            }
        }
        _ => format!("{}d", secs / 86_400),
    }
}

/// `12481` → `12,481`. The pager's numbers are read by a person, and §7 writes them
/// with separators.
fn thousands(n: u64) -> String {
    let digits = n.to_string();
    let mut out = String::with_capacity(digits.len() + digits.len() / 3);
    for (i, c) in digits.chars().enumerate() {
        if i > 0 && (digits.len() - i).is_multiple_of(3) {
            out.push(',');
        }
        out.push(c);
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::view::{Position, Scoping};
    use quokka_core::Row;
    use time::macros::datetime;

    fn meta(created_at: &str) -> Meta {
        Meta {
            created_at: Some(created_at.to_string()),
            query_id: None,
            connection: Some("prod".to_string()),
            rows: 12_481,
            rows_returned: 12_481,
            spool_capped: None,
            truncated_by_max_rows: false,
            query_duration_ms: Some(120),
            status: Some("ok".to_string()),
            data_scanned_bytes: None,
            engine_time_ms: None,
        }
    }

    fn page(rows: usize, rows_before: u64, more: bool) -> Page {
        Page {
            columns: Vec::new(),
            rows: vec![Row(Vec::new()); rows],
            next: more.then(Position::start),
            rows_before,
            scope: Scoping {
                spooled_rows: 12_481,
                rows_returned: 12_481,
                spool_capped: None,
                truncated_by_max_rows: false,
            },
        }
    }

    #[test]
    fn the_line_reads_as_section_7_writes_it() {
        let pager = Pager::new(
            &page(512, 0, true),
            12_481,
            &meta("2026-05-04T10:00:00Z"),
            datetime!(2026-05-04 10:45:00 UTC),
            Some(Duration::from_secs(2 * 3600)),
        );
        assert_eq!(pager.line(), "rows 1–512 of 12,481 · as of 10:00 (45m ago)");
        assert!(pager.has_next);
        assert!(!pager.has_previous);
        assert!(!pager.stale, "45m is inside a two-hour window");
    }

    #[test]
    fn a_second_page_counts_from_where_it_starts() {
        let pager = Pager::new(
            &page(512, 512, true),
            12_481,
            &meta("2026-05-04T10:00:00Z"),
            datetime!(2026-05-04 10:00:30 UTC),
            None,
        );
        assert_eq!(pager.rows_phrase(), "rows 513–1,024 of 12,481");
        assert!(pager.has_previous);
        assert_eq!(pager.freshness().as_deref(), Some("as of 10:00 (30s ago)"));
    }

    #[test]
    fn past_stale_after_the_tab_says_so_in_words() {
        let pager = Pager::new(
            &page(512, 0, false),
            512,
            &meta("2026-05-04T10:00:00Z"),
            datetime!(2026-05-04 12:31:00 UTC),
            Some(Duration::from_secs(1800)),
        );
        assert!(pager.stale);
        assert_eq!(
            pager.freshness().as_deref(),
            Some("as of 10:00 (2h 31m ago) — stale")
        );
    }

    /// §3.2's number, in the line a person actually reads. The one thing an Athena user
    /// most wants to know about the result on screen is what it cost.
    #[test]
    fn an_athena_result_says_what_it_scanned() {
        let mut m = meta("2026-05-04T10:00:00Z");
        m.data_scanned_bytes = Some(1_234_567_890);
        let pager = Pager::new(
            &page(512, 0, true),
            12_481,
            &m,
            datetime!(2026-05-04 10:00:30 UTC),
            None,
        );
        assert_eq!(
            pager.line(),
            "rows 1–512 of 12,481 · 1.2 GB scanned · as of 10:00 (30s ago)"
        );
    }

    /// Zero is an answer on Athena — a result served from the cache scanned nothing and
    /// cost nothing — so it is said rather than hidden. A driver that reports *no*
    /// number says nothing at all, which is a different line.
    #[test]
    fn nothing_scanned_and_nothing_reported_read_differently() {
        let mut free = meta("2026-05-04T10:00:00Z");
        free.data_scanned_bytes = Some(0);
        let pager = Pager::new(
            &page(1, 0, false),
            1,
            &free,
            datetime!(2026-05-04 10:00:01 UTC),
            None,
        );
        assert_eq!(pager.scanned_phrase().as_deref(), Some("0 bytes scanned"));

        // Every driver but Athena.
        let pager = Pager::new(
            &page(1, 0, false),
            1,
            &meta("2026-05-04T10:00:00Z"),
            datetime!(2026-05-04 10:00:01 UTC),
            None,
        );
        assert_eq!(pager.scanned_phrase(), None);
        assert!(
            !pager.line().contains("scanned"),
            "a driver that does not measure this should not appear to: {}",
            pager.line()
        );
    }

    #[test]
    fn a_zero_stale_after_never_flags_anything() {
        let pager = Pager::new(
            &page(1, 0, false),
            1,
            &meta("2026-05-04T10:00:00Z"),
            datetime!(2026-05-11 10:00:00 UTC),
            None,
        );
        assert!(!pager.stale, "the config asked for no staleness flag");
        assert_eq!(pager.freshness().as_deref(), Some("as of 10:00 (7d ago)"));
    }

    #[test]
    fn an_empty_result_says_so_rather_than_counting_from_one() {
        let pager = Pager::new(
            &page(0, 0, false),
            0,
            &meta("2026-05-04T10:00:00Z"),
            datetime!(2026-05-04 10:00:01 UTC),
            None,
        );
        assert_eq!(pager.rows_phrase(), "no rows");
        assert!(!pager.has_next);
    }

    #[test]
    fn a_spool_with_no_recorded_time_says_nothing_about_freshness() {
        let mut m = meta("2026-05-04T10:00:00Z");
        m.created_at = None;
        let pager = Pager::new(
            &page(3, 0, false),
            3,
            &m,
            datetime!(2026-05-04 10:00:01 UTC),
            Some(Duration::from_secs(1)),
        );
        assert_eq!(pager.freshness(), None);
        assert!(!pager.stale, "an unknown age is not a stale one");
        assert_eq!(pager.line(), "rows 1–3 of 3");
    }
}
