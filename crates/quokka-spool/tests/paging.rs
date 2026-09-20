//! The strongest statement of invariant 2 there is, and the cheapest to write: page
//! through a multi-page result and prove the database was touched exactly once.
//!
//! Also the rest of what a read of a spool has to get right — stable ordering, a sort
//! and a filter that never leave the file, and the scoping every one of them reports
//! when the spool holds only part of the result (§4.2).

mod support;

use quokka_core::{execute, Actor, ActorKind, Client, EventKind, ExecuteRequest, Value};
use quokka_spool::{Filter, Limits, Op, Position, SortKey, Spool, SpoolSet, View};
use support::Harness;

fn actor() -> Actor {
    Actor {
        kind: ActorKind::Human,
        id: "tester".to_string(),
    }
}

/// Run one query into a spool and hand back the finished spool.
async fn run(
    harness: &Harness,
    spools: &SpoolSet,
    sql: &str,
    max_rows: u64,
) -> (Spool, quokka_core::Outcome) {
    let query_id = uuid::Uuid::now_v7();
    let mut writer = spools.writer(query_id, "app").expect("spool");
    let path = writer.path().to_path_buf();

    let mut request = ExecuteRequest::new("app", sql, actor());
    request.client = Client::Cli;
    request.max_rows = max_rows;

    let outcome = execute(&harness.engine, request, &mut writer)
        .await
        .expect("execute");
    (Spool::open(&path).await.expect("open spool"), outcome)
}

#[tokio::test]
async fn paging_a_multi_page_result_runs_exactly_one_query() {
    let harness = Harness::with_rows(1500).await;
    let spools = SpoolSet::open(Some(&harness.dir.path().join("cache")), Limits::default())
        .await
        .expect("spool set");

    let (spool, outcome) = run(&harness, &spools, "SELECT * FROM items", 2000).await;
    assert_eq!(outcome.rows_returned, 1500);
    assert_eq!(outcome.rows_spooled, Some(1500));

    // Three full pages and a fourth that is short — every one of them a read of the
    // spool.
    let mut at = Position::start();
    let mut seen = Vec::new();
    let mut pages = 0;
    loop {
        let page = spool
            .page(&View::arrival_order(), at, 512)
            .await
            .expect("page");
        pages += 1;
        assert_eq!(page.rows_before, seen.len() as u64);
        seen.extend(page.rows.iter().map(|r| r.0[0].clone()));
        match page.next {
            Some(next) => at = next,
            None => break,
        }
    }
    assert_eq!(pages, 3);
    assert_eq!(seen.len(), 1500);

    // Arrival order, and every row exactly once.
    let ids: Vec<i64> = seen
        .iter()
        .map(|v| match v {
            Value::Int(i) => *i,
            other => panic!("id came back as {other:?}"),
        })
        .collect();
    assert_eq!(ids, (1..=1500).collect::<Vec<i64>>());

    // And the whole point: the log holds one query pair. Not one pair per page, not a
    // pair plus a count query — one execution, paid for once (§4, invariant 2).
    let events = harness.events().await;
    let pairs: Vec<&EventKind> = events
        .iter()
        .map(|e| &e.event_kind)
        .filter(|k| matches!(k, EventKind::QueryStarted | EventKind::QueryFinished))
        .collect();
    assert_eq!(
        pairs.len(),
        2,
        "paging should touch no database at all; the log holds {events:#?}"
    );

    spool.close().await;
    spools.close().await;
}

#[tokio::test]
async fn counting_and_filtering_also_stay_inside_the_spool() {
    let harness = Harness::with_rows(100).await;
    let spools = SpoolSet::open(Some(&harness.dir.path().join("cache")), Limits::default())
        .await
        .expect("spool set");
    let (spool, _) = run(&harness, &spools, "SELECT * FROM items", 200).await;

    assert_eq!(spool.count(&View::arrival_order()).await.unwrap(), 100);

    // `amount` is id * 1.5, so twenty rows are at or above 121.5.
    let view = View::arrival_order().with_filter(Filter::new(2, Op::Ge, Value::Float(121.5)));
    assert_eq!(spool.count(&view).await.unwrap(), 20);
    let page = spool.page(&view, Position::start(), 512).await.unwrap();
    assert_eq!(page.rows.len(), 20);

    // A text filter that is a substring, not a pattern: `%` in a value must match
    // itself rather than becoming a wildcard.
    let contains = View::arrival_order().with_filter(Filter::new(
        1,
        Op::Contains,
        Value::Text("item-0001".into()),
    ));
    assert_eq!(contains_count(&spool, &contains).await, 10);

    let wildcard =
        View::arrival_order().with_filter(Filter::new(1, Op::Contains, Value::Text("%".into())));
    assert_eq!(contains_count(&spool, &wildcard).await, 0);

    let events = harness.events().await;
    assert_eq!(
        events
            .iter()
            .filter(|e| matches!(e.event_kind, EventKind::QueryStarted))
            .count(),
        1
    );

    spool.close().await;
    spools.close().await;
}

async fn contains_count(spool: &Spool, view: &View) -> u64 {
    spool.count(view).await.expect("count")
}

#[tokio::test]
async fn a_sort_is_total_so_pages_do_not_repeat_or_drop_rows() {
    let harness = Harness::with_rows(300).await;
    let spools = SpoolSet::open(Some(&harness.dir.path().join("cache")), Limits::default())
        .await
        .expect("spool set");
    // Every row ties on this key, which is exactly the case where an unstable sort
    // starts serving row 7 on two different pages.
    let (spool, _) = run(
        &harness,
        &spools,
        "SELECT id, 'same' AS grp FROM items",
        400,
    )
    .await;

    let view = View::sorted_by(vec![SortKey::desc(1)]);
    let mut at = Position::start();
    let mut ids = Vec::new();
    loop {
        let page = spool.page(&view, at, 50).await.expect("page");
        ids.extend(page.rows.iter().map(|r| r.0[0].clone()));
        match page.next {
            Some(next) => at = next,
            None => break,
        }
    }

    let mut numbers: Vec<i64> = ids
        .iter()
        .map(|v| match v {
            Value::Int(i) => *i,
            other => panic!("{other:?}"),
        })
        .collect();
    assert_eq!(numbers.len(), 300, "a page repeated or dropped rows");
    numbers.sort_unstable();
    numbers.dedup();
    assert_eq!(numbers.len(), 300, "a row appeared on two pages");

    spool.close().await;
    spools.close().await;
}

/// §4.2's trap: a sort over a truncated spool orders the spooled prefix. The API has to
/// say so, or the UI at M4 gets it wrong by omission.
#[tokio::test]
async fn a_truncated_spool_reports_that_a_sort_is_scoped_to_it() {
    let harness = Harness::with_rows(100).await;
    let spools = SpoolSet::open(
        Some(&harness.dir.path().join("cache")),
        Limits {
            max_rows: 10,
            ..Limits::default()
        },
    )
    .await
    .expect("spool set");

    let (spool, outcome) = run(&harness, &spools, "SELECT * FROM items", 100).await;
    assert_eq!(outcome.rows_returned, 100);
    assert_eq!(outcome.rows_spooled, Some(10));
    assert_eq!(outcome.spool_capped, Some(quokka_core::Cap::Rows));

    let page = spool
        .page(
            &View::sorted_by(vec![SortKey::desc(2)]),
            Position::start(),
            512,
        )
        .await
        .expect("page");

    assert!(!page.scope.is_whole_result());
    let note = page.scope.note().expect("a truncated result must say so");
    assert!(note.contains("10"), "{note}");
    assert!(note.contains("ORDER BY"), "{note}");

    // And the sort really is over the spooled ten, not the hundred: the largest amount
    // in the spool is row 10's, not row 100's.
    assert_eq!(page.rows.len(), 10);
    assert_eq!(page.rows[0].0[0], Value::Int(10));

    // A spool that holds everything says nothing, so a surface can print the note
    // unconditionally.
    let (whole, _) = run(&harness, &spools, "SELECT * FROM items LIMIT 5", 100).await;
    assert!(whole.scoping().is_whole_result());
    assert!(whole.scoping().note().is_none());

    spool.close().await;
    whole.close().await;
    spools.close().await;
}

/// The two caps are different things and stay distinguishable — in the outcome, and in
/// the log, where `rows_spooled` beside `rows_returned` is what tells them apart.
#[tokio::test]
async fn truncation_is_reported_at_both_caps_and_they_are_distinguishable() {
    let harness = Harness::with_rows(100).await;

    // The caller's cap: everything that came back was kept.
    let roomy = SpoolSet::open(
        Some(&harness.dir.path().join("cache-roomy")),
        Limits::default(),
    )
    .await
    .unwrap();
    let (spool, by_max_rows) = run(&harness, &roomy, "SELECT * FROM items", 5).await;
    assert!(by_max_rows.truncated);
    assert_eq!(by_max_rows.spool_capped, None);
    assert_eq!(by_max_rows.rows_returned, 5);
    assert_eq!(by_max_rows.rows_spooled, Some(5));
    assert!(by_max_rows.is_partial());
    spool.close().await;

    // The spool's cap: the rows kept coming and the cache stopped growing.
    let tight = SpoolSet::open(
        Some(&harness.dir.path().join("cache-tight")),
        Limits {
            max_rows: 5,
            ..Limits::default()
        },
    )
    .await
    .unwrap();
    // `max_rows` is the whole table, so the caller's cap cannot fire and the only cap
    // left is the spool's — which is the point of this half of the test.
    let (spool, by_spool) = run(&harness, &tight, "SELECT * FROM items", 100).await;
    assert!(!by_spool.truncated);
    assert_eq!(by_spool.spool_capped, Some(quokka_core::Cap::Rows));
    assert_eq!(by_spool.rows_returned, 100);
    assert_eq!(by_spool.rows_spooled, Some(5));
    assert!(by_spool.is_partial());
    spool.close().await;

    // The byte cap is its own answer, not the row cap wearing a different hat.
    let thin = SpoolSet::open(
        Some(&harness.dir.path().join("cache-thin")),
        Limits {
            max_rows: 1_000_000,
            max_bytes: 200,
        },
    )
    .await
    .unwrap();
    let (spool, by_bytes) = run(&harness, &thin, "SELECT * FROM items", 100).await;
    assert_eq!(by_bytes.spool_capped, Some(quokka_core::Cap::Bytes));
    assert!(by_bytes.rows_spooled.unwrap() < by_bytes.rows_returned);
    spool.close().await;

    // In the log: `truncated` is set for either cap, and the pair of row counts says
    // which. Equal means the caller's cap; fewer spooled than returned means the
    // spool's.
    let finished: Vec<_> = harness
        .events()
        .await
        .into_iter()
        .filter(|e| matches!(e.event_kind, EventKind::QueryFinished))
        .collect();
    assert_eq!(finished.len(), 3);

    assert_eq!(finished[0].truncated, Some(true));
    assert_eq!(finished[0].rows_returned, Some(5));
    assert_eq!(finished[0].rows_spooled, Some(5));

    // Truncated in the log even though the caller's cap never fired: §4.2 says hitting
    // the spool cap marks the result truncated, and the row counts say which cap it was.
    assert_eq!(finished[1].truncated, Some(true));
    assert_eq!(finished[1].rows_returned, Some(100));
    assert_eq!(finished[1].rows_spooled, Some(5));

    assert_eq!(finished[2].truncated, Some(true));
    assert!(finished[2].rows_spooled < finished[2].rows_returned);

    roomy.close().await;
    tight.close().await;
    thin.close().await;
}
