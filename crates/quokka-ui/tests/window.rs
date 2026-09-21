//! What M4 claims about the window, asserted against the audit log rather than against
//! a screenshot.
//!
//! The window itself is not driven here, and that is the design rather than a gap. §9
//! asks for the iced layer to be thin enough that its test story is smoke tests, and the
//! way to earn that is to keep everything worth asserting out of `update` and `view`.
//! What is left in those functions is wiring; what these tests exercise is
//! [`quokka_ui::work`], which is every path the window has to the engine, called exactly
//! as `update` calls it.
//!
//! Four claims, each one the UI version of a promise an earlier milestone made:
//!
//! 1. The mode binds the *third* surface identically (invariant 9, §6.3).
//! 2. Paging runs one query — M2's claim, two layers up (§4, invariant 2).
//! 3. Autocomplete leaves no trace in the log, because it reached no database (§1.4, §5).
//! 4. An export from the window is an audited event like any other (§5).

use std::sync::Arc;

use quokka_core::{
    AccessMode, Actor, ActorKind, AuditLog, ConnectionConfig, Engine, EventKind, Registry, Status,
};
use quokka_spool::{Position, SpoolSet, View};
use quokka_ui::work::{self, Ran, Session};

struct Harness {
    session: Session,
    dir: tempfile::TempDir,
}

/// Two connections over one SQLite file, exactly as the MCP tests set them up: `app` is
/// `read_write`, `app-ro` is not.
///
/// The session is assembled rather than booted: `work::boot` reads a config file and
/// claims the XDG cache directory, and a test that went through it would be testing
/// `Config::load` again while fighting over a shared directory.
async fn harness(rows: usize) -> Harness {
    let dir = tempfile::tempdir().expect("tempdir");
    let app_db = dir.path().join("app.db");
    let audit_db = dir.path().join("audit.db");

    {
        let options = sqlx::sqlite::SqliteConnectOptions::new()
            .filename(&app_db)
            .create_if_missing(true);
        let pool = sqlx::SqlitePool::connect_with(options)
            .await
            .expect("app db");
        sqlx::query("CREATE TABLE orders (id INTEGER PRIMARY KEY, total REAL, note TEXT)")
            .execute(&pool)
            .await
            .expect("create");
        for i in 1..=rows {
            sqlx::query("INSERT INTO orders (id, total, note) VALUES (?, ?, ?)")
                .bind(i as i64)
                .bind(i as f64 * 1.5)
                .bind(format!("note {i}"))
                .execute(&pool)
                .await
                .expect("insert");
        }
        pool.close().await;
    }

    let audit = AuditLog::open(&audit_db).await.expect("audit log");
    let mut registry = Registry::builtin_only(&audit_db);
    registry.insert(ConnectionConfig {
        path: Some(app_db.clone()),
        mode: AccessMode::ReadWrite,
        ..ConnectionConfig::new("app", "sqlite")
    });
    registry.insert(ConnectionConfig {
        path: Some(app_db),
        mode: AccessMode::ReadOnly,
        ..ConnectionConfig::new("app-ro", "sqlite")
    });

    let connections = work::connection_rows(&registry);
    let engine = Arc::new(Engine::new(
        registry,
        audit,
        quokka_driver::builtin_factories(),
    ));
    let spools = Arc::new(
        SpoolSet::open(Some(&dir.path().join("cache")), Default::default())
            .await
            .expect("spool set"),
    );

    Harness {
        session: Session {
            engine,
            spools,
            spool: quokka_core::SpoolConfig::default(),
            actor: Actor {
                kind: ActorKind::Human,
                id: "ivy".to_string(),
            },
            connections,
        },
        dir,
    }
}

impl Harness {
    async fn events(&self) -> Vec<quokka_audit::StoredEvent> {
        self.session
            .engine
            .audit()
            .read_all()
            .await
            .expect("read the log")
    }

    async fn run(&self, connection: &str, sql: &str, write: bool) -> Ran {
        work::run(
            self.session.clone(),
            connection.to_string(),
            sql.to_string(),
            write,
        )
        .await
    }

    async fn intact(&self) -> bool {
        self.session
            .engine
            .audit()
            .verify()
            .await
            .expect("verify")
            .is_intact()
    }
}

/// **Invariant 9, on the third surface.** The same write, against the same connection,
/// refused from the window in exactly the words the CLI and MCP use — and with the same
/// two events in the log. There was a test pairing two surfaces; this makes it three.
#[tokio::test(flavor = "multi_thread")]
async fn a_write_to_a_read_only_connection_is_denied_at_the_window_too() {
    let h = harness(3).await;

    let ran = h.run("app-ro", "DELETE FROM orders", true).await;

    let Ran::Denied { code, message, .. } = ran else {
        panic!("a write on a read_only connection must be refused: {ran:?}");
    };
    assert_eq!(code, "policy.read_only");
    // Rendered verbatim by the window, so the refusal reads the same in all three
    // places. If this ever stops naming the setting, three surfaces stop explaining it.
    assert!(
        message.contains("read_only") && message.contains("config"),
        "the denial must name the setting and where to change it: {message}"
    );

    let events = h.events().await;
    assert_eq!(events.len(), 2, "a denial is a query pair, not a lone row");
    assert_eq!(events[0].event.event_kind, EventKind::QueryStarted);
    assert_eq!(events[1].event.status, Status::Denied);
    assert_eq!(events[1].event.client, quokka_audit::Client::Ui);
    assert!(h.intact().await);
}

/// And the same statement, on a connection a human configured for writes, runs.
#[tokio::test(flavor = "multi_thread")]
async fn the_same_write_runs_where_a_human_allowed_it() {
    let h = harness(3).await;
    let ran = h.run("app", "DELETE FROM orders", true).await;
    assert!(
        matches!(ran, Ran::Loaded(_)),
        "a write a human configured and confirmed should run: {ran:?}"
    );
}

/// The confirmation the window shows before that write is a rendering of the same parse
/// the guardrail used — and it names the disaster specifically (§7).
#[test]
fn an_unfiltered_delete_is_flagged_before_it_runs() {
    let summary = quokka_core::summarize("DELETE FROM orders", quokka_core::Dialect::Sqlite);
    let confirmation =
        quokka_core::WriteConfirmation::for_statement(&summary).expect("a write is confirmed");
    assert_eq!(confirmation.headline(), "Run this DELETE against orders?");
    assert!(confirmation
        .warnings()
        .iter()
        .any(|w| w.contains("no WHERE")));

    assert!(
        quokka_core::WriteConfirmation::for_statement(&quokka_core::summarize(
            "SELECT * FROM orders",
            quokka_core::Dialect::Sqlite
        ))
        .is_none(),
        "a read is never confirmed"
    );
}

/// **M2's claim, two layers up.** Paging a multi-page result reads the spool; the log
/// holds exactly one pair of events for it, however many pages are turned.
#[tokio::test(flavor = "multi_thread")]
async fn paging_the_grid_runs_one_query() {
    let h = harness(1500).await;

    let ran = h.run("app", "SELECT * FROM orders", false).await;
    let Ran::Loaded(loaded) = ran else {
        panic!("the query should have produced rows: {ran:?}")
    };

    assert_eq!(
        loaded.page.rows.len(),
        512,
        "one page is the ceiling (§4.2)"
    );
    assert_eq!(
        loaded.rows_in_view, 1500,
        "the count is exact, from the spool"
    );

    // Turn every page the way `[Next]` does.
    let mut pages = 1;
    let mut seen = loaded.page.rows.len();
    let mut next = loaded.page.next;
    while let Some(position) = next {
        let paged = work::page(
            loaded.spool.clone(),
            View::arrival_order(),
            position,
            loaded.query_id,
        )
        .await
        .expect("a page");
        seen += paged.page.rows.len();
        next = paged.page.next;
        pages += 1;
    }
    assert_eq!(pages, 3, "1500 rows is three pages of 512");
    assert_eq!(seen, 1500);

    // Sorting is a read of the same spool, so it adds nothing either.
    let sorted = work::page(
        loaded.spool.clone(),
        View::sorted_by(vec![quokka_spool::SortKey::desc(0)]),
        Position::start(),
        loaded.query_id,
    )
    .await
    .expect("a sorted page");
    assert_eq!(sorted.page.rows[0].0[0], quokka_core::Value::Int(1500));

    let events = h.events().await;
    assert_eq!(
        events.len(),
        2,
        "one execution, one pair of events — paging never re-runs anything: {:?}",
        events
            .iter()
            .map(|e| (e.event.event_kind, e.event.status))
            .collect::<Vec<_>>()
    );
}

/// **Autocomplete leaves nothing in the log, because it reached no database.**
///
/// The catalog is read once, explicitly, which is one `introspect` event (§5). Every
/// suggestion after that is a pure function of the catalog in memory — a keystroke's
/// worth of completion adds nothing to the log, and a second read inside the TTL adds
/// nothing either, because a cache hit touches no database.
#[tokio::test(flavor = "multi_thread")]
async fn autocomplete_leaves_nothing_in_the_log() {
    let h = harness(3).await;

    let catalog = work::catalog(h.session.clone(), "app".to_string(), false)
        .await
        .expect("a catalog");
    let after_refresh = h.events().await;
    assert_eq!(after_refresh.len(), 1, "one introspect event, never a pair");
    assert_eq!(after_refresh[0].event.event_kind, EventKind::Introspect);

    let mut suggestions = 0;
    for typed in ["o", "or", "ord", "orders.", "orders.t", "orders.no"] {
        let word = quokka_ui::complete::word_at(typed, typed.chars().count());
        suggestions += quokka_ui::complete::suggest(&catalog, &word).len();
    }
    assert!(
        suggestions > 0,
        "the catalog should have answered something"
    );

    // And selecting the connection again reads the cache, which appends nothing.
    let _ = work::catalog(h.session.clone(), "app".to_string(), false)
        .await
        .expect("a cached catalog");

    let events = h.events().await;
    assert_eq!(
        events.len(),
        1,
        "completion reached no database, so there is nothing for the log to say"
    );
}

/// An export from the window is an `export` event linked to the query that filled it —
/// clicking rather than typing does not make it optional (§5).
#[tokio::test(flavor = "multi_thread")]
async fn exporting_from_the_window_is_audited() {
    let h = harness(20).await;
    let Ran::Loaded(loaded) = h.run("app", "SELECT * FROM orders", false).await else {
        panic!("rows expected")
    };
    let path = h.dir.path().join("orders.csv");

    let report = work::export(
        h.session.clone(),
        loaded.spool.clone(),
        View::arrival_order(),
        loaded.outcome.clone(),
        loaded.sql.clone(),
        path.display().to_string(),
        quokka_spool::Format::Csv,
    )
    .await
    .expect("the export");
    assert_eq!(report.rows, 20);
    assert!(report.whole_result);
    assert!(path.exists());

    let events = h.events().await;
    let export = events
        .iter()
        .find(|e| e.event.event_kind == EventKind::Export)
        .expect("an export event");
    assert_eq!(export.event.client, quokka_audit::Client::Ui);
    assert_eq!(
        export.event.parent_id,
        Some(loaded.query_id),
        "an export points at the query whose rows it wrote (§5)"
    );
    // Invariant 4 does not soften for exports: a count, never a value from the file.
    let log = serde_json::to_string(&events).expect("serializable log");
    assert!(
        !log.contains("note 7"),
        "no result data reaches the log, ever"
    );
}

/// The audit view is a result tab over a query on `@audit` (§5) — so reading the log is
/// itself a logged query, and it pages and exports like any other result.
#[tokio::test(flavor = "multi_thread")]
async fn the_audit_view_is_an_ordinary_audited_query() {
    let h = harness(3).await;
    let _ = h.run("app", "SELECT * FROM orders", false).await;

    let ran = h
        .run(
            quokka_core::AUDIT_CONNECTION,
            "SELECT event_kind, status, client FROM audit_log ORDER BY id",
            false,
        )
        .await;
    let Ran::Loaded(loaded) = ran else {
        panic!("the audit view is a query like any other: {ran:?}")
    };
    assert!(loaded.page.rows.len() >= 2);

    let events = h.events().await;
    assert_eq!(
        events
            .iter()
            .filter(|e| e.event.connection == "@audit")
            .count(),
        2,
        "reading the log leaves its own pair of events in the log"
    );
}

/// A write against `@audit` is refused like any other write against a read-only
/// connection — the log is not writable from the window either.
#[tokio::test(flavor = "multi_thread")]
async fn the_log_cannot_be_written_from_the_window() {
    let h = harness(1).await;
    let ran = h
        .run(quokka_core::AUDIT_CONNECTION, "DELETE FROM audit_log", true)
        .await;
    assert!(
        matches!(ran, Ran::Denied { .. }),
        "the audit connection is read-only for the human too: {ran:?}"
    );
    assert!(h.intact().await);
}

// ---------------------------------------------------------------------------
// M5: the cost guard at the window (§6.4)
// ---------------------------------------------------------------------------

/// A harness whose `app` connection carries a budget, and an agent that has spent it.
///
/// The spend is appended to the log directly because no SQLite query scans anything —
/// `data_scanned_bytes` is Athena's column, and the budget sums it. What is under test
/// is the refusal, not the arithmetic, which `quokka-core` tests against a driver that
/// reports bytes.
async fn budgeted_harness(spent: i64, kind: ActorKind) -> Harness {
    let h = harness(3).await;

    let guard = quokka_core::CostGuard {
        window: std::time::Duration::from_secs(86_400),
        agent_limit: Some(50_000_000_000),
        human_limit: None,
        human_warn: Some(500_000_000_000),
    };

    let audit_db = h.dir.path().join("audit.db");
    let audit = AuditLog::open(&audit_db).await.expect("audit log");
    audit
        .append(quokka_audit::AuditEvent {
            id: uuid::Uuid::now_v7(),
            query_id: uuid::Uuid::now_v7(),
            parent_id: None,
            at: quokka_audit::now_rfc3339().expect("a timestamp"),
            duration_ms: Some(1),
            actor_kind: kind,
            actor_id: "ivy".to_string(),
            session_id: "seed".to_string(),
            client: quokka_audit::Client::Ui,
            connection: "app".to_string(),
            dialect: "athena".to_string(),
            database: None,
            schema_name: None,
            event_kind: EventKind::QueryFinished,
            sql_logging: quokka_audit::SqlLogging::Fingerprint,
            sql_text: None,
            sql_fingerprint: "SELECT ?".to_string(),
            statement_kind: Some("query".to_string()),
            read_only: Some(true),
            params: None,
            status: Status::Ok,
            error_code: None,
            error_message: None,
            rows_returned: Some(1),
            rows_affected: None,
            rows_spooled: None,
            truncated: Some(false),
            export_format: None,
            export_path: None,
            data_scanned_bytes: Some(spent),
            cost_estimate_usd: None,
            approved_by: None,
            tags: None,
        })
        .await
        .expect("append");

    // The registry has to be rebuilt to carry the budget, over the same log and the same
    // database file.
    let mut registry = Registry::builtin_only(&audit_db);
    registry.insert(ConnectionConfig {
        path: Some(h.dir.path().join("app.db")),
        mode: AccessMode::ReadWrite,
        cost_guard: Some(guard),
        ..ConnectionConfig::new("app", "sqlite")
    });

    let connections = work::connection_rows(&registry);
    Harness {
        session: Session {
            engine: Arc::new(Engine::new(
                registry,
                audit,
                quokka_driver::builtin_factories(),
            )),
            connections,
            ..h.session
        },
        dir: h.dir,
    }
}

/// **The parity test grows again, on the third surface.** A budget denial reads at the
/// window exactly as it does from the CLI and from MCP — the same code, and the same
/// sentence, because there is one place those words are composed and every surface
/// renders it verbatim.
#[tokio::test(flavor = "multi_thread")]
async fn a_budget_denial_reads_the_same_at_the_window() {
    let h = budgeted_harness(60_000_000_000, ActorKind::Agent).await;
    let session = Session {
        actor: Actor {
            kind: ActorKind::Agent,
            id: "ivy".to_string(),
        },
        ..h.session.clone()
    };

    let ran = work::run(
        session,
        "app".to_string(),
        "SELECT * FROM orders".to_string(),
        false,
    )
    .await;

    let Ran::Denied { code, message, .. } = ran else {
        panic!("an agent past its budget must be refused at the window too: {ran:?}");
    };
    assert_eq!(code, "policy.cost_budget");
    // The same three facts the CLI's envelope and MCP's `data` carry.
    assert!(message.contains("50 GB"), "the budget: {message}");
    assert!(message.contains("1d"), "the window: {message}");
    assert!(message.contains("60 GB"), "the spend: {message}");
    assert!(
        message.contains("cost_guard"),
        "and where to change it, since only a human can: {message}"
    );

    // And it is the denial shape in the log: two events, the second `denied`.
    let events = h.events().await;
    let denials: Vec<_> = events
        .iter()
        .filter(|e| e.event.status == Status::Denied)
        .collect();
    assert_eq!(denials.len(), 1);
    assert_eq!(denials[0].event.client, quokka_audit::Client::Ui);
    assert!(h.intact().await);
}

/// The asymmetry, at the window: the same spend, the same connection, a human.
#[tokio::test(flavor = "multi_thread")]
async fn the_same_spend_by_a_human_runs_and_warns() {
    let h = budgeted_harness(600_000_000_000, ActorKind::Human).await;

    let ran = work::run(
        h.session.clone(),
        "app".to_string(),
        "SELECT * FROM orders".to_string(),
        false,
    )
    .await;

    let Ran::Loaded(loaded) = ran else {
        panic!("an uncapped human is never refused by the agent cap: {ran:?}");
    };
    let warning = loaded
        .outcome
        .cost_warning
        .as_deref()
        .expect("past human_warn, the window has a sentence to show");
    assert!(warning.contains("600 GB"), "{warning}");
    assert!(
        warning.contains("after a query runs"),
        "the warning must not imply a pre-execution estimate: {warning}"
    );
}
