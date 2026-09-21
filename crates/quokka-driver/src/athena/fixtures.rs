//! Athena, tested without Athena (ARCHITECTURE §9).
//!
//! LocalStack's Athena support is not in its community edition, so there is no container
//! to point at — which leaves the two things §9 settles on: trait-level fakes, and
//! **recorded HTTP fixtures**. This file is the second. A `wiremock` server on loopback
//! replays the JSON Athena returns for `StartQueryExecution`, `GetQueryExecution`,
//! `GetQueryResults` and `StopQueryExecution`, and the driver is pointed at it.
//!
//! **A recorded fixture is not a server, and this file cannot pretend otherwise.** What
//! it proves is that this driver reads those four shapes correctly, submits what it says
//! it submits, and stops what it says it stops. What it cannot prove is that the shapes
//! are right — that is a claim about Athena, and only a real workgroup settles it. The
//! README says so in the compatibility matrix rather than leaving the reader to assume.
//!
//! These live inside the crate rather than in `tests/` for a mundane reason with a good
//! consequence: `aws-sdk-athena` is an *optional* dependency, so only code inside
//! `quokka-driver` can name it under `#[cfg(feature = "athena")]`. Putting the fixtures
//! here keeps `aws-sdk-athena` out of the dev-dependency graph of the default
//! `cargo test`, which would otherwise compile the whole AWS SDK for everyone.
//!
//! Note what these tests still cannot do: call `AthenaDriver::execute` directly. It
//! takes an [`ExecutePermit`](quokka_core::ExecutePermit), which only
//! `quokka-core::execute()` can construct — so even the driver's own fixtures reach the
//! "database" through the audited path, and every one of them leaves two events in a
//! real audit log.

use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;

use async_trait::async_trait;
use aws_sdk_athena::config::{BehaviorVersion, Credentials, Region};
use aws_sdk_athena::Client;
use quokka_core::{
    execute, AccessMode, Actor, ActorKind, AthenaConfig, AuditLog, Column, ConnectionConfig,
    Driver, DriverFactory, Engine, ExecuteRequest, Outcome, Registry, Row, RowSink, Status,
};
use serde_json::{json, Value as Json};
use wiremock::matchers::{header, method};
use wiremock::{Mock, MockServer, Request, Respond, ResponseTemplate};

use super::{AthenaDriver, AthenaSettings, Backoff};

// ---------------------------------------------------------------------------
// The recordings
// ---------------------------------------------------------------------------

/// `GetQueryExecution`, in one state.
fn execution(
    state: &str,
    scanned: Option<i64>,
    engine_ms: Option<i64>,
    reason: Option<&str>,
) -> Json {
    let mut status = json!({ "State": state });
    if let Some(reason) = reason {
        status["StateChangeReason"] = json!(reason);
    }
    let mut statistics = json!({});
    if let Some(scanned) = scanned {
        statistics["DataScannedInBytes"] = json!(scanned);
    }
    if let Some(ms) = engine_ms {
        statistics["EngineExecutionTimeInMillis"] = json!(ms);
    }
    json!({
        "QueryExecution": {
            "QueryExecutionId": "q-1",
            "Status": status,
            "Statistics": statistics,
        }
    })
}

/// One `ResultSet` page: the metadata, the header row Athena prepends to a `SELECT`, and
/// the rows.
fn results(columns: &[(&str, &str)], rows: &[Vec<Option<&str>>], header_row: bool) -> Json {
    let column_info: Vec<Json> = columns
        .iter()
        .map(|(name, ty)| {
            json!({
                "CatalogName": "awsdatacatalog",
                "SchemaName": "",
                "TableName": "",
                "Name": name,
                "Label": name,
                "Type": ty,
                "Precision": 0,
                "Scale": 0,
                "Nullable": "UNKNOWN",
                "CaseSensitive": false,
            })
        })
        .collect();

    let mut out = Vec::new();
    if header_row {
        out.push(json!({
            "Data": columns
                .iter()
                .map(|(name, _)| json!({ "VarCharValue": name }))
                .collect::<Vec<_>>()
        }));
    }
    for row in rows {
        out.push(json!({
            "Data": row
                .iter()
                .map(|cell| match cell {
                    // A NULL is a datum with no `VarCharValue` at all.
                    None => json!({}),
                    Some(text) => json!({ "VarCharValue": text }),
                })
                .collect::<Vec<_>>()
        }));
    }

    json!({
        "ResultSet": {
            "ResultSetMetadata": { "ColumnInfo": column_info },
            "Rows": out,
        }
    })
}

// ---------------------------------------------------------------------------
// The fixture server
// ---------------------------------------------------------------------------

/// Answers one Athena operation, in order, from a script of recorded responses.
struct Script {
    responses: Vec<Json>,
    calls: Arc<AtomicUsize>,
}

impl Respond for Script {
    fn respond(&self, _: &Request) -> ResponseTemplate {
        let n = self.calls.fetch_add(1, Ordering::SeqCst);
        // Past the end of the script, the last recording repeats. A test that polls
        // three times and recorded two answers is testing the backoff, not the server.
        let body = self
            .responses
            .get(n)
            .or_else(|| self.responses.last())
            .cloned()
            .unwrap_or_else(|| json!({}));
        ResponseTemplate::new(200).set_body_json(body)
    }
}

/// A recorded Athena, and the counters that say what the driver asked it.
struct Recording {
    server: MockServer,
    started: Arc<AtomicUsize>,
    polled: Arc<AtomicUsize>,
    fetched: Arc<AtomicUsize>,
    stopped: Arc<AtomicUsize>,
}

impl Recording {
    /// Mount one operation, matched the way the AWS JSON 1.1 protocol identifies them:
    /// by the `X-Amz-Target` header.
    async fn mount(&self, operation: &str, responses: Vec<Json>, calls: Arc<AtomicUsize>) {
        Mock::given(method("POST"))
            .and(header(
                "x-amz-target",
                format!("AmazonAthena.{operation}").as_str(),
            ))
            .respond_with(Script { responses, calls })
            .mount(&self.server)
            .await;
    }

    async fn new() -> Self {
        Recording {
            server: MockServer::start().await,
            started: Arc::new(AtomicUsize::new(0)),
            polled: Arc::new(AtomicUsize::new(0)),
            fetched: Arc::new(AtomicUsize::new(0)),
            stopped: Arc::new(AtomicUsize::new(0)),
        }
    }

    /// The client the driver runs against: the recording's address, static credentials,
    /// and a plain-HTTP connector because a fixture server has no certificate.
    fn client(&self) -> Client {
        let http = aws_smithy_http_client::Builder::new().build_http();
        let config = aws_sdk_athena::Config::builder()
            .behavior_version(BehaviorVersion::latest())
            .region(Region::new("eu-west-1"))
            .credentials_provider(Credentials::new("ak", "sk", None, None, "fixtures"))
            .endpoint_url(self.server.uri())
            .http_client(http)
            .build();
        Client::from_conf(config)
    }

    fn driver(&self) -> AthenaDriver {
        AthenaDriver::with_client(
            self.client(),
            AthenaSettings {
                connection: "lake".to_string(),
                workgroup: "quokka".to_string(),
                output_location: Some("s3://bucket/results/".to_string()),
                database: Some("analytics".to_string()),
                catalog: "AwsDataCatalog".to_string(),
                profile: Some("analytics".to_string()),
                // Tests should not spend five seconds proving a backoff that has its own
                // unit test.
                poll: Backoff {
                    first: std::time::Duration::from_millis(1),
                    max: std::time::Duration::from_millis(4),
                    factor: 2,
                },
            },
        )
    }
}

/// Hands `quokka-core` the fixture-backed driver, since `Driver::connect` would go to
/// AWS for credentials and there are none here.
struct RecordedFactory(std::sync::Mutex<Option<AthenaDriver>>);

#[async_trait]
impl DriverFactory for RecordedFactory {
    fn name(&self) -> &'static str {
        "athena"
    }
    fn dialect(&self) -> quokka_core::Dialect {
        quokka_core::Dialect::Athena
    }
    async fn open(
        &self,
        _cfg: &ConnectionConfig,
    ) -> Result<Arc<dyn Driver>, quokka_core::DriverError> {
        let driver = self
            .0
            .lock()
            .expect("factory poisoned")
            .take()
            .expect("the engine opens a connection once");
        Ok(Arc::new(driver))
    }
}

#[derive(Default)]
struct Collect {
    columns: Vec<Column>,
    rows: Vec<Row>,
}

impl RowSink for Collect {
    fn begin(&mut self, columns: &[Column]) -> std::io::Result<()> {
        self.columns = columns.to_vec();
        Ok(())
    }
    fn row(&mut self, row: &Row) -> std::io::Result<()> {
        self.rows.push(row.clone());
        Ok(())
    }
    fn end(&mut self, _outcome: &Outcome) -> std::io::Result<()> {
        Ok(())
    }
}

struct Harness {
    engine: Arc<Engine>,
    _dir: tempfile::TempDir,
}

async fn harness(driver: AthenaDriver) -> Harness {
    let dir = tempfile::tempdir().expect("tempdir");
    let audit_db = dir.path().join("audit.db");
    let audit = AuditLog::open(&audit_db).await.expect("audit log");

    let mut registry = Registry::builtin_only(&audit_db);
    registry.insert(ConnectionConfig {
        mode: AccessMode::ReadOnly,
        database: Some("analytics".to_string()),
        credential: quokka_core::CredentialRef::None,
        athena: Some(AthenaConfig {
            region: "eu-west-1".to_string(),
            profile: Some("analytics".to_string()),
            workgroup: "quokka".to_string(),
            output_location: Some("s3://bucket/results/".to_string()),
            catalog: quokka_core::DEFAULT_ATHENA_CATALOG.to_string(),
        }),
        ..ConnectionConfig::new("lake", "athena")
    });

    Harness {
        engine: Arc::new(Engine::new(
            registry,
            audit,
            vec![Arc::new(RecordedFactory(std::sync::Mutex::new(Some(
                driver,
            ))))],
        )),
        _dir: dir,
    }
}

impl Harness {
    async fn run(&self, sql: &str) -> (Result<Outcome, quokka_core::CoreError>, Collect) {
        let mut sink = Collect::default();
        let request = ExecuteRequest::new(
            "lake",
            sql,
            Actor {
                kind: ActorKind::Human,
                id: "tester".to_string(),
            },
        );
        let outcome = execute(&self.engine, request, &mut sink).await;
        (outcome, sink)
    }

    async fn events(&self) -> Vec<quokka_audit::StoredEvent> {
        self.engine.audit().read_all().await.expect("read the log")
    }
}

// ---------------------------------------------------------------------------
// The tests
// ---------------------------------------------------------------------------

/// The whole of §3.2's happy path: submit, poll, page, type from `ResultSetMetadata`.
#[tokio::test(flavor = "multi_thread")]
async fn a_result_set_is_typed_from_its_metadata() {
    let recording = Recording::new().await;
    recording
        .mount(
            "StartQueryExecution",
            vec![json!({ "QueryExecutionId": "q-1" })],
            recording.started.clone(),
        )
        .await;
    recording
        .mount(
            "GetQueryExecution",
            vec![
                execution("QUEUED", None, None, None),
                execution("RUNNING", None, None, None),
                execution("SUCCEEDED", Some(1_234_567), Some(890), None),
            ],
            recording.polled.clone(),
        )
        .await;
    recording
        .mount(
            "GetQueryResults",
            vec![results(
                &[("id", "integer"), ("total", "double"), ("note", "varchar")],
                &[
                    vec![Some("1"), Some("2.5"), Some("first")],
                    vec![Some("2"), Some("0.0"), None],
                ],
                true,
            )],
            recording.fetched.clone(),
        )
        .await;

    let h = harness(recording.driver()).await;
    let (outcome, collected) = h.run("SELECT id, total, note FROM orders").await;
    let outcome = outcome.expect("the query should run");

    assert_eq!(outcome.status, Status::Ok);
    assert_eq!(
        collected
            .columns
            .iter()
            .map(|c| c.name.as_str())
            .collect::<Vec<_>>(),
        vec!["id", "total", "note"]
    );
    assert_eq!(
        collected
            .columns
            .iter()
            .map(|c| c.driver_type.as_str())
            .collect::<Vec<_>>(),
        vec!["integer", "double", "varchar"],
        "the driver's own type names are kept verbatim (invariant 10)"
    );

    assert_eq!(
        collected.rows.len(),
        2,
        "Athena's header row is not a row of the result"
    );
    assert_eq!(collected.rows[0].0[0], quokka_core::Value::Int(1));
    assert_eq!(collected.rows[0].0[1], quokka_core::Value::Float(2.5));
    assert_eq!(
        collected.rows[1].0[2],
        quokka_core::Value::Null,
        "a datum with no VarCharValue is a NULL"
    );

    // Polling really did back off rather than asking once and giving up.
    assert!(recording.polled.load(Ordering::SeqCst) >= 3);
    assert_eq!(recording.started.load(Ordering::SeqCst), 1);
}

/// Invariant 10, end to end and where it actually bites: a type this build has never
/// heard of, and a value that does not fit the type it was declared with. Neither may
/// abort the result set.
#[tokio::test(flavor = "multi_thread")]
async fn an_unrecognized_type_degrades_to_text_without_aborting_the_result() {
    let recording = Recording::new().await;
    recording
        .mount(
            "StartQueryExecution",
            vec![json!({ "QueryExecutionId": "q-1" })],
            recording.started.clone(),
        )
        .await;
    recording
        .mount(
            "GetQueryExecution",
            vec![execution("SUCCEEDED", Some(10), Some(1), None)],
            recording.polled.clone(),
        )
        .await;
    recording
        .mount(
            "GetQueryResults",
            vec![results(
                &[
                    ("here", "geometry"),
                    ("who", "ipaddress"),
                    ("n", "integer"),
                    ("exact", "decimal(38,2)"),
                ],
                &[
                    vec![
                        Some("POINT (1 2)"),
                        Some("10.0.0.1"),
                        // An integer column holding something no i64 can be.
                        Some("99999999999999999999999"),
                        Some("1.25"),
                    ],
                    vec![Some("POLYGON EMPTY"), None, Some("7"), Some("0.10")],
                ],
                true,
            )],
            recording.fetched.clone(),
        )
        .await;

    let h = harness(recording.driver()).await;
    let (outcome, collected) = h.run("SELECT here, who, n, exact FROM places").await;
    let outcome = outcome.expect("an unknown type must not fail the query");

    assert_eq!(outcome.status, Status::Ok);
    assert_eq!(collected.rows.len(), 2, "both rows survived");
    assert_eq!(
        collected.rows[0].0[0],
        quokka_core::Value::Text("POINT (1 2)".to_string())
    );
    assert_eq!(
        collected.rows[0].0[2],
        quokka_core::Value::Text("99999999999999999999999".to_string()),
        "a value that does not fit its declared type is a string, not an error"
    );
    assert_eq!(
        collected.rows[0].0[3],
        quokka_core::Value::Text("1.25".to_string()),
        "an exact numeric stays exact, which means text"
    );
    assert_eq!(
        collected.columns[0].driver_type, "geometry",
        "the type name survives even though nothing here understands it"
    );
}

/// A result spread over three `GetQueryResults` pages arrives as one result, and the
/// header row is dropped from the first page only.
#[tokio::test(flavor = "multi_thread")]
async fn a_paged_result_is_one_result() {
    let recording = Recording::new().await;
    recording
        .mount(
            "StartQueryExecution",
            vec![json!({ "QueryExecutionId": "q-1" })],
            recording.started.clone(),
        )
        .await;
    recording
        .mount(
            "GetQueryExecution",
            vec![execution("SUCCEEDED", Some(2_000), Some(5), None)],
            recording.polled.clone(),
        )
        .await;

    let mut page_one = results(
        &[("id", "integer")],
        &[vec![Some("1")], vec![Some("2")]],
        true,
    );
    page_one["NextToken"] = json!("page-2");
    let mut page_two = results(&[("id", "integer")], &[vec![Some("3")]], false);
    page_two["NextToken"] = json!("page-3");
    // The last page carries no token, which is how paging ends.
    let page_three = results(&[("id", "integer")], &[vec![Some("4")]], false);

    recording
        .mount(
            "GetQueryResults",
            vec![page_one, page_two, page_three],
            recording.fetched.clone(),
        )
        .await;

    let h = harness(recording.driver()).await;
    let (outcome, collected) = h.run("SELECT id FROM orders").await;
    outcome.expect("the query should run");

    assert_eq!(
        collected
            .rows
            .iter()
            .map(|r| r.0[0].clone())
            .collect::<Vec<_>>(),
        vec![
            quokka_core::Value::Int(1),
            quokka_core::Value::Int(2),
            quokka_core::Value::Int(3),
            quokka_core::Value::Int(4),
        ],
        "every page's rows, and the header row from none of them"
    );
    assert_eq!(recording.fetched.load(Ordering::SeqCst), 3);
}

/// **The cost wire, end to end.** What the driver reported reaches `query_finished`, and
/// `cost_estimate_usd` stays NULL beside it.
#[tokio::test(flavor = "multi_thread")]
async fn bytes_scanned_reach_the_audit_log() {
    let recording = Recording::new().await;
    recording
        .mount(
            "StartQueryExecution",
            vec![json!({ "QueryExecutionId": "q-1" })],
            recording.started.clone(),
        )
        .await;
    recording
        .mount(
            "GetQueryExecution",
            vec![execution(
                "SUCCEEDED",
                Some(3_221_225_472),
                Some(4_120),
                None,
            )],
            recording.polled.clone(),
        )
        .await;
    recording
        .mount(
            "GetQueryResults",
            vec![results(&[("n", "integer")], &[vec![Some("1")]], true)],
            recording.fetched.clone(),
        )
        .await;

    let h = harness(recording.driver()).await;
    let (outcome, _) = h.run("SELECT count(*) AS n FROM events").await;
    let outcome = outcome.expect("the query should run");

    assert_eq!(outcome.data_scanned_bytes, Some(3_221_225_472));
    assert_eq!(outcome.engine_time_ms, Some(4_120));

    let events = h.events().await;
    let started = events
        .iter()
        .find(|e| e.event.event_kind == quokka_audit::EventKind::QueryStarted)
        .expect("a start");
    let finished = events
        .iter()
        .find(|e| e.event.event_kind == quokka_audit::EventKind::QueryFinished)
        .expect("a finish");

    assert_eq!(
        started.event.data_scanned_bytes, None,
        "nothing has been scanned when the start is written"
    );
    assert_eq!(finished.event.data_scanned_bytes, Some(3_221_225_472));
    assert_eq!(
        finished.event.cost_estimate_usd, None,
        "the rate is the reader's, not ours — see the note in execute()"
    );

    assert!(
        h.engine.audit().verify().await.expect("verify").is_intact(),
        "the two fields are hashed, so filling them must not break the chain"
    );
}

/// A query that failed still scanned what it scanned, and the bill does not care that
/// the rows never arrived.
#[tokio::test(flavor = "multi_thread")]
async fn a_failed_query_still_reports_what_it_scanned() {
    let recording = Recording::new().await;
    recording
        .mount(
            "StartQueryExecution",
            vec![json!({ "QueryExecutionId": "q-1" })],
            recording.started.clone(),
        )
        .await;
    recording
        .mount(
            "GetQueryExecution",
            vec![execution(
                "FAILED",
                Some(700_000),
                Some(90),
                Some("COLUMN_NOT_FOUND: line 1:8: Column 'nope' cannot be resolved"),
            )],
            recording.polled.clone(),
        )
        .await;

    let h = harness(recording.driver()).await;
    let (outcome, _) = h.run("SELECT nope FROM orders").await;
    let outcome = outcome.expect("a failed query is still a reported outcome");

    assert_eq!(outcome.status, Status::Error);
    assert!(
        outcome
            .error_message
            .as_deref()
            .unwrap_or_default()
            .contains("COLUMN_NOT_FOUND"),
        "Athena's own reason should survive: {:?}",
        outcome.error_message
    );
    assert_eq!(
        outcome.data_scanned_bytes,
        Some(700_000),
        "charging only for successes would leave an agent's worst hour invisible"
    );

    let events = h.events().await;
    let finished = events
        .iter()
        .find(|e| e.event.event_kind == quokka_audit::EventKind::QueryFinished)
        .expect("a finish");
    assert_eq!(finished.event.data_scanned_bytes, Some(700_000));
    assert_eq!(finished.event.status, Status::Error);
}

/// A driver that reports nothing leaves NULL — not 0. The distinction is the whole point
/// of the column: 0 is a real Athena answer (a cached result scans nothing).
#[tokio::test(flavor = "multi_thread")]
async fn a_query_that_scanned_nothing_is_not_a_query_that_reported_nothing() {
    let recording = Recording::new().await;
    recording
        .mount(
            "StartQueryExecution",
            vec![json!({ "QueryExecutionId": "q-1" })],
            recording.started.clone(),
        )
        .await;
    // `SUCCEEDED` with statistics that carry a zero, which is what a result-cache hit
    // looks like.
    recording
        .mount(
            "GetQueryExecution",
            vec![execution("SUCCEEDED", Some(0), Some(12), None)],
            recording.polled.clone(),
        )
        .await;
    recording
        .mount(
            "GetQueryResults",
            vec![results(&[("n", "integer")], &[vec![Some("1")]], true)],
            recording.fetched.clone(),
        )
        .await;

    let h = harness(recording.driver()).await;
    let (outcome, _) = h.run("SELECT count(*) AS n FROM events").await;
    let outcome = outcome.expect("the query should run");

    assert_eq!(
        outcome.data_scanned_bytes,
        Some(0),
        "zero is an answer: this query was free, and the log should say so"
    );

    let events = h.events().await;
    let finished = events
        .iter()
        .find(|e| e.event.event_kind == quokka_audit::EventKind::QueryFinished)
        .expect("a finish");
    assert_eq!(finished.event.data_scanned_bytes, Some(0));
}

/// **The cancel really calls `StopQueryExecution`.**
///
/// §3.2's step 4, and the trap M5 names: the polling loop is where a cancel goes to die.
/// Dropping the future would leave the execution running and billing, so the flag has to
/// break the loop *and* the driver has to make the call.
#[tokio::test(flavor = "multi_thread")]
async fn a_cancel_stops_the_execution_rather_than_dropping_a_future() {
    let recording = Recording::new().await;
    recording
        .mount(
            "StartQueryExecution",
            vec![json!({ "QueryExecutionId": "q-1" })],
            recording.started.clone(),
        )
        .await;
    // Never finishes. The only way out of this loop is the cancel.
    recording
        .mount(
            "GetQueryExecution",
            vec![execution("RUNNING", Some(500), None, None)],
            recording.polled.clone(),
        )
        .await;
    recording
        .mount(
            "StopQueryExecution",
            vec![json!({})],
            recording.stopped.clone(),
        )
        .await;

    let h = harness(recording.driver()).await;
    let engine = h.engine.clone();

    // Cancel once the query is demonstrably in flight — polling, not merely submitted.
    let polled = recording.polled.clone();
    let canceller = tokio::spawn(async move {
        for _ in 0..500 {
            if polled.load(Ordering::SeqCst) >= 2 {
                break;
            }
            tokio::time::sleep(std::time::Duration::from_millis(5)).await;
        }
        engine.cancel_all().await;
    });

    let (outcome, _) = h.run("SELECT * FROM the_whole_lake").await;
    canceller.await.expect("the canceller should not panic");
    let outcome = outcome.expect("a cancelled query is a reported outcome");

    assert_eq!(outcome.status, Status::Cancelled);
    assert!(
        recording.stopped.load(Ordering::SeqCst) >= 1,
        "the cancel must reach StopQueryExecution: on Athena that is what stops the bill"
    );

    // And it is a fully logged query, not a start with no finish.
    let events = h.events().await;
    assert_eq!(events.len(), 2);
    assert_eq!(events[1].event.status, Status::Cancelled);
    assert_eq!(
        events[1].event.data_scanned_bytes,
        Some(500),
        "what a cancelled scan had already read is still what it cost"
    );
}

/// What `StartQueryExecution` is actually sent: the configured workgroup and output
/// location, never an inherited default (§6.4's layer 1 lives in the workgroup).
#[tokio::test(flavor = "multi_thread")]
async fn the_configured_workgroup_and_output_location_are_sent() {
    let recording = Recording::new().await;
    let bodies = Arc::new(std::sync::Mutex::new(Vec::<Json>::new()));
    let captured = bodies.clone();

    Mock::given(method("POST"))
        .and(header("x-amz-target", "AmazonAthena.StartQueryExecution"))
        .respond_with(move |req: &Request| {
            captured
                .lock()
                .expect("captured poisoned")
                .push(serde_json::from_slice(&req.body).unwrap_or(Json::Null));
            ResponseTemplate::new(200).set_body_json(json!({ "QueryExecutionId": "q-1" }))
        })
        .mount(&recording.server)
        .await;
    recording
        .mount(
            "GetQueryExecution",
            vec![execution("SUCCEEDED", Some(1), Some(1), None)],
            recording.polled.clone(),
        )
        .await;
    recording
        .mount(
            "GetQueryResults",
            vec![results(&[("n", "integer")], &[vec![Some("1")]], true)],
            recording.fetched.clone(),
        )
        .await;

    let h = harness(recording.driver()).await;
    h.run("SELECT 1 AS n")
        .await
        .0
        .expect("the query should run");

    let bodies = bodies.lock().expect("captured poisoned");
    let body = bodies.first().expect("a StartQueryExecution body");
    assert_eq!(body["WorkGroup"], "quokka");
    assert_eq!(
        body["ResultConfiguration"]["OutputLocation"],
        "s3://bucket/results/"
    );
    assert_eq!(body["QueryExecutionContext"]["Database"], "analytics");
    assert_eq!(body["QueryExecutionContext"]["Catalog"], "AwsDataCatalog");
    assert_eq!(body["QueryString"], "SELECT 1 AS n");
}

/// Athena has no typed parameter binding, and this driver says so rather than
/// substituting text on the caller's behalf.
#[tokio::test(flavor = "multi_thread")]
async fn bound_parameters_are_refused_with_a_reason() {
    let recording = Recording::new().await;
    recording
        .mount(
            "StartQueryExecution",
            vec![json!({ "QueryExecutionId": "q-1" })],
            recording.started.clone(),
        )
        .await;

    let h = harness(recording.driver()).await;
    let mut sink = Collect::default();
    let mut request = ExecuteRequest::new(
        "lake",
        "SELECT * FROM orders WHERE id = ?",
        Actor {
            kind: ActorKind::Agent,
            id: "claude".to_string(),
        },
    );
    request.params = vec![quokka_core::Value::Int(7)];

    let outcome = execute(&h.engine, request, &mut sink)
        .await
        .expect("a refusal by the driver is still a reported outcome");
    assert_eq!(outcome.status, Status::Error);
    assert!(
        outcome
            .error_message
            .as_deref()
            .unwrap_or_default()
            .contains("ExecutionParameters"),
        "the message should say what Athena does have and why it is not binding: {:?}",
        outcome.error_message
    );
    assert_eq!(
        recording.started.load(Ordering::SeqCst),
        0,
        "nothing should have been submitted"
    );
}

/// **An auth failure is a sentence, not a protocol dump.**
///
/// The raw SDK rendering of this is a hundred lines of nested `Debug` — request id,
/// headers, raw body, retry classification — which is a protocol error in exactly the
/// sense §3.2 says an expired token must not be. It can arrive here rather than at
/// connect time: credentials that resolved may still be rejected, and a token that was
/// valid when the connection opened may expire during a long session.
#[tokio::test(flavor = "multi_thread")]
async fn a_rejected_token_mid_query_still_says_run_aws_sso_login() {
    let recording = Recording::new().await;
    Mock::given(method("POST"))
        .and(header("x-amz-target", "AmazonAthena.StartQueryExecution"))
        .respond_with(ResponseTemplate::new(400).set_body_json(json!({
            "__type": "UnrecognizedClientException",
            "message": "The security token included in the request is invalid.",
        })))
        .mount(&recording.server)
        .await;

    let h = harness(recording.driver()).await;
    let (outcome, _) = h.run("SELECT 1").await;
    let outcome = outcome.expect("a rejected token is a reported outcome");
    let message = outcome.error_message.unwrap_or_default();

    assert!(
        message.contains("aws sso login --profile analytics"),
        "an auth failure must name the command that fixes it, wherever it arrives: {message}"
    );
    assert!(
        message.contains("UnrecognizedClientException"),
        "and still say what AWS actually called it: {message}"
    );
    assert!(
        !message.contains("SdkBody") && !message.contains("ErrorMetadata"),
        "the raw SDK rendering is the thing this test exists to keep out: {message}"
    );
    assert!(
        message.len() < 700,
        "a person has to be able to read it ({} chars): {message}",
        message.len()
    );
}

/// An error that is not about credentials is reported as whatever Athena called it, and
/// gets no misleading advice about signing in.
#[tokio::test(flavor = "multi_thread")]
async fn an_ordinary_service_error_is_short_and_says_what_athena_said() {
    let recording = Recording::new().await;
    Mock::given(method("POST"))
        .and(header("x-amz-target", "AmazonAthena.StartQueryExecution"))
        .respond_with(ResponseTemplate::new(400).set_body_json(json!({
            "__type": "InvalidRequestException",
            "message": "line 1:8: Column 'nope' cannot be resolved",
        })))
        .mount(&recording.server)
        .await;

    let h = harness(recording.driver()).await;
    let (outcome, _) = h.run("SELECT nope").await;
    let message = outcome
        .expect("a reported outcome")
        .error_message
        .unwrap_or_default();

    assert!(message.contains("InvalidRequestException"), "{message}");
    assert!(message.contains("cannot be resolved"), "{message}");
    assert!(
        !message.contains("aws sso login"),
        "a query error is not a credentials problem: {message}"
    );
    assert!(
        message.contains("quokka"),
        "the workgroup is context: {message}"
    );
}
