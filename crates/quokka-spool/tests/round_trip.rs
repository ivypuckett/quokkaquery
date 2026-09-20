//! CLAUDE.md's third testing priority: every `Value` that goes into a spool comes back
//! out equal, and every export format reproduces the spool exactly.
//!
//! This is where a silent type conversion would hide, so the corpus is deliberately
//! nasty: the values SQLite has no storage class for, the ones an affinity would coerce,
//! and a randomized sweep over the whole vocabulary on a fixed seed so that a
//! regression is reproducible rather than a story about a flaky test.

mod support;

use quokka_core::{Column, Row, RowSink, Value};
use quokka_spool::{same_value, Destination, Format, Position, Spool, View};
use support::{finish, spool_writer};

/// The cases a `Value` round-trip has to survive, each with the reason it is here.
fn corpus() -> Vec<Value> {
    vec![
        Value::Null,
        // SQLite has no boolean storage class, so both of these would come back as
        // `Int` without the codec's escape.
        Value::Bool(true),
        Value::Bool(false),
        Value::Int(0),
        Value::Int(-1),
        Value::Int(i64::MIN),
        Value::Int(i64::MAX),
        Value::Float(0.0),
        Value::Float(-0.0),
        Value::Float(1.5),
        Value::Float(f64::MIN),
        Value::Float(f64::MAX),
        Value::Float(f64::EPSILON),
        // SQLite stores NaN as NULL. Without the escape this row would come back a
        // NULL, which is not a rounding error but a different value.
        Value::Float(f64::NAN),
        Value::Float(f64::INFINITY),
        Value::Float(f64::NEG_INFINITY),
        Value::Text(String::new()),
        Value::Text("ordinary".into()),
        // An exact numeric, which Postgres and MySQL deliberately hand over as text
        // because an f64 is not exact. A column with any numeric affinity would turn
        // this into a REAL and lose the last digits; the spool's typeless columns must
        // not.
        Value::Text("12345678901234567890.00000000001".into()),
        Value::Text("-0.1000000000000000000000001".into()),
        // Looks like an integer, is a string. Same trap, one digit long.
        Value::Text("42".into()),
        Value::Text("0x1f".into()),
        Value::Text("2026-09-20T10:11:12.123456+02:00".into()),
        Value::Text("emoji 🦘 and a snowman ☃".into()),
        Value::Text("tab\tnewline\nquote\"backslash\\".into()),
        Value::Text("embedded\0nul".into()),
        Value::Blob(Vec::new()),
        Value::Blob(vec![0]),
        Value::Blob(vec![0, 1, 2, 3, 0xff]),
        // The first byte of a blob is what the codec tags, so a blob starting with each
        // tag value is the case that would break a naive tagging scheme.
        Value::Blob(vec![0x00, 0xde, 0xad]),
        Value::Blob(vec![0x01]),
        Value::Blob(vec![0x02, 0xbe, 0xef]),
        Value::Blob(vec![0x03]),
        Value::Blob((0..=255u8).collect()),
    ]
}

/// A deterministic value generator: property testing without a dependency, and with a
/// seed a failure can be reproduced from.
struct Rng(u64);

impl Rng {
    fn next(&mut self) -> u64 {
        // xorshift64*. Good enough to wander the value space, short enough to read.
        let mut x = self.0;
        x ^= x >> 12;
        x ^= x << 25;
        x ^= x >> 27;
        self.0 = x;
        x.wrapping_mul(0x2545_F491_4F6C_DD1D)
    }

    fn value(&mut self) -> Value {
        match self.next() % 6 {
            0 => Value::Null,
            1 => Value::Bool(self.next().is_multiple_of(2)),
            2 => Value::Int(self.next() as i64),
            3 => match self.next() % 8 {
                0 => Value::Float(f64::NAN),
                1 => Value::Float(f64::INFINITY),
                2 => Value::Float(f64::NEG_INFINITY),
                _ => Value::Float(f64::from_bits(self.next())),
            },
            4 => {
                let len = (self.next() % 24) as usize;
                Value::Text(
                    (0..len)
                        .map(|_| char::from_u32((self.next() % 0x2000) as u32).unwrap_or('?'))
                        .collect(),
                )
            }
            _ => {
                let len = (self.next() % 24) as usize;
                Value::Blob((0..len).map(|_| self.next() as u8).collect())
            }
        }
    }
}

fn columns(n: usize) -> Vec<Column> {
    (0..n)
        .map(|i| Column {
            name: format!("c{i}"),
            // A driver type the spool must carry across unchanged — SQLite has no
            // `numeric`, so only the sidecar can hold it.
            driver_type: if i == 0 { "numeric" } else { "text" }.to_string(),
            nullable: Some(i % 2 == 0),
        })
        .collect()
}

async fn round_trip(rows: Vec<Row>) -> (Vec<Row>, tempfile::TempDir) {
    let width = rows.first().map(|r| r.len()).unwrap_or(1);
    let (dir, mut writer, path) = spool_writer(Default::default());
    let cols = columns(width);
    writer.begin(&cols).expect("begin");
    for row in &rows {
        writer.row(row).expect("row");
    }
    finish(&mut writer, rows.len() as u64, false);

    let spool = Spool::open(&path).await.expect("open");
    let mut out = Vec::new();
    let mut at = Position::start();
    loop {
        let page = spool
            .page(&View::arrival_order(), at, 64)
            .await
            .expect("page");
        out.extend(page.rows);
        match page.next {
            Some(next) => at = next,
            None => break,
        }
    }
    (out, dir)
}

#[tokio::test]
async fn every_value_in_the_corpus_comes_back_equal() {
    // One row per value, so a failure names the value rather than a row of thirty.
    let corpus = corpus();
    let rows: Vec<Row> = corpus.iter().map(|v| Row(vec![v.clone()])).collect();
    let (back, _dir) = round_trip(rows).await;

    assert_eq!(back.len(), corpus.len());
    for (original, returned) in corpus.iter().zip(&back) {
        let got = &returned.0[0];
        assert!(
            same_value(original, got),
            "{original:?} came back as {got:?}"
        );
        assert_eq!(
            original.type_name(),
            got.type_name(),
            "{original:?} came back as a {} ({got:?})",
            got.type_name()
        );
    }
}

#[tokio::test]
async fn a_thousand_random_rows_come_back_equal() {
    let mut rng = Rng(0x5eed_1234_abcd_ef01);
    let rows: Vec<Row> = (0..1000)
        .map(|_| Row((0..5).map(|_| rng.value()).collect()))
        .collect();

    let (back, _dir) = round_trip(rows.clone()).await;

    assert_eq!(back.len(), rows.len());
    for (i, (original, returned)) in rows.iter().zip(&back).enumerate() {
        for (j, (a, b)) in original.0.iter().zip(&returned.0).enumerate() {
            assert!(
                same_value(a, b),
                "row {i} column {j}: {a:?} came back as {b:?}"
            );
        }
    }
}

/// Pins what SQLite actually does with the two values the codec has to escape, so that
/// a bundled-SQLite upgrade which changed any of it fails here — beside the comment
/// explaining the escape — rather than silently in somebody's result.
#[tokio::test]
async fn sqlite_itself_still_behaves_the_way_the_codec_assumes() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("raw.db");
    let pool = sqlx::SqlitePool::connect_with(
        sqlx::sqlite::SqliteConnectOptions::new()
            .filename(&path)
            .create_if_missing(true),
    )
    .await
    .unwrap();
    sqlx::raw_sql("CREATE TABLE t (v)")
        .execute(&pool)
        .await
        .unwrap();

    let typeof_after = |value: f64| {
        let pool = pool.clone();
        async move {
            sqlx::query("INSERT INTO t (v) VALUES (?)")
                .bind(value)
                .execute(&pool)
                .await
                .unwrap();
            let row: (String,) =
                sqlx::query_as("SELECT typeof(v) FROM t ORDER BY rowid DESC LIMIT 1")
                    .fetch_one(&pool)
                    .await
                    .unwrap();
            row.0
        }
    };

    // The reason `Value::Float(NaN)` is written as a tagged blob.
    assert_eq!(typeof_after(f64::NAN).await, "null");
    // And the reason the infinities are not: they store as REAL and come back as
    // themselves. The codec does not lean on this, but the assumption should be
    // visible rather than folded into a comment nobody rechecks.
    assert_eq!(typeof_after(f64::INFINITY).await, "real");
    assert_eq!(typeof_after(f64::NEG_INFINITY).await, "real");

    // And the reason a `Value::Bool` is written as a tagged blob: SQLite has no
    // boolean, so the storage class it lands in is indistinguishable from an integer.
    sqlx::query("INSERT INTO t (v) VALUES (?)")
        .bind(true)
        .execute(&pool)
        .await
        .unwrap();
    let row: (String,) = sqlx::query_as("SELECT typeof(v) FROM t ORDER BY rowid DESC LIMIT 1")
        .fetch_one(&pool)
        .await
        .unwrap();
    assert_eq!(row.0, "integer");
}

#[tokio::test]
async fn the_driver_s_own_type_names_survive() {
    let (dir, mut writer, path) = spool_writer(Default::default());
    let cols = vec![
        Column {
            name: "amount".into(),
            driver_type: "numeric(38,10)".into(),
            nullable: Some(false),
        },
        Column {
            name: "tags".into(),
            driver_type: "hstore".into(),
            nullable: Some(true),
        },
    ];
    writer.begin(&cols).unwrap();
    writer
        .row(&Row(vec![Value::Text("1.0000000001".into()), Value::Null]))
        .unwrap();
    finish(&mut writer, 1, false);

    let spool = Spool::open(&path).await.unwrap();
    assert_eq!(spool.columns(), cols.as_slice());
    drop(dir);
}

/// Every export format reproduces the spool exactly.
#[tokio::test]
async fn every_export_format_reproduces_the_spool() {
    let corpus = corpus();
    let (dir, mut writer, path) = spool_writer(Default::default());
    let cols = columns(1);
    writer.begin(&cols).unwrap();
    for value in &corpus {
        writer.row(&Row(vec![value.clone()])).unwrap();
    }
    finish(&mut writer, corpus.len() as u64, false);

    let spool = Spool::open(&path).await.unwrap();
    let view = View::arrival_order();

    // NDJSON: one object per row, in arrival order, each holding the same JSON the
    // `--format json` preview would have shown.
    let ndjson = dir.path().join("out.ndjson");
    let report = quokka_spool::export(
        &spool,
        &Destination::Path(ndjson.clone()),
        Format::Ndjson,
        &view,
    )
    .await
    .unwrap();
    assert_eq!(report.rows, corpus.len() as u64);
    let text = std::fs::read_to_string(&ndjson).unwrap();
    let lines: Vec<&str> = text.lines().collect();
    assert_eq!(lines.len(), corpus.len());
    for (value, line) in corpus.iter().zip(&lines) {
        let parsed: serde_json::Value = serde_json::from_str(line).unwrap();
        let expected = serde_json::to_value(value).unwrap();
        assert_eq!(parsed["c0"], expected, "ndjson disagreed about {value:?}");
    }

    // JSON: the same objects, as one array.
    let json = dir.path().join("out.json");
    quokka_spool::export(
        &spool,
        &Destination::Path(json.clone()),
        Format::Json,
        &view,
    )
    .await
    .unwrap();
    let parsed: serde_json::Value =
        serde_json::from_str(&std::fs::read_to_string(&json).unwrap()).unwrap();
    let array = parsed.as_array().expect("a JSON array");
    assert_eq!(array.len(), corpus.len());
    for (value, object) in corpus.iter().zip(array) {
        assert_eq!(object["c0"], serde_json::to_value(value).unwrap());
    }

    // CSV and TSV: the same text a cell would render as, quoted where the delimiter,
    // a quote or a newline would otherwise break the row apart.
    for (format, sep) in [(Format::Csv, ','), (Format::Tsv, '\t')] {
        let file = dir.path().join(format!("out.{format}"));
        quokka_spool::export(&spool, &Destination::Path(file.clone()), format, &view)
            .await
            .unwrap();
        let text = std::fs::read_to_string(&file).unwrap();
        let cells = parse_delimited(&text, sep);
        assert_eq!(cells[0], vec!["c0".to_string()], "{format} header");
        assert_eq!(cells.len(), corpus.len() + 1, "{format} row count");
        for (value, row) in corpus.iter().zip(&cells[1..]) {
            let expected = match value {
                Value::Null => String::new(),
                other => other.to_string(),
            };
            assert_eq!(row[0], expected, "{format} disagreed about {value:?}");
        }
    }

    spool.close().await;
}

#[cfg(feature = "parquet")]
#[tokio::test]
async fn parquet_carries_the_values_and_the_driver_s_types() {
    use arrow_array::{Array, Float64Array, Int64Array, StringArray};

    let (dir, mut writer, path) = spool_writer(Default::default());
    let cols = vec![
        Column {
            name: "n".into(),
            driver_type: "bigint".into(),
            nullable: Some(false),
        },
        Column {
            name: "x".into(),
            driver_type: "double precision".into(),
            nullable: Some(true),
        },
        Column {
            name: "exact".into(),
            driver_type: "numeric".into(),
            nullable: Some(true),
        },
    ];
    writer.begin(&cols).unwrap();
    let rows = vec![
        Row(vec![
            Value::Int(1),
            Value::Float(1.5),
            Value::Text("0.10000000000000000001".into()),
        ]),
        Row(vec![Value::Int(2), Value::Null, Value::Text("2".into())]),
    ];
    for row in &rows {
        writer.row(row).unwrap();
    }
    finish(&mut writer, rows.len() as u64, false);

    let spool = Spool::open(&path).await.unwrap();
    let file = dir.path().join("out.parquet");
    let report = quokka_spool::export(
        &spool,
        &Destination::Path(file.clone()),
        Format::Parquet,
        &View::arrival_order(),
    )
    .await
    .unwrap();
    assert_eq!(report.rows, 2);

    let reader = parquet::arrow::arrow_reader::ParquetRecordBatchReaderBuilder::try_new(
        std::fs::File::open(&file).unwrap(),
    )
    .unwrap();
    let schema = reader.schema().clone();
    // The exact numeric stayed a string, because an f64 is not exact — and the field
    // still says what it was on the server.
    assert_eq!(
        schema.field(2).metadata().get("quokka.driver_type"),
        Some(&"numeric".to_string())
    );
    assert_eq!(schema.field(2).data_type(), &arrow_schema::DataType::Utf8);

    let batches: Vec<_> = reader.build().unwrap().map(|b| b.unwrap()).collect();
    let batch = &batches[0];
    let ints = batch
        .column(0)
        .as_any()
        .downcast_ref::<Int64Array>()
        .unwrap();
    assert_eq!(ints.value(0), 1);
    assert_eq!(ints.value(1), 2);
    let floats = batch
        .column(1)
        .as_any()
        .downcast_ref::<Float64Array>()
        .unwrap();
    assert_eq!(floats.value(0), 1.5);
    assert!(floats.is_null(1));
    let exact = batch
        .column(2)
        .as_any()
        .downcast_ref::<StringArray>()
        .unwrap();
    assert_eq!(exact.value(0), "0.10000000000000000001");

    spool.close().await;
}

/// A delimited file back into cells, honouring RFC 4180 quoting.
fn parse_delimited(text: &str, sep: char) -> Vec<Vec<String>> {
    let mut rows = Vec::new();
    let mut row = Vec::new();
    let mut cell = String::new();
    let mut quoted = false;
    let mut chars = text.chars().peekable();

    while let Some(c) = chars.next() {
        match (quoted, c) {
            (true, '"') => {
                if chars.peek() == Some(&'"') {
                    chars.next();
                    cell.push('"');
                } else {
                    quoted = false;
                }
            }
            (true, c) => cell.push(c),
            (false, '"') if cell.is_empty() => quoted = true,
            (false, c) if c == sep => row.push(std::mem::take(&mut cell)),
            (false, '\n') => {
                row.push(std::mem::take(&mut cell));
                rows.push(std::mem::take(&mut row));
            }
            (false, '\r') => {}
            (false, c) => cell.push(c),
        }
    }
    if !cell.is_empty() || !row.is_empty() {
        row.push(cell);
        rows.push(row);
    }
    rows
}
