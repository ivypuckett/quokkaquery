//! The SQL corpus (CLAUDE.md's first testing priority, ARCHITECTURE §9).
//!
//! This is the security boundary, so a miss here is a hole rather than a bug. The corpus
//! is table-driven and deliberately full of the cases a naive implementation gets wrong:
//! writes hidden inside CTEs, statements stacked behind a `--` comment, semicolons
//! inside string literals, keywords used as column names, and each dialect's own
//! spelling of the same idea.
//!
//! Two properties are asserted separately, because they fail differently:
//!
//! - **Classification** — what the statement *is*. A wrong answer here is wrong in the
//!   audit log as well as at the guardrail.
//! - **Decision** — whether it may run. This is what an agent actually meets.

use quokka_policy::{summarize, AccessMode, Allowlist, Denial, Dialect, Outcome, Policy};

/// One corpus entry: what the classifier must say about a statement.
struct Case {
    sql: &'static str,
    dialect: Dialect,
    /// `None` when the text is not expected to parse.
    kind: Option<&'static str>,
    read_only: Option<bool>,
    statements: usize,
    /// Sorted, dotted, CTE names removed. `None` means "do not assert".
    tables: Option<&'static [&'static str]>,
}

const fn case(
    sql: &'static str,
    dialect: Dialect,
    kind: Option<&'static str>,
    read_only: Option<bool>,
    statements: usize,
    tables: Option<&'static [&'static str]>,
) -> Case {
    Case {
        sql,
        dialect,
        kind,
        read_only,
        statements,
        tables,
    }
}

const READS: &[Case] = &[
    case(
        "SELECT id FROM users WHERE email = 'a@b.example'",
        Dialect::Postgres,
        Some("select"),
        Some(true),
        1,
        Some(&["users"]),
    ),
    // A keyword-shaped column name is not a write. The naive implementation of this
    // check is a substring scan over the text, and this is the case that breaks it.
    case(
        "SELECT last_update, deleted_at, insert_count FROM audit",
        Dialect::Sqlite,
        Some("select"),
        Some(true),
        1,
        Some(&["audit"]),
    ),
    // Nor is a *string* that says DELETE.
    case(
        "SELECT * FROM t WHERE action = 'DELETE FROM users'",
        Dialect::Postgres,
        Some("select"),
        Some(true),
        1,
        Some(&["t"]),
    ),
    // A comment that says DELETE is gone before anything looks at it.
    case(
        "SELECT * FROM t -- DELETE FROM users\n",
        Dialect::Postgres,
        Some("select"),
        Some(true),
        1,
        Some(&["t"]),
    ),
    case(
        "/* DELETE FROM users */ SELECT 1",
        Dialect::MySql,
        Some("select"),
        Some(true),
        1,
        Some(&[]),
    ),
    // An ordinary CTE is not a table, so it must not appear in `tables` — an allowlist
    // that thought `recent` were a table would deny a legitimate query.
    case(
        "WITH recent AS (SELECT * FROM orders WHERE at > '2024-01-01') \
         SELECT count(*) FROM recent",
        Dialect::Postgres,
        Some("select"),
        Some(true),
        1,
        Some(&["orders"]),
    ),
    case(
        "SELECT * FROM public.orders o JOIN public.customers c ON c.id = o.customer_id",
        Dialect::Postgres,
        Some("select"),
        Some(true),
        1,
        Some(&["public.customers", "public.orders"]),
    ),
    case(
        "SELECT * FROM awsdatacatalog.sales.orders LIMIT 10",
        Dialect::Athena,
        Some("select"),
        Some(true),
        1,
        Some(&["awsdatacatalog.sales.orders"]),
    ),
    case(
        "SELECT * FROM `sales`.`orders`",
        Dialect::MySql,
        Some("select"),
        Some(true),
        1,
        Some(&["sales.orders"]),
    ),
    case(
        "SHOW TABLES",
        Dialect::MySql,
        Some("show"),
        Some(true),
        1,
        None,
    ),
    case(
        "SELECT a FROM t UNION ALL SELECT b FROM u",
        Dialect::Postgres,
        Some("select"),
        Some(true),
        1,
        Some(&["t", "u"]),
    ),
    // A trailing semicolon is punctuation, not a second statement.
    case(
        "SELECT 1;",
        Dialect::Sqlite,
        Some("select"),
        Some(true),
        1,
        Some(&[]),
    ),
];

const WRITES: &[Case] = &[
    case(
        "INSERT INTO t (a) VALUES (1)",
        Dialect::Sqlite,
        Some("insert"),
        Some(false),
        1,
        Some(&["t"]),
    ),
    case(
        "UPDATE t SET a = 1 WHERE id IN (SELECT id FROM staging)",
        Dialect::MySql,
        Some("update"),
        Some(false),
        1,
        Some(&["staging", "t"]),
    ),
    case(
        "DELETE FROM t",
        Dialect::Sqlite,
        Some("delete"),
        Some(false),
        1,
        Some(&["t"]),
    ),
    // DDL is a write, and its target is deliberately *not* asserted: sqlparser reports
    // no relation for a `DROP` and two for a `CREATE TABLE … AS SELECT`, which is why an
    // allowlist refuses DDL outright rather than trusting the list it gets.
    case(
        "DROP TABLE t",
        Dialect::Sqlite,
        Some("ddl"),
        Some(false),
        1,
        None,
    ),
    case(
        "CREATE TABLE x AS SELECT * FROM y",
        Dialect::Athena,
        Some("ddl"),
        Some(false),
        1,
        None,
    ),
    case(
        "GRANT SELECT ON t TO reader",
        Dialect::Postgres,
        Some("dcl"),
        Some(false),
        1,
        None,
    ),
    // The headline case §6.3 names: a statement that reads like a SELECT and deletes.
    case(
        "WITH moved AS (DELETE FROM archive RETURNING *) SELECT * FROM moved",
        Dialect::Postgres,
        Some("delete"),
        Some(false),
        1,
        Some(&["archive"]),
    ),
    case(
        "WITH added AS (INSERT INTO log (m) VALUES ('x') RETURNING id) \
         SELECT id FROM added",
        Dialect::Postgres,
        Some("insert"),
        Some(false),
        1,
        Some(&["log"]),
    ),
    // Two levels down, and behind a comment, and still a write.
    case(
        "WITH outer_q AS (\n  -- nothing to see\n  WITH inner_q AS (UPDATE t SET a = 1 \
         RETURNING *) SELECT * FROM inner_q\n) SELECT * FROM outer_q",
        Dialect::Postgres,
        Some("update"),
        Some(false),
        1,
        Some(&["t"]),
    ),
    case(
        "INSERT INTO a SELECT * FROM b",
        Dialect::Postgres,
        Some("insert"),
        Some(false),
        1,
        Some(&["a", "b"]),
    ),
];

/// Statements the classifier deliberately refuses to call reads, even though none of
/// them is obviously a write. `read_only = None` is the answer that makes the guardrail
/// hold: see the crate docs on why unknown and write are one case.
const UNCERTAIN: &[Case] = &[
    case("VACUUM", Dialect::Sqlite, Some("other"), None, 1, None),
    case(
        "COPY t FROM '/etc/passwd'",
        Dialect::Postgres,
        Some("other"),
        None,
        1,
        None,
    ),
    case(
        "UNLOAD (SELECT * FROM t) TO 's3://bucket/prefix'",
        Dialect::Athena,
        Some("other"),
        None,
        1,
        None,
    ),
    case(
        "SET search_path = public",
        Dialect::Postgres,
        Some("session"),
        None,
        1,
        None,
    ),
    case("BEGIN", Dialect::Sqlite, Some("session"), None, 1, None),
    // sqlparser's SQLite dialect does not read this one, so nothing below the parse is
    // known — and the answer is the same as for everything else it cannot read.
    case("PRAGMA table_info(t)", Dialect::Sqlite, None, None, 1, None),
    case("SELEKT 1 FROM t", Dialect::Sqlite, None, None, 1, None),
];

/// Stacked bodies, including the ones a naive splitter gets wrong.
const STACKED: &[Case] = &[
    case(
        "SELECT 1; DROP TABLE t",
        Dialect::Sqlite,
        Some("ddl"),
        Some(false),
        2,
        None,
    ),
    case(
        "SELECT 1; SELECT 2",
        Dialect::Sqlite,
        Some("select"),
        Some(true),
        2,
        None,
    ),
    case(
        "DELETE FROM a; DELETE FROM b;",
        Dialect::Postgres,
        Some("delete"),
        Some(false),
        2,
        Some(&["a", "b"]),
    ),
    case(
        "SELECT 1; VACUUM",
        Dialect::Sqlite,
        Some("other"),
        None,
        2,
        None,
    ),
    // Unparseable *and* stacked: the count comes from the token stream, so it is still
    // seen. This is the case that decides whether the stacked-statement rule survives a
    // dialect sqlparser does not know.
    case(
        "SELEKT 1; DROP TABLE t",
        Dialect::Sqlite,
        None,
        None,
        2,
        None,
    ),
];

/// A semicolon that is not a statement separator. Each of these is one statement, and a
/// `split(';')` implementation reports two.
const NOT_STACKED: &[Case] = &[
    case(
        "SELECT 'a;b' FROM t",
        Dialect::Sqlite,
        Some("select"),
        Some(true),
        1,
        Some(&["t"]),
    ),
    case(
        "SELECT * FROM t -- ; DROP TABLE t\n",
        Dialect::Sqlite,
        Some("select"),
        Some(true),
        1,
        Some(&["t"]),
    ),
    case(
        "SELECT /* ; */ 1",
        Dialect::Postgres,
        Some("select"),
        Some(true),
        1,
        Some(&[]),
    ),
    // The same trap in text the parser cannot read, where the token count is what
    // answers.
    case("SELEKT 'a;b'", Dialect::Sqlite, None, None, 1, None),
    case("SELEKT 1 -- ; x\n", Dialect::Sqlite, None, None, 1, None),
];

/// Text sqlparser cannot read, classified from the token stream instead.
///
/// The first group is the friction that failing closed would otherwise cost: ordinary
/// reads in syntax this build's parser is behind on. The second is the same traps as the
/// rest of the corpus, aimed at the weaker classifier — because a fallback that the
/// corpus does not cover is a fallback nobody checks.
const FALLBACK_READS: &[Case] = &[
    // SQLite's null-safe `IS ?`, which sqlparser does not parse — and which is as plain
    // a read as SQL has.
    case(
        "SELECT count(*) FROM t WHERE a IS ?",
        Dialect::Sqlite,
        Some("select"),
        Some(true),
        1,
        Some(&[]),
    ),
    // A write keyword inside a comment is not a write: the tokenizer dropped it.
    case(
        "SELECT a FROM t WHERE x IS ? -- DELETE FROM users
",
        Dialect::Sqlite,
        Some("select"),
        Some(true),
        1,
        Some(&[]),
    ),
    // Nor is one inside a string literal.
    case(
        "SELECT a FROM t WHERE x IS ? AND note = 'DELETE FROM users'",
        Dialect::Sqlite,
        Some("select"),
        Some(true),
        1,
        Some(&[]),
    ),
    // Nor one inside an identifier.
    case(
        "SELECT deleted_at, insert_count FROM t WHERE a IS ?",
        Dialect::Sqlite,
        Some("select"),
        Some(true),
        1,
        Some(&[]),
    ),
];

const FALLBACK_NOT_READS: &[Case] = &[
    // The headline trap, one layer down: a write hidden in a CTE, in text that does not
    // parse. The keyword is a token of its own and the fallback sees it.
    case(
        "WITH moved AS (DELETE FROM archive RETURNING *) SELECT * FROM moved WHERE x IS ?",
        Dialect::Sqlite,
        None,
        None,
        1,
        Some(&[]),
    ),
    // Postgres' `SELECT … INTO`, which creates a table.
    case(
        "SELECT * INTO backup FROM t WHERE a IS ?",
        Dialect::Sqlite,
        None,
        None,
        1,
        Some(&[]),
    ),
    // A locking read is a write as far as a read-only server is concerned, and the
    // fallback agrees.
    case(
        "SELECT * FROM t WHERE a IS ? FOR UPDATE",
        Dialect::Sqlite,
        None,
        None,
        1,
        Some(&[]),
    ),
    // Leading keyword the fallback does not vouch for.
    case(
        "PRAGMA table_info(t)",
        Dialect::Sqlite,
        None,
        None,
        1,
        Some(&[]),
    ),
    case("SELEKT 1 FROM t", Dialect::Sqlite, None, None, 1, Some(&[])),
];

fn check(group: &str, cases: &[Case]) {
    for c in cases {
        let s = summarize(c.sql, c.dialect);
        assert_eq!(
            s.statement_kind.as_deref(),
            c.kind,
            "{group}: statement_kind for {:?} ({})",
            c.sql,
            c.dialect
        );
        assert_eq!(
            s.read_only, c.read_only,
            "{group}: read_only for {:?} ({})",
            c.sql, c.dialect
        );
        assert_eq!(
            s.statement_count, c.statements,
            "{group}: statement_count for {:?} ({})",
            c.sql, c.dialect
        );
        if let Some(expected) = c.tables {
            let found: Vec<String> = s.tables.iter().map(|t| t.to_string()).collect();
            assert_eq!(
                found, expected,
                "{group}: tables for {:?} ({})",
                c.sql, c.dialect
            );
        }
    }
}

#[test]
fn reads_are_classified_as_reads() {
    check("reads", READS);
}

#[test]
fn writes_are_classified_as_writes() {
    check("writes", WRITES);
}

#[test]
fn a_statement_the_classifier_cannot_prove_is_a_read_is_never_called_one() {
    check("uncertain", UNCERTAIN);
}

#[test]
fn a_read_the_parser_cannot_read_is_still_recognized_from_its_tokens() {
    check("fallback reads", FALLBACK_READS);
    for c in FALLBACK_READS {
        assert!(
            !summarize(c.sql, c.dialect).parsed,
            "{:?} parsed after all — it no longer covers the fallback",
            c.sql
        );
    }
}

#[test]
fn the_fallback_classifier_is_not_fooled_by_what_fools_a_text_scan() {
    check("fallback non-reads", FALLBACK_NOT_READS);

    let allow = Allowlist::none();
    for c in FALLBACK_NOT_READS {
        let s = summarize(c.sql, c.dialect);
        assert!(
            matches!(Policy::read_only(&allow).decide(&s), Outcome::Deny(_)),
            "a read-only connection admitted {:?}",
            c.sql
        );
    }
}

#[test]
fn stacked_bodies_are_counted() {
    check("stacked", STACKED);
}

#[test]
fn a_semicolon_in_a_string_or_a_comment_is_not_a_statement() {
    check("not stacked", NOT_STACKED);
}

/// The property the whole corpus exists to establish, stated once: on a read-only
/// connection, nothing that is not *certainly* a read may run.
#[test]
fn a_read_only_connection_admits_only_certain_reads() {
    let allow = Allowlist::none();
    let policy = Policy::read_only(&allow);

    for c in READS.iter().chain(FALLBACK_READS) {
        let s = summarize(c.sql, c.dialect);
        assert_eq!(
            policy.decide(&s),
            Outcome::Allow {
                writes: false,
                warning: None
            },
            "a read was denied: {:?} ({})",
            c.sql,
            c.dialect
        );
    }

    for c in WRITES.iter().chain(UNCERTAIN).chain(STACKED) {
        let s = summarize(c.sql, c.dialect);
        assert!(
            matches!(policy.decide(&s), Outcome::Deny(_)),
            "a read-only connection admitted {:?} ({})",
            c.sql,
            c.dialect
        );
    }
}

/// The mode is one key and the call-site opt-in is the other, and neither works alone.
#[test]
fn a_write_needs_the_mode_and_the_opt_in() {
    let allow = Allowlist::none();
    let s = summarize("DELETE FROM t", Dialect::Postgres);

    let read_only = Policy {
        mode: AccessMode::ReadOnly,
        surface_mode: AccessMode::ReadWrite,
        write_requested: true,
        allow: &allow,
        default_schema: None,
        cost: None,
    };
    assert!(
        matches!(
            read_only.decide(&s).denial(),
            Some(Denial::WriteOnReadOnlyConnection { .. })
        ),
        "the opt-in must not widen a read-only connection"
    );

    let no_opt_in = Policy {
        mode: AccessMode::ReadWrite,
        surface_mode: AccessMode::ReadWrite,
        write_requested: false,
        allow: &allow,
        default_schema: None,
        cost: None,
    };
    assert!(
        matches!(
            no_opt_in.decide(&s).denial(),
            Some(Denial::WriteNotOptedIn { .. })
        ),
        "a read_write connection still needs the call-site opt-in"
    );

    let both = Policy {
        mode: AccessMode::ReadWrite,
        surface_mode: AccessMode::ReadWrite,
        write_requested: true,
        allow: &allow,
        default_schema: None,
        cost: None,
    };
    assert_eq!(
        both.decide(&s),
        Outcome::Allow {
            writes: true,
            warning: None
        }
    );
}

/// The parse-failure decision, asserted in both directions so that a later change
/// cannot quietly flip it. See the crate docs for the reasoning.
#[test]
fn unreadable_text_is_a_write() {
    let allow = Allowlist::none();
    let s = summarize("PRAGMA table_info(t)", Dialect::Sqlite);
    assert!(!s.parsed);

    assert!(
        matches!(
            Policy::read_only(&allow).decide(&s).denial(),
            Some(Denial::WriteOnReadOnlyConnection { certain: false, .. })
        ),
        "a read-only connection must refuse text the classifier could not read"
    );

    let authorized = Policy {
        mode: AccessMode::ReadWrite,
        surface_mode: AccessMode::ReadWrite,
        write_requested: true,
        allow: &allow,
        default_schema: None,
        cost: None,
    };
    assert_eq!(
        authorized.decide(&s),
        Outcome::Allow {
            writes: true,
            warning: None
        },
        "a human who already authorized writes here is not second-guessed"
    );
}

/// A surface may be stricter than a connection, and the denial says which one refused —
/// because "this connection is read-only" and "this server is read-only" send a person
/// to different files.
#[test]
fn a_surface_can_be_stricter_than_the_connection_and_says_so() {
    let allow = Allowlist::none();
    let s = summarize("DELETE FROM t", Dialect::Postgres);

    let narrowed = Policy {
        mode: AccessMode::ReadWrite,
        surface_mode: AccessMode::ReadOnly,
        write_requested: true,
        allow: &allow,
        default_schema: None,
        cost: None,
    };
    let denial = narrowed.decide(&s).denial().cloned().expect("denied");
    assert!(matches!(
        denial,
        Denial::WriteOnReadOnlyConnection {
            by_surface: true,
            ..
        }
    ));
    let message = denial.explain("prod");
    assert!(
        message.contains("this server was started read-only"),
        "{message}"
    );

    // And the other way round, which must remain impossible: a permissive surface
    // cannot open a read-only connection.
    let widened = Policy {
        mode: AccessMode::ReadOnly,
        surface_mode: AccessMode::ReadWrite,
        write_requested: true,
        allow: &allow,
        default_schema: None,
        cost: None,
    };
    let denial = widened.decide(&s).denial().cloned().expect("denied");
    assert!(matches!(
        denial,
        Denial::WriteOnReadOnlyConnection {
            by_surface: false,
            ..
        }
    ));
    assert!(denial.explain("prod").contains("mode = \"read_only\""));
}

/// Stacked statements are refused whatever the mode — the rule is about the shape of
/// the body, not about who may write.
#[test]
fn stacked_statements_are_refused_even_with_every_key_turned() {
    let allow = Allowlist::none();
    let policy = Policy {
        mode: AccessMode::ReadWrite,
        surface_mode: AccessMode::ReadWrite,
        write_requested: true,
        allow: &allow,
        default_schema: None,
        cost: None,
    };
    let s = summarize("SELECT 1; DROP TABLE t", Dialect::Sqlite);
    assert!(matches!(
        policy.decide(&s).denial(),
        Some(Denial::MultipleStatements { count: 2 })
    ));
}

#[test]
fn an_empty_body_is_refused_rather_than_sent() {
    let allow = Allowlist::none();
    for sql in ["", "   \n\t", "-- nothing here", "/* nor here */"] {
        let s = summarize(sql, Dialect::Sqlite);
        assert!(
            matches!(
                Policy::read_only(&allow).decide(&s).denial(),
                Some(Denial::NothingToRun)
            ),
            "{sql:?} should not have reached a database"
        );
    }
}

mod allowlist {
    use super::*;

    fn policy<'a>(allow: &'a Allowlist, schema: Option<&'a str>) -> Policy<'a> {
        Policy {
            mode: AccessMode::ReadOnly,
            surface_mode: AccessMode::ReadWrite,
            write_requested: false,
            allow,
            default_schema: schema,
            cost: None,
        }
    }

    #[test]
    fn an_empty_allowlist_governs_nothing() {
        let allow = Allowlist::none();
        let s = summarize("SELECT * FROM anything", Dialect::Postgres);
        assert_eq!(
            policy(&allow, None).decide(&s),
            Outcome::Allow {
                writes: false,
                warning: None
            }
        );
    }

    #[test]
    fn a_listed_table_passes_and_its_neighbour_does_not() {
        let allow = Allowlist::new([], ["public.orders".to_string()]).expect("valid");
        let p = policy(&allow, None);

        let ok = summarize("SELECT * FROM public.orders", Dialect::Postgres);
        assert_eq!(
            p.decide(&ok),
            Outcome::Allow {
                writes: false,
                warning: None
            }
        );

        let not_ok = summarize("SELECT * FROM public.customers", Dialect::Postgres);
        assert!(matches!(
            p.decide(&not_ok).denial(),
            Some(Denial::TableNotAllowed { table }) if table == "public.customers"
        ));
    }

    #[test]
    fn every_table_in_a_join_has_to_be_listed() {
        let allow = Allowlist::new([], ["orders".to_string()]).expect("valid");
        let p = policy(&allow, None);
        let s = summarize(
            "SELECT * FROM orders JOIN customers USING (id)",
            Dialect::Postgres,
        );
        assert!(matches!(
            p.decide(&s).denial(),
            Some(Denial::TableNotAllowed { table }) if table == "customers"
        ));
    }

    /// A CTE is not a table, so an allowlist must not ask for it to be listed.
    #[test]
    fn a_cte_name_does_not_have_to_be_allowlisted() {
        let allow = Allowlist::new([], ["orders".to_string()]).expect("valid");
        let s = summarize(
            "WITH recent AS (SELECT * FROM orders) SELECT * FROM recent",
            Dialect::Postgres,
        );
        assert_eq!(
            policy(&allow, None).decide(&s),
            Outcome::Allow {
                writes: false,
                warning: None
            }
        );
    }

    #[test]
    fn a_schema_can_be_listed_instead_of_every_table_in_it() {
        let allow = Allowlist::new(["analytics".to_string()], []).expect("valid");
        let p = policy(&allow, None);

        let ok = summarize("SELECT * FROM analytics.daily", Dialect::Postgres);
        assert_eq!(
            p.decide(&ok),
            Outcome::Allow {
                writes: false,
                warning: None
            }
        );

        let not_ok = summarize("SELECT * FROM secrets.daily", Dialect::Postgres);
        assert!(matches!(
            p.decide(&not_ok).denial(),
            Some(Denial::TableNotAllowed { .. })
        ));
    }

    /// An unqualified name is resolved against the connection's own `schema`, and
    /// refused when there is none to resolve it against — because guessing would make
    /// the allowlist mean something different on every connection.
    #[test]
    fn an_unqualified_name_needs_a_default_schema_to_match_a_schema_entry() {
        let allow = Allowlist::new(["analytics".to_string()], []).expect("valid");
        let s = summarize("SELECT * FROM daily", Dialect::Postgres);

        assert!(matches!(
            policy(&allow, None).decide(&s).denial(),
            Some(Denial::TableNotAllowed { .. })
        ));
        assert_eq!(
            policy(&allow, Some("analytics")).decide(&s),
            Outcome::Allow {
                writes: false,
                warning: None
            }
        );
    }

    #[test]
    fn identifier_case_does_not_decide_the_answer() {
        let allow = Allowlist::new([], ["Public.Orders".to_string()]).expect("valid");
        let s = summarize("SELECT * FROM public.ORDERS", Dialect::Postgres);
        assert_eq!(
            policy(&allow, None).decide(&s),
            Outcome::Allow {
                writes: false,
                warning: None
            }
        );
    }

    /// An allowlist can only check what the classifier enumerated, so text it could not
    /// read is refused rather than found unobjectionable.
    #[test]
    fn what_cannot_be_read_cannot_be_allowed() {
        let allow = Allowlist::new([], ["t".to_string()]).expect("valid");
        let p = Policy {
            mode: AccessMode::ReadWrite,
            surface_mode: AccessMode::ReadWrite,
            write_requested: true,
            allow: &allow,
            default_schema: None,
            cost: None,
        };

        for sql in [
            "SELEKT 1 FROM t",
            "COPY t FROM '/etc/passwd'",
            "VACUUM",
            // DDL: its target is not a relation sqlparser reports, so an allowlisted
            // connection refuses it rather than finding nothing to object to.
            "DROP TABLE t",
            "ALTER TABLE t ADD COLUMN c INT",
        ] {
            let s = summarize(sql, Dialect::Postgres);
            assert!(
                matches!(p.decide(&s).denial(), Some(Denial::UnknownTables)),
                "{sql:?} slipped past an allowlist"
            );
        }
    }

    #[test]
    fn an_entry_that_could_never_match_is_refused_at_load_rather_than_silently_kept() {
        assert!(Allowlist::new([], ["a.b.c.d".to_string()]).is_err());
        assert!(Allowlist::new([], ["".to_string()]).is_err());
    }
}

/// §7's write confirmation is the UI's to draw and this crate's to make possible: the
/// classic disaster is a write that looks like the one you meant and is missing four
/// words, and the classifier has to be the thing that notices.
#[test]
fn an_update_or_delete_with_no_where_clause_is_flagged_without_being_refused() {
    let allow = Allowlist::none();
    let authorized = Policy {
        mode: AccessMode::ReadWrite,
        surface_mode: AccessMode::ReadWrite,
        write_requested: true,
        allow: &allow,
        default_schema: None,
        cost: None,
    };

    for (sql, expected) in [
        ("DELETE FROM orders", true),
        ("DELETE FROM orders WHERE id = 1", false),
        ("UPDATE orders SET total = 0", true),
        ("UPDATE orders SET total = 0 WHERE id = 1", false),
        // Two levels down and still missing its WHERE.
        (
            "WITH gone AS (DELETE FROM orders RETURNING *) SELECT * FROM gone",
            true,
        ),
        // Not applicable, and so not claimed: an INSERT has nothing to filter.
        ("INSERT INTO orders (id) VALUES (1)", false),
        ("SELECT * FROM orders", false),
    ] {
        let summary = summarize(sql, Dialect::Postgres);
        assert_eq!(
            summary.unfiltered_write, expected,
            "unfiltered_write for {sql:?}"
        );
        // And flagging is not refusing: an unfiltered write is a legitimate thing to
        // want, and this crate says what a statement is rather than second-guessing it.
        if summary.statement_kind.is_some() && summary.statement_count == 1 {
            assert!(
                matches!(authorized.decide(&summary), Outcome::Allow { .. }),
                "{sql:?} should have been allowed with both keys turned"
            );
        }
    }
}

/// Invariant 8 holds for every entry in the corpus: a fingerprint never carries a
/// literal. Checked here as well as in the unit tests because the corpus is where the
/// awkward statements live.
#[test]
fn no_fingerprint_in_the_corpus_carries_a_literal() {
    let needles = [
        "a@b.example",
        "2024-01-01",
        "/etc/passwd",
        "s3://bucket/prefix",
        "a;b",
    ];
    for c in READS
        .iter()
        .chain(WRITES)
        .chain(UNCERTAIN)
        .chain(STACKED)
        .chain(NOT_STACKED)
    {
        let fp = summarize(c.sql, c.dialect).fingerprint;
        for needle in needles {
            assert!(
                !fp.contains(needle),
                "the fingerprint of {:?} leaked {needle:?}: {fp}",
                c.sql
            );
        }
    }
}

// ---------------------------------------------------------------------------
// The cumulative cost budget (§6.4, layer 2)
// ---------------------------------------------------------------------------

/// Table-driven like the rest of the corpus, because the interesting part of a budget is
/// the boundary: at the limit, one byte under it, one byte over, and the three ways a
/// budget can be absent.
mod cost_guard {
    use super::*;
    use quokka_policy::{ActorClass, CostContext, CostGuard};
    use std::time::Duration;

    const GB: u64 = 1_000_000_000;

    fn guard() -> CostGuard {
        CostGuard {
            window: Duration::from_secs(86_400),
            agent_limit: Some(50 * GB),
            human_limit: None,
            human_warn: Some(500 * GB),
        }
    }

    fn decide(actor: ActorClass, spend: Option<u64>) -> Outcome {
        let allow = Allowlist::none();
        let policy = Policy {
            mode: AccessMode::ReadOnly,
            surface_mode: AccessMode::ReadWrite,
            write_requested: false,
            allow: &allow,
            default_schema: None,
            cost: Some(CostContext {
                guard: guard(),
                actor,
                spend,
            }),
        };
        policy.decide(&summarize("SELECT * FROM events", Dialect::Athena))
    }

    /// **The asymmetry §6.4 exists for**, asserted rather than assumed: one config, two
    /// callers, two answers. A person running an expensive query is awake and watching;
    /// an agent looping at 3am is the invoice.
    #[test]
    fn agents_and_humans_are_capped_separately_under_one_config() {
        let spent = Some(60 * GB);

        let agent = decide(ActorClass::Agent, spent);
        assert_eq!(
            agent.denial().map(|d| d.code()),
            Some("policy.cost_budget"),
            "an agent past 50GB is refused: {agent:?}"
        );

        let human = decide(ActorClass::Human, spent);
        assert!(
            matches!(human, Outcome::Allow { .. }),
            "the same spend by a human on the same connection runs: {human:?}"
        );
        assert!(
            matches!(human, Outcome::Allow { warning: None, .. }),
            "and is not even warned, at a tenth of the warning threshold: {human:?}"
        );
    }

    #[test]
    fn the_boundary_is_at_the_limit_not_past_it() {
        assert!(
            matches!(
                decide(ActorClass::Agent, Some(50 * GB - 1)),
                Outcome::Allow { .. }
            ),
            "one byte under the budget still runs"
        );
        assert_eq!(
            decide(ActorClass::Agent, Some(50 * GB))
                .denial()
                .map(|d| d.code()),
            Some("policy.cost_budget"),
            "at the budget, the next query is the one that is refused — the budget \
             stops the query after the one that crossed the line (§6.4)"
        );
    }

    /// The message has to name the budget, the window and the spend, or it is not
    /// actionable — and it has to be honest about what it did not do.
    #[test]
    fn a_refusal_names_the_budget_the_window_and_what_was_spent() {
        let outcome = decide(ActorClass::Agent, Some(62 * GB));
        let denial = outcome.denial().expect("a denial");
        let message = denial.explain("lake");

        assert!(message.contains("50 GB"), "the budget: {message}");
        assert!(message.contains("1d"), "the window: {message}");
        assert!(message.contains("62 GB"), "the spend: {message}");
        assert!(message.contains("lake"), "the connection: {message}");
        assert!(
            message.contains("cost_guard"),
            "where to change it, since only a human can: {message}"
        );
        assert!(
            message.contains("BytesScannedCutoffPerQuery"),
            "the message must say which layer can actually stop a running query: {message}"
        );
        assert!(
            message.contains("after the one that crossed the line"),
            "promising a pre-execution cap would be a lie: {message}"
        );
    }

    /// A human past `human_warn` runs and is told. The warning is a sentence, not a
    /// behaviour.
    #[test]
    fn a_human_past_the_warning_threshold_is_warned_and_runs() {
        let outcome = decide(ActorClass::Human, Some(501 * GB));
        let Outcome::Allow { warning, .. } = outcome else {
            panic!("an uncapped human is never refused: {outcome:?}");
        };
        let warning = warning.expect("past human_warn, there should be a warning");
        let message = warning.message("lake");
        assert!(message.contains("501 GB"), "{message}");
        assert!(message.contains("500 GB"), "{message}");
        assert!(message.contains("no limit"), "{message}");
    }

    /// **Judgement call, written down.** A spend that could not be read is not a spend of
    /// zero. Invariant 6 fails closed when the log cannot be *written*; this is the other
    /// half, and it needs stating either way rather than falling out of a `?`.
    #[test]
    fn a_spend_that_cannot_be_read_fails_closed() {
        let outcome = decide(ActorClass::Agent, None);
        let denial = outcome.denial().expect("an unknown spend is a refusal");
        assert_eq!(denial.code(), "policy.cost_unknown");

        let message = denial.explain("lake");
        assert!(
            message.contains("fails closed"),
            "the refusal should say it is a decision: {message}"
        );
        assert!(
            message.contains("cost_guard"),
            "and how to stop having a budget, if that is what you want: {message}"
        );

        // It binds a human exactly as it binds an agent: not knowing is not knowing.
        assert_eq!(
            decide(ActorClass::Human, None).denial().map(|d| d.code()),
            Some("policy.cost_unknown")
        );
    }

    /// A connection with no budget reads nothing and refuses nothing — which is every
    /// connection by default.
    #[test]
    fn no_budget_means_no_check_at_all() {
        let allow = Allowlist::none();
        let policy = Policy {
            mode: AccessMode::ReadOnly,
            surface_mode: AccessMode::ReadWrite,
            write_requested: false,
            allow: &allow,
            default_schema: None,
            cost: None,
        };
        let outcome = policy.decide(&summarize("SELECT 1", Dialect::Athena));
        assert!(matches!(outcome, Outcome::Allow { warning: None, .. }));
    }

    /// The order of the checks: a statement that is refused for what it *is* must be
    /// reported that way, not as an overspend. A caller told "you are over budget" goes
    /// and looks at the budget, and the budget is not what is wrong.
    #[test]
    fn a_statement_refused_for_what_it_is_is_not_reported_as_an_overspend() {
        let allow = Allowlist::none();
        let policy = Policy {
            mode: AccessMode::ReadOnly,
            surface_mode: AccessMode::ReadWrite,
            write_requested: false,
            allow: &allow,
            default_schema: None,
            cost: Some(CostContext {
                guard: guard(),
                actor: ActorClass::Agent,
                spend: Some(900 * GB),
            }),
        };

        let write = policy.decide(&summarize("DELETE FROM events", Dialect::Athena));
        assert_eq!(write.denial().map(|d| d.code()), Some("policy.read_only"));

        let stacked = policy.decide(&summarize("SELECT 1; SELECT 2", Dialect::Athena));
        assert_eq!(
            stacked.denial().map(|d| d.code()),
            Some("policy.multiple_statements")
        );
    }

    /// An unlimited actor is never refused, however much it has spent — `"unlimited"` in
    /// the config file means what it says.
    #[test]
    fn an_unlimited_actor_is_never_refused() {
        let outcome = decide(ActorClass::Human, Some(9_000 * GB));
        assert!(matches!(outcome, Outcome::Allow { .. }), "{outcome:?}");
    }
}
