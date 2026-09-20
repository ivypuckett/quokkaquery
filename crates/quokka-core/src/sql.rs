//! Fingerprinting and statement classification.
//!
//! Invariant 8: `fingerprint` is the default logging mode, and the fingerprint is
//! recorded in *every* mode (§5.1, rule 2). Normalization replaces literals, not
//! identifiers, so which tables an agent touched — and when, how often, with what kind
//! of statement — survives at the safest setting.
//!
//! Classification here is *descriptive*: it fills the `statement_kind` and `read_only`
//! columns of the audit log. Enforcement — denying a write on a read-only connection,
//! rejecting stacked statements, the SQL corpus with comments and writes hidden in CTEs —
//! is `quokka-policy`'s job at M3, and this module deliberately stops short of it.
//! Where classification is not certain, `read_only` is left unknown rather than guessed
//! optimistically.

use std::ops::ControlFlow;

use sqlparser::ast::{visit_expressions_mut, Expr, Statement, Value as AstValue, ValueWithSpan};
use sqlparser::dialect::{
    Dialect as SqlDialect, GenericDialect, MySqlDialect, PostgreSqlDialect, SQLiteDialect,
};
use sqlparser::parser::Parser;
use sqlparser::tokenizer::{Token, Tokenizer, Whitespace};

use crate::value::Dialect;

/// Recorded when the text could neither be parsed nor tokenized.
///
/// `sql_fingerprint` is `NOT NULL` and must never leak a literal, so unparseable input
/// gets a marker rather than a best-effort copy of the original text.
pub const UNFINGERPRINTABLE: &str = "<unfingerprintable>";

/// What the log needs to know about a statement, none of it derived from its results.
#[derive(Debug, Clone, PartialEq)]
pub struct SqlSummary {
    /// Normalized shape, literals replaced by `?`. Always present.
    pub fingerprint: String,
    /// `select` | `insert` | `update` | `delete` | `ddl` | ... — `None` if unparseable.
    pub statement_kind: Option<String>,
    /// `Some(true)` only when the statement is certainly a read. `None` means the
    /// classifier would be guessing.
    pub read_only: Option<bool>,
    /// How many statements the text holds. M3 rejects anything above one.
    pub statement_count: usize,
}

fn dialect_for(d: Dialect) -> Box<dyn SqlDialect> {
    match d {
        Dialect::Sqlite => Box::new(SQLiteDialect {}),
        Dialect::Postgres => Box::new(PostgreSqlDialect {}),
        Dialect::MySql => Box::new(MySqlDialect {}),
        // Athena is Presto/Trino-flavoured; the generic dialect is the closest fit
        // sqlparser offers and only affects normalization, never execution.
        Dialect::Athena => Box::new(GenericDialect {}),
    }
}

/// Summarize `sql` for the audit log.
pub fn summarize(sql: &str, dialect: Dialect) -> SqlSummary {
    let d = dialect_for(dialect);

    match Parser::parse_sql(d.as_ref(), sql) {
        Ok(mut statements) if !statements.is_empty() => {
            for stmt in &mut statements {
                mask_literals(stmt);
            }
            let rendered: Vec<String> = statements.iter().map(|s| s.to_string()).collect();
            let (kind, read_only) = classify(&statements, &rendered);
            SqlSummary {
                fingerprint: rendered.join("; "),
                statement_kind: Some(kind),
                read_only,
                statement_count: statements.len(),
            }
        }
        // Empty parse (whitespace or comments only) or a parse error: fall back to the
        // tokenizer, which still strips every literal and every comment.
        _ => match token_fingerprint(d.as_ref(), sql) {
            Some(fp) => SqlSummary {
                fingerprint: fp,
                statement_kind: None,
                read_only: None,
                statement_count: 0,
            },
            None => SqlSummary {
                fingerprint: UNFINGERPRINTABLE.to_string(),
                statement_kind: None,
                read_only: None,
                statement_count: 0,
            },
        },
    }
}

/// Replace every literal in the AST with `?`.
fn mask_literals(stmt: &mut Statement) {
    let _: ControlFlow<()> = visit_expressions_mut(stmt, |expr| {
        if let Expr::Value(ValueWithSpan { value, span }) = expr {
            // `NULL` is not a literal to hide: it carries no data and dropping it would
            // make `col IS NULL` and `col = 'x'` look alike.
            if !matches!(value, AstValue::Null | AstValue::Placeholder(_)) {
                *expr = Expr::Value(ValueWithSpan {
                    value: AstValue::Placeholder("?".to_string()),
                    span: *span,
                });
            }
        }
        ControlFlow::Continue(())
    });
}

/// Keywords whose presence in a rendered `SELECT` means the classifier cannot call it a
/// read: a data-modifying CTE is exactly the case §9 wants the M3 corpus to cover.
fn hides_a_write(rendered: &str) -> bool {
    const WRITES: [&str; 5] = ["INSERT", "UPDATE", "DELETE", "MERGE", "UPSERT"];
    let upper = rendered.to_ascii_uppercase();
    WRITES.iter().any(|w| contains_word(&upper, w))
}

fn contains_word(haystack: &str, needle: &str) -> bool {
    let bytes = haystack.as_bytes();
    let mut from = 0;
    while let Some(idx) = haystack[from..].find(needle) {
        let start = from + idx;
        let end = start + needle.len();
        let before_ok = start == 0 || !is_word_byte(bytes[start - 1]);
        let after_ok = end == bytes.len() || !is_word_byte(bytes[end]);
        if before_ok && after_ok {
            return true;
        }
        from = start + 1;
    }
    false
}

fn is_word_byte(b: u8) -> bool {
    b.is_ascii_alphanumeric() || b == b'_'
}

/// The kind and read-only-ness of a statement body.
///
/// With several statements the strictest answer wins: a body is only a read if every
/// statement in it is, and the kind reported is the first statement's.
fn classify(statements: &[Statement], rendered: &[String]) -> (String, Option<bool>) {
    let mut kinds = Vec::with_capacity(statements.len());
    let mut read_only = Some(true);

    for (stmt, text) in statements.iter().zip(rendered) {
        let (kind, ro) = classify_one(stmt, text);
        kinds.push(kind);
        read_only = match (read_only, ro) {
            (Some(false), _) | (_, Some(false)) => Some(false),
            (None, _) | (_, None) => None,
            _ => Some(true),
        };
    }

    (kinds.first().cloned().unwrap_or_default(), read_only)
}

fn classify_one(stmt: &Statement, rendered: &str) -> (String, Option<bool>) {
    let kind = match stmt {
        Statement::Query(_) => {
            return if hides_a_write(rendered) {
                ("select".to_string(), None)
            } else {
                ("select".to_string(), Some(true))
            }
        }
        Statement::Insert(_) => return ("insert".to_string(), Some(false)),
        Statement::Update(_) => return ("update".to_string(), Some(false)),
        Statement::Delete(_) => return ("delete".to_string(), Some(false)),
        Statement::Merge(_) => return ("merge".to_string(), Some(false)),
        Statement::Explain { .. } | Statement::ExplainTable { .. } => {
            // `EXPLAIN ANALYZE` executes the statement it explains, so only a plain
            // EXPLAIN is certainly a read.
            return (
                "explain".to_string(),
                if hides_a_write(rendered) {
                    None
                } else {
                    Some(true)
                },
            );
        }
        _ => first_word(rendered),
    };

    match kind.as_str() {
        "CREATE" | "ALTER" | "DROP" | "TRUNCATE" | "RENAME" | "COMMENT" | "ATTACH" | "DETACH" => {
            ("ddl".to_string(), Some(false))
        }
        "GRANT" | "REVOKE" | "DENY" => ("dcl".to_string(), Some(false)),
        "SHOW" | "DESCRIBE" | "DESC" | "LIST" => ("show".to_string(), Some(true)),
        "SET" | "USE" | "BEGIN" | "START" | "COMMIT" | "ROLLBACK" | "SAVEPOINT" | "RELEASE"
        | "DECLARE" | "FETCH" | "CLOSE" | "DEALLOCATE" | "PREPARE" | "DISCARD" => {
            ("session".to_string(), None)
        }
        "COPY" | "LOAD" | "CALL" | "EXECUTE" | "LOCK" | "UNLOCK" | "ANALYZE" | "VACUUM"
        | "PRAGMA" | "CACHE" | "FLUSH" | "KILL" | "INSTALL" | "MSCK" | "ASSERT" | "RAISE" => {
            // Each of these can write on at least one supported engine, so none of them
            // gets an optimistic `read_only = true`.
            (kind.to_ascii_lowercase(), None)
        }
        _ => ("other".to_string(), None),
    }
}

fn first_word(rendered: &str) -> String {
    rendered
        .split_whitespace()
        .next()
        .unwrap_or_default()
        .trim_matches(|c: char| !c.is_ascii_alphanumeric())
        .to_ascii_uppercase()
}

/// The fallback for text the parser rejects.
///
/// Every literal token becomes `?` and every comment is dropped, so a fingerprint
/// produced here is no less private than one produced from an AST — only less tidy.
fn token_fingerprint(dialect: &dyn SqlDialect, sql: &str) -> Option<String> {
    let tokens = Tokenizer::new(dialect, sql).tokenize().ok()?;
    let mut out = String::new();
    for token in tokens {
        let piece = match token {
            Token::EOF => continue,
            // Comments can hold anything, including the literal someone pasted.
            Token::Whitespace(Whitespace::SingleLineComment { .. })
            | Token::Whitespace(Whitespace::MultiLineComment(_)) => continue,
            Token::Whitespace(_) => " ".to_string(),
            Token::Number(..)
            | Token::SingleQuotedString(_)
            | Token::DoubleQuotedString(_)
            | Token::TripleSingleQuotedString(_)
            | Token::TripleDoubleQuotedString(_)
            | Token::DollarQuotedString(_)
            | Token::SingleQuotedByteStringLiteral(_)
            | Token::DoubleQuotedByteStringLiteral(_)
            | Token::TripleSingleQuotedByteStringLiteral(_)
            | Token::TripleDoubleQuotedByteStringLiteral(_)
            | Token::SingleQuotedRawStringLiteral(_)
            | Token::DoubleQuotedRawStringLiteral(_)
            | Token::TripleSingleQuotedRawStringLiteral(_)
            | Token::TripleDoubleQuotedRawStringLiteral(_)
            | Token::NationalStringLiteral(_)
            | Token::QuoteDelimitedStringLiteral(_)
            | Token::NationalQuoteDelimitedStringLiteral(_)
            | Token::EscapedStringLiteral(_)
            | Token::UnicodeStringLiteral(_)
            | Token::HexStringLiteral(_) => "?".to_string(),
            other => other.to_string(),
        };
        push_normalized(&mut out, &piece);
    }
    let trimmed = out.trim().to_string();
    if trimmed.is_empty() {
        None
    } else {
        Some(trimmed)
    }
}

fn push_normalized(out: &mut String, piece: &str) {
    if piece == " " {
        if !out.ends_with(' ') && !out.is_empty() {
            out.push(' ');
        }
    } else {
        out.push_str(piece);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn fp(sql: &str) -> String {
        summarize(sql, Dialect::Sqlite).fingerprint
    }

    #[test]
    fn literals_become_placeholders_but_identifiers_survive() {
        // The whole bargain of invariant 8: the shape and the tables stay legible while
        // the values do not survive.
        assert_eq!(
            fp("SELECT id FROM users WHERE email = 'a@b.example' AND age > 30"),
            "SELECT id FROM users WHERE email = ? AND age > ?"
        );
    }

    #[test]
    fn formatting_and_case_are_normalized_so_shapes_group() {
        let a = fp("select  *\n  from   orders\nwhere id = 1");
        let b = fp("SELECT * FROM orders WHERE id = 99");
        assert_eq!(a, b);
    }

    #[test]
    fn comments_are_dropped_rather_than_carried_along() {
        let with_comment = fp("SELECT 1 -- ssn 123-45-6789\n");
        assert!(
            !with_comment.contains("123-45-6789"),
            "a comment must not smuggle a literal into the log: {with_comment}"
        );
    }

    #[test]
    fn null_is_not_a_literal_worth_hiding() {
        // `col IS NULL` and `col = 'x'` must not fingerprint alike.
        assert_eq!(
            fp("SELECT * FROM t WHERE c IS NULL"),
            "SELECT * FROM t WHERE c IS NULL"
        );
    }

    #[test]
    fn unparseable_text_still_yields_a_literal_free_fingerprint() {
        let summary = summarize("SELEKT 'secret' FROM;;", Dialect::Sqlite);
        assert!(
            !summary.fingerprint.contains("secret"),
            "the fallback leaked a literal: {}",
            summary.fingerprint
        );
        assert!(summary.fingerprint.contains('?'));
        assert_eq!(summary.statement_kind, None);
        assert_eq!(summary.read_only, None);
    }

    #[test]
    fn a_fingerprint_is_always_produced() {
        for sql in ["", "   ", "-- nothing but a comment", "))))"] {
            let summary = summarize(sql, Dialect::Sqlite);
            assert!(
                !summary.fingerprint.is_empty(),
                "sql_fingerprint is NOT NULL; {sql:?} produced nothing"
            );
        }
    }

    #[test]
    fn statements_are_classified_for_the_log() {
        let cases = [
            ("SELECT 1", "select", Some(true)),
            ("INSERT INTO t VALUES (1)", "insert", Some(false)),
            ("UPDATE t SET a = 1", "update", Some(false)),
            ("DELETE FROM t", "delete", Some(false)),
            ("CREATE TABLE t (a INT)", "ddl", Some(false)),
            ("DROP TABLE t", "ddl", Some(false)),
        ];
        for (sql, kind, read_only) in cases {
            let summary = summarize(sql, Dialect::Sqlite);
            assert_eq!(summary.statement_kind.as_deref(), Some(kind), "for {sql}");
            assert_eq!(summary.read_only, read_only, "for {sql}");
        }
    }

    #[test]
    fn a_write_hidden_in_a_cte_is_not_called_a_read() {
        // Enforcement is M3's; refusing to *claim* it is a read is M0's.
        let summary = summarize(
            "WITH moved AS (DELETE FROM a RETURNING *) SELECT * FROM moved",
            Dialect::Postgres,
        );
        assert_ne!(
            summary.read_only,
            Some(true),
            "a data-modifying CTE must not be recorded as read-only: {summary:?}"
        );
    }

    #[test]
    fn a_column_named_like_a_keyword_is_still_a_read() {
        let summary = summarize("SELECT last_update, deleted_at FROM t", Dialect::Sqlite);
        assert_eq!(summary.read_only, Some(true));
    }

    #[test]
    fn a_stacked_write_makes_the_whole_body_a_write() {
        let summary = summarize("SELECT 1; DROP TABLE t", Dialect::Sqlite);
        assert_eq!(summary.statement_count, 2);
        assert_eq!(summary.read_only, Some(false));
    }
}
