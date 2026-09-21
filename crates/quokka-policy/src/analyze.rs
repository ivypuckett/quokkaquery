//! Parsing, fingerprinting and classification — everything this crate knows about a
//! statement before any rule is applied to it.
//!
//! Two consumers, one parse. The audit log needs a fingerprint, a `statement_kind` and
//! a `read_only` flag (ARCHITECTURE §5.1); the guardrails need to know whether the body
//! writes, how many statements it holds and which tables it touches (§6.3). Deriving
//! those separately would be wasteful and, much worse, divergent: the log could record
//! `select` for a statement the policy engine denied as a write. They come from one
//! [`summarize`] call so they cannot disagree.
//!
//! **Classification is an AST walk, not a keyword scan.** `WITH moved AS (DELETE FROM a
//! RETURNING *) SELECT * FROM moved` parses to a `Query` whose body holds a `Delete`
//! statement, and the walk below finds it wherever it is nested. A statement whose only
//! clue is after a `--` cannot hide either: comments are gone before the tokenizer hands
//! anything back.

use std::collections::BTreeSet;
use std::ops::ControlFlow;

use sqlparser::ast::{
    visit_expressions_mut, Expr, Query, Statement, Value as AstValue, ValueWithSpan, Visit, Visitor,
};
use sqlparser::ast::{ObjectName, ObjectNamePart};
use sqlparser::parser::Parser;
use sqlparser::tokenizer::{Token, Tokenizer, Whitespace, Word};

use crate::dialect::Dialect;

/// Recorded when the text could neither be parsed nor tokenized.
///
/// `sql_fingerprint` is `NOT NULL` and must never leak a literal, so unreadable input
/// gets a marker rather than a best-effort copy of the original text.
pub const UNFINGERPRINTABLE: &str = "<unfingerprintable>";

/// One table, schema or view a statement names, as it was written.
///
/// Parts are unquoted: `"Orders"` and `Orders` both yield `Orders`. Comparison is the
/// allowlist's job, which is where the case rules live.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub struct TableRef {
    pub parts: Vec<String>,
}

impl TableRef {
    /// The last part: the object's own name.
    pub fn name(&self) -> &str {
        self.parts.last().map(String::as_str).unwrap_or_default()
    }

    /// The part before the name, when the reference was qualified.
    pub fn qualifier(&self) -> Option<&str> {
        if self.parts.len() < 2 {
            return None;
        }
        Some(self.parts[self.parts.len() - 2].as_str())
    }
}

impl std::fmt::Display for TableRef {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.parts.join("."))
    }
}

/// What the log and the guardrails need to know about a statement, none of it derived
/// from its results.
#[derive(Debug, Clone, PartialEq)]
pub struct SqlSummary {
    /// Normalized shape, literals replaced by `?`. Always present.
    pub fingerprint: String,
    /// `select` | `insert` | `update` | `delete` | `ddl` | ... — `None` if unparseable.
    ///
    /// When a body hides a write inside a read — a data-modifying CTE — this names the
    /// *write*, because that is the consequential half and the one a confirmation
    /// prompt has to say out loud (§7).
    pub statement_kind: Option<String>,
    /// `Some(true)` only when every statement in the body is certainly a read.
    ///
    /// `None` means the classifier would be guessing. [`crate::Policy`] treats `None`
    /// exactly as it treats `Some(false)`; see the crate docs for why that is one rule
    /// rather than two.
    pub read_only: Option<bool>,
    /// How many statements the body holds.
    ///
    /// From the parser when the text parsed, and from the token stream when it did not —
    /// so a stacked statement is counted even in text sqlparser could not read, and a
    /// `;` inside a string or after a `--` is not mistaken for one.
    pub statement_count: usize,
    /// Every table, view or schema-qualified object the body names, with CTE names
    /// removed. Empty when the text did not parse — which is why an allowlist denies
    /// unparseable text rather than finding nothing to object to.
    pub tables: Vec<TableRef>,
    /// Whether sqlparser read the text. `false` means the fingerprint came from the
    /// tokenizer and nothing below it is known.
    pub parsed: bool,
    /// Whether [`SqlSummary::tables`] is the *complete* list of what the body names.
    ///
    /// True only for the statement kinds whose objects this build enumerates in full:
    /// queries, DML and `EXPLAIN`. It is false for DDL, DCL and everything sqlparser
    /// either could not read or classified as `other`, because those carry their target
    /// in fields that are not table references and differ per statement — `DROP TABLE t`
    /// reports no relation at all, while `CREATE TABLE x AS SELECT …` reports two.
    ///
    /// An allowlist refuses whatever this is false for, rather than finding an empty
    /// list unobjectionable. Chasing the per-statement fields instead would be a list
    /// that only ever grows and whose gaps are silent — the same reasoning that decided
    /// the parse-failure question.
    pub objects_enumerated: bool,
}

impl SqlSummary {
    /// True when the classifier is certain the body only reads.
    pub fn is_certainly_read_only(&self) -> bool {
        self.read_only == Some(true)
    }
}

/// Parse `sql`, and answer every question the log and the guardrails ask of it.
pub fn summarize(sql: &str, dialect: Dialect) -> SqlSummary {
    let d = dialect.parser();

    match Parser::parse_sql(d.as_ref(), sql) {
        Ok(statements) if !statements.is_empty() => {
            let walk = Walk::over(&statements);
            let tables = walk.tables();
            let mut masked = statements;
            for stmt in &mut masked {
                mask_literals(stmt);
            }
            let rendered = masked
                .iter()
                .map(|s| s.to_string())
                .collect::<Vec<_>>()
                .join("; ");
            // Belt and braces, and the braces matter. Masking walks *expressions*, and
            // not every literal in the grammar is one: `COPY t FROM '/etc/passwd'` and
            // Athena's `UNLOAD (…) TO 's3://…'` carry theirs in a statement field the
            // expression visitor never reaches, so an AST-rendered fingerprint can come
            // back still holding the string someone pasted. Rather than chase that
            // class of field per statement type — a list that only ever grows and whose
            // gaps are silent — a rendered fingerprint with a surviving string literal
            // is thrown away for the tokenizer's, which masks unconditionally.
            //
            // Numbers are deliberately not part of this test: one in an expression is
            // already `?` by the time we get here, so a number that survived is a
            // syntactic constant — a `VARCHAR(255)`, a row count — and downgrading
            // every sized column type to `VARCHAR(?)` would cost legibility for no
            // privacy.
            let fingerprint = if holds_a_string_literal(dialect, &rendered) {
                Tokenizer::new(d.as_ref(), sql)
                    .tokenize()
                    .ok()
                    .as_deref()
                    .and_then(token_fingerprint)
                    .unwrap_or_else(|| UNFINGERPRINTABLE.to_string())
            } else {
                rendered
            };
            SqlSummary {
                fingerprint,
                statement_kind: Some(walk.kind),
                read_only: walk.read_only,
                statement_count: masked.len(),
                tables,
                parsed: true,
                objects_enumerated: walk.objects_enumerated,
            }
        }
        // Empty parse (whitespace or comments only) or a parse error: fall back to the
        // tokenizer, which still strips every literal and every comment, and still
        // counts the statements.
        _ => {
            let tokens = Tokenizer::new(d.as_ref(), sql).tokenize().ok();
            let statement_count = tokens.as_deref().map(count_statements).unwrap_or(0);
            let (statement_kind, read_only) = tokens
                .as_deref()
                .map(token_classification)
                .unwrap_or((None, None));
            let fingerprint = tokens
                .as_deref()
                .and_then(token_fingerprint)
                .unwrap_or_else(|| UNFINGERPRINTABLE.to_string());
            SqlSummary {
                fingerprint,
                statement_kind,
                read_only,
                statement_count,
                tables: Vec::new(),
                parsed: false,
                // Nothing was enumerated, so an allowlist has nothing to check and
                // refuses (see the field's own note).
                objects_enumerated: false,
            }
        }
    }
}

/// One pass over the parsed body: what it is, whether it writes, and what it names.
#[derive(Default)]
struct Walk {
    kind: String,
    read_only: Option<bool>,
    /// Set once the first writing statement names the body's kind, so a later read does
    /// not take the name back.
    kind_is_a_write: bool,
    saw_a_statement: bool,
    objects_enumerated: bool,
    relations: Vec<TableRef>,
    /// CTE names, which look exactly like tables at the point a relation is visited and
    /// are not tables at all. `WITH recent AS (…) SELECT * FROM recent` names one table,
    /// not two, and an allowlist that thought otherwise would deny a legitimate query.
    cte_names: BTreeSet<String>,
}

impl Walk {
    fn over(statements: &[Statement]) -> Self {
        let mut walk = Walk {
            read_only: Some(true),
            objects_enumerated: true,
            ..Walk::default()
        };
        for stmt in statements {
            let _: ControlFlow<()> = stmt.visit(&mut walk);
        }
        if !walk.saw_a_statement {
            walk.read_only = None;
        }
        walk
    }

    fn tables(&self) -> Vec<TableRef> {
        let mut out: Vec<TableRef> = self
            .relations
            .iter()
            .filter(|r| !(r.parts.len() == 1 && self.cte_names.contains(&lower(r.name()))))
            .cloned()
            .collect();
        out.sort();
        out.dedup();
        out
    }
}

impl Visitor for Walk {
    type Break = ();

    /// Every statement node, at any depth. The nesting is the point: a `Delete` inside a
    /// `SetExpr` inside a `WITH` arrives here exactly like a top-level one.
    fn pre_visit_statement(&mut self, statement: &Statement) -> ControlFlow<()> {
        let (kind, read_only) = classify_one(statement);
        let writes = read_only != Some(true);
        if !enumerates_its_objects(statement) {
            self.objects_enumerated = false;
        }

        if !self.saw_a_statement || (writes && !self.kind_is_a_write) {
            self.kind = kind;
            self.kind_is_a_write = writes;
        }
        self.saw_a_statement = true;

        // The strictest answer wins: a body is a read only if every statement in it is.
        self.read_only = match (self.read_only, read_only) {
            (Some(false), _) | (_, Some(false)) => Some(false),
            (None, _) | (_, None) => None,
            _ => Some(true),
        };
        ControlFlow::Continue(())
    }

    fn pre_visit_query(&mut self, query: &Query) -> ControlFlow<()> {
        if let Some(with) = &query.with {
            for cte in &with.cte_tables {
                self.cte_names.insert(lower(&cte.alias.name.value));
            }
        }
        ControlFlow::Continue(())
    }

    fn pre_visit_relation(&mut self, relation: &ObjectName) -> ControlFlow<()> {
        let parts: Vec<String> = relation
            .0
            .iter()
            .map(|p| match p {
                ObjectNamePart::Identifier(ident) => ident.value.clone(),
                // A name produced by a function call is not something an allowlist can
                // check, so it is recorded as written and will not match any entry.
                ObjectNamePart::Function(f) => f.name.value.clone(),
            })
            .collect();
        if !parts.is_empty() {
            self.relations.push(TableRef { parts });
        }
        ControlFlow::Continue(())
    }
}

fn lower(s: &str) -> String {
    s.to_ascii_lowercase()
}

/// Whether a rendered fingerprint still holds a quoted string, in any of the spellings
/// the dialects use.
fn holds_a_string_literal(dialect: Dialect, rendered: &str) -> bool {
    let Ok(tokens) = Tokenizer::new(dialect.parser().as_ref(), rendered).tokenize() else {
        // Unreadable output from our own renderer is not something to reason about; the
        // tokenizer fingerprint is the safe answer.
        return true;
    };
    tokens.iter().any(|t| {
        matches!(
            t,
            Token::SingleQuotedString(_)
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
                | Token::HexStringLiteral(_)
        )
    })
}

/// Whether every object this statement names reaches [`Visitor::pre_visit_relation`].
///
/// Only the query and DML shapes qualify. See [`SqlSummary::objects_enumerated`].
fn enumerates_its_objects(stmt: &Statement) -> bool {
    matches!(
        stmt,
        Statement::Query(_)
            | Statement::Insert(_)
            | Statement::Update { .. }
            | Statement::Delete(_)
            | Statement::Merge { .. }
            | Statement::Explain { .. }
            | Statement::ExplainTable { .. }
    )
}

/// One statement's kind and whether it is certainly a read.
///
/// Nothing here consults the rendered text: nesting is the visitor's job, so this only
/// has to answer for the node in front of it.
fn classify_one(stmt: &Statement) -> (String, Option<bool>) {
    match stmt {
        Statement::Query(_) => return ("select".to_string(), Some(true)),
        Statement::Insert(_) => return ("insert".to_string(), Some(false)),
        Statement::Update { .. } => return ("update".to_string(), Some(false)),
        Statement::Delete(_) => return ("delete".to_string(), Some(false)),
        Statement::Merge { .. } => return ("merge".to_string(), Some(false)),
        Statement::Explain { .. } | Statement::ExplainTable { .. } => {
            // `EXPLAIN ANALYZE` runs the statement it explains, and the statement it
            // explains is visited separately — so this node answers only for the
            // explaining, which reads.
            return ("explain".to_string(), Some(true));
        }
        _ => {}
    }

    match first_word(stmt) {
        "CREATE" | "ALTER" | "DROP" | "TRUNCATE" | "RENAME" | "COMMENT" | "ATTACH" | "DETACH" => {
            ("ddl".to_string(), Some(false))
        }
        "GRANT" | "REVOKE" | "DENY" => ("dcl".to_string(), Some(false)),
        "SHOW" | "DESCRIBE" | "DESC" | "LIST" => ("show".to_string(), Some(true)),
        "SET" | "USE" | "BEGIN" | "START" | "COMMIT" | "ROLLBACK" | "SAVEPOINT" | "RELEASE"
        | "DECLARE" | "FETCH" | "CLOSE" | "DEALLOCATE" | "PREPARE" | "DISCARD" => {
            ("session".to_string(), None)
        }
        other => {
            // `COPY`, `CALL`, `EXECUTE`, `PRAGMA`, `VACUUM`, `LOAD`, `UNLOAD` and
            // everything this build has never seen. Each of them can write on at least
            // one supported engine, so none gets an optimistic `read_only = true`.
            let word = other.to_ascii_lowercase();
            if word.is_empty() {
                ("other".to_string(), None)
            } else {
                (word, None)
            }
        }
    }
}

/// The leading keyword of a statement, taken from its rendered form.
///
/// Only reached for statements with no dedicated branch above, where the keyword is the
/// only thing that distinguishes them — and a rendered statement is normalized SQL, so
/// the first word is the keyword rather than whatever whitespace the user typed.
fn first_word(stmt: &Statement) -> &'static str {
    const KEYWORDS: [&str; 29] = [
        "CREATE",
        "ALTER",
        "DROP",
        "TRUNCATE",
        "RENAME",
        "COMMENT",
        "ATTACH",
        "DETACH",
        "GRANT",
        "REVOKE",
        "DENY",
        "SHOW",
        "DESCRIBE",
        "DESC",
        "LIST",
        "SET",
        "USE",
        "BEGIN",
        "START",
        "COMMIT",
        "ROLLBACK",
        "SAVEPOINT",
        "RELEASE",
        "DISCARD",
        "DECLARE",
        "FETCH",
        "CLOSE",
        "DEALLOCATE",
        "PREPARE",
    ];
    let rendered = stmt.to_string();
    let head = rendered
        .split_whitespace()
        .next()
        .unwrap_or_default()
        .trim_matches(|c: char| !c.is_ascii_alphanumeric())
        .to_ascii_uppercase();
    KEYWORDS.into_iter().find(|k| *k == head).unwrap_or("")
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

/// How many statements a token stream holds.
///
/// Used only when the parser could not read the text — which is exactly the case where
/// a stacked statement matters most and where a naive `split(';')` is most wrong. The
/// tokenizer has already resolved strings and comments, so a `;` inside `'a;b'` or after
/// a `--` is not a separator here.
fn count_statements(tokens: &[Token]) -> usize {
    let mut count = 0usize;
    let mut segment_has_content = false;
    for token in tokens {
        match token {
            Token::SemiColon => {
                if segment_has_content {
                    count += 1;
                }
                segment_has_content = false;
            }
            Token::EOF => {}
            Token::Whitespace(Whitespace::SingleLineComment { .. })
            | Token::Whitespace(Whitespace::MultiLineComment(_)) => {}
            Token::Whitespace(_) => {}
            _ => segment_has_content = true,
        }
    }
    if segment_has_content {
        count += 1;
    }
    count
}

/// Words that mean a statement is not certainly a read.
///
/// Compared against the *token* stream, never against the text. That distinction is the
/// whole reason this is not the keyword scan the corpus exists to reject: by the time a
/// token exists, a comment has been discarded, a string literal is a string token rather
/// than a run of words, and `deleted_at` is one word whose value is `DELETED_AT`. The
/// three cases that break a text scan — a keyword in a comment, a keyword in a literal,
/// and a keyword inside an identifier — cannot reach this list.
const NOT_A_READ: &[&str] = &[
    "INSERT",
    "UPDATE",
    "DELETE",
    "MERGE",
    "REPLACE",
    "UPSERT",
    "TRUNCATE",
    "CREATE",
    "ALTER",
    "DROP",
    "RENAME",
    "COMMENT",
    "GRANT",
    "REVOKE",
    "DENY",
    "ATTACH",
    "DETACH",
    "VACUUM",
    "ANALYZE",
    "REINDEX",
    "OPTIMIZE",
    "REPAIR",
    "PRAGMA",
    "COPY",
    "LOAD",
    "UNLOAD",
    "CALL",
    "EXECUTE",
    "EXEC",
    "LOCK",
    "UNLOCK",
    "SET",
    "USE",
    "BEGIN",
    "START",
    "COMMIT",
    "ROLLBACK",
    "SAVEPOINT",
    "RELEASE",
    "DECLARE",
    "PREPARE",
    "DEALLOCATE",
    "DISCARD",
    "FLUSH",
    "KILL",
    "INSTALL",
    "MSCK",
    "CACHE",
    "REFRESH",
    "IMPORT",
    "EXPORT",
    "BACKUP",
    "RESTORE",
    "SHUTDOWN",
    // `SELECT … INTO t` creates a table in Postgres, and `SELECT … INTO OUTFILE` writes a
    // file in MySQL. Both are reads right up until the word that makes them not one.
    "INTO",
    "OUTFILE",
    "DUMPFILE",
];

/// Words a statement may begin with and still be a candidate read.
const READ_LEADS: &[(&str, &str)] = &[
    ("SELECT", "select"),
    ("WITH", "select"),
    ("VALUES", "select"),
    ("TABLE", "select"),
    ("SHOW", "show"),
    ("DESCRIBE", "show"),
    ("DESC", "show"),
    ("EXPLAIN", "explain"),
];

/// The weaker classifier, for text sqlparser could not read.
///
/// The rule the whole crate rests on does not change here: anything not *certainly* a
/// read is a write. What changes is how much "certainly" can be established without an
/// AST. A body that begins with a reading keyword and contains no word from
/// [`NOT_A_READ`] anywhere is called a read; everything else returns `None` and is
/// handled as a write.
///
/// This is deliberately conservative to a fault — `SELECT id FROM "set"` is refused,
/// because `set` unquoted would be a session change and the cost of being wrong is not
/// symmetric. What it buys is that the friction of failing closed falls on genuinely
/// ambiguous text rather than on every statement sqlparser happens to be behind on: a
/// SQLite `WHERE a IS ?`, a dialect's index hint, a function this build has not seen.
///
/// What it cannot see is what the AST cannot see either: a `SELECT` that calls a
/// function which writes. That hole is the same size on both paths, so this one does not
/// widen it.
fn token_classification(tokens: &[Token]) -> (Option<String>, Option<bool>) {
    let words: Vec<&Word> = tokens
        .iter()
        .filter_map(|t| match t {
            // A quoted word is an identifier, whatever it spells.
            Token::Word(w) if w.quote_style.is_none() => Some(w),
            _ => None,
        })
        .collect();

    let Some(first) = words.first() else {
        return (None, None);
    };
    let lead = first.value.to_ascii_uppercase();
    let Some((_, kind)) = READ_LEADS.iter().find(|(word, _)| *word == lead) else {
        return (None, None);
    };

    for word in &words {
        let upper = word.value.to_ascii_uppercase();
        if NOT_A_READ.contains(&upper.as_str()) {
            return (None, None);
        }
    }

    (Some((*kind).to_string()), Some(true))
}

/// The fingerprint fallback for text the parser rejects.
///
/// Every literal token becomes `?` and every comment is dropped, so a fingerprint
/// produced here is no less private than one produced from an AST — only less tidy.
fn token_fingerprint(tokens: &[Token]) -> Option<String> {
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

    /// The hole the AST pass alone leaves: a literal in a statement field that is not an
    /// expression. `COPY`'s filename and Athena's `UNLOAD … TO` are the cases in the
    /// supported dialects, and the fix is general rather than per-statement.
    #[test]
    fn a_literal_outside_an_expression_still_does_not_reach_the_fingerprint() {
        for (sql, dialect, secret) in [
            (
                "COPY t FROM '/etc/passwd'",
                Dialect::Postgres,
                "/etc/passwd",
            ),
            (
                "UNLOAD (SELECT * FROM t) TO 's3://bucket/secret-prefix'",
                Dialect::Athena,
                "secret-prefix",
            ),
        ] {
            let summary = summarize(sql, dialect);
            assert!(
                !summary.fingerprint.contains(secret),
                "{sql:?} leaked {secret:?}: {}",
                summary.fingerprint
            );
        }
    }

    /// A quoted identifier is not a literal (§5.1, rule 2): normalization replaces
    /// values, not names, and the fallback above must not take the names with it.
    #[test]
    fn a_quoted_identifier_survives_normalization() {
        for dialect in [Dialect::Sqlite, Dialect::Postgres, Dialect::Athena] {
            let summary = summarize("SELECT \"col\" FROM \"tbl\"", dialect);
            assert!(
                summary.fingerprint.contains("col") && summary.fingerprint.contains("tbl"),
                "{dialect} lost an identifier: {}",
                summary.fingerprint
            );
        }
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
    fn a_write_hidden_in_a_cte_is_named_for_the_write() {
        let summary = summarize(
            "WITH moved AS (DELETE FROM a RETURNING *) SELECT * FROM moved",
            Dialect::Postgres,
        );
        assert_eq!(summary.read_only, Some(false));
        // The consequential half names the body, because that is what a write
        // confirmation has to say out loud (§7).
        assert_eq!(summary.statement_kind.as_deref(), Some("delete"));
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
