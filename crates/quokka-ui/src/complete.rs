//! Identifier completion, over a catalog already in memory (ARCHITECTURE §1.4, §7).
//!
//! **The rule this module exists to keep:** autocomplete never queries. Not to fill a
//! suggestion, not to check whether a table exists, not to "warm" anything. It is a pure
//! function of a [`Catalog`] the window already has and the text left of the cursor, so
//! there is no code path from a keystroke to a database — and therefore nothing for the
//! audit log to record, because nothing happened (§5).
//!
//! That is the whole reason this takes a `&Catalog` rather than an `&Engine`. A function
//! holding an engine could introspect; a function holding a catalog cannot. The catalog
//! arrives from one explicit refresh (see `work::catalog`), which is an audited event of
//! its own, and every keystroke after it is free.
//!
//! **And it is identifier completion, not an IDE.** §7 says so in as many words. No
//! signature help, no `SELECT`-clause awareness, no keyword snippets: the useful part of
//! completion in a query tool is remembering whether the column is `created_at` or
//! `createdAt`, and everything past that is a second product.

use quokka_core::Catalog;

/// How many suggestions to offer. More than a glance is worse than none.
pub const MAX_SUGGESTIONS: usize = 10;

/// What kind of thing a suggestion names.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Kind {
    Schema,
    Table,
    Column,
}

impl Kind {
    pub fn label(self) -> &'static str {
        match self {
            Kind::Schema => "schema",
            Kind::Table => "table",
            Kind::Column => "column",
        }
    }
}

/// One suggestion.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Candidate {
    /// The identifier to insert.
    pub text: String,
    /// Where it comes from: a table's schema, or a column's table and type.
    pub detail: String,
    pub kind: Kind,
}

/// The identifier being typed, and how much of it to replace.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct Word {
    /// The part after the last `.` — what is being matched.
    pub prefix: String,
    /// The part before it, if the identifier was qualified: `orders` in `orders.cr`.
    pub qualifier: Option<String>,
    /// How many characters left of the cursor [`Word::prefix`] occupies, so accepting a
    /// suggestion replaces exactly what was typed.
    pub replace: usize,
}

/// Read the identifier ending at the cursor out of one line.
///
/// `column` is a character index, as `text_editor`'s cursor reports it.
pub fn word_at(line: &str, column: usize) -> Word {
    let chars: Vec<char> = line.chars().collect();
    let end = column.min(chars.len());

    let is_ident = |c: char| c.is_alphanumeric() || c == '_';

    let mut start = end;
    while start > 0 && is_ident(chars[start - 1]) {
        start -= 1;
    }
    let prefix: String = chars[start..end].iter().collect();

    // One level of qualification, which is all a grid of tables and columns can use.
    let mut qualifier = None;
    if start > 0 && chars[start - 1] == '.' {
        let mut q = start - 1;
        while q > 0 && is_ident(chars[q - 1]) {
            q -= 1;
        }
        let name: String = chars[q..start - 1].iter().collect();
        if !name.is_empty() {
            qualifier = Some(name);
        }
    }

    Word {
        replace: prefix.chars().count(),
        prefix,
        qualifier,
    }
}

/// Suggestions for `word`, drawn from `catalog` and nothing else.
///
/// Empty when there is nothing to go on: an empty, unqualified prefix offers no
/// suggestions at all, because a list of every identifier in the database is not help.
/// A qualified empty prefix — `orders.` — does list that table's columns, which is the
/// one case where the list is short and is exactly the question being asked.
pub fn suggest(catalog: &Catalog, word: &Word) -> Vec<Candidate> {
    if word.prefix.is_empty() && word.qualifier.is_none() {
        return Vec::new();
    }
    let prefix = word.prefix.to_lowercase();

    let mut candidates: Vec<(u8, Candidate)> = Vec::new();
    let mut push = |rank: u8, candidate: Candidate| candidates.push((rank, candidate));

    match &word.qualifier {
        // `orders.` or `public.` — a name on the left narrows what may be on the right.
        Some(qualifier) => {
            let q = qualifier.to_lowercase();
            for table in &catalog.tables {
                let in_this_table = table.name.to_lowercase() == q;
                let in_this_schema = table
                    .schema
                    .as_deref()
                    .map(|s| s.to_lowercase() == q)
                    .unwrap_or(false);

                if in_this_table {
                    for column in &table.columns {
                        if let Some(rank) = rank_of(&column.name, &prefix) {
                            push(
                                rank,
                                Candidate {
                                    text: column.name.clone(),
                                    detail: format!("{} · {}", table.name, column.driver_type),
                                    kind: Kind::Column,
                                },
                            );
                        }
                    }
                }
                if in_this_schema {
                    if let Some(rank) = rank_of(&table.name, &prefix) {
                        push(
                            rank,
                            Candidate {
                                text: table.name.clone(),
                                detail: table.kind.clone(),
                                kind: Kind::Table,
                            },
                        );
                    }
                }
            }
        }
        None => {
            let mut schemas: Vec<&str> = catalog
                .tables
                .iter()
                .filter_map(|t| t.schema.as_deref())
                .collect();
            schemas.sort_unstable();
            schemas.dedup();
            for schema in schemas {
                if let Some(rank) = rank_of(schema, &prefix) {
                    push(
                        rank,
                        Candidate {
                            text: schema.to_string(),
                            detail: "schema".to_string(),
                            kind: Kind::Schema,
                        },
                    );
                }
            }
            for table in &catalog.tables {
                if let Some(rank) = rank_of(&table.name, &prefix) {
                    push(
                        rank,
                        Candidate {
                            text: table.name.clone(),
                            detail: match &table.schema {
                                Some(schema) => format!("{schema} · {}", table.kind),
                                None => table.kind.clone(),
                            },
                            kind: Kind::Table,
                        },
                    );
                }
                for column in &table.columns {
                    if let Some(rank) = rank_of(&column.name, &prefix) {
                        // A column is ranked below a table of the same quality: the
                        // identifier after `FROM` is what people type first, and a
                        // hundred columns would otherwise bury the table they came from.
                        push(
                            rank + 2,
                            Candidate {
                                text: column.name.clone(),
                                detail: format!("{} · {}", table.name, column.driver_type),
                                kind: Kind::Column,
                            },
                        );
                    }
                }
            }
        }
    }

    candidates.sort_by(|a, b| {
        a.0.cmp(&b.0)
            .then_with(|| a.1.text.len().cmp(&b.1.text.len()))
            .then_with(|| a.1.text.cmp(&b.1.text))
    });

    let mut seen = std::collections::HashSet::new();
    candidates
        .into_iter()
        .map(|(_, c)| c)
        .filter(|c| seen.insert((c.kind, c.text.clone())))
        .take(MAX_SUGGESTIONS)
        .collect()
}

/// 0 for a prefix match, 1 for a match anywhere, `None` for no match. Case-insensitive,
/// because SQL identifiers usually are and nobody types the case they stored.
fn rank_of(name: &str, prefix: &str) -> Option<u8> {
    if prefix.is_empty() {
        return Some(0);
    }
    let lower = name.to_lowercase();
    if lower.starts_with(prefix) {
        Some(0)
    } else if lower.contains(prefix) {
        Some(1)
    } else {
        None
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use quokka_core::{Column, TableInfo};

    fn catalog() -> Catalog {
        Catalog {
            tables: vec![
                TableInfo {
                    database: None,
                    schema: Some("public".to_string()),
                    name: "orders".to_string(),
                    kind: "table".to_string(),
                    columns: vec![
                        column("id", "integer"),
                        column("created_at", "timestamptz"),
                        column("customer_id", "integer"),
                    ],
                },
                TableInfo {
                    database: None,
                    schema: Some("public".to_string()),
                    name: "order_items".to_string(),
                    kind: "table".to_string(),
                    columns: vec![column("order_id", "integer")],
                },
            ],
        }
    }

    fn column(name: &str, driver_type: &str) -> Column {
        Column {
            name: name.to_string(),
            driver_type: driver_type.to_string(),
            nullable: Some(true),
        }
    }

    fn texts(word: &str) -> Vec<String> {
        let w = word_at(word, word.chars().count());
        suggest(&catalog(), &w)
            .into_iter()
            .map(|c| c.text)
            .collect()
    }

    #[test]
    fn a_prefix_finds_the_tables_that_start_with_it() {
        let names = texts("SELECT * FROM ord");
        assert_eq!(names.first().map(String::as_str), Some("orders"));
        assert!(names.contains(&"order_items".to_string()));
    }

    #[test]
    fn a_qualifier_narrows_to_that_table_s_columns() {
        assert_eq!(
            texts("SELECT orders.cr"),
            vec!["created_at".to_string()],
            "one level of qualification is what a catalog of tables and columns can use"
        );
    }

    #[test]
    fn a_trailing_dot_lists_the_table_s_columns() {
        assert_eq!(
            texts("SELECT orders."),
            vec![
                "id".to_string(),
                "created_at".to_string(),
                "customer_id".to_string()
            ]
        );
    }

    #[test]
    fn a_schema_qualifier_lists_its_tables() {
        assert_eq!(texts("SELECT * FROM public.ord").len(), 2);
    }

    #[test]
    fn nothing_is_offered_for_nothing_typed() {
        assert!(
            texts("SELECT * FROM ").is_empty(),
            "a list of everything is not help"
        );
    }

    #[test]
    fn a_table_outranks_a_column_that_matches_as_well() {
        let names = texts("SELECT order");
        assert_eq!(names.first().map(String::as_str), Some("orders"));
    }

    #[test]
    fn the_word_under_the_cursor_is_what_gets_replaced() {
        let word = word_at("SELECT cust FROM orders", 11);
        assert_eq!(word.prefix, "cust");
        assert_eq!(word.replace, 4);
        assert_eq!(word.qualifier, None);

        let word = word_at("SELECT orders.cr", 16);
        assert_eq!(word.prefix, "cr");
        assert_eq!(word.qualifier.as_deref(), Some("orders"));
        assert_eq!(word.replace, 2);
    }

    #[test]
    fn matching_ignores_case_because_identifiers_usually_do() {
        assert!(texts("SELECT * FROM ORD").contains(&"orders".to_string()));
    }

    #[test]
    fn suggestions_are_bounded_so_the_overlay_stays_a_glance() {
        let mut big = catalog();
        for i in 0..50 {
            big.tables.push(TableInfo {
                database: None,
                schema: None,
                name: format!("order_{i}"),
                kind: "table".to_string(),
                columns: Vec::new(),
            });
        }
        let word = word_at("ord", 3);
        assert_eq!(suggest(&big, &word).len(), MAX_SUGGESTIONS);
    }
}
