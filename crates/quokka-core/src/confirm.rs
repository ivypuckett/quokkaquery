//! What a surface should ask a human before it runs a write (ARCHITECTURE §7).
//!
//! §7 wants the UI to confirm DML and DDL on a `read_write` connection, "naming the
//! statement kind and target table, and flagging an `UPDATE` or `DELETE` with no
//! `WHERE` clause specifically". Every fact that needs is already in
//! [`SqlSummary`](crate::SqlSummary) — M3 put `unfiltered_write` there for exactly this
//! — so this module is a *rendering* of that struct and parses nothing.
//!
//! It lives here rather than in `quokka-ui` for the reason §9 gives: logic inside an
//! iced `update`/`view` function is logic that cannot be tested. The sentence a human
//! reads before deleting a table is worth a table-driven test, and this is where one can
//! exist. It is also why the type is a description rather than a widget — the words are
//! settled here, the buttons are the surface's.
//!
//! **This is not the guardrail.** A dialog asks a human; [`execute()`](crate::execute)
//! decides. A write against a `read_only` connection is refused whether or not a dialog
//! appeared, and a confirmation a surface forgot to show does not authorize anything:
//! the call-site opt-in is `ExecuteRequest::write`, and the authorization is the
//! connection's mode, which only a human can set. The moment a dialog is the thing
//! stopping a write, there are two policies and they will drift.

use crate::sql::{SqlSummary, TableRef};

/// The question to put to a human before running a statement that is not certainly a
/// read.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WriteConfirmation {
    /// `insert` | `update` | `delete` | `ddl` | … — what the classifier called it.
    ///
    /// `None` when the text could not be parsed at all, which is a question of its own
    /// rather than a missing detail: see [`WriteConfirmation::is_unclassified`].
    pub statement_kind: Option<String>,
    /// The tables the statement names, as it wrote them.
    pub tables: Vec<TableRef>,
    /// Whether [`WriteConfirmation::tables`] is everything the statement touches.
    ///
    /// False for DDL and for anything unparsed, where the target lives in a field this
    /// build does not enumerate. A prompt that said "this affects no tables" because the
    /// list came back empty would be worse than one that says it cannot tell.
    pub tables_complete: bool,
    /// An `UPDATE` or `DELETE` with no `WHERE` — the classic disaster §7 names.
    pub unfiltered: bool,
}

impl WriteConfirmation {
    /// The confirmation this statement needs, or `None` when it is certainly a read.
    ///
    /// The condition is "not *certainly* a read" rather than "is a write", which is the
    /// same rule [`Policy`](quokka_policy::Policy) decides on. Text the classifier could
    /// not read is confirmed like a write, because that is how it will be treated.
    pub fn for_statement(summary: &SqlSummary) -> Option<Self> {
        if summary.is_certainly_read_only() {
            return None;
        }
        Some(WriteConfirmation {
            statement_kind: summary.statement_kind.clone(),
            tables: summary.tables.clone(),
            tables_complete: summary.objects_enumerated,
            unfiltered: summary.unfiltered_write,
        })
    }

    /// True when the classifier could not read the statement.
    ///
    /// Worth saying out loud in a prompt: the statement will run as a write if the
    /// connection allows one, and the human is the only thing that knows what it does.
    pub fn is_unclassified(&self) -> bool {
        self.statement_kind.is_none()
    }

    /// The one-line question. "Run this DELETE against `public.orders`?"
    pub fn headline(&self) -> String {
        let kind = match &self.statement_kind {
            Some(kind) => kind.to_uppercase(),
            None => return "Run this statement?".to_string(),
        };
        match self.target() {
            Some(target) => format!("Run this {kind} against {target}?"),
            None => format!("Run this {kind}?"),
        }
    }

    /// The tables, as a prompt should name them: `orders`, `a and b`, `a, b and c`.
    ///
    /// `None` when there is nothing certain to name — either the statement named no
    /// table this build enumerates, or it could not be read at all.
    pub fn target(&self) -> Option<String> {
        if !self.tables_complete || self.tables.is_empty() {
            return None;
        }
        let names: Vec<String> = self.tables.iter().map(|t| t.to_string()).collect();
        Some(match names.split_last() {
            Some((last, [])) => last.clone(),
            Some((last, rest)) => format!("{} and {last}", rest.join(", ")),
            None => return None,
        })
    }

    /// The sentences to show under the headline, most alarming first.
    ///
    /// Empty for an ordinary, filtered write: a prompt that always has something
    /// frightening to say is a prompt nobody reads.
    pub fn warnings(&self) -> Vec<String> {
        let mut warnings = Vec::new();
        if self.unfiltered {
            let kind = self.statement_kind.as_deref().unwrap_or("statement");
            warnings.push(match self.target() {
                Some(target) => {
                    format!("This {kind} has no WHERE clause: it affects every row in {target}.")
                }
                None => format!("This {kind} has no WHERE clause: it affects every row."),
            });
        }
        if self.is_unclassified() {
            warnings.push(
                "This statement could not be parsed, so QuokkaQuery cannot say what it \
                 does. Anything not certainly a read is treated as a write."
                    .to_string(),
            );
        } else if !self.tables_complete {
            warnings.push(
                "QuokkaQuery cannot list every object this statement touches \u{2014} it \
                 enumerates them in full only for queries and DML."
                    .to_string(),
            );
        }
        warnings
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::sql::summarize;
    use crate::value::Dialect;

    fn confirm(sql: &str) -> Option<WriteConfirmation> {
        WriteConfirmation::for_statement(&summarize(sql, Dialect::Postgres))
    }

    #[test]
    fn a_read_is_never_confirmed() {
        assert_eq!(confirm("SELECT * FROM orders"), None);
    }

    #[test]
    fn a_write_names_its_kind_and_its_table() {
        let c = confirm("UPDATE public.orders SET total = 0 WHERE id = 1").expect("a write");
        assert_eq!(c.headline(), "Run this UPDATE against public.orders?");
        assert!(c.warnings().is_empty(), "a filtered write is not alarming");
    }

    #[test]
    fn a_write_with_no_where_says_so_specifically() {
        let c = confirm("DELETE FROM orders").expect("a write");
        assert!(c.unfiltered);
        let warning = c.warnings().first().cloned().expect("a warning");
        assert!(
            warning.contains("no WHERE") && warning.contains("every row in orders"),
            "the classic disaster has to be named: {warning}"
        );
    }

    #[test]
    fn a_write_hidden_in_a_cte_is_confirmed_as_the_write_it_is() {
        let c = confirm("WITH gone AS (DELETE FROM orders RETURNING *) SELECT * FROM gone")
            .expect("a data-modifying CTE is a write");
        assert_eq!(c.statement_kind.as_deref(), Some("delete"));
    }

    #[test]
    fn ddl_is_confirmed_without_claiming_to_know_every_object() {
        let c = confirm("DROP TABLE orders").expect("DDL is a write");
        assert!(!c.tables_complete);
        assert_eq!(c.headline(), "Run this DDL?");
        assert!(
            c.warnings().iter().any(|w| w.contains("enumerates")),
            "it must say it cannot list the objects rather than implying there are none"
        );
    }

    #[test]
    fn unparseable_text_is_confirmed_and_says_it_could_not_be_read() {
        let c = confirm("MERGE QUIETLY INTO ~~~").expect("not certainly a read");
        assert!(c.is_unclassified());
        assert_eq!(c.headline(), "Run this statement?");
        assert!(c
            .warnings()
            .iter()
            .any(|w| w.contains("could not be parsed")));
    }
}
