//! Secret scrubbing, applied before every audit write.
//!
//! §5 puts this outside `sql_logging` on purpose: it runs in every mode, so a password
//! pasted into a query never lands in the log even at `full`. It is a net, not a
//! guarantee — a regex cannot know that `SET x = 'hunter2'` was a credential — which is
//! exactly why `fingerprint` remains the default rather than leaning on this.

use std::sync::OnceLock;

use regex::Regex;

/// What replaces a matched secret. Kept distinct from the fingerprint's `?` so that a
/// scrubbed value is visibly a scrub rather than a normalized literal.
const MASK: &str = "'***'";

struct Patterns {
    keyword_assignment: Regex,
    identified_by: Regex,
    connection_uri: Regex,
    aws_access_key: Regex,
    bearer_token: Regex,
}

fn patterns() -> &'static Patterns {
    static P: OnceLock<Patterns> = OnceLock::new();
    P.get_or_init(|| Patterns {
        // password = 'x', "api_key" := 'x', secret: 'x'
        keyword_assignment: Regex::new(
            r#"(?i)\b(pass|passwd|password|pwd|secret|token|api[_-]?key|access[_-]?key|private[_-]?key|credential)\b(\s*["`\]]?\s*)(=|:=|:|=>)\s*'(?:[^']|'')*'"#,
        )
        .expect("static regex"),
        identified_by: Regex::new(r#"(?i)\bidentified\s+by\s+'(?:[^']|'')*'"#).expect("static regex"),
        // postgres://user:password@host
        connection_uri: Regex::new(r#"(?i)([a-z][a-z0-9+.-]*://[^\s:/@'"]+):([^\s@'"]+)@"#)
            .expect("static regex"),
        aws_access_key: Regex::new(r#"\b(?:AKIA|ASIA|AGPA|AIDA|AROA|ANPA|ANVA|ABIA|ACCA)[0-9A-Z]{16}\b"#)
            .expect("static regex"),
        bearer_token: Regex::new(r#"(?i)\bbearer\s+[A-Za-z0-9\-._~+/]{8,}={0,2}"#).expect("static regex"),
    })
}

/// Mask anything that looks like a credential.
///
/// Applied to `sql_text` and to bound `params` on the way into the log, in every
/// `sql_logging` mode.
pub fn scrub(text: &str) -> String {
    let p = patterns();
    let out = p
        .keyword_assignment
        .replace_all(text, |c: &regex::Captures| {
            format!("{}{}{} {MASK}", &c[1], &c[2], &c[3])
        });
    let out = p
        .identified_by
        .replace_all(&out, format!("IDENTIFIED BY {MASK}"));
    let out = p.connection_uri.replace_all(&out, "$1:***@");
    let out = p.aws_access_key.replace_all(&out, "***");
    let out = p.bearer_token.replace_all(&out, "Bearer ***");
    out.into_owned()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn masks_credential_assignments() {
        assert_eq!(
            scrub("ALTER USER bob SET password = 'hunter2'"),
            "ALTER USER bob SET password = '***'"
        );
        assert!(!scrub("SELECT * FROM t WHERE api_key = 'sk-live-abc'").contains("sk-live-abc"));
        assert!(!scrub("CREATE USER x IDENTIFIED BY 'pw'").contains("pw"));
    }

    #[test]
    fn masks_secrets_that_are_not_assignments() {
        assert!(!scrub("SELECT 'AKIAIOSFODNN7EXAMPLE'").contains("AKIAIOSFODNN7EXAMPLE"));
        assert!(!scrub("-- Authorization: Bearer abcdefghij").contains("abcdefghij"));
        assert_eq!(
            scrub("postgres://admin:s3cr3t@db.example/app"),
            "postgres://admin:***@db.example/app"
        );
    }

    #[test]
    fn leaves_ordinary_sql_alone() {
        let sql = "SELECT id, email FROM users WHERE created_at > '2026-01-01'";
        assert_eq!(scrub(sql), sql);
    }
}
