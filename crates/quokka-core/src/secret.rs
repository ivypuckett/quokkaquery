//! `Secret` — a string the log cannot print.
//!
//! §5: "Credentials never enter the log." That is a property worth making structural
//! rather than a rule to remember, so a resolved credential is never a `String`. This
//! type has no `Display`, its `Debug` prints a fixed mask, it does not serialize, and it
//! zeroizes on drop. Reading the value takes a call to [`Secret::expose`], which is
//! greppable — and the only callers are the drivers' `connect`.

use std::fmt;

use zeroize::Zeroize;

/// A credential in memory.
pub struct Secret(String);

impl Secret {
    pub fn new(value: impl Into<String>) -> Self {
        Secret(value.into())
    }

    /// The value itself. Named to be conspicuous in a diff and in a grep.
    pub fn expose(&self) -> &str {
        &self.0
    }

    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }
}

/// No `{:?}` of a config, an error or a driver can print a password.
impl fmt::Debug for Secret {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("Secret(***)")
    }
}

impl Drop for Secret {
    fn drop(&mut self) {
        self.0.zeroize();
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_secret_does_not_print_itself() {
        let s = Secret::new("hunter2");
        assert_eq!(format!("{s:?}"), "Secret(***)");
        assert!(!format!("{s:?}").contains("hunter2"));
    }
}
