//! Where the log lives.

use std::path::PathBuf;

/// `$QUOKKA_AUDIT_DB`, else `<XDG data dir>/quokkaquery/audit.db`.
///
/// The override exists for tests and for anyone keeping the log on an encrypted volume;
/// it is a path, not a logging-fidelity setting, so it is not the human-only
/// configuration invariant 7 protects.
pub fn default_audit_path() -> Result<PathBuf, std::io::Error> {
    if let Some(p) = std::env::var_os("QUOKKA_AUDIT_DB") {
        return Ok(PathBuf::from(p));
    }
    let dirs = directories::ProjectDirs::from("", "", "quokkaquery").ok_or_else(|| {
        std::io::Error::other(
            "no home directory: set QUOKKA_AUDIT_DB to choose where the audit log lives",
        )
    })?;
    Ok(dirs.data_dir().join("audit.db"))
}
