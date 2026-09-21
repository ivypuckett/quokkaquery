//! Where a connection's password comes from, and where it never goes.
//!
//! §5: "Credentials never enter the log — they live in the OS keyring via `keyring` 4.x,
//! with an encrypted file fallback for headless Linux." Two consequences shape this
//! module:
//!
//! - **The config file holds a *reference*, never a value.** [`CredentialRef`] names a
//!   keyring entry or an environment variable. `Registry::load` can therefore be read by
//!   anything without handling a secret, and a config file can be committed to a repo.
//! - **A resolved credential is a [`Secret`](crate::Secret)**, which has no `Display`,
//!   does not serialize, and prints as `Secret(***)`. The type is what keeps a password
//!   out of a log line, not the discipline of whoever writes the next `format!`.
//!
//! The fallback exists because a headless Linux box usually has no Secret Service, and
//! "we support Postgres unless you are on a server" would be a poor joke. It is a real
//! encryption, not obfuscation, but be clear about the key: with
//! `$QUOKKA_CREDENTIAL_PASSPHRASE` set, the file is useless to someone who copies it;
//! without one, the key sits in a `0600` file beside it and **file permissions are the
//! security boundary** — the same boundary `~/.pgpass` and `~/.ssh/id_ed25519` rely on.

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

use zeroize::Zeroizing;

use crate::secret::Secret;

/// The keyring service name used when a connection does not name one.
pub const DEFAULT_SERVICE: &str = "quokkaquery";

/// Magic line at the top of the fallback file, and the AAD its ciphertext is bound to.
const FILE_MAGIC: &str = "quokkaquery-credentials-v1";

const SALT_LEN: usize = 16;
const NONCE_LEN: usize = 24; // XChaCha20-Poly1305
const KEY_LEN: usize = 32;

#[derive(Debug, thiserror::Error)]
pub enum CredentialError {
    #[error("credential {reference}: the OS keyring refused it ({detail})")]
    Keyring { reference: String, detail: String },

    #[error("credential {reference}: ${var} is not set")]
    MissingEnv { reference: String, var: String },

    #[error("the encrypted credential file at {path}: {detail}")]
    File { path: PathBuf, detail: String },

    #[error(
        "the encrypted credential file at {path} could not be decrypted. \
         If $QUOKKA_CREDENTIAL_PASSPHRASE is set, it is the wrong one; if it is not set, \
         the key file beside it is missing or does not belong to this file."
    )]
    BadKey { path: PathBuf },

    #[error("could not locate the credential store: {0}")]
    Path(String),

    #[error("credential reference {0:?} is not understood; expected \"keyring\", \"keyring:<service>/<account>\", \"env:<VAR>\" or \"none\"")]
    BadReference(String),

    /// The reference is fine; there is simply nowhere for QuokkaQuery to put a value.
    /// Distinct from [`CredentialError::BadReference`] because the fix is different:
    /// this one is answered by editing the config file, not by correcting a typo.
    #[error("connection {connection:?} keeps no credential of its own: {detail}")]
    NotStorable { connection: String, detail: String },
}

/// Which store a reference resolves against.
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize)]
#[serde(rename_all = "snake_case")]
pub enum Backend {
    /// Keychain, Credential Manager or Secret Service.
    OsKeyring,
    /// The XChaCha20-Poly1305 file, used when no OS keyring is reachable.
    EncryptedFile,
    /// An environment variable, resolved in the caller's process.
    Environment,
    /// The connection carries no credential.
    None,
}

impl Backend {
    pub fn as_str(self) -> &'static str {
        match self {
            Backend::OsKeyring => "os_keyring",
            Backend::EncryptedFile => "encrypted_file",
            Backend::Environment => "environment",
            Backend::None => "none",
        }
    }
}

/// Where a connection's password lives. Never the password itself.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum CredentialRef {
    /// The connection authenticates without one — a unix socket with peer auth, a
    /// SQLite file, `trust` in `pg_hba.conf`.
    None,
    /// An entry in the OS keyring, or in the encrypted file standing in for it.
    Keyring { service: String, account: String },
    /// An environment variable, for CI and for containers that inject secrets that way.
    Env { var: String },
}

impl CredentialRef {
    /// The default for a connection that does not say: its own name in the keyring.
    ///
    /// Defaulting to the keyring rather than to `none` is deliberate — the safe place is
    /// the one you get without asking — and costs nothing when no entry exists, since a
    /// missing entry resolves to "no credential" rather than to an error.
    pub fn default_for(connection: &str) -> Self {
        CredentialRef::Keyring {
            service: DEFAULT_SERVICE.to_string(),
            account: connection.to_string(),
        }
    }

    /// The default for a connection whose driver keeps its credentials elsewhere.
    ///
    /// One driver does: Athena authenticates through the AWS SDK's own chain — an
    /// `sso_session` profile in `~/.aws/config` and the token cache `aws sso login`
    /// writes — so there is no secret for QuokkaQuery to hold. This module is about
    /// secrets *QuokkaQuery stores*, and an SSO token cache belongs to the AWS CLI: it
    /// is refreshed by a tool we do not run, expires on a schedule we do not set, and
    /// would be the one keyring entry `quokka credential set` could not fill. So the
    /// AWS profile is an ordinary connection field (`profile = "…"`) and the credential
    /// reference is [`CredentialRef::None`], rather than a fourth variant here that
    /// would mean "look somewhere this crate cannot look".
    pub fn for_driver(driver: &str, connection: &str) -> Self {
        match driver {
            "athena" => CredentialRef::None,
            _ => CredentialRef::default_for(connection),
        }
    }

    /// Parse the `credential = "..."` setting.
    pub fn parse(text: &str, connection: &str) -> Result<Self, CredentialError> {
        let text = text.trim();
        if text.eq_ignore_ascii_case("none") {
            return Ok(CredentialRef::None);
        }
        if text.eq_ignore_ascii_case("keyring") {
            return Ok(CredentialRef::default_for(connection));
        }
        if let Some(rest) = text.strip_prefix("env:") {
            let var = rest.trim();
            if var.is_empty() {
                return Err(CredentialError::BadReference(text.to_string()));
            }
            return Ok(CredentialRef::Env {
                var: var.to_string(),
            });
        }
        if let Some(rest) = text.strip_prefix("keyring:") {
            let (service, account) = match rest.split_once('/') {
                Some((s, a)) if !s.is_empty() && !a.is_empty() => (s, a),
                // `keyring:prod` names the account in the default service.
                None if !rest.is_empty() => (DEFAULT_SERVICE, rest),
                _ => return Err(CredentialError::BadReference(text.to_string())),
            };
            return Ok(CredentialRef::Keyring {
                service: service.to_string(),
                account: account.to_string(),
            });
        }
        Err(CredentialError::BadReference(text.to_string()))
    }

    /// How the reference is written in a config file. Safe to print: it names a
    /// location, never a value.
    pub fn as_config_string(&self) -> String {
        match self {
            CredentialRef::None => "none".to_string(),
            CredentialRef::Keyring { service, account } => format!("keyring:{service}/{account}"),
            CredentialRef::Env { var } => format!("env:{var}"),
        }
    }

    /// Which store this reference reads from, as things stand right now.
    pub fn backend(&self) -> Backend {
        match self {
            CredentialRef::None => Backend::None,
            CredentialRef::Env { .. } => Backend::Environment,
            CredentialRef::Keyring { .. } => {
                if os_keyring_available() {
                    Backend::OsKeyring
                } else {
                    Backend::EncryptedFile
                }
            }
        }
    }
}

/// Look the credential up. `Ok(None)` means there is none, which is not an error: a
/// connection may legitimately authenticate without one.
///
/// A keyring reference consults the OS keyring first and the encrypted file second, so a
/// machine that gains a Secret Service later still finds what it stored before, and one
/// that loses it still starts.
pub fn resolve(reference: &CredentialRef) -> Result<Option<Secret>, CredentialError> {
    match reference {
        CredentialRef::None => Ok(None),
        CredentialRef::Env { var } => match std::env::var(var) {
            Ok(v) => Ok(Some(Secret::new(v))),
            Err(_) => Err(CredentialError::MissingEnv {
                reference: reference.as_config_string(),
                var: var.clone(),
            }),
        },
        CredentialRef::Keyring { service, account } => {
            if let Some(secret) = keyring_get(reference, service, account)? {
                return Ok(Some(secret));
            }
            file_get(service, account)
        }
    }
}

/// [`resolve`] off the async runtime.
///
/// The OS keyring is a blocking D-Bus or Keychain call, and Argon2 over the fallback
/// file is deliberately slow, so neither belongs on a reactor thread.
pub async fn resolve_async(reference: &CredentialRef) -> Result<Option<Secret>, CredentialError> {
    let reference = reference.clone();
    match tokio::task::spawn_blocking(move || resolve(&reference)).await {
        Ok(result) => result,
        Err(e) => Err(CredentialError::Path(format!(
            "the credential lookup task did not finish: {e}"
        ))),
    }
}

/// Save a credential, returning the store it landed in.
pub fn store(
    connection: &str,
    reference: &CredentialRef,
    secret: &Secret,
) -> Result<Backend, CredentialError> {
    match reference {
        CredentialRef::None => Err(CredentialError::NotStorable {
            connection: connection.to_string(),
            detail: "it is configured with credential = \"none\"".to_string(),
        }),
        CredentialRef::Env { var } => Err(CredentialError::NotStorable {
            connection: connection.to_string(),
            detail: format!(
                "it reads ${var} from the environment, so the value belongs to whoever \
                 sets that variable"
            ),
        }),
        CredentialRef::Keyring { service, account } => {
            if os_keyring_available() {
                keyring_set(reference, service, account, secret)?;
                Ok(Backend::OsKeyring)
            } else {
                file_set(service, account, secret)?;
                Ok(Backend::EncryptedFile)
            }
        }
    }
}

/// Remove a credential from wherever it is. `true` if something was removed.
pub fn delete(reference: &CredentialRef) -> Result<bool, CredentialError> {
    match reference {
        CredentialRef::None | CredentialRef::Env { .. } => Ok(false),
        CredentialRef::Keyring { service, account } => {
            // Both stores, so "deleted" does not leave a copy behind in the other one.
            let from_keyring = keyring_delete(reference, service, account)?;
            let from_file = file_delete(service, account)?;
            Ok(from_keyring || from_file)
        }
    }
}

// --- the OS keyring ---------------------------------------------------------------

/// Whether an OS credential store could be reached at all.
///
/// `keyring` initializes its platform store once, lazily; this is the documented way to
/// ask how that went without creating an entry first.
fn os_keyring_available() -> bool {
    // A headless box with no Secret Service is exactly the case the file fallback is
    // for, and this is where that fork is decided.
    if std::env::var_os("QUOKKA_CREDENTIAL_FORCE_FILE").is_some() {
        return false;
    }
    keyring::Entry::store_status().is_ok()
}

fn keyring_get(
    reference: &CredentialRef,
    service: &str,
    account: &str,
) -> Result<Option<Secret>, CredentialError> {
    if !os_keyring_available() {
        return Ok(None);
    }
    let entry = match keyring::Entry::new(service, account) {
        Ok(e) => e,
        Err(keyring::Error::NoDefaultStore) => return Ok(None),
        Err(e) => return Err(keyring_error(reference, e)),
    };
    match entry.get_password() {
        Ok(p) => Ok(Some(Secret::new(p))),
        Err(keyring::Error::NoEntry) => Ok(None),
        // The store is there but would not answer — a locked keychain, a denied prompt.
        // Falling through to the file would silently use a stale password, so say so.
        Err(e) => Err(keyring_error(reference, e)),
    }
}

fn keyring_set(
    reference: &CredentialRef,
    service: &str,
    account: &str,
    secret: &Secret,
) -> Result<(), CredentialError> {
    let entry = keyring::Entry::new(service, account).map_err(|e| keyring_error(reference, e))?;
    entry
        .set_password(secret.expose())
        .map_err(|e| keyring_error(reference, e))
}

fn keyring_delete(
    reference: &CredentialRef,
    service: &str,
    account: &str,
) -> Result<bool, CredentialError> {
    if !os_keyring_available() {
        return Ok(false);
    }
    let entry = match keyring::Entry::new(service, account) {
        Ok(e) => e,
        Err(keyring::Error::NoDefaultStore) => return Ok(false),
        Err(e) => return Err(keyring_error(reference, e)),
    };
    match entry.delete_credential() {
        Ok(()) => Ok(true),
        Err(keyring::Error::NoEntry) => Ok(false),
        Err(e) => Err(keyring_error(reference, e)),
    }
}

/// `keyring::Error` never carries the secret itself, but it can carry the entry's
/// attributes, so the message is passed through the same scrubber every audit write uses.
fn keyring_error(reference: &CredentialRef, e: keyring::Error) -> CredentialError {
    CredentialError::Keyring {
        reference: reference.as_config_string(),
        detail: crate::redact::scrub(&e.to_string()),
    }
}

// --- the encrypted file fallback ---------------------------------------------------

/// `$QUOKKA_CREDENTIAL_FILE`, else `<XDG data dir>/quokkaquery/credentials.enc`.
pub fn credential_file_path() -> Result<PathBuf, CredentialError> {
    if let Some(p) = std::env::var_os("QUOKKA_CREDENTIAL_FILE") {
        return Ok(PathBuf::from(p));
    }
    let dirs = directories::ProjectDirs::from("", "", "quokkaquery").ok_or_else(|| {
        CredentialError::Path(
            "no home directory; set QUOKKA_CREDENTIAL_FILE to choose where the encrypted \
             credential file lives"
                .to_string(),
        )
    })?;
    Ok(dirs.data_dir().join("credentials.enc"))
}

fn key_file_path(store: &Path) -> PathBuf {
    store.with_extension("key")
}

fn entry_key(service: &str, account: &str) -> String {
    format!("{service}/{account}")
}

fn file_get(service: &str, account: &str) -> Result<Option<Secret>, CredentialError> {
    let path = credential_file_path()?;
    if !path.exists() {
        return Ok(None);
    }
    let entries = read_file(&path)?;
    Ok(entries
        .get(&entry_key(service, account))
        .map(|v| Secret::new(v.clone())))
}

fn file_set(service: &str, account: &str, secret: &Secret) -> Result<(), CredentialError> {
    let path = credential_file_path()?;
    let mut entries = if path.exists() {
        read_file(&path)?
    } else {
        BTreeMap::new()
    };
    entries.insert(entry_key(service, account), secret.expose().to_string());
    write_file(&path, &entries)
}

fn file_delete(service: &str, account: &str) -> Result<bool, CredentialError> {
    let path = credential_file_path()?;
    if !path.exists() {
        return Ok(false);
    }
    let mut entries = read_file(&path)?;
    if entries.remove(&entry_key(service, account)).is_none() {
        return Ok(false);
    }
    write_file(&path, &entries)?;
    Ok(true)
}

/// The decrypted contents: entry key -> password.
type Entries = BTreeMap<String, String>;

fn read_file(path: &Path) -> Result<Entries, CredentialError> {
    let text = std::fs::read_to_string(path).map_err(|e| CredentialError::File {
        path: path.to_path_buf(),
        detail: e.to_string(),
    })?;

    let mut lines = text.lines();
    let magic = lines.next().unwrap_or_default();
    if magic != FILE_MAGIC {
        return Err(CredentialError::File {
            path: path.to_path_buf(),
            detail: format!("not a QuokkaQuery credential file (expected {FILE_MAGIC:?})"),
        });
    }
    let bad = |what: &str| CredentialError::File {
        path: path.to_path_buf(),
        detail: format!("the {what} line is missing or malformed"),
    };
    let salt = hex_decode(lines.next().ok_or_else(|| bad("salt"))?).ok_or_else(|| bad("salt"))?;
    let nonce =
        hex_decode(lines.next().ok_or_else(|| bad("nonce"))?).ok_or_else(|| bad("nonce"))?;
    let ciphertext = hex_decode(lines.next().ok_or_else(|| bad("ciphertext"))?)
        .ok_or_else(|| bad("ciphertext"))?;
    if salt.len() != SALT_LEN || nonce.len() != NONCE_LEN {
        return Err(bad("header"));
    }

    // `create: false` — a read must never mint a new key: that would turn "the key is
    // missing" into "the file decrypts to nothing", which reads as "you have no
    // credentials" and is the worst possible answer.
    let key = derive_key(path, &salt, false)?;
    let plaintext = decrypt(&key, &nonce, &ciphertext).ok_or_else(|| CredentialError::BadKey {
        path: path.to_path_buf(),
    })?;

    // The payload is `key\tvalue` per line: a format with no escaping questions, since
    // an entry key cannot contain a tab and a password cannot contain a newline.
    let mut entries = Entries::new();
    for line in plaintext.lines() {
        if let Some((k, v)) = line.split_once('\t') {
            entries.insert(k.to_string(), v.to_string());
        }
    }
    Ok(entries)
}

fn write_file(path: &Path, entries: &Entries) -> Result<(), CredentialError> {
    if let Some(dir) = path.parent() {
        if !dir.as_os_str().is_empty() {
            std::fs::create_dir_all(dir).map_err(|e| CredentialError::File {
                path: dir.to_path_buf(),
                detail: e.to_string(),
            })?;
        }
    }

    // A fresh salt and nonce on every write: the file is rewritten whole, so there is
    // never a reason to reuse either.
    let salt = random_bytes::<SALT_LEN>(path)?;
    let nonce = random_bytes::<NONCE_LEN>(path)?;
    let key = derive_key(path, &salt, true)?;

    let mut plaintext = Zeroizing::new(String::new());
    for (k, v) in entries {
        plaintext.push_str(k);
        plaintext.push('\t');
        plaintext.push_str(v);
        plaintext.push('\n');
    }

    let ciphertext =
        encrypt(&key, &nonce, plaintext.as_bytes()).ok_or_else(|| CredentialError::File {
            path: path.to_path_buf(),
            detail: "encryption failed".to_string(),
        })?;

    let body = format!(
        "{FILE_MAGIC}\n{}\n{}\n{}\n",
        hex_encode(&salt),
        hex_encode(&nonce),
        hex_encode(&ciphertext)
    );

    // Written to a sibling and renamed, so a crash mid-write cannot leave a file that
    // decrypts to nothing and loses every credential at once.
    let tmp = path.with_extension("enc.tmp");
    write_private(&tmp, body.as_bytes())?;
    std::fs::rename(&tmp, path).map_err(|e| CredentialError::File {
        path: path.to_path_buf(),
        detail: e.to_string(),
    })
}

/// The key the file is encrypted under.
///
/// `$QUOKKA_CREDENTIAL_PASSPHRASE` if set — then the file is useless to someone who
/// copies it — otherwise a 32-byte key in a `0600` file beside it, where the file
/// permissions are the boundary. Argon2id is used only in the first case; stretching a
/// key that is already 256 bits of entropy would buy nothing but latency.
fn derive_key(
    store: &Path,
    salt: &[u8],
    create: bool,
) -> Result<Zeroizing<[u8; KEY_LEN]>, CredentialError> {
    if let Ok(passphrase) = std::env::var("QUOKKA_CREDENTIAL_PASSPHRASE") {
        let passphrase = Zeroizing::new(passphrase);
        let mut key = Zeroizing::new([0u8; KEY_LEN]);
        argon2::Argon2::default()
            .hash_password_into(passphrase.as_bytes(), salt, key.as_mut())
            .map_err(|e| CredentialError::File {
                path: store.to_path_buf(),
                detail: format!("key derivation failed: {e}"),
            })?;
        return Ok(key);
    }
    read_or_create_key_file(store, create)
}

fn read_or_create_key_file(
    store: &Path,
    create: bool,
) -> Result<Zeroizing<[u8; KEY_LEN]>, CredentialError> {
    let path = key_file_path(store);
    if path.exists() {
        let text = std::fs::read_to_string(&path).map_err(|e| CredentialError::File {
            path: path.clone(),
            detail: e.to_string(),
        })?;
        let bytes = hex_decode(text.trim()).ok_or_else(|| CredentialError::File {
            path: path.clone(),
            detail: "the key file is not 32 hex-encoded bytes".to_string(),
        })?;
        let array: [u8; KEY_LEN] = bytes.try_into().map_err(|_| CredentialError::File {
            path: path.clone(),
            detail: "the key file is not 32 hex-encoded bytes".to_string(),
        })?;
        return Ok(Zeroizing::new(array));
    }

    if !create {
        return Err(CredentialError::BadKey {
            path: store.to_path_buf(),
        });
    }

    let key = random_bytes::<KEY_LEN>(&path)?;
    write_private(&path, hex_encode(&key).as_bytes())?;
    Ok(Zeroizing::new(key))
}

/// Create or replace `path` readable only by its owner.
///
/// The mode is set *before* the bytes are written, so there is no window in which the
/// key or the ciphertext is world-readable.
fn write_private(path: &Path, bytes: &[u8]) -> Result<(), CredentialError> {
    use std::io::Write as _;

    if let Some(dir) = path.parent() {
        if !dir.as_os_str().is_empty() {
            std::fs::create_dir_all(dir).map_err(|e| CredentialError::File {
                path: dir.to_path_buf(),
                detail: e.to_string(),
            })?;
        }
    }

    let mut options = std::fs::OpenOptions::new();
    options.write(true).create(true).truncate(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt as _;
        options.mode(0o600);
    }

    let mut file = options.open(path).map_err(|e| CredentialError::File {
        path: path.to_path_buf(),
        detail: e.to_string(),
    })?;
    file.write_all(bytes).map_err(|e| CredentialError::File {
        path: path.to_path_buf(),
        detail: e.to_string(),
    })?;
    file.sync_all().map_err(|e| CredentialError::File {
        path: path.to_path_buf(),
        detail: e.to_string(),
    })
}

fn random_bytes<const N: usize>(context: &Path) -> Result<[u8; N], CredentialError> {
    let mut buf = [0u8; N];
    getrandom::fill(&mut buf).map_err(|e| CredentialError::File {
        path: context.to_path_buf(),
        detail: format!("the operating system would not supply random bytes: {e}"),
    })?;
    Ok(buf)
}

fn encrypt(key: &[u8; KEY_LEN], nonce: &[u8], plaintext: &[u8]) -> Option<Vec<u8>> {
    use chacha20poly1305::aead::{Aead, KeyInit, Payload};
    let cipher = chacha20poly1305::XChaCha20Poly1305::new_from_slice(key).ok()?;
    let nonce = chacha20poly1305::XNonce::try_from(nonce).ok()?;
    cipher
        .encrypt(
            &nonce,
            Payload {
                msg: plaintext,
                // Binding the ciphertext to the format marker means a file from a future
                // format cannot be fed to this one and silently decrypt.
                aad: FILE_MAGIC.as_bytes(),
            },
        )
        .ok()
}

fn decrypt(key: &[u8; KEY_LEN], nonce: &[u8], ciphertext: &[u8]) -> Option<Zeroizing<String>> {
    use chacha20poly1305::aead::{Aead, KeyInit, Payload};
    let cipher = chacha20poly1305::XChaCha20Poly1305::new_from_slice(key).ok()?;
    let nonce = chacha20poly1305::XNonce::try_from(nonce).ok()?;
    let plaintext = cipher
        .decrypt(
            &nonce,
            Payload {
                msg: ciphertext,
                aad: FILE_MAGIC.as_bytes(),
            },
        )
        .ok()?;
    let text = String::from_utf8(plaintext).ok()?;
    Some(Zeroizing::new(text))
}

fn hex_encode(bytes: &[u8]) -> String {
    use std::fmt::Write as _;
    let mut out = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        let _ = write!(out, "{b:02x}");
    }
    out
}

fn hex_decode(text: &str) -> Option<Vec<u8>> {
    let text = text.trim();
    if !text.len().is_multiple_of(2) {
        return None;
    }
    (0..text.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&text[i..i + 2], 16).ok())
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_reference_names_a_place_and_never_a_value() {
        assert_eq!(
            CredentialRef::parse("keyring", "prod").expect("keyring"),
            CredentialRef::Keyring {
                service: DEFAULT_SERVICE.to_string(),
                account: "prod".to_string()
            }
        );
        assert_eq!(
            CredentialRef::parse("keyring:acme/prod", "prod").expect("qualified"),
            CredentialRef::Keyring {
                service: "acme".to_string(),
                account: "prod".to_string()
            }
        );
        assert_eq!(
            CredentialRef::parse("env:PGPASSWORD", "prod").expect("env"),
            CredentialRef::Env {
                var: "PGPASSWORD".to_string()
            }
        );
        assert_eq!(
            CredentialRef::parse("none", "prod").expect("none"),
            CredentialRef::None
        );
        assert!(CredentialRef::parse("hunter2", "prod").is_err());
    }

    /// The fallback is a real encryption, so the password must not be findable in the
    /// bytes on disk — and it must come back out again.
    #[test]
    fn the_fallback_file_round_trips_without_storing_the_password_in_the_clear() {
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("credentials.enc");

        let entries: Entries = [("quokkaquery/prod".to_string(), "hunter2".to_string())]
            .into_iter()
            .collect();
        write_file(&path, &entries).expect("write");

        let bytes = std::fs::read(&path).expect("read");
        assert!(
            !String::from_utf8_lossy(&bytes).contains("hunter2"),
            "the credential file holds the password in the clear"
        );

        let back = read_file(&path).expect("read back");
        assert_eq!(
            back.get("quokkaquery/prod").map(String::as_str),
            Some("hunter2")
        );
    }

    #[test]
    fn a_file_whose_key_is_gone_fails_loudly_rather_than_returning_nothing() {
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("credentials.enc");
        write_file(
            &path,
            &[("a/b".to_string(), "pw".to_string())]
                .into_iter()
                .collect(),
        )
        .expect("write");

        std::fs::remove_file(key_file_path(&path)).expect("remove the key");
        let err = read_file(&path).expect_err("a missing key is not an empty store");
        assert!(matches!(err, CredentialError::BadKey { .. }), "{err:?}");
    }

    #[cfg(unix)]
    #[test]
    fn the_key_file_is_not_world_readable() {
        use std::os::unix::fs::PermissionsExt as _;
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("credentials.enc");
        write_file(&path, &Entries::new()).expect("write");

        for p in [path.clone(), key_file_path(&path)] {
            let mode = std::fs::metadata(&p)
                .expect("metadata")
                .permissions()
                .mode();
            assert_eq!(mode & 0o077, 0, "{} is readable by others", p.display());
        }
    }
}
