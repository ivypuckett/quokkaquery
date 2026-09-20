//! `quokka credential set | delete | status`.
//!
//! §5 says credentials live in the OS keyring with an encrypted file behind it; this is
//! the door to that store. Without it the Postgres and MySQL drivers would be usable
//! only by someone willing to drive `secret-tool` or Keychain Access by hand, which is
//! not a daily driver.
//!
//! Two rules shape the whole file:
//!
//! - **The secret never comes from `argv`.** It is read from a terminal without echo, or
//!   from stdin when something is piping it in. A password on a command line lands in
//!   shell history and in every `ps` on the machine, which is a worse leak than the one
//!   the keyring exists to prevent.
//! - **Nothing here ever prints a credential**, not even to confirm what was stored.
//!   `status` answers "is there one, and where", which is the question you can act on.

use anyhow::{Context, Result};
use quokka_core::{credential, Engine, Secret};
use serde_json::{Map, Value as Json};

use crate::format::{print_records, Format};

const COLUMNS: &[&str] = &["connection", "credential", "backend", "stored", "detail"];

/// Look a connection up and hand back where its credential lives.
fn reference_for(engine: &Engine, connection: &str) -> Result<credential::CredentialRef> {
    let cfg = engine.registry().get(connection).ok_or_else(|| {
        anyhow::anyhow!("no connection named {connection:?}; check your config file")
    })?;
    Ok(cfg.credential.clone())
}

pub fn set(engine: &Engine, connection: &str) -> Result<u8> {
    let reference = reference_for(engine, connection)?;
    let secret = read_secret()?;
    if secret.is_empty() {
        anyhow::bail!("nothing was entered; the credential was left as it was");
    }

    let backend = credential::store(connection, &reference, &secret)
        .with_context(|| format!("storing the credential for {connection:?}"))?;

    eprintln!(
        "stored the credential for {connection:?} in the {} ({})",
        match backend {
            credential::Backend::OsKeyring => "OS keyring",
            credential::Backend::EncryptedFile => "encrypted file",
            credential::Backend::Environment => "environment",
            credential::Backend::None => "nowhere",
        },
        reference.as_config_string()
    );
    if backend == credential::Backend::EncryptedFile {
        // The one thing a user of the fallback has to know, said at the moment it starts
        // being true rather than in a document they will not read.
        eprintln!(
            "note: no OS keyring was reachable, so this went into the encrypted file at {}. \
             Without $QUOKKA_CREDENTIAL_PASSPHRASE its key is a 0600 file beside it, which \
             makes file permissions the security boundary.",
            credential::credential_file_path()
                .map(|p| p.display().to_string())
                .unwrap_or_else(|_| "the data directory".to_string())
        );
    }
    Ok(crate::exit::OK)
}

pub fn delete(engine: &Engine, connection: &str) -> Result<u8> {
    let reference = reference_for(engine, connection)?;
    let removed = credential::delete(&reference)
        .with_context(|| format!("deleting the credential for {connection:?}"))?;

    if removed {
        eprintln!("removed the credential for {connection:?}");
    } else {
        eprintln!("there was no stored credential for {connection:?}");
    }
    Ok(crate::exit::OK)
}

/// Where each connection's credential lives, and whether one is there.
///
/// This *does* reach into the keyring, which may unlock a keychain or raise a prompt —
/// which is why it is its own command rather than a column in `connections list`.
pub fn status(engine: &Engine, connection: Option<&str>, format: Format) -> Result<u8> {
    let configs: Vec<_> = match connection {
        Some(name) => vec![engine
            .registry()
            .get(name)
            .ok_or_else(|| anyhow::anyhow!("no connection named {name:?}"))?
            .clone()],
        None => engine.registry().iter().cloned().collect(),
    };

    let mut records = Vec::with_capacity(configs.len());
    for cfg in &configs {
        let mut m = Map::new();
        m.insert("connection".into(), Json::String(cfg.name.clone()));
        m.insert(
            "credential".into(),
            Json::String(cfg.credential.as_config_string()),
        );
        m.insert(
            "backend".into(),
            Json::String(cfg.credential.backend().as_str().into()),
        );
        match credential::resolve(&cfg.credential) {
            // The boolean, never the value.
            Ok(found) => {
                m.insert("stored".into(), Json::Bool(found.is_some()));
            }
            // `stored` is null rather than false: "the store would not answer" and
            // "there is nothing there" are different facts, and only one of them is
            // something to go and fix.
            Err(e) => {
                m.insert("stored".into(), Json::Null);
                m.insert("detail".into(), Json::String(e.to_string()));
            }
        }
        records.push(Json::Object(m));
    }

    let mut envelope = Map::new();
    envelope.insert("count".into(), Json::from(records.len()));
    print_records(format, envelope, "credentials", records, COLUMNS)?;
    Ok(crate::exit::OK)
}

/// A terminal prompt with no echo, or a line from stdin when something is piping.
fn read_secret() -> Result<Secret> {
    if std::io::IsTerminal::is_terminal(&std::io::stdin()) {
        let first = rpassword::prompt_password("credential: ").context("reading the credential")?;
        let again = rpassword::prompt_password("again: ").context("reading the credential")?;
        if first != again {
            anyhow::bail!("the two entries did not match; nothing was stored");
        }
        return Ok(Secret::new(first));
    }

    let mut line = String::new();
    std::io::BufRead::read_line(&mut std::io::stdin().lock(), &mut line)
        .context("reading the credential from stdin")?;
    // A trailing newline from `echo` is not part of the password; anything else the
    // caller typed is.
    Ok(Secret::new(line.trim_end_matches(['\n', '\r'])))
}
