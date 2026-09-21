//! SSO credentials, through `aws-config` (ARCHITECTURE §3.2).
//!
//! v1 leans on the AWS CLI rather than reimplementing it: `aws-config` resolves
//! `sso_session` profiles from `~/.aws/config` and the token cache `aws sso login`
//! writes, refresh included. What this module adds is the sentence §3.2 asks for by
//! name — **an expired token gets "run `aws sso login --profile X`", not a protocol
//! error** — and the decision to find that out at connect time rather than twenty
//! seconds into a query.
//!
//! The in-process OIDC device-authorization flow (driving `aws-sdk-ssooidc` ourselves,
//! so the AWS CLI is not required at all) is M7 and is deliberately not here.
//!
//! ## Why the credentials are resolved eagerly
//!
//! Nothing forces it: the SDK would resolve them lazily at the first call, and the
//! failure would surface as a `DispatchFailure` wrapped around a `ProviderError` several
//! layers down, at the bottom of a query the user has been waiting for. Resolving in
//! `connect` turns that into a connection error with an instruction in it — which is the
//! same trade `connect_timeout` already makes for a mistyped host (§config): a typo
//! should be a message, not half a minute of silence.

use aws_config::{BehaviorVersion, Region, SdkConfig};
use aws_credential_types::provider::ProvideCredentials;
use quokka_core::{AthenaConfig, ConnectionConfig, DriverError};

/// Build the SDK configuration for one connection.
///
/// The HTTPS client is constructed by hand rather than taken from the SDK's default,
/// and that is the §8 decision the workspace manifest explains: the default resolves to
/// `rustls-aws-lc`, which pulls `aws-lc-sys` — a C library wanting a C compiler *and*
/// cmake. `rustls` over `ring` is the same stack `sqlx` already puts in the tree, with
/// the same native root store, so Athena adds no build dependency at all.
pub async fn load(cfg: &ConnectionConfig, athena: &AthenaConfig) -> Result<SdkConfig, DriverError> {
    let https = aws_smithy_http_client::Builder::new()
        .tls_provider(aws_smithy_http_client::tls::Provider::Rustls(
            aws_smithy_http_client::tls::rustls_provider::CryptoMode::Ring,
        ))
        .build_https();

    let mut loader = aws_config::defaults(BehaviorVersion::latest())
        .http_client(https)
        .region(Region::new(athena.region.clone()))
        // The connection's own `connect_timeout`, applied where it means the same thing
        // it means for a wire-protocol driver: how long a *connection attempt* may take
        // before it is called a failure. The statement's own budget is the engine's
        // `timeout`, and an Athena query legitimately runs for minutes, so no read
        // timeout is set here — that would cancel long queries at ten seconds.
        .timeout_config(
            aws_smithy_types::timeout::TimeoutConfig::builder()
                .connect_timeout(cfg.connect_timeout)
                .build(),
        );

    if let Some(profile) = &athena.profile {
        loader = loader.profile_name(profile.as_str());
    }

    Ok(loader.load().await)
}

/// Resolve credentials once, so that an expired SSO session is a sentence rather than a
/// protocol error.
pub async fn verify(
    sdk: &SdkConfig,
    cfg: &ConnectionConfig,
    athena: &AthenaConfig,
) -> Result<(), DriverError> {
    let provider = sdk
        .credentials_provider()
        .ok_or_else(|| DriverError::Connect {
            connection: cfg.name.clone(),
            detail: advice_for(AthenaAuth::NoProvider, athena.profile.as_deref()),
        })?;

    let resolved = tokio::time::timeout(cfg.connect_timeout, provider.provide_credentials()).await;

    match resolved {
        Ok(Ok(_)) => Ok(()),
        Ok(Err(e)) => {
            // The chain's text, not just the head: `CredentialsError`'s own `Display` is
            // usually "an error occurred while loading credentials", and every word that
            // identifies *which* error lives in the source below it.
            let detail = error_chain(&e);
            Err(DriverError::Connect {
                connection: cfg.name.clone(),
                detail: format!(
                    "{}\n\n(AWS said: {detail})",
                    advice_for(classify(&detail), athena.profile.as_deref())
                ),
            })
        }
        Err(_) => Err(DriverError::Connect {
            connection: cfg.name.clone(),
            detail: format!(
                "resolving AWS credentials took longer than {:?}. If this profile uses \
                 SSO, `aws sso login{}` refreshes it; otherwise raise `connect_timeout` \
                 on this connection.",
                cfg.connect_timeout,
                profile_flag(athena.profile.as_deref()),
            ),
        }),
    }
}

/// What went wrong with the credentials, as far as the text can say.
///
/// A classification rather than a match on error types, because the SDK's own types do
/// not distinguish these: an expired SSO token, a profile that does not exist and a
/// missing region all arrive as `CredentialsError::ProviderError` with a message inside.
/// Splitting on the message is doing what the message is for; being wrong about it costs
/// a less useful sentence and never a wrong action.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AthenaAuth {
    /// An SSO session that has run out and cannot refresh itself.
    ExpiredSso,
    /// No `sso_session`, no keys, nothing the chain could use.
    NotFound,
    /// The named profile is not in `~/.aws/config`.
    NoSuchProfile,
    /// The SDK produced no credentials provider at all.
    NoProvider,
    /// Something else — a network failure, a permissions error, an unfamiliar message.
    Other,
}

/// Read the SDK's error text and say which of the five it is.
///
/// Exposed so the table test can put real AWS error strings through it: that test is the
/// only thing standing between this and a sentence that stops appearing the day an SDK
/// release rewords something.
pub fn classify(detail: &str) -> AthenaAuth {
    let text = detail.to_ascii_lowercase();

    // Order matters: an expired-token message usually also mentions "sso", and a
    // missing-profile message usually also mentions "profile".
    if text.contains("expired") || text.contains("token has expired") || text.contains("refresh") {
        return AthenaAuth::ExpiredSso;
    }
    if text.contains("profile") && (text.contains("was not defined") || text.contains("not found"))
    {
        return AthenaAuth::NoSuchProfile;
    }
    if text.contains("no credentials")
        || text.contains("could not load credentials")
        || text.contains("credentialsnotloaded")
        || text.contains("no providers in chain")
    {
        return AthenaAuth::NotFound;
    }
    AthenaAuth::Other
}

/// The sentence a person is shown, given what went wrong and which profile they named.
///
/// §3.2 asks for one message in particular and this is it: an expired token says `aws
/// sso login --profile X`. The rest exist so that the *other* four ways this fails do
/// not fall back to a protocol error either.
pub fn advice_for(auth: AthenaAuth, profile: Option<&str>) -> String {
    let flag = profile_flag(profile);
    let named = match profile {
        Some(p) => format!("profile {p:?}"),
        None => "the default profile".to_string(),
    };

    match auth {
        AthenaAuth::ExpiredSso => format!(
            "the AWS SSO session for {named} has expired. Run `aws sso login{flag}` and \
             try again.\n\nQuokkaQuery reads the token cache the AWS CLI writes and \
             refreshes it when it can; it does not open a browser itself (the in-process \
             device flow is a later version)."
        ),
        AthenaAuth::NoSuchProfile => format!(
            "{named} is not in ~/.aws/config. `aws configure sso` creates an \
             `sso_session` profile; `aws configure list-profiles` shows what is there \
             now. The name in the config file's `profile = \"…\"` has to match one of \
             them."
        ),
        AthenaAuth::NotFound | AthenaAuth::NoProvider => format!(
            "no AWS credentials could be found for {named}. For SSO, run `aws sso \
             login{flag}` — and check that the profile names an `sso_session` in \
             ~/.aws/config. QuokkaQuery stores no AWS credential of its own: an Athena \
             connection is `credential = \"none\"` and authenticates through the AWS \
             SDK's own chain."
        ),
        AthenaAuth::Other => format!(
            "AWS credentials for {named} could not be resolved. If this profile uses \
             SSO, `aws sso login{flag}` is the usual fix."
        ),
    }
}

fn profile_flag(profile: Option<&str>) -> String {
    match profile {
        Some(p) => format!(" --profile {p}"),
        None => String::new(),
    }
}

/// Every layer of an error's `source` chain, joined.
fn error_chain(e: &(dyn std::error::Error + 'static)) -> String {
    let mut parts = vec![e.to_string()];
    let mut source = e.source();
    while let Some(next) = source {
        parts.push(next.to_string());
        source = next.source();
    }
    parts.join(": ")
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Real error text from the SDK, so the classifier is tested against what it will
    /// actually be handed rather than against what this file imagines.
    #[test]
    fn an_expired_sso_session_is_recognized_from_what_the_sdk_says() {
        for text in [
            "profile (analytics) - the SSO session has expired or is invalid",
            "error loading credentials: the SSO token has expired",
            "Token refresh failed: refresh token is expired",
            "ExpiredToken: The security token included in the request is expired",
        ] {
            assert_eq!(
                classify(text),
                AthenaAuth::ExpiredSso,
                "should have been read as an expired session: {text}"
            );
        }
    }

    #[test]
    fn a_missing_profile_and_a_missing_credential_read_differently() {
        assert_eq!(
            classify("profile `analytics` was not defined"),
            AthenaAuth::NoSuchProfile
        );
        assert_eq!(
            classify("no providers in chain provided credentials"),
            AthenaAuth::NotFound
        );
        assert_eq!(
            classify("dispatch failure: io error: connection refused"),
            AthenaAuth::Other
        );
    }

    /// §3.2's sentence, asserted literally. If this stops naming the command, the
    /// deliverable has quietly stopped being met.
    #[test]
    fn an_expired_token_names_the_command_that_fixes_it() {
        let message = advice_for(AthenaAuth::ExpiredSso, Some("analytics"));
        assert!(
            message.contains("aws sso login --profile analytics"),
            "{message}"
        );
        assert!(
            !message.contains("DispatchFailure") && !message.contains("ProviderError"),
            "the point is that it is not a protocol error: {message}"
        );
    }

    #[test]
    fn with_no_profile_named_the_command_has_no_flag() {
        let message = advice_for(AthenaAuth::ExpiredSso, None);
        assert!(message.contains("aws sso login"), "{message}");
        assert!(!message.contains("--profile"), "{message}");
    }

    #[test]
    fn a_missing_credential_says_where_athena_credentials_come_from() {
        let message = advice_for(AthenaAuth::NotFound, Some("analytics"));
        assert!(message.contains("credential = \"none\""), "{message}");
        assert!(
            message.contains("aws sso login --profile analytics"),
            "{message}"
        );
    }
}
