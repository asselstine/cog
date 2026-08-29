use crate::Config;
use std::fmt;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum StartupPhase {
    StorageInitialization,
    ConditionalWriteProbe,
    LeaseAcquisition,
    Restore,
    DatabaseOpen,
    InitialReplication,
}

impl fmt::Display for StartupPhase {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::StorageInitialization => "storage initialization",
            Self::ConditionalWriteProbe => "conditional-write probing",
            Self::LeaseAcquisition => "lease acquisition",
            Self::Restore => "database restore",
            Self::DatabaseOpen => "local database initialization",
            Self::InitialReplication => "initial replication",
        })
    }
}

#[derive(Debug)]
pub struct StartupError {
    phase: StartupPhase,
    kind: &'static str,
    guidance: &'static str,
}

impl StartupError {
    pub fn new(phase: StartupPhase, error: &(dyn std::error::Error + 'static)) -> Self {
        let kind = classify_error(error);
        let guidance = match (phase, kind) {
            (_, "credentials expired") => {
                "refresh the AWS credentials or configure a renewable credential provider"
            }
            (_, "credentials unavailable or rejected") => {
                "verify the selected AWS credential provider and its permissions"
            }
            (StartupPhase::ConditionalWriteProbe, _) => {
                "verify bucket access and support for conditional create and update requests"
            }
            (StartupPhase::LeaseAcquisition, _) => {
                "verify bucket access and check whether another cog instance owns the lease"
            }
            (StartupPhase::Restore, _) => {
                "verify access to the configured prefix and the integrity of its LTX objects"
            }
            (StartupPhase::StorageInitialization, _) => {
                "verify the bucket, region, endpoint, TLS settings, and AWS credential configuration"
            }
            (StartupPhase::DatabaseOpen, _) => {
                "verify the data directory is writable and contains a valid SQLite database"
            }
            (StartupPhase::InitialReplication, _) => {
                "verify lease authority, bucket access, and the restored database state"
            }
        };
        Self {
            phase,
            kind,
            guidance,
        }
    }
}

impl fmt::Display for StartupError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "cog startup failed during {}: {}; {}",
            self.phase, self.kind, self.guidance
        )
    }
}

impl std::error::Error for StartupError {}

fn classify_error(error: &(dyn std::error::Error + 'static)) -> &'static str {
    let mut text = String::new();
    let mut current = Some(error);
    while let Some(item) = current {
        text.push_str(&item.to_string().to_ascii_lowercase());
        text.push(' ');
        current = item.source();
    }
    if text.contains("expiredtoken")
        || text.contains("expired token")
        || text.contains("expired credential")
    {
        "credentials expired"
    } else if text.contains("credential")
        || text.contains("accessdenied")
        || text.contains("signature")
        || text.contains("unauthorized")
        || text.contains("forbidden")
        || text.contains("metadata")
    {
        "credentials unavailable or rejected"
    } else if text.contains("timeout") || text.contains("timed out") {
        "storage request timed out"
    } else if text.contains("connect") || text.contains("dns") {
        "storage endpoint could not be reached"
    } else if text.contains("precondition") || text.contains("conditional") {
        "storage conditional-write requirement was not met"
    } else if text.contains("not found") || text.contains("nosuchbucket") {
        "bucket or object was not found"
    } else {
        "storage operation failed (provider details redacted)"
    }
}

/// Produce a bounded description suitable for logs. The returned value never
/// contains the provider's raw message, response body, headers, or error chain.
pub fn redacted_error(error: &(dyn std::error::Error + 'static)) -> &'static str {
    classify_error(error)
}

/// Render an error for an API response without reflecting provider-controlled
/// messages, bodies, headers, or nested error chains.
pub fn safe_error(error: &(dyn std::error::Error + 'static)) -> String {
    let kind = classify_error(error);
    match kind {
        "storage operation failed (provider details redacted)" => kind.to_owned(),
        _ => format!("{kind} (provider details redacted)"),
    }
}

/// Classify Git transport failures without retaining request data, provider
/// response bodies, authorization material, URLs, or the raw error chain.
pub fn safe_git_error(error: &(dyn std::error::Error + 'static)) -> &'static str {
    let mut text = String::new();
    let mut current = Some(error);
    while let Some(item) = current {
        text.push_str(&item.to_string().to_ascii_lowercase());
        text.push(' ');
        current = item.source();
    }
    if text.contains("pack") || text.contains("zlib") || text.contains("deflate") {
        "invalid Git pack stream"
    } else if text.contains("upstream discovery") {
        "upstream Git discovery failed"
    } else if text.contains("upstream git rpc") || text.contains("error sending request") {
        "upstream Git request failed"
    } else if text.contains("idle timeout") || text.contains("timed out") {
        "Git transport timed out"
    } else if text.contains("byte limit") || text.contains("stream limit") {
        "Git transport limit exceeded"
    } else if text.contains("client disconnected") || text.contains("input closed") {
        "Git client disconnected"
    } else if text.contains("grant") || text.contains("permission") || text.contains("revoked") {
        "Git authorization is no longer valid"
    } else {
        "Git transport operation failed"
    }
}

pub fn credential_provider_class() -> &'static str {
    credential_provider_class_from(|name| std::env::var_os(name).is_some())
}

fn credential_provider_class_from(mut is_set: impl FnMut(&str) -> bool) -> &'static str {
    // Keep this precedence in lockstep with object_store's AmazonS3Builder.
    // In particular, environment credentials are deliberately static even
    // when AWS_SESSION_TOKEN is present: changing the process environment is
    // not a supported renewal mechanism.
    if is_set("AWS_ACCESS_KEY_ID") || is_set("AWS_SECRET_ACCESS_KEY") {
        "environment/static credentials (not renewable)"
    } else if is_set("AWS_WEB_IDENTITY_TOKEN_FILE") && is_set("AWS_ROLE_ARN") {
        "web identity credentials (renewable)"
    } else if is_set("AWS_CONTAINER_CREDENTIALS_RELATIVE_URI")
        || (is_set("AWS_CONTAINER_CREDENTIALS_FULL_URI")
            && is_set("AWS_CONTAINER_AUTHORIZATION_TOKEN_FILE"))
    {
        "container credentials (renewable)"
    } else {
        "EC2 instance metadata credentials (renewable)"
    }
}

pub fn safe_endpoint(config: &Config) -> String {
    let Some(endpoint) = &config.s3_endpoint else {
        return "AWS default".to_owned();
    };
    let Ok(mut url) = url::Url::parse(endpoint) else {
        return "custom endpoint (invalid URL redacted)".to_owned();
    };
    let _ = url.set_username("");
    let _ = url.set_password(None);
    url.set_query(None);
    url.set_fragment(None);
    url.to_string()
}

#[cfg(test)]
mod tests {
    use super::*;
    use clap::Parser;
    use std::{
        error::Error,
        io::Write,
        sync::{Arc, Mutex},
    };

    #[derive(Clone)]
    struct Capture(Arc<Mutex<Vec<u8>>>);
    impl Write for Capture {
        fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
            self.0.lock().unwrap().extend_from_slice(bytes);
            Ok(bytes.len())
        }
        fn flush(&mut self) -> std::io::Result<()> {
            Ok(())
        }
    }

    #[derive(Debug)]
    struct Injected(String);
    impl fmt::Display for Injected {
        fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
            f.write_str(&self.0)
        }
    }
    impl std::error::Error for Injected {}

    #[derive(Debug)]
    struct Wrapped(Injected);
    impl fmt::Display for Wrapped {
        fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
            f.write_str("outer")
        }
    }
    impl std::error::Error for Wrapped {
        fn source(&self) -> Option<&(dyn Error + 'static)> {
            Some(&self.0)
        }
    }

    #[test]
    fn every_phase_classification_and_guidance_is_bounded() {
        let phases = [
            (
                StartupPhase::StorageInitialization,
                "storage initialization",
                "bucket",
            ),
            (
                StartupPhase::ConditionalWriteProbe,
                "conditional-write probing",
                "conditional",
            ),
            (StartupPhase::LeaseAcquisition, "lease acquisition", "lease"),
            (StartupPhase::Restore, "database restore", "LTX"),
            (
                StartupPhase::DatabaseOpen,
                "local database initialization",
                "SQLite",
            ),
            (
                StartupPhase::InitialReplication,
                "initial replication",
                "lease",
            ),
        ];
        for (phase, label, guidance) in phases {
            assert_eq!(phase.to_string(), label);
            let rendered = StartupError::new(phase, &Injected("opaque".into())).to_string();
            assert!(rendered.contains(label));
            assert!(rendered.contains(guidance));
        }

        let categories = [
            ("ExpiredToken secret", "credentials expired"),
            ("credential secret", "credentials unavailable or rejected"),
            ("request timed out secret", "storage request timed out"),
            ("DNS secret", "storage endpoint could not be reached"),
            (
                "precondition secret",
                "storage conditional-write requirement was not met",
            ),
            ("NoSuchBucket secret", "bucket or object was not found"),
            (
                "opaque secret",
                "storage operation failed (provider details redacted)",
            ),
        ];
        for (raw, expected) in categories {
            let error = Wrapped(Injected(raw.into()));
            assert_eq!(redacted_error(&error), expected);
            let safe = safe_error(&error);
            assert!(safe.starts_with(expected));
            assert!(!safe.contains("secret"));
        }
    }

    #[test]
    fn every_git_classification_is_bounded() {
        let categories = [
            ("zlib secret", "invalid Git pack stream"),
            ("upstream discovery secret", "upstream Git discovery failed"),
            ("upstream git rpc secret", "upstream Git request failed"),
            ("idle timeout secret", "Git transport timed out"),
            ("stream limit secret", "Git transport limit exceeded"),
            ("client disconnected secret", "Git client disconnected"),
            (
                "grant revoked secret",
                "Git authorization is no longer valid",
            ),
            ("opaque secret", "Git transport operation failed"),
        ];
        for (raw, expected) in categories {
            assert_eq!(safe_git_error(&Wrapped(Injected(raw.into()))), expected);
        }
    }

    #[test]
    fn credential_precedence_covers_partial_and_complete_providers() {
        let classify = |set: &[&str]| credential_provider_class_from(|name| set.contains(&name));
        assert_eq!(
            classify(&["AWS_ACCESS_KEY_ID"]),
            "environment/static credentials (not renewable)"
        );
        assert_eq!(
            classify(&["AWS_SECRET_ACCESS_KEY"]),
            "environment/static credentials (not renewable)"
        );
        assert_eq!(
            classify(&["AWS_WEB_IDENTITY_TOKEN_FILE", "AWS_ROLE_ARN"]),
            "web identity credentials (renewable)"
        );
        assert_eq!(
            classify(&["AWS_WEB_IDENTITY_TOKEN_FILE"]),
            "EC2 instance metadata credentials (renewable)"
        );
        assert_eq!(
            classify(&["AWS_CONTAINER_CREDENTIALS_RELATIVE_URI"]),
            "container credentials (renewable)"
        );
        assert_eq!(
            classify(&[
                "AWS_CONTAINER_CREDENTIALS_FULL_URI",
                "AWS_CONTAINER_AUTHORIZATION_TOKEN_FILE"
            ]),
            "container credentials (renewable)"
        );
        assert_eq!(
            classify(&["AWS_CONTAINER_CREDENTIALS_FULL_URI"]),
            "EC2 instance metadata credentials (renewable)"
        );
        assert_eq!(
            classify(&[]),
            "EC2 instance metadata credentials (renewable)"
        );
    }

    #[test]
    fn git_errors_are_bounded_and_do_not_retain_input() {
        let error = Injected("corrupt deflate stream token=recognizable-secret".into());
        assert_eq!(safe_git_error(&error), "invalid Git pack stream");
        assert!(!safe_git_error(&error).contains("recognizable-secret"));
    }

    #[test]
    fn startup_errors_do_not_retain_provider_secrets_or_response_bodies() {
        let secrets = [
            "AKIAIOSFODNN7EXAMPLE",
            "recognizable-session-token-secret",
            "AWS4-HMAC-SHA256 Credential=AKIASECRET, SignedHeaders=host, Signature=deadbeef",
            "<Error><Code>ExpiredToken</Code><Message>token recognizable-xml-secret</Message></Error>",
        ];
        for secret in secrets {
            let error = StartupError::new(StartupPhase::LeaseAcquisition, &Injected(secret.into()));
            let rendered = format!("{error:#}");
            assert!(!rendered.contains(secret));
            assert!(
                error.source().is_none(),
                "raw provider error must not enter the chain"
            );
        }
    }

    #[test]
    fn tracing_a_startup_error_does_not_emit_the_provider_error() {
        let secret = "recognizable-tracing-session-token";
        let error = StartupError::new(
            StartupPhase::ConditionalWriteProbe,
            &Injected(format!("Authorization: Bearer {secret}")),
        );
        let bytes = Arc::new(Mutex::new(Vec::new()));
        let writer = Capture(bytes.clone());
        let subscriber = tracing_subscriber::fmt()
            .without_time()
            .with_ansi(false)
            .with_writer(move || writer.clone())
            .finish();
        tracing::subscriber::with_default(subscriber, || {
            tracing::error!(%error, "startup aborted");
        });
        let output = String::from_utf8(bytes.lock().unwrap().clone()).unwrap();
        assert!(!output.contains(secret));
        assert!(output.contains("conditional-write probing"));
    }

    #[test]
    fn structured_provider_errors_keep_classification_but_drop_all_material() {
        let bodies = [
            r#"<Error><Code>ExpiredToken</Code><Message>AKIAIOSFODNN7EXAMPLE session=very-secret</Message><RequestId>abc</RequestId></Error>"#,
            r#"{"code":"AccessDenied","message":"Authorization: Bearer oauth-secret","access_key":"AKIASECRET","token":"session-secret"}"#,
        ];
        for body in bodies {
            let rendered = safe_error(&Injected(body.into()));
            assert!(rendered.contains("provider details redacted"));
            for secret in [
                "AKIA",
                "very-secret",
                "oauth-secret",
                "session-secret",
                "Authorization",
            ] {
                assert!(!rendered.contains(secret));
            }
        }
        assert!(safe_error(&Injected(bodies[0].into())).contains("credentials expired"));
        assert!(safe_error(&Injected(bodies[1].into())).contains("credentials unavailable"));
    }

    #[test]
    fn endpoint_drops_credentials_query_and_fragment() {
        let mut config = Config::parse_from([
            "cog",
            "--s3-bucket",
            "bucket",
            "--master-key",
            "abcdefghijklmnopqrstuvwxyz123456",
        ]);
        config.s3_endpoint = Some("https://user:pass@example.test/path?token=secret#secret".into());
        assert_eq!(safe_endpoint(&config), "https://example.test/path");
    }

    #[test]
    fn git_provider_material_is_never_reflected() {
        for secret in [
            "-----BEGIN RSA PRIVATE KEY----- secret -----END RSA PRIVATE KEY-----",
            "ghs_installationTokenSecret",
            "eyJhbGciOiJSUzI1NiJ9.jwt.signature",
            "Authorization: Basic eC1hY2Nlc3MtdG9rZW46c2VjcmV0",
            "cog_git_derivedSecret",
        ] {
            let rendered = safe_error(&Injected(secret.into()));
            assert!(!rendered.contains(secret));
            assert!(rendered.contains("redacted"));
        }
    }

    #[test]
    fn credential_provider_selection_matches_s3_builder_precedence() {
        let selected =
            |names: &[&str]| credential_provider_class_from(|name| names.contains(&name));
        assert_eq!(
            selected(&[
                "AWS_ACCESS_KEY_ID",
                "AWS_WEB_IDENTITY_TOKEN_FILE",
                "AWS_ROLE_ARN"
            ]),
            "environment/static credentials (not renewable)"
        );
        assert_eq!(
            selected(&["AWS_WEB_IDENTITY_TOKEN_FILE", "AWS_ROLE_ARN"]),
            "web identity credentials (renewable)"
        );
        assert_eq!(
            selected(&["AWS_CONTAINER_CREDENTIALS_RELATIVE_URI"]),
            "container credentials (renewable)"
        );
        assert_eq!(
            selected(&[
                "AWS_CONTAINER_CREDENTIALS_FULL_URI",
                "AWS_CONTAINER_AUTHORIZATION_TOKEN_FILE"
            ]),
            "container credentials (renewable)"
        );
        assert_eq!(
            selected(&["AWS_PROFILE", "AWS_SHARED_CREDENTIALS_FILE"]),
            "EC2 instance metadata credentials (renewable)"
        );
    }
}
