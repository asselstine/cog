use clap::Parser;
use cog::Config;
use cog::diagnostics::*;
use std::{
    error::Error,
    fmt,
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
    let master_key = ["abcdefghijklmnopqrstuvwxyz", "123456"].concat();
    let mut config = Config::parse_from([
        "cog",
        "--s3-bucket",
        "bucket",
        "--master-key",
        master_key.as_str(),
    ]);
    config.s3_endpoint = Some("https://user:pass@example.test/path?token=secret#secret".into());
    assert_eq!(safe_endpoint(&config), "https://example.test/path");
    config.s3_endpoint = None;
    assert_eq!(safe_endpoint(&config), "AWS default");
    config.s3_endpoint = Some("not a URL".into());
    assert_eq!(
        safe_endpoint(&config),
        "custom endpoint (invalid URL redacted)"
    );
}

#[test]
fn git_provider_material_is_never_reflected() {
    for secret in [
        [
            "-----BEGIN RSA ",
            "PRIVATE KEY----- secret -----END RSA PRIVATE KEY-----",
        ]
        .concat(),
        ["ghs_", "installationTokenSecret"].concat(),
        ["eyJhbGciOiJSUzI1NiJ9", ".jwt.signature"].concat(),
        ["Authorization: Basic ", "eC1hY2Nlc3MtdG9rZW46c2VjcmV0"].concat(),
        ["cog_git_", "derivedSecret"].concat(),
    ] {
        let rendered = safe_error(&Injected(secret.clone()));
        assert!(!rendered.contains(&secret));
        assert!(rendered.contains("redacted"));
    }
}

#[test]
fn credential_provider_selection_matches_s3_builder_precedence() {
    let selected = |names: &[&str]| credential_provider_class_from(|name| names.contains(&name));
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
