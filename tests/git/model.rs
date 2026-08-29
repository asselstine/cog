use cog::git::model::*;
use url::Url;
#[test]
fn repository_ids_are_strict() {
    assert!(!valid_repository_id("../x"));
    assert!(valid_repository_id(&uuid::Uuid::new_v4().to_string()));
}
#[test]
fn secrets_redact() {
    let s = SecretValue::new("secret");
    assert_eq!(format!("{s:?}"), "[REDACTED]");
    assert_eq!(format!("{s}"), "[REDACTED]");
    assert_eq!(
        format!("{:?}", UpstreamAuthorization::Anonymous),
        "UpstreamAuthorization([REDACTED])"
    );
}

#[test]
fn upstream_urls_are_canonical_and_credential_free() {
    let valid = Url::parse("https://github.com/owner/repo.git").unwrap();
    validate_upstream(&valid, "GitHub.COM", false).unwrap();
    for invalid in [
        "http://github.com/owner/repo.git",
        "https://user:secret@github.com/owner/repo.git",
        "https://example.com/owner/repo.git",
        "https://github.com/owner/repo.git#secret",
    ] {
        assert!(validate_upstream(&Url::parse(invalid).unwrap(), "github.com", false).is_err());
    }
    validate_upstream(
        &Url::parse("http://127.0.0.1/repo.git").unwrap(),
        "127.0.0.1",
        true,
    )
    .unwrap();
}

#[tokio::test]
async fn network_policy_rejects_private_destinations() {
    assert!(
        validate_resolved_network(&Url::parse("http://127.0.0.1/repo").unwrap(), false)
            .await
            .is_err()
    );
    validate_resolved_network(&Url::parse("http://127.0.0.1/repo").unwrap(), true)
        .await
        .unwrap();
    assert!(
        validate_resolved_network(&Url::parse("http://[::1]/repo").unwrap(), false)
            .await
            .is_err()
    );
}
