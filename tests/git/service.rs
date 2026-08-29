use cog::git::UpstreamAuthorization;
use cog::git::service::*;

#[test]
fn transports_and_authorization_variants() {
    assert_eq!(Transport::Http.metric_label(), "http");
    assert_eq!(Transport::Ssh.metric_label(), "ssh");
    let client = reqwest::Client::new();
    let cases = [
        (
            UpstreamAuthorization::Basic {
                username: crate::git::SecretValue::new("alice"),
                password: crate::git::SecretValue::new("secret"),
            },
            Some("Basic YWxpY2U6c2VjcmV0"),
        ),
        (
            UpstreamAuthorization::Bearer {
                token: crate::git::SecretValue::new("token"),
            },
            Some("Bearer token"),
        ),
        (UpstreamAuthorization::Anonymous, None),
    ];
    for (authorization, expected) in cases {
        let request = apply_authorization(client.get("http://example.test"), &authorization)
            .build()
            .unwrap();
        assert_eq!(
            request
                .headers()
                .get(reqwest::header::AUTHORIZATION)
                .map(|value| value.to_str().unwrap()),
            expected
        );
    }
}

#[test]
fn service_preamble_is_stripped_exactly() {
    let body = b"001e# service=git-upload-pack\n0000000eversion 2\n";
    assert_eq!(
        strip_service_preamble(body, "git-upload-pack").unwrap(),
        b"000eversion 2\n"
    );
    assert!(strip_service_preamble(body, "git-receive-pack").is_err());
    assert!(strip_service_preamble(b"ffff", "git-upload-pack").is_err());
    assert!(strip_service_preamble(b"0001xxxx", "git-upload-pack").is_err());
    assert!(strip_service_preamble(b"zzzzxxxx", "git-upload-pack").is_err());
    assert!(
        strip_service_preamble(b"001e# service=git-upload-pack\nxxxx", "git-upload-pack").is_err()
    );
    assert_eq!(
        strip_service_preamble(b"000eversion 2\n0000", "git-upload-pack").unwrap(),
        b"000eversion 2\n0000"
    );
}
