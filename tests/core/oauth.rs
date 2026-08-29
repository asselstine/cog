use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use cog::oauth::*;
use cog::{crypto::token_hash, db::Database};
use proptest::prelude::*;
use sha2::{Digest, Sha256};

#[test]
fn registration_is_bounded_canonical_and_reused() {
    let d = tempfile::tempdir().unwrap();
    let db = Database::open(&d.path().join("registration.db")).unwrap();
    let first = register(
        &db,
        RegistrationRequest {
            redirect_uris: vec!["http://localhost/b".into(), "http://localhost/a".into()],
            client_name: "  test client  ".into(),
        },
    )
    .unwrap();
    assert!(first.created);
    assert!(first.changed);
    assert_eq!(first.client_name, "test client");
    assert_eq!(
        first.redirect_uris,
        ["http://localhost/a", "http://localhost/b"]
    );
    let reused = register(
        &db,
        RegistrationRequest {
            redirect_uris: vec!["http://localhost/a".into(), "http://localhost/b".into()],
            client_name: "test client".into(),
        },
    )
    .unwrap();
    assert!(!reused.created);
    assert!(!reused.changed);
    assert_eq!(reused.client_id, first.client_id);

    for request in [
        RegistrationRequest {
            redirect_uris: vec!["http://localhost/cb".into(); 11],
            client_name: "test".into(),
        },
        RegistrationRequest {
            redirect_uris: vec!["http://localhost/cb".into()],
            client_name: "x".repeat(129),
        },
        RegistrationRequest {
            redirect_uris: vec![format!("http://localhost/{}", "x".repeat(2_049))],
            client_name: "test".into(),
        },
        RegistrationRequest {
            redirect_uris: vec![
                "http://localhost/duplicate".into(),
                "http://localhost/duplicate".into(),
            ],
            client_name: "test".into(),
        },
    ] {
        assert!(register(&db, request).is_err());
    }
}

#[test]
fn full_flow() {
    let d = tempfile::tempdir().unwrap();
    let db = Database::open(&d.path().join("d")).unwrap();
    let user = db.create_user("a@b.c", "x").unwrap();
    let reg = register(
        &db,
        RegistrationRequest {
            redirect_uris: vec!["http://localhost/cb".into()],
            client_name: "test".into(),
        },
    )
    .unwrap();
    let identity = db.create_identity(&user, "Personal").unwrap();
    db.bind_agent(&user, &identity, &reg.client_id).unwrap();
    let verifier = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789-._~";
    let challenge = URL_SAFE_NO_PAD.encode(Sha256::digest(verifier));
    let code = issue_code(
        &db,
        &reg.client_id,
        &user,
        "http://localhost/cb",
        "mcp",
        &challenge,
    )
    .unwrap();
    let token = redeem(
        &db,
        TokenRequest {
            grant_type: "authorization_code".into(),
            code: Some(code),
            client_id: reg.client_id.clone(),
            redirect_uri: Some("http://localhost/cb".into()),
            code_verifier: Some(verifier.into()),
            refresh_token: None,
            resource: None,
        },
    )
    .unwrap();
    assert_eq!(
        db.token_user(
            &token_hash(&token.access_token),
            chrono::Utc::now().timestamp()
        )
        .unwrap(),
        Some(user.clone())
    );
    let old_refresh = token.refresh_token.clone();
    let rotated = redeem(
        &db,
        TokenRequest {
            grant_type: "refresh_token".into(),
            code: None,
            client_id: reg.client_id.clone(),
            redirect_uri: None,
            code_verifier: None,
            refresh_token: Some(old_refresh.clone()),
            resource: None,
        },
    )
    .unwrap();
    assert_ne!(rotated.refresh_token, old_refresh);
    assert!(
        redeem(
            &db,
            TokenRequest {
                grant_type: "refresh_token".into(),
                code: None,
                client_id: reg.client_id.clone(),
                redirect_uri: None,
                code_verifier: None,
                refresh_token: Some(old_refresh),
                resource: None,
            }
        )
        .is_err(),
        "rotated refresh tokens cannot be replayed"
    );
    let clients = db.agent_clients(&user).unwrap();
    assert_eq!(clients[0].client_id, reg.client_id);
    let tokens = db.agent_tokens(&user).unwrap();
    assert_eq!(tokens.len(), 1);
    assert!(db.revoke_agent_token(&user, &tokens[0].token_id).unwrap());
    assert!(db.agent_tokens(&user).unwrap().is_empty());
    assert!(
        redeem(
            &db,
            TokenRequest {
                grant_type: "authorization_code".into(),
                code: Some("used".into()),
                client_id: "x".into(),
                redirect_uri: Some("http://localhost/cb".into()),
                code_verifier: Some("x".into()),
                refresh_token: None,
                resource: None,
            }
        )
        .is_err()
    );
    assert!(
        register(
            &db,
            RegistrationRequest {
                redirect_uris: vec![],
                client_name: "x".into()
            }
        )
        .is_err()
    );
    assert!(
        register(
            &db,
            RegistrationRequest {
                redirect_uris: vec!["http://example.com/cb".into()],
                client_name: "x".into()
            }
        )
        .is_err()
    );
    assert!(issue_code(&db, "bad", &user, "http://localhost/no", "mcp", "x").is_err());
    let defaulted: RegistrationRequest =
        serde_json::from_value(serde_json::json!({"redirect_uris":["http://localhost/cb"]}))
            .unwrap();
    assert_eq!(defaulted.client_name, "MCP client");
    assert!(
        issue_code(
            &db,
            &reg.client_id,
            &user,
            "http://localhost/cb",
            "unknown",
            "x"
        )
        .is_err()
    );
    assert!(issue_code(&db, &reg.client_id, &user, "http://localhost/cb", "mcp", "").is_err());
    for request in [
        TokenRequest {
            grant_type: "unknown".into(),
            code: None,
            client_id: reg.client_id.clone(),
            redirect_uri: None,
            code_verifier: None,
            refresh_token: None,
            resource: None,
        },
        TokenRequest {
            grant_type: "authorization_code".into(),
            code: None,
            client_id: reg.client_id.clone(),
            redirect_uri: None,
            code_verifier: None,
            refresh_token: None,
            resource: None,
        },
        TokenRequest {
            grant_type: "refresh_token".into(),
            code: None,
            client_id: reg.client_id.clone(),
            redirect_uri: None,
            code_verifier: None,
            refresh_token: None,
            resource: None,
        },
    ] {
        assert!(redeem(&db, request).is_err());
    }
}

#[test]
fn granular_and_integration_scopes_are_owner_validated() {
    let dir = tempfile::tempdir().unwrap();
    let db = Database::open(&dir.path().join("scope.db")).unwrap();
    let owner = db.create_user("owner@example.com", "hash").unwrap();
    let other = db.create_user("other@example.com", "hash").unwrap();
    db.register_client("client", None, "agent", &["http://localhost/cb".into()])
        .unwrap();
    let integration = db
        .create_integration(
            &owner,
            "Cloudflare",
            "http",
            &serde_json::json!({"url":"https://example.com/mcp"}),
            None,
        )
        .unwrap();
    let identity = db.list_identities(&owner).unwrap()[0].id.clone();
    db.bind_agent(&owner, &identity, "client").unwrap();
    let scope = format!("mcp integrations:read integration:{integration}");
    assert!(
        issue_code(
            &db,
            "client",
            &owner,
            "http://localhost/cb",
            &scope,
            "challenge"
        )
        .is_ok()
    );
    assert!(
        issue_code(
            &db,
            "client",
            &other,
            "http://localhost/cb",
            &scope,
            "challenge"
        )
        .is_err()
    );
    assert!(
        issue_code(
            &db,
            "client",
            &owner,
            "http://localhost/cb",
            "mcp integration:missing",
            "challenge"
        )
        .is_err()
    );
}

proptest! {
    #[test]
    fn registration_uri_validation_never_panics(uri in any::<String>()) {
        let directory = tempfile::tempdir().unwrap();
        let db = Database::open(&directory.path().join("oauth.db")).unwrap();
        let _ = register(&db, RegistrationRequest {
            redirect_uris: vec![uri],
            client_name: "property client".into(),
        });
    }

    #[test]
    fn pkce_challenges_are_deterministic(verifier in prop::collection::vec(any::<u8>(), 43..129)) {
        let first = URL_SAFE_NO_PAD.encode(Sha256::digest(&verifier));
        let second = URL_SAFE_NO_PAD.encode(Sha256::digest(&verifier));
        prop_assert_eq!(first, second);
    }
}
