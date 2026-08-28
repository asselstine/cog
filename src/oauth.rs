use crate::{
    crypto::{random_token, token_hash},
    db::Database,
};
use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::HashSet;

const MAX_CLIENT_NAME_BYTES: usize = 128;
const MAX_REDIRECT_URIS: usize = 10;
const MAX_REDIRECT_URI_BYTES: usize = 2_048;
const MAX_REGISTRATION_METADATA_BYTES: usize = 16 * 1_024;
const MAX_UNUSED_CLIENTS: u64 = 1_000;

#[derive(Debug, Deserialize)]
pub struct RegistrationRequest {
    pub redirect_uris: Vec<String>,
    #[serde(default = "default_client_name")]
    pub client_name: String,
}
fn default_client_name() -> String {
    "MCP client".into()
}
#[derive(Debug, Serialize)]
pub struct RegistrationResponse {
    pub client_id: String,
    pub client_name: String,
    pub redirect_uris: Vec<String>,
    pub token_endpoint_auth_method: &'static str,
}
pub struct RegistrationResult {
    pub response: RegistrationResponse,
    pub created: bool,
    pub changed: bool,
}
impl std::ops::Deref for RegistrationResult {
    type Target = RegistrationResponse;

    fn deref(&self) -> &Self::Target {
        &self.response
    }
}
#[derive(Debug, Deserialize)]
pub struct TokenRequest {
    pub grant_type: String,
    pub code: Option<String>,
    pub client_id: String,
    pub redirect_uri: Option<String>,
    pub code_verifier: Option<String>,
    pub refresh_token: Option<String>,
    pub resource: Option<String>,
}
#[derive(Debug, Serialize)]
pub struct TokenResponse {
    pub access_token: String,
    pub token_type: &'static str,
    pub expires_in: u64,
    pub refresh_token: String,
    pub scope: String,
}

pub fn register(
    db: &Database,
    mut request: RegistrationRequest,
) -> anyhow::Result<RegistrationResult> {
    request.client_name = request.client_name.trim().to_owned();
    anyhow::ensure!(!request.client_name.is_empty(), "client_name required");
    anyhow::ensure!(
        request.client_name.len() <= MAX_CLIENT_NAME_BYTES,
        "client_name is too long"
    );
    anyhow::ensure!(!request.redirect_uris.is_empty(), "redirect_uris required");
    anyhow::ensure!(
        request.redirect_uris.len() <= MAX_REDIRECT_URIS,
        "too many redirect URIs"
    );
    let metadata_bytes =
        request.client_name.len() + request.redirect_uris.iter().map(String::len).sum::<usize>();
    anyhow::ensure!(
        metadata_bytes <= MAX_REGISTRATION_METADATA_BYTES,
        "client registration metadata is too large"
    );
    let mut unique = HashSet::new();
    for uri in &request.redirect_uris {
        anyhow::ensure!(
            uri.len() <= MAX_REDIRECT_URI_BYTES,
            "redirect URI is too long"
        );
        anyhow::ensure!(unique.insert(uri), "duplicate redirect URI");
        validate_redirect_uri(uri)?;
    }
    request.redirect_uris.sort();
    let id = random_token(24);
    let (client_id, created, changed) = db.register_or_reuse_public_client(
        &id,
        &request.client_name,
        &request.redirect_uris,
        chrono::Utc::now().timestamp(),
        MAX_UNUSED_CLIENTS,
    )?;
    Ok(RegistrationResult {
        response: RegistrationResponse {
            client_id,
            client_name: request.client_name,
            redirect_uris: request.redirect_uris,
            token_endpoint_auth_method: "none",
        },
        created,
        changed,
    })
}

pub fn validate_redirect_uri(uri: &str) -> anyhow::Result<()> {
    let url = url::Url::parse(uri)?;
    anyhow::ensure!(
        url.fragment().is_none(),
        "redirect URI cannot contain a fragment"
    );
    anyhow::ensure!(
        url.username().is_empty() && url.password().is_none(),
        "redirect URI cannot contain user information"
    );
    let loopback = matches!(url.host_str(), Some("localhost" | "127.0.0.1" | "::1"));
    anyhow::ensure!(
        (url.scheme() == "https" && url.host_str().is_some())
            || (url.scheme() == "http" && loopback),
        "redirect URI must use HTTPS except loopback"
    );
    Ok(())
}
pub fn issue_code(
    db: &Database,
    client: &str,
    user: &str,
    redirect: &str,
    scope: &str,
    challenge: &str,
) -> anyhow::Result<String> {
    let scopes = scope.split_ascii_whitespace().collect::<Vec<_>>();
    anyhow::ensure!(!scopes.is_empty(), "scope required");
    for requested in &scopes {
        let supported = matches!(
            *requested,
            "mcp"
                | "admin"
                | "integrations:read"
                | "integrations:write"
                | "agents:read"
                | "agents:write"
                | "audit:read"
                | "git:read"
                | "git:write"
        ) || requested
            .strip_prefix("integration:")
            .is_some_and(|id| !id.is_empty() && db.integration(id, user).ok().flatten().is_some());
        anyhow::ensure!(supported, "unsupported or unauthorized scope: {requested}");
    }
    anyhow::ensure!(
        db.client_redirect_allowed(client, redirect)?,
        "redirect URI is not registered"
    );
    anyhow::ensure!(!challenge.is_empty(), "PKCE S256 challenge required");
    let code = random_token(32);
    db.store_code(
        &token_hash(&code),
        client,
        user,
        redirect,
        scope,
        challenge,
        chrono::Utc::now().timestamp() + 300,
    )?;
    Ok(code)
}
pub fn redeem(db: &Database, request: TokenRequest) -> anyhow::Result<TokenResponse> {
    if request.grant_type == "refresh_token" {
        return refresh(db, request);
    }
    anyhow::ensure!(
        request.grant_type == "authorization_code",
        "unsupported grant type"
    );
    let code = request
        .code
        .ok_or_else(|| anyhow::anyhow!("code required"))?;
    let redirect_uri = request
        .redirect_uri
        .ok_or_else(|| anyhow::anyhow!("redirect_uri required"))?;
    let verifier = request
        .code_verifier
        .ok_or_else(|| anyhow::anyhow!("code_verifier required"))?;
    let row = db
        .redeem_code(&token_hash(&code))?
        .ok_or_else(|| anyhow::anyhow!("invalid authorization code"))?;
    let (client, user, redirect, scope, challenge, expires) = row;
    anyhow::ensure!(
        client == request.client_id
            && redirect == redirect_uri
            && expires >= chrono::Utc::now().timestamp(),
        "invalid or expired authorization code"
    );
    let actual = URL_SAFE_NO_PAD.encode(Sha256::digest(verifier.as_bytes()));
    let valid: bool = subtle::ConstantTimeEq::ct_eq(actual.as_bytes(), challenge.as_bytes()).into();
    anyhow::ensure!(valid, "PKCE verification failed");
    let access = random_token(32);
    let refresh = random_token(32);
    db.store_access_token(
        &token_hash(&access),
        &client,
        &user,
        &scope,
        chrono::Utc::now().timestamp() + 3600,
        Some(&token_hash(&refresh)),
        Some(chrono::Utc::now().timestamp() + 30 * 24 * 3600),
    )?;
    Ok(TokenResponse {
        access_token: access,
        token_type: "Bearer",
        expires_in: 3600,
        refresh_token: refresh,
        scope,
    })
}

fn refresh(db: &Database, request: TokenRequest) -> anyhow::Result<TokenResponse> {
    let old = request
        .refresh_token
        .ok_or_else(|| anyhow::anyhow!("refresh_token required"))?;
    let access = random_token(32);
    let refresh = random_token(32);
    let now = chrono::Utc::now().timestamp();
    let Some((_user, scope)) = db.rotate_refresh_token(
        &token_hash(&old),
        &request.client_id,
        now,
        &token_hash(&access),
        now + 3600,
        &token_hash(&refresh),
        now + 30 * 24 * 3600,
    )?
    else {
        anyhow::bail!("invalid, expired, or replayed refresh token")
    };
    Ok(TokenResponse {
        access_token: access,
        token_type: "Bearer",
        expires_in: 3600,
        refresh_token: refresh,
        scope,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use proptest::prelude::*;

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
}
