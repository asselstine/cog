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
