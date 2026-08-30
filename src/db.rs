use rusqlite::{Connection, OptionalExtension, params};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::{
    path::Path,
    sync::{Arc, Mutex},
};
use uuid::Uuid;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum StorageMode {
    Local,
    S3,
}

impl StorageMode {
    fn as_str(self) -> &'static str {
        match self {
            Self::Local => "local",
            Self::S3 => "s3",
        }
    }
}

#[derive(Clone)]
pub struct Database(Arc<Mutex<Connection>>);
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Integration {
    pub id: String,
    pub user_id: String,
    pub identity_id: String,
    pub name: String,
    pub provider_name: Option<String>,
    pub provider_account: Option<String>,
    pub transport: String,
    pub config: serde_json::Value,
    pub enabled: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Identity {
    pub id: String,
    pub user_id: String,
    pub name: String,
    pub created_at: i64,
    pub updated_at: i64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Agent {
    pub id: String,
    pub identity_id: String,
    pub oauth_client_id: String,
    pub registered_name: String,
    pub display_name: String,
    pub created_at: i64,
    pub updated_at: i64,
    pub last_used_at: Option<i64>,
}

#[derive(Debug, Clone)]
pub struct GitHubAppSetup {
    pub user_id: String,
    pub integration_id: String,
    pub expires_at: i64,
    pub app_slug: Option<String>,
    pub manifest_completed_at: Option<i64>,
}
pub type AuthorizationCodeRow = (String, String, String, String, String, i64);
pub type UpstreamOAuthStateRow = (String, String, String, String, i64, Option<String>);
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UpstreamOAuthClient {
    pub client_id: String,
    pub client_secret_ciphertext: Option<String>,
    pub authorization_endpoint: String,
    pub token_endpoint: String,
    /// Empty in the database means the authorization server did not advertise
    /// scopes and the integration did not explicitly request one.
    pub scope: String,
    pub resource: Option<String>,
    pub issuer: Option<String>,
}
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UpstreamOAuthToken {
    pub access_token_ciphertext: String,
    pub refresh_token_ciphertext: Option<String>,
    pub token_type: String,
    pub scope: String,
    pub expires_at: Option<i64>,
    pub refresh_expires_at: Option<i64>,
}
#[derive(Debug, Clone, Serialize)]
pub struct AuditEvent {
    pub id: i64,
    pub occurred_at: i64,
    pub actor: Option<String>,
    pub action: String,
    pub target: Option<String>,
    pub outcome: String,
    pub details: serde_json::Value,
}
#[derive(Debug, Clone, Serialize)]
pub struct AgentClient {
    pub client_id: String,
    pub client_name: String,
    pub redirect_uris: Vec<String>,
    pub created_at: i64,
    pub scopes: Vec<String>,
    pub integration_ids: Vec<String>,
}
#[derive(Debug, Clone, Serialize)]
pub struct AgentToken {
    pub token_id: String,
    pub client_id: String,
    pub scope: String,
    pub issued_at: i64,
    pub expires_at: i64,
    pub refresh_expires_at: Option<i64>,
    pub last_used_at: Option<i64>,
    pub integration_ids: Vec<String>,
    pub refresh_capable: bool,
}
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TokenContext {
    pub user_id: String,
    pub agent_id: String,
    pub client_id: String,
    pub identity_id: String,
    pub scopes: Vec<String>,
    pub integration_ids: Vec<String>,
}

#[derive(Debug, Clone, Serialize)]
pub struct SshKeyRecord {
    pub id: String,
    pub purpose: String,
    pub algorithm: String,
    pub public_key: String,
    #[serde(skip_serializing)]
    pub private_ciphertext: String,
    pub created_at: i64,
    pub active: bool,
    pub retirement_time: Option<i64>,
}

#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
pub struct AgentSshKey {
    pub agent_id: String,
    pub public_key: String,
    pub fingerprint: String,
    pub lease_expires_at: i64,
    pub created_at: i64,
    pub updated_at: i64,
    pub revoked_at: Option<i64>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AgentSshBinding {
    pub user_id: String,
    pub identity_id: String,
    pub agent_id: String,
    pub client_id: String,
    pub public_key: String,
    pub fingerprint: String,
    pub lease_expires_at: i64,
}
type RefreshTokenRow = (Vec<u8>, String, String, String, Option<i64>);
fn git_repo_row(row: &rusqlite::Row<'_>) -> rusqlite::Result<crate::git::GitRepository> {
    Ok(crate::git::GitRepository {
        id: row.get(0)?,
        user_id: row.get(1)?,
        integration_id: row.get(2)?,
        provider_repository_id: row.get(3)?,
        display_name: row.get(4)?,
        upstream_url: row.get(5)?,
        metadata: serde_json::from_str(&row.get::<_, String>(6)?).unwrap_or_default(),
    })
}

fn normalize_display_name(value: &str) -> anyhow::Result<String> {
    let normalized = value.split_whitespace().collect::<Vec<_>>().join(" ");
    anyhow::ensure!(!normalized.is_empty(), "name is required");
    anyhow::ensure!(normalized.chars().count() <= 128, "name is too long");
    anyhow::ensure!(
        normalized.chars().all(|c| !c.is_control()),
        "name contains control characters"
    );
    Ok(normalized)
}
fn split_grant(scope: &str) -> (String, String) {
    if let Some(id) = scope.strip_prefix("integration:") {
        ("integration".into(), id.into())
    } else {
        (scope.into(), String::new())
    }
}
fn agent_row(row: &rusqlite::Row<'_>) -> rusqlite::Result<Agent> {
    Ok(Agent {
        id: row.get(0)?,
        identity_id: row.get(1)?,
        oauth_client_id: row.get(2)?,
        registered_name: row.get(3)?,
        display_name: row.get(4)?,
        created_at: row.get(5)?,
        updated_at: row.get(6)?,
        last_used_at: row.get(7)?,
    })
}
fn agent_for_client_conn(conn: &Connection, client: &str) -> anyhow::Result<Option<Agent>> {
    Ok(conn.query_row("SELECT a.id,a.identity_id,a.oauth_client_id,c.registered_name,a.display_name,a.created_at,a.updated_at,a.last_used_at FROM agents a JOIN oauth_clients c ON c.client_id=a.oauth_client_id WHERE a.oauth_client_id=?",[client],agent_row).optional()?)
}
fn agent_for_client_tx(
    tx: &rusqlite::Transaction<'_>,
    client: &str,
) -> anyhow::Result<Option<Agent>> {
    Ok(tx.query_row("SELECT a.id,a.identity_id,a.oauth_client_id,c.registered_name,a.display_name,a.created_at,a.updated_at,a.last_used_at FROM agents a JOIN oauth_clients c ON c.client_id=a.oauth_client_id WHERE a.oauth_client_id=?",[client],agent_row).optional()?)
}

mod audit;
mod git;
mod identity;
mod integrations;
mod migrations;
mod oauth;
mod ssh;

pub use migrations::SCHEMA_VERSION;
