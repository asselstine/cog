use crate::{
    Config,
    crypto::{SecretBox, token_hash},
    db::{Database, StorageMode, UpstreamOAuthClient, UpstreamOAuthToken},
    diagnostics::{
        StartupError, StartupPhase, credential_provider_class, redacted_error, safe_endpoint,
        safe_error, safe_git_error,
    },
    git::providers::{GitProvider, github::GitHubProvider},
    git::{GitOperation, RepositoryReference, ResolvedRepository},
    lease::{LeaseGuard, probe_conditional_writes},
    ltx::Replicator,
    mcp::{self, RpcRequest, RpcResponse},
    oauth,
    runtime::CodeRuntime,
    upstream::{Catalog, HttpMcp, StdioMcp, Tool, ToolProvider, UpstreamInsufficientScope},
};
use anyhow::Context;
use argon2::{
    Argon2, PasswordHash, PasswordHasher, PasswordVerifier,
    password_hash::{SaltString, rand_core::OsRng},
};
use axum::{
    Json, Router,
    extract::{DefaultBodyLimit, Query},
    extract::{Form, Path, State},
    http::{HeaderMap, StatusCode, header},
    response::{Html, IntoResponse, Redirect, Response},
    routing::{get, post},
};
use futures_util::StreamExt;
use object_store::{ObjectStore, aws::AmazonS3Builder, path::Path as ObjectPath};
use russh::server::{Msg as SshMsg, Server as _, Session as SshSession};
use russh::{Channel, ChannelId};
use rust_embed::RustEmbed;
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use std::{
    collections::{HashMap, HashSet, VecDeque},
    net::{IpAddr, SocketAddr},
    sync::{
        Arc,
        atomic::{AtomicBool, AtomicU64, Ordering},
    },
    time::{Duration, Instant},
};
use tokio::io::{AsyncReadExt, AsyncWriteExt};

#[derive(Default)]
pub struct Metrics {
    pub oauth_failures: AtomicU64,
    pub execution_failures: AtomicU64,
    pub v8_limit_hits: AtomicU64,
    pub upstream_calls: AtomicU64,
    pub upstream_failures: AtomicU64,
    pub ssh_handshakes: AtomicU64,
    pub ssh_auth_success: AtomicU64,
    pub ssh_auth_denied: AtomicU64,
    pub ssh_active_sessions: AtomicU64,
    pub ssh_read_operations: AtomicU64,
    pub ssh_write_operations: AtomicU64,
    pub ssh_request_bytes: AtomicU64,
    pub ssh_response_bytes: AtomicU64,
    pub ssh_timeouts: AtomicU64,
    pub ssh_limit_rejections: AtomicU64,
    pub ssh_upstream_failures: AtomicU64,
    pub ssh_key_registrations: AtomicU64,
    pub ssh_key_lease_renewals: AtomicU64,
}

#[derive(Default)]
pub struct ClientStreamLimiter {
    pub active: std::sync::Mutex<HashMap<String, usize>>,
}
pub struct ClientStreamPermit {
    limiter: Arc<ClientStreamLimiter>,
    client: String,
}
impl ClientStreamLimiter {
    pub fn try_acquire(
        self: &Arc<Self>,
        client: &str,
        maximum: usize,
    ) -> Option<ClientStreamPermit> {
        let mut active = self.active.lock().ok()?;
        let count = active.entry(client.to_owned()).or_default();
        if *count >= maximum {
            return None;
        }
        *count += 1;
        Some(ClientStreamPermit {
            limiter: self.clone(),
            client: client.to_owned(),
        })
    }
}
impl Drop for ClientStreamPermit {
    fn drop(&mut self) {
        if let Ok(mut active) = self.limiter.active.lock()
            && let Some(count) = active.get_mut(&self.client)
        {
            *count -= 1;
            if *count == 0 {
                active.remove(&self.client);
            }
        }
    }
}

#[derive(RustEmbed)]
#[folder = "frontend/dist"]
pub struct Frontend;

pub struct MeasuredProvider {
    pub inner: Arc<dyn ToolProvider>,
    pub metrics: Arc<Metrics>,
}

pub struct PolicyProvider {
    pub inner: Arc<dyn ToolProvider>,
    pub allow: Option<HashSet<String>>,
    pub deny: HashSet<String>,
}

pub struct OAuthStepUpProvider {
    pub inner: Arc<dyn ToolProvider>,
    pub app: App,
    pub user: String,
    pub integration: String,
}

pub struct AdminProvider {
    pub app: App,
    pub auth: AuthContext,
}

pub struct GitControlProvider {
    pub app: App,
    pub auth: AuthContext,
}

pub fn admin_tool(name: &str, description: &str) -> Tool {
    let (input_schema, read_only, destructive, idempotent, open_world) = match name {
        "integrations_list" | "agents_list" | "tokens_list" | "agent_get_self" => (
            json!({"type":"object","properties":{},"additionalProperties":false}),
            true,
            false,
            true,
            false,
        ),
        "agent_update_self" => (
            json!({"type":"object","properties":{"display_name":{"type":"string","maxLength":128}},"required":["display_name"],"additionalProperties":false}),
            false,
            false,
            true,
            false,
        ),
        "integration_get" => (
            json!({"type":"object","properties":{"id":{"type":"string"}},"required":["id"],"additionalProperties":false}),
            true,
            false,
            true,
            false,
        ),
        "github_app_setup_status" => (
            json!({"type":"object","properties":{"id":{"type":"string"}},"required":["id"],"additionalProperties":false}),
            true,
            false,
            true,
            false,
        ),
        "github_app_setup_start" => (
            json!({"type":"object","properties":{"name":{"type":"string"}},"required":["name"],"additionalProperties":false}),
            false,
            false,
            false,
            true,
        ),
        "integration_create" => (
            json!({"type":"object","properties":{"name":{"type":"string"},"transport":{"type":"string","enum":["http","sse","stdio","git"]},"config":{"type":"object"},"headers":{"type":"object","additionalProperties":{"type":"string"}}},"required":["name","transport","config"],"additionalProperties":false}),
            false,
            false,
            false,
            true,
        ),
        "integration_update" => (
            json!({"type":"object","properties":{"id":{"type":"string"},"name":{"type":"string"},"config":{"type":"object"},"enabled":{"type":"boolean"},"headers":{"type":"object","additionalProperties":{"type":"string"}}},"required":["id"],"additionalProperties":false}),
            false,
            false,
            false,
            true,
        ),
        "integration_set_enabled" => (
            json!({"type":"object","properties":{"id":{"type":"string"},"enabled":{"type":"boolean"}},"required":["id","enabled"],"additionalProperties":false}),
            false,
            false,
            true,
            false,
        ),
        "integration_authorize" => (
            json!({"type":"object","properties":{"id":{"type":"string"}},"required":["id"],"additionalProperties":false}),
            false,
            false,
            false,
            true,
        ),
        "integration_disconnect"
        | "integration_reconnect"
        | "integration_delete"
        | "agent_revoke"
        | "token_revoke" => (
            json!({"type":"object","properties":{"id":{"type":"string"}},"required":["id"],"additionalProperties":false}),
            false,
            true,
            true,
            false,
        ),
        "identity_grant_revoke" => (
            json!({"type":"object","properties":{"client_id":{"type":"string"},"integration_id":{"type":"string"}},"required":["client_id","integration_id"],"additionalProperties":false}),
            false,
            true,
            true,
            false,
        ),
        "audit_list" => (
            json!({"type":"object","properties":{"limit":{"type":"integer","minimum":1,"maximum":1000,"default":100,"description":"Maximum number of recent audit events to return."}},"additionalProperties":false}),
            true,
            false,
            true,
            false,
        ),
        _ => (json!({"type":"object"}), false, true, false, true),
    };
    let mut extra = serde_json::Map::new();
    extra.insert("annotations".into(), json!({"readOnlyHint":read_only,"destructiveHint":destructive,"idempotentHint":idempotent,"openWorldHint":open_world}));
    let required_scope = if name == "integrations_list" {
        "mcp"
    } else {
        admin_required_scope(name).unwrap_or("mcp")
    };
    let security_schemes = json!([{"type":"oauth2","scopes":[required_scope]}]);
    extra.insert("securitySchemes".into(), security_schemes.clone());
    extra.insert("_meta".into(), json!({"securitySchemes":security_schemes}));
    Tool {
        name: name.into(),
        description: Some(description.into()),
        input_schema,
        extra,
    }
}

pub fn upstream_connection_state(
    a: &App,
    integration: &crate::db::Integration,
) -> (&'static str, bool) {
    if integration.transport == "git"
        || integration.config.get("kind").and_then(Value::as_str) == Some("git")
    {
        let provider = integration
            .config
            .get("providerConfig")
            .and_then(Value::as_object);
        let configured = provider.is_some_and(|provider| {
            provider
                .get("appId")
                .and_then(Value::as_str)
                .is_some_and(|value| !value.is_empty())
                && provider
                    .get("installationId")
                    .and_then(Value::as_str)
                    .is_some_and(|value| !value.is_empty())
        }) && a
            .db
            .integration_secret(&integration.id, &integration.user_id)
            .ok()
            .flatten()
            .is_some();
        return if configured {
            ("configured", true)
        } else {
            ("setup_required", false)
        };
    }
    if !integration
        .config
        .get("oauth")
        .is_some_and(|value| !value.is_null())
    {
        return ("configured", true);
    }
    let Ok(Some(token)) = a.db.upstream_oauth_token(&integration.id) else {
        return ("disconnected", false);
    };
    let now = chrono::Utc::now().timestamp();
    if token.expires_at.is_none_or(|expires| expires > now + 30)
        || (token.refresh_token_ciphertext.is_some()
            && token.refresh_expires_at.is_none_or(|expires| expires > now))
    {
        ("connected", true)
    } else {
        ("expired", false)
    }
}

fn safe_integration(a: &App, integration: crate::db::Integration, access: bool) -> Value {
    let required_scope = format!("integration:{}", integration.id);
    let (status, connected) = upstream_connection_state(a, &integration);
    json!({"id":integration.id,"name":integration.name,"transport":integration.transport,"enabled":integration.enabled,"config":redact_value(integration.config),"upstreamConnected":connected,"upstreamStatus":status,"clientAccessGranted":access,"requiredScope":required_scope})
}

pub fn redact_value(value: Value) -> Value {
    match value {
        Value::Object(map) => Value::Object(
            map.into_iter()
                .filter_map(|(key, value)| {
                    let lower = key.to_ascii_lowercase();
                    (!lower.contains("secret")
                        && !lower.contains("token")
                        && !lower.contains("ciphertext")
                        && lower != "headers"
                        && lower != "authorization")
                        .then(|| (key, redact_value(value)))
                })
                .collect(),
        ),
        Value::Array(values) => Value::Array(values.into_iter().map(redact_value).collect()),
        other => other,
    }
}

#[async_trait::async_trait]
impl ToolProvider for AdminProvider {
    async fn tools(&self) -> anyhow::Result<Vec<Tool>> {
        // Code-mode discovery must include operations that need progressive
        // consent. Authorization is enforced at call time so a client can
        // discover and describe a tool before receiving its exact scope
        // challenge.
        Ok(self
            .advertised_tools()
            .await?
            .into_iter()
            .map(|mut tool| {
                let required_scope = admin_required_scope(&tool.name).unwrap_or("mcp");
                let access_granted = matches!(
                    tool.name.as_str(),
                    "integrations_list" | "agent_get_self" | "agent_update_self"
                ) || self.auth.allows(required_scope);
                tool.extra
                    .insert("x-cog-clientAccessGranted".into(), json!(access_granted));
                tool.extra
                    .insert("x-cog-requiredScope".into(), json!(required_scope));
                tool
            })
            .collect())
    }

    async fn advertised_tools(&self) -> anyhow::Result<Vec<Tool>> {
        Ok(vec![
            admin_tool(
                "agent_get_self",
                "Read the authenticated agent's immutable IDs and display name.",
            ),
            admin_tool(
                "agent_update_self",
                "Rename the authenticated agent without changing its identity or authorization.",
            ),
            admin_tool(
                "integrations_list",
                "List every integration with separate upstream-provider connection and calling-client access-grant status, without credentials.",
            ),
            admin_tool(
                "integration_get",
                "Inspect one integration by immutable id without credentials.",
            ),
            admin_tool("integration_create", "Create an integration."),
            admin_tool(
                "github_app_setup_start",
                "Create a pending GitHub integration and return a one-time browser URL that creates the GitHub App, stores its credentials, and continues to repository installation.",
            ),
            admin_tool(
                "github_app_setup_status",
                "Inspect GitHub App creation and installation status without returning credentials.",
            ),
            admin_tool(
                "integration_update",
                "Update an integration by immutable id.",
            ),
            admin_tool(
                "integration_disconnect",
                "Disconnect the upstream provider by atomically removing OAuth tokens, client registration secrets, pending authorization state, and static authentication headers. The integration ID, configuration, and downstream agent grants are preserved. This operation is idempotent.",
            ),
            admin_tool(
                "integration_reconnect",
                "Deprecated compatibility operation: destructively disconnect provider credentials, then start authorization. Use integration_disconnect followed by integration_authorize. It cannot grant this calling client downstream access.",
            ),
            admin_tool(
                "integration_authorize",
                "Connect cog to an upstream provider. Returns alreadyConnected when valid credentials exist; otherwise returns a one-time provider OAuth URL that must not be prefetched. This does not grant the calling agent access.",
            ),
            admin_tool(
                "integration_set_enabled",
                "Enable or disable an integration.",
            ),
            admin_tool(
                "integration_delete",
                "Permanently delete an integration, including its immutable ID, provider credentials, pending authorization state, and every downstream client grant. Use integration_disconnect to preserve configuration and grants.",
            ),
            admin_tool("agents_list", "List authorized agents."),
            admin_tool(
                "tokens_list",
                "List token lifecycle and grants without token values.",
            ),
            admin_tool("agent_revoke", "Revoke an agent and all its credentials."),
            admin_tool("token_revoke", "Revoke one token by public token id."),
            admin_tool(
                "identity_grant_revoke",
                "Immediately revoke one immutable integration grant from all client tokens and refresh access.",
            ),
            admin_tool("audit_list", "Read recent audit events."),
        ])
    }

    async fn call(&self, name: &str, args: Value) -> anyhow::Result<Value> {
        let id = || {
            args.get("id")
                .and_then(Value::as_str)
                .ok_or_else(|| anyhow::anyhow!("id is required"))
        };
        match name {
            "agent_get_self" if self.auth.allows("mcp") => Ok(serde_json::to_value(
                self.app
                    .db
                    .agent_for_client(&self.auth.client)?
                    .ok_or_else(|| anyhow::anyhow!("agent not found"))?,
            )?),
            "agent_update_self" if self.auth.allows("mcp") => {
                let name = args
                    .get("display_name")
                    .and_then(Value::as_str)
                    .ok_or_else(|| anyhow::anyhow!("display_name is required"))?;
                anyhow::ensure!(
                    self.app.db.rename_self(&self.auth.agent, name)?,
                    "agent not found"
                );
                self.app.db.record_audit(Some(&self.auth.user),"agent.rename",Some(&self.auth.agent),"success",&json!({"identity_id":self.auth.identity,"agent_id":self.auth.agent,"client_id":self.auth.client}))?;
                Ok(serde_json::to_value(
                    self.app
                        .db
                        .agent_for_client(&self.auth.client)?
                        .ok_or_else(|| anyhow::anyhow!("agent not found"))?,
                )?)
            }
            "integrations_list"
                if self.auth.allows("mcp") || self.auth.allows("integrations:read") =>
            {
                Ok(Value::Array(
                    self.app
                        .db
                        .list_integrations(&self.auth.user)?
                        .into_iter()
                        .map(|integration| {
                            let access = self.auth.scopes.contains("admin")
                                || self.auth.integrations.contains(&integration.id);
                            safe_integration(&self.app, integration, access)
                        })
                        .collect(),
                ))
            }
            "integration_get" if self.auth.allows("integrations:read") => self
                .app
                .db
                .integration(id()?, &self.auth.user)?
                .map(|integration| {
                    let access = self.auth.scopes.contains("admin")
                        || self.auth.integrations.contains(&integration.id);
                    safe_integration(&self.app, integration, access)
                })
                .ok_or_else(|| anyhow::anyhow!("integration not found")),
            "agents_list" if self.auth.allows("agents:read") => Ok(serde_json::to_value(
                self.app.db.agent_clients(&self.auth.user)?,
            )?),
            "tokens_list" if self.auth.allows("agents:read") => Ok(serde_json::to_value(
                self.app.db.agent_tokens(&self.auth.user)?,
            )?),
            "audit_list" if self.auth.allows("audit:read") => {
                let limit = args.get("limit").and_then(Value::as_u64).unwrap_or(100);
                anyhow::ensure!(
                    (1..=1000).contains(&limit),
                    "limit must be between 1 and 1000"
                );
                Ok(serde_json::to_value(
                    self.app
                        .db
                        .audit_events_for_user(&self.auth.user, limit as u32)?,
                )?)
            }
            "integration_create" if self.auth.allows("integrations:write") => {
                admin_create(&self.app, &self.auth.user, args).await
            }
            "github_app_setup_start" if self.auth.allows("integrations:write") => {
                admin_github_app_setup_start(&self.app, &self.auth.user, args).await
            }
            "github_app_setup_status" if self.auth.allows("integrations:read") => {
                admin_github_app_setup_status(&self.app, &self.auth.user, id()?).await
            }
            "integration_update" if self.auth.allows("integrations:write") => {
                admin_update(&self.app, &self.auth.user, id()?.to_owned(), args).await
            }
            "integration_set_enabled" if self.auth.allows("integrations:write") => {
                let enabled = args
                    .get("enabled")
                    .and_then(Value::as_bool)
                    .ok_or_else(|| anyhow::anyhow!("enabled is required"))?;
                admin_update(
                    &self.app,
                    &self.auth.user,
                    id()?.to_owned(),
                    json!({"enabled":enabled}),
                )
                .await
            }
            "integration_reconnect" if self.auth.allows("integrations:write") => {
                admin_reconnect(&self.app, &self.auth.user, id()?).await
            }
            "integration_disconnect" if self.auth.allows("integrations:write") => {
                admin_disconnect(&self.app, &self.auth.user, id()?).await
            }
            "integration_authorize" if self.auth.allows("integrations:write") => {
                admin_authorize(&self.app, &self.auth.user, id()?).await
            }
            "integration_delete" if self.auth.allows("integrations:write") => {
                admin_delete(&self.app, &self.auth.user, id()?).await
            }
            "agent_revoke" if self.auth.allows("agents:write") => {
                admin_revoke_client(&self.app, &self.auth.user, id()?).await
            }
            "token_revoke" if self.auth.allows("agents:write") => {
                admin_revoke_token(&self.app, &self.auth.user, id()?).await
            }
            "identity_grant_revoke" if self.auth.allows("agents:write") => {
                let client = args
                    .get("client_id")
                    .and_then(Value::as_str)
                    .ok_or_else(|| anyhow::anyhow!("client_id is required"))?;
                let integration = args
                    .get("integration_id")
                    .and_then(Value::as_str)
                    .ok_or_else(|| anyhow::anyhow!("integration_id is required"))?;
                admin_revoke_grant(&self.app, &self.auth.user, client, integration).await
            }
            name if admin_required_scope(name).is_some() => {
                Err(crate::authz::InsufficientScope::one(
                    admin_required_scope(name).expect("checked above"),
                )
                .into())
            }
            _ => anyhow::bail!("unknown or unauthorized administration tool"),
        }
    }
}

fn git_control_tool(name: &str, description: &str) -> Tool {
    let (input_schema, read_only, idempotent, open_world) = match name {
        "repository_access" => (
            json!({"type":"object","properties":{
                "integrationId":{"type":"string","description":"Immutable ID of the configured GitHub integration. Use integrations_list to discover it; do not use its display name."},
                "repository":{"type":"string","description":"GitHub repository reference to resolve, normally owner/name. This may contact GitHub and records the resolved repository grant."}
            },"required":["integrationId","repository"],"additionalProperties":false}),
            false,
            true,
            true,
        ),
        "ssh_key_status" => (
            json!({"type":"object","properties":{
                "publicKey":{"type":"string","description":"Exact canonical OpenSSH Ed25519 public key registered by this OAuth-bound agent. Never send the private key."}
            },"required":["publicKey"],"additionalProperties":false}),
            true,
            true,
            false,
        ),
        "ssh_key_register" => (
            json!({"type":"object","properties":{
                "publicKey":{"type":"string","description":"Exact canonical OpenSSH Ed25519 public key for this OAuth-bound agent. The private key stays local."}
            },"required":["publicKey"],"additionalProperties":false}),
            false,
            false,
            false,
        ),
        "ssh_key_lease_renew" => (
            json!({"type":"object","properties":{
                "publicKey":{"type":"string","description":"The exact registered canonical OpenSSH Ed25519 public key whose internal lease should be renewed."}
            },"required":["publicKey"],"additionalProperties":false}),
            false,
            false,
            false,
        ),
        _ => (
            json!({"type":"object","properties":{},"additionalProperties":false}),
            false,
            false,
            false,
        ),
    };
    let security_schemes = json!([{"type":"oauth2","scopes":["mcp"]}]);
    Tool {
        name: name.into(),
        description: Some(description.into()),
        input_schema,
        extra: serde_json::from_value(json!({
            "annotations":{
                "readOnlyHint":read_only,
                "destructiveHint":false,
                "idempotentHint":idempotent,
                "openWorldHint":open_world
            },
            "securitySchemes":security_schemes,
            "_meta":{"securitySchemes":security_schemes}
        }))
        .unwrap_or_default(),
    }
}

fn ssh_advertisement(app: &App, repository_id: &str) -> Option<Value> {
    if !app.ssh_ready.load(Ordering::Acquire) {
        return None;
    }
    let keys = app.ssh_keys.as_ref()?;
    let keys = keys.read().ok()?;
    let host = app.config.ssh_public_host.as_deref()?;
    let port = app
        .config
        .ssh_public_port
        .unwrap_or(app.config.ssh_listen?.port());
    let host_field = if port == 22 {
        host.to_owned()
    } else {
        format!("[{host}]:{port}")
    };
    let public_key = keys.host.public_key().to_openssh().ok()?;
    Some(json!({
        "available":true,
        "url":format!("ssh://git@{host}:{port}/{repository_id}"),
        "keyRegistrationTool":"ssh_key_register",
        "keyStatusTool":"ssh_key_status",
        "keyLeaseRenewalTool":"ssh_key_lease_renew",
        "keyLeaseTtlSeconds":app.config.ssh_key_lease_ttl_secs,
        "publicHost":host,
        "publicPort":port,
        "hostKeyFingerprint":crate::git::ssh::fingerprint(keys.host.public_key()),
        "knownHosts":format!("{host_field} {public_key}"),
        "requiredPrograms":["git","ssh"]
    }))
}

pub async fn git_provider(
    a: &App,
    integration: &crate::db::Integration,
) -> anyhow::Result<Arc<dyn GitProvider>> {
    if let Some(p) = a.git_providers.lock().await.get(&integration.id).cloned() {
        return Ok(p);
    }
    anyhow::ensure!(
        integration.transport == "git"
            || integration.config.get("kind").and_then(Value::as_str) == Some("git"),
        "integration is not Git"
    );
    anyhow::ensure!(
        integration.config.get("provider").and_then(Value::as_str) == Some("github"),
        "unsupported Git provider"
    );
    let pc = integration
        .config
        .get("providerConfig")
        .and_then(Value::as_object)
        .ok_or_else(|| anyhow::anyhow!("providerConfig is required"))?;
    let secret =
        a.db.integration_secret(&integration.id, &integration.user_id)?
            .ok_or_else(|| anyhow::anyhow!("Git integration is disconnected"))?;
    let opened = a.secrets.open(&secret)?;
    let private_key = serde_json::from_slice::<Value>(&opened)
        .ok()
        .and_then(|v| {
            v.get("privateKey")
                .and_then(Value::as_str)
                .map(str::to_owned)
        })
        .unwrap_or_else(|| String::from_utf8_lossy(&opened).into_owned());
    let provider: Arc<dyn GitProvider> = Arc::new(GitHubProvider::new(
        pc.get("appId")
            .and_then(Value::as_str)
            .unwrap_or_default()
            .to_owned(),
        pc.get("installationId")
            .and_then(Value::as_str)
            .unwrap_or_default()
            .to_owned(),
        integration
            .config
            .get("host")
            .and_then(Value::as_str)
            .unwrap_or("github.com")
            .to_owned(),
        private_key.as_bytes(),
    )?);
    a.git_providers
        .lock()
        .await
        .insert(integration.id.clone(), provider.clone());
    Ok(provider)
}

#[async_trait::async_trait]
impl ToolProvider for GitControlProvider {
    async fn tools(&self) -> anyhow::Result<Vec<Tool>> {
        let mut tools = vec![git_control_tool(
            "repository_access",
            "Resolve a GitHub repository and return its COG SSH remote plus pinned host key. Reuse the agent's existing Ed25519 identity, register its public key once with ssh_key_register, and renew only its internal authorization lease with ssh_key_lease_renew. The private key remains local and unchanged. Access is controlled by the live key lease, repository grant, integration, and this client's authorization.",
        )];
        if self.app.ssh_keys.is_some() && self.app.ssh_ready.load(Ordering::Acquire) {
            tools.push(git_control_tool(
                "ssh_key_status",
                "Check whether this OAuth-bound agent's registered Ed25519 public key has a live internal SSH authorization lease.",
            ));
            tools.push(git_control_tool(
                "ssh_key_register",
                "Register this OAuth-bound agent's existing Ed25519 public key and start its internal authorization lease. This never accepts, creates, or replaces a private key.",
            ));
            tools.push(git_control_tool(
                "ssh_key_lease_renew",
                "Extend the internal authorization lease for this OAuth-bound agent's exact registered Ed25519 public key. The keypair and local files do not change.",
            ));
        }
        Ok(tools)
    }
    async fn call(&self, name: &str, args: Value) -> anyhow::Result<Value> {
        match name {
            "repository_access" => {
                // Fence stale owners before repository resolution performs any
                // provider I/O, then prove authority again under the mutation
                // lock immediately before committing local state.
                self.app.lease.assert_live()?;
                let integration_id = args
                    .get("integrationId")
                    .and_then(Value::as_str)
                    .ok_or_else(|| anyhow::anyhow!("integrationId is required"))?;
                if !self.auth.allows_integration(integration_id) {
                    return Err(crate::authz::InsufficientScope {
                        scopes: vec![format!("integration:{integration_id}")],
                    }
                    .into());
                }
                let integration = self
                    .app
                    .db
                    .integration(integration_id, &self.auth.user)?
                    .ok_or_else(|| anyhow::anyhow!("integration not found"))?;
                let repository = args
                    .get("repository")
                    .and_then(Value::as_str)
                    .ok_or_else(|| anyhow::anyhow!("repository is required"))?;
                let provider_config = integration
                    .config
                    .get("providerConfig")
                    .and_then(Value::as_object);
                if integration.config.get("setupStatus").is_some()
                    && provider_config
                        .and_then(|config| config.get("installationId"))
                        .and_then(Value::as_str)
                        .is_none_or(str::is_empty)
                {
                    let mut result =
                        admin_github_app_setup_status(&self.app, &self.auth.user, integration_id)
                            .await?;
                    if let Some(object) = result.as_object_mut() {
                        object.insert("error".into(), json!("github_app_installation_required"));
                        object.insert("repository".into(), json!(repository));
                        object.insert("action".into(), json!("completeGitHubSetupThenRetry"));
                    }
                    return Ok(result);
                }
                anyhow::ensure!(integration.enabled, "integration disabled");
                let provider = git_provider(&self.app, &integration).await?;
                let resolved = match provider
                    .resolve_repository(&RepositoryReference(repository.to_owned()))
                    .await
                {
                    Ok(resolved) => resolved,
                    Err(error)
                        if error
                            .to_string()
                            .contains("repository lookup failed with status 404") =>
                    {
                        let mut result = admin_github_app_setup_status(
                            &self.app,
                            &self.auth.user,
                            integration_id,
                        )
                        .await?;
                        if let Some(object) = result.as_object_mut() {
                            object.insert(
                                "error".into(),
                                json!("github_repository_installation_required"),
                            );
                            object.insert("repository".into(), json!(repository));
                            object.insert(
                                "action".into(),
                                json!("openRepositorySelectionUrlThenRetry"),
                            );
                        }
                        return Ok(result);
                    }
                    Err(error) => return Err(error),
                };
                let _mutation = self.app.mutations.lock().await;
                self.app.lease.assert_live()?;
                let repo = self.app.db.upsert_git_repository(
                    &self.auth.user,
                    integration_id,
                    &resolved,
                )?;
                // GitHub App repository selection is the authorization boundary.
                // Materialize that provider-approved write access for this
                // identity so credentials minted immediately afterward are usable.
                self.app
                    .db
                    .set_git_grant(&self.auth.user, &self.auth.client, &repo.id, "write")?;
                persist(&self.app).await?;
                let ssh = ssh_advertisement(&self.app, &repo.id);
                let remote = ssh
                    .as_ref()
                    .and_then(|value| value.get("url"))
                    .and_then(Value::as_str)
                    .ok_or_else(|| anyhow::anyhow!("SSH listener is disabled or not ready"))?;
                Ok(json!({
                    "repositoryId":repo.id,
                    "displayName":repo.display_name,
                    "remoteUrl":remote,
                    "sshRemoteUrl":remote,
                    "remoteUrlVersion":2,
                    "nextAction":"reuseExistingEd25519IdentityAndCheckKeyLease",
                    "workflow":[
                        {"step":1,"action":"resolveExistingEd25519Identity","sources":["SSH configuration","SSH agent","standard SSH identity paths"],"privateKeyRemainsLocal":true,"ifUnavailable":"report that an Ed25519 identity must be provisioned; do not generate one automatically"},
                        {"step":2,"action":"checkRegisteredKeyLease","tool":"ssh_key_status","arguments":{"publicKey":"existing Ed25519 public key"},"ifActive":"reuse","ifMissing":"register"},
                        {"step":3,"action":"registerKeyIfMissing","tool":"ssh_key_register","arguments":{"publicKey":"existing Ed25519 public key"}},
                        {"step":4,"action":"renewInternalLease","tool":"ssh_key_lease_renew","arguments":{"publicKey":"the same existing Ed25519 public key"},"when":"the lease is expired or SSH authentication fails"},
                        {"step":5,"action":"writeKnownHosts","knownHostsPath":"<private-known-hosts-path>","preserveForReuse":true},
                        {"step":6,"action":"useRemote","remoteField":"sshRemoteUrl","operations":["clone","fetch","push"],"strictHostKeyChecking":true,"onAuthenticationFailure":"renew the internal key lease and retry; never recreate the identity"}
                    ],
                    "remotes":{
                        "version":2,
                        "preferred":"ssh",
                        "ssh":ssh.expect("checked above")
                    }
                }))
            }
            "ssh_key_status" => {
                let public_key = crate::git::ssh::parse_public_key(
                    args.get("publicKey")
                        .and_then(Value::as_str)
                        .ok_or_else(|| anyhow::anyhow!("publicKey is required"))?,
                )?;
                let canonical = public_key.to_openssh()?;
                let now = chrono::Utc::now().timestamp();
                let registered = self
                    .app
                    .db
                    .agent_ssh_key(&self.auth.user, &self.auth.agent)?;
                let Some(registered) = registered.filter(|key| key.public_key == canonical) else {
                    return Ok(json!({
                        "registered": false,
                        "active": false,
                        "action": "registerKey",
                        "tool": "ssh_key_register"
                    }));
                };
                let active = registered.revoked_at.is_none() && registered.lease_expires_at > now;
                Ok(json!({
                    "registered": true,
                    "active": active,
                    "fingerprint": registered.fingerprint,
                    "leaseExpiresAt": chrono::DateTime::from_timestamp(registered.lease_expires_at, 0).expect("valid timestamp").to_rfc3339(),
                    "usableForSeconds": registered.lease_expires_at.saturating_sub(now),
                    "action": if active { "reuse" } else { "renewLease" },
                    "renewalTool": "ssh_key_lease_renew"
                }))
            }
            "ssh_key_register" | "ssh_key_lease_renew" => {
                anyhow::ensure!(
                    self.app.ssh_ready.load(Ordering::Acquire),
                    "SSH listener is not ready"
                );
                let public_key = crate::git::ssh::parse_public_key(
                    args.get("publicKey")
                        .and_then(Value::as_str)
                        .ok_or_else(|| anyhow::anyhow!("publicKey is required"))?,
                )?;
                let canonical = public_key.to_openssh()?;
                let fingerprint = crate::git::ssh::fingerprint(&public_key);
                let renewing = name == "ssh_key_lease_renew";
                anyhow::ensure!(
                    self.app.auth_rate_limit.allow(
                        format!("ssh-key-lease:{}", self.auth.client),
                        30,
                        Duration::from_secs(60)
                    ),
                    "SSH key lease mutation rate limit exceeded"
                );
                let _mutation = self.app.mutations.lock().await;
                self.app.lease.assert_live()?;
                let expires_at =
                    chrono::Utc::now().timestamp() + self.app.config.ssh_key_lease_ttl_secs as i64;
                let key = if renewing {
                    self.app.db.renew_agent_ssh_key_lease(
                        &self.auth.user,
                        &self.auth.identity,
                        &self.auth.agent,
                        &self.auth.client,
                        &canonical,
                        expires_at,
                    )?
                } else {
                    self.app.db.register_agent_ssh_key(
                        &self.auth.user,
                        &self.auth.agent,
                        &self.auth.client,
                        &canonical,
                        &fingerprint,
                        expires_at,
                    )?
                };
                let action = if renewing {
                    "git.ssh_key.lease_renew"
                } else {
                    "git.ssh_key.register"
                };
                self.app.db.record_audit(
                    Some(&self.auth.user),
                    action,
                    Some(&self.auth.agent),
                    "success",
                    &json!({
                        "identity_id": self.auth.identity,
                        "agent_id": self.auth.agent,
                        "client_id": self.auth.client,
                        "fingerprint": key.fingerprint,
                        "lease_expires_at": key.lease_expires_at
                    }),
                )?;
                persist(&self.app).await?;
                if renewing {
                    self.app
                        .metrics
                        .ssh_key_lease_renewals
                        .fetch_add(1, Ordering::Relaxed);
                } else {
                    self.app
                        .metrics
                        .ssh_key_registrations
                        .fetch_add(1, Ordering::Relaxed);
                }
                Ok(json!({
                    "action": if renewing { "renewedInternalLease" } else { "registeredExistingKey" },
                    "agentId": key.agent_id,
                    "fingerprint": key.fingerprint,
                    "leaseExpiresAt": chrono::DateTime::from_timestamp(key.lease_expires_at, 0).expect("valid timestamp").to_rfc3339(),
                    "leaseTtlSeconds": self.app.config.ssh_key_lease_ttl_secs,
                    "privateKeyRemainsLocal": true,
                    "keyMaterialChanged": false,
                    "renewal": {
                        "tool": "ssh_key_lease_renew",
                        "action": "extend the internal lease for this exact public key"
                    }
                }))
            }
            _ => anyhow::bail!("unknown Git control operation"),
        }
    }
}

impl PolicyProvider {
    fn permitted(&self, tool: &str) -> bool {
        self.allow.as_ref().is_none_or(|allow| allow.contains(tool)) && !self.deny.contains(tool)
    }
}

#[async_trait::async_trait]
impl ToolProvider for PolicyProvider {
    async fn tools(&self) -> anyhow::Result<Vec<Tool>> {
        Ok(self
            .inner
            .tools()
            .await?
            .into_iter()
            .filter(|tool| self.permitted(&tool.name))
            .collect())
    }

    async fn call(&self, name: &str, args: Value) -> anyhow::Result<Value> {
        anyhow::ensure!(self.permitted(name), "tool denied by integration policy");
        self.inner.call(name, args).await
    }

    async fn close(&self) -> anyhow::Result<()> {
        self.inner.close().await
    }
}

#[async_trait::async_trait]
impl ToolProvider for OAuthStepUpProvider {
    async fn tools(&self) -> anyhow::Result<Vec<Tool>> {
        self.inner.tools().await
    }

    async fn advertised_tools(&self) -> anyhow::Result<Vec<Tool>> {
        self.inner.advertised_tools().await
    }

    async fn call(&self, name: &str, args: Value) -> anyhow::Result<Value> {
        match self.inner.call(name, args).await {
            Ok(value) => Ok(value),
            Err(error) => {
                let Some(challenge) = error.downcast_ref::<UpstreamInsufficientScope>() else {
                    return Err(error);
                };
                if let Some(token) = self.app.db.upstream_oauth_token(&self.integration)? {
                    let granted = token.scope.split_ascii_whitespace().collect::<HashSet<_>>();
                    if challenge
                        .scopes
                        .iter()
                        .all(|scope| granted.contains(scope.as_str()))
                    {
                        anyhow::bail!(
                            "upstream MCP repeated an insufficient_scope challenge after consent; the operation was retried once and will not be retried again"
                        );
                    }
                }
                let authorization_url =
                    start_upstream_step_up(&self.app, &self.user, &self.integration, challenge)
                        .await?;
                anyhow::bail!(
                    "upstream OAuth consent is required for scopes [{}]. Open this one-time URL without prefetching it, complete consent, then retry this operation once: {}",
                    challenge.scopes.join(" "),
                    authorization_url
                )
            }
        }
    }

    async fn close(&self) -> anyhow::Result<()> {
        self.inner.close().await
    }
}

#[derive(Default)]
pub struct RateLimiter {
    attempts: std::sync::Mutex<HashMap<String, VecDeque<Instant>>>,
}

impl RateLimiter {
    pub fn allow(&self, key: String, maximum: usize, window: Duration) -> bool {
        let Ok(mut attempts) = self.attempts.lock() else {
            return false;
        };
        let now = Instant::now();
        let queue = attempts.entry(key).or_default();
        while queue
            .front()
            .is_some_and(|attempt| now.duration_since(*attempt) >= window)
        {
            queue.pop_front();
        }
        if queue.len() >= maximum {
            return false;
        }
        queue.push_back(now);
        true
    }
}

#[async_trait::async_trait]
impl ToolProvider for MeasuredProvider {
    async fn tools(&self) -> anyhow::Result<Vec<Tool>> {
        self.metrics.upstream_calls.fetch_add(1, Ordering::Relaxed);
        self.inner.tools().await.inspect_err(|_| {
            self.metrics
                .upstream_failures
                .fetch_add(1, Ordering::Relaxed);
        })
    }

    async fn call(&self, name: &str, args: Value) -> anyhow::Result<Value> {
        self.metrics.upstream_calls.fetch_add(1, Ordering::Relaxed);
        self.inner.call(name, args).await.inspect_err(|_| {
            self.metrics
                .upstream_failures
                .fetch_add(1, Ordering::Relaxed);
        })
    }

    async fn close(&self) -> anyhow::Result<()> {
        self.inner.close().await
    }
}

#[derive(Clone)]
pub struct App {
    pub config: Config,
    pub db: Database,
    pub secrets: SecretBox,
    pub runtime: Arc<CodeRuntime>,
    pub lease: Authority,
    pub replicator: Durability,
    pub providers: Arc<tokio::sync::Mutex<HashMap<String, Arc<dyn ToolProvider>>>>,
    pub metrics: Arc<Metrics>,
    /// Serializes each committed mutation with its LTX durability proof. This
    /// prevents another request from advancing the WAL between a mutation and
    /// the acknowledgement position captured for it.
    pub mutations: Arc<tokio::sync::Mutex<()>>,
    pub auth_rate_limit: Arc<RateLimiter>,
    pub git_providers: Arc<tokio::sync::Mutex<HashMap<String, Arc<dyn GitProvider>>>>,
    pub git_streams: Arc<tokio::sync::Semaphore>,
    pub git_client_streams: Arc<ClientStreamLimiter>,
    pub ssh_keys: Option<Arc<std::sync::RwLock<crate::git::ssh::KeySet>>>,
    pub ssh_ready: Arc<AtomicBool>,
    pub ssh_connections: Arc<tokio::sync::Semaphore>,
    pub github_api_base: url::Url,
}

#[derive(Clone)]
pub enum Authority {
    Local,
    S3(LeaseGuard),
}

impl Authority {
    fn is_live(&self) -> bool {
        match self {
            Self::Local => true,
            Self::S3(lease) => lease.is_live(),
        }
    }
    fn assert_live(&self) -> anyhow::Result<()> {
        match self {
            Self::Local => Ok(()),
            Self::S3(lease) => lease.assert_live(),
        }
    }
    fn generation(&self) -> u64 {
        match self {
            Self::Local => 0,
            Self::S3(lease) => lease.generation(),
        }
    }
    fn authority_until_ms(&self) -> u64 {
        match self {
            Self::Local => 0,
            Self::S3(lease) => lease.authority_until_ms(),
        }
    }
    fn stop_renewal(&self) {
        if let Self::S3(lease) = self {
            lease.stop_renewal();
        }
    }
}

#[derive(Clone)]
pub enum Durability {
    Local,
    S3(Arc<Replicator>),
}

impl Durability {
    pub async fn sync(&self) -> anyhow::Result<u64> {
        match self {
            Self::Local => Ok(1),
            Self::S3(repl) => repl.sync().await,
        }
    }
    fn durable_txid(&self) -> u64 {
        match self {
            Self::Local => 0,
            Self::S3(repl) => repl.durable_txid(),
        }
    }
    fn pending_txids(&self) -> u64 {
        match self {
            Self::Local => 0,
            Self::S3(repl) => repl.pending_txids(),
        }
    }
}

pub async fn create_user(config: Config, email: &str, password: &str) -> anyhow::Result<()> {
    anyhow::ensure!(!email.trim().is_empty(), "email is required");
    anyhow::ensure!(
        password.len() >= 12,
        "password must be at least 12 characters"
    );
    std::fs::create_dir_all(&config.data_dir)?;
    if !config.s3_enabled() {
        ensure_local_database_compatible(&config)?;
        let db = Database::open_with_mode(&config.db_path(), StorageMode::Local)?;
        create_user_record(&db, email, password)?;
        println!("Created user {email}");
        return Ok(());
    }
    ensure_s3_database_compatible(&config)?;
    let store = build_store(&config)?;
    probe_conditional_writes(
        store.clone(),
        ObjectPath::from(format!("{}probe/conditional", config.s3_prefix)),
    )
    .await?;
    let lease = LeaseGuard::acquire(
        store.clone(),
        ObjectPath::from(format!("{}lease.json", config.s3_prefix)),
        config.lease_ttl(),
    )
    .await
    .map_err(|error| anyhow::anyhow!("cannot create a user while cog is running: {error}"))?;
    let mut renewal = lease.clone().spawn_renewal();
    let result = async {
        let replicator = Replicator::new(
            store,
            config.s3_prefix.clone(),
            config.db_path(),
            lease.generation(),
        );
        let _ = replicator.restore().await?;
        let db = Database::open_with_mode(&config.db_path(), StorageMode::S3)?;
        replicator.sync().await?;
        replicator.commit_generation().await?;

        create_user_record(&db, email, password)?;
        let durable_txid = replicator.sync().await?;
        anyhow::ensure!(
            durable_txid > 0,
            "user mutation has no durable LTX position"
        );
        lease.assert_live()?;
        Ok::<(), anyhow::Error>(())
    }
    .await;

    lease.stop_renewal();
    let _ = (&mut renewal).await;
    let relinquish = lease.relinquish().await;
    result?;
    relinquish?;
    println!("Created user {email}");
    Ok(())
}

pub fn create_user_record(db: &Database, email: &str, password: &str) -> anyhow::Result<()> {
    let salt = SaltString::generate(&mut OsRng);
    let hash = Argon2::default()
        .hash_password(password.as_bytes(), &salt)
        .map_err(|error| anyhow::anyhow!("could not hash password: {error}"))?
        .to_string();
    let user = db.create_user(email, &hash)?;
    db.record_audit(
        Some(&user),
        "user.create_cli",
        Some(&user),
        "success",
        &json!({}),
    )?;
    Ok(())
}

pub async fn run(config: Config) -> anyhow::Result<()> {
    std::fs::create_dir_all(&config.data_dir)
        .map_err(|error| StartupError::new(StartupPhase::DatabaseOpen, &error))?;
    let (db, lease, replicator, mut renewal) = if config.s3_enabled() {
        ensure_s3_database_compatible(&config)?;
        tracing::info!(
            credential_provider = credential_provider_class(),
            bucket = %config.s3_bucket.as_deref().unwrap_or_default(),
            region = %config.s3_region,
            endpoint = %safe_endpoint(&config),
            "initializing S3 storage"
        );
        let store = build_store(&config).map_err(|error| {
            StartupError::new(StartupPhase::StorageInitialization, error.as_ref())
        })?;
        probe_conditional_writes(
            store.clone(),
            ObjectPath::from(format!("{}probe/conditional", config.s3_prefix)),
        )
        .await
        .map_err(|error| StartupError::new(StartupPhase::ConditionalWriteProbe, error.as_ref()))?;
        let remote_lease = LeaseGuard::acquire(
            store.clone(),
            ObjectPath::from(format!("{}lease.json", config.s3_prefix)),
            config.lease_ttl(),
        )
        .await
        .map_err(|error| StartupError::new(StartupPhase::LeaseAcquisition, &error))?;
        let renewal = remote_lease.clone().spawn_renewal();
        let repl = Arc::new(Replicator::new(
            store,
            config.s3_prefix.clone(),
            config.db_path(),
            remote_lease.generation(),
        ));
        let _ = repl
            .restore()
            .await
            .map_err(|error| StartupError::new(StartupPhase::Restore, error.as_ref()))?;
        let db = Database::open_with_mode(&config.db_path(), StorageMode::S3)
            .map_err(|error| StartupError::new(StartupPhase::DatabaseOpen, error.as_ref()))?;
        repl.sync()
            .await
            .map_err(|error| StartupError::new(StartupPhase::InitialReplication, error.as_ref()))?;
        repl.commit_generation()
            .await
            .map_err(|error| StartupError::new(StartupPhase::InitialReplication, error.as_ref()))?;
        (
            db,
            Authority::S3(remote_lease),
            Durability::S3(repl),
            Some(renewal),
        )
    } else {
        ensure_local_database_compatible(&config)?;
        tracing::info!(path = %config.db_path().display(), "initializing local SQLite storage");
        let db = Database::open_with_mode(&config.db_path(), StorageMode::Local)
            .map_err(|error| StartupError::new(StartupPhase::DatabaseOpen, error.as_ref()))?;
        (db, Authority::Local, Durability::Local, None)
    };
    if db.user_count()? == 0 {
        lease.stop_renewal();
        if let Some(task) = renewal.as_mut() {
            let _ = task.await;
        }
        if let Authority::S3(remote) = &lease {
            remote.relinquish().await?;
        }
        eprintln!(
            "No users exist. Create the first user with:\n  cog create-user $EMAIL $PASSWORD"
        );
        return Ok(());
    }
    let secrets = SecretBox::new(config.master_key.as_bytes());
    let mut app = App {
        secrets,
        runtime: Arc::new(CodeRuntime::new(
            config.v8_heap_mb,
            Duration::from_secs(config.execution_timeout_secs),
        )),
        config: config.clone(),
        db,
        lease: lease.clone(),
        replicator: replicator.clone(),
        providers: Arc::new(tokio::sync::Mutex::new(HashMap::new())),
        metrics: Arc::new(Metrics::default()),
        mutations: Arc::new(tokio::sync::Mutex::new(())),
        auth_rate_limit: Arc::new(RateLimiter::default()),
        git_providers: Arc::new(tokio::sync::Mutex::new(HashMap::new())),
        git_streams: Arc::new(tokio::sync::Semaphore::new(config.git_max_streams)),
        git_client_streams: Arc::new(ClientStreamLimiter::default()),
        ssh_keys: None,
        ssh_ready: Arc::new(AtomicBool::new(false)),
        ssh_connections: Arc::new(tokio::sync::Semaphore::new(config.ssh_max_connections)),
        github_api_base: "https://api.github.com/"
            .parse()
            .expect("valid GitHub API URL"),
    };
    let ssh_listener = if let Some(address) = config.ssh_listen {
        let keys = Arc::new(std::sync::RwLock::new(
            crate::git::ssh::KeySet::load_or_create(&app.db, &app.secrets)?,
        ));
        app.ssh_keys = Some(keys);
        // Key creation is a durable mutation. In S3 mode it must be replicated
        // before either the public key or listener is advertised.
        persist(&app).await?;
        Some(
            tokio::net::TcpListener::bind(address)
                .await
                .with_context(|| format!("configured SSH listener {address} could not be bound"))?,
        )
    } else {
        None
    };
    let (ssh_shutdown, _) = tokio::sync::broadcast::channel::<()>(1);
    let ssh_task = if let Some(listener) = ssh_listener {
        let keys = app.ssh_keys.as_ref().expect("SSH keys loaded");
        let encoded = crate::git::ssh::encode_private(
            &keys
                .read()
                .map_err(|_| anyhow::anyhow!("SSH key lock poisoned"))?
                .host,
        )?;
        let host_key = russh::keys::PrivateKey::from_openssh(&encoded)?;
        let ssh_config = Arc::new(russh::server::Config {
            methods: russh::MethodSet::from(&[russh::MethodKind::PublicKey][..]),
            auth_rejection_time: Duration::from_secs(1),
            auth_rejection_time_initial: Some(Duration::ZERO),
            keys: vec![host_key],
            window_size: 256 * 1024,
            maximum_packet_size: 32 * 1024,
            channel_buffer_size: 8,
            event_buffer_size: 8,
            max_auth_attempts: 3,
            inactivity_timeout: Some(Duration::from_secs(config.ssh_channel_timeout_secs)),
            nodelay: true,
            ..Default::default()
        });
        let factory = SshServerFactory { app: app.clone() };
        let mut shutdown = ssh_shutdown.subscribe();
        app.ssh_ready.store(true, Ordering::Release);
        Some(tokio::spawn(async move {
            let mut factory = factory;
            let running = factory.run_on_socket(ssh_config, &listener);
            let handle = running.handle();
            tokio::pin!(running);
            tokio::select! {
                result = &mut running => result,
                _ = shutdown.recv() => {
                    handle.shutdown("COG is shutting down".into());
                    running.await
                }
            }
        }))
    } else {
        None
    };
    let shutdown_providers = app.providers.clone();
    let router = build_router(app.clone());
    let listener = tokio::net::TcpListener::bind(config.listen).await?;
    tracing::info!(address=%config.listen,"cog ready");
    axum::serve(listener, router)
        .with_graceful_shutdown(async move {
            tokio::select! {
                _ = tokio::signal::ctrl_c() => {
                    let _ = ssh_shutdown.send(());
                    // Stop admitting new work, capture the final committed
                    // position while authority is still proven, then stop the
                    // renewer and conditionally expire our ownership record.
                    if lease.is_live()
                        && let Err(error) = replicator.sync().await
                    {
                        tracing::error!(error = redacted_error(error.as_ref()), "final LTX sync failed during shutdown");
                    }
                    lease.stop_renewal();
                    if let Some(task) = renewal.as_mut() { let _ = task.await; }
                    if let Authority::S3(remote) = &lease
                        && let Err(error) = remote.relinquish().await {
                            tracing::warn!(error = redacted_error(error.as_ref()), "lease relinquish failed");
                    }
                }
                _ = async {
                    match renewal.as_mut() {
                        Some(task) => { let _ = task.await; }
                        None => std::future::pending::<()>().await,
                    }
                } => {
                    let _ = ssh_shutdown.send(());
                    tracing::error!("SELF-FENCE: lease renewal terminated; shutting down");
                }
            }
            let providers = {
                let mut providers = shutdown_providers.lock().await;
                providers
                    .drain()
                    .map(|(_, provider)| provider)
                    .collect::<Vec<_>>()
            };
            for provider in providers {
                if let Err(error) = provider.close().await {
                    tracing::warn!(error = %safe_error(error.as_ref()), "upstream cleanup failed");
                }
            }
        })
        .await?;
    app.ssh_ready.store(false, Ordering::Release);
    if let Some(mut task) = ssh_task
        && tokio::time::timeout(
            Duration::from_secs(config.ssh_channel_timeout_secs),
            &mut task,
        )
        .await
        .is_err()
    {
        task.abort();
    }
    Ok(())
}

pub fn build_router(app: App) -> Router {
    Router::new()
        .route("/", get(home))
        .route("/healthz", get(health))
        .route("/readyz", get(readiness))
        .route("/version", get(version))
        .route("/metrics", get(metrics))
        .route("/login", get(login_page).post(login))
        .route("/logout", post(logout))
        .route("/ui", get(admin_ui))
        .route("/ui/", get(admin_ui))
        .route("/ui/assets/{*path}", get(ui_asset))
        .route("/ui/integrations", post(ui_add_integration))
        .route("/ui/identities", post(ui_create_identity))
        .route("/ui/identities/{id}/rename", post(ui_rename_identity))
        .route("/ui/identities/{id}/delete", post(ui_delete_identity))
        .route("/ui/agents/{id}/rename", post(ui_rename_agent))
        .route("/ui/integrations/{id}/delete", post(ui_delete_integration))
        .route(
            "/ui/integrations/{id}/disconnect",
            post(ui_disconnect_integration),
        )
        .route("/ui/tokens/{id}/revoke", post(ui_revoke_token))
        .route("/ui/clients/{id}/revoke", post(ui_revoke_client))
        .route("/ui/ssh/{purpose}/prepare", post(ui_prepare_ssh_key))
        .route("/ui/ssh/{purpose}/{id}/activate", post(ui_activate_ssh_key))
        .route("/ui/ssh/{purpose}/{id}/retire", post(ui_retire_ssh_key))
        .route(
            "/ui/clients/{client}/integrations/{integration}/revoke",
            post(ui_revoke_grant),
        )
        .route(
            "/ui/clients/{client}/integrations/{integration}/grant",
            post(ui_grant_integration),
        )
        .route(
            "/.well-known/oauth-authorization-server",
            get(auth_metadata),
        )
        .route(
            "/.well-known/oauth-protected-resource",
            get(resource_metadata),
        )
        .route("/.well-known/oauth-client", get(oauth_client_metadata))
        .route(
            "/oauth/register",
            post(register).layer(DefaultBodyLimit::max(32 * 1_024)),
        )
        .route("/oauth/authorize", get(authorize_page))
        .route("/oauth/token", post(token))
        .route("/oauth/revoke", post(revoke_token))
        .route("/mcp", post(mcp_endpoint))
        .route("/github/app/setup/{state}", get(github_app_setup_launch))
        .route(
            "/github/app/manifest/callback",
            get(github_app_manifest_callback),
        )
        .route(
            "/github/app/installation/callback",
            get(github_app_installation_callback),
        )
        .route("/github/app/installation/complete", get(authorize_page))
        .route(
            "/api/integrations",
            get(list_integrations).post(add_integration),
        )
        .route(
            "/api/integrations/{id}",
            get(get_integration)
                .patch(update_integration)
                .delete(delete_integration),
        )
        .route(
            "/api/integrations/{id}/reconnect",
            post(reconnect_integration),
        )
        .route(
            "/api/integrations/{id}/credentials",
            axum::routing::delete(disconnect_integration),
        )
        .route(
            "/api/integrations/{id}/oauth/start",
            post(upstream_oauth_start),
        )
        .route("/api/clients", get(list_agent_clients))
        .route(
            "/api/clients/{id}",
            axum::routing::delete(revoke_agent_client),
        )
        .route(
            "/api/clients/{client}/integrations/{integration}",
            axum::routing::delete(revoke_agent_grant),
        )
        .route("/api/tokens", get(list_agent_tokens))
        .route(
            "/api/tokens/{id}",
            axum::routing::delete(revoke_agent_token),
        )
        .route("/api/audit", get(list_audit_events))
        .route("/api/ui", get(ui_bootstrap))
        .route(
            "/api/oauth/consent",
            get(authorize_consent).post(authorize_post),
        )
        .route("/oauth/upstream/callback", get(upstream_callback))
        .with_state(app)
}

#[derive(Clone)]
pub struct SshServerFactory {
    pub app: App,
}

pub struct SshConnection {
    app: App,
    binding: Option<crate::db::AgentSshBinding>,
    protocols: HashMap<ChannelId, String>,
    inputs: HashMap<ChannelId, tokio::sync::mpsc::Sender<anyhow::Result<bytes::Bytes>>>,
    opened_channel: bool,
    executed_channel: Option<ChannelId>,
    _connection_permit: Option<tokio::sync::OwnedSemaphorePermit>,
}

impl russh::server::Server for SshServerFactory {
    type Handler = SshConnection;

    fn new_client(&mut self, _peer_addr: Option<SocketAddr>) -> Self::Handler {
        self.app
            .metrics
            .ssh_handshakes
            .fetch_add(1, Ordering::Relaxed);
        let permit = self.app.ssh_connections.clone().try_acquire_owned().ok();
        if permit.is_none() {
            self.app
                .metrics
                .ssh_limit_rejections
                .fetch_add(1, Ordering::Relaxed);
        }
        SshConnection {
            app: self.app.clone(),
            binding: None,
            protocols: HashMap::new(),
            inputs: HashMap::new(),
            opened_channel: false,
            executed_channel: None,
            _connection_permit: permit,
        }
    }

    fn handle_session_error(&mut self, error: <Self::Handler as russh::server::Handler>::Error) {
        tracing::debug!(error = %safe_error(error.as_ref()), "SSH session ended with an error");
    }
}

impl Drop for SshConnection {
    fn drop(&mut self) {
        if self.binding.is_some() {
            self.app
                .metrics
                .ssh_active_sessions
                .fetch_sub(1, Ordering::Relaxed);
        }
    }
}

impl russh::server::Handler for SshConnection {
    type Error = anyhow::Error;

    async fn auth_publickey(
        &mut self,
        user: &str,
        key: &russh::keys::PublicKey,
    ) -> Result<russh::server::Auth, Self::Error> {
        let result = (|| -> anyhow::Result<crate::db::AgentSshBinding> {
            anyhow::ensure!(user == "git", "SSH username must be git");
            anyhow::ensure!(
                self._connection_permit.is_some(),
                "SSH connection limit exceeded"
            );
            self.app.lease.assert_live()?;
            let encoded = key.to_openssh()?;
            let public_key = crate::git::ssh::parse_public_key(&encoded)?;
            let canonical = public_key.to_openssh()?;
            self.app
                .db
                .active_agent_ssh_key(&canonical, chrono::Utc::now().timestamp())?
                .ok_or_else(|| anyhow::anyhow!("SSH key is not registered or its lease expired"))
        })();
        match result {
            Ok(binding) => {
                self.binding = Some(binding.clone());
                self.app
                    .metrics
                    .ssh_auth_success
                    .fetch_add(1, Ordering::Relaxed);
                self.app
                    .metrics
                    .ssh_active_sessions
                    .fetch_add(1, Ordering::Relaxed);
                let _ = self.app.db.record_audit(
                    Some(&binding.user_id),
                    "git.ssh_authentication",
                    Some(&binding.agent_id),
                    "success",
                    &json!({
                        "identity_id": binding.identity_id,
                        "agent_id": binding.agent_id,
                        "client_id": binding.client_id,
                        "fingerprint": binding.fingerprint,
                        "lease_expires_at": binding.lease_expires_at
                    }),
                );
                Ok(russh::server::Auth::Accept)
            }
            Err(_) => {
                self.app
                    .metrics
                    .ssh_auth_denied
                    .fetch_add(1, Ordering::Relaxed);
                Ok(russh::server::Auth::reject())
            }
        }
    }

    async fn channel_open_session(
        &mut self,
        _channel: Channel<SshMsg>,
        _session: &mut SshSession,
    ) -> Result<bool, Self::Error> {
        if self.binding.is_none() || self.opened_channel {
            self.app
                .metrics
                .ssh_limit_rejections
                .fetch_add(1, Ordering::Relaxed);
            return Ok(false);
        }
        self.opened_channel = true;
        Ok(true)
    }

    async fn env_request(
        &mut self,
        channel: ChannelId,
        variable_name: &str,
        variable_value: &str,
        session: &mut SshSession,
    ) -> Result<(), Self::Error> {
        if variable_name == "GIT_PROTOCOL"
            && crate::git::ssh::parse_git_protocol(variable_value).is_ok()
            && !self.protocols.contains_key(&channel)
        {
            self.protocols.insert(channel, variable_value.to_owned());
            let _ = session.channel_success(channel);
        } else {
            let _ = session.channel_failure(channel);
        }
        Ok(())
    }

    async fn exec_request(
        &mut self,
        channel: ChannelId,
        command: &[u8],
        session: &mut SshSession,
    ) -> Result<(), Self::Error> {
        if self.executed_channel.is_some() {
            let _ = session.channel_failure(channel);
            return Ok(());
        }
        let result = std::str::from_utf8(command)
            .map_err(anyhow::Error::from)
            .and_then(crate::git::ssh::parse_command);
        let Ok((service, repository_id)) = result else {
            let _ = session.channel_failure(channel);
            return Ok(());
        };
        let Some(binding) = self.binding.clone() else {
            let _ = session.channel_failure(channel);
            return Ok(());
        };
        let (sender, receiver) = tokio::sync::mpsc::channel(8);
        self.inputs.insert(channel, sender);
        self.executed_channel = Some(channel);
        let _ = session.channel_success(channel);
        let app = self.app.clone();
        let protocol = self.protocols.get(&channel).cloned();
        let handle = session.handle();
        tokio::spawn(async move {
            let result = tokio::time::timeout(
                Duration::from_secs(app.config.git_timeout_secs),
                run_ssh_git(
                    app.clone(),
                    binding.clone(),
                    service,
                    repository_id.clone(),
                    protocol,
                    SshGitIo {
                        input: receiver,
                        output: handle.clone(),
                        channel,
                    },
                ),
            )
            .await;
            let status = if matches!(result, Ok(Ok(()))) { 0 } else { 1 };
            if result.is_err() {
                app.metrics.ssh_timeouts.fetch_add(1, Ordering::Relaxed);
            }
            if status != 0 {
                app.metrics
                    .ssh_upstream_failures
                    .fetch_add(1, Ordering::Relaxed);
                let error_kind = match &result {
                    Ok(Err(error)) => safe_git_error(error.as_ref()),
                    Err(_) => "Git transport timed out",
                    Ok(Ok(())) => "Git transport operation failed",
                };
                tracing::warn!(
                    repository_id = %repository_id,
                    service = ?service,
                    error = error_kind,
                    "SSH Git operation failed"
                );
                let _ = app.db.record_audit(
                    Some(&binding.user_id),
                    "git.ssh_operation",
                    Some(&repository_id),
                    "failure",
                    &json!({"identity_id":binding.identity_id,"agent_id":binding.agent_id,"client_id":binding.client_id,"fingerprint":binding.fingerprint,"transport":"ssh","error":error_kind}),
                );
                let message = match &result {
                    Ok(Err(error)) => {
                        format!(
                            "COG Git operation failed: {}\n",
                            safe_git_error(error.as_ref())
                        )
                    }
                    Err(_) => "COG Git operation timed out\n".to_owned(),
                    Ok(Ok(())) => String::new(),
                };
                let _ = handle.extended_data(channel, 1, message).await;
            }
            let _ = handle.exit_status_request(channel, status).await;
            let _ = handle.eof(channel).await;
            let _ = handle.close(channel).await;
        });
        Ok(())
    }

    async fn data(
        &mut self,
        channel: ChannelId,
        data: &[u8],
        _session: &mut SshSession,
    ) -> Result<(), Self::Error> {
        if let Some(sender) = self.inputs.get(&channel) {
            sender
                .send(Ok(bytes::Bytes::copy_from_slice(data)))
                .await
                .map_err(|_| anyhow::anyhow!("SSH Git input closed"))?;
        }
        Ok(())
    }

    async fn channel_eof(
        &mut self,
        channel: ChannelId,
        _session: &mut SshSession,
    ) -> Result<(), Self::Error> {
        self.inputs.remove(&channel);
        Ok(())
    }

    async fn channel_close(
        &mut self,
        channel: ChannelId,
        _session: &mut SshSession,
    ) -> Result<(), Self::Error> {
        self.inputs.remove(&channel);
        Ok(())
    }

    async fn shell_request(
        &mut self,
        channel: ChannelId,
        session: &mut SshSession,
    ) -> Result<(), Self::Error> {
        let _ = session.channel_failure(channel);
        Ok(())
    }

    async fn subsystem_request(
        &mut self,
        channel: ChannelId,
        _name: &str,
        session: &mut SshSession,
    ) -> Result<(), Self::Error> {
        let _ = session.channel_failure(channel);
        Ok(())
    }

    async fn pty_request(
        &mut self,
        channel: ChannelId,
        _term: &str,
        _col_width: u32,
        _row_height: u32,
        _pix_width: u32,
        _pix_height: u32,
        _modes: &[(russh::Pty, u32)],
        session: &mut SshSession,
    ) -> Result<(), Self::Error> {
        let _ = session.channel_failure(channel);
        Ok(())
    }

    async fn agent_request(
        &mut self,
        channel: ChannelId,
        session: &mut SshSession,
    ) -> Result<bool, Self::Error> {
        let _ = session.channel_failure(channel);
        Ok(false)
    }
}

struct SshGitIo {
    input: tokio::sync::mpsc::Receiver<anyhow::Result<bytes::Bytes>>,
    output: russh::server::Handle,
    channel: ChannelId,
}

async fn run_ssh_git(
    app: App,
    binding: crate::db::AgentSshBinding,
    service: crate::git::ssh::Service,
    repository_id: String,
    git_protocol: Option<String>,
    io: SshGitIo,
) -> anyhow::Result<()> {
    let SshGitIo {
        input,
        output,
        channel,
    } = io;
    let operation = match service {
        crate::git::ssh::Service::UploadPack => GitOperation::Read,
        crate::git::ssh::Service::ReceivePack => GitOperation::Write,
    };
    match operation {
        GitOperation::Read => app
            .metrics
            .ssh_read_operations
            .fetch_add(1, Ordering::Relaxed),
        GitOperation::Write => app
            .metrics
            .ssh_write_operations
            .fetch_add(1, Ordering::Relaxed),
    };
    let _global = app
        .git_streams
        .clone()
        .try_acquire_owned()
        .map_err(|_| anyhow::anyhow!("global Git stream limit exceeded"))?;
    let _client = app
        .git_client_streams
        .try_acquire(&binding.client_id, app.config.git_max_streams_per_client)
        .ok_or_else(|| anyhow::anyhow!("client Git stream limit exceeded"))?;
    app.lease.assert_live()?;
    let repository = app
        .db
        .git_repository(&repository_id)?
        .filter(|repository| repository.user_id == binding.user_id)
        .ok_or_else(|| anyhow::anyhow!("repository is no longer available"))?;
    let live_key = app
        .db
        .agent_ssh_key(&binding.user_id, &binding.agent_id)?
        .filter(|key| {
            key.public_key == binding.public_key
                && key.revoked_at.is_none()
                && key.lease_expires_at > chrono::Utc::now().timestamp()
        })
        .ok_or_else(|| anyhow::anyhow!("SSH key lease has expired or been revoked"))?;
    let grant = app
        .db
        .git_grant_permission(&binding.user_id, &binding.client_id, &repository_id)?
        .ok_or_else(|| anyhow::anyhow!("repository grant has been revoked"))?;
    anyhow::ensure!(
        crate::git::grants::permits(&grant, operation),
        "repository grant does not permit the operation"
    );
    let integration = app
        .db
        .integration(&repository.integration_id, &binding.user_id)?
        .filter(|integration| integration.enabled && integration.identity_id == binding.identity_id)
        .ok_or_else(|| anyhow::anyhow!("integration is disabled or revoked"))?;
    let provider = git_provider(&app, &integration).await?;
    let resolved = ResolvedRepository {
        provider_repository_id: repository.provider_repository_id.clone(),
        display_name: repository.display_name.clone(),
        upstream_url: url::Url::parse(&repository.upstream_url)?,
        metadata: repository.metadata.clone(),
    };
    let authorization = provider.authorize_upstream(&resolved, operation).await?;
    let upstream = provider.upstream_url(&resolved)?;
    let service_name = match service {
        crate::git::ssh::Service::UploadPack => "git-upload-pack",
        crate::git::ssh::Service::ReceivePack => "git-receive-pack",
    };
    let client = reqwest::Client::builder()
        .redirect(reqwest::redirect::Policy::none())
        .timeout(Duration::from_secs(app.config.git_timeout_secs))
        .build()?;
    let mut discovery_url = upstream.clone();
    discovery_url.set_path(&format!(
        "{}.git/info/refs",
        upstream.path().trim_end_matches(".git")
    ));
    discovery_url.set_query(Some(&format!("service={service_name}")));
    let mut discovery = client.get(discovery_url);
    if let Some(protocol) = &git_protocol {
        discovery = discovery.header("Git-Protocol", protocol);
    }
    discovery = crate::git::service::apply_authorization(discovery, &authorization);
    let response = discovery.send().await?;
    anyhow::ensure!(response.status().is_success(), "upstream discovery failed");
    let advertisement = response.bytes().await?;
    let advertisement = crate::git::service::strip_service_preamble(&advertisement, service_name)?;
    output
        .data(channel, bytes::Bytes::copy_from_slice(advertisement))
        .await
        .map_err(|_| anyhow::anyhow!("SSH client disconnected"))?;

    // Revalidate the key lease and live grants immediately before the RPC.
    app.lease.assert_live()?;
    anyhow::ensure!(
        app.db
            .agent_ssh_key(&binding.user_id, &binding.agent_id)?
            .is_some_and(|key| key.public_key == live_key.public_key
                && key.revoked_at.is_none()
                && key.lease_expires_at > chrono::Utc::now().timestamp()),
        "SSH key lease has expired or been revoked"
    );
    anyhow::ensure!(
        app.db
            .git_grant_permission(&binding.user_id, &binding.client_id, &repository_id)?
            .is_some_and(|permission| crate::git::grants::permits(&permission, operation)),
        "repository grant has been revoked"
    );
    anyhow::ensure!(
        app.db
            .integration(&repository.integration_id, &binding.user_id)?
            .is_some_and(
                |integration| integration.enabled && integration.identity_id == binding.identity_id
            ),
        "integration is disabled"
    );
    let maximum = app.config.git_max_request_bytes;
    let idle = Duration::from_secs(app.config.git_idle_timeout_secs);
    let upload_pack_rounds = matches!(service, crate::git::ssh::Service::UploadPack);
    let receive_pack = matches!(service, crate::git::ssh::Service::ReceivePack);
    let input = Arc::new(tokio::sync::Mutex::new(input));
    let mut rpc_url = upstream;
    rpc_url.set_path(&format!(
        "{}.git/{service_name}",
        rpc_url.path().trim_end_matches(".git")
    ));
    let mut seen = 0_u64;
    loop {
        let round_input = input.clone();
        let request_metrics = app.metrics.clone();
        let request_stream = async_stream::stream! {
            let mut round_seen = 0_u64;
            let mut tail = Vec::with_capacity(9);
            let mut pack_boundary = crate::git::pack::ReceivePackBoundary::default();
            loop {
                let next = {
                    let mut input = round_input.lock().await;
                    tokio::time::timeout(idle, input.recv()).await
                };
                match next {
                    Err(_) => {
                        yield Err::<bytes::Bytes, std::io::Error>(std::io::Error::new(std::io::ErrorKind::TimedOut, "SSH Git request idle timeout"));
                        break;
                    }
                    Ok(None) => break,
                    Ok(Some(Err(error))) => {
                        yield Err(std::io::Error::other(safe_error(error.as_ref())));
                        break;
                    }
                    Ok(Some(Ok(bytes))) => {
                        round_seen = round_seen.saturating_add(bytes.len() as u64);
                        if round_seen > maximum {
                            yield Err(std::io::Error::new(std::io::ErrorKind::FileTooLarge, "SSH Git request byte limit exceeded"));
                            break;
                        }
                        request_metrics.ssh_request_bytes.fetch_add(bytes.len() as u64, Ordering::Relaxed);
                        if upload_pack_rounds {
                            tail.extend_from_slice(&bytes);
                            if tail.len() > 9 {
                                tail.drain(..tail.len() - 9);
                            }
                        }
                        let pack_complete = if receive_pack {
                            match pack_boundary.push(&bytes) {
                                Ok(complete) => complete,
                                Err(error) => {
                                    yield Err(std::io::Error::new(std::io::ErrorKind::InvalidData, safe_error(error.as_ref())));
                                    break;
                                }
                            }
                        } else {
                            false
                        };
                        yield Ok(bytes);
                        if (upload_pack_rounds && (tail.ends_with(b"0000") || tail.ends_with(b"0009done\n"))) || pack_complete {
                            break;
                        }
                    }
                }
            }
        };
        let mut request = client
            .post(rpc_url.clone())
            .header(
                header::CONTENT_TYPE,
                format!("application/x-{service_name}-request"),
            )
            .header(
                header::ACCEPT,
                format!("application/x-{service_name}-result"),
            )
            .body(reqwest::Body::wrap_stream(request_stream));
        if let Some(protocol) = &git_protocol {
            request = request.header("Git-Protocol", protocol);
        }
        request = crate::git::service::apply_authorization(request, &authorization);
        let response = request.send().await?;
        anyhow::ensure!(response.status().is_success(), "upstream Git RPC failed");
        let mut body = response.bytes_stream();
        let mut marker = Vec::new();
        let mut saw_packfile = false;
        while let Some(chunk) = tokio::time::timeout(idle, body.next())
            .await
            .map_err(|_| anyhow::anyhow!("SSH Git response idle timeout"))?
        {
            let chunk = chunk?;
            seen = seen.saturating_add(chunk.len() as u64);
            anyhow::ensure!(
                seen <= app.config.git_max_response_bytes,
                "SSH Git response byte limit exceeded"
            );
            marker.extend_from_slice(&chunk);
            saw_packfile |= marker.windows(9).any(|window| window == b"packfile\n")
                || marker.windows(4).any(|window| window == b"PACK");
            if marker.len() > 64 {
                marker.drain(..marker.len() - 64);
            }
            app.metrics
                .ssh_response_bytes
                .fetch_add(chunk.len() as u64, Ordering::Relaxed);
            output
                .data(channel, chunk)
                .await
                .map_err(|_| anyhow::anyhow!("SSH client disconnected"))?;
        }
        let final_round = receive_pack || saw_packfile;
        if final_round {
            break;
        }
    }
    app.db.record_audit(
        Some(&binding.user_id),
        match operation {
            GitOperation::Read => "git.ssh_read",
            GitOperation::Write => "git.ssh_write",
        },
        Some(&repository_id),
        "success",
        &json!({"identity_id":binding.identity_id,"agent_id":binding.agent_id,"client_id":binding.client_id,"integration_id":repository.integration_id,"fingerprint":binding.fingerprint,"transport":"ssh","protocol":git_protocol.as_deref().unwrap_or("version=0")}),
    )?;
    Ok(())
}

pub fn build_store(c: &Config) -> anyhow::Result<Arc<dyn ObjectStore>> {
    // `from_env` selects object_store's expiration-aware web-identity,
    // container, or EC2 metadata provider when no static access key is set.
    // The resulting provider remains attached to this store, so every S3
    // operation (lease renewal, restore, replication, and final shutdown
    // sync/relinquish) asks the same cache for a currently valid credential.
    // The cache refreshes temporary credentials shortly before expiration.
    let mut b = AmazonS3Builder::from_env()
        .with_bucket_name(
            c.s3_bucket
                .as_deref()
                .context("S3 bucket is not configured")?,
        )
        .with_region(&c.s3_region)
        .with_allow_http(c.s3_allow_http)
        .with_virtual_hosted_style_request(false);
    if let Some(e) = &c.s3_endpoint {
        b = b.with_endpoint(e)
    }
    Ok(Arc::new(b.build()?))
}

fn ensure_local_database_compatible(config: &Config) -> anyhow::Result<()> {
    match Database::inspect_storage_mode(&config.db_path())? {
        Some(StorageMode::Local) | None if !config.db_path().exists() => Ok(()),
        Some(StorageMode::S3) => anyhow::bail!(
            "the existing database is an S3 working copy; configure COG_S3_BUCKET or use a different data directory"
        ),
        Some(StorageMode::Local) => Ok(()),
        None => anyhow::bail!(
            "the existing database predates local storage mode and is treated as S3-backed; configure COG_S3_BUCKET or migrate it explicitly"
        ),
    }
}

fn ensure_s3_database_compatible(config: &Config) -> anyhow::Result<()> {
    if Database::inspect_storage_mode(&config.db_path())? == Some(StorageMode::Local) {
        anyhow::bail!(
            "the existing database is local-only and cannot be started with S3; migrate it explicitly or use a different data directory"
        );
    }
    Ok(())
}
async fn health() -> Json<Value> {
    Json(json!({"status":"ok"}))
}
pub async fn readiness(State(a): State<App>) -> impl IntoResponse {
    let live = a.lease.is_live();
    let pending = a.replicator.pending_txids();
    let ssh_configured = a.config.ssh_listen.is_some();
    let ssh_ready = a.ssh_ready.load(Ordering::Acquire);
    let status = if live && pending == 0 && (!ssh_configured || ssh_ready) {
        StatusCode::OK
    } else {
        StatusCode::SERVICE_UNAVAILABLE
    };
    (
        status,
        Json(json!({
            "ready": status == StatusCode::OK,
            "lease": {
                "live": live,
                "generation": a.lease.generation(),
                "authority_until_ms": a.lease.authority_until_ms()
            },
            "replication": {
                "durable_txid": a.replicator.durable_txid(),
                "pending_txids": pending
            },
            "ssh": {
                "configured": ssh_configured,
                "ready": ssh_ready,
                "listen": a.config.ssh_listen.map(|address| address.to_string()),
                "publicHost": a.config.ssh_public_host,
                "publicPort": a.config.ssh_public_port.or_else(|| a.config.ssh_listen.map(|address| address.port())),
                "hostKeyFingerprint": a.ssh_keys.as_ref().and_then(|keys| keys.read().ok().map(|keys| crate::git::ssh::fingerprint(keys.host.public_key())))
            }
        })),
    )
}
async fn version(State(a): State<App>) -> Json<Value> {
    Json(json!({
        "name":"cog",
        "version":env!("CARGO_PKG_VERSION"),
        "schemaVersion": a.db.schema_version().unwrap_or(crate::db::SCHEMA_VERSION),
        "supportedSchemaVersion": crate::db::SCHEMA_VERSION
    }))
}
async fn metrics(State(a): State<App>) -> impl IntoResponse {
    let body = format!(
        concat!(
            "# TYPE cog_lease_live gauge\ncog_lease_live {}\n",
            "# TYPE cog_lease_generation gauge\ncog_lease_generation {}\n",
            "# TYPE cog_replication_durable_txid gauge\ncog_replication_durable_txid {}\n",
            "# TYPE cog_replication_lag_txids gauge\ncog_replication_lag_txids {}\n",
            "# TYPE cog_oauth_failures_total counter\ncog_oauth_failures_total {}\n",
            "# TYPE cog_execution_failures_total counter\ncog_execution_failures_total {}\n",
            "# TYPE cog_v8_limit_hits_total counter\ncog_v8_limit_hits_total {}\n",
            "# TYPE cog_upstream_calls_total counter\ncog_upstream_calls_total {}\n",
            "# TYPE cog_upstream_failures_total counter\ncog_upstream_failures_total {}\n",
            "# TYPE cog_ssh_handshakes_total counter\ncog_ssh_handshakes_total {}\n",
            "# TYPE cog_ssh_auth_total counter\ncog_ssh_auth_total{{result=\"success\"}} {}\ncog_ssh_auth_total{{result=\"denied\"}} {}\n",
            "# TYPE cog_ssh_active_sessions gauge\ncog_ssh_active_sessions {}\n",
            "# TYPE cog_ssh_operations_total counter\ncog_ssh_operations_total{{operation=\"read\"}} {}\ncog_ssh_operations_total{{operation=\"write\"}} {}\n",
            "# TYPE cog_ssh_bytes_total counter\ncog_ssh_bytes_total{{direction=\"request\"}} {}\ncog_ssh_bytes_total{{direction=\"response\"}} {}\n",
            "# TYPE cog_ssh_timeouts_total counter\ncog_ssh_timeouts_total {}\n",
            "# TYPE cog_ssh_limit_rejections_total counter\ncog_ssh_limit_rejections_total {}\n",
            "# TYPE cog_ssh_upstream_failures_total counter\ncog_ssh_upstream_failures_total {}\n",
            "# TYPE cog_ssh_keys_total counter\ncog_ssh_keys_total{{operation=\"register\"}} {}\ncog_ssh_keys_total{{operation=\"lease_renew\"}} {}\n"
        ),
        u8::from(a.lease.is_live()),
        a.lease.generation(),
        a.replicator.durable_txid(),
        a.replicator.pending_txids(),
        a.metrics.oauth_failures.load(Ordering::Relaxed),
        a.metrics.execution_failures.load(Ordering::Relaxed),
        a.metrics.v8_limit_hits.load(Ordering::Relaxed),
        a.metrics.upstream_calls.load(Ordering::Relaxed),
        a.metrics.upstream_failures.load(Ordering::Relaxed),
        a.metrics.ssh_handshakes.load(Ordering::Relaxed),
        a.metrics.ssh_auth_success.load(Ordering::Relaxed),
        a.metrics.ssh_auth_denied.load(Ordering::Relaxed),
        a.metrics.ssh_active_sessions.load(Ordering::Relaxed),
        a.metrics.ssh_read_operations.load(Ordering::Relaxed),
        a.metrics.ssh_write_operations.load(Ordering::Relaxed),
        a.metrics.ssh_request_bytes.load(Ordering::Relaxed),
        a.metrics.ssh_response_bytes.load(Ordering::Relaxed),
        a.metrics.ssh_timeouts.load(Ordering::Relaxed),
        a.metrics.ssh_limit_rejections.load(Ordering::Relaxed),
        a.metrics.ssh_upstream_failures.load(Ordering::Relaxed),
        a.metrics.ssh_key_registrations.load(Ordering::Relaxed),
        a.metrics.ssh_key_lease_renewals.load(Ordering::Relaxed),
    );
    (
        [(http::header::CONTENT_TYPE, "text/plain; version=0.0.4")],
        body,
    )
}
pub fn frontend_response(path: &str) -> Response {
    let Some(file) = Frontend::get(path) else {
        return StatusCode::NOT_FOUND.into_response();
    };
    let content_type = match path.rsplit_once('.').map(|(_, extension)| extension) {
        Some("html") => "text/html; charset=utf-8",
        Some("css") => "text/css; charset=utf-8",
        Some("js") => "text/javascript; charset=utf-8",
        Some("svg") => "image/svg+xml",
        Some("png") => "image/png",
        Some("woff2") => "font/woff2",
        _ => "application/octet-stream",
    };
    (
        [(header::CONTENT_TYPE, content_type)],
        bytes::Bytes::copy_from_slice(file.data.as_ref()),
    )
        .into_response()
}

async fn ui_asset(Path(path): Path<String>) -> Response {
    frontend_response(&format!("assets/{path}"))
}

fn ui_shell() -> Response {
    let mut response = frontend_response("index.html");
    response.headers_mut().insert(
        header::CACHE_CONTROL,
        header::HeaderValue::from_static("no-cache"),
    );
    response
}

async fn home() -> Response {
    ui_shell()
}

fn cookie(headers: &HeaderMap, name: &str) -> Option<String> {
    headers
        .get(http::header::COOKIE)?
        .to_str()
        .ok()?
        .split(';')
        .filter_map(|part| part.trim().split_once('='))
        .find_map(|(key, value)| (key == name).then(|| value.to_owned()))
}

fn origin_allowed(a: &App, headers: &HeaderMap) -> bool {
    let Some(origin) = headers
        .get(http::header::ORIGIN)
        .and_then(|value| value.to_str().ok())
    else {
        return false;
    };
    let expected = a.config.base_url.origin().ascii_serialization();
    origin == expected
}

fn browser_session(a: &App, headers: &HeaderMap, csrf: Option<&str>) -> Option<String> {
    let session = cookie(headers, "cog_session")?;
    let csrf_hash = csrf.map(token_hash);
    a.db.session_user(
        &token_hash(&session),
        csrf_hash.as_ref().map(<[u8; 32]>::as_slice),
        chrono::Utc::now().timestamp(),
    )
    .ok()
    .flatten()
}

pub fn rate_limit(
    a: &App,
    action: &str,
    subject: &str,
    maximum: usize,
) -> Option<axum::response::Response> {
    if a.auth_rate_limit.allow(
        format!("{action}:{}", subject.to_ascii_lowercase()),
        maximum,
        Duration::from_secs(60),
    ) {
        None
    } else {
        Some(
            (
                StatusCode::TOO_MANY_REQUESTS,
                [(http::header::RETRY_AFTER, "60")],
                "rate limit exceeded",
            )
                .into_response(),
        )
    }
}

fn audit(
    a: &App,
    actor: Option<&str>,
    action: &str,
    target: Option<&str>,
    outcome: &str,
) -> anyhow::Result<()> {
    a.db.record_audit(actor, action, target, outcome, &json!({}))
}

fn audit_details(
    a: &App,
    actor: Option<&str>,
    action: &str,
    target: Option<&str>,
    outcome: &str,
    details: &Value,
) -> anyhow::Result<()> {
    a.db.record_audit(actor, action, target, outcome, details)
}

async fn login_page() -> Response {
    ui_shell()
}

#[derive(Deserialize)]
struct LoginForm {
    email: String,
    password: String,
}

async fn login(
    State(a): State<App>,
    headers: HeaderMap,
    Form(form): Form<LoginForm>,
) -> impl IntoResponse {
    if let Some(response) = rate_limit(&a, "login", &form.email, 10) {
        return response;
    }
    if !origin_allowed(&a, &headers) {
        return (StatusCode::FORBIDDEN, "invalid origin").into_response();
    }
    let Some((user, hash)) = a.db.user_by_email(&form.email).ok().flatten() else {
        if audit(&a, Some(&form.email), "session.login", None, "denied").is_ok() {
            let _ = persist(&a).await;
        }
        return (StatusCode::UNAUTHORIZED, "invalid credentials").into_response();
    };
    let valid = PasswordHash::new(&hash).ok().is_some_and(|hash| {
        Argon2::default()
            .verify_password(form.password.as_bytes(), &hash)
            .is_ok()
    });
    if !valid {
        if audit(&a, Some(&form.email), "session.login", None, "denied").is_ok() {
            let _ = persist(&a).await;
        }
        return (StatusCode::UNAUTHORIZED, "invalid credentials").into_response();
    }
    let session = crate::crypto::random_token(32);
    let csrf = crate::crypto::random_token(32);
    if let Err(error) = a.db.create_session(
        &token_hash(&session),
        &user,
        &token_hash(&csrf),
        chrono::Utc::now().timestamp() + 12 * 3600,
    ) {
        return (StatusCode::INTERNAL_SERVER_ERROR, error.to_string()).into_response();
    }
    if let Err(error) = audit(&a, Some(&user), "session.login", None, "success") {
        return (StatusCode::INTERNAL_SERVER_ERROR, error.to_string()).into_response();
    }
    if let Err(error) = persist(&a).await {
        return (StatusCode::SERVICE_UNAVAILABLE, error.to_string()).into_response();
    }
    let secure = if a.config.base_url.scheme() == "https" {
        "; Secure"
    } else {
        ""
    };
    let session_cookie =
        format!("cog_session={session}; Path=/; HttpOnly; SameSite=Lax; Max-Age=43200{secure}");
    let csrf_cookie = format!("cog_csrf={csrf}; Path=/; SameSite=Lax; Max-Age=43200{secure}");
    let mut response = (StatusCode::SEE_OTHER, [(http::header::LOCATION, "/")]).into_response();
    response.headers_mut().append(
        http::header::SET_COOKIE,
        http::HeaderValue::from_str(&session_cookie).expect("generated session cookie is valid"),
    );
    response.headers_mut().append(
        http::header::SET_COOKIE,
        http::HeaderValue::from_str(&csrf_cookie).expect("generated CSRF cookie is valid"),
    );
    response
}

#[derive(Deserialize)]
pub struct CsrfForm {
    pub csrf_token: String,
}

async fn logout(
    State(a): State<App>,
    headers: HeaderMap,
    Form(form): Form<CsrfForm>,
) -> impl IntoResponse {
    if !origin_allowed(&a, &headers) {
        return (StatusCode::FORBIDDEN, "invalid session or CSRF token").into_response();
    }
    let Some(user) = browser_session(&a, &headers, Some(&form.csrf_token)) else {
        return (StatusCode::FORBIDDEN, "invalid session or CSRF token").into_response();
    };
    let session = cookie(&headers, "cog_session").expect("validated session cookie");
    if let Err(error) = a.db.delete_session(&token_hash(&session)) {
        return (StatusCode::INTERNAL_SERVER_ERROR, error.to_string()).into_response();
    }
    if let Err(error) = audit(&a, Some(&user), "session.logout", None, "success") {
        return (StatusCode::INTERNAL_SERVER_ERROR, error.to_string()).into_response();
    }
    if let Err(error) = persist(&a).await {
        return (StatusCode::SERVICE_UNAVAILABLE, error.to_string()).into_response();
    }
    let mut response = (StatusCode::SEE_OTHER, [(http::header::LOCATION, "/")]).into_response();
    for cookie in [
        "cog_session=; Path=/; HttpOnly; SameSite=Lax; Max-Age=0",
        "cog_csrf=; Path=/; SameSite=Lax; Max-Age=0",
    ] {
        response.headers_mut().append(
            http::header::SET_COOKIE,
            http::HeaderValue::from_static(cookie),
        );
    }
    response
}

fn html_escape(value: &str) -> String {
    value
        .replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('"', "&quot;")
        .replace('\'', "&#39;")
}

async fn admin_ui(State(a): State<App>, headers: HeaderMap) -> Response {
    if browser_session(&a, &headers, None).is_none() {
        return Redirect::to("/login").into_response();
    }
    ui_shell()
}

async fn ui_bootstrap(State(a): State<App>, headers: HeaderMap) -> impl IntoResponse {
    let Some(user) = browser_session(&a, &headers, None) else {
        return Json(json!({"mode": "login"})).into_response();
    };
    let Some(csrf) = cookie(&headers, "cog_csrf") else {
        return (StatusCode::FORBIDDEN, "CSRF cookie missing").into_response();
    };
    let integrations = match a.db.list_integrations(&user) {
        Ok(items) => items
            .into_iter()
            .map(|integration| {
                let token = a.db.upstream_oauth_token(&integration.id).ok().flatten();
                let oauth = if integration.config.get("oauth").is_none() {
                    "not configured"
                } else if token.is_some() {
                    "connected"
                } else {
                    "connection required"
                };
                let oauth_scopes = token
                    .map(|token| {
                        token
                            .scope
                            .split_ascii_whitespace()
                            .map(str::to_owned)
                            .collect::<Vec<_>>()
                    })
                    .unwrap_or_default();
                json!({
                    "id": integration.id,
                    "identity_id":integration.identity_id,
                    "name": integration.name,
                    "display_name":integration.name,
                    "provider_name":integration.provider_name,
                    "provider_account":integration.provider_account,
                    "transport": integration.transport,
                    "enabled": integration.enabled,
                    "oauth": oauth,
                    "oauth_scopes": oauth_scopes,
                })
            })
            .collect::<Vec<_>>(),
        Err(error) => {
            return (StatusCode::INTERNAL_SERVER_ERROR, error.to_string()).into_response();
        }
    };
    let clients = a.db.agent_clients(&user).unwrap_or_default();
    let tokens = a.db.agent_tokens(&user).unwrap_or_default();
    let identities=a.db.list_identities(&user).unwrap_or_default().into_iter().map(|identity|{
        let connections=integrations.iter().filter(|connection|connection.get("identity_id").and_then(Value::as_str)==Some(identity.id.as_str())).cloned().collect::<Vec<_>>();
        let agents=a.db.agents_for_identity(&user,&identity.id).unwrap_or_default();
        let grants=a.db.identity_grants(&user,&identity.id).unwrap_or_default();
        json!({"id":identity.id,"name":identity.name,"created_at":identity.created_at,"updated_at":identity.updated_at,"connections":connections,"agents":agents,"grants":grants})
    }).collect::<Vec<_>>();
    let ssh_keys = a.db.ssh_keys().unwrap_or_default().into_iter().map(|key| json!({
        "id":key.id,
        "purpose":key.purpose,
        "algorithm":key.algorithm,
        "fingerprint":ssh_key::PublicKey::from_openssh(&key.public_key).ok().map(|key| crate::git::ssh::fingerprint(&key)),
        "created_at":key.created_at,
        "active":key.active,
        "retirement_time":key.retirement_time
    })).collect::<Vec<_>>();
    Json(json!({
        "mode": "admin",
        "user": user,
        "csrf_token": csrf,
        "integrations": integrations,
        "clients": clients,
        "tokens": tokens,
        "identities": identities,
        "ssh": {
            "configured": a.config.ssh_listen.is_some(),
            "ready": a.ssh_ready.load(Ordering::Acquire),
            "public_host": a.config.ssh_public_host,
            "public_port": a.config.ssh_public_port.or_else(|| a.config.ssh_listen.map(|address| address.port())),
            "key_lease_ttl_seconds": a.config.ssh_key_lease_ttl_secs,
            "keys": ssh_keys
        },
        "git_transport_usage": {
            "ssh_operations": a.metrics.ssh_read_operations.load(Ordering::Relaxed) + a.metrics.ssh_write_operations.load(Ordering::Relaxed)
        }
    }))
    .into_response()
}

#[derive(Deserialize)]
pub struct UiIntegrationForm {
    pub name: String,
    pub url: url::Url,
    pub csrf_token: String,
}
#[derive(Deserialize)]
pub struct UiNameForm {
    pub name: String,
    pub csrf_token: String,
}

pub async fn ui_prepare_ssh_key(
    State(a): State<App>,
    Path(purpose): Path<String>,
    headers: HeaderMap,
    Form(form): Form<CsrfForm>,
) -> Response {
    let _mutation = a.mutations.lock().await;
    let user = match ui_user(&a, &headers, &form.csrf_token) {
        Ok(user) => user,
        Err(error) => return (StatusCode::FORBIDDEN, error).into_response(),
    };
    let result = (|| -> anyhow::Result<crate::db::SshKeyRecord> {
        a.lease.assert_live()?;
        anyhow::ensure!(purpose == "host", "invalid SSH key purpose");
        let key = crate::git::ssh::generate_key()?;
        let public = key.public_key().to_openssh()?;
        let encrypted = a.secrets.seal(&crate::git::ssh::encode_private(&key)?)?;
        a.db.prepare_ssh_key(&purpose, &public, &encrypted)
    })();
    match result {
        Ok(key) => {
            let fingerprint = ssh_key::PublicKey::from_openssh(&key.public_key)
                .map(|key| crate::git::ssh::fingerprint(&key))
                .unwrap_or_else(|_| "invalid".into());
            if let Err(error) = a.db.record_audit(
                Some(&user),
                "git.ssh_key.prepare",
                Some(&key.id),
                "success",
                &json!({"purpose":purpose,"fingerprint":fingerprint}),
            ) {
                return (
                    StatusCode::INTERNAL_SERVER_ERROR,
                    safe_error(error.as_ref()),
                )
                    .into_response();
            }
            if let Err(error) = persist(&a).await {
                return (StatusCode::SERVICE_UNAVAILABLE, safe_error(error.as_ref()))
                    .into_response();
            }
            Redirect::to("/ui").into_response()
        }
        Err(error) => (StatusCode::BAD_REQUEST, safe_error(error.as_ref())).into_response(),
    }
}

pub async fn ui_activate_ssh_key(
    State(a): State<App>,
    Path((purpose, id)): Path<(String, String)>,
    headers: HeaderMap,
    Form(form): Form<CsrfForm>,
) -> Response {
    let _mutation = a.mutations.lock().await;
    let user = match ui_user(&a, &headers, &form.csrf_token) {
        Ok(user) => user,
        Err(error) => return (StatusCode::FORBIDDEN, error).into_response(),
    };
    if purpose == "host" && a.ssh_ready.load(Ordering::Acquire) {
        return (
            StatusCode::CONFLICT,
            "disable SSH and restart COG before activating a prepared host key",
        )
            .into_response();
    }
    let overlap = 86_400;
    let result =
        a.db.activate_ssh_key(&id, &purpose, chrono::Utc::now().timestamp() + overlap);
    if let Err(error) = result {
        return (StatusCode::BAD_REQUEST, safe_error(error.as_ref())).into_response();
    }
    if let Err(error) = a.db.record_audit(
        Some(&user),
        "git.ssh_key.activate",
        Some(&id),
        "success",
        &json!({"purpose":purpose,"overlap_until":chrono::Utc::now().timestamp()+overlap}),
    ) {
        return (
            StatusCode::INTERNAL_SERVER_ERROR,
            safe_error(error.as_ref()),
        )
            .into_response();
    }
    if let Err(error) = persist(&a).await {
        return (StatusCode::SERVICE_UNAVAILABLE, safe_error(error.as_ref())).into_response();
    }
    Redirect::to("/ui").into_response()
}

pub async fn ui_retire_ssh_key(
    State(a): State<App>,
    Path((purpose, id)): Path<(String, String)>,
    headers: HeaderMap,
    Form(form): Form<CsrfForm>,
) -> Response {
    let _mutation = a.mutations.lock().await;
    let user = match ui_user(&a, &headers, &form.csrf_token) {
        Ok(user) => user,
        Err(error) => return (StatusCode::FORBIDDEN, error).into_response(),
    };
    match a.db.retire_ssh_key(&id, chrono::Utc::now().timestamp()) {
        Ok(()) => {
            let _ = a.db.record_audit(
                Some(&user),
                "git.ssh_key.retire",
                Some(&id),
                "success",
                &json!({"purpose":purpose}),
            );
            match persist(&a).await {
                Ok(()) => Redirect::to("/ui").into_response(),
                Err(error) => {
                    (StatusCode::SERVICE_UNAVAILABLE, safe_error(error.as_ref())).into_response()
                }
            }
        }
        Err(error) => (StatusCode::BAD_REQUEST, safe_error(error.as_ref())).into_response(),
    }
}
pub async fn ui_create_identity(
    State(a): State<App>,
    headers: HeaderMap,
    Form(form): Form<UiNameForm>,
) -> impl IntoResponse {
    let user = match ui_user(&a, &headers, &form.csrf_token) {
        Ok(user) => user,
        Err(error) => return (StatusCode::FORBIDDEN, error).into_response(),
    };
    match a.db.create_identity(&user, &form.name) {
        Ok(id) => {
            let _ = a.db.record_audit(
                Some(&user),
                "identity.create",
                Some(&id),
                "success",
                &json!({"identity_id":id}),
            );
            if let Err(error) = persist(&a).await {
                return (StatusCode::SERVICE_UNAVAILABLE, error.to_string()).into_response();
            }
            StatusCode::NO_CONTENT.into_response()
        }
        Err(error) => (StatusCode::BAD_REQUEST, error.to_string()).into_response(),
    }
}
pub async fn ui_rename_identity(
    State(a): State<App>,
    Path(id): Path<String>,
    headers: HeaderMap,
    Form(form): Form<UiNameForm>,
) -> impl IntoResponse {
    let user = match ui_user(&a, &headers, &form.csrf_token) {
        Ok(user) => user,
        Err(error) => return (StatusCode::FORBIDDEN, error).into_response(),
    };
    match a.db.rename_identity(&user, &id, &form.name) {
        Ok(true) => {
            let _ = a.db.record_audit(
                Some(&user),
                "identity.rename",
                Some(&id),
                "success",
                &json!({"identity_id":id}),
            );
            let _ = persist(&a).await;
            StatusCode::NO_CONTENT.into_response()
        }
        Ok(false) => StatusCode::NOT_FOUND.into_response(),
        Err(error) => (StatusCode::BAD_REQUEST, error.to_string()).into_response(),
    }
}
pub async fn ui_delete_identity(
    State(a): State<App>,
    Path(id): Path<String>,
    headers: HeaderMap,
    Form(form): Form<CsrfForm>,
) -> impl IntoResponse {
    let user = match ui_user(&a, &headers, &form.csrf_token) {
        Ok(user) => user,
        Err(error) => return (StatusCode::FORBIDDEN, error).into_response(),
    };
    match a.db.delete_identity(&user, &id) {
        Ok(true) => {
            let _ = a.db.record_audit(
                Some(&user),
                "identity.delete",
                Some(&id),
                "success",
                &json!({"identity_id":id}),
            );
            let _ = persist(&a).await;
            StatusCode::NO_CONTENT.into_response()
        }
        Ok(false) => StatusCode::NOT_FOUND.into_response(),
        Err(error) => (StatusCode::BAD_REQUEST, error.to_string()).into_response(),
    }
}
pub async fn ui_rename_agent(
    State(a): State<App>,
    Path(id): Path<String>,
    headers: HeaderMap,
    Form(form): Form<UiNameForm>,
) -> impl IntoResponse {
    let user = match ui_user(&a, &headers, &form.csrf_token) {
        Ok(user) => user,
        Err(error) => return (StatusCode::FORBIDDEN, error).into_response(),
    };
    match a.db.rename_agent(&user, &id, &form.name) {
        Ok(true) => {
            let _ = a.db.record_audit(
                Some(&user),
                "agent.rename",
                Some(&id),
                "success",
                &json!({"agent_id":id}),
            );
            let _ = persist(&a).await;
            StatusCode::NO_CONTENT.into_response()
        }
        Ok(false) => StatusCode::NOT_FOUND.into_response(),
        Err(error) => (StatusCode::BAD_REQUEST, error.to_string()).into_response(),
    }
}

fn ui_user(a: &App, headers: &HeaderMap, csrf: &str) -> Result<String, &'static str> {
    if !origin_allowed(a, headers) {
        return Err("invalid origin");
    }
    browser_session(a, headers, Some(csrf)).ok_or("invalid session or CSRF token")
}

pub async fn ui_add_integration(
    State(a): State<App>,
    headers: HeaderMap,
    Form(form): Form<UiIntegrationForm>,
) -> impl IntoResponse {
    let user = match ui_user(&a, &headers, &form.csrf_token) {
        Ok(user) => user,
        Err(error) => return (StatusCode::FORBIDDEN, error).into_response(),
    };
    if !matches!(form.url.scheme(), "http" | "https") {
        return (StatusCode::BAD_REQUEST, "HTTP URL required").into_response();
    }
    let id =
        match a
            .db
            .create_integration(&user, &form.name, "http", &json!({"url":form.url}), None)
        {
            Ok(id) => id,
            Err(error) => return (StatusCode::BAD_REQUEST, error.to_string()).into_response(),
        };
    if let Err(error) = audit(&a, Some(&user), "integration.create", Some(&id), "success") {
        return (StatusCode::INTERNAL_SERVER_ERROR, error.to_string()).into_response();
    }
    match persist(&a).await {
        Ok(()) => Redirect::to("/ui").into_response(),
        Err(error) => (StatusCode::SERVICE_UNAVAILABLE, error.to_string()).into_response(),
    }
}

pub async fn ui_delete_integration(
    State(a): State<App>,
    Path(id): Path<String>,
    headers: HeaderMap,
    Form(form): Form<CsrfForm>,
) -> impl IntoResponse {
    let _mutation = a.mutations.lock().await;
    let user = match ui_user(&a, &headers, &form.csrf_token) {
        Ok(user) => user,
        Err(error) => return (StatusCode::FORBIDDEN, error).into_response(),
    };
    match a.db.delete_integration(&id, &user) {
        Ok(true) => {
            disconnect_provider(&a, &id).await;
            if let Err(error) = audit(&a, Some(&user), "integration.delete", Some(&id), "success") {
                return (StatusCode::INTERNAL_SERVER_ERROR, error.to_string()).into_response();
            }
            match persist(&a).await {
                Ok(()) => Redirect::to("/ui").into_response(),
                Err(error) => (StatusCode::SERVICE_UNAVAILABLE, error.to_string()).into_response(),
            }
        }
        Ok(false) => StatusCode::NOT_FOUND.into_response(),
        Err(error) => (StatusCode::INTERNAL_SERVER_ERROR, error.to_string()).into_response(),
    }
}

pub async fn ui_disconnect_integration(
    State(a): State<App>,
    Path(id): Path<String>,
    headers: HeaderMap,
    Form(form): Form<CsrfForm>,
) -> impl IntoResponse {
    let user = match ui_user(&a, &headers, &form.csrf_token) {
        Ok(user) => user,
        Err(error) => return (StatusCode::FORBIDDEN, error).into_response(),
    };
    match admin_disconnect(&a, &user, &id).await {
        Ok(_) => Redirect::to("/ui").into_response(),
        Err(error) if error.to_string().contains("not found") => {
            StatusCode::NOT_FOUND.into_response()
        }
        Err(error) => (StatusCode::BAD_REQUEST, error.to_string()).into_response(),
    }
}

pub async fn ui_revoke_token(
    State(a): State<App>,
    Path(id): Path<String>,
    headers: HeaderMap,
    Form(form): Form<CsrfForm>,
) -> impl IntoResponse {
    let _mutation = a.mutations.lock().await;
    let user = match ui_user(&a, &headers, &form.csrf_token) {
        Ok(user) => user,
        Err(error) => return (StatusCode::FORBIDDEN, error).into_response(),
    };
    match a.db.revoke_agent_token(&user, &id) {
        Ok(true) => {
            if let Err(error) = audit(&a, Some(&user), "agent_token.revoke", Some(&id), "success") {
                return (StatusCode::INTERNAL_SERVER_ERROR, error.to_string()).into_response();
            }
            match persist(&a).await {
                Ok(()) => Redirect::to("/ui").into_response(),
                Err(error) => (StatusCode::SERVICE_UNAVAILABLE, error.to_string()).into_response(),
            }
        }
        Ok(false) => StatusCode::NOT_FOUND.into_response(),
        Err(error) => (StatusCode::INTERNAL_SERVER_ERROR, error.to_string()).into_response(),
    }
}

pub async fn ui_revoke_client(
    State(a): State<App>,
    Path(id): Path<String>,
    headers: HeaderMap,
    Form(form): Form<CsrfForm>,
) -> impl IntoResponse {
    let _mutation = a.mutations.lock().await;
    let user = match ui_user(&a, &headers, &form.csrf_token) {
        Ok(user) => user,
        Err(error) => return (StatusCode::FORBIDDEN, error).into_response(),
    };
    match a.db.revoke_agent_client(&user, &id) {
        Ok(true) => {
            if let Err(error) = audit(&a, Some(&user), "agent_client.revoke", Some(&id), "success")
            {
                return (StatusCode::INTERNAL_SERVER_ERROR, error.to_string()).into_response();
            }
            match persist(&a).await {
                Ok(()) => Redirect::to("/ui").into_response(),
                Err(error) => (StatusCode::SERVICE_UNAVAILABLE, error.to_string()).into_response(),
            }
        }
        Ok(false) => StatusCode::NOT_FOUND.into_response(),
        Err(error) => (StatusCode::INTERNAL_SERVER_ERROR, error.to_string()).into_response(),
    }
}

pub async fn ui_revoke_grant(
    State(a): State<App>,
    Path((client, integration)): Path<(String, String)>,
    headers: HeaderMap,
    Form(form): Form<CsrfForm>,
) -> impl IntoResponse {
    let user = match ui_user(&a, &headers, &form.csrf_token) {
        Ok(user) => user,
        Err(error) => return (StatusCode::FORBIDDEN, error).into_response(),
    };
    match admin_revoke_grant(&a, &user, &client, &integration).await {
        Ok(_) => Redirect::to("/ui").into_response(),
        Err(error) => (StatusCode::BAD_REQUEST, error.to_string()).into_response(),
    }
}

pub async fn ui_grant_integration(
    State(a): State<App>,
    Path((client, integration)): Path<(String, String)>,
    headers: HeaderMap,
    Form(form): Form<CsrfForm>,
) -> impl IntoResponse {
    let _mutation = a.mutations.lock().await;
    let user = match ui_user(&a, &headers, &form.csrf_token) {
        Ok(user) => user,
        Err(error) => return (StatusCode::FORBIDDEN, error).into_response(),
    };
    match a.db.grant_client_integration(&user, &client, &integration) {
        Ok(_) => {
            if let Err(error) = audit(
                &a,
                Some(&user),
                "agent_client.integration_grant",
                Some(&integration),
                "success",
            ) {
                return (
                    StatusCode::INTERNAL_SERVER_ERROR,
                    safe_error(error.as_ref()),
                )
                    .into_response();
            }
            match persist(&a).await {
                Ok(()) => Redirect::to("/ui").into_response(),
                Err(error) => {
                    (StatusCode::SERVICE_UNAVAILABLE, safe_error(error.as_ref())).into_response()
                }
            }
        }
        Err(error) => (StatusCode::BAD_REQUEST, safe_error(error.as_ref())).into_response(),
    }
}
async fn auth_metadata(State(a): State<App>) -> Json<Value> {
    let b = a.config.base_url.as_str().trim_end_matches('/');
    let scopes = vec![
        "mcp".to_owned(),
        "integrations:read".to_owned(),
        "integrations:write".to_owned(),
        "agents:read".to_owned(),
        "agents:write".to_owned(),
        "audit:read".to_owned(),
        "git:read".to_owned(),
        "git:write".to_owned(),
    ];
    Json(
        json!({"issuer":b,"authorization_endpoint":format!("{b}/oauth/authorize"),"token_endpoint":format!("{b}/oauth/token"),"revocation_endpoint":format!("{b}/oauth/revoke"),"registration_endpoint":format!("{b}/oauth/register"),"response_types_supported":["code"],"grant_types_supported":["authorization_code","refresh_token"],"code_challenge_methods_supported":["S256"],"token_endpoint_auth_methods_supported":["none"],"scopes_supported":scopes}),
    )
}
async fn resource_metadata(State(a): State<App>) -> Json<Value> {
    let b = a.config.base_url.as_str().trim_end_matches('/');
    Json(
        json!({"resource":format!("{b}/mcp"),"authorization_servers":[b],"scopes_supported":["mcp","git:read","git:write"]}),
    )
}

async fn oauth_client_metadata(State(a): State<App>) -> Json<Value> {
    let b = a.config.base_url.as_str().trim_end_matches('/');
    Json(json!({
        "client_id": format!("{b}/.well-known/oauth-client"),
        "client_name": "cog",
        "client_uri": b,
        "redirect_uris": [format!("{b}/oauth/upstream/callback")],
        "grant_types": ["authorization_code", "refresh_token"],
        "response_types": ["code"],
        "token_endpoint_auth_method": "none"
    }))
}
async fn register(
    State(a): State<App>,
    Json(r): Json<oauth::RegistrationRequest>,
) -> impl IntoResponse {
    if let Some(response) = rate_limit(&a, "registration", "global", 20) {
        return response;
    }
    let _mutation = a.mutations.lock().await;
    if let Err(e) = a.lease.assert_live() {
        return (
            StatusCode::SERVICE_UNAVAILABLE,
            Json(json!({"error":"temporarily_unavailable","error_description":e.to_string()})),
        )
            .into_response();
    }
    match oauth::register(&a.db, r) {
        Ok(result) => {
            if result.created
                && let Err(error) = audit(
                    &a,
                    None,
                    "oauth.register",
                    Some(&result.response.client_id),
                    "success",
                )
            {
                return (
                    StatusCode::INTERNAL_SERVER_ERROR,
                    Json(json!({"error":"server_error","error_description":error.to_string()})),
                )
                    .into_response();
            }
            match if result.changed { persist(&a).await } else { Ok(()) } {
            Ok(()) => (StatusCode::CREATED, Json(json!(result.response))).into_response(),
            Err(e) => (
                StatusCode::SERVICE_UNAVAILABLE,
                Json(json!({"error":"temporarily_unavailable","error_description":e.to_string()})),
            )
                .into_response(),
            }
        }
        Err(e) => (
            StatusCode::BAD_REQUEST,
            Json(json!({"error":"invalid_client_metadata","error_description":e.to_string()})),
        )
            .into_response(),
    }
}
#[derive(Deserialize)]
pub struct Authorize {
    #[serde(default = "response_code")]
    pub response_type: String,
    pub client_id: String,
    pub redirect_uri: String,
    pub state: String,
    pub code_challenge: String,
    #[serde(default = "challenge_s256")]
    pub code_challenge_method: String,
    #[serde(default = "scope_mcp")]
    pub scope: String,
    pub resource: String,
}

#[derive(Serialize, Deserialize)]
pub struct ConsentRequest {
    pub response_type: String,
    pub client_id: String,
    pub redirect_uri: String,
    pub state: String,
    pub code_challenge: String,
    pub code_challenge_method: String,
    pub requested_scope: String,
    pub resource: String,
    pub user: String,
    pub allowed_identity_ids: Vec<String>,
    pub fixed_identity_id: Option<String>,
    pub expires_at: i64,
    #[serde(default)]
    pub git_pending_ids: Vec<String>,
}

#[derive(Deserialize)]
pub struct ConsentForm {
    pub consent: String,
    pub csrf_token: String,
    pub decision: String,
    #[serde(flatten)]
    pub fields: HashMap<String, String>,
}
pub fn response_code() -> String {
    "code".into()
}
pub fn challenge_s256() -> String {
    "S256".into()
}
pub fn scope_mcp() -> String {
    "mcp".into()
}

fn standalone_page(eyebrow: &str, title: &str, body: &str, _tone: &str) -> String {
    format!(
        r##"<!doctype html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><meta name="color-scheme" content="light dark"><meta name="theme-color" content="#fafafa"><title>{title} · Clanker Operations Gateway</title><style>
:root{{color-scheme:light;font-family:Inter,ui-sans-serif,system-ui,-apple-system,BlinkMacSystemFont,"Segoe UI",sans-serif;color:#18181b;background:#fafafa;font-synthesis:none}}*{{box-sizing:border-box}}body{{margin:0;min-width:320px;min-height:100vh;background:radial-gradient(circle at 20% 0%,#dbeafe 0,transparent 32rem),#fafafa}}main{{width:min(100% - 2rem,720px);min-height:100vh;margin:auto;padding:2rem 0;display:grid;grid-template-rows:auto 1fr auto}}header{{display:flex;align-items:center;gap:.75rem}}.mark{{width:2.5rem;height:2.5rem;display:grid;place-items:center;border-radius:.75rem;background:#3b82f6;color:white;box-shadow:0 10px 25px rgba(59,130,246,.25)}}.brand{{font-size:1.05rem;font-weight:750;letter-spacing:-.02em}}.tagline,.muted{{color:#71717a}}.tagline{{font-size:.75rem}}.stage{{display:grid;place-items:center;padding:2.5rem 0}}.card{{width:100%;padding:clamp(1.35rem,5vw,2.25rem);border:1px solid #e4e4e7;border-radius:1.25rem;background:rgba(255,255,255,.88);box-shadow:0 22px 55px rgba(39,39,42,.12);backdrop-filter:blur(14px)}}.eyebrow{{margin:0;color:#2563eb;font-size:.72rem;font-weight:750;text-transform:uppercase;letter-spacing:.18em}}h1{{margin:.65rem 0 0;font-size:clamp(1.75rem,5vw,2.35rem);line-height:1.1;letter-spacing:-.035em}}p{{line-height:1.65}}.lead{{margin:.85rem 0 0;color:#52525b}}.notice{{margin:1.4rem 0 0;padding:1rem;border:1px solid #e4e4e7;border-radius:.8rem;background:#fafafa;color:#52525b;font-size:.9rem}}.notice.success{{border-color:#bbf7d0;background:#f0fdf4;color:#166534}}.notice.warning{{border-color:#fde68a;background:#fffbeb;color:#92400e}}.notice.danger{{border-color:#fecaca;background:#fef2f2;color:#991b1b}}.button{{appearance:none;border:0;border-radius:.65rem;padding:.72rem 1rem;background:#3b82f6;color:white;font:inherit;font-size:.9rem;font-weight:700;cursor:pointer;text-decoration:none;display:inline-flex;align-items:center;justify-content:center;transition:background .15s,transform .15s}}.button:hover{{background:#2563eb}}.button:active{{transform:translateY(1px)}}.button.secondary{{border:1px solid #e4e4e7;background:white;color:#3f3f46}}.button.secondary:hover{{background:#f4f4f5}}.actions{{display:flex;gap:.75rem;margin-top:1.5rem}}footer{{padding:.5rem 0;color:#a1a1aa;text-align:center;font-size:.72rem}}code{{font-family:ui-monospace,SFMono-Regular,Menlo,monospace}}
@media(max-width:520px){{.actions{{flex-direction:column}}.button{{width:100%}}}}
@media(prefers-color-scheme:dark){{:root{{color-scheme:dark;color:#e4e4e7;background:#09090b}}body{{background:radial-gradient(circle at 20% 0%,#18233b 0,transparent 32rem),#09090b}}.card{{border-color:rgba(255,255,255,.1);background:rgba(24,24,27,.82);box-shadow:0 24px 70px rgba(0,0,0,.3)}}.tagline,.muted{{color:#a1a1aa}}.lead{{color:#a1a1aa}}.notice{{border-color:rgba(255,255,255,.1);background:rgba(0,0,0,.22);color:#d4d4d8}}.notice.success{{border-color:rgba(34,197,94,.25);background:rgba(34,197,94,.1);color:#bbf7d0}}.notice.warning{{border-color:rgba(245,158,11,.25);background:rgba(245,158,11,.1);color:#fde68a}}.notice.danger{{border-color:rgba(239,68,68,.25);background:rgba(239,68,68,.1);color:#fecaca}}.button.secondary{{border-color:rgba(255,255,255,.12);background:rgba(255,255,255,.05);color:#e4e4e7}}.button.secondary:hover{{background:rgba(255,255,255,.1)}}}}
</style></head><body><main><header><div class="mark" aria-hidden="true"><svg width="21" height="21" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round"><path d="M4 14.9V9.1a2 2 0 0 1 1-1.73l6-3.46a2 2 0 0 1 2 0l6 3.46a2 2 0 0 1 1 1.73v5.8a2 2 0 0 1-1 1.73l-6 3.46a2 2 0 0 1-2 0l-6-3.46a2 2 0 0 1-1-1.73Z"/><path d="m8.5 10 3.5 2 3.5-2M12 12v4"/></svg></div><div><div class="brand">COG</div><div class="tagline">Clanker Operations Gateway</div></div></header><section class="stage"><article class="card"><p class="eyebrow">{eyebrow}</p><h1>{title}</h1>{body}</article></section><footer>Secure authorization by Clanker Operations Gateway</footer></main></body></html>"##,
        eyebrow = html_escape(eyebrow),
        title = html_escape(title),
        body = body,
    )
}

fn browser_error(status: StatusCode, title: &str, message: &str) -> Response {
    (
        status,
        Html(standalone_page(
            "Authorization error",
            title,
            &format!(
                "<p class=\"lead\">{}</p><div class=\"actions\"><a class=\"button secondary\" href=\"/\">Return to cog</a></div>",
                html_escape(message)
            ),
            "status",
        )),
    )
        .into_response()
}

pub fn permission_copy(scope: &str, integration_name: Option<&str>) -> (String, String) {
    if let Some(name) = integration_name {
        return (
            format!("Use {name}"),
            "Discover and call tools from this integration.".into(),
        );
    }
    match scope {
        "mcp" => (
            "Connect to cog".into(),
            "Use cog's MCP execution surface.".into(),
        ),
        "integrations:read" => (
            "View integrations".into(),
            "See configured MCP integrations and their status.".into(),
        ),
        "integrations:write" => (
            "Manage integrations".into(),
            "Create, change, reconnect, enable, or delete integrations.".into(),
        ),
        "agents:read" => (
            "View agent access".into(),
            "See authorized clients and issued credentials.".into(),
        ),
        "agents:write" => (
            "Manage agent access".into(),
            "Revoke clients, credentials, and integration grants.".into(),
        ),
        "audit:read" => (
            "Read audit history".into(),
            "Review security and administration activity.".into(),
        ),
        "git:read" => (
            "Read Git repositories".into(),
            "Clone, fetch, and pull only from individually approved repositories.".into(),
        ),
        "git:write" => (
            "Write Git repositories".into(),
            "Push to individually approved repositories, subject to provider rules.".into(),
        ),
        "admin" => (
            "Legacy administrator access".into(),
            "Compatibility access equivalent to all administrative permissions.".into(),
        ),
        other => (
            other.into(),
            "Additional access requested by this client.".into(),
        ),
    }
}

pub fn selected_scopes(requested: &str, fields: &HashMap<String, String>) -> String {
    requested
        .split_ascii_whitespace()
        .enumerate()
        .filter(|(index, scope)| *scope == "mcp" || fields.contains_key(&format!("scope_{index}")))
        .map(|(_, scope)| scope)
        .collect::<Vec<_>>()
        .join(" ")
}

fn available_consent_scopes(a: &App, user: &str) -> Vec<String> {
    let mut scopes = vec![
        "mcp".to_owned(),
        "integrations:read".to_owned(),
        "integrations:write".to_owned(),
        "agents:read".to_owned(),
        "agents:write".to_owned(),
        "audit:read".to_owned(),
        "git:read".to_owned(),
        "git:write".to_owned(),
    ];
    if let Ok(integrations) = a.db.list_integrations(user) {
        scopes.extend(
            integrations
                .into_iter()
                .map(|integration| format!("integration:{}", integration.id)),
        );
    }
    scopes
}

enum ConsentPermissionKind {
    New,
    Approved,
    ApprovedNotRequested,
    Required { new: bool },
    Other,
}

fn consent_permission_json(
    a: &App,
    user: &str,
    scope: &str,
    index: Option<usize>,
    kind: ConsentPermissionKind,
) -> Value {
    let integration = scope.strip_prefix("integration:").and_then(|id| {
        a.db.integration(id, user)
            .ok()
            .flatten()
            .map(|integration| integration.name)
    });
    let (label, description) = permission_copy(scope, integration.as_deref());
    let (checked, disabled, badge, tone) = match kind {
        ConsentPermissionKind::New => (true, false, "New access", "new"),
        ConsentPermissionKind::Approved => (true, false, "Approved", "approved"),
        ConsentPermissionKind::ApprovedNotRequested => (true, true, "Approved", "approved"),
        ConsentPermissionKind::Required { new } => {
            (true, true, "Required", if new { "new" } else { "approved" })
        }
        ConsentPermissionKind::Other => (false, true, "Not requested", "other"),
    };
    json!({
        "scope": scope,
        "field": index.map(|index| format!("scope_{index}")),
        "label": label,
        "description": description,
        "checked": checked,
        "disabled": disabled,
        "badge": badge,
        "tone": tone,
    })
}

fn consent_api_error(status: StatusCode, error: &str, message: &str) -> Response {
    (status, Json(json!({"error":error,"message":message}))).into_response()
}

async fn authorize_page() -> Response {
    ui_shell()
}

pub async fn authorize_consent(
    State(a): State<App>,
    headers: HeaderMap,
    axum::extract::Query(q): axum::extract::Query<Authorize>,
) -> impl IntoResponse {
    if let Err(e) = a.lease.assert_live() {
        return (StatusCode::SERVICE_UNAVAILABLE, e.to_string()).into_response();
    }
    if q.response_type != "code" || q.code_challenge_method != "S256" {
        return consent_api_error(
            StatusCode::BAD_REQUEST,
            "Unsupported authorization request",
            "response_type=code and PKCE S256 are required",
        );
    }
    let expected_resource = format!("{}/mcp", a.config.base_url.as_str().trim_end_matches('/'));
    if q.resource != expected_resource {
        return consent_api_error(
            StatusCode::BAD_REQUEST,
            "Invalid OAuth resource",
            "The authorization request is not bound to this MCP server.",
        );
    }
    let Some((client_name, _)) = a.db.client_info(&q.client_id).ok().flatten() else {
        return consent_api_error(
            StatusCode::BAD_REQUEST,
            "Unknown client",
            "Clanker Operations Gateway does not recognize the application that started this request.",
        );
    };
    if !a
        .db
        .client_redirect_allowed(&q.client_id, &q.redirect_uri)
        .unwrap_or(false)
    {
        return consent_api_error(
            StatusCode::BAD_REQUEST,
            "Invalid return address",
            "The application's callback address is not registered with cog.",
        );
    }
    if browser_session(&a, &headers, None).is_none() {
        return consent_api_error(
            StatusCode::UNAUTHORIZED,
            "Sign in to continue",
            "Your cog session is missing or expired. Sign in, then restart the authorization request from your agent.",
        );
    }
    let Some(csrf) = cookie(&headers, "cog_csrf") else {
        return consent_api_error(
            StatusCode::FORBIDDEN,
            "Session verification failed",
            "The browser security cookie is missing. Sign in and start a fresh authorization request.",
        );
    };
    let user = browser_session(&a, &headers, None).expect("session checked");
    let existing_agent = a.db.agent_for_client(&q.client_id).ok().flatten();
    if let Some(agent) = &existing_agent
        && a.db
            .identity(&user, &agent.identity_id)
            .ok()
            .flatten()
            .is_none()
    {
        return consent_api_error(
            StatusCode::FORBIDDEN,
            "Conflicting agent binding",
            "This OAuth client is already bound to an identity owned by another user.",
        );
    }
    let identities = a.db.list_identities(&user).unwrap_or_default();
    let git_pending =
        a.db.git_pending_requests(&user, &q.client_id, chrono::Utc::now().timestamp())
            .unwrap_or_default();
    let consent = ConsentRequest {
        response_type: q.response_type,
        client_id: q.client_id,
        redirect_uri: q.redirect_uri,
        state: q.state,
        code_challenge: q.code_challenge,
        code_challenge_method: q.code_challenge_method,
        requested_scope: q.scope,
        resource: q.resource,
        user: user.clone(),
        allowed_identity_ids: identities
            .iter()
            .map(|identity| identity.id.clone())
            .collect(),
        fixed_identity_id: existing_agent
            .as_ref()
            .map(|agent| agent.identity_id.clone()),
        expires_at: chrono::Utc::now().timestamp() + 600,
        git_pending_ids: git_pending
            .iter()
            .map(|request| request.id.clone())
            .collect(),
    };
    let serialized = match serde_json::to_vec(&consent) {
        Ok(serialized) => serialized,
        Err(error) => {
            return (StatusCode::INTERNAL_SERVER_ERROR, error.to_string()).into_response();
        }
    };
    let sealed = match a.secrets.seal(&serialized) {
        Ok(sealed) => sealed,
        Err(error) => {
            return (StatusCode::INTERNAL_SERVER_ERROR, error.to_string()).into_response();
        }
    };
    let requested = consent
        .requested_scope
        .split_ascii_whitespace()
        .collect::<Vec<_>>();
    if requested.is_empty() {
        return consent_api_error(
            StatusCode::BAD_REQUEST,
            "No access requested",
            "The client did not request any OAuth scope.",
        );
    }
    let granted = match a.db.client_granted_scopes(&user, &consent.client_id) {
        Ok(scopes) => scopes.into_iter().collect::<HashSet<_>>(),
        Err(error) => {
            return (StatusCode::INTERNAL_SERVER_ERROR, error.to_string()).into_response();
        }
    };
    let requested_set = requested.iter().copied().collect::<HashSet<_>>();
    let available = available_consent_scopes(&a, &user);
    let mut new_permissions = Vec::new();
    let mut approved_permissions = Vec::new();
    for (index, scope) in requested.iter().enumerate() {
        let required = *scope == "mcp";
        let previously_granted = granted.contains(*scope);
        let permission = consent_permission_json(
            &a,
            &user,
            scope,
            Some(index),
            if required {
                ConsentPermissionKind::Required {
                    new: !previously_granted,
                }
            } else if previously_granted {
                ConsentPermissionKind::Approved
            } else {
                ConsentPermissionKind::New
            },
        );
        if previously_granted {
            approved_permissions.push(permission);
        } else {
            new_permissions.push(permission);
        }
    }
    for scope in &available {
        if granted.contains(scope) && !requested_set.contains(scope.as_str()) {
            approved_permissions.push(consent_permission_json(
                &a,
                &user,
                scope,
                None,
                ConsentPermissionKind::ApprovedNotRequested,
            ));
        }
    }
    let mut remaining_grants = granted
        .iter()
        .filter(|scope| {
            !requested_set.contains(scope.as_str()) && !available.iter().any(|item| item == *scope)
        })
        .collect::<Vec<_>>();
    remaining_grants.sort();
    for scope in remaining_grants {
        approved_permissions.push(consent_permission_json(
            &a,
            &user,
            scope,
            None,
            ConsentPermissionKind::ApprovedNotRequested,
        ));
    }
    let mut other_permissions = Vec::new();
    for scope in available {
        if !requested_set.contains(scope.as_str()) && !granted.contains(&scope) {
            other_permissions.push(consent_permission_json(
                &a,
                &user,
                &scope,
                None,
                ConsentPermissionKind::Other,
            ));
        }
    }
    let mut permission_groups = Vec::new();
    if !new_permissions.is_empty() {
        permission_groups
            .push(json!({"title":"Newly requested","tone":"new","permissions":new_permissions}));
    }
    if !approved_permissions.is_empty() {
        permission_groups.push(json!({"title":"Previously approved","tone":"approved","permissions":approved_permissions}));
    }
    if !other_permissions.is_empty() {
        permission_groups.push(json!({"title":"Other available permissions","tone":"other","permissions":other_permissions}));
    }
    if !git_pending.is_empty() {
        let requests=git_pending.iter().enumerate().map(|(index,request)|json!({
            "field":format!("git_request_{index}"),
            "label":request.display_name,
            "description":format!("{} access through integration {}",request.permission,request.integration_id),
            "checked":true,
            "disabled":false,
            "badge":"Repository",
            "tone":"new",
        })).collect::<Vec<_>>();
        permission_groups
            .push(json!({"title":"Exact repository access","tone":"new","permissions":requests}));
    }
    let redirect_host = url::Url::parse(&consent.redirect_uri)
        .ok()
        .and_then(|url| url.host_str().map(str::to_owned))
        .unwrap_or_else(|| consent.redirect_uri.clone());
    let fixed_identity = consent.fixed_identity_id.as_ref().map(|id| {
        let name = identities
            .iter()
            .find(|item| &item.id == id)
            .map(|item| item.name.as_str())
            .unwrap_or("Unknown identity");
        json!({"id":id,"name":name})
    });
    let identities = identities
        .into_iter()
        .map(|identity| json!({"id":identity.id,"name":identity.name}))
        .collect::<Vec<_>>();
    let mut response = Json(json!({
        "client":{"name":client_name,"id":consent.client_id.chars().take(12).collect::<String>(),"redirectHost":redirect_host},
        "consent":sealed,
        "csrfToken":csrf,
        "identities":identities,
        "fixedIdentity":fixed_identity,
        "permissionGroups":permission_groups,
    })).into_response();
    response.headers_mut().insert(
        header::CACHE_CONTROL,
        header::HeaderValue::from_static("no-store"),
    );
    response
}
pub async fn authorize_post(
    State(a): State<App>,
    headers: HeaderMap,
    Form(form): Form<ConsentForm>,
) -> impl IntoResponse {
    let mutation = a.mutations.lock().await;
    if let Err(e) = a.lease.assert_live() {
        return (StatusCode::SERVICE_UNAVAILABLE, e.to_string()).into_response();
    }
    let consent = match a
        .secrets
        .open(&form.consent)
        .and_then(|value| Ok(serde_json::from_slice::<ConsentRequest>(&value)?))
    {
        Ok(consent) => consent,
        Err(_) => return (StatusCode::BAD_REQUEST, "invalid consent request").into_response(),
    };
    if consent.expires_at < chrono::Utc::now().timestamp()
        || consent.response_type != "code"
        || consent.code_challenge_method != "S256"
        || consent.resource != format!("{}/mcp", a.config.base_url.as_str().trim_end_matches('/'))
        || !a
            .db
            .client_redirect_allowed(&consent.client_id, &consent.redirect_uri)
            .unwrap_or(false)
    {
        return (StatusCode::BAD_REQUEST, "invalid authorization request").into_response();
    }
    if !origin_allowed(&a, &headers) {
        return (StatusCode::FORBIDDEN, "invalid origin").into_response();
    }
    let Some(user) = browser_session(&a, &headers, Some(&form.csrf_token)) else {
        return (StatusCode::UNAUTHORIZED, "invalid session or CSRF token").into_response();
    };
    if user != consent.user {
        return (
            StatusCode::FORBIDDEN,
            "consent request belongs to another session",
        )
            .into_response();
    }
    if let Some(response) = rate_limit(&a, "authorization", &user, 30) {
        return response;
    }
    if form.decision == "deny" {
        if let Err(error) = a.db.consume_git_pending_requests(
            &user,
            &consent.client_id,
            &[],
            chrono::Utc::now().timestamp(),
        ) {
            return (StatusCode::INTERNAL_SERVER_ERROR, error.to_string()).into_response();
        }
        if let Err(error) = audit_details(
            &a,
            Some(&user),
            "oauth.consent",
            Some(&consent.client_id),
            "denied",
            &json!({"requested_scopes": consent.requested_scope.split_ascii_whitespace().collect::<Vec<_>>(), "granted_scopes": []}),
        ) {
            return (StatusCode::INTERNAL_SERVER_ERROR, error.to_string()).into_response();
        }
        if let Err(error) = persist(&a).await {
            return (StatusCode::SERVICE_UNAVAILABLE, error.to_string()).into_response();
        }
        let mut url = match url::Url::parse(&consent.redirect_uri) {
            Ok(url) => url,
            Err(error) => return (StatusCode::BAD_REQUEST, error.to_string()).into_response(),
        };
        url.query_pairs_mut()
            .append_pair("error", "access_denied")
            .append_pair("state", &consent.state);
        return Redirect::to(url.as_str()).into_response();
    }
    if form.decision != "allow" {
        return (StatusCode::BAD_REQUEST, "invalid consent decision").into_response();
    }
    let selected_identity = form
        .fields
        .get("identity_id")
        .map(String::as_str)
        .or(consent.fixed_identity_id.as_deref())
        .unwrap_or("");
    let identity_id = if let Some(fixed) = &consent.fixed_identity_id {
        if selected_identity != fixed {
            return (
                StatusCode::FORBIDDEN,
                "agent identity binding cannot be changed",
            )
                .into_response();
        }
        fixed.clone()
    } else if selected_identity.is_empty() {
        let name = form
            .fields
            .get("new_identity_name")
            .map(String::as_str)
            .unwrap_or("");
        match a.db.create_identity(&user, name) {
            Ok(id) => id,
            Err(error) => return (StatusCode::BAD_REQUEST, error.to_string()).into_response(),
        }
    } else {
        if !consent
            .allowed_identity_ids
            .iter()
            .any(|id| id == selected_identity)
            || a.db
                .identity(&user, selected_identity)
                .ok()
                .flatten()
                .is_none()
        {
            return (
                StatusCode::FORBIDDEN,
                "identity is unavailable or belongs to another user",
            )
                .into_response();
        }
        selected_identity.to_owned()
    };
    let agent = match a.db.bind_agent(&user, &identity_id, &consent.client_id) {
        Ok(agent) => agent,
        Err(error) => return (StatusCode::FORBIDDEN, error.to_string()).into_response(),
    };
    let requested = consent
        .requested_scope
        .split_ascii_whitespace()
        .collect::<HashSet<_>>();
    let mut granted =
        a.db.client_granted_scopes(&user, &consent.client_id)
            .unwrap_or_default()
            .into_iter()
            .filter(|scope| !requested.contains(scope.as_str()))
            .collect::<Vec<_>>();
    for scope in selected_scopes(&consent.requested_scope, &form.fields).split_ascii_whitespace() {
        if !granted.iter().any(|item| item == scope) {
            granted.push(scope.to_owned());
        }
    }
    let granted_scope = granted.join(" ");
    if let Err(error) = a.db.set_identity_grants(&user, &identity_id, &granted) {
        return (StatusCode::BAD_REQUEST, error.to_string()).into_response();
    }
    let selected_git = consent
        .git_pending_ids
        .iter()
        .enumerate()
        .filter(|(index, _)| form.fields.contains_key(&format!("git_request_{index}")))
        .map(|(_, id)| id.clone())
        .collect::<Vec<_>>();
    let approved_git = match a.db.consume_git_pending_requests(
        &user,
        &consent.client_id,
        &selected_git,
        chrono::Utc::now().timestamp(),
    ) {
        Ok(value) => value,
        Err(error) => return (StatusCode::BAD_REQUEST, error.to_string()).into_response(),
    };
    match oauth::issue_code(
        &a.db,
        &consent.client_id,
        &user,
        &consent.redirect_uri,
        &granted_scope,
        &consent.code_challenge,
    ) {
        Ok(code) => {
            if let Err(error) = audit_details(
                &a,
                Some(&user),
                "oauth.consent",
                Some(&consent.client_id),
                "allowed",
                &json!({"identity_id":identity_id,"agent_id":agent.id,"client_id":consent.client_id,"requested_scopes": consent.requested_scope.split_ascii_whitespace().collect::<Vec<_>>(), "granted_scopes": granted_scope.split_ascii_whitespace().collect::<Vec<_>>(),"git_repository_grants":approved_git}),
            ) {
                return (StatusCode::INTERNAL_SERVER_ERROR, error.to_string()).into_response();
            }
            if let Err(e) = persist(&a).await {
                return (StatusCode::SERVICE_UNAVAILABLE, e.to_string()).into_response();
            }
            let mut url = url::Url::parse(&consent.redirect_uri).unwrap();
            url.query_pairs_mut()
                .append_pair("code", &code)
                .append_pair("state", &consent.state);
            drop(mutation);
            match a.config.server_local_callbacks {
                crate::config::ServerLocalCallbacks::Off => {
                    Redirect::to(url.as_str()).into_response()
                }
                mode => match deliver_loopback_callback(&url).await {
                    CallbackDelivery::Delivered => Html(standalone_page(
                        "Authorization complete",
                        "You're all set",
                        "<p class=\"lead\">The authorization was delivered securely to your local agent.</p><div class=\"notice success\">You can close this window and return to your agent.</div><div class=\"actions\"><a class=\"button\" href=\"/\">Return to cog</a></div>",
                        "status",
                    ))
                    .into_response(),
                    CallbackDelivery::NotSent
                        if mode == crate::config::ServerLocalCallbacks::Auto =>
                    {
                        Redirect::to(url.as_str()).into_response()
                    }
                    CallbackDelivery::NotSent => (
                        StatusCode::BAD_GATEWAY,
                        Html(standalone_page(
                            "Delivery failed",
                            "Authorization was not delivered",
                            "<p class=\"lead\">Clanker Operations Gateway could not reach the required local callback. No browser redirect was attempted.</p><div class=\"notice warning\">Return to your agent and start a fresh authorization request.</div>",
                            "status",
                        )),
                    )
                        .into_response(),
                    CallbackDelivery::Indeterminate => (
                        StatusCode::BAD_GATEWAY,
                        Html(standalone_page(
                            "Delivery uncertain",
                            "Check your agent",
                            "<p class=\"lead\">The callback may have received the authorization. To prevent duplicate delivery, cog did not try another channel.</p><div class=\"notice warning\">Check your agent before starting a new authorization request.</div>",
                            "status",
                        )),
                    )
                        .into_response(),
                },
            }
        }
        Err(e) => (StatusCode::BAD_REQUEST, e.to_string()).into_response(),
    }
}

#[derive(Debug, PartialEq, Eq)]
pub enum CallbackDelivery {
    NotSent,
    Delivered,
    Indeterminate,
}

/// Delivers an already-durable authorization response without proxies,
/// redirects, credentials, cookies, or response-body buffering. `NotSent` is
/// returned only when cog can prove no callback bytes left this process.
pub async fn deliver_loopback_callback(url: &url::Url) -> CallbackDelivery {
    if url.scheme() != "http"
        || !url.username().is_empty()
        || url.password().is_some()
        || url.fragment().is_some()
    {
        return CallbackDelivery::NotSent;
    }
    let ip = match url.host() {
        Some(url::Host::Ipv4(ip)) if ip == std::net::Ipv4Addr::LOCALHOST => IpAddr::V4(ip),
        Some(url::Host::Ipv6(ip)) if ip == std::net::Ipv6Addr::LOCALHOST => IpAddr::V6(ip),
        _ => return CallbackDelivery::NotSent,
    };
    let address = SocketAddr::new(ip, url.port().unwrap_or(80));
    let Ok(Ok(mut stream)) = tokio::time::timeout(
        Duration::from_secs(2),
        tokio::net::TcpStream::connect(address),
    )
    .await
    else {
        return CallbackDelivery::NotSent;
    };
    let target = match url.query() {
        Some(query) => format!("{}?{query}", url.path()),
        None => url.path().to_owned(),
    };
    let host = match ip {
        IpAddr::V4(ip) => format!("{ip}:{}", address.port()),
        IpAddr::V6(ip) => format!("[{ip}]:{}", address.port()),
    };
    let request = format!(
        "GET {target} HTTP/1.1\r\nHost: {host}\r\nConnection: close\r\nUser-Agent: cog-local-callback\r\n\r\n"
    );
    let bytes = request.as_bytes();
    let mut sent = 0;
    while sent < bytes.len() {
        match tokio::time::timeout(Duration::from_secs(2), stream.write(&bytes[sent..])).await {
            Ok(Ok(0)) | Ok(Err(_)) | Err(_) => {
                return if sent == 0 {
                    CallbackDelivery::NotSent
                } else {
                    CallbackDelivery::Indeterminate
                };
            }
            Ok(Ok(written)) => sent += written,
        }
    }
    let mut response = Vec::with_capacity(1024);
    loop {
        let mut chunk = [0_u8; 1024];
        match tokio::time::timeout(Duration::from_secs(3), stream.read(&mut chunk)).await {
            Ok(Ok(0)) => break,
            Ok(Ok(read)) => {
                response.extend_from_slice(&chunk[..read]);
                if response.windows(4).any(|window| window == b"\r\n\r\n") {
                    break;
                }
                if response.len() >= 16 * 1024 {
                    return CallbackDelivery::Indeterminate;
                }
            }
            Ok(Err(_)) | Err(_) => return CallbackDelivery::Indeterminate,
        }
    }
    let status = response
        .split(|byte| *byte == b'\n')
        .next()
        .unwrap_or_default();
    if status.starts_with(b"HTTP/1.1 2") || status.starts_with(b"HTTP/1.0 2") {
        CallbackDelivery::Delivered
    } else {
        CallbackDelivery::Indeterminate
    }
}

#[derive(Deserialize)]
struct RevocationRequest {
    token: String,
}

async fn revoke_token(
    State(a): State<App>,
    Form(request): Form<RevocationRequest>,
) -> impl IntoResponse {
    let _mutation = a.mutations.lock().await;
    if let Some(response) = rate_limit(&a, "revocation", "global", 120) {
        return response;
    }
    if let Err(error) = a.lease.assert_live() {
        return (StatusCode::SERVICE_UNAVAILABLE, error.to_string()).into_response();
    }
    match a.db.revoke_token(&token_hash(&request.token)) {
        Ok(changed) => {
            if let Err(error) = audit(
                &a,
                None,
                "oauth.revoke",
                None,
                if changed { "success" } else { "not_found" },
            ) {
                return (StatusCode::INTERNAL_SERVER_ERROR, error.to_string()).into_response();
            }
            if let Err(error) = persist(&a).await {
                return (StatusCode::SERVICE_UNAVAILABLE, error.to_string()).into_response();
            }
            StatusCode::OK.into_response()
        }
        Err(error) => (StatusCode::INTERNAL_SERVER_ERROR, error.to_string()).into_response(),
    }
}
async fn token(State(a): State<App>, Form(r): Form<oauth::TokenRequest>) -> impl IntoResponse {
    let _mutation = a.mutations.lock().await;
    if let Some(response) = rate_limit(&a, "token", &r.client_id, 60) {
        return response;
    }
    let audit_client = r.client_id.clone();
    let expected_resource = format!("{}/mcp", a.config.base_url.as_str().trim_end_matches('/'));
    if r.resource.as_deref() != Some(expected_resource.as_str()) {
        return (
            StatusCode::BAD_REQUEST,
            Json(json!({"error":"invalid_target","error_description":"resource must identify this MCP server"})),
        )
            .into_response();
    }
    if let Err(e) = a.lease.assert_live() {
        return (
            StatusCode::SERVICE_UNAVAILABLE,
            Json(json!({"error":"temporarily_unavailable","error_description":e.to_string()})),
        )
            .into_response();
    }
    match oauth::redeem(&a.db, r) {
        Ok(v) => {
            if let Err(error) = audit(&a, Some(&audit_client), "oauth.token", None, "success") {
                return (StatusCode::INTERNAL_SERVER_ERROR, error.to_string()).into_response();
            }
            match persist(&a).await {
            Ok(()) => Json(json!(v)).into_response(),
            Err(e) => (
                StatusCode::SERVICE_UNAVAILABLE,
                Json(json!({"error":"temporarily_unavailable","error_description":e.to_string()})),
            )
                .into_response(),
            }
        }
        Err(e) => {
            a.metrics.oauth_failures.fetch_add(1, Ordering::Relaxed);
            if audit(&a, Some(&audit_client), "oauth.token", None, "denied").is_ok() {
                let _ = persist(&a).await;
            }
            (
                StatusCode::BAD_REQUEST,
                Json(json!({"error":"invalid_grant","error_description":e.to_string()})),
            )
                .into_response()
        }
    }
}
fn bearer(headers: &HeaderMap) -> Option<&str> {
    headers
        .get(http::header::AUTHORIZATION)?
        .to_str()
        .ok()?
        .strip_prefix("Bearer ")
}
#[derive(Debug)]
pub enum AuthFailure {
    Missing,
    Invalid,
    Insufficient,
    Internal,
}

#[derive(Clone)]
pub struct AuthContext {
    pub user: String,
    pub agent: String,
    pub client: String,
    pub identity: String,
    pub scopes: HashSet<String>,
    pub integrations: HashSet<String>,
}

impl AuthContext {
    fn allows(&self, required: &str) -> bool {
        self.scopes.contains(required)
            || (self.scopes.contains("admin")
                && matches!(
                    required,
                    "integrations:read"
                        | "integrations:write"
                        | "agents:read"
                        | "agents:write"
                        | "audit:read"
                ))
    }

    pub fn allows_integration(&self, integration_id: &str) -> bool {
        self.scopes.contains("admin") || self.integrations.contains(integration_id)
    }
}

fn auth_context(a: &App, h: &HeaderMap) -> Result<AuthContext, AuthFailure> {
    let token = bearer(h).ok_or(AuthFailure::Missing)?;
    let row =
        a.db.token_context(&token_hash(token), chrono::Utc::now().timestamp())
            .map_err(|_| AuthFailure::Internal)?
            .ok_or(AuthFailure::Invalid)?;
    Ok(AuthContext {
        user: row.user_id,
        agent: row.agent_id,
        client: row.client_id,
        identity: row.identity_id,
        scopes: row.scopes.into_iter().collect(),
        integrations: row.integration_ids.into_iter().collect(),
    })
}

pub fn scoped_user(a: &App, h: &HeaderMap, scope: &str) -> Result<String, AuthFailure> {
    let context = auth_context(a, h)?;
    if !context.allows(scope) {
        return Err(AuthFailure::Insufficient);
    }
    Ok(context.user)
}

pub fn auth_failure(a: &App, failure: AuthFailure, scope: &str) -> axum::response::Response {
    if matches!(failure, AuthFailure::Internal) {
        return StatusCode::INTERNAL_SERVER_ERROR.into_response();
    }
    let metadata = resource_metadata_url(a);
    let (status, error) = match failure {
        AuthFailure::Missing => (StatusCode::UNAUTHORIZED, None),
        AuthFailure::Invalid => (StatusCode::UNAUTHORIZED, Some("invalid_token")),
        AuthFailure::Insufficient => (StatusCode::FORBIDDEN, Some("insufficient_scope")),
        AuthFailure::Internal => unreachable!(),
    };
    let mut challenge = format!("Bearer resource_metadata=\"{metadata}\", scope=\"{scope}\"");
    if let Some(error) = error {
        challenge.push_str(&format!(", error=\"{error}\""));
    }
    (
        status,
        [(http::header::WWW_AUTHENTICATE, challenge)],
        "unauthorized",
    )
        .into_response()
}

fn resource_metadata_url(a: &App) -> String {
    format!(
        "{}/.well-known/oauth-protected-resource",
        a.config.base_url.as_str().trim_end_matches('/')
    )
}

fn mcp_http_response(response: RpcResponse) -> Response {
    let challenge = response
        .result
        .as_ref()
        .and_then(|result| result.pointer("/_meta/mcp~1www_authenticate/0"))
        .and_then(Value::as_str)
        .map(str::to_owned);
    let mut response = Json(response).into_response();
    if let Some(challenge) = challenge {
        *response.status_mut() = StatusCode::FORBIDDEN;
        response.headers_mut().insert(
            header::WWW_AUTHENTICATE,
            challenge
                .parse()
                .expect("internally generated OAuth challenge is a valid header"),
        );
    }
    response
}

fn mcp_origin_allowed(a: &App, auth: &AuthContext, headers: &HeaderMap) -> bool {
    let Some(origin) = headers
        .get(http::header::ORIGIN)
        .and_then(|value| value.to_str().ok())
    else {
        // Non-browser MCP clients generally do not send Origin. A supplied
        // Origin is always validated below, which blocks DNS-rebinding input.
        return true;
    };
    if origin == a.config.base_url.origin().ascii_serialization() {
        return true;
    }
    a.db.client_info(&auth.client)
        .ok()
        .flatten()
        .is_some_and(|(_, redirects)| {
            redirects.iter().any(|redirect| {
                url::Url::parse(redirect)
                    .ok()
                    .is_some_and(|url| url.origin().ascii_serialization() == origin)
            })
        })
}

fn mcp_protocol_version_valid(headers: &HeaderMap) -> bool {
    headers
        .get("MCP-Protocol-Version")
        .and_then(|value| value.to_str().ok())
        .is_none_or(mcp::protocol_version_supported)
}
pub async fn catalog(a: &App, auth: &AuthContext) -> anyhow::Result<Catalog> {
    let _agent_id = &auth.agent;
    let mut c = Catalog::new();
    c.add_labeled(
        "git".into(),
        "COG Git repository access".into(),
        Arc::new(GitControlProvider {
            app: a.clone(),
            auth: auth.clone(),
        }),
    );
    c.add_labeled(
        "cog".into(),
        "Clanker Operations Gateway administration".into(),
        Arc::new(AdminProvider {
            app: a.clone(),
            auth: auth.clone(),
        }),
    );
    let compatibility_all = auth.scopes.contains("admin");
    for i in
        a.db.list_integrations(&auth.user)?
            .into_iter()
            .filter(|i| i.enabled && (compatibility_all || i.identity_id == auth.identity))
    {
        let authorized = compatibility_all || auth.integrations.contains(&i.id);
        let oauth_enabled = i.config.get("oauth").is_some_and(|value| !value.is_null());
        if !oauth_enabled && let Some(provider) = a.providers.lock().await.get(&i.id).cloned() {
            if authorized {
                c.add_labeled(i.id, i.name, provider);
            } else {
                c.add_discoverable(i.id, i.name, provider);
            }
            continue;
        }
        let cfg = i
            .config
            .as_object()
            .ok_or_else(|| anyhow::anyhow!("invalid integration config"))?;
        let provider: Option<Arc<dyn ToolProvider>> = match i.transport.as_str() {
            "http" | "sse" => {
                let url = cfg
                    .get("url")
                    .and_then(Value::as_str)
                    .ok_or_else(|| anyhow::anyhow!("url required"))?
                    .to_owned();
                let mut headers = HashMap::new();
                if let Some(secret) = a.db.integration_secret(&i.id, &auth.user)? {
                    headers = serde_json::from_slice(&a.secrets.open(&secret)?)?
                }
                if oauth_enabled {
                    let authorization = match upstream_authorization(a, &i.id).await {
                        Ok(Some(authorization)) => authorization,
                        Ok(None) => {
                            tracing::info!(integration_id = %i.id, "upstream OAuth connection required");
                            c.add_unavailable(i.id, i.name, "disconnected", authorized);
                            continue;
                        }
                        Err(error) => {
                            tracing::info!(integration_id = %i.id, error = %safe_error(error.as_ref()), "upstream OAuth connection unusable");
                            let (status, _) = upstream_connection_state(a, &i);
                            c.add_unavailable(i.id, i.name, status, authorized);
                            continue;
                        }
                    };
                    headers.insert("Authorization".into(), authorization);
                }
                let provider = if i.transport == "sse" {
                    HttpMcp::new_sse(url, headers)
                } else {
                    HttpMcp::new(url, headers)
                };
                Some(Arc::new(provider))
            }
            "stdio" => {
                anyhow::ensure!(
                    a.config.allow_stdio,
                    "stdio integration disabled by deployment policy"
                );
                let command = cfg
                    .get("command")
                    .and_then(Value::as_str)
                    .ok_or_else(|| anyhow::anyhow!("command required"))?
                    .to_owned();
                let args = serde_json::from_value(cfg.get("args").cloned().unwrap_or(json!([])))?;
                Some(Arc::new(StdioMcp::new(command, args, HashMap::new())))
            }
            _ => None,
        };
        if let Some(provider) = provider {
            let provider: Arc<dyn ToolProvider> =
                if let Some(policy) = integration_policy(&i.config)? {
                    Arc::new(PolicyProvider {
                        inner: provider,
                        allow: policy.allow_tools.map(|tools| tools.into_iter().collect()),
                        deny: policy.deny_tools.into_iter().collect(),
                    })
                } else {
                    provider
                };
            let provider: Arc<dyn ToolProvider> = if oauth_enabled {
                Arc::new(OAuthStepUpProvider {
                    inner: provider,
                    app: a.clone(),
                    user: auth.user.clone(),
                    integration: i.id.clone(),
                })
            } else {
                provider
            };
            let provider: Arc<dyn ToolProvider> = Arc::new(MeasuredProvider {
                inner: provider,
                metrics: a.metrics.clone(),
            });
            if !oauth_enabled {
                a.providers
                    .lock()
                    .await
                    .insert(i.id.clone(), provider.clone());
            }
            if authorized {
                c.add_labeled(i.id, i.name, provider);
            } else {
                c.add_discoverable(i.id, i.name, provider);
            }
        }
    }
    Ok(c)
}
async fn mcp_endpoint(
    State(a): State<App>,
    Query(options): Query<McpOptions>,
    headers: HeaderMap,
    Json(req): Json<RpcRequest>,
) -> impl IntoResponse {
    if let Err(e) = a.lease.assert_live() {
        return (StatusCode::SERVICE_UNAVAILABLE, e.to_string()).into_response();
    }
    let auth = match auth_context(&a, &headers) {
        Ok(v) if v.allows("mcp") => v,
        Ok(_) => return auth_failure(&a, AuthFailure::Insufficient, "mcp"),
        Err(failure) => return auth_failure(&a, failure, "mcp"),
    };
    if !mcp_origin_allowed(&a, &auth, &headers) {
        return (StatusCode::FORBIDDEN, "invalid origin").into_response();
    }
    if !mcp_protocol_version_valid(&headers) {
        return (StatusCode::BAD_REQUEST, "unsupported MCP protocol version").into_response();
    }
    // JSON-RPC notifications deliberately have no response object. Streamable
    // HTTP acknowledges an accepted notification with 202 and an empty body.
    // Do this after authentication and lease validation, but before catalog
    // construction: an unavailable upstream must not break base protocol
    // notifications such as rmcp/Codex's `notifications/initialized`.
    if req.id.is_none() {
        return StatusCode::ACCEPTED.into_response();
    }
    if !options.codemode
        && req.method == "tools/call"
        && let Some(name) = req.params.get("name").and_then(Value::as_str)
        && let Some(required) = native_admin_scope(name)
        && name != "cog_integrations_list"
        && !auth.allows(required)
    {
        return mcp_http_response(mcp::insufficient_scope_result(
            req.id.clone(),
            &[required.to_owned()],
            &resource_metadata_url(&a),
        ));
    }
    // Code-mode clients name an immutable integration in describe/call. Check
    // that reference before V8 execution so incremental authorization remains
    // an actionable RFC 6750 HTTP challenge.
    if req.method == "tools/call"
        && req.params.get("name").and_then(Value::as_str) == Some("execute")
        && let Some(code) = req
            .params
            .pointer("/arguments/code")
            .and_then(Value::as_str)
    {
        let mut required_scopes = Vec::new();
        for integration in a.db.list_integrations(&auth.user).unwrap_or_default() {
            let referenced = ["codemode.call", "codemode.describe"]
                .iter()
                .any(|operation| {
                    [
                        format!("{operation}('{}", integration.id),
                        format!("{operation}(\"{}", integration.id),
                    ]
                    .iter()
                    .any(|needle| code.contains(needle))
                });
            if referenced
                && !auth.integrations.contains(&integration.id)
                && !auth.scopes.contains("admin")
            {
                required_scopes.push(format!("integration:{}", integration.id));
            }
        }
        if !required_scopes.is_empty() {
            return mcp_http_response(mcp::insufficient_scope_result(
                req.id.clone(),
                &required_scopes,
                &resource_metadata_url(&a),
            ));
        }
    }
    if req.method == "tools/call"
        && let Some(response) = rate_limit(&a, "mcp_tool", &auth.client, 600)
    {
        return response;
    }
    match catalog(&a, &auth).await {
        Ok(c) => {
            let metadata = resource_metadata_url(&a);
            let response = mcp::handle_with_options(
                req,
                a.runtime.clone(),
                Arc::new(c),
                &metadata,
                options.codemode,
            )
            .await;
            if response
                .result
                .as_ref()
                .and_then(|result| result.get("isError"))
                .and_then(Value::as_bool)
                .unwrap_or(false)
            {
                a.metrics.execution_failures.fetch_add(1, Ordering::Relaxed);
                if response
                    .result
                    .as_ref()
                    .and_then(|result| result.pointer("/content/0/text"))
                    .and_then(Value::as_str)
                    .is_some_and(|message| message.contains("limit") || message.contains("heap"))
                {
                    a.metrics.v8_limit_hits.fetch_add(1, Ordering::Relaxed);
                }
            }
            mcp_http_response(response)
        }
        Err(e) => (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()).into_response(),
    }
}

#[derive(Deserialize)]
struct McpOptions {
    #[serde(default = "default_codemode")]
    codemode: bool,
}

fn default_codemode() -> bool {
    false
}

pub fn native_admin_scope(tool: &str) -> Option<&'static str> {
    admin_required_scope(tool.strip_prefix("cog_")?)
}

fn admin_required_scope(tool: &str) -> Option<&'static str> {
    Some(match tool {
        "integrations_list" | "integration_get" | "github_app_setup_status" => "integrations:read",
        "integration_create"
        | "github_app_setup_start"
        | "integration_update"
        | "integration_disconnect"
        | "integration_reconnect"
        | "integration_authorize"
        | "integration_set_enabled"
        | "integration_delete" => "integrations:write",
        "agents_list" | "tokens_list" => "agents:read",
        "agent_revoke" | "token_revoke" | "identity_grant_revoke" => "agents:write",
        "audit_list" => "audit:read",
        _ => return None,
    })
}
pub async fn list_integrations(State(a): State<App>, h: HeaderMap) -> impl IntoResponse {
    let auth = match auth_context(&a, &h) {
        Ok(auth) if auth.allows("integrations:read") => auth,
        Ok(_) => return auth_failure(&a, AuthFailure::Insufficient, "integrations:read"),
        Err(failure) => return auth_failure(&a, failure, "integrations:read"),
    };
    match a.db.list_integrations(&auth.user) {
        Ok(integrations) => Json(json!(
            integrations
                .into_iter()
                .map(|integration| {
                    let access = auth.scopes.contains("admin")
                        || auth.integrations.contains(&integration.id);
                    safe_integration(&a, integration, access)
                })
                .collect::<Vec<_>>()
        ))
        .into_response(),
        Err(_) => StatusCode::INTERNAL_SERVER_ERROR.into_response(),
    }
}
pub async fn get_integration(
    State(a): State<App>,
    Path(id): Path<String>,
    headers: HeaderMap,
) -> impl IntoResponse {
    let user = match scoped_user(&a, &headers, "integrations:read") {
        Ok(user) => user,
        Err(failure) => return auth_failure(&a, failure, "integrations:read"),
    };
    match a.db.integration(&id, &user) {
        Ok(Some(integration)) => Json(integration).into_response(),
        Ok(None) => StatusCode::NOT_FOUND.into_response(),
        Err(error) => (StatusCode::INTERNAL_SERVER_ERROR, error.to_string()).into_response(),
    }
}

pub async fn list_agent_clients(State(a): State<App>, headers: HeaderMap) -> impl IntoResponse {
    let user = match scoped_user(&a, &headers, "agents:read") {
        Ok(user) => user,
        Err(failure) => return auth_failure(&a, failure, "agents:read"),
    };
    match a.db.agent_clients(&user) {
        Ok(clients) => Json(json!(clients)).into_response(),
        Err(error) => (StatusCode::INTERNAL_SERVER_ERROR, error.to_string()).into_response(),
    }
}

pub async fn list_agent_tokens(State(a): State<App>, headers: HeaderMap) -> impl IntoResponse {
    let user = match scoped_user(&a, &headers, "agents:read") {
        Ok(user) => user,
        Err(failure) => return auth_failure(&a, failure, "agents:read"),
    };
    match a.db.agent_tokens(&user) {
        Ok(tokens) => Json(json!(tokens)).into_response(),
        Err(error) => (StatusCode::INTERNAL_SERVER_ERROR, error.to_string()).into_response(),
    }
}

pub async fn revoke_agent_client(
    State(a): State<App>,
    Path(client): Path<String>,
    headers: HeaderMap,
) -> impl IntoResponse {
    let user = match scoped_user(&a, &headers, "agents:write") {
        Ok(user) => user,
        Err(failure) => return auth_failure(&a, failure, "agents:write"),
    };
    match admin_revoke_client(&a, &user, &client).await {
        Ok(_) => StatusCode::NO_CONTENT.into_response(),
        Err(error) if error.to_string().contains("not found") => {
            StatusCode::NOT_FOUND.into_response()
        }
        Err(error) => (StatusCode::BAD_REQUEST, error.to_string()).into_response(),
    }
}

pub async fn revoke_agent_grant(
    State(a): State<App>,
    Path((client, integration)): Path<(String, String)>,
    headers: HeaderMap,
) -> impl IntoResponse {
    let user = match scoped_user(&a, &headers, "agents:write") {
        Ok(user) => user,
        Err(failure) => return auth_failure(&a, failure, "agents:write"),
    };
    match admin_revoke_grant(&a, &user, &client, &integration).await {
        Ok(_) => StatusCode::NO_CONTENT.into_response(),
        Err(error) if error.to_string().contains("not found") => {
            StatusCode::NOT_FOUND.into_response()
        }
        Err(error) => (StatusCode::BAD_REQUEST, error.to_string()).into_response(),
    }
}

pub async fn revoke_agent_token(
    State(a): State<App>,
    Path(token): Path<String>,
    headers: HeaderMap,
) -> impl IntoResponse {
    let user = match scoped_user(&a, &headers, "agents:write") {
        Ok(user) => user,
        Err(failure) => return auth_failure(&a, failure, "agents:write"),
    };
    match admin_revoke_token(&a, &user, &token).await {
        Ok(_) => StatusCode::NO_CONTENT.into_response(),
        Err(error) if error.to_string().contains("not found") => {
            StatusCode::NOT_FOUND.into_response()
        }
        Err(error) => (StatusCode::BAD_REQUEST, error.to_string()).into_response(),
    }
}

#[derive(Deserialize)]
pub struct AuditQuery {
    #[serde(default = "default_audit_limit")]
    pub limit: u32,
}

fn default_audit_limit() -> u32 {
    100
}

pub async fn list_audit_events(
    State(a): State<App>,
    headers: HeaderMap,
    axum::extract::Query(query): axum::extract::Query<AuditQuery>,
) -> impl IntoResponse {
    let user = match scoped_user(&a, &headers, "audit:read") {
        Ok(user) => user,
        Err(failure) => return auth_failure(&a, failure, "audit:read"),
    };
    match a.db.audit_events_for_user(&user, query.limit) {
        Ok(events) => Json(json!(events)).into_response(),
        Err(error) => (StatusCode::INTERNAL_SERVER_ERROR, error.to_string()).into_response(),
    }
}
#[derive(Deserialize)]
struct NewIntegration {
    name: String,
    transport: String,
    config: Value,
    headers: Option<HashMap<String, String>>,
}

#[derive(Clone, Deserialize)]
struct HttpTransportConfig {
    url: url::Url,
    #[serde(default)]
    oauth: Option<UpstreamOAuthConfig>,
}

#[derive(Clone, Default, Deserialize)]
struct UpstreamOAuthConfig {
    resource_metadata_url: Option<url::Url>,
    resource: Option<String>,
    issuer: Option<url::Url>,
    authorization_endpoint: Option<url::Url>,
    token_endpoint: Option<url::Url>,
    registration_endpoint: Option<url::Url>,
    client_id: Option<String>,
    client_secret: Option<String>,
    scope: Option<String>,
}

#[derive(Deserialize)]
struct StdioTransportConfig {
    command: String,
    #[serde(default)]
    args: Vec<String>,
}

#[derive(Clone, Default, Deserialize)]
struct IntegrationPolicy {
    allow_tools: Option<Vec<String>>,
    #[serde(default)]
    deny_tools: Vec<String>,
}

fn integration_policy(config: &Value) -> anyhow::Result<Option<IntegrationPolicy>> {
    config
        .get("policy")
        .filter(|value| !value.is_null())
        .cloned()
        .map(serde_json::from_value)
        .transpose()
        .map_err(Into::into)
}

pub fn validate_policy(config: &Value) -> anyhow::Result<()> {
    if let Some(policy) = integration_policy(config)? {
        let names = policy
            .allow_tools
            .iter()
            .flatten()
            .chain(policy.deny_tools.iter());
        for name in names {
            anyhow::ensure!(
                !name.is_empty()
                    && name.len() <= 128
                    && name
                        .bytes()
                        .all(|byte| byte.is_ascii_alphanumeric()
                            || matches!(byte, b'_' | b'-' | b'.')),
                "policy contains an invalid tool name"
            );
        }
    }
    Ok(())
}

pub fn validate_transport(
    transport: &str,
    config: &Value,
    headers: Option<&HashMap<String, String>>,
    allow_stdio: bool,
) -> anyhow::Result<()> {
    validate_policy(config)?;
    match transport {
        "http" | "sse" => {
            let parsed: HttpTransportConfig = serde_json::from_value(config.clone())?;
            anyhow::ensure!(
                matches!(parsed.url.scheme(), "http" | "https"),
                "HTTP transport URL must use http or https"
            );
            anyhow::ensure!(
                parsed.url.username().is_empty() && parsed.url.password().is_none(),
                "credentials must be submitted through encrypted secret fields, not URLs"
            );
            if let Some(oauth) = parsed.oauth {
                anyhow::ensure!(
                    oauth
                        .scope
                        .as_deref()
                        .is_none_or(|scope| !scope.trim().is_empty()),
                    "OAuth scope cannot be empty"
                );
                anyhow::ensure!(
                    oauth.client_secret.is_none(),
                    "OAuth client secrets cannot be stored in integration configuration; use dynamic registration"
                );
                if let Some(resource) = oauth.resource.as_ref() {
                    validate_oauth_uri(&url::Url::parse(resource)?, "OAuth resource")?;
                }
                for endpoint in [
                    oauth.resource_metadata_url,
                    oauth.issuer,
                    oauth.authorization_endpoint,
                    oauth.token_endpoint,
                    oauth.registration_endpoint,
                ]
                .into_iter()
                .flatten()
                {
                    anyhow::ensure!(
                        endpoint.scheme() == "https"
                            || (endpoint.scheme() == "http"
                                && matches!(
                                    endpoint.host_str(),
                                    Some("localhost" | "127.0.0.1" | "::1")
                                )),
                        "OAuth endpoints must use HTTPS except loopback"
                    );
                    anyhow::ensure!(
                        endpoint.username().is_empty() && endpoint.password().is_none(),
                        "OAuth endpoint URLs cannot contain credentials"
                    );
                }
            }
        }
        "stdio" => {
            anyhow::ensure!(
                allow_stdio,
                "stdio integrations are disabled by deployment policy"
            );
            let parsed: StdioTransportConfig = serde_json::from_value(config.clone())?;
            anyhow::ensure!(
                !parsed.command.trim().is_empty(),
                "stdio command is required"
            );
            anyhow::ensure!(
                parsed.args.iter().all(|argument| !argument.contains('\0')),
                "stdio arguments cannot contain NUL"
            );
        }
        "git" => {
            anyhow::ensure!(
                config.get("kind").and_then(Value::as_str) == Some("git"),
                "Git integration kind must be git"
            );
            anyhow::ensure!(
                config.get("provider").and_then(Value::as_str) == Some("github"),
                "only the GitHub provider is currently supported"
            );
            let provider = config
                .get("providerConfig")
                .and_then(Value::as_object)
                .ok_or_else(|| anyhow::anyhow!("providerConfig is required"))?;
            anyhow::ensure!(
                provider
                    .get("appId")
                    .and_then(Value::as_str)
                    .is_some_and(|v| !v.is_empty())
                    && provider
                        .get("installationId")
                        .and_then(Value::as_str)
                        .is_some_and(|v| !v.is_empty()),
                "GitHub App and installation IDs are required"
            );
            let key = headers
                .and_then(|h| h.get("privateKey"))
                .ok_or_else(|| anyhow::anyhow!("GitHub App privateKey secret is required"))?;
            GitHubProvider::new(
                provider["appId"].as_str().unwrap().to_owned(),
                provider["installationId"].as_str().unwrap().to_owned(),
                config
                    .get("host")
                    .and_then(Value::as_str)
                    .unwrap_or("github.com")
                    .to_owned(),
                key.as_bytes(),
            )?;
        }
        _ => anyhow::bail!("unsupported transport"),
    }
    if let Some(headers) = headers {
        for (name, value) in headers {
            http::HeaderName::try_from(name)?;
            http::HeaderValue::try_from(value)?;
        }
    }
    Ok(())
}

pub fn validate_oauth_uri(uri: &url::Url, label: &str) -> anyhow::Result<()> {
    anyhow::ensure!(uri.has_host(), "{label} must be an absolute URI");
    anyhow::ensure!(
        uri.username().is_empty() && uri.password().is_none(),
        "{label} cannot contain userinfo"
    );
    anyhow::ensure!(
        uri.fragment().is_none(),
        "{label} cannot contain a fragment"
    );
    anyhow::ensure!(
        uri.scheme() == "https"
            || (uri.scheme() == "http"
                && matches!(uri.host_str(), Some("localhost" | "127.0.0.1" | "::1"))),
        "{label} must use HTTPS except loopback"
    );
    Ok(())
}
async fn add_integration(
    State(a): State<App>,
    h: HeaderMap,
    Json(n): Json<NewIntegration>,
) -> impl IntoResponse {
    let u = match scoped_user(&a, &h, "integrations:write") {
        Ok(v) => v,
        Err(failure) => return auth_failure(&a, failure, "integrations:write"),
    };
    match admin_create(
        &a,
        &u,
        json!({"name":n.name,"transport":n.transport,"config":n.config,"headers":n.headers}),
    )
    .await
    {
        Ok(value) => (StatusCode::CREATED, Json(value)).into_response(),
        Err(error) => (StatusCode::BAD_REQUEST, error.to_string()).into_response(),
    }
}

pub fn github_app_install_url(slug: &str) -> anyhow::Result<String> {
    anyhow::ensure!(
        !slug.is_empty()
            && slug
                .bytes()
                .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || byte == b'-'),
        "GitHub returned an invalid App slug"
    );
    Ok(format!("https://github.com/apps/{slug}/installations/new"))
}

pub async fn admin_github_app_setup_start(
    a: &App,
    user: &str,
    args: Value,
) -> anyhow::Result<Value> {
    let name = args
        .get("name")
        .and_then(Value::as_str)
        .map(str::trim)
        .filter(|name| !name.is_empty())
        .ok_or_else(|| anyhow::anyhow!("name is required"))?;
    anyhow::ensure!(name.len() <= 128, "name is too long");
    let state = crate::crypto::random_token(32);
    let expires_at = chrono::Utc::now().timestamp() + 20 * 60;
    let _mutation = a.mutations.lock().await;
    a.lease.assert_live()?;
    let id =
        a.db.create_github_app_setup(user, name, &token_hash(&state), expires_at)?;
    audit(
        a,
        Some(user),
        "github_app.setup.start",
        Some(&id),
        "pending",
    )?;
    persist(a).await?;
    let browser_url = format!(
        "{}/github/app/setup/{state}",
        a.config.base_url.as_str().trim_end_matches('/')
    );
    Ok(json!({
        "id": id,
        "status": "manifest_pending",
        "browserUrl": browser_url,
        "callbackOrigin": a.config.base_url.origin().ascii_serialization(),
        "browserRequirement": "The browser completing GitHub setup must be able to reach callbackOrigin; use the public COG URL, a private-network route, or an SSH tunnel.",
        "expiresAt": expires_at,
        "action": "openBrowserUrlThenWaitForGitHubSetup"
    }))
}

pub async fn admin_github_app_setup_status(a: &App, user: &str, id: &str) -> anyhow::Result<Value> {
    let integration =
        a.db.integration(id, user)?
            .ok_or_else(|| anyhow::anyhow!("integration not found"))?;
    anyhow::ensure!(
        integration.transport == "git"
            && integration.config.get("provider").and_then(Value::as_str) == Some("github"),
        "integration is not GitHub"
    );
    let provider = integration
        .config
        .get("providerConfig")
        .and_then(Value::as_object);
    let app_created = provider
        .and_then(|provider| provider.get("appId"))
        .and_then(Value::as_str)
        .is_some_and(|value| !value.is_empty());
    let installed = provider
        .and_then(|provider| provider.get("installationId"))
        .and_then(Value::as_str)
        .is_some_and(|value| !value.is_empty());
    let app_slug = provider
        .and_then(|provider| provider.get("appSlug"))
        .and_then(Value::as_str);
    let pending =
        a.db.github_app_setup_for_integration(user, id, chrono::Utc::now().timestamp())?;
    let status = if installed {
        "installed"
    } else if app_created
        || pending
            .as_ref()
            .is_some_and(|setup| setup.manifest_completed_at.is_some())
    {
        "installation_pending"
    } else if pending.is_some() {
        "manifest_pending"
    } else {
        "setup_expired"
    };
    let mut result = json!({
        "id": id,
        "status": status,
        "appCreated": app_created,
        "installed": installed,
        "credentialsConfigured": app_created && a.db.integration_secret(id, user)?.is_some()
    });
    if let Some(slug) = app_slug
        && let Some(object) = result.as_object_mut()
    {
        object.insert(
            "repositorySelectionUrl".into(),
            json!(github_app_install_url(slug)?),
        );
    }
    Ok(result)
}

async fn github_app_setup_launch(State(a): State<App>, Path(state): Path<String>) -> Response {
    if state.len() > 256 {
        return (StatusCode::BAD_REQUEST, "GitHub App setup link is invalid").into_response();
    }
    let now = chrono::Utc::now().timestamp();
    let setup = match a.db.github_app_setup_by_state(&token_hash(&state), now) {
        Ok(Some(setup)) if setup.manifest_completed_at.is_none() => setup,
        _ => {
            return (
                StatusCode::BAD_REQUEST,
                "GitHub App setup link is invalid or expired",
            )
                .into_response();
        }
    };
    let callback = format!(
        "{}/github/app/manifest/callback",
        a.config.base_url.as_str().trim_end_matches('/')
    );
    let encoded_state = url::form_urlencoded::byte_serialize(state.as_bytes()).collect::<String>();
    let installation_callback = format!(
        "{}/github/app/installation/callback?state={}",
        a.config.base_url.as_str().trim_end_matches('/'),
        encoded_state
    );
    let suffix = setup.integration_id.chars().take(8).collect::<String>();
    let manifest = json!({
        "name": format!("COG {suffix}"),
        "url": a.config.base_url.as_str(),
        "redirect_url": callback,
        "setup_url": installation_callback,
        "public": false,
        "default_permissions": {"contents": "write", "workflows": "write"},
        "default_events": []
    });
    let body = format!(
        "<!doctype html><html><head><meta charset=\"utf-8\"><title>Continue to GitHub</title></head><body><p>Continuing to GitHub App creation…</p><form id=\"github-manifest\" method=\"post\" action=\"https://github.com/settings/apps/new?state={}\"><input type=\"hidden\" name=\"manifest\" value=\"{}\"></form><script>document.getElementById('github-manifest').submit()</script><noscript><button form=\"github-manifest\" type=\"submit\">Continue to GitHub</button></noscript></body></html>",
        html_escape(&encoded_state),
        html_escape(&manifest.to_string())
    );
    Html(body).into_response()
}

#[derive(Deserialize)]
struct GitHubManifestCallbackQuery {
    code: String,
    state: String,
}

#[derive(Deserialize)]
struct GitHubManifestConversion {
    id: u64,
    slug: String,
    pem: String,
}

async fn github_app_manifest_callback(
    State(a): State<App>,
    Query(query): Query<GitHubManifestCallbackQuery>,
) -> Response {
    let now = chrono::Utc::now().timestamp();
    if query.code.len() > 512 || query.state.len() > 256 {
        return (StatusCode::BAD_REQUEST, "GitHub App callback is invalid").into_response();
    }
    let state_hash = token_hash(&query.state);
    let setup = match a.db.github_app_setup_by_state(&state_hash, now) {
        Ok(Some(setup)) if setup.manifest_completed_at.is_none() => setup,
        _ => {
            return (
                StatusCode::BAD_REQUEST,
                "GitHub App setup state is invalid or expired",
            )
                .into_response();
        }
    };
    if let Err(error) = a.lease.assert_live() {
        return (StatusCode::SERVICE_UNAVAILABLE, error.to_string()).into_response();
    }
    let client = match reqwest::Client::builder()
        .redirect(reqwest::redirect::Policy::none())
        .timeout(Duration::from_secs(30))
        .user_agent("cog-github-app-setup")
        .build()
    {
        Ok(client) => client,
        Err(_) => return StatusCode::INTERNAL_SERVER_ERROR.into_response(),
    };
    let encoded_code =
        url::form_urlencoded::byte_serialize(query.code.as_bytes()).collect::<String>();
    let conversion_url = match a
        .github_api_base
        .join(&format!("app-manifests/{encoded_code}/conversions"))
    {
        Ok(url) => url,
        Err(_) => return StatusCode::INTERNAL_SERVER_ERROR.into_response(),
    };
    let response = match client
        .post(conversion_url)
        .header(header::ACCEPT, "application/vnd.github+json")
        .header("X-GitHub-Api-Version", "2022-11-28")
        .send()
        .await
    {
        Ok(response) => response,
        Err(_) => {
            return (
                StatusCode::BAD_GATEWAY,
                "GitHub App creation could not be completed",
            )
                .into_response();
        }
    };
    if !response.status().is_success() {
        return (
            StatusCode::BAD_GATEWAY,
            "GitHub rejected the App manifest conversion",
        )
            .into_response();
    }
    let body = match response.bytes().await {
        Ok(body) if body.len() <= 1024 * 1024 => body,
        _ => {
            return (
                StatusCode::BAD_GATEWAY,
                "GitHub returned an invalid App manifest response",
            )
                .into_response();
        }
    };
    let conversion: GitHubManifestConversion = match serde_json::from_slice(&body) {
        Ok(conversion) => conversion,
        Err(_) => {
            return (
                StatusCode::BAD_GATEWAY,
                "GitHub returned an invalid App manifest response",
            )
                .into_response();
        }
    };
    if jsonwebtoken::EncodingKey::from_rsa_pem(conversion.pem.as_bytes()).is_err()
        || github_app_install_url(&conversion.slug).is_err()
    {
        return (
            StatusCode::BAD_GATEWAY,
            "GitHub returned invalid App credentials",
        )
            .into_response();
    }
    let secret_json = match serde_json::to_vec(&json!({"privateKey": conversion.pem})) {
        Ok(secret) => secret,
        Err(_) => return StatusCode::INTERNAL_SERVER_ERROR.into_response(),
    };
    let secret = match a.secrets.seal(&secret_json) {
        Ok(secret) => secret,
        Err(_) => return StatusCode::INTERNAL_SERVER_ERROR.into_response(),
    };
    let config = json!({
        "kind": "git",
        "provider": "github",
        "host": "github.com",
        "providerConfig": {
            "appId": conversion.id.to_string(),
            "appSlug": conversion.slug
        },
        "setupStatus": "installation_pending"
    });
    let _mutation = a.mutations.lock().await;
    if let Err(error) = a.lease.assert_live() {
        return (StatusCode::SERVICE_UNAVAILABLE, error.to_string()).into_response();
    }
    match a.db.complete_github_app_manifest(
        &state_hash,
        &config,
        &secret,
        config
            .pointer("/providerConfig/appSlug")
            .and_then(Value::as_str)
            .unwrap_or_default(),
        now,
    ) {
        Ok(true) => {}
        Ok(false) => {
            return (
                StatusCode::CONFLICT,
                "GitHub App setup was already completed",
            )
                .into_response();
        }
        Err(_) => return StatusCode::INTERNAL_SERVER_ERROR.into_response(),
    }
    if audit(
        &a,
        Some(&setup.user_id),
        "github_app.manifest.complete",
        Some(&setup.integration_id),
        "success",
    )
    .is_err()
        || persist(&a).await.is_err()
    {
        return StatusCode::SERVICE_UNAVAILABLE.into_response();
    }
    let slug = config
        .pointer("/providerConfig/appSlug")
        .and_then(Value::as_str)
        .unwrap_or_default();
    match github_app_install_url(slug) {
        Ok(url) => Redirect::to(&url).into_response(),
        Err(_) => StatusCode::INTERNAL_SERVER_ERROR.into_response(),
    }
}

#[derive(Deserialize)]
struct GitHubInstallationCallbackQuery {
    installation_id: String,
    state: String,
    #[serde(default)]
    setup_action: Option<String>,
}

async fn github_app_installation_callback(
    State(a): State<App>,
    Query(query): Query<GitHubInstallationCallbackQuery>,
) -> Response {
    if query.installation_id.is_empty()
        || query.installation_id.len() > 32
        || query.state.len() > 256
        || !query
            .installation_id
            .bytes()
            .all(|byte| byte.is_ascii_digit())
        || query
            .setup_action
            .as_deref()
            .is_some_and(|action| action != "install" && action != "update")
    {
        return (
            StatusCode::BAD_REQUEST,
            "GitHub installation callback is invalid",
        )
            .into_response();
    }
    let now = chrono::Utc::now().timestamp();
    let state_hash = token_hash(&query.state);
    let setup = match a.db.github_app_setup_by_state(&state_hash, now) {
        Ok(Some(setup)) if setup.manifest_completed_at.is_some() => setup,
        _ => {
            return (
                StatusCode::BAD_REQUEST,
                "GitHub installation state is invalid or expired",
            )
                .into_response();
        }
    };
    let integration = match a.db.integration(&setup.integration_id, &setup.user_id) {
        Ok(Some(integration)) => integration,
        _ => return StatusCode::BAD_REQUEST.into_response(),
    };
    let mut config = integration.config;
    let Some(provider) = config
        .get_mut("providerConfig")
        .and_then(Value::as_object_mut)
    else {
        return StatusCode::INTERNAL_SERVER_ERROR.into_response();
    };
    provider.insert("installationId".into(), json!(query.installation_id));
    if let Some(object) = config.as_object_mut() {
        object.insert("setupStatus".into(), json!("installed"));
    }
    let _mutation = a.mutations.lock().await;
    if let Err(error) = a.lease.assert_live() {
        return (StatusCode::SERVICE_UNAVAILABLE, error.to_string()).into_response();
    }
    let id = match a
        .db
        .complete_github_app_installation(&state_hash, &config, now)
    {
        Ok(Some(id)) => id,
        Ok(None) => {
            return (
                StatusCode::CONFLICT,
                "GitHub installation was already completed",
            )
                .into_response();
        }
        Err(_) => return StatusCode::INTERNAL_SERVER_ERROR.into_response(),
    };
    if audit(
        &a,
        Some(&setup.user_id),
        "github_app.installation.complete",
        Some(&id),
        "success",
    )
    .is_err()
        || persist(&a).await.is_err()
    {
        return StatusCode::SERVICE_UNAVAILABLE.into_response();
    }
    Redirect::to(&format!(
        "/github/app/installation/complete?integration_id={}",
        id
    ))
    .into_response()
}

#[derive(Deserialize)]
struct UpdateIntegration {
    name: Option<String>,
    config: Option<Value>,
    enabled: Option<bool>,
    headers: Option<HashMap<String, String>>,
}

async fn admin_create(a: &App, user: &str, args: Value) -> anyhow::Result<Value> {
    let _mutation = a.mutations.lock().await;
    a.lease.assert_live()?;
    let request: NewIntegration = serde_json::from_value(args)?;
    validate_transport(
        &request.transport,
        &request.config,
        request.headers.as_ref(),
        a.config.allow_stdio,
    )?;
    let secret = request
        .headers
        .map(|headers| a.secrets.seal(&serde_json::to_vec(&headers)?))
        .transpose()?;
    let id = a.db.create_integration(
        user,
        &request.name,
        &request.transport,
        &request.config,
        secret.as_deref(),
    )?;
    audit(a, Some(user), "integration.create", Some(&id), "success")?;
    persist(a).await?;
    Ok(json!({"id":id}))
}

async fn admin_update(a: &App, user: &str, id: String, args: Value) -> anyhow::Result<Value> {
    let _mutation = a.mutations.lock().await;
    a.lease.assert_live()?;
    let update: UpdateIntegration = serde_json::from_value(args)?;
    let current =
        a.db.integration(&id, user)?
            .ok_or_else(|| anyhow::anyhow!("integration not found"))?;
    validate_transport(
        &current.transport,
        update.config.as_ref().unwrap_or(&current.config),
        update.headers.as_ref(),
        a.config.allow_stdio,
    )?;
    let secret = update
        .headers
        .as_ref()
        .map(|headers| a.secrets.seal(&serde_json::to_vec(headers)?))
        .transpose()?;
    a.db.update_integration(
        &id,
        user,
        update.name.as_deref(),
        update.config.as_ref(),
        update.enabled,
        secret.as_deref(),
    )?;
    if update.config.is_some() {
        a.db.clear_upstream_oauth(&id)?;
    }
    disconnect_provider(a, &id).await;
    a.git_providers.lock().await.remove(&id);
    audit(a, Some(user), "integration.update", Some(&id), "success")?;
    persist(a).await?;
    Ok(json!({"id":id,"updated":true}))
}

async fn admin_reconnect(a: &App, user: &str, id: &str) -> anyhow::Result<Value> {
    admin_disconnect(a, user, id).await?;
    let integration =
        a.db.integration(id, user)?
            .ok_or_else(|| anyhow::anyhow!("integration not found"))?;
    if !integration
        .config
        .get("oauth")
        .is_some_and(|value| !value.is_null())
    {
        return Ok(json!({
            "id": id,
            "deprecatedOperation": "integration_reconnect",
            "reconnected": false,
            "upstreamConnected": true,
            "upstreamStatus": "configured",
            "message": "Static credentials were removed. Configure new credentials with integration_update; use integration_disconnect for future credential removal."
        }));
    }
    let mut result = admin_authorize(a, user, id).await?;
    if let Some(object) = result.as_object_mut() {
        object.insert("deprecatedOperation".into(), json!("integration_reconnect"));
        object.insert("reconnected".into(), json!(false));
        object.insert("message".into(), json!("Credentials were removed; reauthorization must complete before the integration is reconnected."));
    }
    Ok(result)
}

async fn admin_disconnect(a: &App, user: &str, id: &str) -> anyhow::Result<Value> {
    let _mutation = a.mutations.lock().await;
    a.lease.assert_live()?;
    anyhow::ensure!(
        a.db.clear_integration_credentials(id, user)?,
        "integration not found"
    );
    disconnect_provider(a, id).await;
    a.git_providers.lock().await.remove(id);
    audit(a, Some(user), "integration.disconnect", Some(id), "success")?;
    persist(a).await?;
    let integration =
        a.db.integration(id, user)?
            .expect("integration was preserved");
    Ok(safe_integration(a, integration, false))
}

async fn admin_delete(a: &App, user: &str, id: &str) -> anyhow::Result<Value> {
    let _mutation = a.mutations.lock().await;
    a.lease.assert_live()?;
    anyhow::ensure!(a.db.delete_integration(id, user)?, "integration not found");
    disconnect_provider(a, id).await;
    a.git_providers.lock().await.remove(id);
    audit(a, Some(user), "integration.delete", Some(id), "success")?;
    persist(a).await?;
    Ok(json!({"id":id,"deleted":true}))
}

async fn admin_revoke_client(a: &App, user: &str, id: &str) -> anyhow::Result<Value> {
    let _mutation = a.mutations.lock().await;
    a.lease.assert_live()?;
    anyhow::ensure!(a.db.revoke_agent_client(user, id)?, "client not found");
    audit(a, Some(user), "agent_client.revoke", Some(id), "success")?;
    persist(a).await?;
    Ok(json!({"id":id,"revoked":true}))
}

async fn admin_revoke_token(a: &App, user: &str, id: &str) -> anyhow::Result<Value> {
    let _mutation = a.mutations.lock().await;
    a.lease.assert_live()?;
    anyhow::ensure!(a.db.revoke_agent_token(user, id)?, "token not found");
    audit(a, Some(user), "agent_token.revoke", Some(id), "success")?;
    persist(a).await?;
    Ok(json!({"id":id,"revoked":true}))
}

async fn admin_revoke_grant(
    a: &App,
    user: &str,
    client: &str,
    integration: &str,
) -> anyhow::Result<Value> {
    let _mutation = a.mutations.lock().await;
    a.lease.assert_live()?;
    anyhow::ensure!(
        a.db.revoke_client_integration_grant(user, client, integration)?,
        "grant not found"
    );
    audit(a, Some(user), "agent_grant.revoke", Some(client), "success")?;
    persist(a).await?;
    Ok(json!({"client_id":client,"integration_id":integration,"revoked":true}))
}

pub async fn admin_authorize(a: &App, user: &str, id: &str) -> anyhow::Result<Value> {
    let _mutation = a.mutations.lock().await;
    a.lease.assert_live()?;
    let integration =
        a.db.integration(id, user)?
            .ok_or_else(|| anyhow::anyhow!("integration not found"))?;
    anyhow::ensure!(
        integration
            .config
            .get("oauth")
            .is_some_and(|value| !value.is_null()),
        "integration does not use upstream OAuth"
    );
    let (status, connected) = upstream_connection_state(a, &integration);
    if connected {
        return Ok(json!({
            "id": id,
            "alreadyConnected": true,
            "upstreamConnected": true,
            "upstreamStatus": status,
            "reconnectRequired": true
        }));
    }
    let client = resolve_upstream_client(a, &integration).await?;
    let state = crate::crypto::random_token(32);
    let verifier = crate::crypto::random_token(48);
    use base64::Engine;
    use sha2::Digest;
    let challenge = base64::engine::general_purpose::URL_SAFE_NO_PAD
        .encode(sha2::Sha256::digest(verifier.as_bytes()));
    let redirect = format!(
        "{}/oauth/upstream/callback",
        a.config.base_url.as_str().trim_end_matches('/')
    );
    let sealed = a.secrets.seal(verifier.as_bytes())?;
    a.db.store_oauth_state(
        &token_hash(&state),
        user,
        id,
        &sealed,
        &redirect,
        chrono::Utc::now().timestamp() + 600,
        client.resource.as_deref(),
    )?;
    audit(
        a,
        Some(user),
        "integration.oauth_start",
        Some(id),
        "success",
    )?;
    persist(a).await?;
    let mut url = url::Url::parse(&client.authorization_endpoint)?;
    let mut pairs = url.query_pairs_mut();
    pairs
        .append_pair("response_type", "code")
        .append_pair("client_id", &client.client_id)
        .append_pair("redirect_uri", &redirect)
        .append_pair("state", &state)
        .append_pair("code_challenge", &challenge)
        .append_pair("code_challenge_method", "S256");
    if !client.scope.is_empty() {
        pairs.append_pair("scope", &client.scope);
    }
    if let Some(resource) = client.resource.as_deref() {
        pairs.append_pair("resource", resource);
    }
    drop(pairs);
    Ok(
        json!({"id":id,"alreadyConnected":false,"upstreamConnected":false,"upstreamStatus":status,"authorization_url":url,"one_time":true,"prefetched":false}),
    )
}

async fn update_integration(
    State(a): State<App>,
    Path(id): Path<String>,
    headers: HeaderMap,
    Json(update): Json<UpdateIntegration>,
) -> impl IntoResponse {
    let user = match scoped_user(&a, &headers, "integrations:write") {
        Ok(user) => user,
        Err(failure) => return auth_failure(&a, failure, "integrations:write"),
    };
    match admin_update(&a, &user, id, json!({"name":update.name,"config":update.config,"enabled":update.enabled,"headers":update.headers})).await {
        Ok(_) => StatusCode::NO_CONTENT.into_response(), Err(error) if error.to_string().contains("not found") => StatusCode::NOT_FOUND.into_response(), Err(error) => (StatusCode::BAD_REQUEST, error.to_string()).into_response()
    }
}

pub async fn reconnect_integration(
    State(a): State<App>,
    Path(id): Path<String>,
    headers: HeaderMap,
) -> impl IntoResponse {
    let user = match scoped_user(&a, &headers, "integrations:write") {
        Ok(user) => user,
        Err(failure) => return auth_failure(&a, failure, "integrations:write"),
    };
    match admin_reconnect(&a, &user, &id).await {
        Ok(_) => StatusCode::NO_CONTENT.into_response(),
        Err(error) if error.to_string().contains("not found") => {
            StatusCode::NOT_FOUND.into_response()
        }
        Err(error) => (StatusCode::BAD_REQUEST, error.to_string()).into_response(),
    }
}

pub async fn disconnect_integration(
    State(a): State<App>,
    Path(id): Path<String>,
    headers: HeaderMap,
) -> impl IntoResponse {
    let user = match scoped_user(&a, &headers, "integrations:write") {
        Ok(user) => user,
        Err(failure) => return auth_failure(&a, failure, "integrations:write"),
    };
    match admin_disconnect(&a, &user, &id).await {
        Ok(value) => Json(value).into_response(),
        Err(error) if error.to_string().contains("not found") => {
            StatusCode::NOT_FOUND.into_response()
        }
        Err(error) => (StatusCode::BAD_REQUEST, error.to_string()).into_response(),
    }
}

pub async fn delete_integration(
    State(a): State<App>,
    Path(id): Path<String>,
    headers: HeaderMap,
) -> impl IntoResponse {
    let user = match scoped_user(&a, &headers, "integrations:write") {
        Ok(user) => user,
        Err(failure) => return auth_failure(&a, failure, "integrations:write"),
    };
    match admin_delete(&a, &user, &id).await {
        Ok(_) => StatusCode::NO_CONTENT.into_response(),
        Err(error) if error.to_string().contains("not found") => {
            StatusCode::NOT_FOUND.into_response()
        }
        Err(error) => (StatusCode::BAD_REQUEST, error.to_string()).into_response(),
    }
}

async fn disconnect_provider(a: &App, id: &str) {
    let provider = a.providers.lock().await.remove(id);
    if let Some(provider) = provider
        && let Err(error) = provider.close().await
    {
        tracing::warn!(error = %safe_error(error.as_ref()), integration_id = id, "upstream cleanup failed");
    }
}

async fn oauth_json(request: reqwest::RequestBuilder) -> anyhow::Result<Value> {
    const MAX_OAUTH_RESPONSE: usize = 1024 * 1024;
    let response = request.send().await?.error_for_status()?;
    anyhow::ensure!(
        response.content_length().unwrap_or(0) <= MAX_OAUTH_RESPONSE as u64,
        "upstream OAuth response too large"
    );
    let bytes = response.bytes().await?;
    anyhow::ensure!(
        bytes.len() <= MAX_OAUTH_RESPONSE,
        "upstream OAuth response too large"
    );
    Ok(serde_json::from_slice(&bytes)?)
}

pub fn well_known(base: &url::Url, name: &str) -> anyhow::Result<url::Url> {
    let mut url = base.clone();
    let issuer_path = base.path().trim_start_matches('/');
    let path = if issuer_path.is_empty() {
        format!("/.well-known/{name}")
    } else {
        format!("/.well-known/{name}/{issuer_path}")
    };
    url.set_path(&path);
    url.set_query(None);
    url.set_fragment(None);
    Ok(url)
}

fn oidc_well_known(issuer: &url::Url) -> anyhow::Result<url::Url> {
    let mut url = issuer.clone();
    let path = format!(
        "{}/.well-known/openid-configuration",
        issuer.path().trim_end_matches('/')
    );
    url.set_path(&path);
    url.set_query(None);
    url.set_fragment(None);
    Ok(url)
}

pub async fn authorization_server_metadata(
    http: &reqwest::Client,
    issuer: &url::Url,
) -> anyhow::Result<Value> {
    let oauth_url = well_known(issuer, "oauth-authorization-server")?;
    match oauth_json(http.get(oauth_url)).await {
        Ok(metadata) => Ok(metadata),
        Err(oauth_error) => {
            let oidc_url = oidc_well_known(issuer)?;
            oauth_json(http.get(oidc_url)).await.map_err(|oidc_error| {
                anyhow::anyhow!(
                    "authorization-server metadata discovery failed (OAuth: {oauth_error}; OIDC: {oidc_error})"
                )
            })
        }
    }
}

pub async fn resolve_upstream_client(
    a: &App,
    integration: &crate::db::Integration,
) -> anyhow::Result<UpstreamOAuthClient> {
    if let Some(client) = a.db.upstream_oauth_client(&integration.id)? {
        return Ok(client);
    }
    let transport: HttpTransportConfig = serde_json::from_value(integration.config.clone())?;
    let oauth = transport
        .oauth
        .ok_or_else(|| anyhow::anyhow!("integration has no OAuth configuration"))?;
    let http = reqwest::Client::builder()
        .timeout(Duration::from_secs(15))
        .build()?;
    let mut issuer = oauth.issuer.clone();
    // Keep the issuer's advertised representation for RFC 9207 callback
    // comparison. `url::Url::to_string()` adds `/` to an origin-only URL,
    // which would turn an exact advertised issuer such as
    // `https://mcp.cloudflare.com` into a different issuer identifier.
    let mut advertised_issuer = issuer.as_ref().map(|value| value.as_str().to_owned());
    let mut authorization = oauth.authorization_endpoint.clone();
    let mut token = oauth.token_endpoint.clone();
    let mut registration = oauth.registration_endpoint.clone();
    let mut scope = oauth.scope.clone();
    let explicit_resource = oauth.resource.clone();
    let mut resource = None;
    let mut client_id_metadata_supported = false;

    if (authorization.is_none() || token.is_none()) && issuer.is_none() {
        let resource_metadata = match oauth.resource_metadata_url {
            Some(url) => url,
            None => well_known(&transport.url, "oauth-protected-resource")?,
        };
        let metadata = oauth_json(http.get(resource_metadata)).await?;
        resource = metadata
            .get("resource")
            .and_then(Value::as_str)
            .map(str::to_owned);
        if let Some(discovered) = resource.as_ref() {
            validate_oauth_uri(&url::Url::parse(discovered)?, "discovered OAuth resource")?;
        }
        if let (Some(explicit), Some(discovered)) = (&explicit_resource, &resource) {
            anyhow::ensure!(
                explicit == discovered,
                "explicit OAuth resource conflicts with protected-resource metadata"
            );
        }
        let authorization_server = metadata
            .get("authorization_servers")
            .and_then(Value::as_array)
            .and_then(|servers| servers.first())
            .and_then(Value::as_str);
        issuer = authorization_server.map(url::Url::parse).transpose()?;
        advertised_issuer = authorization_server.map(str::to_owned);
        anyhow::ensure!(
            issuer.is_some(),
            "protected-resource metadata has no authorization server"
        );
    }

    if authorization.is_none()
        || token.is_none()
        || (oauth.client_id.is_none() && registration.is_none())
    {
        let issuer = issuer
            .clone()
            .ok_or_else(|| anyhow::anyhow!("OAuth issuer is required for discovery"))?;
        let metadata = authorization_server_metadata(&http, &issuer).await?;
        client_id_metadata_supported = metadata
            .get("client_id_metadata_document_supported")
            .and_then(Value::as_bool)
            .unwrap_or(false);
        if scope.is_none() {
            scope = metadata
                .get("scopes_supported")
                .and_then(Value::as_array)
                .and_then(|scopes| {
                    scopes
                        .iter()
                        .filter_map(Value::as_str)
                        .find(|candidate| *candidate == "mcp")
                        .or_else(|| scopes.iter().find_map(Value::as_str))
                })
                .map(str::to_owned);
        }
        if let Some(discovered_issuer) = metadata.get("issuer").and_then(Value::as_str) {
            anyhow::ensure!(
                url::Url::parse(discovered_issuer)? == issuer,
                "authorization-server issuer mismatch"
            );
            advertised_issuer = Some(discovered_issuer.to_owned());
        }
        authorization = authorization.or_else(|| {
            metadata
                .get("authorization_endpoint")
                .and_then(Value::as_str)
                .and_then(|value| url::Url::parse(value).ok())
        });
        token = token.or_else(|| {
            metadata
                .get("token_endpoint")
                .and_then(Value::as_str)
                .and_then(|value| url::Url::parse(value).ok())
        });
        registration = registration.or_else(|| {
            metadata
                .get("registration_endpoint")
                .and_then(Value::as_str)
                .and_then(|value| url::Url::parse(value).ok())
        });
        anyhow::ensure!(
            metadata
                .get("code_challenge_methods_supported")
                .and_then(Value::as_array)
                .is_some_and(|methods| methods.iter().any(|method| method == "S256")),
            "upstream authorization server does not advertise PKCE S256"
        );
    }
    let authorization =
        authorization.ok_or_else(|| anyhow::anyhow!("authorization endpoint missing"))?;
    let token = token.ok_or_else(|| anyhow::anyhow!("token endpoint missing"))?;
    let (client_id, client_secret) = if let Some(client_id) = oauth.client_id {
        (client_id, oauth.client_secret)
    } else if client_id_metadata_supported {
        (
            format!(
                "{}/.well-known/oauth-client",
                a.config.base_url.as_str().trim_end_matches('/')
            ),
            None,
        )
    } else {
        let registration = registration
            .ok_or_else(|| anyhow::anyhow!("upstream does not advertise dynamic registration"))?;
        let redirect = format!(
            "{}/oauth/upstream/callback",
            a.config.base_url.as_str().trim_end_matches('/')
        );
        let response = oauth_json(http.post(registration).json(&json!({
            "client_name":"cog",
            "redirect_uris":[redirect],
            "grant_types":["authorization_code","refresh_token"],
            "response_types":["code"],
            "token_endpoint_auth_method":"client_secret_post"
        })))
        .await?;
        (
            response
                .get("client_id")
                .and_then(Value::as_str)
                .ok_or_else(|| anyhow::anyhow!("registration response has no client_id"))?
                .to_owned(),
            response
                .get("client_secret")
                .and_then(Value::as_str)
                .map(str::to_owned),
        )
    };
    let client = UpstreamOAuthClient {
        client_id,
        client_secret_ciphertext: client_secret
            .map(|secret| a.secrets.seal(secret.as_bytes()))
            .transpose()?,
        authorization_endpoint: authorization.to_string(),
        token_endpoint: token.to_string(),
        scope: scope.unwrap_or_default(),
        resource: resource.or(explicit_resource),
        issuer: advertised_issuer,
    };
    a.db.put_upstream_oauth_client(&integration.id, &client)?;
    Ok(client)
}

pub fn open_secret_text(a: &App, ciphertext: &str) -> anyhow::Result<String> {
    Ok(String::from_utf8(a.secrets.open(ciphertext)?)?)
}

pub fn oauth_authorization_value(token_type: &str, access_token: &str) -> String {
    // OAuth token type identifiers are case-insensitive (RFC 6749 §7.1), but
    // some protected resources accept only the conventional HTTP spelling.
    let scheme = if token_type.eq_ignore_ascii_case("bearer") {
        "Bearer"
    } else {
        token_type
    };
    format!("{scheme} {access_token}")
}

pub async fn upstream_authorization(a: &App, integration: &str) -> anyhow::Result<Option<String>> {
    let Some(mut token) = a.db.upstream_oauth_token(integration)? else {
        return Ok(None);
    };
    let now = chrono::Utc::now().timestamp();
    if token.expires_at.is_none_or(|expires| expires > now + 30) {
        return Ok(Some(oauth_authorization_value(
            &token.token_type,
            &open_secret_text(a, &token.access_token_ciphertext)?,
        )));
    }

    let _mutation = a.mutations.lock().await;
    // Another request may have refreshed while we waited for the mutation gate.
    token =
        a.db.upstream_oauth_token(integration)?
            .ok_or_else(|| anyhow::anyhow!("upstream OAuth token disappeared"))?;
    let now = chrono::Utc::now().timestamp();
    if token.expires_at.is_none_or(|expires| expires > now + 30) {
        return Ok(Some(oauth_authorization_value(
            &token.token_type,
            &open_secret_text(a, &token.access_token_ciphertext)?,
        )));
    }
    anyhow::ensure!(
        token.refresh_expires_at.is_none_or(|expires| expires > now),
        "upstream refresh token expired; reconnect required"
    );
    let refresh_ciphertext = token
        .refresh_token_ciphertext
        .as_deref()
        .ok_or_else(|| anyhow::anyhow!("upstream access token expired; reconnect required"))?;
    let refresh = open_secret_text(a, refresh_ciphertext)?;
    let client =
        a.db.upstream_oauth_client(integration)?
            .ok_or_else(|| anyhow::anyhow!("upstream OAuth client missing"))?;
    let mut form = vec![
        ("grant_type", "refresh_token".to_owned()),
        ("refresh_token", refresh),
        ("client_id", client.client_id.clone()),
    ];
    if let Some(resource) = client.resource.clone() {
        form.push(("resource", resource));
    }
    if let Some(secret) = client.client_secret_ciphertext.as_deref() {
        form.push(("client_secret", open_secret_text(a, secret)?));
    }
    let http = reqwest::Client::builder()
        .timeout(Duration::from_secs(15))
        .build()?;
    let response = oauth_json(http.post(&client.token_endpoint).form(&form)).await?;
    let access = response
        .get("access_token")
        .and_then(Value::as_str)
        .ok_or_else(|| anyhow::anyhow!("refresh response has no access_token"))?;
    let rotated_refresh = response
        .get("refresh_token")
        .and_then(Value::as_str)
        .map(|value| a.secrets.seal(value.as_bytes()))
        .transpose()?
        .or_else(|| token.refresh_token_ciphertext.clone());
    let refreshed = UpstreamOAuthToken {
        access_token_ciphertext: a.secrets.seal(access.as_bytes())?,
        refresh_token_ciphertext: rotated_refresh,
        token_type: response
            .get("token_type")
            .and_then(Value::as_str)
            .unwrap_or(&token.token_type)
            .to_owned(),
        scope: response
            .get("scope")
            .and_then(Value::as_str)
            .unwrap_or(&token.scope)
            .to_owned(),
        expires_at: response
            .get("expires_in")
            .and_then(Value::as_i64)
            .map(|seconds| now + seconds),
        refresh_expires_at: response
            .get("refresh_expires_in")
            .and_then(Value::as_i64)
            .map(|seconds| now + seconds)
            .or(token.refresh_expires_at),
    };
    a.db.put_upstream_oauth_token(integration, &refreshed)?;
    persist(a).await?;
    Ok(Some(oauth_authorization_value(
        &refreshed.token_type,
        access,
    )))
}

pub async fn start_upstream_step_up(
    a: &App,
    user: &str,
    integration_id: &str,
    challenge: &UpstreamInsufficientScope,
) -> anyhow::Result<url::Url> {
    let _mutation = a.mutations.lock().await;
    a.lease.assert_live()?;
    anyhow::ensure!(
        a.db.integration(integration_id, user)?.is_some(),
        "integration not found"
    );
    let mut client =
        a.db.upstream_oauth_client(integration_id)?
            .ok_or_else(|| anyhow::anyhow!("upstream OAuth client missing"))?;
    let metadata = oauth_json(
        reqwest::Client::builder()
            .timeout(Duration::from_secs(15))
            .build()?
            .get(&challenge.resource_metadata),
    )
    .await?;
    let challenged_resource = metadata
        .get("resource")
        .and_then(Value::as_str)
        .ok_or_else(|| anyhow::anyhow!("upstream resource metadata has no resource"))?;
    validate_oauth_uri(
        &url::Url::parse(challenged_resource)?,
        "challenged OAuth resource",
    )?;
    anyhow::ensure!(
        client.resource.as_deref() == Some(challenged_resource),
        "upstream scope challenge is for an unexpected resource"
    );

    let mut scopes = client
        .scope
        .split_ascii_whitespace()
        .map(str::to_owned)
        .collect::<Vec<_>>();
    if let Some(token) = a.db.upstream_oauth_token(integration_id)? {
        for scope in token.scope.split_ascii_whitespace() {
            if !scopes.iter().any(|existing| existing == scope) {
                scopes.push(scope.to_owned());
            }
        }
    }
    for scope in &challenge.scopes {
        if !scopes.contains(scope) {
            scopes.push(scope.clone());
        }
    }
    client.scope = scopes.join(" ");
    a.db.put_upstream_oauth_client(integration_id, &client)?;

    let state = crate::crypto::random_token(32);
    let verifier = crate::crypto::random_token(48);
    use base64::Engine;
    use sha2::Digest;
    let code_challenge = base64::engine::general_purpose::URL_SAFE_NO_PAD
        .encode(sha2::Sha256::digest(verifier.as_bytes()));
    let redirect = format!(
        "{}/oauth/upstream/callback",
        a.config.base_url.as_str().trim_end_matches('/')
    );
    a.db.store_oauth_state(
        &token_hash(&state),
        user,
        integration_id,
        &a.secrets.seal(verifier.as_bytes())?,
        &redirect,
        chrono::Utc::now().timestamp() + 600,
        client.resource.as_deref(),
    )?;
    audit_details(
        a,
        Some(user),
        "integration.oauth_step_up",
        Some(integration_id),
        "required",
        &json!({"scopes":challenge.scopes}),
    )?;
    persist(a).await?;

    let mut url = url::Url::parse(&client.authorization_endpoint)?;
    url.query_pairs_mut()
        .append_pair("response_type", "code")
        .append_pair("client_id", &client.client_id)
        .append_pair("redirect_uri", &redirect)
        .append_pair("state", &state)
        .append_pair("code_challenge", &code_challenge)
        .append_pair("code_challenge_method", "S256")
        .append_pair("scope", &client.scope)
        .append_pair("resource", challenged_resource);
    Ok(url)
}

pub async fn upstream_oauth_start(
    State(a): State<App>,
    Path(id): Path<String>,
    h: HeaderMap,
) -> impl IntoResponse {
    let _mutation = a.mutations.lock().await;
    if let Err(e) = a.lease.assert_live() {
        return (StatusCode::SERVICE_UNAVAILABLE, e.to_string()).into_response();
    }
    let u = match scoped_user(&a, &h, "integrations:write") {
        Ok(v) => v,
        Err(failure) => return auth_failure(&a, failure, "integrations:write"),
    };
    let Some(i) = a.db.integration(&id, &u).ok().flatten() else {
        return StatusCode::NOT_FOUND.into_response();
    };
    if !i.config.get("oauth").is_some_and(|value| !value.is_null()) {
        return (
            StatusCode::BAD_REQUEST,
            "integration does not use upstream OAuth",
        )
            .into_response();
    }
    let (status, connected) = upstream_connection_state(&a, &i);
    if connected {
        return Json(json!({
            "id": id,
            "alreadyConnected": true,
            "upstreamConnected": true,
            "upstreamStatus": status,
            "reconnectRequired": true
        }))
        .into_response();
    }
    let client = match resolve_upstream_client(&a, &i).await {
        Ok(client) => client,
        Err(error) => return (StatusCode::BAD_GATEWAY, error.to_string()).into_response(),
    };
    let state = crate::crypto::random_token(32);
    let verifier = crate::crypto::random_token(48);
    use base64::Engine;
    use sha2::Digest;
    let challenge = base64::engine::general_purpose::URL_SAFE_NO_PAD
        .encode(sha2::Sha256::digest(verifier.as_bytes()));
    let redirect = format!(
        "{}/oauth/upstream/callback",
        a.config.base_url.as_str().trim_end_matches('/')
    );
    let sealed = match a.secrets.seal(verifier.as_bytes()) {
        Ok(v) => v,
        Err(e) => return (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()).into_response(),
    };
    if let Err(e) = a.db.store_oauth_state(
        &token_hash(&state),
        &u,
        &id,
        &sealed,
        &redirect,
        chrono::Utc::now().timestamp() + 600,
        client.resource.as_deref(),
    ) {
        return (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()).into_response();
    }
    if let Err(error) = audit(
        &a,
        Some(&u),
        "integration.oauth_start",
        Some(&id),
        "success",
    ) {
        return (StatusCode::INTERNAL_SERVER_ERROR, error.to_string()).into_response();
    }
    if let Err(e) = persist(&a).await {
        return (StatusCode::SERVICE_UNAVAILABLE, e.to_string()).into_response();
    }
    let mut url = match url::Url::parse(&client.authorization_endpoint) {
        Ok(v) => v,
        Err(e) => return (StatusCode::BAD_REQUEST, e.to_string()).into_response(),
    };
    let mut pairs = url.query_pairs_mut();
    pairs
        .append_pair("response_type", "code")
        .append_pair("client_id", &client.client_id)
        .append_pair("redirect_uri", &redirect)
        .append_pair("state", &state)
        .append_pair("code_challenge", &challenge)
        .append_pair("code_challenge_method", "S256");
    if !client.scope.is_empty() {
        pairs.append_pair("scope", &client.scope);
    }
    if let Some(resource) = client.resource.as_deref() {
        pairs.append_pair("resource", resource);
    }
    drop(pairs);
    Json(json!({"id":id,"alreadyConnected":false,"upstreamConnected":false,"upstreamStatus":status,"authorization_url":url,"one_time":true,"prefetched":false})).into_response()
}
#[derive(Deserialize)]
pub struct UpstreamCallback {
    pub code: Option<String>,
    pub state: String,
    pub error: Option<String>,
    pub error_description: Option<String>,
    pub iss: Option<String>,
}
pub async fn upstream_callback(
    State(a): State<App>,
    axum::extract::Query(q): axum::extract::Query<UpstreamCallback>,
) -> impl IntoResponse {
    let _mutation = a.mutations.lock().await;
    if let Err(e) = a.lease.assert_live() {
        return (StatusCode::SERVICE_UNAVAILABLE, e.to_string()).into_response();
    }
    if let Some(e) = q.error {
        let description = q
            .error_description
            .as_deref()
            .unwrap_or("authorization was rejected");
        return (
            StatusCode::BAD_REQUEST,
            Html(standalone_page(
                "Integration authorization",
                "Connection was not completed",
                &format!(
                    "<p class=\"lead\">The upstream provider returned an authorization error.</p><div class=\"notice danger\"><strong>{}</strong><br>{}</div><div class=\"actions\"><a class=\"button secondary\" href=\"/\">Return to cog</a></div>",
                    html_escape(&e),
                    html_escape(description)
                ),
                "status",
            )),
        )
            .into_response();
    }
    let Some(code) = q.code else {
        return browser_error(
            StatusCode::BAD_REQUEST,
            "Missing authorization code",
            "The upstream provider returned without an authorization code.",
        );
    };
    let Some((user, id, sealed, redirect, expires, state_resource)) =
        a.db.redeem_oauth_state(&token_hash(&q.state))
            .ok()
            .flatten()
    else {
        return browser_error(
            StatusCode::BAD_REQUEST,
            "Authorization request expired",
            "This authorization link is invalid or has already been used. Start a fresh connection from cog.",
        );
    };
    if expires < chrono::Utc::now().timestamp() {
        return browser_error(
            StatusCode::BAD_REQUEST,
            "Authorization request expired",
            "This authorization request took too long. Start a fresh connection from cog.",
        );
    }
    let verifier = match a
        .secrets
        .open(&sealed)
        .and_then(|v| Ok(String::from_utf8(v)?))
    {
        Ok(v) => v,
        Err(_) => {
            return browser_error(
                StatusCode::BAD_REQUEST,
                "Authorization request is invalid",
                "Clanker Operations Gateway could not verify this authorization request. Start a fresh connection.",
            );
        }
    };
    let Some(_integration) = a.db.integration(&id, &user).ok().flatten() else {
        return browser_error(
            StatusCode::NOT_FOUND,
            "Integration not found",
            "The integration associated with this request no longer exists.",
        );
    };
    let Some(client) = a.db.upstream_oauth_client(&id).ok().flatten() else {
        return browser_error(
            StatusCode::BAD_REQUEST,
            "Connection must be restarted",
            "The saved upstream authorization client is missing.",
        );
    };
    if state_resource != client.resource {
        return browser_error(
            StatusCode::BAD_REQUEST,
            "Connection details changed",
            "OAuth resource changed; reconnect required",
        );
    }
    if let Some(callback_issuer) = q.iss.as_deref()
        && client
            .issuer
            .as_deref()
            .is_some_and(|issuer| issuer != callback_issuer)
    {
        return browser_error(
            StatusCode::BAD_REQUEST,
            "Provider verification failed",
            "The authorization response came from an unexpected issuer.",
        );
    }
    let mut form = vec![
        ("grant_type", "authorization_code".to_owned()),
        ("code", code),
        ("client_id", client.client_id.clone()),
        ("redirect_uri", redirect),
        ("code_verifier", verifier),
    ];
    if let Some(secret) = client.client_secret_ciphertext.as_deref() {
        let secret = match a
            .secrets
            .open(secret)
            .and_then(|value| Ok(String::from_utf8(value)?))
        {
            Ok(secret) => secret,
            Err(_) => {
                return browser_error(
                    StatusCode::INTERNAL_SERVER_ERROR,
                    "Connection could not be completed",
                    "Clanker Operations Gateway could not open the saved provider credentials.",
                );
            }
        };
        form.push(("client_secret", secret));
    }
    if let Some(resource) = client.resource.clone() {
        form.push(("resource", resource));
    }
    let http = match reqwest::Client::builder()
        .timeout(Duration::from_secs(15))
        .build()
    {
        Ok(client) => client,
        Err(_) => {
            return browser_error(
                StatusCode::INTERNAL_SERVER_ERROR,
                "Connection could not be completed",
                "Clanker Operations Gateway could not prepare the provider token request.",
            );
        }
    };
    let token = match oauth_json(http.post(&client.token_endpoint).form(&form)).await {
        Ok(token) => token,
        Err(_) => {
            return browser_error(
                StatusCode::BAD_GATEWAY,
                "Provider token exchange failed",
                "The upstream provider did not accept or complete the token exchange.",
            );
        }
    };
    let Some(access) = token.get("access_token").and_then(Value::as_str) else {
        return browser_error(
            StatusCode::BAD_GATEWAY,
            "Provider response was incomplete",
            "The upstream provider did not return an access token.",
        );
    };
    let now = chrono::Utc::now().timestamp();
    let stored = match (|| -> anyhow::Result<UpstreamOAuthToken> {
        let refresh = token.get("refresh_token").and_then(Value::as_str);
        Ok(UpstreamOAuthToken {
            access_token_ciphertext: a.secrets.seal(access.as_bytes())?,
            refresh_token_ciphertext: refresh
                .map(|token| a.secrets.seal(token.as_bytes()))
                .transpose()?,
            token_type: token
                .get("token_type")
                .and_then(Value::as_str)
                .unwrap_or("Bearer")
                .to_owned(),
            scope: token
                .get("scope")
                .and_then(Value::as_str)
                .unwrap_or(&client.scope)
                .to_owned(),
            expires_at: token
                .get("expires_in")
                .and_then(Value::as_i64)
                .map(|seconds| now + seconds),
            refresh_expires_at: token
                .get("refresh_expires_in")
                .and_then(Value::as_i64)
                .map(|seconds| now + seconds),
        })
    })() {
        Ok(token) => token,
        Err(_) => {
            return browser_error(
                StatusCode::INTERNAL_SERVER_ERROR,
                "Connection could not be saved",
                "Clanker Operations Gateway could not protect the provider credentials.",
            );
        }
    };
    if a.db.put_upstream_oauth_token(&id, &stored).is_err() {
        return browser_error(
            StatusCode::INTERNAL_SERVER_ERROR,
            "Connection could not be saved",
            "Clanker Operations Gateway could not store the provider credentials.",
        );
    }
    if audit(
        &a,
        Some(&user),
        "integration.oauth_connect",
        Some(&id),
        "success",
    )
    .is_err()
    {
        return browser_error(
            StatusCode::INTERNAL_SERVER_ERROR,
            "Connection could not be completed",
            "Clanker Operations Gateway could not record the authorization result.",
        );
    }
    disconnect_provider(&a, &id).await;
    if persist(&a).await.is_err() {
        return browser_error(
            StatusCode::SERVICE_UNAVAILABLE,
            "Connection is not durable yet",
            "Clanker Operations Gateway could not safely persist this authorization. Check service health before retrying.",
        );
    }
    Html(standalone_page(
        "Integration connected",
        "Connection complete",
        "<p class=\"lead\">Clanker Operations Gateway securely received and stored the integration authorization.</p><div class=\"notice success\">You can close this window or return to the dashboard.</div><div class=\"actions\"><a class=\"button\" href=\"/\">Return to cog</a></div>",
        "status",
    ))
    .into_response()
}

async fn persist(a: &App) -> anyhow::Result<()> {
    a.lease.assert_live()?;
    let durable_txid = match a.replicator.sync().await {
        Ok(txid) => txid,
        Err(error) => {
            // A committed SQLite mutation that cannot be proven in S3 makes
            // continued ownership unsafe. Stopping renewal drives the server's
            // terminal self-fence path; this process must not acknowledge or
            // perform subsequent mutations from an unreplicated state.
            a.lease.stop_renewal();
            return Err(error);
        }
    };
    anyhow::ensure!(durable_txid > 0, "mutation has no durable LTX position");
    a.lease.assert_live()?;
    tracing::debug!(durable_txid, "database mutation is durable");
    Ok(())
}
