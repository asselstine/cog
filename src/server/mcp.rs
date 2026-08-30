use super::*;

use crate::{
    diagnostics::safe_error,
    git::RepositoryReference,
    git::providers::{GitProvider, github::GitHubProvider},
    mcp::{self, RpcRequest, RpcResponse},
    upstream::{Catalog, HttpMcp, StdioMcp, Tool, ToolProvider, UpstreamInsufficientScope},
};
use axum::{
    Json,
    extract::Query,
    extract::State,
    http::{HeaderMap, StatusCode, header},
    response::{IntoResponse, Response},
};
use rust_embed::RustEmbed;
use serde::Deserialize;
use serde_json::{Value, json};
use std::{
    collections::{HashMap, HashSet, VecDeque},
    sync::{
        Arc,
        atomic::{AtomicU64, Ordering},
    },
    time::{Duration, Instant},
};

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
    crate::mcp::tools::admin::tool(name, description)
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

pub(super) fn safe_integration(
    a: &App,
    integration: crate::db::Integration,
    access: bool,
) -> Value {
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

pub(super) fn git_control_tool(name: &str, description: &str) -> Tool {
    crate::mcp::tools::git::tool(name, description)
}

pub(super) fn ssh_advertisement(app: &App, repository_id: &str) -> Option<Value> {
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

pub(super) fn resource_metadata_url(a: &App) -> String {
    format!(
        "{}/.well-known/oauth-protected-resource",
        a.config.base_url.as_str().trim_end_matches('/')
    )
}

pub(super) fn mcp_http_response(response: RpcResponse) -> Response {
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

pub(super) fn mcp_origin_allowed(a: &App, auth: &AuthContext, headers: &HeaderMap) -> bool {
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

pub(super) fn mcp_protocol_version_valid(headers: &HeaderMap) -> bool {
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
pub(super) async fn mcp_endpoint(
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
pub(super) struct McpOptions {
    #[serde(default = "default_codemode")]
    codemode: bool,
}

pub(super) fn default_codemode() -> bool {
    false
}

pub fn native_admin_scope(tool: &str) -> Option<&'static str> {
    admin_required_scope(tool.strip_prefix("cog_")?)
}

pub(super) fn admin_required_scope(tool: &str) -> Option<&'static str> {
    crate::mcp::tools::admin::required_scope(tool)
}
