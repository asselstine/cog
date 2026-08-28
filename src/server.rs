use crate::{
    Config,
    crypto::{SecretBox, token_hash},
    db::{Database, StorageMode, UpstreamOAuthClient, UpstreamOAuthToken},
    diagnostics::{
        StartupError, StartupPhase, credential_provider_class, redacted_error, safe_endpoint,
        safe_error,
    },
    git::providers::{GitProvider, github::GitHubProvider},
    git::{GitOperation, RepositoryReference, ResolvedRepository, UpstreamAuthorization},
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
    body::{Body, HttpBody},
    extract::{DefaultBodyLimit, Query},
    extract::{Form, Path, State},
    http::{HeaderMap, Request, StatusCode, header},
    response::{Html, IntoResponse, Redirect, Response},
    routing::{get, post},
};
use futures_util::StreamExt;
use object_store::{ObjectStore, aws::AmazonS3Builder, path::Path as ObjectPath};
use rust_embed::RustEmbed;
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use std::{
    collections::{HashMap, HashSet, VecDeque},
    net::{IpAddr, SocketAddr},
    sync::{
        Arc,
        atomic::{AtomicU64, Ordering},
    },
    time::{Duration, Instant},
};
use tokio::io::{AsyncReadExt, AsyncWriteExt};

#[derive(Default)]
struct Metrics {
    oauth_failures: AtomicU64,
    execution_failures: AtomicU64,
    v8_limit_hits: AtomicU64,
    upstream_calls: AtomicU64,
    upstream_failures: AtomicU64,
    git_active_streams: AtomicU64,
    git_operations: AtomicU64,
    git_auth_denied: AtomicU64,
    git_upstream_failures: AtomicU64,
    git_request_bytes: AtomicU64,
    git_response_bytes: AtomicU64,
    git_limit_rejections: AtomicU64,
    git_client_limit_rejections: AtomicU64,
}

#[derive(Default)]
struct ClientStreamLimiter {
    active: std::sync::Mutex<HashMap<String, usize>>,
}
struct ClientStreamPermit {
    limiter: Arc<ClientStreamLimiter>,
    client: String,
}
impl ClientStreamLimiter {
    fn try_acquire(self: &Arc<Self>, client: &str, maximum: usize) -> Option<ClientStreamPermit> {
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
struct Frontend;

struct MeasuredProvider {
    inner: Arc<dyn ToolProvider>,
    metrics: Arc<Metrics>,
}

struct PolicyProvider {
    inner: Arc<dyn ToolProvider>,
    allow: Option<HashSet<String>>,
    deny: HashSet<String>,
}

struct OAuthStepUpProvider {
    inner: Arc<dyn ToolProvider>,
    app: App,
    user: String,
    integration: String,
}

struct AdminProvider {
    app: App,
    auth: AuthContext,
}

struct GitControlProvider {
    app: App,
    auth: AuthContext,
}

fn admin_tool(name: &str, description: &str) -> Tool {
    let (input_schema, read_only, destructive, idempotent, open_world) = match name {
        "integrations_list" | "agents_list" | "tokens_list" | "audit_list" | "agent_get_self" => (
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

fn upstream_connection_state(
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

fn redact_value(value: Value) -> Value {
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
        Ok(self
            .advertised_tools()
            .await?
            .into_iter()
            .filter(|tool| {
                (matches!(
                    tool.name.as_str(),
                    "integrations_list" | "agent_get_self" | "agent_update_self"
                ) && self.auth.allows("mcp"))
                    || admin_required_scope(&tool.name).is_some_and(|scope| self.auth.allows(scope))
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
                Ok(serde_json::to_value(self.app.db.audit_events_for_user(
                    &self.auth.user,
                    args.get("limit").and_then(Value::as_u64).unwrap_or(100) as u32,
                )?)?)
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
            _ => anyhow::bail!("unknown or unauthorized administration tool"),
        }
    }
}

fn git_control_tool(name: &str, description: &str, destructive: bool) -> Tool {
    Tool{name:name.into(),description:Some(description.into()),input_schema:match name{
 "repository_access"=>json!({"type":"object","properties":{"integrationId":{"type":"string"},"repository":{"type":"string"}},"required":["integrationId","repository"],"additionalProperties":false}),
 "sealed_credentials"=>json!({"type":"object","properties":{"repositoryId":{"type":"string"},"recipientPublicKey":{"type":"string"},"requestNonce":{"type":"string"}},"required":["repositoryId","recipientPublicKey","requestNonce"],"additionalProperties":false}),
 _=>json!({"type":"object","properties":{},"additionalProperties":false})},extra:serde_json::from_value(json!({"annotations":{"readOnlyHint":!destructive,"destructiveHint":destructive,"openWorldHint":false}})).unwrap_or_default()}
}

async fn git_provider(
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
        Ok(vec![
            git_control_tool(
                "repository_access",
                "Resolve a GitHub repository and return its COG remote. Access is controlled by the GitHub App installation and this client's existing integration authorization.",
                false,
            ),
            git_control_tool(
                "sealed_credentials",
                "Mint a 15-minute repository credential encrypted to a one-use git-credential-cog public key. The result contains ciphertext only and must be passed to `git-credential-cog import` over stdin.",
                false,
            ),
        ])
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
                Ok(
                    json!({"repositoryId":repo.id,"displayName":repo.display_name,"remoteUrl":format!("{}/git/{}.git",self.app.config.base_url.as_str().trim_end_matches('/'),repo.id),"credential":{"source":"sealed_credentials","helper":"git-credential-cog","useHttpPath":true}}),
                )
            }
            "sealed_credentials" => {
                let request: crate::git::sealed::SealedCredentialRequest =
                    serde_json::from_value(args)?;
                let repository_id = &request.repository_id;
                crate::git::sealed::decode_array::<32>(&request.request_nonce, "request nonce")?;
                let repository = self
                    .app
                    .db
                    .git_repository(repository_id)?
                    .filter(|repository| repository.user_id == self.auth.user)
                    .ok_or_else(|| anyhow::anyhow!("repository not found"))?;
                if !self.auth.allows_integration(&repository.integration_id) {
                    return Err(crate::authz::InsufficientScope {
                        scopes: vec![format!("integration:{}", repository.integration_id)],
                    }
                    .into());
                }
                let _mutation = self.app.mutations.lock().await;
                self.app.lease.assert_live()?;
                let expires_at = chrono::Utc::now().timestamp() + 900;
                let credential = self.app.db.issue_git_credential(
                    &self.auth.user,
                    &self.auth.client,
                    repository_id,
                    "write",
                    900,
                )?;
                persist(&self.app).await?;
                let origin = self.app.config.base_url.as_str().trim_end_matches('/');
                Ok(serde_json::to_value(crate::git::sealed::seal(
                    &request,
                    origin,
                    &crate::git::sealed::CredentialPayload {
                        username: "cog".into(),
                        password: credential,
                        repository_id: repository_id.clone(),
                        origin: origin.to_owned(),
                        expires_at,
                    },
                )?)?)
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
struct RateLimiter {
    attempts: std::sync::Mutex<HashMap<String, VecDeque<Instant>>>,
}

impl RateLimiter {
    fn allow(&self, key: String, maximum: usize, window: Duration) -> bool {
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
struct App {
    config: Config,
    db: Database,
    secrets: SecretBox,
    runtime: Arc<CodeRuntime>,
    lease: Authority,
    replicator: Durability,
    providers: Arc<tokio::sync::Mutex<HashMap<String, Arc<dyn ToolProvider>>>>,
    metrics: Arc<Metrics>,
    /// Serializes each committed mutation with its LTX durability proof. This
    /// prevents another request from advancing the WAL between a mutation and
    /// the acknowledgement position captured for it.
    mutations: Arc<tokio::sync::Mutex<()>>,
    auth_rate_limit: Arc<RateLimiter>,
    git_providers: Arc<tokio::sync::Mutex<HashMap<String, Arc<dyn GitProvider>>>>,
    git_streams: Arc<tokio::sync::Semaphore>,
    git_client_streams: Arc<ClientStreamLimiter>,
}

#[derive(Clone)]
enum Authority {
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
enum Durability {
    Local,
    S3(Arc<Replicator>),
}

impl Durability {
    async fn sync(&self) -> anyhow::Result<u64> {
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

fn create_user_record(db: &Database, email: &str, password: &str) -> anyhow::Result<()> {
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
    let app = App {
        secrets: SecretBox::new(config.master_key.as_bytes()),
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
    };
    let shutdown_providers = app.providers.clone();
    let router = build_router(app);
    let listener = tokio::net::TcpListener::bind(config.listen).await?;
    tracing::info!(address=%config.listen,"cog ready");
    axum::serve(listener, router)
        .with_graceful_shutdown(async move {
            tokio::select! {
                _ = tokio::signal::ctrl_c() => {
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
    Ok(())
}

fn build_router(app: App) -> Router {
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
        .route("/git/{*path}", axum::routing::any(git_smart_http))
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

async fn git_smart_http(
    State(a): State<App>,
    Path(path): Path<String>,
    request: Request<Body>,
) -> Response {
    let Some((repository, endpoint)) = path
        .split_once(".git/")
        .map(|(repository, endpoint)| (repository.to_owned(), endpoint.to_owned()))
    else {
        return StatusCode::NOT_FOUND.into_response();
    };
    let permit = match a.git_streams.clone().try_acquire_owned() {
        Ok(v) => v,
        Err(_) => {
            a.metrics
                .git_limit_rejections
                .fetch_add(1, Ordering::Relaxed);
            return StatusCode::TOO_MANY_REQUESTS.into_response();
        }
    };
    a.metrics.git_active_streams.fetch_add(1, Ordering::Relaxed);
    a.metrics.git_operations.fetch_add(1, Ordering::Relaxed);
    struct ActiveGuard {
        metrics: Arc<Metrics>,
        _permit: tokio::sync::OwnedSemaphorePermit,
    }
    impl Drop for ActiveGuard {
        fn drop(&mut self) {
            self.metrics
                .git_active_streams
                .fetch_sub(1, Ordering::Relaxed);
        }
    }
    let active = ActiveGuard {
        metrics: a.metrics.clone(),
        _permit: permit,
    };
    if !crate::git::model::valid_repository_id(&repository) {
        return StatusCode::NOT_FOUND.into_response();
    }
    let service = request.uri().query().and_then(|q| {
        url::form_urlencoded::parse(q.as_bytes())
            .find(|(k, _)| k == "service")
            .map(|(_, v)| v.into_owned())
    });
    let operation =
        match crate::git::model::classify(request.method().as_str(), &endpoint, service.as_deref())
        {
            Ok(v) => v,
            Err(_) => return StatusCode::BAD_REQUEST.into_response(),
        };
    if !a.lease.is_live() {
        return StatusCode::SERVICE_UNAVAILABLE.into_response();
    }
    let token = match crate::git::auth::credential(request.headers()) {
        Some(v) => v,
        None => {
            a.metrics.git_auth_denied.fetch_add(1, Ordering::Relaxed);
            return git_auth_failure(AuthFailure::Missing);
        }
    };
    let now = chrono::Utc::now().timestamp();
    if request
        .body()
        .size_hint()
        .upper()
        .is_some_and(|size| size > a.config.git_max_request_bytes)
    {
        a.metrics
            .git_limit_rejections
            .fetch_add(1, Ordering::Relaxed);
        return StatusCode::PAYLOAD_TOO_LARGE.into_response();
    }
    let context = match a
        .db
        .git_credential_context(&token, &repository, now)
        .ok()
        .flatten()
    {
        Some(v) => v,
        None => {
            return git_auth_failure(AuthFailure::Invalid);
        }
    };
    let repo = match a.db.git_repository(&repository).ok().flatten() {
        Some(v) if v.user_id == context.user_id => v,
        _ => return StatusCode::NOT_FOUND.into_response(),
    };
    if !a.auth_rate_limit.allow(
        format!("git:{}:{}", context.client_id, repository),
        300,
        Duration::from_secs(60),
    ) {
        a.metrics
            .git_limit_rejections
            .fetch_add(1, Ordering::Relaxed);
        return StatusCode::TOO_MANY_REQUESTS.into_response();
    }
    if !context.integration_ids.contains(&repo.integration_id) {
        return git_auth_failure(AuthFailure::Insufficient);
    }
    let Some(client_permit) = a
        .git_client_streams
        .try_acquire(&context.client_id, a.config.git_max_streams_per_client)
    else {
        a.metrics
            .git_client_limit_rejections
            .fetch_add(1, Ordering::Relaxed);
        return StatusCode::TOO_MANY_REQUESTS.into_response();
    };
    let integration = match a
        .db
        .integration(&repo.integration_id, &context.user_id)
        .ok()
        .flatten()
    {
        Some(v) if v.enabled => v,
        _ => return StatusCode::FORBIDDEN.into_response(),
    };
    let provider = match git_provider(&a, &integration).await {
        Ok(v) => v,
        Err(_) => return StatusCode::BAD_GATEWAY.into_response(),
    };
    let resolved = ResolvedRepository {
        provider_repository_id: repo.provider_repository_id.clone(),
        display_name: repo.display_name.clone(),
        upstream_url: match url::Url::parse(&repo.upstream_url) {
            Ok(v) => v,
            Err(_) => return StatusCode::BAD_GATEWAY.into_response(),
        },
        metadata: repo.metadata.clone(),
    };
    let authorization = match provider.authorize_upstream(&resolved, operation).await {
        Ok(v) => v,
        Err(_) => return StatusCode::BAD_GATEWAY.into_response(),
    };
    let mut upstream = match provider.upstream_url(&resolved) {
        Ok(v) => v,
        Err(_) => return StatusCode::BAD_GATEWAY.into_response(),
    };
    upstream.set_path(&format!(
        "{}.git/{}",
        upstream.path().trim_end_matches(".git"),
        endpoint
    ));
    upstream.set_query(request.uri().query());
    let (parts, body) = request.into_parts();
    let client = match reqwest::Client::builder()
        .redirect(reqwest::redirect::Policy::none())
        .timeout(Duration::from_secs(a.config.git_timeout_secs))
        .build()
    {
        Ok(v) => v,
        Err(_) => return StatusCode::INTERNAL_SERVER_ERROR.into_response(),
    };
    let request_metrics = a.metrics.clone();
    let request_max = a.config.git_max_request_bytes;
    let idle = Duration::from_secs(a.config.git_idle_timeout_secs);
    let mut incoming = Box::pin(body.into_data_stream());
    let request_stream = async_stream::stream! {let mut seen=0_u64;loop{match tokio::time::timeout(idle,incoming.next()).await{Err(_)=>{yield Err::<bytes::Bytes,std::io::Error>(std::io::Error::new(std::io::ErrorKind::TimedOut,"Git request idle timeout"));break},Ok(None)=>break,Ok(Some(Err(_)))=>{yield Err::<bytes::Bytes,std::io::Error>(std::io::Error::new(std::io::ErrorKind::InvalidData,"invalid Git request body"));break},Ok(Some(Ok(bytes)))=>{seen=seen.saturating_add(bytes.len() as u64);if seen>request_max{yield Err::<bytes::Bytes,std::io::Error>(std::io::Error::new(std::io::ErrorKind::FileTooLarge,"Git request byte limit exceeded"));break}request_metrics.git_request_bytes.fetch_add(bytes.len() as u64,Ordering::Relaxed);yield Ok::<bytes::Bytes,std::io::Error>(bytes);}}}};
    let mut outgoing = client
        .request(parts.method, upstream)
        .headers(crate::git::headers::request_headers(&parts.headers))
        .body(reqwest::Body::wrap_stream(request_stream));
    outgoing = match authorization {
        UpstreamAuthorization::Basic { username, password } => {
            outgoing.basic_auth(username.expose(), Some(password.expose()))
        }
        UpstreamAuthorization::Bearer { token } => outgoing.bearer_auth(token.expose()),
        UpstreamAuthorization::Anonymous => outgoing,
    };
    let response = match tokio::time::timeout(
        Duration::from_secs(a.config.git_timeout_secs),
        outgoing.send(),
    )
    .await
    {
        Ok(Ok(v)) => v,
        _ => {
            a.metrics
                .git_upstream_failures
                .fetch_add(1, Ordering::Relaxed);
            return StatusCode::BAD_GATEWAY.into_response();
        }
    };
    if response.status().is_redirection() {
        return StatusCode::BAD_GATEWAY.into_response();
    }
    let status = response.status();
    let action = match operation {
        GitOperation::Write => "git.push",
        GitOperation::Read if endpoint == "info/refs" => "git.fetch",
        GitOperation::Read => "git.clone",
    };
    let _=a.db.record_audit(Some(&context.user_id),action,Some(&repository),if status.is_success(){"success"}else{"upstream_denied"},&json!({"identity_id":context.identity_id,"agent_id":context.agent_id,"client_id":context.client_id,"integration_id":repo.integration_id,"operation":format!("{operation:?}"),"upstream_status":status.as_u16()}));
    if !status.is_success() {
        a.metrics
            .git_upstream_failures
            .fetch_add(1, Ordering::Relaxed);
        return (
            StatusCode::BAD_GATEWAY,
            "upstream Git provider rejected the request",
        )
            .into_response();
    }
    let headers = crate::git::headers::response_headers(response.headers());
    let metrics = a.metrics.clone();
    let maximum = a.config.git_max_response_bytes;
    let idle = Duration::from_secs(a.config.git_idle_timeout_secs);
    let deadline = tokio::time::Instant::now() + Duration::from_secs(a.config.git_timeout_secs);
    let mut incoming = Box::pin(response.bytes_stream());
    let stream = async_stream::stream! {let _active=active;let _client_permit=client_permit;let mut seen=0_u64;loop{let remaining=deadline.saturating_duration_since(tokio::time::Instant::now());if remaining.is_zero(){yield Err::<bytes::Bytes,std::io::Error>(std::io::Error::new(std::io::ErrorKind::TimedOut,"Git response duration limit exceeded"));break}match tokio::time::timeout(idle.min(remaining),incoming.next()).await{Err(_)=>{yield Err::<bytes::Bytes,std::io::Error>(std::io::Error::new(std::io::ErrorKind::TimedOut,"Git response timeout"));break},Ok(None)=>break,Ok(Some(Err(_)))=>{yield Err::<bytes::Bytes,std::io::Error>(std::io::Error::other("Git upstream stream failed"));break},Ok(Some(Ok(bytes)))=>{seen=seen.saturating_add(bytes.len() as u64);if seen>maximum{yield Err::<bytes::Bytes,std::io::Error>(std::io::Error::new(std::io::ErrorKind::FileTooLarge,"Git response byte limit exceeded"));break}metrics.git_response_bytes.fetch_add(bytes.len() as u64,Ordering::Relaxed);yield Ok::<bytes::Bytes,std::io::Error>(bytes);}}}};
    let mut downstream = Response::new(Body::from_stream(stream));
    *downstream.status_mut() = status;
    *downstream.headers_mut() = headers;
    downstream
}

fn build_store(c: &Config) -> anyhow::Result<Arc<dyn ObjectStore>> {
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
async fn readiness(State(a): State<App>) -> impl IntoResponse {
    let live = a.lease.is_live();
    let pending = a.replicator.pending_txids();
    let status = if live && pending == 0 {
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
            }
        })),
    )
}
async fn version() -> Json<Value> {
    Json(json!({"name":"cog","version":env!("CARGO_PKG_VERSION")}))
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
            "# TYPE cog_git_active_streams gauge\ncog_git_active_streams {}\n",
            "# TYPE cog_git_operations_total counter\ncog_git_operations_total {}\n",
            "# TYPE cog_git_auth_denied_total counter\ncog_git_auth_denied_total {}\n",
            "# TYPE cog_git_upstream_failures_total counter\ncog_git_upstream_failures_total {}\n",
            "# TYPE cog_git_request_bytes_total counter\ncog_git_request_bytes_total {}\n",
            "# TYPE cog_git_response_bytes_total counter\ncog_git_response_bytes_total {}\n",
            "# TYPE cog_git_limit_rejections_total counter\ncog_git_limit_rejections_total {}\n",
            "# TYPE cog_git_client_limit_rejections_total counter\ncog_git_client_limit_rejections_total {}\n"
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
        a.metrics.git_active_streams.load(Ordering::Relaxed),
        a.metrics.git_operations.load(Ordering::Relaxed),
        a.metrics.git_auth_denied.load(Ordering::Relaxed),
        a.metrics.git_upstream_failures.load(Ordering::Relaxed),
        a.metrics.git_request_bytes.load(Ordering::Relaxed),
        a.metrics.git_response_bytes.load(Ordering::Relaxed),
        a.metrics.git_limit_rejections.load(Ordering::Relaxed),
        a.metrics
            .git_client_limit_rejections
            .load(Ordering::Relaxed),
    );
    (
        [(http::header::CONTENT_TYPE, "text/plain; version=0.0.4")],
        body,
    )
}
fn frontend_response(path: &str) -> Response {
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

fn rate_limit(
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
struct CsrfForm {
    csrf_token: String,
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
    Json(json!({
        "mode": "admin",
        "user": user,
        "csrf_token": csrf,
        "integrations": integrations,
        "clients": clients,
        "tokens": tokens,
        "identities": identities,
    }))
    .into_response()
}

#[derive(Deserialize)]
struct UiIntegrationForm {
    name: String,
    url: url::Url,
    csrf_token: String,
}
#[derive(Deserialize)]
struct UiNameForm {
    name: String,
    csrf_token: String,
}
async fn ui_create_identity(
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
async fn ui_rename_identity(
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
async fn ui_delete_identity(
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
async fn ui_rename_agent(
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

async fn ui_add_integration(
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

async fn ui_delete_integration(
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

async fn ui_disconnect_integration(
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

async fn ui_revoke_token(
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

async fn ui_revoke_client(
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

async fn ui_revoke_grant(
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

async fn ui_grant_integration(
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
struct Authorize {
    #[serde(default = "response_code")]
    response_type: String,
    client_id: String,
    redirect_uri: String,
    state: String,
    code_challenge: String,
    #[serde(default = "challenge_s256")]
    code_challenge_method: String,
    #[serde(default = "scope_mcp")]
    scope: String,
    resource: String,
}

#[derive(Serialize, Deserialize)]
struct ConsentRequest {
    response_type: String,
    client_id: String,
    redirect_uri: String,
    state: String,
    code_challenge: String,
    code_challenge_method: String,
    requested_scope: String,
    resource: String,
    user: String,
    allowed_identity_ids: Vec<String>,
    fixed_identity_id: Option<String>,
    expires_at: i64,
    #[serde(default)]
    git_pending_ids: Vec<String>,
}

#[derive(Deserialize)]
struct ConsentForm {
    consent: String,
    csrf_token: String,
    decision: String,
    #[serde(flatten)]
    fields: HashMap<String, String>,
}
fn response_code() -> String {
    "code".into()
}
fn challenge_s256() -> String {
    "S256".into()
}
fn scope_mcp() -> String {
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

fn permission_copy(scope: &str, integration_name: Option<&str>) -> (String, String) {
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

fn selected_scopes(requested: &str, fields: &HashMap<String, String>) -> String {
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

async fn authorize_consent(
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
async fn authorize_post(
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
enum CallbackDelivery {
    NotSent,
    Delivered,
    Indeterminate,
}

/// Delivers an already-durable authorization response without proxies,
/// redirects, credentials, cookies, or response-body buffering. `NotSent` is
/// returned only when cog can prove no callback bytes left this process.
async fn deliver_loopback_callback(url: &url::Url) -> CallbackDelivery {
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
enum AuthFailure {
    Missing,
    Invalid,
    Insufficient,
    Internal,
}

#[derive(Clone)]
struct AuthContext {
    user: String,
    agent: String,
    client: String,
    identity: String,
    scopes: HashSet<String>,
    integrations: HashSet<String>,
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

    fn allows_integration(&self, integration_id: &str) -> bool {
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

fn scoped_user(a: &App, h: &HeaderMap, scope: &str) -> Result<String, AuthFailure> {
    let context = auth_context(a, h)?;
    if !context.allows(scope) {
        return Err(AuthFailure::Insufficient);
    }
    Ok(context.user)
}

fn auth_failure(a: &App, failure: AuthFailure, scope: &str) -> axum::response::Response {
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

fn git_auth_failure(failure: AuthFailure) -> axum::response::Response {
    if matches!(failure, AuthFailure::Internal) {
        return StatusCode::INTERNAL_SERVER_ERROR.into_response();
    }
    let status = if matches!(failure, AuthFailure::Insufficient) {
        StatusCode::FORBIDDEN
    } else {
        StatusCode::UNAUTHORIZED
    };
    (
        status,
        [(http::header::WWW_AUTHENTICATE, "Basic realm=\"cog-git\"")],
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
async fn catalog(a: &App, auth: &AuthContext) -> anyhow::Result<Catalog> {
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
    if req.method == "tools/call"
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
    true
}

fn native_admin_scope(tool: &str) -> Option<&'static str> {
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
async fn list_integrations(State(a): State<App>, h: HeaderMap) -> impl IntoResponse {
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
async fn get_integration(
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

async fn list_agent_clients(State(a): State<App>, headers: HeaderMap) -> impl IntoResponse {
    let user = match scoped_user(&a, &headers, "agents:read") {
        Ok(user) => user,
        Err(failure) => return auth_failure(&a, failure, "agents:read"),
    };
    match a.db.agent_clients(&user) {
        Ok(clients) => Json(json!(clients)).into_response(),
        Err(error) => (StatusCode::INTERNAL_SERVER_ERROR, error.to_string()).into_response(),
    }
}

async fn list_agent_tokens(State(a): State<App>, headers: HeaderMap) -> impl IntoResponse {
    let user = match scoped_user(&a, &headers, "agents:read") {
        Ok(user) => user,
        Err(failure) => return auth_failure(&a, failure, "agents:read"),
    };
    match a.db.agent_tokens(&user) {
        Ok(tokens) => Json(json!(tokens)).into_response(),
        Err(error) => (StatusCode::INTERNAL_SERVER_ERROR, error.to_string()).into_response(),
    }
}

async fn revoke_agent_client(
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

async fn revoke_agent_grant(
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

async fn revoke_agent_token(
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
struct AuditQuery {
    #[serde(default = "default_audit_limit")]
    limit: u32,
}

fn default_audit_limit() -> u32 {
    100
}

async fn list_audit_events(
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

fn validate_policy(config: &Value) -> anyhow::Result<()> {
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

fn validate_transport(
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

fn validate_oauth_uri(uri: &url::Url, label: &str) -> anyhow::Result<()> {
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

fn github_app_install_url(slug: &str) -> anyhow::Result<String> {
    anyhow::ensure!(
        !slug.is_empty()
            && slug
                .bytes()
                .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || byte == b'-'),
        "GitHub returned an invalid App slug"
    );
    Ok(format!("https://github.com/apps/{slug}/installations/new"))
}

async fn admin_github_app_setup_start(a: &App, user: &str, args: Value) -> anyhow::Result<Value> {
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

async fn admin_github_app_setup_status(a: &App, user: &str, id: &str) -> anyhow::Result<Value> {
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
    let response = match client
        .post(format!(
            "https://api.github.com/app-manifests/{}/conversions",
            encoded_code
        ))
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

async fn admin_authorize(a: &App, user: &str, id: &str) -> anyhow::Result<Value> {
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

async fn reconnect_integration(
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

async fn disconnect_integration(
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

async fn delete_integration(
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

fn well_known(base: &url::Url, name: &str) -> anyhow::Result<url::Url> {
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

async fn authorization_server_metadata(
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

async fn resolve_upstream_client(
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

fn open_secret_text(a: &App, ciphertext: &str) -> anyhow::Result<String> {
    Ok(String::from_utf8(a.secrets.open(ciphertext)?)?)
}

fn oauth_authorization_value(token_type: &str, access_token: &str) -> String {
    // OAuth token type identifiers are case-insensitive (RFC 6749 §7.1), but
    // some protected resources accept only the conventional HTTP spelling.
    let scheme = if token_type.eq_ignore_ascii_case("bearer") {
        "Bearer"
    } else {
        token_type
    };
    format!("{scheme} {access_token}")
}

async fn upstream_authorization(a: &App, integration: &str) -> anyhow::Result<Option<String>> {
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

async fn start_upstream_step_up(
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

async fn upstream_oauth_start(
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
struct UpstreamCallback {
    code: Option<String>,
    state: String,
    error: Option<String>,
    error_description: Option<String>,
    iss: Option<String>,
}
async fn upstream_callback(
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

#[cfg(test)]
mod tests {
    use super::*;
    use axum::{
        Router,
        extract::State,
        routing::{get, post},
    };
    use http_body_util::BodyExt;
    use object_store::memory::InMemory;
    use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
    use tower::ServiceExt;

    #[derive(Clone)]
    struct FakeGitProvider {
        upstream: url::Url,
        authorizations: Arc<std::sync::Mutex<Vec<GitOperation>>>,
    }
    #[async_trait::async_trait]
    impl GitProvider for FakeGitProvider {
        async fn resolve_repository(
            &self,
            reference: &RepositoryReference,
        ) -> anyhow::Result<ResolvedRepository> {
            Ok(ResolvedRepository {
                provider_repository_id: reference.0.clone(),
                display_name: reference.0.clone(),
                upstream_url: self.upstream.clone(),
                metadata: json!({}),
            })
        }
        async fn authorize_upstream(
            &self,
            _: &ResolvedRepository,
            operation: GitOperation,
        ) -> anyhow::Result<UpstreamAuthorization> {
            self.authorizations.lock().unwrap().push(operation);
            Ok(UpstreamAuthorization::Basic {
                username: crate::git::SecretValue::new("provider-user"),
                password: crate::git::SecretValue::new("provider-secret"),
            })
        }
        fn upstream_url(&self, _: &ResolvedRepository) -> anyhow::Result<url::Url> {
            Ok(self.upstream.clone())
        }
    }

    type GitUpstreamCalls = Vec<(String, HeaderMap, Vec<u8>)>;
    #[derive(Clone, Default)]
    struct GitUpstreamFixture(Arc<std::sync::Mutex<GitUpstreamCalls>>);
    async fn fake_git_upstream(
        State(state): State<GitUpstreamFixture>,
        request: Request<Body>,
    ) -> Response {
        let (parts, body) = request.into_parts();
        let call_index = {
            let mut calls = state.0.lock().unwrap();
            let index = calls.len();
            calls.push((parts.uri.to_string(), parts.headers, Vec::new()));
            index
        };
        let bytes = body
            .collect()
            .await
            .map(|body| body.to_bytes().to_vec())
            .unwrap_or_default();
        state.0.lock().unwrap()[call_index].2 = bytes;
        if parts.uri.path().contains("redirect") {
            return (
                StatusCode::FOUND,
                [(header::LOCATION, "https://example.com/")],
            )
                .into_response();
        }
        if parts.uri.path().contains("failure") {
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                "provider-secret oauth-token installation-secret",
            )
                .into_response();
        }
        if parts.uri.path().contains("slow-headers") {
            tokio::time::sleep(Duration::from_secs(2)).await;
        }
        if parts.uri.path().contains("slow-body") {
            let body = Body::from_stream(async_stream::stream! {
                yield Ok::<_, std::io::Error>(bytes::Bytes::from_static(b"0008NAK\n"));
                tokio::time::sleep(Duration::from_secs(2)).await;
                yield Ok(bytes::Bytes::from_static(b"0000"));
            });
            return Response::new(body);
        }
        let mut response = Response::new(Body::from("0008NAK\n"));
        response.headers_mut().insert(
            header::CONTENT_TYPE,
            "application/x-git-upload-pack-result".parse().unwrap(),
        );
        response
            .headers_mut()
            .insert(header::SET_COOKIE, "secret=value".parse().unwrap());
        response
    }

    #[test]
    fn client_stream_limit_is_isolated_and_permits_release_on_drop() {
        let limiter = Arc::new(ClientStreamLimiter::default());
        let first = limiter.try_acquire("client-a", 1).unwrap();
        assert!(limiter.try_acquire("client-a", 1).is_none());
        let other = limiter.try_acquire("client-b", 1).unwrap();
        drop(first);
        assert!(limiter.try_acquire("client-a", 1).is_some());
        drop(other);
        assert!(limiter.active.lock().unwrap().get("client-b").is_none());
    }

    #[tokio::test]
    async fn git_proxy_is_provider_neutral_filters_headers_and_authorizes_before_io() {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let fixture = GitUpstreamFixture::default();
        let server = tokio::spawn(
            axum::serve(
                listener,
                Router::new()
                    .route("/{*path}", axum::routing::any(fake_git_upstream))
                    .with_state(fixture.clone()),
            )
            .into_future(),
        );
        let (app, _directory) = route_test_app().await;
        let user = app.db.create_user("git-proxy@example.com", "hash").unwrap();
        app.db
            .register_client(
                "git-client",
                Some(&user),
                "git client",
                &["http://localhost/cb".into()],
            )
            .unwrap();
        let integration = app
            .db
            .create_integration(&user, "fake git", "git", &json!({"kind":"git"}), None)
            .unwrap();
        let resolved = ResolvedRepository {
            provider_repository_id: "repo-1".into(),
            display_name: "owner/repo".into(),
            upstream_url: format!("http://{address}/owner/repo").parse().unwrap(),
            metadata: json!({}),
        };
        let repository = app
            .db
            .upsert_git_repository(&user, &integration, &resolved)
            .unwrap();
        let mcp_oauth = "oauth-secret";
        app.db
            .store_access_token(
                &token_hash(mcp_oauth),
                "git-client",
                &user,
                &format!("mcp git:write integration:{integration}"),
                chrono::Utc::now().timestamp() + 300,
                None,
                None,
            )
            .unwrap();
        let oauth: &'static str = Box::leak({
            app.db
                .set_git_grant(&user, "git-client", &repository.id, "write")
                .unwrap();
            app.db
                .issue_git_credential(&user, "git-client", &repository.id, "write", 900)
                .unwrap()
                .into_boxed_str()
        });
        let authorizations = Arc::new(std::sync::Mutex::new(Vec::new()));
        app.git_providers.lock().await.insert(
            integration.clone(),
            Arc::new(FakeGitProvider {
                upstream: resolved.upstream_url.clone(),
                authorizations: authorizations.clone(),
            }),
        );
        let router = build_router(app.clone());
        let request = |token: &str, endpoint: &str, service: Option<&str>, body: &'static str| {
            let suffix = service.map(|v| format!("?service={v}")).unwrap_or_default();
            Request::builder()
                .method(if endpoint == "info/refs" {
                    "GET"
                } else {
                    "POST"
                })
                .uri(format!("/git/{}.git/{endpoint}{suffix}", repository.id))
                .header(header::AUTHORIZATION, format!("Bearer {token}"))
                .header("git-protocol", "version=2")
                .header("x-forbidden", "drop-me")
                .body(Body::from(body))
                .unwrap()
        };
        let missing = router
            .clone()
            .oneshot(
                Request::builder()
                    .uri(format!(
                        "/git/{}.git/info/refs?service=git-upload-pack",
                        repository.id
                    ))
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(missing.status(), StatusCode::UNAUTHORIZED);
        assert_eq!(
            missing.headers()[header::WWW_AUTHENTICATE],
            "Basic realm=\"cog-git\""
        );
        let read = router
            .clone()
            .oneshot(request(oauth, "info/refs", Some("git-upload-pack"), ""))
            .await
            .unwrap();
        assert_eq!(read.status(), StatusCode::OK);
        assert!(read.headers().get(header::SET_COOKIE).is_none());
        read.into_body().collect().await.unwrap();
        let write = router
            .clone()
            .oneshot(request(oauth, "git-receive-pack", None, "push-body"))
            .await
            .unwrap();
        assert_eq!(write.status(), StatusCode::OK);
        write.into_body().collect().await.unwrap();
        {
            let calls = fixture.0.lock().unwrap();
            assert_eq!(calls.len(), 2);
            assert_eq!(calls[1].2, b"push-body");
            assert_eq!(calls[1].1["git-protocol"], "version=2");
            assert!(calls[1].1.get("x-forbidden").is_none());
            assert!(
                calls[1].1[header::AUTHORIZATION]
                    .to_str()
                    .unwrap()
                    .starts_with("Basic ")
            );
        }
        assert_eq!(
            *authorizations.lock().unwrap(),
            vec![GitOperation::Read, GitOperation::Write]
        );
        app.db
            .register_client(
                "other-client",
                Some(&user),
                "other",
                &["http://localhost/other".into()],
            )
            .unwrap();
        let other = "other-oauth";
        app.db
            .store_access_token(
                &token_hash(other),
                "other-client",
                &user,
                "mcp",
                chrono::Utc::now().timestamp() + 300,
                None,
                None,
            )
            .unwrap();
        let before = fixture.0.lock().unwrap().len();
        let wrong_client = router
            .clone()
            .oneshot(request(other, "git-upload-pack", None, "fetch"))
            .await
            .unwrap();
        assert_eq!(wrong_client.status(), StatusCode::UNAUTHORIZED);
        assert_eq!(fixture.0.lock().unwrap().len(), before);

        app.db
            .update_integration(&integration, &user, None, None, Some(false), None)
            .unwrap();
        let disabled = router
            .clone()
            .oneshot(request(oauth, "git-upload-pack", None, "fetch"))
            .await
            .unwrap();
        assert_eq!(disabled.status(), StatusCode::UNAUTHORIZED);
        assert_eq!(fixture.0.lock().unwrap().len(), before);
        app.db
            .update_integration(&integration, &user, None, None, Some(true), None)
            .unwrap();

        app.git_providers.lock().await.insert(
            integration.clone(),
            Arc::new(FakeGitProvider {
                upstream: format!("http://{address}/redirect").parse().unwrap(),
                authorizations: authorizations.clone(),
            }),
        );
        let redirected = router
            .clone()
            .oneshot(request(oauth, "git-upload-pack", None, "fetch"))
            .await
            .unwrap();
        assert_eq!(redirected.status(), StatusCode::BAD_GATEWAY);

        app.git_providers.lock().await.insert(
            integration.clone(),
            Arc::new(FakeGitProvider {
                upstream: format!("http://{address}/failure").parse().unwrap(),
                authorizations: authorizations.clone(),
            }),
        );
        let failed = router
            .clone()
            .oneshot(request(oauth, "git-upload-pack", None, "fetch"))
            .await
            .unwrap();
        assert_eq!(failed.status(), StatusCode::BAD_GATEWAY);
        let failure_body = failed.into_body().collect().await.unwrap().to_bytes();
        let failure_text = String::from_utf8_lossy(&failure_body);
        assert!(failure_text.contains("provider rejected"));
        assert!(!failure_text.contains("provider-secret"));

        let unused = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let unused_address = unused.local_addr().unwrap();
        drop(unused);
        app.git_providers.lock().await.insert(
            integration.clone(),
            Arc::new(FakeGitProvider {
                upstream: format!("http://{unused_address}/unavailable")
                    .parse()
                    .unwrap(),
                authorizations: authorizations.clone(),
            }),
        );
        let unavailable = router
            .clone()
            .oneshot(request(oauth, "git-upload-pack", None, "fetch"))
            .await
            .unwrap();
        assert_eq!(unavailable.status(), StatusCode::BAD_GATEWAY);

        app.git_providers.lock().await.insert(
            integration.clone(),
            Arc::new(FakeGitProvider {
                upstream: format!("http://{address}/slow-headers").parse().unwrap(),
                authorizations: authorizations.clone(),
            }),
        );
        let mut timeout_app = app.clone();
        timeout_app.config.git_timeout_secs = 1;
        let timed_out = build_router(timeout_app)
            .oneshot(request(oauth, "git-upload-pack", None, "fetch"))
            .await
            .unwrap();
        assert_eq!(timed_out.status(), StatusCode::BAD_GATEWAY);

        app.git_providers.lock().await.insert(
            integration.clone(),
            Arc::new(FakeGitProvider {
                upstream: format!("http://{address}/slow-body").parse().unwrap(),
                authorizations: authorizations.clone(),
            }),
        );
        let mut duration_app = app.clone();
        duration_app.config.git_timeout_secs = 1;
        let duration_limited = build_router(duration_app)
            .oneshot(request(oauth, "git-upload-pack", None, "fetch"))
            .await
            .unwrap();
        assert_eq!(duration_limited.status(), StatusCode::OK);
        assert!(duration_limited.into_body().collect().await.is_err());

        let mut limited_app = app.clone();
        limited_app.config.git_max_request_bytes = 3;
        let limited = build_router(limited_app)
            .oneshot(request(oauth, "git-receive-pack", None, "oversized"))
            .await
            .unwrap();
        assert_eq!(limited.status(), StatusCode::PAYLOAD_TOO_LARGE);

        // Response limits are enforced while streaming and release both stream
        // permits when the downstream observes the terminal body error.
        app.git_providers.lock().await.insert(
            integration.clone(),
            Arc::new(FakeGitProvider {
                upstream: resolved.upstream_url.clone(),
                authorizations: authorizations.clone(),
            }),
        );
        let mut response_limited_app = app.clone();
        response_limited_app.config.git_max_response_bytes = 3;
        let response_limited = build_router(response_limited_app)
            .oneshot(request(oauth, "git-upload-pack", None, "fetch"))
            .await
            .unwrap();
        assert_eq!(response_limited.status(), StatusCode::OK);
        assert!(response_limited.into_body().collect().await.is_err());

        let mut cancellation_app = app.clone();
        cancellation_app.config.git_max_streams_per_client = 1;
        let cancellation_router = build_router(cancellation_app);
        let abandoned = cancellation_router
            .clone()
            .oneshot(request(oauth, "git-upload-pack", None, "fetch"))
            .await
            .unwrap();
        let backpressured = cancellation_router
            .clone()
            .oneshot(request(oauth, "git-upload-pack", None, "fetch"))
            .await
            .unwrap();
        assert_eq!(backpressured.status(), StatusCode::TOO_MANY_REQUESTS);
        drop(abandoned);
        let after_cancellation = cancellation_router
            .oneshot(request(oauth, "git-upload-pack", None, "fetch"))
            .await
            .unwrap();
        assert_eq!(after_cancellation.status(), StatusCode::OK);
        after_cancellation.into_body().collect().await.unwrap();

        // A request body that fails after the first push chunk is sent exactly
        // once. The gateway never retries a non-idempotent receive-pack.
        let calls_before_partial = fixture.0.lock().unwrap().len();
        let partial_body = Body::from_stream(async_stream::stream! {
            yield Ok::<_, std::io::Error>(bytes::Bytes::from_static(b"first-push-chunk"));
            tokio::time::sleep(Duration::from_millis(50)).await;
            yield Err(std::io::Error::new(
                std::io::ErrorKind::ConnectionReset,
                "downstream cancelled",
            ));
        });
        let partial = Request::builder()
            .method("POST")
            .uri(format!("/git/{}.git/git-receive-pack", repository.id))
            .header(header::AUTHORIZATION, format!("Bearer {oauth}"))
            .body(partial_body)
            .unwrap();
        let partial_response = router.clone().oneshot(partial).await.unwrap();
        let _ = partial_response.into_body().collect().await;
        tokio::time::sleep(Duration::from_millis(20)).await;
        assert_eq!(fixture.0.lock().unwrap().len(), calls_before_partial + 1);

        // Missing provider credentials fail before any provider network call.
        app.git_providers.lock().await.remove(&integration);
        let before_disconnected = fixture.0.lock().unwrap().len();
        let disconnected = router
            .clone()
            .oneshot(request(oauth, "git-upload-pack", None, "fetch"))
            .await
            .unwrap();
        assert_eq!(disconnected.status(), StatusCode::BAD_GATEWAY);
        assert_eq!(fixture.0.lock().unwrap().len(), before_disconnected);
        app.git_providers.lock().await.insert(
            integration.clone(),
            Arc::new(FakeGitProvider {
                upstream: resolved.upstream_url.clone(),
                authorizations: authorizations.clone(),
            }),
        );

        // Expired OAuth access is rejected before repository/provider lookup.
        let expired = "expired-oauth";
        app.db
            .store_access_token(
                &token_hash(expired),
                "git-client",
                &user,
                &format!("mcp git:write integration:{integration}"),
                chrono::Utc::now().timestamp() - 1,
                None,
                None,
            )
            .unwrap();
        let before_expired = fixture.0.lock().unwrap().len();
        let expired_response = router
            .clone()
            .oneshot(request(expired, "git-upload-pack", None, "fetch"))
            .await
            .unwrap();
        assert_eq!(expired_response.status(), StatusCode::UNAUTHORIZED);
        assert_eq!(fixture.0.lock().unwrap().len(), before_expired);

        let control = GitControlProvider {
            app: app.clone(),
            auth: AuthContext {
                user: user.clone(),
                agent: "test-agent".into(),
                identity: "test-identity".into(),
                client: "git-client".into(),
                scopes: HashSet::from([format!("integration:{integration}")]),
                integrations: HashSet::from([integration.clone()]),
            },
        };
        let tools = control.tools().await.unwrap();
        assert_eq!(tools.len(), 2);
        assert!(tools.iter().any(|tool| tool.name == "repository_access"));
        assert!(tools.iter().any(|tool| tool.name == "sealed_credentials"));
        let allowed = control
            .call(
                "repository_access",
                json!({"integrationId":integration,"repository":"owner/pending"}),
            )
            .await
            .unwrap();
        let pending_repo = app
            .db
            .git_repository_by_provider(&user, &integration, "owner/pending")
            .unwrap()
            .unwrap();
        assert!(
            allowed["remoteUrl"]
                .as_str()
                .unwrap()
                .contains(&pending_repo.id)
        );
        assert_eq!(allowed["credential"]["source"], "sealed_credentials");
        assert_eq!(
            app.db
                .git_grant_permission(&user, "git-client", &pending_repo.id)
                .unwrap()
                .as_deref(),
            Some("write")
        );
        let (recipient_secret, recipient_public_key) = crate::git::sealed::new_recipient();
        let sealed_request = crate::git::sealed::SealedCredentialRequest {
            repository_id: pending_repo.id.clone(),
            recipient_public_key,
            request_nonce: crate::crypto::random_token(32),
        };
        let sealed = control
            .call(
                "sealed_credentials",
                serde_json::to_value(&sealed_request).unwrap(),
            )
            .await
            .unwrap();
        let visible = serde_json::to_string(&sealed).unwrap();
        assert!(!visible.contains("password"));
        assert!(!visible.contains("cog_git_"));
        let payload =
            crate::git::sealed::open(&serde_json::from_value(sealed).unwrap(), &recipient_secret)
                .unwrap();
        assert_eq!(payload.repository_id, pending_repo.id);
        assert!(payload.password.starts_with("cog_git_"));
        assert!(control.call("unknown", json!({})).await.is_err());
        if let Authority::S3(lease) = &app.lease {
            lease.relinquish().await.unwrap();
        }
        let stale = router
            .oneshot(request(oauth, "git-upload-pack", None, "fetch"))
            .await
            .unwrap();
        assert_eq!(stale.status(), StatusCode::SERVICE_UNAVAILABLE);
        let stale_control = GitControlProvider {
            app: app.clone(),
            auth: AuthContext {
                user: user.clone(),
                agent: "test-agent".into(),
                identity: "test-identity".into(),
                client: "git-client".into(),
                scopes: HashSet::from([format!("integration:{integration}")]),
                integrations: HashSet::from([integration.clone()]),
            },
        };
        assert!(
            stale_control
                .call(
                    "repository_access",
                    json!({"integrationId":integration,"repository":"owner/repo"})
                )
                .await
                .is_err()
        );
        server.abort();
    }

    #[derive(Clone)]
    struct GitHttpBackendFixture {
        project_root: std::path::PathBuf,
        protocol_v2: Arc<AtomicBool>,
    }

    async fn git_http_backend(
        State(state): State<GitHttpBackendFixture>,
        request: Request<Body>,
    ) -> Response {
        let (parts, body) = request.into_parts();
        let body = match body.collect().await {
            Ok(body) => body.to_bytes(),
            Err(_) => return StatusCode::BAD_REQUEST.into_response(),
        };
        let method = parts.method.to_string();
        let path = parts.uri.path().to_owned();
        let query = parts.uri.query().unwrap_or_default().to_owned();
        let content_type = parts
            .headers
            .get(header::CONTENT_TYPE)
            .and_then(|value| value.to_str().ok())
            .unwrap_or_default()
            .to_owned();
        let git_protocol = parts
            .headers
            .get("git-protocol")
            .and_then(|value| value.to_str().ok())
            .map(str::to_owned);
        if git_protocol.as_deref() == Some("version=2") {
            state.protocol_v2.store(true, Ordering::SeqCst);
        }
        let root = state.project_root;
        let output = tokio::task::spawn_blocking(move || {
            let mut command = std::process::Command::new("git");
            command
                .arg("http-backend")
                .env("GIT_PROJECT_ROOT", root)
                .env("GIT_HTTP_EXPORT_ALL", "1")
                .env("REQUEST_METHOD", method)
                .env("PATH_INFO", path)
                .env("QUERY_STRING", query)
                .env("CONTENT_TYPE", content_type)
                .env("CONTENT_LENGTH", body.len().to_string())
                .stdin(std::process::Stdio::piped())
                .stdout(std::process::Stdio::piped());
            if let Some(protocol) = git_protocol {
                command.env("HTTP_GIT_PROTOCOL", protocol);
            }
            let mut child = command.spawn()?;
            use std::io::Write;
            child.stdin.take().unwrap().write_all(&body)?;
            child.wait_with_output()
        })
        .await;
        let Ok(Ok(output)) = output else {
            return StatusCode::BAD_GATEWAY.into_response();
        };
        if !output.status.success() {
            return StatusCode::BAD_GATEWAY.into_response();
        }
        let Some(split) = output
            .stdout
            .windows(4)
            .position(|window| window == b"\r\n\r\n")
        else {
            return StatusCode::BAD_GATEWAY.into_response();
        };
        let raw_headers = &output.stdout[..split];
        let payload = output.stdout[split + 4..].to_vec();
        let mut response = Response::new(Body::from(payload));
        for line in String::from_utf8_lossy(raw_headers).lines() {
            let Some((name, value)) = line.split_once(": ") else {
                continue;
            };
            if name.eq_ignore_ascii_case("status") {
                if let Some(code) = value.split_whitespace().next().and_then(|v| v.parse().ok()) {
                    *response.status_mut() = StatusCode::from_u16(code).unwrap();
                }
            } else if let (Ok(name), Ok(value)) = (
                http::HeaderName::from_bytes(name.as_bytes()),
                http::HeaderValue::from_str(value),
            ) {
                response.headers_mut().append(name, value);
            }
        }
        response
    }

    fn git(directory: &std::path::Path, arguments: &[&str]) {
        git_with_bearer(directory, arguments, None)
    }

    fn git_with_bearer(directory: &std::path::Path, arguments: &[&str], bearer: Option<&str>) {
        let mut command = std::process::Command::new("git");
        if let Some(token) = bearer {
            command
                .arg("-c")
                .arg(format!("http.extraHeader=Authorization: Bearer {token}"));
        }
        let output = command
            .args(arguments)
            .current_dir(directory)
            .env("GIT_AUTHOR_NAME", "Cog Test")
            .env("GIT_AUTHOR_EMAIL", "cog@example.test")
            .env("GIT_COMMITTER_NAME", "Cog Test")
            .env("GIT_COMMITTER_EMAIL", "cog@example.test")
            .env("GIT_TERMINAL_PROMPT", "0")
            .output()
            .unwrap();
        assert!(
            output.status.success(),
            "git {arguments:?} failed: {}",
            String::from_utf8_lossy(&output.stderr)
        );
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn real_git_clone_fetch_pull_push_and_set_upstream_use_smart_http_v2() {
        if std::process::Command::new("git")
            .arg("--version")
            .output()
            .is_err()
        {
            return;
        }
        let directory = tempfile::tempdir().unwrap();
        let bare = directory.path().join("owner/repo.git");
        std::fs::create_dir_all(bare.parent().unwrap()).unwrap();
        git(
            directory.path(),
            &["init", "--bare", bare.to_str().unwrap()],
        );
        let seed = directory.path().join("seed");
        git(directory.path(), &["init", seed.to_str().unwrap()]);
        std::fs::write(seed.join("README.md"), "initial\n").unwrap();
        git(&seed, &["add", "README.md"]);
        git(&seed, &["commit", "-m", "initial"]);
        git(&seed, &["branch", "-M", "main"]);
        git(&seed, &["remote", "add", "origin", bare.to_str().unwrap()]);
        git(&seed, &["push", "origin", "main"]);
        git(&bare, &["symbolic-ref", "HEAD", "refs/heads/main"]);
        git(&bare, &["config", "http.receivepack", "true"]);

        let backend_listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let backend_address = backend_listener.local_addr().unwrap();
        let protocol_v2 = Arc::new(AtomicBool::new(false));
        let backend = tokio::spawn(
            axum::serve(
                backend_listener,
                Router::new()
                    .route("/{*path}", axum::routing::any(git_http_backend))
                    .with_state(GitHttpBackendFixture {
                        project_root: directory.path().to_path_buf(),
                        protocol_v2: protocol_v2.clone(),
                    }),
            )
            .into_future(),
        );

        let (app, _app_directory) = route_test_app().await;
        let user = app.db.create_user("real-git@example.com", "hash").unwrap();
        app.db
            .register_client(
                "real-git",
                Some(&user),
                "git",
                &["http://localhost/cb".into()],
            )
            .unwrap();
        let integration = app
            .db
            .create_integration(&user, "git", "git", &json!({"kind":"git"}), None)
            .unwrap();
        let resolved = ResolvedRepository {
            provider_repository_id: "fixture-repo".into(),
            display_name: "owner/repo".into(),
            upstream_url: format!("http://{backend_address}/owner/repo")
                .parse()
                .unwrap(),
            metadata: json!({}),
        };
        let repository = app
            .db
            .upsert_git_repository(&user, &integration, &resolved)
            .unwrap();
        let mcp_oauth = "real-git-oauth";
        app.db
            .store_access_token(
                &token_hash(mcp_oauth),
                "real-git",
                &user,
                &format!("mcp git:write integration:{integration}"),
                chrono::Utc::now().timestamp() + 300,
                None,
                None,
            )
            .unwrap();
        app.db
            .set_git_grant(&user, "real-git", &repository.id, "write")
            .unwrap();
        let oauth = app
            .db
            .issue_git_credential(&user, "real-git", &repository.id, "write", 900)
            .unwrap();
        app.git_providers.lock().await.insert(
            integration,
            Arc::new(FakeGitProvider {
                upstream: resolved.upstream_url,
                authorizations: Default::default(),
            }),
        );
        let gateway_listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let gateway_address = gateway_listener.local_addr().unwrap();
        let gateway = tokio::spawn(
            axum::serve(gateway_listener, build_router(app).into_make_service()).into_future(),
        );
        let remote = format!("http://{gateway_address}/git/{}.git", repository.id);
        let clone = directory.path().join("clone");
        git_with_bearer(
            directory.path(),
            &[
                "-c",
                "protocol.version=2",
                "clone",
                &remote,
                clone.to_str().unwrap(),
            ],
            Some(&oauth),
        );
        let fallback = directory.path().join("fallback-clone");
        git_with_bearer(
            directory.path(),
            &[
                "-c",
                "protocol.version=0",
                "clone",
                &remote,
                fallback.to_str().unwrap(),
            ],
            Some(&oauth),
        );
        assert!(fallback.join("README.md").exists());
        std::fs::write(clone.join("from-clone.txt"), "push\n").unwrap();
        git(&clone, &["add", "from-clone.txt"]);
        git(&clone, &["commit", "-m", "push"]);
        git(&clone, &["checkout", "-b", "fixture-branch"]);
        git_with_bearer(
            &clone,
            &["push", "--set-upstream", "origin", "fixture-branch"],
            Some(&oauth),
        );
        git(&clone, &["checkout", "main"]);
        git(&clone, &["reset", "--hard", "origin/main"]);
        std::fs::write(seed.join("README.md"), "initial\nupstream\n").unwrap();
        git(&seed, &["add", "README.md"]);
        git(&seed, &["commit", "-m", "upstream"]);
        git(&seed, &["push", "origin", "main"]);
        git_with_bearer(&clone, &["fetch", "origin"], Some(&oauth));
        std::fs::write(seed.join("README.md"), "initial\nupstream\npull\n").unwrap();
        git(&seed, &["add", "README.md"]);
        git(&seed, &["commit", "-m", "pull"]);
        git(&seed, &["push", "origin", "main"]);
        git_with_bearer(
            &clone,
            &["pull", "--ff-only", "origin", "main"],
            Some(&oauth),
        );
        assert!(protocol_v2.load(Ordering::SeqCst));
        gateway.abort();
        backend.abort();
    }

    struct PolicyFixture;
    #[async_trait::async_trait]
    impl ToolProvider for PolicyFixture {
        async fn tools(&self) -> anyhow::Result<Vec<Tool>> {
            Ok(["read", "write"]
                .into_iter()
                .map(|name| Tool {
                    name: name.into(),
                    description: None,
                    input_schema: json!({}),
                    extra: Default::default(),
                })
                .collect())
        }
        async fn call(&self, name: &str, _args: Value) -> anyhow::Result<Value> {
            Ok(json!(name))
        }
    }

    struct FailingFixture;
    #[async_trait::async_trait]
    impl ToolProvider for FailingFixture {
        async fn tools(&self) -> anyhow::Result<Vec<Tool>> {
            anyhow::bail!("expected tools failure")
        }
        async fn call(&self, _name: &str, _args: Value) -> anyhow::Result<Value> {
            anyhow::bail!("expected call failure")
        }
        async fn close(&self) -> anyhow::Result<()> {
            anyhow::bail!("expected close failure")
        }
    }

    struct ScopeChallengeFixture {
        challenge: UpstreamInsufficientScope,
    }
    #[async_trait::async_trait]
    impl ToolProvider for ScopeChallengeFixture {
        async fn tools(&self) -> anyhow::Result<Vec<Tool>> {
            Ok(vec![Tool {
                name: "search".into(),
                description: Some("Search provider operations".into()),
                input_schema: json!({"type":"object"}),
                extra: Default::default(),
            }])
        }
        async fn call(&self, _name: &str, _args: Value) -> anyhow::Result<Value> {
            Err(self.challenge.clone().into())
        }
    }

    #[derive(Clone)]
    struct OAuthFixture {
        base: String,
        refreshes: Arc<AtomicUsize>,
        client_metadata: Arc<AtomicBool>,
    }

    async fn resource(State(state): State<OAuthFixture>) -> Json<Value> {
        Json(json!({
            "resource": format!("{}/mcp", state.base),
            "authorization_servers":[state.base.as_str()]
        }))
    }

    async fn authorization_metadata(State(state): State<OAuthFixture>) -> Json<Value> {
        Json(json!({
            "issuer":state.base.as_str(),
            "authorization_endpoint":format!("{}/authorize",state.base),
            "token_endpoint":format!("{}/token",state.base),
            "registration_endpoint":format!("{}/register",state.base),
            "code_challenge_methods_supported":["S256"],
            "client_id_metadata_document_supported":state.client_metadata.load(Ordering::SeqCst)
        }))
    }

    async fn dynamic_registration(body: axum::body::Bytes) -> Json<Value> {
        let request: Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(request["token_endpoint_auth_method"], "client_secret_post");
        Json(json!({"client_id":"dynamic-client","client_secret":"dynamic-secret"}))
    }

    async fn refresh_token(State(state): State<OAuthFixture>, body: String) -> Json<Value> {
        assert!(body.contains("grant_type=refresh_token"));
        assert!(body.contains("refresh_token=old-refresh"));
        assert!(body.contains("client_secret=dynamic-secret"));
        let resource_values: Vec<_> = url::form_urlencoded::parse(body.as_bytes())
            .filter(|(name, _)| name == "resource")
            .map(|(_, value)| value.into_owned())
            .collect();
        assert_eq!(resource_values, vec![format!("{}/mcp", state.base)]);
        assert!(!body.contains("scope="));
        state.refreshes.fetch_add(1, Ordering::SeqCst);
        Json(json!({
            "access_token":"new-access",
            "refresh_token":"new-refresh",
            "token_type":"Bearer",
            "scope":"mcp",
            "expires_in":3600,
            "refresh_expires_in":7200
        }))
    }

    #[tokio::test]
    async fn upstream_authorization_discovery_falls_back_to_oidc() {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let state = OAuthFixture {
            base: format!("http://{address}"),
            refreshes: Arc::new(AtomicUsize::new(0)),
            client_metadata: Arc::new(AtomicBool::new(true)),
        };
        let server = tokio::spawn(
            axum::serve(
                listener,
                Router::new()
                    .route(
                        "/.well-known/openid-configuration",
                        get(authorization_metadata),
                    )
                    .with_state(state.clone()),
            )
            .into_future(),
        );
        let metadata =
            authorization_server_metadata(&reqwest::Client::new(), &state.base.parse().unwrap())
                .await
                .unwrap();
        assert_eq!(metadata["issuer"], state.base);
        assert_eq!(metadata["client_id_metadata_document_supported"], true);
        server.abort();
    }

    #[tokio::test]
    async fn upstream_discovery_dcr_and_refresh_rotation() {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let state = OAuthFixture {
            base: format!("http://{address}"),
            refreshes: Arc::new(AtomicUsize::new(0)),
            client_metadata: Arc::new(AtomicBool::new(false)),
        };
        let server = tokio::spawn(
            axum::serve(
                listener,
                Router::new()
                    .route("/.well-known/oauth-protected-resource/mcp", get(resource))
                    .route(
                        "/.well-known/oauth-authorization-server",
                        get(authorization_metadata),
                    )
                    .route("/register", post(dynamic_registration))
                    .route("/token", post(refresh_token))
                    .with_state(state.clone()),
            )
            .into_future(),
        );

        let directory = tempfile::tempdir().unwrap();
        let store: Arc<dyn ObjectStore> = Arc::new(InMemory::new());
        let lease = LeaseGuard::acquire(
            store.clone(),
            ObjectPath::from("lease"),
            Duration::from_secs(30),
        )
        .await
        .unwrap();
        let db_path = directory.path().join("cog.sqlite");
        let db = Database::open(&db_path).unwrap();
        let replicator = Arc::new(Replicator::new(
            store,
            "app/".into(),
            db_path,
            lease.generation(),
        ));
        replicator.sync().await.unwrap();
        let app = App {
            config: Config {
                listen: "127.0.0.1:0".parse().unwrap(),
                base_url: "http://localhost:4788".parse().unwrap(),
                data_dir: directory.path().to_path_buf(),
                s3_bucket: Some("test".into()),
                s3_prefix: "app/".into(),
                s3_endpoint: None,
                s3_region: "us-east-1".into(),
                s3_allow_http: true,
                master_key: "0123456789abcdef0123456789abcdef".into(),
                lease_ttl_secs: 30,
                v8_heap_mb: 16,
                execution_timeout_secs: 1,
                allow_stdio: false,
                git_max_request_bytes: 1024 * 1024,
                git_max_response_bytes: 1024 * 1024,
                git_timeout_secs: 30,
                git_idle_timeout_secs: 10,
                git_max_streams: 4,
                git_max_streams_per_client: 2,
                server_local_callbacks: crate::config::ServerLocalCallbacks::Off,
            },
            db: db.clone(),
            secrets: SecretBox::new(b"0123456789abcdef0123456789abcdef"),
            runtime: Arc::new(CodeRuntime::new(16, Duration::from_secs(1))),
            lease: Authority::S3(lease),
            replicator: Durability::S3(replicator),
            providers: Arc::new(tokio::sync::Mutex::new(HashMap::new())),
            metrics: Arc::new(Metrics::default()),
            mutations: Arc::new(tokio::sync::Mutex::new(())),
            auth_rate_limit: Arc::new(RateLimiter::default()),
            git_providers: Arc::new(tokio::sync::Mutex::new(HashMap::new())),
            git_streams: Arc::new(tokio::sync::Semaphore::new(4)),
            git_client_streams: Arc::new(ClientStreamLimiter::default()),
        };
        let user = db.create_user("owner@example.com", "hash").unwrap();
        let missing = auth_failure(&app, AuthFailure::Missing, "mcp");
        assert_eq!(missing.status(), StatusCode::UNAUTHORIZED);
        assert!(
            missing.headers()[http::header::WWW_AUTHENTICATE]
                .to_str()
                .unwrap()
                .contains("resource_metadata=")
        );
        db.register_client(
            "test-client",
            Some(&user),
            "test",
            &["http://localhost/callback".into()],
        )
        .unwrap();
        db.store_access_token(
            &token_hash("admin-token"),
            "test-client",
            &user,
            "admin",
            chrono::Utc::now().timestamp() + 60,
            None,
            None,
        )
        .unwrap();
        let mut auth_headers = HeaderMap::new();
        auth_headers.insert(
            http::header::AUTHORIZATION,
            "Bearer admin-token".parse().unwrap(),
        );
        assert_eq!(scoped_user(&app, &auth_headers, "mcp").unwrap(), user);
        let integration_id = db
            .create_integration(
                &user,
                "remote",
                "http",
                &json!({"url":format!("{}/mcp",state.base),"oauth":{}}),
                None,
            )
            .unwrap();
        let integration = db.integration(&integration_id, &user).unwrap().unwrap();
        let client = resolve_upstream_client(&app, &integration).await.unwrap();
        assert_eq!(client.client_id, "dynamic-client");
        assert_eq!(client.issuer.as_deref(), Some(state.base.as_str()));
        // Cloudflare's MCP metadata has this shape: PKCE endpoints, but no
        // scopes_supported. An unconfigured scope must remain absent rather
        // than silently becoming the invalid `mcp` scope.
        assert!(client.scope.is_empty());
        let expected_resource = format!("{}/mcp", state.base);
        assert_eq!(client.resource.as_deref(), Some(expected_resource.as_str()));
        assert_ne!(
            client.client_secret_ciphertext.as_deref(),
            Some("dynamic-secret")
        );
        state.client_metadata.store(true, Ordering::SeqCst);
        let metadata_integration_id = db
            .create_integration(
                &user,
                "remote metadata client",
                "http",
                &json!({"url":format!("{}/mcp",state.base),"oauth":{}}),
                None,
            )
            .unwrap();
        let metadata_integration = db
            .integration(&metadata_integration_id, &user)
            .unwrap()
            .unwrap();
        let metadata_client = resolve_upstream_client(&app, &metadata_integration)
            .await
            .unwrap();
        assert_eq!(
            metadata_client.client_id,
            "http://localhost:4788/.well-known/oauth-client"
        );
        assert!(metadata_client.client_secret_ciphertext.is_none());
        let start = upstream_oauth_start(
            State(app.clone()),
            Path(integration_id.clone()),
            auth_headers.clone(),
        )
        .await
        .into_response();
        assert_eq!(start.status(), StatusCode::OK);
        let start: Value =
            serde_json::from_slice(&start.into_body().collect().await.unwrap().to_bytes()).unwrap();
        let authorization_url =
            url::Url::parse(start["authorization_url"].as_str().unwrap()).unwrap();
        assert!(
            authorization_url
                .query_pairs()
                .all(|(name, _)| name != "scope")
        );
        let resources: Vec<_> = authorization_url
            .query_pairs()
            .filter(|(name, _)| name == "resource")
            .map(|(_, value)| value.into_owned())
            .collect();
        assert_eq!(resources, vec![format!("{}/mcp", state.base)]);

        db.put_upstream_oauth_token(
            &integration_id,
            &UpstreamOAuthToken {
                access_token_ciphertext: app.secrets.seal(b"expired-access").unwrap(),
                refresh_token_ciphertext: Some(app.secrets.seal(b"old-refresh").unwrap()),
                token_type: "Bearer".into(),
                scope: "mcp".into(),
                expires_at: Some(chrono::Utc::now().timestamp() - 1),
                refresh_expires_at: Some(chrono::Utc::now().timestamp() + 60),
            },
        )
        .unwrap();
        assert_eq!(
            upstream_authorization(&app, &integration_id)
                .await
                .unwrap()
                .as_deref(),
            Some("Bearer new-access")
        );
        assert_eq!(state.refreshes.load(Ordering::SeqCst), 1);
        let rotated = db.upstream_oauth_token(&integration_id).unwrap().unwrap();
        assert_eq!(
            open_secret_text(&app, &rotated.refresh_token_ciphertext.unwrap()).unwrap(),
            "new-refresh"
        );
        server.abort();
    }

    #[tokio::test]
    async fn local_callback_rejects_non_literal_loopback_and_falls_back_only_before_writes() {
        for rejected in [
            "http://localhost:1234/cb?code=x&state=y",
            "http://127.0.0.2:1234/cb?code=x&state=y",
            "http://2130706433:1234/cb?code=x&state=y",
            "http://user@127.0.0.1:1234/cb?code=x&state=y",
            "http://127.0.0.1:1234/cb?code=x&state=y#fragment",
            "https://127.0.0.1:1234/cb?code=x&state=y",
        ] {
            assert_eq!(
                deliver_loopback_callback(&url::Url::parse(rejected).unwrap()).await,
                CallbackDelivery::NotSent
            );
        }
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        drop(listener);
        let refused = url::Url::parse(&format!(
            "http://{address}/callback?code=secret&state=opaque"
        ))
        .unwrap();
        assert_eq!(
            deliver_loopback_callback(&refused).await,
            CallbackDelivery::NotSent
        );
    }

    #[tokio::test]
    async fn local_callback_sends_no_credentials_and_does_not_follow_redirects() {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let receiver = tokio::spawn(async move {
            let (mut stream, _) = listener.accept().await.unwrap();
            let mut request = Vec::new();
            loop {
                let mut chunk = [0_u8; 512];
                let read = stream.read(&mut chunk).await.unwrap();
                if read == 0 {
                    break;
                }
                request.extend_from_slice(&chunk[..read]);
                if request.windows(4).any(|window| window == b"\r\n\r\n") {
                    break;
                }
            }
            stream
                .write_all(b"HTTP/1.1 204 No Content\r\nLocation: http://example.com/evil\r\nContent-Length: 999999\r\n\r\n")
                .await
                .unwrap();
            String::from_utf8(request).unwrap()
        });
        let callback = url::Url::parse(&format!(
            "http://{address}/callback?existing=1&code=secret&state=opaque"
        ))
        .unwrap();
        assert_eq!(
            deliver_loopback_callback(&callback).await,
            CallbackDelivery::Delivered
        );
        let request = receiver.await.unwrap();
        assert!(request.starts_with("GET /callback?existing=1&code=secret&state=opaque HTTP/1.1"));
        assert!(!request.to_ascii_lowercase().contains("authorization:"));
        assert!(!request.to_ascii_lowercase().contains("cookie:"));
    }

    async fn route_test_app() -> (App, tempfile::TempDir) {
        let directory = tempfile::tempdir().unwrap();
        let store: Arc<dyn ObjectStore> = Arc::new(InMemory::new());
        let lease = LeaseGuard::acquire(
            store.clone(),
            ObjectPath::from("route-test-lease"),
            Duration::from_secs(30),
        )
        .await
        .unwrap();
        let db_path = directory.path().join("cog.sqlite");
        let db = Database::open(&db_path).unwrap();
        let replicator = Arc::new(Replicator::new(
            store,
            "routes/".into(),
            db_path,
            lease.generation(),
        ));
        replicator.sync().await.unwrap();
        (
            App {
                config: Config {
                    listen: "127.0.0.1:0".parse().unwrap(),
                    base_url: "http://localhost:4788".parse().unwrap(),
                    data_dir: directory.path().to_path_buf(),
                    s3_bucket: Some("test".into()),
                    s3_prefix: "routes/".into(),
                    s3_endpoint: None,
                    s3_region: "us-east-1".into(),
                    s3_allow_http: true,
                    master_key: "0123456789abcdef0123456789abcdef".into(),
                    lease_ttl_secs: 30,
                    v8_heap_mb: 16,
                    execution_timeout_secs: 1,
                    allow_stdio: false,
                    git_max_request_bytes: 1024 * 1024,
                    git_max_response_bytes: 1024 * 1024,
                    git_timeout_secs: 30,
                    git_idle_timeout_secs: 10,
                    git_max_streams: 4,
                    git_max_streams_per_client: 2,
                    server_local_callbacks: crate::config::ServerLocalCallbacks::Off,
                },
                db,
                secrets: SecretBox::new(b"0123456789abcdef0123456789abcdef"),
                runtime: Arc::new(CodeRuntime::new(16, Duration::from_secs(1))),
                lease: Authority::S3(lease),
                replicator: Durability::S3(replicator),
                providers: Arc::new(tokio::sync::Mutex::new(HashMap::new())),
                metrics: Arc::new(Metrics::default()),
                mutations: Arc::new(tokio::sync::Mutex::new(())),
                auth_rate_limit: Arc::new(RateLimiter::default()),
                git_providers: Arc::new(tokio::sync::Mutex::new(HashMap::new())),
                git_streams: Arc::new(tokio::sync::Semaphore::new(4)),
                git_client_streams: Arc::new(ClientStreamLimiter::default()),
            },
            directory,
        )
    }

    fn encoded_form(pairs: &[(&str, &str)]) -> String {
        let mut serializer = url::form_urlencoded::Serializer::new(String::new());
        serializer.extend_pairs(pairs.iter().copied());
        serializer.finish()
    }

    async fn response_json(response: axum::response::Response) -> Value {
        let bytes = response.into_body().collect().await.unwrap().to_bytes();
        serde_json::from_slice(&bytes).unwrap()
    }

    async fn response_text(response: axum::response::Response) -> String {
        String::from_utf8(
            response
                .into_body()
                .collect()
                .await
                .unwrap()
                .to_bytes()
                .to_vec(),
        )
        .unwrap()
    }

    #[tokio::test]
    async fn github_manifest_setup_returns_browser_handoff_and_pending_repository_result() {
        let (app, _directory) = route_test_app().await;
        let user = app
            .db
            .create_user("github-manifest@example.com", "hash")
            .unwrap();
        let started = admin_github_app_setup_start(&app, &user, json!({"name":"GitHub"}))
            .await
            .unwrap();
        let integration = started["id"].as_str().unwrap();
        assert_eq!(started["status"], "manifest_pending");
        let browser_url = url::Url::parse(started["browserUrl"].as_str().unwrap()).unwrap();
        let response = build_router(app.clone())
            .oneshot(
                Request::builder()
                    .uri(browser_url.path())
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        let page = response_text(response).await;
        assert!(page.contains("https://github.com/settings/apps/new"));
        assert!(page.contains("github/app/manifest/callback&quot;"));
        assert!(page.contains("settings/apps/new?state="));
        assert!(page.contains("github/app/installation/callback?state="));
        assert!(page.contains("&quot;contents&quot;:&quot;write&quot;"));
        assert!(page.contains("&quot;workflows&quot;:&quot;write&quot;"));
        assert!(!page.contains("&quot;hook_attributes&quot;"));
        assert!(!page.contains("privateKey"));

        let status = admin_github_app_setup_status(&app, &user, integration)
            .await
            .unwrap();
        assert_eq!(status["status"], "manifest_pending");
        assert_eq!(status["credentialsConfigured"], false);
        let control = GitControlProvider {
            app: app.clone(),
            auth: AuthContext {
                user,
                agent: "test-agent".into(),
                identity: "test-identity".into(),
                client: "manifest-client".into(),
                scopes: HashSet::from([format!("integration:{integration}")]),
                integrations: HashSet::from([integration.to_owned()]),
            },
        };
        let result = control
            .call(
                "repository_access",
                json!({"integrationId":integration,"repository":"asselstine/cog"}),
            )
            .await
            .unwrap();
        assert_eq!(result["error"], "github_app_installation_required");
        assert_eq!(result["action"], "completeGitHubSetupThenRetry");
    }

    #[test]
    fn consent_selection_is_least_privilege_and_cannot_add_scopes() {
        let mut selected = HashMap::new();
        selected.insert("scope_2".into(), "on".into());
        selected.insert("scope_99".into(), "on".into());
        assert_eq!(
            selected_scopes("mcp integrations:read integrations:write", &selected),
            "mcp integrations:write"
        );
        assert_eq!(selected_scopes("mcp admin", &HashMap::new()), "mcp");
    }

    #[test]
    fn progressive_consent_preserves_prior_grants_and_adds_selected_integration() {
        let requested = "mcp audit:read integration:cloudflare";
        let fields = HashMap::from([
            ("scope_1".to_owned(), "on".to_owned()),
            ("scope_2".to_owned(), "on".to_owned()),
        ]);
        assert_eq!(
            selected_scopes(requested, &fields),
            "mcp audit:read integration:cloudflare"
        );
    }

    #[tokio::test]
    async fn route_flow_covers_metadata_consent_tokens_mcp_and_admin_scopes() {
        let (mut app, _directory) = route_test_app().await;
        app.config.allow_stdio = true;
        let salt = SaltString::generate(&mut OsRng);
        let hash = Argon2::default()
            .hash_password(b"long-test-password", &salt)
            .unwrap()
            .to_string();
        let owner = app.db.create_user("owner@example.com", &hash).unwrap();
        let integration = app
            .db
            .create_integration(
                &owner,
                "metadata fixture",
                "stdio",
                &json!({
                    "command":"sh",
                    "args":[format!("{}/tests/fixtures/stdio-mcp.sh", env!("CARGO_MANIFEST_DIR"))]
                }),
                None,
            )
            .unwrap();
        let router = build_router(app.clone());
        let origin = "http://localhost:4788";

        for path in [
            "/.well-known/oauth-authorization-server",
            "/.well-known/oauth-protected-resource",
            "/.well-known/oauth-client",
        ] {
            let response = router
                .clone()
                .oneshot(
                    axum::http::Request::get(path)
                        .body(axum::body::Body::empty())
                        .unwrap(),
                )
                .await
                .unwrap();
            assert_eq!(response.status(), StatusCode::OK);
            let metadata = response_json(response).await;
            assert!(metadata.is_object());
            if path == "/.well-known/oauth-protected-resource" {
                assert_eq!(
                    metadata["scopes_supported"],
                    json!(["mcp", "git:read", "git:write"])
                );
            } else if path == "/.well-known/oauth-client" {
                assert_eq!(
                    metadata["client_id"],
                    "http://localhost:4788/.well-known/oauth-client"
                );
                assert_eq!(
                    metadata["redirect_uris"],
                    json!(["http://localhost:4788/oauth/upstream/callback"])
                );
            }
        }

        let registration = router
            .clone()
            .oneshot(
                axum::http::Request::post("/oauth/register")
                    .header(http::header::CONTENT_TYPE, "application/json")
                    .body(axum::body::Body::from(
                        json!({"client_name":"route fixture","redirect_uris":["http://localhost/callback"]}).to_string(),
                    ))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(registration.status(), StatusCode::CREATED);
        let client_id = response_json(registration).await["client_id"]
            .as_str()
            .unwrap()
            .to_owned();
        let oauth_repository = app
            .db
            .upsert_git_repository(
                &owner,
                &integration,
                &ResolvedRepository {
                    provider_repository_id: "oauth-repository".into(),
                    display_name: "owner/oauth-repository".into(),
                    upstream_url: "https://github.com/owner/oauth-repository.git"
                        .parse()
                        .unwrap(),
                    metadata: json!({}),
                },
            )
            .unwrap();
        let identity = app.db.list_identities(&owner).unwrap()[0].id.clone();
        app.db.bind_agent(&owner, &identity, &client_id).unwrap();
        app.db
            .create_git_pending_request(
                &owner,
                &client_id,
                &integration,
                &oauth_repository.id,
                "read",
                600,
            )
            .unwrap();

        let login_response = router
            .clone()
            .oneshot(
                axum::http::Request::post("/login")
                    .header(http::header::ORIGIN, origin)
                    .header(
                        http::header::CONTENT_TYPE,
                        "application/x-www-form-urlencoded",
                    )
                    .body(axum::body::Body::from(encoded_form(&[
                        ("email", "owner@example.com"),
                        ("password", "long-test-password"),
                    ])))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert!(login_response.status().is_redirection());
        let cookies = login_response
            .headers()
            .get_all(http::header::SET_COOKIE)
            .iter()
            .map(|value| {
                value
                    .to_str()
                    .unwrap()
                    .split(';')
                    .next()
                    .unwrap()
                    .to_owned()
            })
            .collect::<Vec<_>>();
        assert_eq!(cookies.len(), 2);
        let cookie_header = cookies.join("; ");
        let csrf = cookies
            .iter()
            .find_map(|cookie| cookie.strip_prefix("cog_csrf="))
            .unwrap()
            .to_owned();
        let verifier = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789-._~";
        use base64::Engine;
        use sha2::Digest;
        let challenge = base64::engine::general_purpose::URL_SAFE_NO_PAD
            .encode(sha2::Sha256::digest(verifier.as_bytes()));
        let query = encoded_form(&[
            ("response_type", "code"),
            ("client_id", &client_id),
            ("redirect_uri", "http://localhost/callback"),
            ("state", "route-state"),
            ("code_challenge", &challenge),
            ("code_challenge_method", "S256"),
            ("scope", "mcp admin git:read"),
            ("resource", "http://localhost:4788/mcp"),
        ]);
        let consent = router
            .clone()
            .oneshot(
                axum::http::Request::get(format!("/oauth/authorize?{query}"))
                    .header(http::header::COOKIE, &cookie_header)
                    .body(axum::body::Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(consent.status(), StatusCode::OK);
        let consent_page = response_text(consent).await;
        assert!(consent_page.starts_with("<!doctype html>"));
        assert!(!consent_page.contains("Any grant change affects every agent"));
        let consent = router
            .clone()
            .oneshot(
                axum::http::Request::get(format!("/api/oauth/consent?{query}"))
                    .header(http::header::COOKIE, &cookie_header)
                    .body(axum::body::Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(consent.status(), StatusCode::OK);
        assert_eq!(consent.headers()[http::header::CACHE_CONTROL], "no-store");
        let consent_data = response_json(consent).await;
        assert_eq!(consent_data["client"]["name"], "route fixture");
        assert_eq!(
            consent_data["permissionGroups"][0]["title"],
            "Newly requested"
        );
        assert!(
            consent_data["permissionGroups"]
                .as_array()
                .unwrap()
                .iter()
                .any(|group| group["title"] == "Other available permissions")
        );
        assert!(
            consent_data["permissionGroups"]
                .as_array()
                .unwrap()
                .iter()
                .flat_map(|group| group["permissions"].as_array().unwrap())
                .any(|permission| permission["label"] == "Legacy administrator access")
        );
        let sealed_consent = consent_data["consent"].as_str().unwrap().to_owned();

        let mut tampered = sealed_consent.clone().into_bytes();
        let middle = tampered.len() / 2;
        tampered[middle] = if tampered[middle] == b'A' { b'B' } else { b'A' };
        let tampered = String::from_utf8(tampered).unwrap();
        let rejected = router
            .clone()
            .oneshot(
                axum::http::Request::post("/api/oauth/consent")
                    .header(http::header::ORIGIN, origin)
                    .header(http::header::COOKIE, &cookie_header)
                    .header(
                        http::header::CONTENT_TYPE,
                        "application/x-www-form-urlencoded",
                    )
                    .body(axum::body::Body::from(encoded_form(&[
                        ("consent", &tampered),
                        ("csrf_token", &csrf),
                        ("decision", "allow"),
                        ("scope_99", "on"),
                    ])))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(rejected.status(), StatusCode::BAD_REQUEST);

        let authorization = router
            .clone()
            .oneshot(
                axum::http::Request::post("/api/oauth/consent")
                    .header(http::header::ORIGIN, origin)
                    .header(http::header::COOKIE, &cookie_header)
                    .header(
                        http::header::CONTENT_TYPE,
                        "application/x-www-form-urlencoded",
                    )
                    .body(axum::body::Body::from(encoded_form(&[
                        ("consent", &sealed_consent),
                        ("csrf_token", &csrf),
                        ("decision", "allow"),
                        ("scope_1", "on"),
                        ("scope_2", "on"),
                        ("git_request_0", "on"),
                    ])))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert!(authorization.status().is_redirection());
        let location = authorization.headers()[http::header::LOCATION]
            .to_str()
            .unwrap();
        let code = url::Url::parse(location)
            .unwrap()
            .query_pairs()
            .find_map(|(key, value)| (key == "code").then(|| value.into_owned()))
            .unwrap();
        let token_response = router
            .clone()
            .oneshot(
                axum::http::Request::post("/oauth/token")
                    .header(
                        http::header::CONTENT_TYPE,
                        "application/x-www-form-urlencoded",
                    )
                    .body(axum::body::Body::from(encoded_form(&[
                        ("grant_type", "authorization_code"),
                        ("code", &code),
                        ("client_id", &client_id),
                        ("redirect_uri", "http://localhost/callback"),
                        ("code_verifier", verifier),
                        ("resource", "http://localhost:4788/mcp"),
                    ])))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(token_response.status(), StatusCode::OK);
        let access = response_json(token_response).await["access_token"]
            .as_str()
            .unwrap()
            .to_owned();
        assert_eq!(
            app.db
                .git_grant_permission(&owner, &client_id, &oauth_repository.id)
                .unwrap()
                .as_deref(),
            Some("read")
        );
        let access_context = app
            .db
            .token_context(&token_hash(&access), chrono::Utc::now().timestamp())
            .unwrap()
            .unwrap();
        assert!(
            access_context
                .scopes
                .iter()
                .any(|scope| scope == "git:read")
        );

        let unauthenticated = router
            .clone()
            .oneshot(
                axum::http::Request::post("/mcp")
                    .header(http::header::CONTENT_TYPE, "application/json")
                    .body(axum::body::Body::from(
                        json!({"jsonrpc":"2.0","id":1,"method":"ping"}).to_string(),
                    ))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(unauthenticated.status(), StatusCode::UNAUTHORIZED);
        assert!(
            unauthenticated.headers()[http::header::WWW_AUTHENTICATE]
                .to_str()
                .unwrap()
                .contains("scope=\"mcp\"")
        );

        let mcp = router
            .clone()
            .oneshot(
                axum::http::Request::post("/mcp")
                    .header(http::header::AUTHORIZATION, format!("Bearer {access}"))
                    .header(http::header::CONTENT_TYPE, "application/json")
                    .body(axum::body::Body::from(
                        json!({"jsonrpc":"2.0","id":2,"method":"tools/list"}).to_string(),
                    ))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(mcp.status(), StatusCode::OK);
        let code_mode_tools = response_json(mcp).await["result"]["tools"]
            .as_array()
            .unwrap()
            .clone();
        assert!(code_mode_tools.iter().any(|tool| tool["name"] == "execute"));

        let direct = router
            .clone()
            .oneshot(
                axum::http::Request::post("/mcp?codemode=false")
                    .header(http::header::AUTHORIZATION, format!("Bearer {access}"))
                    .header(http::header::CONTENT_TYPE, "application/json")
                    .body(axum::body::Body::from(
                        json!({"jsonrpc":"2.0","id":21,"method":"tools/list"}).to_string(),
                    ))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(direct.status(), StatusCode::OK);
        let direct_tools = response_json(direct).await["result"]["tools"]
            .as_array()
            .unwrap()
            .clone();
        assert!(!direct_tools.iter().any(|tool| tool["name"] == "execute"));
        let direct_echo = direct_tools
            .iter()
            .find(|tool| tool["name"] == format!("{integration}.echo"))
            .unwrap();
        assert_eq!(
            direct_echo["securitySchemes"][0]["scopes"],
            json!([format!("integration:{integration}")])
        );

        let malformed_mode = router
            .clone()
            .oneshot(
                axum::http::Request::post("/mcp?codemode=maybe")
                    .header(http::header::AUTHORIZATION, format!("Bearer {access}"))
                    .header(http::header::CONTENT_TYPE, "application/json")
                    .body(axum::body::Body::from(
                        json!({"jsonrpc":"2.0","id":22,"method":"ping"}).to_string(),
                    ))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(malformed_mode.status(), StatusCode::BAD_REQUEST);

        for (header, expected) in [
            (
                ("MCP-Protocol-Version", "2024-11-05"),
                StatusCode::BAD_REQUEST,
            ),
            (
                (http::header::ORIGIN.as_str(), "https://evil.example"),
                StatusCode::FORBIDDEN,
            ),
        ] {
            let rejected = router
                .clone()
                .oneshot(
                    axum::http::Request::post("/mcp")
                        .header(http::header::AUTHORIZATION, format!("Bearer {access}"))
                        .header(http::header::CONTENT_TYPE, "application/json")
                        .header(header.0, header.1)
                        .body(axum::body::Body::from(
                            json!({"jsonrpc":"2.0","id":20,"method":"ping"}).to_string(),
                        ))
                        .unwrap(),
                )
                .await
                .unwrap();
            assert_eq!(rejected.status(), expected);
        }

        app.db
            .store_access_token(
                &token_hash("step-up-token"),
                &client_id,
                &owner,
                "mcp integrations:read",
                chrono::Utc::now().timestamp() + 60,
                None,
                None,
            )
            .unwrap();
        let direct_step_up = router
            .clone()
            .oneshot(
                axum::http::Request::post("/mcp?codemode=false")
                    .header(http::header::AUTHORIZATION, "Bearer step-up-token")
                    .header(http::header::CONTENT_TYPE, "application/json")
                    .body(axum::body::Body::from(
                        json!({
                            "jsonrpc":"2.0",
                            "id":24,
                            "method":"tools/call",
                            "params":{
                                "name":format!("{integration}.echo"),
                                "arguments":{}
                            }
                        })
                        .to_string(),
                    ))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(direct_step_up.status(), StatusCode::OK);
        let direct_step_up = response_json(direct_step_up).await;
        assert_ne!(direct_step_up["result"]["isError"], true);
        assert!(direct_step_up["result"]["structuredContent"]["requiredScopes"].is_null());
        let step_up = router
            .clone()
            .oneshot(
                axum::http::Request::post("/mcp")
                    .header(http::header::AUTHORIZATION, "Bearer step-up-token")
                    .header(http::header::CONTENT_TYPE, "application/json")
                    .body(axum::body::Body::from(
                        json!({
                            "jsonrpc":"2.0",
                            "id":3,
                            "method":"tools/call",
                            "params":{
                                "name":"execute",
                                "arguments":{
                                    "code":format!("return codemode.describe('{integration}.tool');")
                                }
                            }
                        })
                        .to_string(),
                    ))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(step_up.status(), StatusCode::OK);
        let step_up = response_json(step_up).await;
        assert_ne!(step_up["result"]["isError"], true);

        // A capable MCP client accumulates its existing scopes with the scope
        // from the 403 challenge, performs a fresh authorization-code flow,
        // and retries the exact operation with the widened token.
        let elevated_scope = format!("mcp integrations:read integration:{integration}");
        let elevated_query = encoded_form(&[
            ("response_type", "code"),
            ("client_id", &client_id),
            ("redirect_uri", "http://localhost/callback"),
            ("state", "step-up-state"),
            ("code_challenge", &challenge),
            ("code_challenge_method", "S256"),
            ("scope", &elevated_scope),
            ("resource", "http://localhost:4788/mcp"),
        ]);
        let elevated_consent = router
            .clone()
            .oneshot(
                axum::http::Request::get(format!("/api/oauth/consent?{elevated_query}"))
                    .header(http::header::COOKIE, &cookie_header)
                    .body(axum::body::Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(elevated_consent.status(), StatusCode::OK);
        let elevated_data = response_json(elevated_consent).await;
        let groups = elevated_data["permissionGroups"].as_array().unwrap();
        assert_eq!(groups[0]["title"], "Newly requested");
        assert_eq!(groups[1]["title"], "Previously approved");
        assert_eq!(groups[2]["title"], "Other available permissions");
        assert!(
            groups
                .iter()
                .flat_map(|group| group["permissions"].as_array().unwrap())
                .any(|permission| permission["label"] == "Use metadata fixture")
        );
        assert!(groups.iter().flat_map(|group|group["permissions"].as_array().unwrap()).any(|permission|permission["field"]=="scope_1"&&permission["checked"]==true));
        assert!(groups.iter().flat_map(|group|group["permissions"].as_array().unwrap()).any(|permission|permission["field"]=="scope_2"&&permission["checked"]==true));
        let elevated_consent = elevated_data["consent"].as_str().unwrap().to_owned();
        let elevated_authorization = router
            .clone()
            .oneshot(
                axum::http::Request::post("/api/oauth/consent")
                    .header(http::header::ORIGIN, origin)
                    .header(http::header::COOKIE, &cookie_header)
                    .header(
                        http::header::CONTENT_TYPE,
                        "application/x-www-form-urlencoded",
                    )
                    .body(axum::body::Body::from(encoded_form(&[
                        ("consent", &elevated_consent),
                        ("csrf_token", &csrf),
                        ("decision", "allow"),
                        ("scope_1", "on"),
                        ("scope_2", "on"),
                    ])))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert!(elevated_authorization.status().is_redirection());
        let elevated_code = url::Url::parse(
            elevated_authorization.headers()[http::header::LOCATION]
                .to_str()
                .unwrap(),
        )
        .unwrap()
        .query_pairs()
        .find_map(|(key, value)| (key == "code").then(|| value.into_owned()))
        .unwrap();
        let elevated_token = router
            .clone()
            .oneshot(
                axum::http::Request::post("/oauth/token")
                    .header(
                        http::header::CONTENT_TYPE,
                        "application/x-www-form-urlencoded",
                    )
                    .body(axum::body::Body::from(encoded_form(&[
                        ("grant_type", "authorization_code"),
                        ("code", &elevated_code),
                        ("client_id", &client_id),
                        ("redirect_uri", "http://localhost/callback"),
                        ("code_verifier", verifier),
                        ("resource", "http://localhost:4788/mcp"),
                    ])))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(elevated_token.status(), StatusCode::OK);
        let elevated_access = response_json(elevated_token).await["access_token"]
            .as_str()
            .unwrap()
            .to_owned();
        let retried = router
            .clone()
            .oneshot(
                axum::http::Request::post("/mcp")
                    .header(
                        http::header::AUTHORIZATION,
                        format!("Bearer {elevated_access}"),
                    )
                    .header(http::header::CONTENT_TYPE, "application/json")
                    .body(axum::body::Body::from(
                        json!({
                            "jsonrpc":"2.0",
                            "id":3,
                            "method":"tools/call",
                            "params":{
                                "name":"execute",
                                "arguments":{
                                    "code":format!("return codemode.describe('{integration}.echo');")
                                }
                            }
                        })
                        .to_string(),
                    ))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(retried.status(), StatusCode::OK);
        let retried = response_json(retried).await;
        assert_ne!(retried["result"]["isError"], true);
        assert_eq!(retried["result"]["structuredContent"]["name"], "echo");

        let direct_call = router
            .clone()
            .oneshot(
                axum::http::Request::post("/mcp?codemode=false")
                    .header(
                        http::header::AUTHORIZATION,
                        format!("Bearer {elevated_access}"),
                    )
                    .header(http::header::CONTENT_TYPE, "application/json")
                    .body(axum::body::Body::from(
                        json!({
                            "jsonrpc":"2.0",
                            "id":23,
                            "method":"tools/call",
                            "params":{
                                "name":format!("{integration}.echo"),
                                "arguments":{"message":"direct"}
                            }
                        })
                        .to_string(),
                    ))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(direct_call.status(), StatusCode::OK);
        let direct_call = response_json(direct_call).await;
        assert_ne!(direct_call["result"]["isError"], true);
        assert_eq!(
            direct_call["result"]["structuredContent"],
            json!({"value":42})
        );

        let dynamic_step_up = router
            .clone()
            .oneshot(
                axum::http::Request::post("/mcp")
                    .header(http::header::AUTHORIZATION, "Bearer step-up-token")
                    .header(http::header::CONTENT_TYPE, "application/json")
                    .body(axum::body::Body::from(
                        json!({
                            "jsonrpc":"2.0",
                            "id":4,
                            "method":"tools/call",
                            "params":{
                                "name":"execute",
                                "arguments":{
                                    "code":"const matches = codemode.search('metadata fixture'); return codemode.describe(matches[0].integration + '.tool');"
                                }
                            }
                        })
                        .to_string(),
                    ))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(dynamic_step_up.status(), StatusCode::OK);
        let dynamic_step_up = response_json(dynamic_step_up).await;
        assert_ne!(dynamic_step_up["result"]["isError"], true);
        let admin_step_up = router
            .clone()
            .oneshot(
                axum::http::Request::post("/mcp")
                    .header(http::header::AUTHORIZATION, "Bearer step-up-token")
                    .header(http::header::CONTENT_TYPE, "application/json")
                    .body(axum::body::Body::from(
                        json!({"jsonrpc":"2.0","id":5,"method":"tools/call","params":{"name":"cog_integration_create","arguments":{}}}).to_string(),
                    ))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(admin_step_up.status(), StatusCode::OK);
        let admin_step_up = response_json(admin_step_up).await;
        assert!(admin_step_up.get("error").is_some() || admin_step_up["result"]["isError"] == true);

        // rmcp/Codex sends this as a JSON-RPC notification immediately after
        // initialize. Streamable HTTP requires an empty acknowledgement, not
        // a response with a missing or null id.
        let initialized = router
            .clone()
            .oneshot(
                axum::http::Request::post("/mcp")
                    .header(http::header::AUTHORIZATION, format!("Bearer {access}"))
                    .header(http::header::CONTENT_TYPE, "application/json")
                    .body(axum::body::Body::from(
                        json!({"jsonrpc":"2.0","method":"notifications/initialized"}).to_string(),
                    ))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(initialized.status(), StatusCode::ACCEPTED);
        assert!(
            initialized
                .into_body()
                .collect()
                .await
                .unwrap()
                .to_bytes()
                .is_empty()
        );

        let admin = router
            .clone()
            .oneshot(
                axum::http::Request::get("/api/integrations")
                    .header(http::header::AUTHORIZATION, format!("Bearer {access}"))
                    .body(axum::body::Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(admin.status(), StatusCode::OK);

        for path in ["/", "/healthz", "/readyz", "/version", "/metrics", "/login"] {
            let response = router
                .clone()
                .oneshot(
                    axum::http::Request::get(path)
                        .header(http::header::COOKIE, &cookie_header)
                        .body(axum::body::Body::empty())
                        .unwrap(),
                )
                .await
                .unwrap();
            assert_eq!(response.status(), StatusCode::OK, "{path}");
        }

        let created = router
            .clone()
            .oneshot(
                axum::http::Request::post("/api/integrations")
                    .header(http::header::AUTHORIZATION, format!("Bearer {access}"))
                    .header(http::header::CONTENT_TYPE, "application/json")
                    .body(axum::body::Body::from(
                        json!({"name":"fixture","transport":"http","config":{"url":"http://localhost:9999/mcp"}}).to_string(),
                    ))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(created.status(), StatusCode::CREATED);
        let integration_id = response_json(created).await["id"]
            .as_str()
            .unwrap()
            .to_owned();

        let inspected = router
            .clone()
            .oneshot(
                axum::http::Request::get(format!("/api/integrations/{integration_id}"))
                    .header(http::header::AUTHORIZATION, format!("Bearer {access}"))
                    .body(axum::body::Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(inspected.status(), StatusCode::OK);
        assert_eq!(response_json(inspected).await["name"], "fixture");

        let updated = router
            .clone()
            .oneshot(
                axum::http::Request::patch(format!("/api/integrations/{integration_id}"))
                    .header(http::header::AUTHORIZATION, format!("Bearer {access}"))
                    .header(http::header::CONTENT_TYPE, "application/json")
                    .body(axum::body::Body::from(
                        json!({"name":"renamed","enabled":false}).to_string(),
                    ))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(updated.status(), StatusCode::NO_CONTENT);

        let reconnected = router
            .clone()
            .oneshot(
                axum::http::Request::post(format!("/api/integrations/{integration_id}/reconnect"))
                    .header(http::header::AUTHORIZATION, format!("Bearer {access}"))
                    .body(axum::body::Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(reconnected.status(), StatusCode::NO_CONTENT);

        for path in ["/api/clients", "/api/tokens", "/api/audit"] {
            let response = router
                .clone()
                .oneshot(
                    axum::http::Request::get(path)
                        .header(http::header::AUTHORIZATION, format!("Bearer {access}"))
                        .body(axum::body::Body::empty())
                        .unwrap(),
                )
                .await
                .unwrap();
            assert_eq!(response.status(), StatusCode::OK, "{path}");
            assert!(response_json(response).await.is_array());
        }

        let ui = router
            .clone()
            .oneshot(
                axum::http::Request::get("/ui")
                    .header(http::header::COOKIE, &cookie_header)
                    .body(axum::body::Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(ui.status(), StatusCode::OK);

        let deleted = router
            .clone()
            .oneshot(
                axum::http::Request::delete(format!("/api/integrations/{integration_id}"))
                    .header(http::header::AUTHORIZATION, format!("Bearer {access}"))
                    .body(axum::body::Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(deleted.status(), StatusCode::NO_CONTENT);

        let logout_response = router
            .oneshot(
                axum::http::Request::post("/logout")
                    .header(http::header::ORIGIN, origin)
                    .header(http::header::COOKIE, &cookie_header)
                    .header(
                        http::header::CONTENT_TYPE,
                        "application/x-www-form-urlencoded",
                    )
                    .body(axum::body::Body::from(encoded_form(&[(
                        "csrf_token",
                        &csrf,
                    )])))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert!(logout_response.status().is_redirection());
        assert_eq!(
            logout_response
                .headers()
                .get_all(http::header::SET_COOKIE)
                .iter()
                .count(),
            2
        );
    }

    #[tokio::test]
    async fn administration_ui_revocation_and_upstream_callback_routes() {
        let (app, _directory) = route_test_app().await;
        let user = app.db.create_user("admin@example.com", "hash").unwrap();
        let session = "browser-session";
        let csrf = "browser-csrf";
        app.db
            .create_session(
                &token_hash(session),
                &user,
                &token_hash(csrf),
                chrono::Utc::now().timestamp() + 3600,
            )
            .unwrap();
        app.db
            .register_client(
                "admin-client",
                Some(&user),
                "admin",
                &["http://localhost/callback".into()],
            )
            .unwrap();
        app.db
            .store_access_token(
                &token_hash("admin-access"),
                "admin-client",
                &user,
                "mcp admin",
                chrono::Utc::now().timestamp() + 3600,
                None,
                None,
            )
            .unwrap();
        for client in [
            "api-target",
            "ui-target",
            "api-client-target",
            "ui-token-target",
        ] {
            app.db
                .register_client(
                    client,
                    Some(&user),
                    client,
                    &["http://localhost/callback".into()],
                )
                .unwrap();
            app.db
                .store_access_token(
                    &token_hash(&format!("{client}-access")),
                    client,
                    &user,
                    "mcp",
                    chrono::Utc::now().timestamp() + 3600,
                    None,
                    None,
                )
                .unwrap();
        }
        app.replicator.sync().await.unwrap();
        let router = build_router(app.clone());
        let origin = "http://localhost:4788";
        let cookies = format!("cog_session={session}; cog_csrf={csrf}");

        let unauthenticated = router
            .clone()
            .oneshot(
                axum::http::Request::get("/ui")
                    .body(axum::body::Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert!(unauthenticated.status().is_redirection());
        let ui = router
            .clone()
            .oneshot(
                axum::http::Request::get("/ui")
                    .header(http::header::COOKIE, &cookies)
                    .body(axum::body::Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(ui.status(), StatusCode::OK);

        let add = router
            .clone()
            .oneshot(
                axum::http::Request::post("/ui/integrations")
                    .header(http::header::ORIGIN, origin)
                    .header(http::header::COOKIE, &cookies)
                    .header(
                        http::header::CONTENT_TYPE,
                        "application/x-www-form-urlencoded",
                    )
                    .body(axum::body::Body::from(encoded_form(&[
                        ("name", "ui-http"),
                        ("url", "http://localhost:9999/mcp"),
                        ("csrf_token", csrf),
                    ])))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert!(add.status().is_redirection());
        let ui_integration = app
            .db
            .list_integrations(&user)
            .unwrap()
            .into_iter()
            .find(|integration| integration.name == "ui-http")
            .unwrap();
        let delete = router
            .clone()
            .oneshot(
                axum::http::Request::post(format!("/ui/integrations/{}/delete", ui_integration.id))
                    .header(http::header::ORIGIN, origin)
                    .header(http::header::COOKIE, &cookies)
                    .header(
                        http::header::CONTENT_TYPE,
                        "application/x-www-form-urlencoded",
                    )
                    .body(axum::body::Body::from(encoded_form(&[(
                        "csrf_token",
                        csrf,
                    )])))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert!(delete.status().is_redirection());

        let tokens = app.db.agent_tokens(&user).unwrap();
        let api_token = tokens
            .iter()
            .find(|token| token.client_id == "api-target")
            .unwrap();
        let revoked = router
            .clone()
            .oneshot(
                axum::http::Request::delete(format!("/api/tokens/{}", api_token.token_id))
                    .header(http::header::AUTHORIZATION, "Bearer admin-access")
                    .body(axum::body::Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(revoked.status(), StatusCode::NO_CONTENT);
        let revoked = router
            .clone()
            .oneshot(
                axum::http::Request::post(format!("/ui/clients/{}/revoke", "ui-target"))
                    .header(http::header::ORIGIN, origin)
                    .header(http::header::COOKIE, &cookies)
                    .header(
                        http::header::CONTENT_TYPE,
                        "application/x-www-form-urlencoded",
                    )
                    .body(axum::body::Body::from(encoded_form(&[(
                        "csrf_token",
                        csrf,
                    )])))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert!(revoked.status().is_redirection());

        let revoked = router
            .clone()
            .oneshot(
                axum::http::Request::delete("/api/clients/api-client-target")
                    .header(http::header::AUTHORIZATION, "Bearer admin-access")
                    .body(axum::body::Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(revoked.status(), StatusCode::NO_CONTENT);
        let ui_token = app
            .db
            .agent_tokens(&user)
            .unwrap()
            .into_iter()
            .find(|token| token.client_id == "ui-token-target")
            .unwrap();
        let revoked = router
            .clone()
            .oneshot(
                axum::http::Request::post(format!("/ui/tokens/{}/revoke", ui_token.token_id))
                    .header(http::header::ORIGIN, origin)
                    .header(http::header::COOKIE, &cookies)
                    .header(
                        http::header::CONTENT_TYPE,
                        "application/x-www-form-urlencoded",
                    )
                    .body(axum::body::Body::from(encoded_form(&[(
                        "csrf_token",
                        csrf,
                    )])))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert!(revoked.status().is_redirection());

        let token_listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let token_address = token_listener.local_addr().unwrap();
        let token_server = tokio::spawn(
            axum::serve(
                token_listener,
                Router::new().route(
                    "/token",
                    post(|body: String| async move {
                        let resources: Vec<_> = url::form_urlencoded::parse(body.as_bytes())
                            .filter(|(name, _)| name == "resource")
                            .map(|(_, value)| value.into_owned())
                            .collect();
                        assert_eq!(resources, vec!["http://127.0.0.1:9999/mcp"]);
                        Json(json!({
                            "access_token":"connected-access",
                            "refresh_token":"connected-refresh",
                            "token_type":"Bearer",
                            "scope":"mcp",
                            "expires_in":3600
                        }))
                    }),
                ),
            )
            .into_future(),
        );
        let oauth_id = app
            .db
            .create_integration(
                &user,
                "oauth-http",
                "http",
                &json!({
                    "url":"http://localhost:9999/mcp",
                    "oauth":{
                        "authorization_endpoint":format!("http://{token_address}/authorize"),
                        "token_endpoint":format!("http://{token_address}/token"),
                        "client_id":"configured-client",
                        "scope":"mcp",
                        "resource":"http://127.0.0.1:9999/mcp"
                    }
                }),
                None,
            )
            .unwrap();
        let pending_ui = router
            .clone()
            .oneshot(
                axum::http::Request::get("/api/ui")
                    .header(http::header::COOKIE, &cookies)
                    .body(axum::body::Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert!(
            String::from_utf8(
                pending_ui
                    .into_body()
                    .collect()
                    .await
                    .unwrap()
                    .to_bytes()
                    .to_vec()
            )
            .unwrap()
            .contains("connection required")
        );
        let started = router
            .clone()
            .oneshot(
                axum::http::Request::post(format!("/api/integrations/{oauth_id}/oauth/start"))
                    .header(http::header::AUTHORIZATION, "Bearer admin-access")
                    .body(axum::body::Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(started.status(), StatusCode::OK);
        let authorization_url = response_json(started).await["authorization_url"]
            .as_str()
            .unwrap()
            .to_owned();
        let state = url::Url::parse(&authorization_url)
            .unwrap()
            .query_pairs()
            .find_map(|(key, value)| (key == "state").then(|| value.into_owned()))
            .unwrap();
        let callback = router
            .clone()
            .oneshot(
                axum::http::Request::get(format!(
                    "/oauth/upstream/callback?code=test-code&state={state}"
                ))
                .body(axum::body::Body::empty())
                .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(callback.status(), StatusCode::OK);
        assert!(app.db.upstream_oauth_token(&oauth_id).unwrap().is_some());
        let connected_ui = router
            .clone()
            .oneshot(
                axum::http::Request::get("/api/ui")
                    .header(http::header::COOKIE, &cookies)
                    .body(axum::body::Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        let connected_ui = response_json(connected_ui).await;
        let connected = connected_ui["integrations"]
            .as_array()
            .unwrap()
            .iter()
            .find(|integration| integration["id"] == oauth_id)
            .unwrap();
        assert_eq!(connected["oauth"], "connected");
        assert_eq!(connected["oauth_scopes"], json!(["mcp"]));
        token_server.abort();
    }

    async fn request_status(
        router: &Router,
        method: http::Method,
        uri: impl AsRef<str>,
        authorization: Option<&str>,
        content_type: Option<&str>,
        body: impl Into<axum::body::Body>,
    ) -> StatusCode {
        let mut request = axum::http::Request::builder()
            .method(method)
            .uri(uri.as_ref());
        if let Some(value) = authorization {
            request = request.header(http::header::AUTHORIZATION, value);
        }
        if let Some(value) = content_type {
            request = request.header(http::header::CONTENT_TYPE, value);
        }
        router
            .clone()
            .oneshot(request.body(body.into()).unwrap())
            .await
            .unwrap()
            .status()
    }

    #[tokio::test]
    async fn route_validation_authentication_and_not_found_paths() {
        let (app, _directory) = route_test_app().await;
        let user = app
            .db
            .create_user("errors@example.com", "not-a-password-hash")
            .unwrap();
        app.db
            .register_client(
                "limited-client",
                Some(&user),
                "limited",
                &["http://localhost/callback".into()],
            )
            .unwrap();
        app.db
            .store_access_token(
                &token_hash("mcp-only"),
                "limited-client",
                &user,
                "mcp",
                chrono::Utc::now().timestamp() + 3600,
                None,
                None,
            )
            .unwrap();
        app.replicator.sync().await.unwrap();
        let router = build_router(app.clone());

        for path in [
            "/api/integrations",
            "/api/clients",
            "/api/tokens",
            "/api/audit",
        ] {
            assert_eq!(
                request_status(&router, http::Method::GET, path, None, None, "").await,
                StatusCode::UNAUTHORIZED
            );
            assert_eq!(
                request_status(
                    &router,
                    http::Method::GET,
                    path,
                    Some("Bearer unknown"),
                    None,
                    "",
                )
                .await,
                StatusCode::UNAUTHORIZED
            );
            assert_eq!(
                request_status(
                    &router,
                    http::Method::GET,
                    path,
                    Some("Bearer mcp-only"),
                    None,
                    "",
                )
                .await,
                StatusCode::FORBIDDEN
            );
        }

        for (method, path) in [
            (http::Method::GET, "/api/integrations/missing"),
            (http::Method::DELETE, "/api/integrations/missing"),
            (http::Method::POST, "/api/integrations/missing/reconnect"),
            (http::Method::POST, "/api/integrations/missing/oauth/start"),
            (http::Method::DELETE, "/api/clients/missing"),
            (http::Method::DELETE, "/api/tokens/missing"),
        ] {
            assert_eq!(
                request_status(&router, method, path, Some("Bearer mcp-only"), None, "",).await,
                StatusCode::FORBIDDEN
            );
        }

        for registration in [
            json!({"client_name":"bad","redirect_uris":[]}),
            json!({"client_name":"bad","redirect_uris":["https://example.com/cb#fragment"]}),
        ] {
            assert_eq!(
                request_status(
                    &router,
                    http::Method::POST,
                    "/oauth/register",
                    None,
                    Some("application/json"),
                    registration.to_string(),
                )
                .await,
                StatusCode::BAD_REQUEST
            );
        }

        for query in [
            "response_type=token&client_id=limited-client&redirect_uri=http%3A%2F%2Flocalhost%2Fcallback&state=x&code_challenge=x&code_challenge_method=S256",
            "response_type=code&client_id=unknown&redirect_uri=http%3A%2F%2Flocalhost%2Fcallback&state=x&code_challenge=x&code_challenge_method=S256",
            "response_type=code&client_id=limited-client&redirect_uri=http%3A%2F%2Fevil.example%2Fcallback&state=x&code_challenge=x&code_challenge_method=S256",
            "response_type=code&client_id=limited-client&redirect_uri=http%3A%2F%2Flocalhost%2Fcallback&state=x&code_challenge=x&code_challenge_method=S256",
        ] {
            assert!(matches!(
                request_status(
                    &router,
                    http::Method::GET,
                    format!("/api/oauth/consent?{query}"),
                    None,
                    None,
                    "",
                )
                .await,
                StatusCode::BAD_REQUEST | StatusCode::UNAUTHORIZED
            ));
        }

        assert_eq!(
            request_status(
                &router,
                http::Method::POST,
                "/oauth/token",
                None,
                Some("application/x-www-form-urlencoded"),
                encoded_form(&[
                    ("grant_type", "authorization_code"),
                    ("code", "missing"),
                    ("client_id", "limited-client"),
                    ("redirect_uri", "http://localhost/callback"),
                    ("code_verifier", "invalid"),
                ]),
            )
            .await,
            StatusCode::BAD_REQUEST
        );
        for token in ["unknown-token", "mcp-only"] {
            assert_eq!(
                request_status(
                    &router,
                    http::Method::POST,
                    "/oauth/revoke",
                    None,
                    Some("application/x-www-form-urlencoded"),
                    encoded_form(&[("token", token)]),
                )
                .await,
                StatusCode::OK
            );
        }

        app.db
            .store_access_token(
                &token_hash("admin-errors"),
                "limited-client",
                &user,
                "admin",
                chrono::Utc::now().timestamp() + 3600,
                None,
                None,
            )
            .unwrap();
        for body in [
            json!({"name":"bad","transport":"ftp","config":{}}),
            json!({"name":"bad","transport":"http","config":{"url":"ftp://example.com"}}),
            json!({"name":"bad","transport":"http","config":{"url":"https://user:secret@example.com/mcp"}}),
            json!({"name":"bad","transport":"stdio","config":{"command":"echo"}}),
        ] {
            assert_eq!(
                request_status(
                    &router,
                    http::Method::POST,
                    "/api/integrations",
                    Some("Bearer admin-errors"),
                    Some("application/json"),
                    body.to_string(),
                )
                .await,
                StatusCode::BAD_REQUEST
            );
        }

        let forbidden_form = encoded_form(&[("csrf_token", "wrong")]);
        for path in [
            "/logout",
            "/ui/integrations/missing/delete",
            "/ui/tokens/missing/revoke",
            "/ui/clients/missing/revoke",
        ] {
            assert_eq!(
                request_status(
                    &router,
                    http::Method::POST,
                    path,
                    None,
                    Some("application/x-www-form-urlencoded"),
                    forbidden_form.clone(),
                )
                .await,
                StatusCode::FORBIDDEN
            );
        }

        for (method, path, expected) in [
            (
                http::Method::GET,
                "/api/integrations/missing",
                StatusCode::NOT_FOUND,
            ),
            (
                http::Method::PATCH,
                "/api/integrations/missing",
                StatusCode::NOT_FOUND,
            ),
            (
                http::Method::DELETE,
                "/api/integrations/missing",
                StatusCode::NOT_FOUND,
            ),
            (
                http::Method::POST,
                "/api/integrations/missing/reconnect",
                StatusCode::NOT_FOUND,
            ),
            (
                http::Method::POST,
                "/api/integrations/missing/oauth/start",
                StatusCode::NOT_FOUND,
            ),
            (
                http::Method::DELETE,
                "/api/clients/missing",
                StatusCode::NOT_FOUND,
            ),
            (
                http::Method::DELETE,
                "/api/tokens/missing",
                StatusCode::NOT_FOUND,
            ),
        ] {
            assert_eq!(
                request_status(
                    &router,
                    method,
                    path,
                    Some("Bearer admin-errors"),
                    Some("application/json"),
                    "{}"
                )
                .await,
                expected
            );
        }
        for query in [
            "state=missing&error=access_denied",
            "state=missing",
            "state=missing&code=code",
        ] {
            assert_eq!(
                request_status(
                    &router,
                    http::Method::GET,
                    format!("/oauth/upstream/callback?{query}"),
                    None,
                    None,
                    ""
                )
                .await,
                StatusCode::BAD_REQUEST
            );
        }
        assert_eq!(
            request_status(&router, http::Method::POST, "/setup", None, None, "").await,
            StatusCode::NOT_FOUND
        );
        for (origin, email, password, expected) in [
            (None, "errors@example.com", "wrong", StatusCode::FORBIDDEN),
            (
                Some("http://localhost:4788"),
                "missing@example.com",
                "wrong",
                StatusCode::UNAUTHORIZED,
            ),
            (
                Some("http://localhost:4788"),
                "errors@example.com",
                "wrong",
                StatusCode::UNAUTHORIZED,
            ),
        ] {
            let mut request = axum::http::Request::post("/login").header(
                http::header::CONTENT_TYPE,
                "application/x-www-form-urlencoded",
            );
            if let Some(origin) = origin {
                request = request.header(http::header::ORIGIN, origin);
            }
            let response = router
                .clone()
                .oneshot(
                    request
                        .body(axum::body::Body::from(encoded_form(&[
                            ("email", email),
                            ("password", password),
                        ])))
                        .unwrap(),
                )
                .await
                .unwrap();
            assert_eq!(response.status(), expected);
        }

        let session = "error-session";
        let csrf = "error-csrf";
        app.db
            .create_session(
                &token_hash(session),
                &user,
                &token_hash(csrf),
                chrono::Utc::now().timestamp() + 600,
            )
            .unwrap();
        let cookies = format!("cog_session={session}; cog_csrf={csrf}");
        let query = "response_type=code&client_id=limited-client&redirect_uri=http%3A%2F%2Flocalhost%2Fcallback&state=denied&code_challenge=challenge&code_challenge_method=S256&scope=mcp&resource=http%3A%2F%2Flocalhost%3A4788%2Fmcp";
        let consent = router
            .clone()
            .oneshot(
                axum::http::Request::get(format!("/api/oauth/consent?{query}"))
                    .header(http::header::COOKIE, &cookies)
                    .body(axum::body::Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(consent.status(), StatusCode::OK);
        let sealed_consent = response_json(consent).await["consent"]
            .as_str()
            .unwrap()
            .to_owned();
        let denied = router
            .clone()
            .oneshot(
                axum::http::Request::post("/api/oauth/consent")
                    .header(http::header::ORIGIN, "http://localhost:4788")
                    .header(http::header::COOKIE, &cookies)
                    .header(
                        http::header::CONTENT_TYPE,
                        "application/x-www-form-urlencoded",
                    )
                    .body(axum::body::Body::from(encoded_form(&[
                        ("consent", &sealed_consent),
                        ("csrf_token", csrf),
                        ("decision", "deny"),
                    ])))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert!(denied.status().is_redirection());
    }

    #[tokio::test]
    async fn authentication_rate_limit_is_bounded_per_subject() {
        let limiter = RateLimiter::default();
        assert!(limiter.allow("login:a".into(), 2, Duration::from_secs(60)));
        assert!(limiter.allow("login:a".into(), 2, Duration::from_secs(60)));
        assert!(!limiter.allow("login:a".into(), 2, Duration::from_secs(60)));
        assert!(limiter.allow("login:b".into(), 2, Duration::from_secs(60)));
        let (app, _directory) = route_test_app().await;
        for _ in 0..2 {
            assert!(rate_limit(&app, "test", "subject", 2).is_none());
        }
        assert_eq!(
            rate_limit(&app, "test", "subject", 2).unwrap().status(),
            StatusCode::TOO_MANY_REQUESTS
        );
        assert_eq!(
            build_router(app.clone())
                .oneshot(
                    axum::http::Request::get("/")
                        .body(axum::body::Body::empty())
                        .unwrap()
                )
                .await
                .unwrap()
                .status(),
            StatusCode::OK
        );
        let mut endpoint = app.config.clone();
        endpoint.s3_endpoint = Some("http://localhost:9000".into());
        assert!(build_store(&endpoint).is_ok());
    }

    #[tokio::test]
    async fn dynamic_registration_has_global_and_body_limits() {
        let (app, _directory) = route_test_app().await;
        let router = build_router(app);
        for index in 0..20 {
            let response = router
                .clone()
                .oneshot(
                    axum::http::Request::post("/oauth/register")
                        .header(http::header::CONTENT_TYPE, "application/json")
                        .body(axum::body::Body::from(
                            json!({
                                "client_name": format!("client-{index}"),
                                "redirect_uris": [format!("http://localhost/callback/{index}")]
                            })
                            .to_string(),
                        ))
                        .unwrap(),
                )
                .await
                .unwrap();
            assert_eq!(response.status(), StatusCode::CREATED);
        }
        let limited = router
            .clone()
            .oneshot(
                axum::http::Request::post("/oauth/register")
                    .header(http::header::CONTENT_TYPE, "application/json")
                    .body(axum::body::Body::from(
                        json!({
                            "client_name": "one-too-many",
                            "redirect_uris": ["http://localhost/callback/limited"]
                        })
                        .to_string(),
                    ))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(limited.status(), StatusCode::TOO_MANY_REQUESTS);

        let oversized = router
            .oneshot(
                axum::http::Request::post("/oauth/register")
                    .header(http::header::CONTENT_TYPE, "application/json")
                    .body(axum::body::Body::from("x".repeat(32 * 1_024 + 1)))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(oversized.status(), StatusCode::PAYLOAD_TOO_LARGE);
    }

    #[test]
    fn bearer_authorization_uses_conventional_http_scheme_case() {
        assert_eq!(oauth_authorization_value("bearer", "token"), "Bearer token");
        assert_eq!(oauth_authorization_value("BEARER", "token"), "Bearer token");
        assert_eq!(oauth_authorization_value("DPoP", "token"), "DPoP token");
    }

    #[tokio::test]
    async fn instance_credentials_are_refetched_before_expiration() {
        use object_store::aws::AmazonS3Builder;

        let fetches = Arc::new(AtomicU64::new(0));
        let credential_fetches = fetches.clone();
        let metadata = Router::new()
            .route(
                "/latest/api/token",
                axum::routing::put(|| async { "metadata-token" }),
            )
            .route(
                "/latest/meta-data/iam/security-credentials/",
                get(|| async { "cog-role" }),
            )
            .route(
                "/latest/meta-data/iam/security-credentials/cog-role",
                get(move || {
                    let credential_fetches = credential_fetches.clone();
                    async move {
                        let generation = credential_fetches.fetch_add(1, Ordering::SeqCst) + 1;
                        Json(json!({
                            "AccessKeyId": format!("refresh-key-{generation}"),
                            "SecretAccessKey": "refresh-secret",
                            "Token": format!("refresh-token-{generation}"),
                            // The provider's five-minute safety window makes
                            // this credential eligible for refresh immediately.
                            "Expiration": (chrono::Utc::now() + chrono::Duration::seconds(60))
                                .to_rfc3339(),
                        }))
                    }
                }),
            );
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let endpoint = format!("http://{}", listener.local_addr().unwrap());
        let server = tokio::spawn(async move { axum::serve(listener, metadata).await.unwrap() });

        let store = AmazonS3Builder::new()
            .with_bucket_name("credential-test")
            .with_metadata_endpoint(endpoint)
            .build()
            .unwrap();
        let first = store.credentials().get_credential().await.unwrap();
        tokio::time::sleep(Duration::from_millis(110)).await;
        let second = store.credentials().get_credential().await.unwrap();
        assert_ne!(first.key_id, second.key_id);
        assert!(fetches.load(Ordering::SeqCst) >= 2);
        server.abort();
    }

    #[tokio::test]
    async fn per_integration_tool_policy_filters_discovery_and_calls() {
        let provider = PolicyProvider {
            inner: Arc::new(PolicyFixture),
            allow: Some(HashSet::from(["read".into(), "write".into()])),
            deny: HashSet::from(["write".into()]),
        };
        assert_eq!(provider.tools().await.unwrap()[0].name, "read");
        assert_eq!(provider.call("read", json!({})).await.unwrap(), "read");
        assert!(provider.call("write", json!({})).await.is_err());
        assert!(validate_policy(&json!({"policy":{"allow_tools":["bad name"]}})).is_err());
        assert!(
            validate_transport(
                "http",
                &json!({"url":"https://user:secret@example.com/mcp"}),
                None,
                false,
            )
            .is_err()
        );
        let oauth = json!({"url":"https://example.com/mcp","oauth":{"resource_metadata_url":"https://example.com/resource","issuer":"https://issuer.example/path","authorization_endpoint":"http://localhost/authorize","token_endpoint":"http://127.0.0.1/token","registration_endpoint":"http://localhost/register","client_id":"client","scope":"mcp"}});
        assert!(
            validate_transport(
                "http",
                &oauth,
                Some(&HashMap::from([("X-Test".into(), "ok".into())])),
                false
            )
            .is_ok()
        );
        assert!(validate_transport("http", &json!({"url":"https://example.com/mcp","oauth":{"issuer":"http://remote.example/issuer"}}), None, false).is_err());
        assert!(validate_transport("http", &json!({"url":"https://example.com/mcp","oauth":{"issuer":"https://user:secret@example.com/issuer"}}), None, false).is_err());
        assert!(
            validate_transport(
                "http",
                &json!({"url":"https://example.com/mcp","oauth":{"scope":" "}}),
                None,
                false
            )
            .is_err()
        );
        assert!(
            validate_transport(
                "stdio",
                &json!({"command":"echo","args":["ok"]}),
                None,
                true
            )
            .is_ok()
        );
        assert!(
            validate_transport("stdio", &json!({"command":" ","args":[]}), None, true).is_err()
        );
        assert!(
            validate_transport(
                "stdio",
                &json!({"command":"echo","args":["bad\u{0}"]}),
                None,
                true
            )
            .is_err()
        );
        assert!(
            validate_transport(
                "http",
                &json!({"url":"https://example.com"}),
                Some(&HashMap::from([("bad header".into(), "x".into())])),
                false
            )
            .is_err()
        );
        assert!(
            validate_transport(
                "http",
                &json!({"url":"https://example.com"}),
                Some(&HashMap::from([("X-Test".into(), "bad\nvalue".into())])),
                false
            )
            .is_err()
        );
        provider.close().await.unwrap();
        assert!(
            validate_transport(
                "http",
                &json!({"url":"https://example.com/mcp","oauth":{"client_secret":"secret"}}),
                None,
                false,
            )
            .is_err()
        );
    }

    #[tokio::test]
    async fn provider_metrics_catalog_construction_and_oauth_shortcuts() {
        let metrics = Arc::new(Metrics::default());
        let measured = MeasuredProvider {
            inner: Arc::new(FailingFixture),
            metrics: metrics.clone(),
        };
        assert!(measured.tools().await.is_err());
        assert!(measured.call("x", json!({})).await.is_err());
        assert!(measured.close().await.is_err());
        assert_eq!(metrics.upstream_calls.load(Ordering::Relaxed), 2);
        assert_eq!(metrics.upstream_failures.load(Ordering::Relaxed), 2);

        let (mut app, _directory) = route_test_app().await;
        let user = app.db.create_user("catalog@example.com", "hash").unwrap();
        let auth = AuthContext {
            user: user.clone(),
            agent: "test-agent".into(),
            identity: "test-identity".into(),
            client: "test-client".into(),
            scopes: HashSet::from(["admin".into()]),
            integrations: HashSet::new(),
        };
        let cached = app
            .db
            .create_integration(
                &user,
                "cached",
                "http",
                &json!({"url":"http://localhost:9999/mcp"}),
                None,
            )
            .unwrap();
        app.providers
            .lock()
            .await
            .insert(cached.clone(), Arc::new(PolicyFixture));
        let plain = app.db.create_integration(&user, "plain", "http", &json!({"url":"http://localhost:9998/mcp","policy":{"allow_tools":["read"],"deny_tools":["write"]}}), Some(&app.secrets.seal(br#"{"X-Test":"secret"}"#).unwrap())).unwrap();
        let _sse = app
            .db
            .create_integration(
                &user,
                "events",
                "sse",
                &json!({"url":"http://localhost:9997/sse"}),
                None,
            )
            .unwrap();
        let _unknown = app
            .db
            .create_integration(&user, "unknown", "future", &json!({}), None)
            .unwrap();
        let built = catalog(&app, &auth).await.unwrap();
        assert_eq!(
            built
                .call(&format!("{cached}.read"), json!({}))
                .await
                .unwrap(),
            "read"
        );
        assert!(app.providers.lock().await.contains_key(&plain));

        let oauth = app.db.create_integration(&user, "needs-oauth", "http", &json!({"url":"http://localhost:9996/mcp","oauth":{"authorization_endpoint":"http://localhost/authorize","token_endpoint":"http://localhost/token","client_id":"client"}}), None).unwrap();
        let identity = app.db.list_identities(&user).unwrap()[0].id.clone();
        // An integration awaiting upstream OAuth remains visible to an
        // ungranted downstream client, with the two authorization states kept
        // separate.
        let chatgpt = AuthContext {
            user: user.clone(),
            agent: "test-agent".into(),
            identity,
            client: "chatgpt".into(),
            scopes: HashSet::from(["mcp".into()]),
            integrations: HashSet::new(),
        };
        let awaiting = catalog(&app, &chatgpt)
            .await
            .unwrap()
            .search("needs-oauth")
            .await
            .unwrap();
        assert_eq!(awaiting[0]["upstreamConnected"], false);
        assert_eq!(awaiting[0]["upstreamStatus"], "disconnected");
        assert_eq!(awaiting[0]["clientAccessGranted"], false);
        assert_eq!(awaiting[0]["requiredScope"], format!("integration:{oauth}"));

        app.db
            .put_upstream_oauth_token(
                &oauth,
                &UpstreamOAuthToken {
                    access_token_ciphertext: app.secrets.seal(b"access").unwrap(),
                    refresh_token_ciphertext: None,
                    token_type: "Bearer".into(),
                    scope: "mcp".into(),
                    expires_at: Some(chrono::Utc::now().timestamp() + 3600),
                    refresh_expires_at: None,
                },
            )
            .unwrap();
        let connected = catalog(&app, &chatgpt)
            .await
            .unwrap()
            .search("needs-oauth")
            .await
            .unwrap();
        assert_eq!(connected[0]["clientAccessGranted"], false);
        assert_eq!(
            connected[0]["requiredScope"],
            format!("integration:{oauth}")
        );
        assert!(connected[0].get("authorization_url").is_none());
        let result = admin_authorize(&app, &user, &oauth).await.unwrap();
        assert_eq!(result["alreadyConnected"], true);
        assert!(result.get("authorization_url").is_none());
        app.db.delete_integration(&oauth, &user).unwrap();
        assert_eq!(upstream_authorization(&app, "missing").await.unwrap(), None);
        assert_eq!(
            well_known(
                &"https://issuer.example".parse().unwrap(),
                "oauth-authorization-server"
            )
            .unwrap()
            .path(),
            "/.well-known/oauth-authorization-server"
        );

        let stdio = app
            .db
            .create_integration(
                &user,
                "local",
                "stdio",
                &json!({"command":"echo","args":[]}),
                None,
            )
            .unwrap();
        assert!(catalog(&app, &auth).await.is_err());
        app.db.delete_integration(&stdio, &user).unwrap();
        app.config.allow_stdio = true;
        let stdio = app
            .db
            .create_integration(
                &user,
                "local-enabled",
                "stdio",
                &json!({"command":"echo","args":[]}),
                None,
            )
            .unwrap();
        assert!(catalog(&app, &auth).await.is_ok());
        app.db.delete_integration(&stdio, &user).unwrap();
    }

    #[tokio::test]
    async fn administration_provider_is_least_privilege_and_redacts_secrets() {
        let (app, _directory) = route_test_app().await;
        let user = app.db.create_user("least@example.com", "hash").unwrap();
        let id = app.db.create_integration(&user, "Cloudflare", "http", &json!({"url":"https://example.com/mcp","access_token":"never","nested":{"client_secret":"never"}}), Some("ciphertext-never")).unwrap();
        let read = AdminProvider {
            app: app.clone(),
            auth: AuthContext {
                user: user.clone(),
                agent: "test-agent".into(),
                identity: "test-identity".into(),
                client: "test-client".into(),
                scopes: HashSet::from(["integrations:read".into()]),
                integrations: HashSet::new(),
            },
        };
        let names = read
            .tools()
            .await
            .unwrap()
            .into_iter()
            .map(|tool| tool.name)
            .collect::<Vec<_>>();
        assert!(names.contains(&"integrations_list".into()));
        assert!(!names.contains(&"integration_delete".into()));
        assert!(
            read.call("integration_delete", json!({"id":id}))
                .await
                .is_err()
        );
        let value = read
            .call("integration_get", json!({"id":id}))
            .await
            .unwrap();
        let encoded = value.to_string();
        assert!(!encoded.contains("never"));
        assert!(!encoded.contains("ciphertext"));
    }

    #[tokio::test]
    async fn administration_provider_exercises_every_database_backed_operation() {
        let (app, _directory) = route_test_app().await;
        let user = app
            .db
            .create_user("admin-tools@example.com", "hash")
            .unwrap();
        app.db
            .register_client(
                "admin-tools",
                Some(&user),
                "admin tools",
                &["http://localhost/callback".into()],
            )
            .unwrap();
        app.db
            .store_access_token(
                &token_hash("admin-tools-token"),
                "admin-tools",
                &user,
                "mcp integrations:read integrations:write agents:read agents:write audit:read",
                chrono::Utc::now().timestamp() + 3600,
                None,
                None,
            )
            .unwrap();
        let provider = AdminProvider {
            app: app.clone(),
            auth: AuthContext {
                user: user.clone(),
                agent: "test-agent".into(),
                identity: "test-identity".into(),
                client: "admin-tools".into(),
                scopes: HashSet::from([
                    "mcp".into(),
                    "integrations:read".into(),
                    "integrations:write".into(),
                    "agents:read".into(),
                    "agents:write".into(),
                    "audit:read".into(),
                ]),
                integrations: HashSet::new(),
            },
        };

        assert_eq!(provider.advertised_tools().await.unwrap().len(), 19);
        assert_eq!(provider.tools().await.unwrap().len(), 19);
        let created = provider
            .call(
                "integration_create",
                json!({"name":"fixture","transport":"http","config":{"url":"http://localhost:9876/mcp"}}),
            )
            .await
            .unwrap();
        let id = created["id"].as_str().unwrap().to_owned();
        assert_eq!(
            provider
                .call("integrations_list", json!({}))
                .await
                .unwrap()
                .as_array()
                .unwrap()
                .len(),
            1
        );
        assert_eq!(
            provider
                .call("integration_get", json!({"id":id}))
                .await
                .unwrap()["name"],
            "fixture"
        );
        provider
            .call(
                "integration_update",
                json!({"id":id,"name":"renamed","config":{"url":"http://localhost:9877/mcp"}}),
            )
            .await
            .unwrap();
        provider
            .call("integration_set_enabled", json!({"id":id,"enabled":false}))
            .await
            .unwrap();
        provider
            .call("integration_disconnect", json!({"id":id}))
            .await
            .unwrap();

        assert!(
            provider
                .call("agents_list", json!({}))
                .await
                .unwrap()
                .is_array()
        );
        let tokens = provider.call("tokens_list", json!({})).await.unwrap();
        assert!(tokens.is_array());
        assert!(
            provider
                .call("audit_list", json!({"limit":10}))
                .await
                .unwrap()
                .is_array()
        );

        app.db
            .register_client(
                "revoke-client",
                Some(&user),
                "revoke me",
                &["http://localhost/revoke".into()],
            )
            .unwrap();
        app.db
            .store_access_token(
                &token_hash("revoke-token"),
                "revoke-client",
                &user,
                "mcp",
                chrono::Utc::now().timestamp() + 3600,
                None,
                None,
            )
            .unwrap();
        let token_id = app
            .db
            .agent_tokens(&user)
            .unwrap()
            .into_iter()
            .find(|token| token.client_id == "revoke-client")
            .unwrap()
            .token_id;
        provider
            .call("token_revoke", json!({"id":token_id}))
            .await
            .unwrap();
        app.db
            .register_client(
                "revoke-client-only",
                Some(&user),
                "revoke client",
                &["http://localhost/revoke-client".into()],
            )
            .unwrap();
        app.db
            .store_access_token(
                &token_hash("revoke-client-token"),
                "revoke-client-only",
                &user,
                "mcp",
                chrono::Utc::now().timestamp() + 3600,
                None,
                None,
            )
            .unwrap();
        provider
            .call("agent_revoke", json!({"id":"revoke-client-only"}))
            .await
            .unwrap();

        app.db
            .grant_client_integration(&user, "admin-tools", &id)
            .unwrap();
        provider
            .call(
                "identity_grant_revoke",
                json!({"client_id":"admin-tools","integration_id":id}),
            )
            .await
            .unwrap();
        provider
            .call("integration_delete", json!({"id":id}))
            .await
            .unwrap();
        assert!(provider.call("does_not_exist", json!({})).await.is_err());
    }

    #[test]
    fn native_administration_tools_have_precise_safety_and_scope_metadata() {
        let create = admin_tool("integration_create", "Create an integration.");
        assert_eq!(create.extra["annotations"]["readOnlyHint"], false);
        assert_eq!(create.extra["annotations"]["destructiveHint"], false);
        assert_eq!(create.extra["annotations"]["openWorldHint"], true);
        assert_eq!(
            create.extra["securitySchemes"][0]["scopes"],
            json!(["integrations:write"])
        );
        assert_eq!(
            create.extra["_meta"]["securitySchemes"],
            create.extra["securitySchemes"]
        );
        assert_eq!(
            create.input_schema["required"],
            json!(["name", "transport", "config"])
        );
        assert_eq!(
            native_admin_scope("cog_integration_create"),
            Some("integrations:write")
        );
        assert_eq!(
            native_admin_scope("cog_integrations_list"),
            Some("integrations:read")
        );
        assert_eq!(native_admin_scope("execute"), None);

        let disconnect = admin_tool(
            "integration_disconnect",
            "Disconnect credentials while preserving the integration.",
        );
        assert_eq!(disconnect.extra["annotations"]["readOnlyHint"], false);
        assert_eq!(disconnect.extra["annotations"]["destructiveHint"], true);
        assert_eq!(disconnect.extra["annotations"]["idempotentHint"], true);
        assert_eq!(disconnect.extra["annotations"]["openWorldHint"], false);
        assert_eq!(
            disconnect.extra["securitySchemes"][0]["scopes"],
            json!(["integrations:write"])
        );
        assert_eq!(
            disconnect.extra["_meta"]["securitySchemes"],
            disconnect.extra["securitySchemes"]
        );
    }

    #[tokio::test]
    async fn disconnect_is_idempotent_preserves_target_and_grant_while_delete_removes_both() {
        let (app, _directory) = route_test_app().await;
        let user = app
            .db
            .create_user("disconnect@example.com", "hash")
            .unwrap();
        let integration = app
            .db
            .create_integration(
                &user,
                "Cloudflare",
                "http",
                &json!({"url":"http://localhost:9999/mcp","oauth":{"client_id":"fixture"}}),
                Some(
                    &app.secrets
                        .seal(br#"{"Authorization":"Bearer secret"}"#)
                        .unwrap(),
                ),
            )
            .unwrap();
        let identity = app.db.list_identities(&user).unwrap()[0].id.clone();
        let auth = AuthContext {
            user: user.clone(),
            agent: "test-agent".into(),
            identity,
            client: "agent".into(),
            scopes: HashSet::from(["mcp".into(), "integrations:write".into()]),
            integrations: HashSet::from([integration.clone()]),
        };
        app.db
            .put_upstream_oauth_token(
                &integration,
                &UpstreamOAuthToken {
                    access_token_ciphertext: app.secrets.seal(b"first-access").unwrap(),
                    refresh_token_ciphertext: None,
                    token_type: "Bearer".into(),
                    scope: "mcp".into(),
                    expires_at: Some(chrono::Utc::now().timestamp() + 3600),
                    refresh_expires_at: None,
                },
            )
            .unwrap();
        app.providers
            .lock()
            .await
            .insert(integration.clone(), Arc::new(PolicyFixture));
        let admin = AdminProvider {
            app: app.clone(),
            auth: auth.clone(),
        };

        for _ in 0..2 {
            let disconnected = admin
                .call("integration_disconnect", json!({"id":integration}))
                .await
                .unwrap();
            assert_eq!(disconnected["id"], integration);
            assert_eq!(disconnected["upstreamConnected"], false);
            assert_eq!(disconnected["upstreamStatus"], "disconnected");
            let discovery = catalog(&app, &auth)
                .await
                .unwrap()
                .search("Cloudflare")
                .await
                .unwrap();
            assert_eq!(discovery[0]["integration"], integration);
            assert_eq!(discovery[0]["clientAccessGranted"], true);
        }

        // Reauthorization attaches a provider to the same durable integration,
        // so the previously granted immutable target immediately works again.
        app.db
            .put_upstream_oauth_token(
                &integration,
                &UpstreamOAuthToken {
                    access_token_ciphertext: app.secrets.seal(b"second-access").unwrap(),
                    refresh_token_ciphertext: None,
                    token_type: "Bearer".into(),
                    scope: "mcp".into(),
                    expires_at: Some(chrono::Utc::now().timestamp() + 3600),
                    refresh_expires_at: None,
                },
            )
            .unwrap();
        let mut reauthorized = Catalog::new();
        reauthorized.add_labeled(
            integration.clone(),
            "Cloudflare".into(),
            Arc::new(PolicyFixture),
        );
        assert_eq!(
            reauthorized
                .call(&format!("{integration}.read"), json!({}))
                .await
                .unwrap(),
            "read"
        );

        admin
            .call("integration_delete", json!({"id":integration}))
            .await
            .unwrap();
        assert!(app.db.integration(&integration, &user).unwrap().is_none());
        assert!(
            catalog(&app, &auth)
                .await
                .unwrap()
                .call(&format!("{integration}.read"), json!({}))
                .await
                .is_err()
        );
    }

    #[test]
    fn integration_ui_distinguishes_disconnect_from_permanent_delete() {
        let source = include_str!("../frontend/src/main.jsx");
        assert!(source.contains("Disconnect credentials but preserve this connection?"));
        assert!(source.contains("Delete this connection and every descendant?"));
        assert!(source.contains("all of its connections, agents, credentials, and grants"));
        assert!(source.contains("function Consent()"));
        assert!(source.contains("payload.identities[0]?.id"));
        assert!(source.contains("identity===\"\""));
        assert!(source.contains("action=\"/api/oauth/consent\""));
        assert!(source.contains("function GitHubInstallationComplete()"));
        assert!(source.contains("/github/app/installation/complete"));
    }

    #[test]
    fn integration_access_follows_identity_membership_without_incremental_scope() {
        let integration = "identity-integration".to_owned();
        let auth = AuthContext {
            user: "user".into(),
            agent: "agent".into(),
            client: "client".into(),
            identity: "identity".into(),
            scopes: HashSet::from(["mcp".into()]),
            integrations: HashSet::from([integration.clone()]),
        };
        assert!(auth.allows_integration(&integration));
        assert!(!auth.allows_integration("another-integration"));
    }

    #[tokio::test]
    async fn repeated_scope_challenge_after_consent_is_bounded_and_preserves_credentials() {
        let (app, _directory) = route_test_app().await;
        let user = app
            .db
            .create_user("bounded-step-up@example.com", "hash")
            .unwrap();
        let integration = app
            .db
            .create_integration(
                &user,
                "Cloudflare",
                "http",
                &json!({"url":"https://example.com/mcp"}),
                None,
            )
            .unwrap();
        let ciphertext = app.secrets.seal(b"still-valid").unwrap();
        app.db
            .put_upstream_oauth_token(
                &integration,
                &UpstreamOAuthToken {
                    access_token_ciphertext: ciphertext.clone(),
                    refresh_token_ciphertext: None,
                    token_type: "Bearer".into(),
                    scope: "mcp workers:write".into(),
                    expires_at: Some(chrono::Utc::now().timestamp() + 3600),
                    refresh_expires_at: None,
                },
            )
            .unwrap();
        let provider = OAuthStepUpProvider {
            inner: Arc::new(ScopeChallengeFixture {
                challenge: UpstreamInsufficientScope {
                    scopes: vec!["workers:write".into()],
                    resource_metadata: "https://example.com/.well-known/oauth-protected-resource"
                        .into(),
                },
            }),
            app: app.clone(),
            user,
            integration: integration.clone(),
        };
        let error = provider
            .call("search", json!({}))
            .await
            .unwrap_err()
            .to_string();
        assert!(error.contains("retried once"));
        assert!(!error.contains("https://"));
        assert_eq!(
            app.db
                .upstream_oauth_token(&integration)
                .unwrap()
                .unwrap()
                .access_token_ciphertext,
            ciphertext
        );
    }
}
