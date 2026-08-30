use super::{NativeAvailability, NativeNamespace, NativeToolDefinition, NativeToolId, annotations};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};

#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
struct RepositoryAccessArgs {
    integration_id: String,
    repository: String,
}

#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
struct PublicKeyArgs {
    public_key: String,
}

fn validate_arguments(id: NativeToolId, arguments: Value) -> anyhow::Result<Value> {
    let validated = match id {
        NativeToolId::RepositoryAccess => {
            serde_json::to_value(serde_json::from_value::<RepositoryAccessArgs>(arguments)?)?
        }
        NativeToolId::SshKeyStatus
        | NativeToolId::SshKeyRegister
        | NativeToolId::SshKeyLeaseRenew => {
            serde_json::to_value(serde_json::from_value::<PublicKeyArgs>(arguments)?)?
        }
        _ => anyhow::bail!("non-Git tool ID"),
    };
    Ok(validated)
}

pub const REQUIRED_SCOPE: &str = "mcp";

pub fn definitions() -> Vec<NativeToolDefinition> {
    use NativeToolId::*;
    [
        (RepositoryAccess, "repository_access", "Repository access", "Resolve a GitHub repository and return its COG SSH remote plus pinned host key. Reuse the agent's existing Ed25519 identity, register its public key once with ssh_key_register, and renew only its internal authorization lease with ssh_key_lease_renew. The private key remains local and unchanged. Access is controlled by the live key lease, repository grant, integration, and this client's authorization."),
        (SshKeyStatus, "ssh_key_status", "SSH key status", "Check whether this OAuth-bound agent's registered Ed25519 public key has a live internal SSH authorization lease."),
        (SshKeyRegister, "ssh_key_register", "Register SSH key", "Register this OAuth-bound agent's existing Ed25519 public key and start its internal authorization lease. This never accepts, creates, or replaces a private key."),
        (SshKeyLeaseRenew, "ssh_key_lease_renew", "Renew SSH key lease", "Extend the internal authorization lease for this OAuth-bound agent's exact registered Ed25519 public key. The keypair and local files do not change."),
    ]
    .into_iter()
    .map(|(id, name, title, description)| definition(id, name, title, description))
    .collect()
}

fn definition(
    id: NativeToolId,
    name: &'static str,
    title: &'static str,
    description: &'static str,
) -> NativeToolDefinition {
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
    NativeToolDefinition {
        id,
        namespace: NativeNamespace::Git,
        wire_name: name,
        title,
        description,
        input_schema,
        annotations: annotations(REQUIRED_SCOPE, read_only, false, idempotent, open_world),
        required_scope: REQUIRED_SCOPE,
        availability: if matches!(id, NativeToolId::RepositoryAccess) {
            NativeAvailability::Always
        } else {
            NativeAvailability::Ssh
        },
    }
}

use crate::{
    git::RepositoryReference,
    git::providers::{GitProvider, github::GitHubProvider},
    mcp::{Tool, ToolProvider},
    server::*,
};
use std::{
    sync::{Arc, atomic::Ordering},
    time::Duration,
};

pub struct GitControlProvider {
    pub app: App,
    pub auth: AuthContext,
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
        let ssh_available =
            self.app.ssh_keys.is_some() && self.app.ssh_ready.load(Ordering::Acquire);
        Ok(crate::mcp::tools::git::definitions()
            .into_iter()
            .filter(|definition| definition.available(ssh_available))
            .map(|definition| definition.tool())
            .collect())
    }
    async fn call(&self, name: &str, args: Value) -> anyhow::Result<Value> {
        let definition = crate::mcp::tools::by_code_target(&format!("git.{name}"))
            .ok_or_else(|| anyhow::anyhow!("unknown Git control operation"))?;
        anyhow::ensure!(
            self.auth.allows(definition.required_scope),
            crate::authz::InsufficientScope::one(definition.required_scope)
        );
        let args = validate_arguments(definition.id, args)?;
        match definition.id {
            NativeToolId::RepositoryAccess => {
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
            NativeToolId::SshKeyStatus => {
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
            NativeToolId::SshKeyRegister | NativeToolId::SshKeyLeaseRenew => {
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
                let renewing = definition.id == NativeToolId::SshKeyLeaseRenew;
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
