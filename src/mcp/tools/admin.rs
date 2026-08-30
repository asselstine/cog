use super::{NativeAvailability, NativeNamespace, NativeToolDefinition, NativeToolId, annotations};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use std::collections::HashMap;

#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct EmptyArgs {}

#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct IdArgs {
    id: String,
}

#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct DisplayNameArgs {
    display_name: String,
}

#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct NameArgs {
    name: String,
}

#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct CreateArgs {
    name: String,
    transport: String,
    config: Value,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    headers: Option<HashMap<String, String>>,
}

#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct UpdateArgs {
    id: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    name: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    config: Option<Value>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    enabled: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    headers: Option<HashMap<String, String>>,
}

#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct EnabledArgs {
    id: String,
    enabled: bool,
}

#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct GrantArgs {
    client_id: String,
    integration_id: String,
}

#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct AuditArgs {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    limit: Option<u64>,
}

fn validate_arguments(id: NativeToolId, arguments: Value) -> anyhow::Result<Value> {
    use NativeToolId::*;
    macro_rules! validate {
        ($type:ty) => {{ serde_json::to_value(serde_json::from_value::<$type>(arguments)?)? }};
    }
    Ok(match id {
        IntegrationsList | AgentsList | AgentGetSelf | TokensList => validate!(EmptyArgs),
        AgentUpdateSelf => validate!(DisplayNameArgs),
        GitHubAppSetupStart => validate!(NameArgs),
        IntegrationCreate => validate!(CreateArgs),
        IntegrationUpdate => validate!(UpdateArgs),
        IntegrationSetEnabled => validate!(EnabledArgs),
        IdentityGrantRevoke => validate!(GrantArgs),
        AuditList => validate!(AuditArgs),
        IntegrationGet
        | GitHubAppSetupStatus
        | IntegrationAuthorize
        | IntegrationReconnect
        | IntegrationDisconnect
        | IntegrationDelete
        | AgentRevoke
        | TokenRevoke => {
            validate!(IdArgs)
        }
        _ => anyhow::bail!("non-administration tool ID"),
    })
}

pub fn definitions() -> Vec<NativeToolDefinition> {
    use NativeToolId::*;
    [
        (AgentGetSelf, "agent_get_self", "Get agent", "Read the authenticated agent's immutable IDs and display name."),
        (AgentUpdateSelf, "agent_update_self", "Update agent", "Rename the authenticated agent without changing its identity or authorization."),
        (IntegrationsList, "integrations_list", "List integrations", "List every integration with separate upstream-provider connection and calling-client access-grant status, without credentials."),
        (IntegrationGet, "integration_get", "Get integration", "Inspect one integration by immutable id without credentials."),
        (IntegrationCreate, "integration_create", "Create integration", "Create an integration."),
        (GitHubAppSetupStart, "github_app_setup_start", "Start GitHub App setup", "Create a pending GitHub integration and return a one-time browser URL that creates the GitHub App, stores its credentials, and continues to repository installation."),
        (GitHubAppSetupStatus, "github_app_setup_status", "GitHub App setup status", "Inspect GitHub App creation and installation status without returning credentials."),
        (IntegrationUpdate, "integration_update", "Update integration", "Update an integration by immutable id."),
        (IntegrationDisconnect, "integration_disconnect", "Disconnect integration", "Disconnect the upstream provider by atomically removing OAuth tokens, client registration secrets, pending authorization state, and static authentication headers. The integration ID, configuration, and downstream agent grants are preserved. This operation is idempotent."),
        (IntegrationReconnect, "integration_reconnect", "Reconnect integration", "Deprecated compatibility operation: destructively disconnect provider credentials, then start authorization. Use integration_disconnect followed by integration_authorize. It cannot grant this calling client downstream access."),
        (IntegrationAuthorize, "integration_authorize", "Authorize integration", "Connect cog to an upstream provider. Returns alreadyConnected when valid credentials exist; otherwise returns a one-time provider OAuth URL that must not be prefetched. This does not grant the calling agent access."),
        (IntegrationSetEnabled, "integration_set_enabled", "Enable integration", "Enable or disable an integration."),
        (IntegrationDelete, "integration_delete", "Delete integration", "Permanently delete an integration, including its immutable ID, provider credentials, pending authorization state, and every downstream client grant. Use integration_disconnect to preserve configuration and grants."),
        (AgentsList, "agents_list", "List agents", "List authorized agents."),
        (TokensList, "tokens_list", "List tokens", "List token lifecycle and grants without token values."),
        (AgentRevoke, "agent_revoke", "Revoke agent", "Revoke an agent and all its credentials."),
        (TokenRevoke, "token_revoke", "Revoke token", "Revoke one token by public token id."),
        (IdentityGrantRevoke, "identity_grant_revoke", "Revoke identity grant", "Immediately revoke one immutable integration grant from all client tokens and refresh access."),
        (AuditList, "audit_list", "List audit events", "Read recent audit events."),
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
    let (input_schema, read_only, destructive, idempotent, open_world) = match name {
        "integrations_list" | "agents_list" | "tokens_list" | "agent_get_self" => (
            json!({"type":"object","properties":{},"additionalProperties":false}),
            true,
            false,
            true,
            false,
        ),
        "agent_update_self" => (
            json!({"type":"object","properties":{"display_name":{"type":"string","maxLength":128,"description":"New display name for the authenticated agent."}},"required":["display_name"],"additionalProperties":false}),
            false,
            false,
            true,
            false,
        ),
        "integration_get" => (
            json!({"type":"object","properties":{"id":{"type":"string","description":"Immutable integration ID."}},"required":["id"],"additionalProperties":false}),
            true,
            false,
            true,
            false,
        ),
        "github_app_setup_status" => (
            json!({"type":"object","properties":{"id":{"type":"string","description":"Immutable GitHub integration ID."}},"required":["id"],"additionalProperties":false}),
            true,
            false,
            true,
            false,
        ),
        "github_app_setup_start" => (
            json!({"type":"object","properties":{"name":{"type":"string","description":"Display name for the new GitHub integration."}},"required":["name"],"additionalProperties":false}),
            false,
            false,
            false,
            true,
        ),
        "integration_create" => (
            json!({"type":"object","properties":{"name":{"type":"string","description":"Integration display name."},"transport":{"type":"string","enum":["http","stdio","git"],"description":"Connection transport. MCP upstreams support Streamable HTTP and stdio; git is Cog's native Git integration kind."},"config":{"type":"object","description":"Transport-specific configuration."},"headers":{"type":"object","description":"Optional static upstream HTTP headers.","additionalProperties":{"type":"string"}}},"required":["name","transport","config"],"additionalProperties":false}),
            false,
            false,
            false,
            true,
        ),
        "integration_update" => (
            json!({"type":"object","properties":{"id":{"type":"string","description":"Immutable integration ID."},"name":{"type":"string","description":"Replacement display name."},"config":{"type":"object","description":"Replacement transport configuration."},"enabled":{"type":"boolean","description":"Whether the integration is available."},"headers":{"type":"object","description":"Replacement static upstream HTTP headers.","additionalProperties":{"type":"string"}}},"required":["id"],"additionalProperties":false}),
            false,
            false,
            false,
            true,
        ),
        "integration_set_enabled" => (
            json!({"type":"object","properties":{"id":{"type":"string","description":"Immutable integration ID."},"enabled":{"type":"boolean","description":"Whether the integration is available."}},"required":["id","enabled"],"additionalProperties":false}),
            false,
            false,
            true,
            false,
        ),
        "integration_authorize" => (
            json!({"type":"object","properties":{"id":{"type":"string","description":"Immutable integration ID."}},"required":["id"],"additionalProperties":false}),
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
            json!({"type":"object","properties":{"id":{"type":"string","description":"Immutable integration, agent, or token ID, as applicable."}},"required":["id"],"additionalProperties":false}),
            false,
            true,
            true,
            false,
        ),
        "identity_grant_revoke" => (
            json!({"type":"object","properties":{"client_id":{"type":"string","description":"OAuth client ID whose grant will be revoked."},"integration_id":{"type":"string","description":"Immutable integration ID to remove from the client."}},"required":["client_id","integration_id"],"additionalProperties":false}),
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
    use NativeToolId::*;
    let required_scope = match id {
        IntegrationsList | IntegrationGet | GitHubAppSetupStatus => "integrations:read",
        GitHubAppSetupStart
        | IntegrationCreate
        | IntegrationUpdate
        | IntegrationSetEnabled
        | IntegrationAuthorize
        | IntegrationReconnect
        | IntegrationDisconnect
        | IntegrationDelete => "integrations:write",
        AgentsList | AgentGetSelf | TokensList => "agents:read",
        AgentUpdateSelf | AgentRevoke | TokenRevoke | IdentityGrantRevoke => "agents:write",
        AuditList => "audit:read",
        _ => unreachable!("administration definitions only"),
    };
    NativeToolDefinition {
        id,
        namespace: NativeNamespace::Cog,
        wire_name: name,
        title,
        description,
        input_schema,
        annotations: annotations(
            required_scope,
            read_only,
            destructive,
            idempotent,
            open_world,
        ),
        required_scope,
        availability: NativeAvailability::Always,
    }
}

use crate::{
    mcp::{Tool, ToolProvider},
    server::*,
};

pub struct AdminProvider {
    pub app: App,
    pub auth: AuthContext,
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

pub fn safe_integration(a: &App, integration: crate::db::Integration, access: bool) -> Value {
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
                let definition = crate::mcp::tools::by_code_target(&format!("cog.{}", tool.name))
                    .expect("advertised administration tool is registered");
                let required_scope = definition.required_scope;
                let access_granted = matches!(
                    definition.id,
                    NativeToolId::IntegrationsList
                        | NativeToolId::AgentGetSelf
                        | NativeToolId::AgentUpdateSelf
                ) || self.auth.allows(required_scope);
                crate::mcp::model::insert_meta(
                    &mut tool,
                    crate::mcp::model::META_CLIENT_ACCESS_GRANTED,
                    json!(access_granted),
                );
                crate::mcp::model::insert_meta(
                    &mut tool,
                    crate::mcp::model::META_REQUIRED_SCOPE,
                    json!(required_scope),
                );
                tool
            })
            .collect())
    }

    async fn advertised_tools(&self) -> anyhow::Result<Vec<Tool>> {
        Ok(crate::mcp::tools::admin::definitions()
            .into_iter()
            .map(|definition| definition.tool())
            .collect())
    }

    async fn call(&self, name: &str, args: Value) -> anyhow::Result<Value> {
        use NativeToolId::*;
        let definition = crate::mcp::tools::by_code_target(&format!("cog.{name}"))
            .ok_or_else(|| anyhow::anyhow!("unknown administration tool"))?;
        let baseline_access = matches!(
            definition.id,
            IntegrationsList | AgentGetSelf | AgentUpdateSelf
        ) && self.auth.allows("mcp");
        anyhow::ensure!(
            baseline_access || self.auth.allows(definition.required_scope),
            crate::authz::InsufficientScope::one(definition.required_scope)
        );
        let args = validate_arguments(definition.id, args)?;
        let arg_id = || {
            args.get("id")
                .and_then(Value::as_str)
                .expect("validated administration arguments contain id")
        };
        match definition.id {
            AgentGetSelf => Ok(serde_json::to_value(
                self.app
                    .db
                    .agent_for_client(&self.auth.client)?
                    .ok_or_else(|| anyhow::anyhow!("agent not found"))?,
            )?),
            AgentUpdateSelf => {
                let name = args
                    .get("display_name")
                    .and_then(Value::as_str)
                    .expect("validated agent update arguments contain display_name");
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
            IntegrationsList => Ok(Value::Array(
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
            )),
            IntegrationGet => self
                .app
                .db
                .integration(arg_id(), &self.auth.user)?
                .map(|integration| {
                    let access = self.auth.scopes.contains("admin")
                        || self.auth.integrations.contains(&integration.id);
                    safe_integration(&self.app, integration, access)
                })
                .ok_or_else(|| anyhow::anyhow!("integration not found")),
            AgentsList => Ok(serde_json::to_value(
                self.app.db.agent_clients(&self.auth.user)?,
            )?),
            TokensList => Ok(serde_json::to_value(
                self.app.db.agent_tokens(&self.auth.user)?,
            )?),
            AuditList => {
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
            IntegrationCreate => admin_create(&self.app, &self.auth.user, args).await,
            GitHubAppSetupStart => {
                admin_github_app_setup_start(&self.app, &self.auth.user, args).await
            }
            GitHubAppSetupStatus => {
                admin_github_app_setup_status(&self.app, &self.auth.user, arg_id()).await
            }
            IntegrationUpdate => {
                admin_update(&self.app, &self.auth.user, arg_id().to_owned(), args).await
            }
            IntegrationSetEnabled => {
                let enabled = args
                    .get("enabled")
                    .and_then(Value::as_bool)
                    .expect("validated integration update arguments contain enabled");
                admin_update(
                    &self.app,
                    &self.auth.user,
                    arg_id().to_owned(),
                    json!({"enabled":enabled}),
                )
                .await
            }
            IntegrationReconnect => admin_reconnect(&self.app, &self.auth.user, arg_id()).await,
            IntegrationDisconnect => admin_disconnect(&self.app, &self.auth.user, arg_id()).await,
            IntegrationAuthorize => admin_authorize(&self.app, &self.auth.user, arg_id()).await,
            IntegrationDelete => admin_delete(&self.app, &self.auth.user, arg_id()).await,
            AgentRevoke => admin_revoke_client(&self.app, &self.auth.user, arg_id()).await,
            TokenRevoke => admin_revoke_token(&self.app, &self.auth.user, arg_id()).await,
            IdentityGrantRevoke => {
                let client = args
                    .get("client_id")
                    .and_then(Value::as_str)
                    .expect("validated grant arguments contain client_id");
                let integration = args
                    .get("integration_id")
                    .and_then(Value::as_str)
                    .expect("validated grant arguments contain integration_id");
                admin_revoke_grant(&self.app, &self.auth.user, client, integration).await
            }
            _ => unreachable!("administration registry returned a non-administration ID"),
        }
    }
}
