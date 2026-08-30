use crate::upstream::Tool;
use serde_json::json;

pub const NAMES: &[&str] = &[
    "integrations_list",
    "integration_get",
    "github_app_setup_start",
    "github_app_setup_status",
    "integration_create",
    "integration_update",
    "integration_set_enabled",
    "integration_authorize",
    "integration_reconnect",
    "integration_disconnect",
    "integration_delete",
    "agents_list",
    "agent_get_self",
    "agent_update_self",
    "agent_revoke",
    "tokens_list",
    "token_revoke",
    "identity_grant_revoke",
    "audit_list",
];

pub fn required_scope(name: &str) -> Option<&'static str> {
    Some(match name {
        "integrations_list" | "integration_get" | "github_app_setup_status" => "integrations:read",
        "github_app_setup_start"
        | "integration_create"
        | "integration_update"
        | "integration_set_enabled"
        | "integration_authorize"
        | "integration_reconnect"
        | "integration_disconnect"
        | "integration_delete" => "integrations:write",
        "agents_list" | "agent_get_self" | "tokens_list" => "agents:read",
        "agent_update_self" | "agent_revoke" | "token_revoke" | "identity_grant_revoke" => {
            "agents:write"
        }
        "audit_list" => "audit:read",
        _ => return None,
    })
}

pub fn tool(name: &str, description: &str) -> Tool {
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
    let required_scope = required_scope(name).unwrap_or("mcp");
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
