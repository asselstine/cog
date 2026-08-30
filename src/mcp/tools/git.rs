use crate::upstream::Tool;
use serde_json::json;

pub const NAMES: &[&str] = &[
    "repository_access",
    "ssh_key_status",
    "ssh_key_register",
    "ssh_key_lease_renew",
];

pub const REQUIRED_SCOPE: &str = "mcp";

pub fn tool(name: &str, description: &str) -> Tool {
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
