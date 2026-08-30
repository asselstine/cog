use super::{NativeToolDefinition, annotations};
use crate::upstream::Tool;
use serde_json::json;

pub const INSTRUCTIONS: &str = "The execute tool accepts a synchronous JavaScript function body. Write statements directly; do not wrap them in a function or arrow function, do not use async/await, and do not return a Promise. Include an explicit return statement. Discovery is literal case-insensitive substring matching. Git tools use git.repository_access, git.ssh_key_status, git.ssh_key_register, and git.ssh_key_lease_renew. Reuse an existing Ed25519 identity, register only its public key, pin knownHosts, and use sshRemoteUrl. Renew the internal lease without changing key material. Never send or replace the private key, generate a key automatically, or disable host-key checking.";

pub fn definition() -> NativeToolDefinition {
    NativeToolDefinition {
        tool: Tool {
            name: "execute".into(),
            description: Some(format!(
                "Run JavaScript in an isolated V8 runtime. {INSTRUCTIONS}"
            )),
            input_schema: json!({
                "type":"object",
                "properties":{"code":{"type":"string","description":INSTRUCTIONS}},
                "required":["code"],
                "additionalProperties":false
            }),
            extra: annotations("mcp", false, false, false, true),
        },
        required_scope: "mcp",
    }
}
