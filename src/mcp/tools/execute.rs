use super::{NativeAvailability, NativeNamespace, NativeToolDefinition, NativeToolId, annotations};
use crate::{mcp::Catalog, runtime::CodeRuntime};
use serde_json::json;
use std::sync::Arc;

pub const INSTRUCTIONS: &str = "The execute tool accepts a synchronous JavaScript function body. Write statements directly; do not wrap them in a function or arrow function, do not use async/await, and do not return a Promise. Include an explicit return statement. Discovery is literal case-insensitive substring matching. Git tools use git.repository_access, git.ssh_key_status, git.ssh_key_register, and git.ssh_key_lease_renew. Reuse an existing Ed25519 identity, register only its public key, pin knownHosts, and use sshRemoteUrl. Renew the internal lease without changing key material. Never send or replace the private key, generate a key automatically, or disable host-key checking.";

pub fn definition() -> NativeToolDefinition {
    NativeToolDefinition {
        id: NativeToolId::Execute,
        namespace: NativeNamespace::Execute,
        wire_name: "execute",
        title: "Execute JavaScript",
        description: "Run JavaScript in an isolated V8 runtime. The execute tool accepts a synchronous JavaScript function body. Write statements directly; do not wrap them in a function or arrow function, do not use async/await, and do not return a Promise. Include an explicit return statement.",
        input_schema: json!({
            "type":"object",
            "properties":{
                "code":{"type":"string","description":INSTRUCTIONS},
                "integrations":{"type":"array","items":{"type":"string"},"uniqueItems":true,"description":"Immutable integration IDs this invocation may access. Every integration used by codemode.describe or codemode.call must be declared here."}
            },
            "required":["code","integrations"],
            "additionalProperties":false
        }),
        annotations: annotations("mcp", false, false, false, true),
        required_scope: "mcp",
        availability: NativeAvailability::Always,
    }
}

pub async fn invoke(
    runtime: Arc<CodeRuntime>,
    catalog: Arc<Catalog>,
    code: String,
) -> anyhow::Result<serde_json::Value> {
    runtime.execute(code, catalog).await
}
