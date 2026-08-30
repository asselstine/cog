use crate::{authz::InsufficientScope, runtime::CodeRuntime, upstream::Catalog};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use std::sync::Arc;

pub mod tools;

const EXECUTE_INSTRUCTIONS: &str = tools::execute::INSTRUCTIONS;
const HYBRID_INSTRUCTIONS: &str = "External integration tools are available through execute and COG-native tools are also advertised directly. For Git, call repository_access, reuse an existing Ed25519 identity, register only its public key with ssh_key_register, and renew its internal lease with ssh_key_lease_renew. Pin knownHosts and use sshRemoteUrl. The keypair never changes; never send the private key, generate a key automatically, or disable host-key checking.";

pub const LATEST_PROTOCOL_VERSION: &str = "2025-11-25";
pub const SUPPORTED_PROTOCOL_VERSIONS: &[&str] = &[LATEST_PROTOCOL_VERSION, "2025-06-18"];

pub fn protocol_version_supported(version: &str) -> bool {
    SUPPORTED_PROTOCOL_VERSIONS.contains(&version)
}

#[derive(Debug, Deserialize)]
pub struct RpcRequest {
    pub jsonrpc: String,
    pub id: Option<Value>,
    pub method: String,
    #[serde(default)]
    pub params: Value,
}
#[derive(Debug, Serialize)]
pub struct RpcResponse {
    pub jsonrpc: &'static str,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub id: Option<Value>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub result: Option<Value>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<Value>,
}
impl RpcResponse {
    fn ok(id: Option<Value>, result: Value) -> Self {
        Self {
            jsonrpc: "2.0",
            id,
            result: Some(result),
            error: None,
        }
    }
    fn err(id: Option<Value>, code: i64, message: impl ToString) -> Self {
        Self {
            jsonrpc: "2.0",
            id,
            result: None,
            error: Some(json!({"code":code,"message":message.to_string()})),
        }
    }
}
pub async fn handle(
    req: RpcRequest,
    runtime: Arc<CodeRuntime>,
    catalog: Arc<Catalog>,
) -> RpcResponse {
    handle_with_metadata(
        req,
        runtime,
        catalog,
        "/.well-known/oauth-protected-resource",
    )
    .await
}

pub async fn handle_with_metadata(
    req: RpcRequest,
    runtime: Arc<CodeRuntime>,
    catalog: Arc<Catalog>,
    resource_metadata_url: &str,
) -> RpcResponse {
    handle_with_options(req, runtime, catalog, resource_metadata_url, true).await
}

pub async fn handle_with_options(
    req: RpcRequest,
    runtime: Arc<CodeRuntime>,
    catalog: Arc<Catalog>,
    resource_metadata_url: &str,
    codemode: bool,
) -> RpcResponse {
    if req.jsonrpc != "2.0" {
        return RpcResponse::err(req.id, -32600, "invalid JSON-RPC version");
    }
    match req.method.as_str() {
        "initialize" => {
            let valid = req
                .params
                .get("protocolVersion")
                .is_some_and(Value::is_string)
                && req.params.get("capabilities").is_some_and(Value::is_object)
                && req.params.get("clientInfo").is_some_and(Value::is_object);
            if !valid {
                RpcResponse::err(req.id, -32602, "invalid initialize parameters")
            } else {
                let requested = req.params["protocolVersion"].as_str().unwrap();
                let selected = if protocol_version_supported(requested) {
                    requested
                } else {
                    LATEST_PROTOCOL_VERSION
                };
                RpcResponse::ok(
                    req.id,
                    json!({"protocolVersion":selected,"capabilities":{"tools":{"listChanged":false}},"serverInfo":{"name":"cog","version":env!("CARGO_PKG_VERSION")},"instructions":if codemode { EXECUTE_INSTRUCTIONS } else { HYBRID_INSTRUCTIONS }}),
                )
            }
        }
        "ping" => RpcResponse::ok(req.id, json!({})),
        "notifications/initialized" => RpcResponse::ok(req.id, Value::Null),
        "tools/list" => {
            let mut tools = vec![
                serde_json::to_value(tools::execute::definition().tool)
                    .expect("native tool definition serializes"),
            ];
            if !codemode {
                for (integration, prefix) in [("git", ""), ("cog", "cog_")] {
                    match catalog.native_tools(integration, prefix).await {
                        Ok(native) => tools.extend(
                            native
                                .into_iter()
                                .map(|tool| serde_json::to_value(tool).expect("tool serializes")),
                        ),
                        Err(error) => return RpcResponse::err(req.id, -32603, error),
                    }
                }
            }
            RpcResponse::ok(req.id, json!({"tools":tools}))
        }
        "tools/call" => {
            let Some(name) = req.params.get("name").and_then(Value::as_str) else {
                return RpcResponse::err(req.id, -32602, "tool name is required");
            };
            if !codemode && let Some(target) = native_target(name) {
                let args = req
                    .params
                    .get("arguments")
                    .cloned()
                    .unwrap_or_else(|| json!({}));
                return match catalog.call(&target, args).await {
                    Ok(value) => {
                        let text = serde_json::to_string(&value).unwrap();
                        let structured = if value.is_object() {
                            value
                        } else {
                            json!({"result":value})
                        };
                        RpcResponse::ok(
                            req.id,
                            json!({"content":[{"type":"text","text":text}],"structuredContent":structured}),
                        )
                    }
                    Err(error) => match error.downcast_ref::<InsufficientScope>() {
                        Some(required) => insufficient_scope_result(
                            req.id,
                            &required.scopes,
                            resource_metadata_url,
                        ),
                        None => tool_error(req.id, error),
                    },
                };
            }
            if name != "execute" {
                return RpcResponse::err(req.id, -32602, "unknown tool");
            }
            let Some(code) = req
                .params
                .pointer("/arguments/code")
                .and_then(Value::as_str)
            else {
                return RpcResponse::err(req.id, -32602, "code is required");
            };
            match runtime.execute(code.to_owned(), catalog).await {
                Ok(v) => {
                    let text = serde_json::to_string(&v).unwrap();
                    let structured = if v.is_object() {
                        v
                    } else {
                        json!({ "result": v })
                    };
                    RpcResponse::ok(
                        req.id,
                        json!({"content":[{"type":"text","text":text}],"structuredContent":structured}),
                    )
                }
                Err(e) => match e.downcast_ref::<InsufficientScope>() {
                    Some(required) => {
                        insufficient_scope_result(req.id, &required.scopes, resource_metadata_url)
                    }
                    None => RpcResponse::ok(
                        req.id,
                        json!({"content":[{"type":"text","text":e.to_string()}],"structuredContent":{"error":{"message":e.to_string(),"corrective":true}},"isError":true}),
                    ),
                },
            }
        }
        _ => RpcResponse::err(req.id, -32601, "method not found"),
    }
}

fn native_target(name: &str) -> Option<String> {
    match name {
        "repository_access" | "ssh_key_status" | "ssh_key_register" | "ssh_key_lease_renew" => {
            Some(format!("git.{name}"))
        }
        _ => name.strip_prefix("cog_").map(|tool| format!("cog.{tool}")),
    }
}

fn tool_error(id: Option<Value>, error: anyhow::Error) -> RpcResponse {
    RpcResponse::ok(
        id,
        json!({"content":[{"type":"text","text":error.to_string()}],"structuredContent":{"error":{"message":error.to_string(),"corrective":true}},"isError":true}),
    )
}

pub fn insufficient_scope_result(
    id: Option<Value>,
    scopes: &[String],
    resource_metadata_url: &str,
) -> RpcResponse {
    let mut required = vec!["mcp".to_owned()];
    required.extend(
        scopes
            .iter()
            .filter(|scope| scope.as_str() != "mcp")
            .cloned(),
    );
    let scope = required.join(" ");
    let challenge = format!(
        "Bearer resource_metadata=\"{resource_metadata_url}\", error=\"insufficient_scope\", error_description=\"Additional authorization is required\", scope=\"{scope}\""
    );
    RpcResponse::ok(
        id,
        json!({
            "content":[{"type":"text","text":format!("Additional downstream authorization is required for scope: {scope}. Reauthorize and refresh this same MCP client's credential. Do not use integration_reconnect; it replaces upstream provider credentials and cannot grant this client access.")}],
            "structuredContent":{"error":"insufficient_scope","requiredScopes":required,"action":"reauthorizeSameClient","prohibitedAction":"integration_reconnect"},
            "isError":true,
            "_meta":{"mcp/www_authenticate":[challenge]}
        }),
    )
}
