use crate::{authz::InsufficientScope, runtime::CodeRuntime, upstream::Catalog};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use std::sync::Arc;

const EXECUTE_INSTRUCTIONS: &str = "The execute tool accepts a synchronous JavaScript function body. Write statements directly; do not wrap them in a function or arrow function, do not use async/await, and do not return a Promise. Include an explicit return statement (use `return null;` for intentional empty output). Discovery is literal case-insensitive substring matching, not semantic search. If a task phrase finds nothing, use `return codemode.search('');` to enumerate the full catalog. `codemode.describe()` and `codemode.call()` require the immutable `<integration-id>.<tool-name>` target returned by search, never an integration label or bare tool name. Some providers, including Cloudflare, expose a nested search/execution surface: find and describe that upstream search tool, then call it to locate the provider operation. Prefer an object-shaped final result for broad MCP-client compatibility. Authorization: upstreamConnected reports whether cog is connected to the provider; clientAccessGranted reports whether this calling client has downstream access. If clientAccessGranted=false, call describe or call so cog returns the OAuth insufficient_scope challenge. Reauthorize and refresh this same MCP client's credential; a new process or registration is a different client and does not inherit grants. Never use integration_reconnect for a downstream grant: it replaces upstream provider credentials and cannot authorize the calling client. In code-mode-only mode, Git tools use the `git.repository_access`, `git.ssh_certificate_status`, `git.ssh_certificate`, and `git.renew_ssh_certificate` targets. Call repository_access first and reuse an existing local Ed25519 identity from SSH configuration or the SSH agent. If a saved COG certificate exists, call ssh_certificate_status and reuse it while valid. For initial enrollment call ssh_certificate with only the existing public key. After expiry call renew_ssh_certificate with the same public key and previous certificate. Store the returned certificate separately, pass it with CertificateFile, pin knownHosts, and use sshRemoteUrl for clone, fetch, and push. On SSH authentication failure, renew the certificate; never recreate the identity. Never send or replace the private key, generate a key automatically, disable host-key checking, or discard reusable SSH material. If no Ed25519 identity exists, report that one must be provisioned.";
const HYBRID_INSTRUCTIONS: &str = "External integration tools are available through execute and are never expanded into the top-level tool list. COG-native tools are also advertised directly in this default mode. Calling a tool may request incremental OAuth authorization; reauthorize and refresh this same MCP client's credential because a new process or registration is a different client and does not inherit grants. For Git, call repository_access first and reuse an existing local Ed25519 identity from SSH configuration or the SSH agent. Check a saved COG certificate with ssh_certificate_status and reuse it while valid. For initial enrollment call ssh_certificate with only the existing public key; after expiry call renew_ssh_certificate with the same public key and previous certificate. Store the certificate separately, pass it with CertificateFile, pin knownHosts, and use sshRemoteUrl for clone, fetch, and push. On SSH authentication failure, renew the certificate; never recreate the identity. Never send or replace the private key, generate a key automatically, disable host-key checking, or discard reusable SSH material. If no Ed25519 identity exists, report that one must be provisioned.";

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
                json!({"name":"execute","description":format!("Run JavaScript in an isolated V8 runtime. {EXECUTE_INSTRUCTIONS}"),"inputSchema":{"type":"object","properties":{"code":{"type":"string","description":EXECUTE_INSTRUCTIONS}},"required":["code"],"additionalProperties":false},"securitySchemes":[{"type":"oauth2","scopes":["mcp"]}],"_meta":{"securitySchemes":[{"type":"oauth2","scopes":["mcp"]}]}}),
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
        "repository_access"
        | "ssh_certificate_status"
        | "ssh_certificate"
        | "renew_ssh_certificate" => Some(format!("git.{name}")),
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::upstream::{Tool, ToolProvider};
    use async_trait::async_trait;
    use proptest::prelude::*;

    struct NativeFixture;
    #[async_trait]
    impl ToolProvider for NativeFixture {
        async fn tools(&self) -> anyhow::Result<Vec<Tool>> {
            Ok(vec![
                Tool {
                    name: "repository_access".into(),
                    description: None,
                    input_schema: json!({}),
                    extra: serde_json::Map::new(),
                },
                Tool {
                    name: "object".into(),
                    description: None,
                    input_schema: json!({}),
                    extra: serde_json::Map::new(),
                },
                Tool {
                    name: "scalar".into(),
                    description: None,
                    input_schema: json!({}),
                    extra: serde_json::Map::new(),
                },
                Tool {
                    name: "scope".into(),
                    description: None,
                    input_schema: json!({}),
                    extra: serde_json::Map::new(),
                },
            ])
        }
        async fn call(&self, name: &str, _args: Value) -> anyhow::Result<Value> {
            match name {
                "object" | "repository_access" => Ok(json!({"ok": true})),
                "scalar" => Ok(json!(7)),
                "scope" => Err(InsufficientScope::one("integration:fixture").into()),
                _ => anyhow::bail!("fixture failure"),
            }
        }
    }

    async fn request(
        method: &str,
        params: Value,
        codemode: bool,
        catalog: Arc<Catalog>,
    ) -> RpcResponse {
        handle_with_options(
            RpcRequest {
                jsonrpc: "2.0".into(),
                id: Some(json!(1)),
                method: method.into(),
                params,
            },
            Arc::new(CodeRuntime::new(16, std::time::Duration::from_secs(1))),
            catalog,
            "/metadata",
            codemode,
        )
        .await
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn validation_native_calls_and_error_shapes() {
        let mut fixture = Catalog::new();
        fixture.add("git".into(), Arc::new(NativeFixture));
        fixture.add("cog".into(), Arc::new(NativeFixture));
        let fixture = Arc::new(fixture);

        let invalid = handle(
            RpcRequest {
                jsonrpc: "1.0".into(),
                id: None,
                method: "ping".into(),
                params: json!({}),
            },
            Arc::new(CodeRuntime::new(16, std::time::Duration::from_secs(1))),
            fixture.clone(),
        )
        .await;
        assert_eq!(invalid.error.unwrap()["code"], -32600);
        for params in [
            json!({}),
            json!({"protocolVersion":1,"capabilities":{},"clientInfo":{}}),
        ] {
            assert_eq!(
                request("initialize", params, true, fixture.clone())
                    .await
                    .error
                    .unwrap()["code"],
                -32602
            );
        }
        assert_eq!(
            request(
                "initialize",
                json!({"protocolVersion":"future","capabilities":{},"clientInfo":{}}),
                true,
                fixture.clone()
            )
            .await
            .result
            .unwrap()["protocolVersion"],
            LATEST_PROTOCOL_VERSION
        );
        assert!(
            request("ping", json!({}), true, fixture.clone())
                .await
                .result
                .is_some()
        );
        assert!(
            request(
                "notifications/initialized",
                json!({}),
                true,
                fixture.clone()
            )
            .await
            .result
            .is_some()
        );
        assert_eq!(
            request("missing", json!({}), true, fixture.clone())
                .await
                .error
                .unwrap()["code"],
            -32601
        );
        assert_eq!(
            request("tools/call", json!({}), true, fixture.clone())
                .await
                .error
                .unwrap()["message"],
            "tool name is required"
        );
        assert_eq!(
            request(
                "tools/call",
                json!({"name":"missing"}),
                true,
                fixture.clone()
            )
            .await
            .error
            .unwrap()["message"],
            "unknown tool"
        );
        assert_eq!(
            request(
                "tools/call",
                json!({"name":"execute"}),
                true,
                fixture.clone()
            )
            .await
            .error
            .unwrap()["message"],
            "code is required"
        );

        let listed = request("tools/list", json!({}), false, fixture.clone())
            .await
            .result
            .unwrap();
        assert!(listed["tools"].as_array().unwrap().len() >= 7);
        for (name, expected) in [
            ("repository_access", json!({"ok":true})),
            ("cog_scalar", json!(7)),
        ] {
            let response = request(
                "tools/call",
                json!({"name":name,"arguments":{}}),
                false,
                fixture.clone(),
            )
            .await
            .result
            .unwrap();
            assert_eq!(
                response["structuredContent"],
                if expected.is_object() {
                    expected
                } else {
                    json!({"result":expected})
                }
            );
        }
        let scoped = request(
            "tools/call",
            json!({"name":"cog_scope"}),
            false,
            fixture.clone(),
        )
        .await
        .result
        .unwrap();
        assert_eq!(scoped["structuredContent"]["error"], "insufficient_scope");
        assert_eq!(
            scoped["structuredContent"]["requiredScopes"],
            json!(["mcp", "integration:fixture"])
        );
        let execute_scoped = request(
            "tools/call",
            json!({"name":"execute","arguments":{"code":"return codemode.call('cog.scope',{});"}}),
            true,
            fixture.clone(),
        )
        .await
        .result
        .unwrap();
        assert_eq!(
            execute_scoped["structuredContent"]["requiredScopes"],
            json!(["mcp", "integration:fixture"])
        );
        let failed = request("tools/call", json!({"name":"cog_missing"}), false, fixture)
            .await
            .result
            .unwrap();
        assert_eq!(failed["isError"], true);
    }
    #[tokio::test(flavor = "multi_thread")]
    async fn protocol() {
        let rt = Arc::new(CodeRuntime::new(16, std::time::Duration::from_secs(2)));
        let c = Arc::new(Catalog::new());
        let r = handle(
            RpcRequest {
                jsonrpc: "2.0".into(),
                id: Some(json!(1)),
                method: "tools/list".into(),
                params: json!({}),
            },
            rt.clone(),
            c.clone(),
        )
        .await;
        let tools = r.result.unwrap()["tools"].clone();
        assert!(tools.is_array());
        assert_eq!(tools[0]["securitySchemes"][0]["scopes"], json!(["mcp"]));
        assert_eq!(
            tools[0]["_meta"]["securitySchemes"],
            tools[0]["securitySchemes"]
        );
        let r = handle(
            RpcRequest {
                jsonrpc: "2.0".into(),
                id: Some(json!(2)),
                method: "tools/call".into(),
                params: json!({"name":"execute","arguments":{"code":"return 6*7"}}),
            },
            rt,
            c,
        )
        .await;
        assert_eq!(
            r.result.unwrap()["structuredContent"],
            json!({ "result": 42 })
        );

        for (code, value) in [
            ("return [1, 2, 3]", json!([1, 2, 3])),
            ("return 'hello'", json!("hello")),
            ("return null", Value::Null),
        ] {
            let response = handle(
                RpcRequest {
                    jsonrpc: "2.0".into(),
                    id: Some(json!(2)),
                    method: "tools/call".into(),
                    params: json!({"name":"execute","arguments":{"code":code}}),
                },
                Arc::new(CodeRuntime::new(16, std::time::Duration::from_secs(2))),
                Arc::new(Catalog::new()),
            )
            .await;
            let result = response.result.unwrap();
            assert_eq!(result["structuredContent"], json!({ "result": value }));
            assert_eq!(
                result["content"][0]["text"],
                serde_json::to_string(&value).unwrap()
            );
        }
        for (version, method, params) in [
            ("1.0", "ping", json!({})),
            ("2.0", "missing", json!({})),
            ("2.0", "tools/call", json!({"name":"bad"})),
            (
                "2.0",
                "tools/call",
                json!({"name":"execute","arguments":{}}),
            ),
        ] {
            let r = handle(
                RpcRequest {
                    jsonrpc: version.into(),
                    id: Some(json!(3)),
                    method: method.into(),
                    params,
                },
                Arc::new(CodeRuntime::new(16, std::time::Duration::from_secs(1))),
                Arc::new(Catalog::new()),
            )
            .await;
            assert!(r.error.is_some());
        }
        let ping = handle(
            RpcRequest {
                jsonrpc: "2.0".into(),
                id: Some(json!(4)),
                method: "ping".into(),
                params: json!({}),
            },
            Arc::new(CodeRuntime::new(16, std::time::Duration::from_secs(1))),
            Arc::new(Catalog::new()),
        )
        .await;
        assert!(ping.result.is_some());
        let init = handle(
            RpcRequest {
                jsonrpc: "2.0".into(),
                id: Some(json!(5)),
                method: "initialize".into(),
                params: json!({
                    "protocolVersion":"2025-06-18",
                    "capabilities":{},
                    "clientInfo":{"name":"test","version":"1"}
                }),
            },
            Arc::new(CodeRuntime::new(16, std::time::Duration::from_secs(1))),
            Arc::new(Catalog::new()),
        )
        .await;
        let init = init.result.unwrap();
        assert_eq!(init["serverInfo"]["name"], "cog");
        assert_eq!(init["protocolVersion"], "2025-06-18");
        let latest = handle(
            RpcRequest {
                jsonrpc: "2.0".into(),
                id: Some(json!(6)),
                method: "initialize".into(),
                params: json!({
                    "protocolVersion":"2025-11-25",
                    "capabilities":{},
                    "clientInfo":{"name":"test","version":"1"}
                }),
            },
            Arc::new(CodeRuntime::new(16, std::time::Duration::from_secs(1))),
            Arc::new(Catalog::new()),
        )
        .await;
        assert_eq!(latest.result.unwrap()["protocolVersion"], "2025-11-25");
        let invalid_init = handle(
            RpcRequest {
                jsonrpc: "2.0".into(),
                id: Some(json!(55)),
                method: "initialize".into(),
                params: json!({}),
            },
            Arc::new(CodeRuntime::new(16, std::time::Duration::from_secs(1))),
            Arc::new(Catalog::new()),
        )
        .await;
        assert_eq!(invalid_init.error.unwrap()["code"], -32602);
        let failure = handle(
            RpcRequest {
                jsonrpc: "2.0".into(),
                id: Some(json!(6)),
                method: "tools/call".into(),
                params: json!({"name":"execute","arguments":{"code":"throw new Error('expected')"}}),
            },
            Arc::new(CodeRuntime::new(16, std::time::Duration::from_secs(1))),
            Arc::new(Catalog::new()),
        )
        .await;
        assert_eq!(failure.result.unwrap()["isError"], true);
    }

    #[tokio::test]
    async fn hybrid_mode_keeps_execute_available() {
        let runtime = Arc::new(CodeRuntime::new(16, std::time::Duration::from_secs(1)));
        let catalog = Arc::new(Catalog::new());
        let initialized = handle_with_options(
            RpcRequest {
                jsonrpc: "2.0".into(),
                id: Some(json!(1)),
                method: "initialize".into(),
                params: json!({
                    "protocolVersion":LATEST_PROTOCOL_VERSION,
                    "capabilities":{},
                    "clientInfo":{"name":"test","version":"1"}
                }),
            },
            runtime.clone(),
            catalog.clone(),
            "/metadata",
            false,
        )
        .await;
        let instructions = initialized.result.unwrap()["instructions"]
            .as_str()
            .unwrap()
            .to_owned();
        assert!(instructions.contains("advertised directly"));
        assert!(instructions.contains("External integration tools"));

        let listed = handle_with_options(
            RpcRequest {
                jsonrpc: "2.0".into(),
                id: Some(json!(2)),
                method: "tools/list".into(),
                params: json!({}),
            },
            runtime.clone(),
            catalog.clone(),
            "/metadata",
            false,
        )
        .await;
        assert_eq!(listed.result.unwrap()["tools"][0]["name"], "execute");

        let execute = handle_with_options(
            RpcRequest {
                jsonrpc: "2.0".into(),
                id: Some(json!(3)),
                method: "tools/call".into(),
                params: json!({"name":"execute","arguments":{"code":"return 42"}}),
            },
            runtime,
            catalog,
            "/metadata",
            false,
        )
        .await;
        assert_eq!(execute.result.unwrap()["structuredContent"]["result"], 42);
    }

    proptest! {
        #[test]
        fn json_rpc_deserializer_never_panics(bytes in prop::collection::vec(any::<u8>(), 0..8192)) {
            let _ = serde_json::from_slice::<RpcRequest>(&bytes);
        }
    }
}
