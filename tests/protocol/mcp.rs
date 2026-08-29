use async_trait::async_trait;
use cog::mcp::*;
use cog::{
    authz::InsufficientScope,
    runtime::CodeRuntime,
    upstream::{Catalog, Tool, ToolProvider},
};
use proptest::prelude::*;
use serde_json::{Value, json};
use std::sync::Arc;

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

struct FailingDiscovery;
#[async_trait]
impl ToolProvider for FailingDiscovery {
    async fn tools(&self) -> anyhow::Result<Vec<Tool>> {
        anyhow::bail!("discovery failed")
    }

    async fn call(&self, _name: &str, _args: Value) -> anyhow::Result<Value> {
        unreachable!()
    }
}

#[tokio::test]
async fn native_discovery_failure_is_a_bounded_rpc_error() {
    let mut catalog = Catalog::new();
    catalog.add("git".into(), Arc::new(FailingDiscovery));
    let response = handle_with_options(
        RpcRequest {
            jsonrpc: "2.0".into(),
            id: Some(json!(1)),
            method: "tools/list".into(),
            params: json!({}),
        },
        Arc::new(CodeRuntime::new(16, std::time::Duration::from_secs(1))),
        Arc::new(catalog),
        "/.well-known/oauth-protected-resource",
        false,
    )
    .await;
    assert_eq!(response.error.unwrap()["code"], -32603);
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
