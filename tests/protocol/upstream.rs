use async_trait::async_trait;
use axum::{
    Router, body::Bytes as AxumBytes, extract::State, response::IntoResponse, routing::post,
};
use cog::mcp::client::*;
use cog::mcp::{Catalog, Tool, ToolProvider};
use proptest::prelude::*;
use serde_json::{Value, json};
use std::{
    collections::HashMap,
    sync::{
        Arc,
        atomic::{AtomicBool, AtomicUsize, Ordering},
    },
    time::Duration,
};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
struct Fake;
#[async_trait]
impl ToolProvider for Fake {
    async fn tools(&self) -> anyhow::Result<Vec<Tool>> {
        Ok(vec![Tool {
            name: "send".into(),
            title: None,
            description: Some("Send mail".into()),
            input_schema: json!({"type":"object"}),
            extra: serde_json::Map::new(),
        }])
    }
    async fn call(&self, n: &str, a: Value) -> anyhow::Result<Value> {
        Ok(json!([n, a]))
    }
}
#[tokio::test]
async fn catalog() {
    let mut c = Catalog::default();
    c.add("mail".into(), Arc::new(Fake));
    assert_eq!(c.search("mail").await.unwrap().as_array().unwrap().len(), 1);
    assert_eq!(c.search("").await.unwrap().as_array().unwrap().len(), 1);
    assert_eq!(c.describe("mail.send").await.unwrap()["name"], "send");
    assert_eq!(
        c.call("mail.send", json!({"x":1})).await.unwrap()[0],
        "send"
    );

    c.add_discoverable("locked".into(), "Locked mail".into(), Arc::new(Fake));
    let locked = c.search("locked").await.unwrap();
    assert_eq!(locked[0]["authorized"], false);
    assert_eq!(locked[0]["upstreamConnected"], true);
    assert_eq!(locked[0]["clientAccessGranted"], false);
    assert_eq!(locked[0]["authorizationRequired"], true);
    assert_eq!(locked[0]["requiredScope"], "integration:locked");
    let direct = c.direct_tools("cog").await.unwrap();
    assert_eq!(direct.len(), 2);
    assert!(direct.iter().any(|tool| tool.name == "mail.send"));
    let locked = direct
        .iter()
        .find(|tool| tool.name == "locked.send")
        .unwrap();
    assert_eq!(
        locked.extra["securitySchemes"][0]["scopes"],
        json!(["integration:locked"])
    );
    assert!(c.describe("locked.send").await.is_err());
    assert!(c.call("locked.send", json!({})).await.is_err());
    assert!(c.describe("bad").await.is_err());
    assert!(c.describe("none.send").await.is_err());
    assert!(c.describe("mail.none").await.is_err());
    assert!(c.call("bad", json!({})).await.is_err());
    assert!(c.call("none.x", json!({})).await.is_err());

    c.add_unavailable("offline".into(), "Offline mail".into(), "expired", false);
    let offline = c.search("offline").await.unwrap();
    assert_eq!(offline[0]["upstreamConnected"], false);
    assert_eq!(offline[0]["upstreamStatus"], "expired");
    assert_eq!(offline[0]["clientAccessGranted"], false);
    assert_eq!(offline[0]["requiredScope"], "integration:offline");
    Arc::new(Fake).close().await.unwrap();
    assert_eq!(
        parse_sse_json(
            "data: {\"jsonrpc\":\"2.0\",\"id\":1,\"result\":null}\n\n",
            1
        )
        .unwrap()["result"],
        Value::Null
    );
}

#[test]
fn parses_and_validates_upstream_scope_challenges() {
    let challenge = r#"Bearer error="insufficient_scope", scope="account:read workers:write", resource_metadata="https://mcp.example/.well-known/oauth-protected-resource""#;
    let parsed =
        parse_upstream_insufficient_scope(reqwest::StatusCode::FORBIDDEN, challenge).unwrap();
    assert_eq!(parsed.scopes, ["account:read", "workers:write"]);
    assert_eq!(
        parsed.to_string(),
        "upstream MCP requires additional OAuth scope: account:read workers:write"
    );
    assert!(std::error::Error::source(&parsed).is_none());
    assert_eq!(
        parsed.resource_metadata,
        "https://mcp.example/.well-known/oauth-protected-resource"
    );
    assert!(
        parse_upstream_insufficient_scope(reqwest::StatusCode::UNAUTHORIZED, challenge).is_err()
    );
    assert!(
        parse_upstream_insufficient_scope(
            reqwest::StatusCode::FORBIDDEN,
            r#"Bearer error="insufficient_scope", scope="x""#
        )
        .is_err()
    );
    assert!(parse_upstream_insufficient_scope(reqwest::StatusCode::FORBIDDEN, r#"Bearer error="insufficient_scope", scope="x", resource_metadata="http://example.com/meta""#).is_err());
    for malformed in [
        r#"Basic error="insufficient_scope""#,
        r#"Bearer error="insufficient_scope"#,
        "Bearer error=\"bad\rvalue\"",
    ] {
        assert!(bearer_parameter(malformed, "error").is_none());
    }
}

#[tokio::test]
async fn search_explains_literal_matching_targets_and_broad_fallback() {
    let mut catalog = Catalog::new();
    catalog.add_labeled("immutable-id".into(), "Cloudflare".into(), Arc::new(Fake));
    let match_result = catalog.search("send mail").await.unwrap();
    assert_eq!(match_result[0]["target"], "immutable-id.send");
    assert_eq!(match_result[0]["searchMode"], "literalSubstring");
    let miss = catalog.search("semantic task phrase").await.unwrap();
    assert_eq!(miss[0]["matches"], false);
    assert_eq!(miss[0]["broadDiscoveryFallback"], "codemode.search('')");
}

#[tokio::test]
async fn nested_code_mode_provider_is_discovered_then_used_for_provider_discovery() {
    struct NestedProvider;
    #[async_trait]
    impl ToolProvider for NestedProvider {
        async fn tools(&self) -> anyhow::Result<Vec<Tool>> {
            Ok(vec![Tool {
                name: "search".into(),
                title: None,
                description: Some("Search Cloudflare operations before executing one".into()),
                input_schema: json!({"type":"object","properties":{"query":{"type":"string"}}}),
                extra: Default::default(),
            }])
        }

        async fn call(&self, name: &str, args: Value) -> anyhow::Result<Value> {
            anyhow::ensure!(name == "search", "unexpected outer tool");
            anyhow::ensure!(
                args["query"] == "purge cache",
                "provider query was not forwarded"
            );
            Ok(json!({
                "operation":"zones.cache.purge",
                "invokeWith":{"zone_id":"zone-1"}
            }))
        }
    }

    let mut catalog = Catalog::new();
    catalog.add_labeled(
        "cloudflare-id".into(),
        "Cloudflare".into(),
        Arc::new(NestedProvider),
    );
    let outer = catalog.search("Cloudflare operations").await.unwrap();
    assert_eq!(outer[0]["target"], "cloudflare-id.search");
    let described = catalog.describe("cloudflare-id.search").await.unwrap();
    assert_eq!(described["name"], "search");
    let provider_result = catalog
        .call("cloudflare-id.search", json!({"query":"purge cache"}))
        .await
        .unwrap();
    assert_eq!(provider_result["operation"], "zones.cache.purge");
    assert_eq!(provider_result["invokeWith"]["zone_id"], "zone-1");
}

#[tokio::test]
async fn stdio_process_is_persistent() {
    let dir = tempfile::tempdir().unwrap();
    let marker = dir.path().join("starts");
    let script = r#"
echo started >> "$1"
i=0
while IFS= read -r line; do
  case "$line" in
*'"id":0'*) printf '%s\n' '{"jsonrpc":"2.0","id":0,"result":{"protocolVersion":"2025-06-18","capabilities":{},"serverInfo":{"name":"fixture","version":"1"}}}' ;;
*'"method":"tools/list"'*) i=$((i+1)); printf '{"jsonrpc":"2.0","id":%s,"result":{"tools":[{"name":"echo","inputSchema":{"type":"object"}}]}}\n' "$i" ;;
  esac
done
"#;
    let provider = StdioMcp::new(
        "sh".into(),
        vec![
            "-c".into(),
            script.into(),
            "fixture".into(),
            marker.display().to_string(),
        ],
        HashMap::new(),
    );
    assert_eq!(provider.tools().await.unwrap()[0].name, "echo");
    assert_eq!(provider.tools().await.unwrap()[0].name, "echo");
    assert_eq!(std::fs::read_to_string(marker).unwrap().lines().count(), 1);
    provider.close().await.unwrap();
}

#[tokio::test]
async fn fixture_stdio_covers_discovery_calls_and_malformed_output() {
    let fixture = format!("{}/tests/fixtures/stdio-mcp.sh", env!("CARGO_MANIFEST_DIR"));
    let provider = StdioMcp::new("sh".into(), vec![fixture.clone()], HashMap::new());
    assert_eq!(provider.tools().await.unwrap()[0].name, "echo");
    let result = provider.call("echo", json!({"value":42})).await.unwrap();
    assert_eq!(result["structuredContent"]["value"], 42);

    let malformed = StdioMcp::new(
        "sh".into(),
        vec![fixture],
        HashMap::from([("COG_STDIO_FIXTURE_MODE".into(), "malformed".into())]),
    );
    assert!(malformed.tools().await.is_err());
}

#[tokio::test]
async fn stdio_restarts_safe_discovery_after_crash() {
    let dir = tempfile::tempdir().unwrap();
    let marker = dir.path().join("starts");
    let script = r#"
echo x >> "$1"
count=$(wc -l < "$1")
while IFS= read -r line; do
  case "$line" in
*'"id":0'*) printf '%s\n' '{"jsonrpc":"2.0","id":0,"result":{"protocolVersion":"2025-06-18","capabilities":{},"serverInfo":{"name":"fixture","version":"1"}}}' ;;
*'"method":"tools/list"'*)
  if [ "$count" -eq 1 ]; then exit 7; fi
  id=$(printf '%s' "$line" | sed -n 's/.*"id":\([0-9]*\).*/\1/p')
  printf '{"jsonrpc":"2.0","id":%s,"result":{"tools":[{"name":"ok","inputSchema":{}}]}}\n' "$id" ;;
  esac
done
"#;
    let provider = StdioMcp::new(
        "sh".into(),
        vec![
            "-c".into(),
            script.into(),
            "fixture".into(),
            marker.display().to_string(),
        ],
        HashMap::new(),
    );
    assert_eq!(provider.tools().await.unwrap()[0].name, "ok");
    assert_eq!(std::fs::read_to_string(marker).unwrap().lines().count(), 2);
}

#[tokio::test(start_paused = true)]
async fn stdio_hang_is_killed_at_deadline_with_bounded_diagnostics() {
    let dir = tempfile::tempdir().unwrap();
    let marker = dir.path().join("starts");
    let script = r#"
while IFS= read -r line; do
  case "$line" in
*'"id":0'*) printf '%s\n' '{"jsonrpc":"2.0","id":0,"result":{"protocolVersion":"2025-06-18","capabilities":{},"serverInfo":{"name":"fixture","version":"1"}}}' ;;
*'"method":"tools/list"'*)
  echo x >> "$1"
  i=0
  while [ "$i" -lt 2000 ]; do echo diagnostic-output >&2; i=$((i + 1)); done
  sleep 300 ;;
  esac
done
"#;
    let provider = Arc::new(StdioMcp::new(
        "sh".into(),
        vec![
            "-c".into(),
            script.into(),
            "fixture".into(),
            marker.display().to_string(),
        ],
        HashMap::new(),
    ));
    let request = {
        let provider = provider.clone();
        tokio::spawn(async move { provider.tools().await })
    };
    for expected in 1..=2 {
        for _ in 0..1000 {
            let starts = std::fs::read_to_string(&marker)
                .map(|value| value.lines().count())
                .unwrap_or(0);
            if starts >= expected {
                break;
            }
            tokio::task::yield_now().await;
            std::thread::sleep(Duration::from_millis(1));
        }
        assert_eq!(
            std::fs::read_to_string(&marker).unwrap().lines().count(),
            expected
        );
        tokio::time::advance(Duration::from_secs(31)).await;
    }
    let error = format!("{:#}", request.await.unwrap().unwrap_err());
    assert!(error.contains("timed out"));
    assert!(error.len() <= MAX_DIAGNOSTIC_BYTES + 256);
}

#[tokio::test]
async fn cancelling_stdio_rpc_terminates_the_supervised_process() {
    let dir = tempfile::tempdir().unwrap();
    let marker = dir.path().join("called");
    let script = r#"
while IFS= read -r line; do
  case "$line" in
*'"id":0'*) printf '%s\n' '{"jsonrpc":"2.0","id":0,"result":{"protocolVersion":"2025-06-18","capabilities":{},"serverInfo":{"name":"fixture","version":"1"}}}' ;;
*'"method":"tools/list"'*) sleep 30 & echo $! > "$1"; wait ;;
  esac
done
"#;
    let provider = Arc::new(StdioMcp::new(
        "sh".into(),
        vec![
            "-c".into(),
            script.into(),
            "fixture".into(),
            marker.display().to_string(),
        ],
        HashMap::new(),
    ));
    let running = {
        let provider = provider.clone();
        tokio::spawn(async move { provider.tools().await })
    };
    for _ in 0..100 {
        if marker.exists() {
            break;
        }
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
    assert!(marker.exists());
    let child = std::fs::read_to_string(&marker).unwrap();
    let child = child.trim();
    running.abort();
    let _ = running.await;
    for _ in 0..100 {
        let alive = std::process::Command::new("kill")
            .args(["-0", child])
            .stdout(std::process::Stdio::null())
            .stderr(std::process::Stdio::null())
            .status()
            .is_ok_and(|status| status.success());
        if !alive {
            return;
        }
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
    panic!("cancelled stdio MCP process remained alive");
}

#[tokio::test]
async fn every_transport_rejects_oversized_requests_before_io() {
    let huge = "x".repeat(MAX_MESSAGE_BYTES);
    let http = HttpMcp::new("http://127.0.0.1:1".into(), HashMap::new());
    let error = http
        .rpc_request("tools/call", json!({"value":huge}))
        .await
        .unwrap_err();
    assert!(error.to_string().contains("request too large"));

    let script = r#"while IFS= read -r line; do case "$line" in *'"id":0'*) printf '%s\n' '{"jsonrpc":"2.0","id":0,"result":{"protocolVersion":"2025-06-18","capabilities":{},"serverInfo":{"name":"fixture","version":"1"}}}' ;; esac; done"#;
    let stdio = StdioMcp::new(
        "sh".into(),
        vec!["-c".into(), script.into()],
        HashMap::new(),
    );
    let error = stdio
        .call("echo", json!({"value":"x".repeat(MAX_MESSAGE_BYTES)}))
        .await
        .unwrap_err();
    assert!(error.to_string().contains("request too large"));
}

#[tokio::test]
async fn stdio_output_limit_is_enforced_while_streaming() {
    let script = r#"
while IFS= read -r line; do
  case "$line" in
*'"id":0'*) printf '%s\n' '{"jsonrpc":"2.0","id":0,"result":{"protocolVersion":"2025-06-18","capabilities":{},"serverInfo":{"name":"fixture","version":"1"}}}' ;;
*'"method":"tools/list"'*) head -c 1048577 /dev/zero | tr '\0' x ;;
  esac
done
"#;
    let provider = StdioMcp::new(
        "sh".into(),
        vec!["-c".into(), script.into()],
        HashMap::new(),
    );
    let error = format!("{:#}", provider.tools().await.unwrap_err());
    assert!(error.contains("response too large"));
}

#[test]
fn parses_chunk_agnostic_multiline_sse_events() {
    let body = concat!(
        ": keepalive\r\n",
        "event: message\r\n",
        "data: {\"jsonrpc\":\"2.0\",\r\n",
        "data: \"method\":\"notifications/tools/list_changed\"}\r\n\r\n",
        "id: event-2\r\n",
        "data: {\"jsonrpc\":\"2.0\",\"id\":7,\"result\":{\"ok\":true}}\r\n\r\n"
    );
    assert_eq!(parse_sse_json(body, 7).unwrap()["result"]["ok"], true);
    assert!(parse_sse_json(body, 8).is_err());
}

#[test]
fn initialize_conformance_rejects_unsupported_or_incomplete_servers() {
    let valid = json!({
        "protocolVersion": MCP_PROTOCOL_VERSION,
        "capabilities": {},
        "serverInfo": {"name":"fixture","version":"1"}
    });
    assert!(validate_initialize(&valid).is_ok());
    assert!(
        validate_initialize(&json!({
            "protocolVersion":"2024-11-05",
            "capabilities":{},
            "serverInfo":{}
        }))
        .is_err()
    );
    assert!(validate_initialize(&json!({"protocolVersion":MCP_PROTOCOL_VERSION})).is_err());
}

#[tokio::test]
async fn legacy_sse_discovers_endpoint_and_keeps_stream() {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    let server = tokio::spawn(async move {
        let (mut events, _) = listener.accept().await.unwrap();
        let mut request = vec![0; 4096];
        let _ = events.read(&mut request).await.unwrap();
        events
            .write_all(b"HTTP/1.1 200 OK\r\nContent-Type: text/event-stream\r\nTransfer-Encoding: chunked\r\n\r\n")
            .await
            .unwrap();
        write_chunk(&mut events, "event: endpoint\ndata: /messages\n\n").await;

        for (id, result) in [
            (
                Some(1),
                json!({"protocolVersion":"2025-06-18","capabilities":{},"serverInfo":{"name":"fixture","version":"1"}}),
            ),
            (None, Value::Null),
            (
                Some(2),
                json!({"tools":[{"name":"echo","inputSchema":{"type":"object"}}]}),
            ),
        ] {
            let (mut post, _) = listener.accept().await.unwrap();
            let mut request = vec![0; 4096];
            let _ = post.read(&mut request).await.unwrap();
            post.write_all(
                b"HTTP/1.1 202 Accepted\r\nContent-Length: 0\r\nConnection: close\r\n\r\n",
            )
            .await
            .unwrap();
            if let Some(id) = id {
                write_chunk(
                    &mut events,
                    &format!(
                        "event: message\ndata: {}\n\n",
                        json!({"jsonrpc":"2.0","id":id,"result":result})
                    ),
                )
                .await;
            }
        }
    });

    let provider = HttpMcp::new_sse(format!("http://{address}/sse"), HashMap::new());
    let tools = provider.tools().await.unwrap();
    assert_eq!(tools[0].name, "echo");
    server.await.unwrap();
}

#[derive(Clone, Default)]
struct StreamableFixture {
    session_requests: Arc<AtomicUsize>,
    deleted: Arc<AtomicBool>,
}

async fn streamable_fixture(
    State(state): State<StreamableFixture>,
    method: axum::http::Method,
    headers: axum::http::HeaderMap,
    body: AxumBytes,
) -> axum::response::Response {
    if method == axum::http::Method::DELETE {
        assert_eq!(
            headers
                .get("MCP-Protocol-Version")
                .and_then(|value| value.to_str().ok()),
            Some(MCP_PROTOCOL_VERSION)
        );
        if headers.get("Mcp-Session-Id").and_then(|v| v.to_str().ok()) == Some("session-1") {
            state.deleted.store(true, Ordering::SeqCst);
        }
        return axum::http::StatusCode::NO_CONTENT.into_response();
    }
    assert_eq!(
        headers
            .get(axum::http::header::ACCEPT)
            .and_then(|value| value.to_str().ok()),
        Some("application/json, text/event-stream")
    );
    if headers.get("Mcp-Session-Id").and_then(|v| v.to_str().ok()) == Some("session-1") {
        state.session_requests.fetch_add(1, Ordering::SeqCst);
    }
    let request: Value = serde_json::from_slice(&body).unwrap();
    if request.get("method").and_then(Value::as_str) != Some("initialize") {
        assert_eq!(
            headers
                .get("MCP-Protocol-Version")
                .and_then(|value| value.to_str().ok()),
            Some(MCP_PROTOCOL_VERSION)
        );
    }
    let Some(id) = request.get("id").cloned() else {
        return axum::http::StatusCode::ACCEPTED.into_response();
    };
    let result = match request.get("method").and_then(Value::as_str) {
        Some("initialize") => json!({
            "protocolVersion":MCP_PROTOCOL_VERSION,
            "capabilities":{"tools":{"listChanged":true}},
            "serverInfo":{"name":"fixture","version":"1"}
        }),
        Some("tools/list") => {
            json!({"tools":[{"name":"echo","inputSchema":{"type":"object"}}]})
        }
        _ => Value::Null,
    };
    (
        [("Mcp-Session-Id", "session-1")],
        axum::Json(json!({"jsonrpc":"2.0","id":id,"result":result})),
    )
        .into_response()
}

#[tokio::test]
async fn streamable_http_conforms_and_cleans_up_session() {
    let state = StreamableFixture::default();
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    let server = tokio::spawn(
        axum::serve(
            listener,
            Router::new()
                .route("/", post(streamable_fixture).delete(streamable_fixture))
                .with_state(state.clone()),
        )
        .into_future(),
    );
    let provider = HttpMcp::new(format!("http://{address}/"), HashMap::new());
    assert_eq!(provider.tools().await.unwrap()[0].name, "echo");
    assert!(state.session_requests.load(Ordering::SeqCst) >= 2);
    provider.close().await.unwrap();
    assert!(state.deleted.load(Ordering::SeqCst));
    server.abort();
}

async fn large_catalog_fixture(body: AxumBytes) -> axum::response::Response {
    let request: Value = serde_json::from_slice(&body).unwrap();
    let Some(id) = request.get("id").cloned() else {
        return axum::http::StatusCode::ACCEPTED.into_response();
    };
    let result = match request.get("method").and_then(Value::as_str) {
        Some("initialize") => json!({
            "protocolVersion":MCP_PROTOCOL_VERSION,
            "capabilities":{"tools":{}},
            "serverInfo":{"name":"large-catalog-fixture","version":"1"}
        }),
        Some("tools/list") => json!({"tools":[{
            "name":"large",
            "description":"x".repeat(MAX_MESSAGE_BYTES),
            "inputSchema":{"type":"object"}
        }]}),
        Some("tools/call") => json!({"content":[{
            "type":"text",
            "text":"x".repeat(MAX_MESSAGE_BYTES)
        }]}),
        _ => Value::Null,
    };
    axum::Json(json!({"jsonrpc":"2.0","id":id,"result":result})).into_response()
}

#[tokio::test]
async fn streamable_http_allows_large_tool_catalogs_but_bounds_tool_results() {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    let server = tokio::spawn(
        axum::serve(
            listener,
            Router::new().route("/", post(large_catalog_fixture)),
        )
        .into_future(),
    );
    let provider = HttpMcp::new(format!("http://{address}/"), HashMap::new());
    let tools = provider.tools().await.unwrap();
    assert_eq!(tools.len(), 1);
    assert_eq!(tools[0].name, "large");
    assert_eq!(
        tools[0].description.as_ref().unwrap().len(),
        MAX_MESSAGE_BYTES
    );

    let error = provider.call("large", json!({})).await.unwrap_err();
    assert!(error.to_string().contains("response too large"));
    server.abort();
}

async fn streamable_sse_fixture(body: AxumBytes) -> axum::response::Response {
    let request: Value = serde_json::from_slice(&body).unwrap();
    let Some(id) = request.get("id").cloned() else {
        return axum::http::StatusCode::ACCEPTED.into_response();
    };
    let response = match request.get("method").and_then(Value::as_str) {
        Some("initialize") => json!({"jsonrpc":"2.0","id":id,"result":{
            "protocolVersion":MCP_PROTOCOL_VERSION,"capabilities":{},
            "serverInfo":{"name":"sse-fixture","version":"1"}}}),
        Some("tools/list") => json!({"jsonrpc":"2.0","id":id,"result":{
            "tools":[{"name":"echo","inputSchema":{}}]}}),
        Some("tools/call") => json!({"jsonrpc":"2.0","id":id,"error":{
            "code":-32000,"message":"fixture failure","data":{"retryable":false}}}),
        _ => json!({"jsonrpc":"2.0","id":id,"result":null}),
    };
    (
        [(axum::http::header::CONTENT_TYPE, "text/event-stream")],
        format!(
            ": keepalive\nevent: message\ndata: {}\n\n",
            serde_json::to_string(&response).unwrap()
        ),
    )
        .into_response()
}

#[tokio::test]
async fn streamable_http_accepts_sse_and_preserves_json_rpc_errors() {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    let server = tokio::spawn(
        axum::serve(
            listener,
            Router::new().route("/", post(streamable_sse_fixture)),
        )
        .into_future(),
    );
    let provider = HttpMcp::new(format!("http://{address}/"), HashMap::new());
    assert_eq!(provider.tools().await.unwrap()[0].name, "echo");
    let error = provider.call("echo", json!({})).await.unwrap_err();
    assert!(error.to_string().contains("fixture failure"));
    assert!(error.to_string().contains("retryable"));
    server.abort();
}

#[tokio::test]
async fn legacy_cancellation_sends_protocol_notification() {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    let received = tokio::spawn(async move {
        let (mut stream, _) = listener.accept().await.unwrap();
        let mut request = vec![0; 8192];
        let size = stream.read(&mut request).await.unwrap();
        stream
            .write_all(b"HTTP/1.1 202 Accepted\r\nContent-Length: 0\r\nConnection: close\r\n\r\n")
            .await
            .unwrap();
        String::from_utf8(request[..size].to_vec()).unwrap()
    });
    drop(cancellation_guard(
        reqwest::Client::new(),
        HashMap::new(),
        format!("http://{address}/messages"),
        42,
        false,
        MCP_PROTOCOL_VERSION.to_owned(),
    ));
    let request = tokio::time::timeout(Duration::from_secs(1), received)
        .await
        .unwrap()
        .unwrap();
    assert!(request.contains("notifications/cancelled"));
    assert!(request.contains("requestId"));
}

async fn write_chunk(stream: &mut tokio::net::TcpStream, value: &str) {
    stream
        .write_all(format!("{:x}\r\n{value}\r\n", value.len()).as_bytes())
        .await
        .unwrap();
    stream.flush().await.unwrap();
}

proptest! {
    #[test]
    fn sse_parser_round_trips_json_rpc(id in any::<u64>(), text in "[a-zA-Z0-9 ]{0,128}") {
        let body = format!("event: message\ndata: {}\n\n", json!({"jsonrpc":"2.0","id":id,"result":{"text":text}}));
        let parsed = parse_sse_json(&body, id).unwrap();
        prop_assert_eq!(parsed["result"]["text"].as_str(), Some(text.as_str()));
    }

    #[test]
    fn sse_parser_never_panics(input in any::<String>(), id in any::<u64>()) {
        let _ = parse_sse_json(&input, id);
    }
}
