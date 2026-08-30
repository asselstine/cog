use async_trait::async_trait;
use axum::{
    Router,
    body::Bytes,
    extract::State,
    http::{HeaderMap, Method, StatusCode},
    response::{IntoResponse, Response},
    routing::post,
};
use cog::mcp::{
    Catalog, Tool, ToolProvider,
    client::{
        HttpMcp, MAX_DIAGNOSTIC_BYTES, StdioMcp, bearer_parameter,
        parse_upstream_insufficient_scope,
    },
    model::{
        META_CLIENT_ACCESS_GRANTED, META_INTEGRATION_LABEL, META_REQUIRED_SCOPE,
        META_SECURITY_SCHEMES,
    },
};
use serde_json::{Value, json};
use std::{
    collections::HashMap,
    sync::{
        Arc,
        atomic::{AtomicBool, AtomicUsize, Ordering},
    },
    time::Duration,
};

struct Fake;

#[async_trait]
impl ToolProvider for Fake {
    async fn tools(&self) -> anyhow::Result<Vec<Tool>> {
        Ok(vec![Tool::new(
            "send",
            "Send mail",
            json!({"type":"object"}).as_object().unwrap().clone(),
        )])
    }

    async fn call(&self, name: &str, args: Value) -> anyhow::Result<Value> {
        Ok(json!([name, args]))
    }
}

struct Broken;

#[async_trait]
impl ToolProvider for Broken {
    async fn tools(&self) -> anyhow::Result<Vec<Tool>> {
        anyhow::bail!("fixture unavailable")
    }

    async fn call(&self, _name: &str, _args: Value) -> anyhow::Result<Value> {
        anyhow::bail!("fixture unavailable")
    }
}

#[tokio::test]
async fn catalog_routes_sdk_tools_and_restricts_runtime_integrations() {
    let mut catalog = Catalog::default();
    catalog.add("mail".into(), Arc::new(Fake));
    catalog.add("other".into(), Arc::new(Fake));
    assert_eq!(catalog.describe("mail.send").await.unwrap()["name"], "send");
    assert_eq!(
        catalog.call("mail.send", json!({"x":1})).await.unwrap()[0],
        "send"
    );
    catalog.retain_runtime_integrations(&["mail".to_owned()].into_iter().collect());
    assert!(catalog.describe("other.send").await.is_err());
}

#[tokio::test]
async fn catalog_reports_discovery_authorization_and_availability_states() {
    let mut catalog = Catalog::new();
    catalog.add_labeled("mail-id".into(), "Mail".into(), Arc::new(Fake));
    catalog.add_discoverable("locked".into(), "Locked Mail".into(), Arc::new(Fake));
    catalog.add_unavailable("legacy".into(), "Legacy".into(), "unsupported", false);
    catalog.add_unavailable("offline".into(), "Offline".into(), "expired", true);
    catalog.add_labeled("broken".into(), "Broken".into(), Arc::new(Broken));

    let all = catalog.search("").await.unwrap();
    assert!(all.as_array().unwrap().len() >= 4);
    let locked = catalog.search("locked").await.unwrap();
    assert_eq!(locked[0]["integration"], "locked");
    assert_eq!(locked[0]["clientAccessGranted"], false);
    assert_eq!(locked[0]["authorizationRequired"], true);
    assert_eq!(locked[0]["requiredScope"], "integration:locked");
    assert_eq!(locked[0]["target"], "locked.send");

    let legacy = catalog.search("legacy").await.unwrap();
    assert_eq!(legacy[0]["upstreamConnected"], false);
    assert_eq!(legacy[0]["upstreamStatus"], "unsupported");
    let broken = catalog.search("broken").await.unwrap();
    assert_eq!(broken[0]["upstreamStatus"], "temporarilyUnavailable");

    let miss = catalog
        .search("semantic phrase with no match")
        .await
        .unwrap();
    assert_eq!(miss[0]["matches"], false);
    assert_eq!(miss[0]["searchMode"], "literalSubstring");
    assert_eq!(miss[0]["broadDiscoveryFallback"], "codemode.search('')");

    assert!(catalog.describe("missing-separator").await.is_err());
    assert!(catalog.describe("unknown.send").await.is_err());
    assert!(catalog.describe("mail-id.unknown").await.is_err());
    assert!(catalog.describe("locked.send").await.is_err());
    assert!(catalog.describe("legacy.send").await.is_err());
    assert!(catalog.call("locked.send", json!({})).await.is_err());
    assert!(catalog.call("legacy.send", json!({})).await.is_err());
    assert!(
        catalog
            .describe("offline.send")
            .await
            .unwrap_err()
            .to_string()
            .contains("upstream integration is expired")
    );
    assert!(
        catalog
            .call("offline.send", json!({}))
            .await
            .unwrap_err()
            .to_string()
            .contains("upstream integration is expired")
    );

    let direct = catalog.direct_tools("broken").await.unwrap();
    assert_eq!(direct.len(), 2);
    let locked = direct
        .iter()
        .find(|tool| tool.name == "locked.send")
        .unwrap();
    assert_eq!(
        locked.meta.as_ref().unwrap()[META_SECURITY_SCHEMES][0]["scopes"],
        json!(["integration:locked"])
    );
    assert_eq!(
        locked.meta.as_ref().unwrap()[META_REQUIRED_SCOPE],
        "integration:locked"
    );
    assert_eq!(
        locked.meta.as_ref().unwrap()[META_CLIENT_ACCESS_GRANTED],
        false
    );
    assert_eq!(
        locked.meta.as_ref().unwrap()[META_INTEGRATION_LABEL],
        "Locked Mail"
    );
    assert_eq!(
        catalog.native_tools("unknown", "cog_").await.unwrap(),
        vec![]
    );
    assert_eq!(
        catalog.native_tools("legacy", "cog_").await.unwrap(),
        vec![]
    );
    assert!(catalog.native_tools("broken", "cog_").await.is_err());
    assert_eq!(
        catalog.native_tools("mail-id", "cog_").await.unwrap()[0].name,
        "cog_send"
    );
    Arc::new(Fake).close().await.unwrap();
    assert!(catalog.direct_tools("nothing").await.is_err());
}

#[test]
fn parses_and_rejects_upstream_incremental_scope_challenges() {
    let challenge = r#"Bearer error="insufficient_scope", scope="account:read workers:write", resource_metadata="https://mcp.example/.well-known/oauth-protected-resource""#;
    let parsed =
        parse_upstream_insufficient_scope(reqwest::StatusCode::FORBIDDEN, challenge).unwrap();
    assert_eq!(parsed.scopes, ["account:read", "workers:write"]);
    assert_eq!(
        parsed.to_string(),
        "upstream MCP requires additional OAuth scope: account:read workers:write"
    );
    assert_eq!(
        parsed.resource_metadata,
        "https://mcp.example/.well-known/oauth-protected-resource"
    );
    assert!(std::error::Error::source(&parsed).is_none());
    assert!(
        parse_upstream_insufficient_scope(reqwest::StatusCode::UNAUTHORIZED, challenge).is_err()
    );
    for invalid in [
        r#"Basic error="insufficient_scope""#,
        r#"Bearer error="wrong", scope="x", resource_metadata="https://example.com/meta""#,
        r#"Bearer error="insufficient_scope", resource_metadata="https://example.com/meta""#,
        r#"Bearer error="insufficient_scope", scope="", resource_metadata="https://example.com/meta""#,
        r#"Bearer error="insufficient_scope", scope="x""#,
        r#"Bearer error="insufficient_scope", scope="x", resource_metadata="http://example.com/meta""#,
    ] {
        assert!(
            parse_upstream_insufficient_scope(reqwest::StatusCode::FORBIDDEN, invalid).is_err()
        );
    }
    assert_eq!(
        bearer_parameter("bearer error=\"insufficient_scope\"", "ERROR").as_deref(),
        Some("insufficient_scope")
    );
    for malformed in [
        "Digest token",
        r#"Bearer error=unquoted"#,
        "Bearer error=\"bad\rvalue\"",
        "Bearer error=\"bad\nvalue\"",
        r#"Bearer error="unterminated"#,
    ] {
        assert!(bearer_parameter(malformed, "error").is_none());
    }
}

#[derive(Clone, Default)]
struct HttpFixture {
    requests: Arc<AtomicUsize>,
    session_requests: Arc<AtomicUsize>,
    deleted: Arc<AtomicBool>,
}

async fn http_fixture(
    State(state): State<HttpFixture>,
    method: Method,
    headers: HeaderMap,
    body: Bytes,
) -> Response {
    state.requests.fetch_add(1, Ordering::SeqCst);
    assert_eq!(headers.get("x-cog-test").unwrap(), "present");
    assert_eq!(
        headers.get(http::header::AUTHORIZATION).unwrap(),
        "Bearer secret"
    );
    if method == Method::DELETE {
        state.deleted.store(true, Ordering::SeqCst);
        return StatusCode::NO_CONTENT.into_response();
    }
    if headers.get("Mcp-Session-Id").is_some() {
        state.session_requests.fetch_add(1, Ordering::SeqCst);
    }
    let request: Value = serde_json::from_slice(&body).unwrap();
    let Some(id) = request.get("id").cloned() else {
        return StatusCode::ACCEPTED.into_response();
    };
    let method = request.get("method").and_then(Value::as_str).unwrap();
    let response = match method {
        "server/discover" => json!({
            "jsonrpc":"2.0","id":id,
            "error":{"code":-32601,"message":"Method not found"}
        }),
        "initialize" => json!({
            "jsonrpc":"2.0","id":id,
            "result":{
                "protocolVersion":"2025-11-25",
                "capabilities":{"tools":{}},
                "serverInfo":{"name":"fixture","version":"1"}
            }
        }),
        "tools/list" => {
            if request.pointer("/params/cursor") == Some(&json!("next")) {
                json!({"jsonrpc":"2.0","id":id,"result":{"tools":[{
                    "name":"second","description":"Second page","inputSchema":{"type":"object"}
                }]}})
            } else {
                json!({"jsonrpc":"2.0","id":id,"result":{"tools":[{
                    "name":"first","description":"First page","inputSchema":{"type":"object"}
                }],"nextCursor":"next"}})
            }
        }
        "tools/call" => json!({
            "jsonrpc":"2.0","id":id,
            "result":{
                "content":[{"type":"text","text":"called"}],
                "structuredContent":{"name":request.pointer("/params/name"),"arguments":request.pointer("/params/arguments")}
            }
        }),
        other => panic!("unexpected fixture method: {other}"),
    };
    (
        [("Mcp-Session-Id", "fixture-session")],
        axum::Json(response),
    )
        .into_response()
}

async fn spawn_http_fixture() -> (String, HttpFixture, tokio::task::JoinHandle<()>) {
    let state = HttpFixture::default();
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    let server_state = state.clone();
    let server = tokio::spawn(async move {
        axum::serve(
            listener,
            Router::new()
                .route("/mcp", post(http_fixture).delete(http_fixture))
                .with_state(server_state),
        )
        .await
        .unwrap();
    });
    (format!("http://{address}/mcp"), state, server)
}

#[tokio::test]
async fn sdk_streamable_http_uses_headers_sessions_pagination_calls_and_cleanup() {
    let (url, state, server) = spawn_http_fixture().await;
    let provider = HttpMcp::new(
        url,
        HashMap::from([
            ("Authorization".into(), "Bearer secret".into()),
            ("x-cog-test".into(), "present".into()),
        ]),
    );
    let tools = provider.tools().await.unwrap();
    assert_eq!(
        tools
            .iter()
            .map(|tool| tool.name.as_ref())
            .collect::<Vec<_>>(),
        ["first", "second"]
    );
    let result = provider.call("first", json!({"value":42})).await.unwrap();
    assert_eq!(result["structuredContent"]["name"], "first");
    assert_eq!(result["structuredContent"]["arguments"]["value"], 42);
    assert!(state.requests.load(Ordering::SeqCst) >= 6);
    assert!(state.session_requests.load(Ordering::SeqCst) >= 3);
    provider.close().await.unwrap();
    assert!(state.deleted.load(Ordering::SeqCst));
    server.abort();
}

#[tokio::test]
async fn sdk_http_connection_failures_are_bounded_and_safe_to_close() {
    let provider = HttpMcp::new(
        "http://127.0.0.1:1/mcp".into(),
        HashMap::from([("Authorization".into(), "not-a-bearer-value".into())]),
    );
    let error = provider.tools().await.unwrap_err().to_string();
    assert!(!error.contains("not-a-bearer-value"));
    provider.close().await.unwrap();
}

async fn sse_error_fixture(body: Bytes) -> Response {
    let request: Value = serde_json::from_slice(&body).unwrap();
    let Some(id) = request.get("id").cloned() else {
        return StatusCode::ACCEPTED.into_response();
    };
    let method = request.get("method").and_then(Value::as_str);
    let response = match method {
        Some("server/discover") => json!({
            "jsonrpc":"2.0","id":id,
            "error":{"code":-32601,"message":"legacy fixture"}
        }),
        Some("initialize") => json!({
            "jsonrpc":"2.0","id":id,
            "result":{
                "protocolVersion":"2025-11-25",
                "capabilities":{"tools":{}},
                "serverInfo":{"name":"sse-error-fixture","version":"1"}
            }
        }),
        Some("tools/list") => json!({
            "jsonrpc":"2.0","id":id,
            "result":{"tools":[{
                "name":"fails","description":"Return a structured protocol error",
                "inputSchema":{"type":"object","additionalProperties":false}
            }]}
        }),
        Some("tools/call") => json!({
            "jsonrpc":"2.0","id":id,
            "error":{"code":-32000,"message":"fixture tool failure","data":{
                "retryable":false,"category":"fixture"
            }}
        }),
        method => panic!("unexpected SSE fixture method: {method:?}"),
    };
    if matches!(method, Some("server/discover" | "initialize")) {
        let mut response = axum::Json(response).into_response();
        if method == Some("initialize") {
            response
                .headers_mut()
                .insert("Mcp-Session-Id", "sse-session".parse().unwrap());
        }
        return response;
    }
    let mut response = (
        [(http::header::CONTENT_TYPE, "text/event-stream")],
        format!(
            ": keepalive\nevent: message\ndata: {}\n\n",
            serde_json::to_string(&response).unwrap()
        ),
    )
        .into_response();
    response
        .headers_mut()
        .insert("Mcp-Session-Id", "sse-session".parse().unwrap());
    response
}

#[tokio::test]
async fn sdk_streamable_http_accepts_sse_and_preserves_protocol_errors() {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    let server = tokio::spawn(async move {
        axum::serve(
            listener,
            Router::new().route("/mcp", post(sse_error_fixture)),
        )
        .await
        .unwrap();
    });
    let provider = HttpMcp::new(format!("http://{address}/mcp"), HashMap::new());
    let tools = provider.tools().await.unwrap();
    assert_eq!(tools.len(), 1);
    assert_eq!(tools[0].name, "fails");
    assert_eq!(
        tools[0].description.as_deref(),
        Some("Return a structured protocol error")
    );
    assert_eq!(tools[0].input_schema["type"], "object");
    assert_eq!(tools[0].input_schema["additionalProperties"], false);
    let error = provider.call("fails", json!({})).await.unwrap_err();
    let error = error.to_string();
    assert!(error.contains("fixture tool failure"));
    assert!(error.contains("retryable"));
    assert!(error.contains("category"));
    assert!(error.contains("fixture"));
    provider.close().await.unwrap();
    server.abort();
}

#[tokio::test]
async fn sdk_http_rejects_invalid_custom_header_configuration_without_io() {
    for headers in [
        HashMap::from([("bad header name".into(), "value".into())]),
        HashMap::from([("x-test".into(), "bad\rvalue".into())]),
    ] {
        let provider = HttpMcp::new("http://127.0.0.1:1/mcp".into(), headers);
        let error = provider.tools().await.unwrap_err().to_string();
        assert!(!error.is_empty());
        assert!(error.len() < 1_024);
        provider.close().await.unwrap();
    }
}

#[tokio::test]
async fn sdk_stdio_discovers_calls_reuses_process_redacts_stderr_and_closes() {
    let fixture = format!("{}/tests/fixtures/stdio-mcp.sh", env!("CARGO_MANIFEST_DIR"));
    let provider = StdioMcp::new("sh".into(), vec![fixture], HashMap::new());
    assert_eq!(provider.tools().await.unwrap()[0].name, "echo");
    assert_eq!(provider.tools().await.unwrap()[0].name, "echo");
    let result = provider.call("echo", json!({"value":42})).await.unwrap();
    assert_eq!(result["structuredContent"]["value"], 42);
    provider.close().await.unwrap();

    let secret = "credential-that-must-not-escape";
    let script = r#"
echo "$FIXTURE_SECRET diagnostic output" >&2
while IFS= read -r line; do
  id=$(printf '%s' "$line" | sed -n 's/.*"id":\([0-9][0-9]*\).*/\1/p')
  case "$line" in
    *'"method":"initialize"'*) printf '{"jsonrpc":"2.0","id":%s,"result":{"protocolVersion":"2025-11-25","capabilities":{},"serverInfo":{"name":"diagnostic","version":"1"}}}\n' "$id" ;;
    *'"method":"tools/list"'*) printf '{"jsonrpc":"2.0","id":%s,"result":{"tools":[]}}\n' "$id" ;;
  esac
done
"#;
    let diagnostic = StdioMcp::new(
        "sh".into(),
        vec!["-c".into(), script.into()],
        HashMap::from([("FIXTURE_SECRET".into(), secret.into())]),
    );
    assert!(diagnostic.tools().await.unwrap().is_empty());
    for _ in 0..100 {
        if !diagnostic.diagnostic_tail().await.is_empty() {
            break;
        }
        tokio::time::sleep(Duration::from_millis(5)).await;
    }
    let tail = diagnostic.diagnostic_tail().await;
    assert!(tail.contains("[REDACTED] diagnostic output"));
    assert!(!tail.contains(secret));
    assert!(tail.len() <= MAX_DIAGNOSTIC_BYTES);
    diagnostic.close().await.unwrap();
}

#[tokio::test]
async fn sdk_stdio_restarts_discovery_after_a_terminal_child_failure() {
    let directory = tempfile::tempdir().unwrap();
    let marker = directory.path().join("starts");
    let script = r#"
echo started >> "$1"
count=$(wc -l < "$1")
while IFS= read -r line; do
  id=$(printf '%s' "$line" | sed -n 's/.*"id":\([0-9][0-9]*\).*/\1/p')
  case "$line" in
    *'"method":"initialize"'*) printf '{"jsonrpc":"2.0","id":%s,"result":{"protocolVersion":"2025-11-25","capabilities":{},"serverInfo":{"name":"restart","version":"1"}}}\n' "$id" ;;
    *'"method":"tools/list"'*)
      if [ "$count" -eq 1 ]; then echo first-process-failed >&2; exit 17; fi
      printf '{"jsonrpc":"2.0","id":%s,"result":{"tools":[{"name":"recovered","inputSchema":{"type":"object"}}]}}\n' "$id" ;;
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
    assert_eq!(provider.tools().await.unwrap()[0].name, "recovered");
    assert_eq!(std::fs::read_to_string(marker).unwrap().lines().count(), 2);
    assert!(
        provider
            .diagnostic_tail()
            .await
            .contains("first-process-failed")
    );
    provider.close().await.unwrap();
}

#[tokio::test(start_paused = true)]
async fn sdk_stdio_tool_call_times_out_without_retrying_side_effects() {
    let directory = tempfile::tempdir().unwrap();
    let marker = directory.path().join("calls");
    let script = r#"
while IFS= read -r line; do
  id=$(printf '%s' "$line" | sed -n 's/.*"id":\([0-9][0-9]*\).*/\1/p')
  case "$line" in
    *'"method":"initialize"'*) printf '{"jsonrpc":"2.0","id":%s,"result":{"protocolVersion":"2025-11-25","capabilities":{},"serverInfo":{"name":"timeout","version":"1"}}}\n' "$id" ;;
    *'"method":"tools/call"'*) echo called >> "$1"; sleep 300 ;;
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
        tokio::spawn(async move { provider.call("side_effect", json!({})).await })
    };
    for _ in 0..1_000 {
        if marker.exists() {
            break;
        }
        tokio::task::yield_now().await;
        std::thread::sleep(Duration::from_millis(1));
    }
    assert!(marker.exists());
    tokio::time::advance(Duration::from_secs(31)).await;
    let error = request.await.unwrap().unwrap_err().to_string();
    assert!(error.contains("timed out"));
    assert_eq!(std::fs::read_to_string(marker).unwrap().lines().count(), 1);
    provider.close().await.unwrap();
}

#[tokio::test]
async fn sdk_stdio_terminal_call_failure_keeps_only_a_bounded_redacted_tail() {
    let secret = "stdio-secret-value";
    let script = r#"
while IFS= read -r line; do
  id=$(printf '%s' "$line" | sed -n 's/.*"id":\([0-9][0-9]*\).*/\1/p')
  case "$line" in
    *'"method":"initialize"'*) printf '{"jsonrpc":"2.0","id":%s,"result":{"protocolVersion":"2025-11-25","capabilities":{},"serverInfo":{"name":"stderr","version":"1"}}}\n' "$id" ;;
    *'"method":"tools/call"'*)
      i=0
      while [ "$i" -lt 1000 ]; do printf '%s diagnostic-%s\n' "$FIXTURE_SECRET" "$i" >&2; i=$((i + 1)); done
      exit 23 ;;
  esac
done
"#;
    let provider = StdioMcp::new(
        "sh".into(),
        vec!["-c".into(), script.into()],
        HashMap::from([("FIXTURE_SECRET".into(), secret.into())]),
    );
    let error = provider.call("fail", json!({})).await.unwrap_err();
    let error = error.to_string();
    assert!(error.contains("stdio MCP call failed"));
    assert!(!error.contains(secret));
    let tail = provider.diagnostic_tail().await;
    assert!(!tail.is_empty());
    assert!(tail.len() <= MAX_DIAGNOSTIC_BYTES);
    assert!(!tail.contains(secret));
    assert!(tail.contains("[REDACTED]"));
    assert!(tail.contains("diagnostic-"));
    provider.close().await.unwrap();
}

#[tokio::test(start_paused = true)]
async fn sdk_stdio_discovery_timeout_returns_a_bounded_error() {
    let directory = tempfile::tempdir().unwrap();
    let marker = directory.path().join("starts");
    let script = r#"
echo started >> "$1"
while IFS= read -r line; do
  id=$(printf '%s' "$line" | sed -n 's/.*"id":\([0-9][0-9]*\).*/\1/p')
  case "$line" in
    *'"method":"initialize"'*) printf '{"jsonrpc":"2.0","id":%s,"result":{"protocolVersion":"2025-11-25","capabilities":{},"serverInfo":{"name":"discovery-timeout","version":"1"}}}\n' "$id" ;;
    *'"method":"tools/list"'*) echo waiting-for-tools >&2; sleep 300 ;;
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
    for _ in 0..5_000 {
        if marker.exists() {
            break;
        }
        tokio::task::yield_now().await;
        std::thread::sleep(Duration::from_millis(1));
    }
    assert!(marker.exists());
    tokio::time::advance(Duration::from_secs(61)).await;
    let error = request.await.unwrap().unwrap_err().to_string();
    assert!(error.contains("timed out"));
    assert!(error.len() < MAX_DIAGNOSTIC_BYTES + 1_024);
    assert_eq!(std::fs::read_to_string(marker).unwrap().lines().count(), 1);
    provider.close().await.unwrap();
}
