use super::{
    MAX_MESSAGE_BYTES, MAX_TOOL_CATALOG_BYTES, MCP_PROTOCOL_VERSION, RPC_TIMEOUT,
    auth::{bearer_parameter, parse_upstream_insufficient_scope},
    stdio::validate_initialize,
};
use crate::mcp::catalog::ToolProvider;
use crate::mcp::model::Tool;
use async_trait::async_trait;
use bytes::Bytes;
use futures_util::{Stream, StreamExt};
use serde_json::{Value, json};
use std::{collections::HashMap, pin::Pin, sync::Arc};
use tokio::sync::Mutex;

#[derive(Clone)]
pub struct HttpMcp {
    url: String,
    headers: HashMap<String, String>,
    client: reqwest::Client,
    next: Arc<Mutex<u64>>,
    session: Arc<Mutex<Option<String>>>,
    initialized: Arc<Mutex<bool>>,
    protocol_version: Arc<Mutex<String>>,
    legacy: bool,
    legacy_session: Arc<Mutex<Option<LegacySession>>>,
}

type ResponseStream = Pin<Box<dyn Stream<Item = Result<Bytes, reqwest::Error>> + Send>>;

struct LegacySession {
    endpoint: String,
    stream: ResponseStream,
    buffer: Vec<u8>,
}

struct HttpCancellation {
    client: reqwest::Client,
    headers: HashMap<String, String>,
    endpoint: String,
    id: u64,
    armed: bool,
    streamable: bool,
    protocol_version: String,
}

/// Create a cancellation guard for MCP transport adapters. Dropping the guard
/// sends a best-effort `notifications/cancelled` message for the request.
pub fn cancellation_guard(
    client: reqwest::Client,
    headers: HashMap<String, String>,
    endpoint: String,
    id: u64,
    streamable: bool,
    protocol_version: String,
) -> impl Drop {
    HttpCancellation {
        client,
        headers,
        endpoint,
        id,
        armed: true,
        streamable,
        protocol_version,
    }
}

impl Drop for HttpCancellation {
    fn drop(&mut self) {
        if !self.armed {
            return;
        }
        let client = self.client.clone();
        let headers = self.headers.clone();
        let endpoint = self.endpoint.clone();
        let id = self.id;
        let streamable = self.streamable;
        let protocol_version = self.protocol_version.clone();
        tokio::spawn(async move {
            let mut request = client.post(endpoint).json(&json!({
                "jsonrpc":"2.0",
                "method":"notifications/cancelled",
                "params":{"requestId":id,"reason":"downstream request cancelled"}
            }));
            for (name, value) in headers {
                request = request.header(name, value);
            }
            if streamable {
                request = request.header("MCP-Protocol-Version", protocol_version);
            }
            let _ = request.send().await;
        });
    }
}

impl HttpMcp {
    pub fn new(url: String, headers: HashMap<String, String>) -> Self {
        Self::with_transport(url, headers, false)
    }

    pub fn new_sse(url: String, headers: HashMap<String, String>) -> Self {
        Self::with_transport(url, headers, true)
    }

    fn with_transport(url: String, headers: HashMap<String, String>, legacy: bool) -> Self {
        Self {
            url,
            headers,
            client: reqwest::Client::builder()
                .timeout(RPC_TIMEOUT)
                .build()
                .expect("valid HTTP client configuration"),
            next: Arc::new(Mutex::new(1)),
            session: Arc::new(Mutex::new(None)),
            initialized: Arc::new(Mutex::new(false)),
            protocol_version: Arc::new(Mutex::new(MCP_PROTOCOL_VERSION.to_owned())),
            legacy,
            legacy_session: Arc::new(Mutex::new(None)),
        }
    }
    async fn rpc(&self, method: &str, params: Value) -> anyhow::Result<Value> {
        let attempts = if method == "tools/list" { 2 } else { 1 };
        let mut last_error = None;
        for _ in 0..attempts {
            match self.rpc_once(method, params.clone()).await {
                Ok(value) => return Ok(value),
                Err(error) => {
                    last_error = Some(error);
                    *self.initialized.lock().await = false;
                    *self.session.lock().await = None;
                    *self.legacy_session.lock().await = None;
                }
            }
        }
        Err(last_error.unwrap_or_else(|| anyhow::anyhow!("upstream MCP unavailable")))
    }

    async fn rpc_once(&self, method: &str, params: Value) -> anyhow::Result<Value> {
        let mut initialized = self.initialized.lock().await;
        if method != "initialize" && !*initialized {
            let result = self.rpc_request("initialize",json!({"protocolVersion":MCP_PROTOCOL_VERSION,"capabilities":{},"clientInfo":{"name":"cog","version":env!("CARGO_PKG_VERSION")}})).await?;
            let selected = validate_initialize(&result)?;
            *self.protocol_version.lock().await = selected;
            self.notify_initialized().await?;
            *initialized = true;
        }
        drop(initialized);
        self.rpc_request(method, params).await
    }
    pub async fn rpc_request(&self, method: &str, params: Value) -> anyhow::Result<Value> {
        let mut n = self.next.lock().await;
        let id = *n;
        *n += 1;
        drop(n);
        if self.legacy {
            return self.legacy_rpc(id, method, params).await;
        }
        let body = json!({"jsonrpc":"2.0","id":id,"method":method,"params":params});
        anyhow::ensure!(
            serde_json::to_vec(&body)?.len() <= MAX_MESSAGE_BYTES,
            "upstream MCP request too large"
        );
        let mut req = self
            .client
            .post(&self.url)
            .header(
                reqwest::header::ACCEPT,
                "application/json, text/event-stream",
            )
            .json(&body);
        if method != "initialize" {
            req = req.header(
                "MCP-Protocol-Version",
                self.protocol_version.lock().await.clone(),
            );
        }
        for (k, v) in &self.headers {
            req = req.header(k, v)
        }
        let session_id = self.session.lock().await.clone();
        if let Some(session) = session_id.as_deref() {
            req = req.header("Mcp-Session-Id", session)
        }
        let mut cancel_headers = self.headers.clone();
        if let Some(session) = session_id {
            cancel_headers.insert("Mcp-Session-Id".into(), session);
        }
        let mut cancellation = HttpCancellation {
            client: self.client.clone(),
            headers: cancel_headers,
            endpoint: self.url.clone(),
            id,
            armed: true,
            streamable: true,
            protocol_version: self.protocol_version.lock().await.clone(),
        };
        let response = req.send().await?;
        if matches!(
            response.status(),
            reqwest::StatusCode::UNAUTHORIZED | reqwest::StatusCode::FORBIDDEN
        ) {
            let status = response.status();
            let challenge = response
                .headers()
                .get(reqwest::header::WWW_AUTHENTICATE)
                .and_then(|value| value.to_str().ok())
                .unwrap_or("Bearer");
            if status == reqwest::StatusCode::FORBIDDEN
                && bearer_parameter(challenge, "error").as_deref() == Some("insufficient_scope")
            {
                return Err(parse_upstream_insufficient_scope(status, challenge)?.into());
            }
            anyhow::bail!("upstream MCP authorization required: {challenge}");
        }
        let response = response.error_for_status()?;
        if let Some(session) = response
            .headers()
            .get("Mcp-Session-Id")
            .and_then(|v| v.to_str().ok())
        {
            *self.session.lock().await = Some(session.to_owned())
        }
        let content_type = response
            .headers()
            .get(reqwest::header::CONTENT_TYPE)
            .and_then(|v| v.to_str().ok())
            .unwrap_or("")
            .to_owned();
        let response_limit = if method == "tools/list" {
            MAX_TOOL_CATALOG_BYTES
        } else {
            MAX_MESSAGE_BYTES
        };
        let bytes = bounded_response(response, response_limit).await?;
        let body: Value = if content_type.starts_with("text/event-stream") {
            let text = String::from_utf8(bytes.to_vec())?;
            parse_sse_json(&text, id)?
        } else {
            serde_json::from_slice(&bytes)?
        };
        cancellation.armed = false;
        if let Some(error) = body.get("error") {
            anyhow::bail!("upstream MCP error: {error}")
        }
        Ok(body.get("result").cloned().unwrap_or(Value::Null))
    }
    async fn notify_initialized(&self) -> anyhow::Result<()> {
        let notification = json!({"jsonrpc":"2.0","method":"notifications/initialized"});
        if self.legacy {
            let mut session = self.legacy_session.lock().await;
            let session = session
                .as_mut()
                .ok_or_else(|| anyhow::anyhow!("legacy SSE session unavailable"))?;
            let response = self
                .request(reqwest::Method::POST, &session.endpoint)
                .json(&notification)
                .send()
                .await?;
            anyhow::ensure!(
                response.status().is_success(),
                "upstream rejected initialized notification"
            );
            return Ok(());
        }
        let mut req = self
            .client
            .post(&self.url)
            .header(
                reqwest::header::ACCEPT,
                "application/json, text/event-stream",
            )
            .header(
                "MCP-Protocol-Version",
                self.protocol_version.lock().await.clone(),
            )
            .json(&notification);
        for (k, v) in &self.headers {
            req = req.header(k, v)
        }
        if let Some(session) = self.session.lock().await.as_deref() {
            req = req.header("Mcp-Session-Id", session)
        }
        let response = req.send().await?;
        anyhow::ensure!(
            response.status().is_success(),
            "upstream rejected initialized notification"
        );
        Ok(())
    }

    fn request(&self, method: reqwest::Method, url: &str) -> reqwest::RequestBuilder {
        let mut request = self.client.request(method, url);
        for (name, value) in &self.headers {
            request = request.header(name, value);
        }
        request
    }

    async fn open_legacy_session(&self) -> anyhow::Result<LegacySession> {
        let response = self
            .request(reqwest::Method::GET, &self.url)
            .header(reqwest::header::ACCEPT, "text/event-stream")
            .send()
            .await?
            .error_for_status()?;
        let mut stream: ResponseStream = Box::pin(response.bytes_stream());
        let mut buffer = Vec::new();
        loop {
            let event = next_sse_event(&mut stream, &mut buffer).await?;
            if event.kind.as_deref() == Some("endpoint") {
                let origin = reqwest::Url::parse(&self.url)?;
                let endpoint = origin.join(event.data.trim())?;
                anyhow::ensure!(
                    endpoint.scheme() == origin.scheme()
                        && endpoint.host_str() == origin.host_str()
                        && endpoint.port_or_known_default() == origin.port_or_known_default(),
                    "legacy SSE endpoint changed origin"
                );
                return Ok(LegacySession {
                    endpoint: endpoint.to_string(),
                    stream,
                    buffer,
                });
            }
        }
    }

    async fn legacy_rpc(&self, id: u64, method: &str, params: Value) -> anyhow::Result<Value> {
        let mut session = self.legacy_session.lock().await;
        if session.is_none() {
            *session = Some(self.open_legacy_session().await?);
        }
        let current = session.as_mut().expect("legacy session initialized");
        let body = json!({"jsonrpc":"2.0","id":id,"method":method,"params":params});
        anyhow::ensure!(
            serde_json::to_vec(&body)?.len() <= MAX_MESSAGE_BYTES,
            "upstream MCP request too large"
        );
        let response = self
            .request(reqwest::Method::POST, &current.endpoint)
            .json(&body)
            .send()
            .await?;
        anyhow::ensure!(response.status().is_success(), "legacy SSE POST rejected");
        let mut cancellation = HttpCancellation {
            client: self.client.clone(),
            headers: self.headers.clone(),
            endpoint: current.endpoint.clone(),
            id,
            armed: true,
            streamable: false,
            protocol_version: MCP_PROTOCOL_VERSION.to_owned(),
        };
        loop {
            let event = tokio::time::timeout(
                RPC_TIMEOUT,
                next_sse_event(&mut current.stream, &mut current.buffer),
            )
            .await
            .map_err(|_| anyhow::anyhow!("legacy SSE request timed out"))??;
            if event.kind.as_deref().is_some_and(|kind| kind != "message") {
                continue;
            }
            let body: Value = serde_json::from_str(&event.data)?;
            if body.get("id") != Some(&json!(id)) {
                continue;
            }
            if let Some(error) = body.get("error") {
                anyhow::bail!("upstream MCP error: {error}")
            }
            cancellation.armed = false;
            return Ok(body.get("result").cloned().unwrap_or(Value::Null));
        }
    }
}

async fn bounded_response(response: reqwest::Response, maximum: usize) -> anyhow::Result<Bytes> {
    anyhow::ensure!(
        response.content_length().unwrap_or(0) <= maximum as u64,
        "upstream MCP response too large"
    );
    let mut stream = response.bytes_stream();
    let mut output = Vec::new();
    while let Some(chunk) = stream.next().await {
        let chunk = chunk?;
        anyhow::ensure!(
            output.len().saturating_add(chunk.len()) <= maximum,
            "upstream MCP response too large"
        );
        output.extend_from_slice(&chunk);
    }
    Ok(Bytes::from(output))
}

struct SseEvent {
    kind: Option<String>,
    data: String,
}

async fn next_sse_event(
    stream: &mut ResponseStream,
    buffer: &mut Vec<u8>,
) -> anyhow::Result<SseEvent> {
    loop {
        if let Some(end) = buffer.windows(2).position(|window| window == b"\n\n") {
            let frame = buffer.drain(..end + 2).collect::<Vec<_>>();
            let text = String::from_utf8(frame)?;
            let mut kind = None;
            let mut data = Vec::new();
            for line in text.lines() {
                if let Some(value) = line.strip_prefix("event:") {
                    kind = Some(value.trim().to_owned());
                } else if let Some(value) = line.strip_prefix("data:") {
                    data.push(value.strip_prefix(' ').unwrap_or(value));
                }
            }
            if !data.is_empty() {
                return Ok(SseEvent {
                    kind,
                    data: data.join("\n"),
                });
            }
        }
        let chunk = stream
            .next()
            .await
            .ok_or_else(|| anyhow::anyhow!("legacy SSE stream closed"))??;
        anyhow::ensure!(
            buffer.len().saturating_add(chunk.len()) <= MAX_MESSAGE_BYTES,
            "SSE event too large"
        );
        buffer.extend_from_slice(&chunk);
        if buffer.windows(4).any(|window| window == b"\r\n\r\n") {
            *buffer = buffer
                .split(|byte| *byte == b'\r')
                .flat_map(|part| part.iter().copied())
                .collect();
        }
    }
}
#[async_trait]
impl ToolProvider for HttpMcp {
    async fn tools(&self) -> anyhow::Result<Vec<Tool>> {
        let mut tools = Vec::new();
        let mut cursor: Option<String> = None;
        loop {
            let params = cursor
                .as_ref()
                .map_or_else(|| json!({}), |cursor| json!({"cursor":cursor}));
            let value = self.rpc("tools/list", params).await?;
            tools.extend(serde_json::from_value::<Vec<Tool>>(
                value.get("tools").cloned().unwrap_or(json!([])),
            )?);
            cursor = value
                .get("nextCursor")
                .and_then(Value::as_str)
                .filter(|cursor| !cursor.is_empty())
                .map(str::to_owned);
            if cursor.is_none() {
                return Ok(tools);
            }
        }
    }
    async fn call(&self, name: &str, args: Value) -> anyhow::Result<Value> {
        self.rpc("tools/call", json!({"name":name,"arguments":args}))
            .await
    }
    async fn close(&self) -> anyhow::Result<()> {
        *self.initialized.lock().await = false;
        *self.legacy_session.lock().await = None;
        let session = self.session.lock().await.take();
        if let Some(session) = session {
            let mut request = self.request(reqwest::Method::DELETE, &self.url);
            request = request.header("Mcp-Session-Id", session).header(
                "MCP-Protocol-Version",
                self.protocol_version.lock().await.clone(),
            );
            let response = request.send().await?;
            anyhow::ensure!(
                response.status().is_success()
                    || response.status() == reqwest::StatusCode::NOT_FOUND,
                "upstream rejected MCP session cleanup"
            );
        }
        Ok(())
    }
}

pub fn parse_sse_json(text: &str, id: u64) -> anyhow::Result<Value> {
    let normalized = text.replace("\r\n", "\n");
    for event in normalized.split("\n\n") {
        let data = event
            .lines()
            .filter_map(|line| line.strip_prefix("data:"))
            .map(|line| line.strip_prefix(' ').unwrap_or(line))
            .collect::<Vec<_>>()
            .join("\n");
        if data.is_empty() {
            continue;
        }
        let value: Value = serde_json::from_str(&data)?;
        if value.get("id") == Some(&json!(id)) {
            return Ok(value);
        }
    }
    anyhow::bail!("SSE response contained no response for request {id}")
}
