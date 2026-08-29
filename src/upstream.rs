use async_trait::async_trait;
use bytes::Bytes;
use futures_util::{Stream, StreamExt};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use std::{collections::HashMap, pin::Pin, process::Stdio, sync::Arc, time::Duration};
use tokio::{
    io::{AsyncBufReadExt, AsyncWriteExt, BufReader},
    process::{Child, ChildStdin, ChildStdout, Command},
    sync::Mutex,
};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UpstreamInsufficientScope {
    pub scopes: Vec<String>,
    pub resource_metadata: String,
}

impl std::fmt::Display for UpstreamInsufficientScope {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "upstream MCP requires additional OAuth scope: {}",
            self.scopes.join(" ")
        )
    }
}

impl std::error::Error for UpstreamInsufficientScope {}

pub fn bearer_parameter(challenge: &str, wanted: &str) -> Option<String> {
    let parameters = challenge
        .trim()
        .strip_prefix("Bearer ")
        .or_else(|| challenge.trim().strip_prefix("bearer "))?;
    for parameter in parameters.split(',') {
        let (name, value) = parameter.trim().split_once('=')?;
        if name.trim().eq_ignore_ascii_case(wanted) {
            let value = value.trim();
            if value.len() >= 2 && value.starts_with('"') && value.ends_with('"') {
                let value = &value[1..value.len() - 1];
                if !value.contains(['"', '\r', '\n']) {
                    return Some(value.to_owned());
                }
            }
            return None;
        }
    }
    None
}

pub fn parse_upstream_insufficient_scope(
    status: reqwest::StatusCode,
    challenge: &str,
) -> anyhow::Result<UpstreamInsufficientScope> {
    anyhow::ensure!(
        status == reqwest::StatusCode::FORBIDDEN,
        "challenge is not a 403"
    );
    anyhow::ensure!(
        bearer_parameter(challenge, "error").as_deref() == Some("insufficient_scope"),
        "challenge is not insufficient_scope"
    );
    let scopes = bearer_parameter(challenge, "scope")
        .ok_or_else(|| anyhow::anyhow!("upstream insufficient_scope challenge has no scope"))?
        .split_ascii_whitespace()
        .map(str::to_owned)
        .collect::<Vec<_>>();
    anyhow::ensure!(
        !scopes.is_empty(),
        "upstream insufficient_scope challenge has no scope"
    );
    let resource_metadata = bearer_parameter(challenge, "resource_metadata").ok_or_else(|| {
        anyhow::anyhow!("upstream insufficient_scope challenge has no resource_metadata")
    })?;
    let metadata = url::Url::parse(&resource_metadata)?;
    anyhow::ensure!(
        metadata.scheme() == "https"
            || (metadata.scheme() == "http"
                && matches!(metadata.host_str(), Some("localhost" | "127.0.0.1" | "::1"))),
        "upstream resource_metadata must use HTTPS except loopback"
    );
    Ok(UpstreamInsufficientScope {
        scopes,
        resource_metadata,
    })
}

const RPC_TIMEOUT: Duration = Duration::from_secs(30);
pub const MAX_MESSAGE_BYTES: usize = 1024 * 1024;
pub const MAX_TOOL_CATALOG_BYTES: usize = 32 * 1024 * 1024;
pub const MAX_DIAGNOSTIC_BYTES: usize = 8 * 1024;
pub const MCP_PROTOCOL_VERSION: &str = crate::mcp::LATEST_PROTOCOL_VERSION;

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct Tool {
    pub name: String,
    pub description: Option<String>,
    #[serde(rename = "inputSchema", default)]
    pub input_schema: Value,
    #[serde(flatten, default)]
    pub extra: serde_json::Map<String, Value>,
}

#[async_trait]
pub trait ToolProvider: Send + Sync {
    async fn tools(&self) -> anyhow::Result<Vec<Tool>>;
    async fn advertised_tools(&self) -> anyhow::Result<Vec<Tool>> {
        self.tools().await
    }
    async fn call(&self, name: &str, args: Value) -> anyhow::Result<Value>;
    async fn close(&self) -> anyhow::Result<()> {
        Ok(())
    }
}

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

#[derive(Clone)]
pub struct StdioMcp {
    command: String,
    args: Vec<String>,
    env: HashMap<String, String>,
    process: Arc<Mutex<Option<StdioProcess>>>,
    next: Arc<Mutex<u64>>,
    diagnostics: Arc<Mutex<String>>,
}

struct StdioProcess {
    child: Child,
    stdin: ChildStdin,
    stdout: BufReader<ChildStdout>,
}

struct CancelProcessOnDrop<'a> {
    process: &'a mut StdioProcess,
    armed: bool,
}

impl Drop for CancelProcessOnDrop<'_> {
    fn drop(&mut self) {
        if self.armed {
            terminate_process_tree(&mut self.process.child);
        }
    }
}
impl StdioMcp {
    pub fn new(command: String, args: Vec<String>, env: HashMap<String, String>) -> Self {
        Self {
            command,
            args,
            env,
            process: Arc::new(Mutex::new(None)),
            next: Arc::new(Mutex::new(1)),
            diagnostics: Arc::new(Mutex::new(String::new())),
        }
    }

    async fn start(&self) -> anyhow::Result<StdioProcess> {
        let mut command = Command::new(&self.command);
        command
            .args(&self.args)
            .envs(&self.env)
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .kill_on_drop(true);
        #[cfg(unix)]
        command.process_group(0);
        let mut child = command.spawn()?;
        let stdin = child
            .stdin
            .take()
            .ok_or_else(|| anyhow::anyhow!("stdio MCP stdin unavailable"))?;
        let stdout = child
            .stdout
            .take()
            .ok_or_else(|| anyhow::anyhow!("stdio MCP stdout unavailable"))?;
        let stderr = child
            .stderr
            .take()
            .ok_or_else(|| anyhow::anyhow!("stdio MCP stderr unavailable"))?;
        let diagnostics = self.diagnostics.clone();
        tokio::spawn(async move {
            let mut lines = BufReader::new(stderr).lines();
            while let Ok(Some(line)) = lines.next_line().await {
                let mut text = diagnostics.lock().await;
                if !text.is_empty() {
                    text.push('\n');
                }
                text.push_str(&line);
                if text.len() > MAX_DIAGNOSTIC_BYTES {
                    let split = text.len() - MAX_DIAGNOSTIC_BYTES;
                    *text = text.split_off(split);
                }
            }
        });
        let mut process = StdioProcess {
            child,
            stdin,
            stdout: BufReader::new(stdout),
        };
        Self::write(
            &mut process,
            &json!({"jsonrpc":"2.0","id":0,"method":"initialize","params":{"protocolVersion":MCP_PROTOCOL_VERSION,"capabilities":{},"clientInfo":{"name":"cog","version":env!("CARGO_PKG_VERSION")}}}),
        )
        .await?;
        let result = Self::read_response(&mut process, 0, RPC_TIMEOUT).await?;
        validate_initialize(&result)?;
        Self::write(
            &mut process,
            &json!({"jsonrpc":"2.0","method":"notifications/initialized"}),
        )
        .await?;
        Ok(process)
    }

    async fn write(process: &mut StdioProcess, message: &Value) -> anyhow::Result<()> {
        let encoded = serde_json::to_vec(message)?;
        anyhow::ensure!(
            encoded.len() <= MAX_MESSAGE_BYTES,
            "stdio request too large"
        );
        process.stdin.write_all(&encoded).await?;
        process.stdin.write_all(b"\n").await?;
        process.stdin.flush().await?;
        Ok(())
    }

    async fn read_response(
        process: &mut StdioProcess,
        id: u64,
        timeout: Duration,
    ) -> anyhow::Result<Value> {
        tokio::time::timeout(timeout, async {
            loop {
                let line = read_bounded_line(&mut process.stdout).await?;
                let value: Value = serde_json::from_slice(&line)?;
                if value.get("id") == Some(&json!(id)) {
                    if let Some(error) = value.get("error") {
                        anyhow::bail!("upstream MCP error: {error}")
                    }
                    return Ok(value.get("result").cloned().unwrap_or(Value::Null));
                }
                // Notifications and responses to cancelled/older requests are
                // deliberately consumed while waiting for our serialized ID.
            }
        })
        .await
        .map_err(|_| anyhow::anyhow!("stdio MCP request timed out"))?
    }

    async fn reset(process: &mut Option<StdioProcess>) {
        if let Some(mut old) = process.take() {
            terminate_process_tree(&mut old.child);
            let _ = old.child.wait().await;
        }
    }

    async fn rpc(&self, method: &str, params: Value) -> anyhow::Result<Value> {
        let mut process = self.process.lock().await;
        let attempts = if method == "tools/list" { 2 } else { 1 };
        let mut last_error = None;
        for _ in 0..attempts {
            if process.is_none() {
                match self.start().await {
                    Ok(started) => *process = Some(started),
                    Err(error) => {
                        last_error = Some(error);
                        continue;
                    }
                }
            }
            let id = {
                let mut next = self.next.lock().await;
                let id = *next;
                *next += 1;
                id
            };
            let current = process.as_mut().expect("stdio process initialized");
            let mut cancellation = CancelProcessOnDrop {
                process: current,
                armed: true,
            };
            let result = async {
                Self::write(
                    cancellation.process,
                    &json!({"jsonrpc":"2.0","id":id,"method":method,"params":params}),
                )
                .await?;
                Self::read_response(cancellation.process, id, RPC_TIMEOUT).await
            }
            .await;
            cancellation.armed = false;
            drop(cancellation);
            match result {
                Ok(value) => return Ok(value),
                Err(error) => {
                    last_error = Some(error);
                    Self::reset(&mut process).await;
                }
            }
        }
        let diagnostics = self.diagnostics.lock().await.clone();
        let error = last_error.unwrap_or_else(|| anyhow::anyhow!("stdio MCP unavailable"));
        if diagnostics.is_empty() {
            Err(error)
        } else {
            Err(error.context(format!("stdio diagnostics: {diagnostics}")))
        }
    }
}

pub fn validate_initialize(result: &Value) -> anyhow::Result<String> {
    let selected = result
        .get("protocolVersion")
        .and_then(Value::as_str)
        .ok_or_else(|| anyhow::anyhow!("upstream initialize result has no protocol version"))?;
    anyhow::ensure!(
        crate::mcp::protocol_version_supported(selected),
        "upstream selected unsupported MCP protocol version"
    );
    anyhow::ensure!(
        result.get("capabilities").is_some_and(Value::is_object),
        "upstream initialize result has no capabilities object"
    );
    anyhow::ensure!(
        result.get("serverInfo").is_some_and(Value::is_object),
        "upstream initialize result has no serverInfo object"
    );
    Ok(selected.to_owned())
}

fn terminate_process_tree(child: &mut Child) {
    #[cfg(unix)]
    if let Some(pid) = child.id() {
        // Each stdio integration is its own process group. Negative PID sends
        // SIGKILL to the command and every descendant retaining its pipes.
        unsafe {
            libc::kill(-(pid as i32), libc::SIGKILL);
        }
        return;
    }
    let _ = child.start_kill();
}

async fn read_bounded_line(reader: &mut BufReader<ChildStdout>) -> anyhow::Result<Vec<u8>> {
    let mut line = Vec::new();
    loop {
        let available = reader.fill_buf().await?;
        if available.is_empty() {
            anyhow::bail!("stdio MCP exited without response");
        }
        let consumed = available
            .iter()
            .position(|byte| *byte == b'\n')
            .map_or(available.len(), |index| index + 1);
        anyhow::ensure!(
            line.len().saturating_add(consumed) <= MAX_MESSAGE_BYTES,
            "stdio response too large"
        );
        line.extend_from_slice(&available[..consumed]);
        reader.consume(consumed);
        if line.last() == Some(&b'\n') {
            line.pop();
            if line.last() == Some(&b'\r') {
                line.pop();
            }
            return Ok(line);
        }
    }
}
#[async_trait]
impl ToolProvider for StdioMcp {
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
        let mut process = self.process.lock().await;
        Self::reset(&mut process).await;
        Ok(())
    }
}

pub struct Catalog {
    providers: HashMap<String, CatalogEntry>,
}
struct CatalogEntry {
    label: String,
    provider: Option<Arc<dyn ToolProvider>>,
    upstream_status: String,
    client_access_granted: bool,
}
impl Catalog {
    pub fn new() -> Self {
        Self {
            providers: HashMap::new(),
        }
    }
    pub fn add(&mut self, name: String, p: Arc<dyn ToolProvider>) {
        self.add_labeled(name.clone(), name, p);
    }
    pub fn add_labeled(&mut self, id: String, label: String, provider: Arc<dyn ToolProvider>) {
        self.providers.insert(
            id,
            CatalogEntry {
                label,
                provider: Some(provider),
                upstream_status: "connected".into(),
                client_access_granted: true,
            },
        );
    }
    pub fn add_discoverable(&mut self, id: String, label: String, provider: Arc<dyn ToolProvider>) {
        self.providers.insert(
            id,
            CatalogEntry {
                label,
                provider: Some(provider),
                upstream_status: "connected".into(),
                client_access_granted: false,
            },
        );
    }
    pub fn add_unavailable(
        &mut self,
        id: String,
        label: String,
        upstream_status: impl Into<String>,
        client_access_granted: bool,
    ) {
        self.providers.insert(
            id,
            CatalogEntry {
                label,
                provider: None,
                upstream_status: upstream_status.into(),
                client_access_granted,
            },
        );
    }
    pub async fn search(&self, query: &str) -> anyhow::Result<Value> {
        let q = query.to_lowercase();
        let mut found = Vec::new();
        for (id, entry) in &self.providers {
            let (tools, effective_status) = match &entry.provider {
                Some(provider) => match provider.tools().await {
                    Ok(tools) => (tools, entry.upstream_status.as_str()),
                    Err(_) => (Vec::new(), "temporarilyUnavailable"),
                },
                None => (Vec::new(), entry.upstream_status.as_str()),
            };
            if tools.is_empty()
                && (q.is_empty()
                    || id.to_lowercase().contains(&q)
                    || entry.label.to_lowercase().contains(&q))
            {
                found.push(json!({
                    "integration": id,
                    "integrationLabel": entry.label,
                    "upstreamConnected": effective_status == "connected",
                    "upstreamStatus": effective_status,
                    "clientAccessGranted": entry.client_access_granted,
                    "requiredScope": format!("integration:{id}"),
                    "grantRequestSupported": true,
                    "grantRequestAction": "Proceed with codemode.describe or codemode.call to trigger downstream OAuth progressive consent; do not reconnect the upstream integration.",
                    "searchMode": "literalSubstring",
                    "broadDiscoveryFallback": "codemode.search('')",
                }));
            }
            for tool in tools {
                let target = format!("{id}.{}", tool.name);
                let required_scope = tool
                    .extra
                    .get("x-cog-requiredScope")
                    .and_then(Value::as_str)
                    .map(str::to_owned)
                    .unwrap_or_else(|| format!("integration:{id}"));
                let client_access_granted = tool
                    .extra
                    .get("x-cog-clientAccessGranted")
                    .and_then(Value::as_bool)
                    .unwrap_or(entry.client_access_granted);
                let hay = format!(
                    "{} {} {} {}",
                    id,
                    entry.label,
                    tool.name,
                    tool.description.as_deref().unwrap_or("")
                )
                .to_lowercase();
                if q.is_empty() || hay.contains(&q) {
                    let mut result = json!({
                        "integration": id,
                        "integrationLabel": entry.label,
                        "tool": tool.name,
                        "description": tool.description,
                        "authorized": client_access_granted,
                        "upstreamConnected": entry.upstream_status == "connected",
                        "upstreamStatus": entry.upstream_status,
                        "clientAccessGranted": client_access_granted,
                        "requiredScope": required_scope,
                        "grantRequestSupported": true,
                        "target": target,
                        "searchMode": "literalSubstring",
                        "broadDiscoveryFallback": "codemode.search('')",
                    });
                    if !client_access_granted {
                        result["authorizationRequired"] = json!(true);
                        result["grantRequestAction"] = json!(
                            "Proceed with codemode.describe or codemode.call to trigger downstream OAuth progressive consent; do not reconnect the upstream integration."
                        );
                    }
                    found.push(result)
                }
            }
        }
        if found.is_empty() && !q.is_empty() {
            found.push(json!({"matches":false,"searchMode":"literalSubstring","broadDiscoveryFallback":"codemode.search('')","message":"No literal substring match. Search with an empty string to enumerate the full catalog."}));
        }
        Ok(json!(found))
    }
    pub async fn describe(&self, target: &str) -> anyhow::Result<Value> {
        let (provider, tool) = target
            .split_once('.')
            .ok_or_else(|| anyhow::anyhow!("target must be the immutable <integration-id>.<tool-name> returned by codemode.search(), not a label or bare tool name"))?;
        let entry = self
            .providers
            .get(provider)
            .ok_or_else(|| anyhow::anyhow!("unknown integration"))?;
        if !entry.client_access_granted {
            return Err(
                crate::authz::InsufficientScope::one(format!("integration:{provider}")).into(),
            );
        }
        let p = entry
            .provider
            .as_ref()
            .ok_or_else(|| anyhow::anyhow!("upstream integration is {}", entry.upstream_status))?;
        let t = p
            .advertised_tools()
            .await?
            .into_iter()
            .find(|t| t.name == tool)
            .ok_or_else(|| anyhow::anyhow!("unknown tool"))?;
        Ok(serde_json::to_value(t)?)
    }
    pub async fn call(&self, target: &str, args: Value) -> anyhow::Result<Value> {
        let (provider, tool) = target
            .split_once('.')
            .ok_or_else(|| anyhow::anyhow!("target must be the immutable <integration-id>.<tool-name> returned by codemode.search(), not a label or bare tool name"))?;
        let entry = self
            .providers
            .get(provider)
            .ok_or_else(|| anyhow::anyhow!("unknown integration"))?;
        if !entry.client_access_granted {
            return Err(
                crate::authz::InsufficientScope::one(format!("integration:{provider}")).into(),
            );
        }
        entry
            .provider
            .as_ref()
            .ok_or_else(|| anyhow::anyhow!("upstream integration is {}", entry.upstream_status))?
            .call(tool, args)
            .await
    }
    pub async fn native_tools(&self, integration: &str, prefix: &str) -> anyhow::Result<Vec<Tool>> {
        let Some(entry) = self.providers.get(integration) else {
            return Ok(Vec::new());
        };
        let Some(provider) = &entry.provider else {
            return Ok(Vec::new());
        };
        Ok(provider
            .advertised_tools()
            .await?
            .into_iter()
            .map(|mut tool| {
                tool.name = format!("{prefix}{}", tool.name);
                tool
            })
            .collect())
    }
    pub async fn direct_tools(&self, excluded_integration: &str) -> anyhow::Result<Vec<Tool>> {
        let mut tools = Vec::new();
        for (id, entry) in &self.providers {
            if id == excluded_integration {
                continue;
            }
            let Some(provider) = &entry.provider else {
                continue;
            };
            for mut tool in provider.advertised_tools().await? {
                tool.name = format!("{id}.{}", tool.name);
                let security_schemes =
                    json!([{"type":"oauth2","scopes":[format!("integration:{id}")]}]);
                tool.extra
                    .insert("securitySchemes".into(), security_schemes.clone());
                tool.extra
                    .insert("_meta".into(), json!({"securitySchemes":security_schemes}));
                tools.push(tool);
            }
        }
        tools.sort_by(|a, b| a.name.cmp(&b.name));
        Ok(tools)
    }
}
impl Default for Catalog {
    fn default() -> Self {
        Self::new()
    }
}
