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

fn bearer_parameter(challenge: &str, wanted: &str) -> Option<String> {
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

fn parse_upstream_insufficient_scope(
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
const MAX_MESSAGE_BYTES: usize = 1024 * 1024;
const MAX_TOOL_CATALOG_BYTES: usize = 32 * 1024 * 1024;
const MAX_DIAGNOSTIC_BYTES: usize = 8 * 1024;
const MCP_PROTOCOL_VERSION: &str = crate::mcp::LATEST_PROTOCOL_VERSION;

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
            let result = self.raw_rpc("initialize",json!({"protocolVersion":MCP_PROTOCOL_VERSION,"capabilities":{},"clientInfo":{"name":"cog","version":env!("CARGO_PKG_VERSION")}})).await?;
            let selected = validate_initialize(&result)?;
            *self.protocol_version.lock().await = selected;
            self.notify_initialized().await?;
            *initialized = true;
        }
        drop(initialized);
        self.raw_rpc(method, params).await
    }
    async fn raw_rpc(&self, method: &str, params: Value) -> anyhow::Result<Value> {
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

fn parse_sse_json(text: &str, id: u64) -> anyhow::Result<Value> {
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

#[doc(hidden)]
pub fn fuzz_validate_sse(input: &[u8]) {
    if let Ok(text) = std::str::from_utf8(input) {
        let _ = parse_sse_json(text, 1);
    }
}

#[derive(Clone)]
pub struct StdioMcp {
    command: String,
    args: Vec<String>,
    env: HashMap<String, String>,
    process: Arc<Mutex<Option<StdioProcess>>>,
    next: Arc<Mutex<u64>>,
    diagnostics: Arc<Mutex<String>>,
    timeout: Duration,
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
            timeout: RPC_TIMEOUT,
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
        let result = Self::read_response(&mut process, 0, self.timeout).await?;
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
                Self::read_response(cancellation.process, id, self.timeout).await
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

fn validate_initialize(result: &Value) -> anyhow::Result<String> {
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

#[cfg(test)]
mod tests {
    use super::*;
    use axum::{
        Router, body::Bytes as AxumBytes, extract::State, response::IntoResponse, routing::post,
    };
    use proptest::prelude::*;
    use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    struct Fake;
    #[async_trait]
    impl ToolProvider for Fake {
        async fn tools(&self) -> anyhow::Result<Vec<Tool>> {
            Ok(vec![Tool {
                name: "send".into(),
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
        fuzz_validate_sse(b"data: {\"jsonrpc\":\"2.0\",\"id\":1,\"result\":null}\n\n");
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
            parse_upstream_insufficient_scope(reqwest::StatusCode::UNAUTHORIZED, challenge)
                .is_err()
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
        assert!(malformed.process.lock().await.is_none());
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

    #[tokio::test]
    async fn stdio_hang_is_killed_at_deadline_with_bounded_diagnostics() {
        let script = r#"
while IFS= read -r line; do
  case "$line" in
    *'"id":0'*) printf '%s\n' '{"jsonrpc":"2.0","id":0,"result":{"protocolVersion":"2025-06-18","capabilities":{},"serverInfo":{"name":"fixture","version":"1"}}}' ;;
    *'"method":"tools/list"'*) yes diagnostic >&2 & wait ;;
  esac
done
"#;
        let mut provider = StdioMcp::new(
            "sh".into(),
            vec!["-c".into(), script.into()],
            HashMap::new(),
        );
        provider.timeout = Duration::from_millis(50);
        let error = format!("{:#}", provider.tools().await.unwrap_err());
        assert!(error.contains("timed out"));
        assert!(provider.process.lock().await.is_none());
        assert!(provider.diagnostics.lock().await.len() <= MAX_DIAGNOSTIC_BYTES);
    }

    #[tokio::test]
    async fn cancelling_stdio_rpc_terminates_the_supervised_process() {
        let dir = tempfile::tempdir().unwrap();
        let marker = dir.path().join("called");
        let script = r#"
while IFS= read -r line; do
  case "$line" in
    *'"id":0'*) printf '%s\n' '{"jsonrpc":"2.0","id":0,"result":{"protocolVersion":"2025-06-18","capabilities":{},"serverInfo":{"name":"fixture","version":"1"}}}' ;;
    *'"method":"tools/list"'*) touch "$1"; sleep 30 ;;
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
        running.abort();
        let _ = running.await;
        for _ in 0..100 {
            let exited = {
                let mut process = provider.process.lock().await;
                process
                    .as_mut()
                    .is_some_and(|process| process.child.try_wait().unwrap().is_some())
            };
            if exited {
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
            .raw_rpc("tools/call", json!({"value":huge}))
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
                .write_all(
                    b"HTTP/1.1 202 Accepted\r\nContent-Length: 0\r\nConnection: close\r\n\r\n",
                )
                .await
                .unwrap();
            String::from_utf8(request[..size].to_vec()).unwrap()
        });
        drop(HttpCancellation {
            client: reqwest::Client::new(),
            headers: HashMap::new(),
            endpoint: format!("http://{address}/messages"),
            id: 42,
            armed: true,
            streamable: false,
            protocol_version: MCP_PROTOCOL_VERSION.to_owned(),
        });
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
}
