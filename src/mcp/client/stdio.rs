use super::{MAX_DIAGNOSTIC_BYTES, MAX_MESSAGE_BYTES, MCP_PROTOCOL_VERSION, RPC_TIMEOUT};
use crate::mcp::catalog::ToolProvider;
use crate::mcp::model::Tool;
use async_trait::async_trait;
use serde_json::{Value, json};
use std::{collections::HashMap, process::Stdio, sync::Arc, time::Duration};
use tokio::{
    io::{AsyncBufReadExt, AsyncWriteExt, BufReader},
    process::{Child, ChildStdin, ChildStdout, Command},
    sync::Mutex,
};

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
