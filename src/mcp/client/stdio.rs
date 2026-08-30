use super::{MAX_DIAGNOSTIC_BYTES, RPC_TIMEOUT};
use crate::mcp::{Tool, catalog::ToolProvider};
use async_trait::async_trait;
use rmcp::{
    ServiceExt,
    model::{CallToolRequestParams, ClientInfo},
    service::{RoleClient, RunningService},
    transport::TokioChildProcess,
};
use serde_json::Value;
use std::{collections::HashMap, process::Stdio, sync::Arc};
use tokio::{io::AsyncReadExt, process::Command, sync::Mutex};

type Client = RunningService<RoleClient, ClientInfo>;

#[derive(Clone)]
pub struct StdioMcp {
    command: String,
    args: Vec<String>,
    env: HashMap<String, String>,
    client: Arc<Mutex<Option<Client>>>,
    diagnostics: Arc<Mutex<String>>,
}

impl StdioMcp {
    pub fn new(command: String, args: Vec<String>, env: HashMap<String, String>) -> Self {
        Self {
            command,
            args,
            env,
            client: Arc::new(Mutex::new(None)),
            diagnostics: Arc::new(Mutex::new(String::new())),
        }
    }

    async fn connect(&self) -> anyhow::Result<Client> {
        let mut command = Command::new(&self.command);
        command.args(&self.args).envs(&self.env);
        let (transport, stderr) = TokioChildProcess::builder(command)
            .stderr(Stdio::piped())
            .spawn()?;
        if let Some(mut stderr) = stderr {
            let diagnostics = self.diagnostics.clone();
            let secrets = self
                .env
                .values()
                .filter(|value| !value.is_empty())
                .cloned()
                .collect::<Vec<_>>();
            tokio::spawn(async move {
                let mut bytes = Vec::new();
                let mut chunk = [0_u8; 1024];
                while let Ok(read) = stderr.read(&mut chunk).await {
                    if read == 0 {
                        break;
                    }
                    bytes.extend_from_slice(&chunk[..read]);
                    if bytes.len() > MAX_DIAGNOSTIC_BYTES {
                        bytes.drain(..bytes.len() - MAX_DIAGNOSTIC_BYTES);
                    }
                    let mut text = String::from_utf8_lossy(&bytes).into_owned();
                    for secret in &secrets {
                        text = text.replace(secret, "[REDACTED]");
                    }
                    *diagnostics.lock().await = text;
                }
            });
        }
        ClientInfo::default()
            .serve(transport)
            .await
            .map_err(|error| anyhow::anyhow!("stdio MCP initialization failed: {error}"))
    }

    async fn ensure_connected<'a>(
        &self,
        slot: &'a mut Option<Client>,
    ) -> anyhow::Result<&'a mut Client> {
        if slot.as_ref().is_none_or(Client::is_closed) {
            *slot = Some(
                tokio::time::timeout(RPC_TIMEOUT, self.connect())
                    .await
                    .map_err(|_| anyhow::anyhow!("stdio MCP initialization timed out"))??,
            );
        }
        Ok(slot.as_mut().expect("connected client"))
    }

    pub async fn diagnostic_tail(&self) -> String {
        self.diagnostics.lock().await.clone()
    }
}

#[async_trait]
impl ToolProvider for StdioMcp {
    async fn tools(&self) -> anyhow::Result<Vec<Tool>> {
        let mut slot = self.client.lock().await;
        let client = self.ensure_connected(&mut slot).await?;
        match tokio::time::timeout(RPC_TIMEOUT, client.list_all_tools()).await {
            Ok(Ok(tools)) => Ok(tools),
            first => {
                let first = match first {
                    Ok(Err(error)) => error.to_string(),
                    Err(_) => "request timed out".to_owned(),
                    Ok(Ok(_)) => unreachable!(),
                };
                *slot = None;
                let retry = self.ensure_connected(&mut slot).await?.list_all_tools();
                tokio::time::timeout(RPC_TIMEOUT, retry)
                    .await
                    .map_err(|_| anyhow::anyhow!("stdio discovery timed out after restart; initial failure: {first}"))?
                    .map_err(|second| anyhow::anyhow!("stdio discovery failed after restart: {second}; initial failure: {first}"))
            }
        }
    }

    async fn call(&self, name: &str, args: Value) -> anyhow::Result<Value> {
        let arguments = serde_json::from_value(args)?;
        let mut slot = self.client.lock().await;
        let client = self.ensure_connected(&mut slot).await?;
        let result = tokio::time::timeout(
            RPC_TIMEOUT,
            client.call_tool(CallToolRequestParams::new(name.to_owned()).with_arguments(arguments)),
        )
        .await
        .map_err(|_| anyhow::anyhow!("stdio MCP tool call timed out"))?;
        if result.is_err() && client.is_closed() {
            *slot = None;
        }
        match result {
            Ok(value) => Ok(serde_json::to_value(value)?),
            Err(error) => anyhow::bail!(
                "stdio MCP call failed: {error}; stderr: {}",
                self.diagnostic_tail().await
            ),
        }
    }

    async fn close(&self) -> anyhow::Result<()> {
        if let Some(mut client) = self.client.lock().await.take() {
            client.close_with_timeout(RPC_TIMEOUT).await?;
        }
        Ok(())
    }
}
