use super::{MAX_MESSAGE_BYTES, RPC_TIMEOUT};
use crate::mcp::{Tool, catalog::ToolProvider};
use async_trait::async_trait;
use rmcp::{
    ClientLifecycleMode, ClientServiceExt,
    model::{CallToolRequestParams, ClientInfo, ProtocolVersion},
    service::{RoleClient, RunningService},
    transport::{
        StreamableHttpClientTransport, streamable_http_client::StreamableHttpClientTransportConfig,
    },
};
use serde_json::Value;
use std::{collections::HashMap, sync::Arc};
use tokio::sync::Mutex;

type Client = RunningService<RoleClient, ClientInfo>;

#[derive(Clone)]
pub struct HttpMcp {
    url: String,
    headers: HashMap<String, String>,
    client: Arc<Mutex<Option<Client>>>,
}

impl HttpMcp {
    pub fn new(url: String, headers: HashMap<String, String>) -> Self {
        Self {
            url,
            headers,
            client: Arc::new(Mutex::new(None)),
        }
    }

    async fn connect(&self) -> anyhow::Result<Client> {
        let mut custom_headers = HashMap::new();
        let mut bearer = None;
        for (name, value) in &self.headers {
            if name.eq_ignore_ascii_case(http::header::AUTHORIZATION.as_str()) {
                bearer = value.strip_prefix("Bearer ").map(str::to_owned);
                if bearer.is_some() {
                    continue;
                }
            }
            custom_headers.insert(name.parse()?, value.parse()?);
        }
        let mut config = StreamableHttpClientTransportConfig::with_uri(self.url.clone())
            .custom_headers(custom_headers)
            .max_sse_event_size(MAX_MESSAGE_BYTES)
            // The SDK's transparent session recovery replays the in-flight
            // request. Disable it here because this client also carries tool
            // calls whose side effects may already have occurred; discovery
            // reconnects explicitly at its safe boundary below.
            .reinit_on_expired_session(false);
        if let Some(token) = bearer {
            config = config.auth_header(token);
        }
        ClientInfo::default()
            .serve_with_lifecycle(
                StreamableHttpClientTransport::from_config(config),
                ClientLifecycleMode::Auto {
                    preferred_versions: vec![ProtocolVersion::V_2026_07_28],
                    legacy_version: None,
                },
            )
            .await
            .map_err(Into::into)
    }

    async fn ensure_connected<'a>(
        &self,
        slot: &'a mut Option<Client>,
    ) -> anyhow::Result<&'a mut Client> {
        if slot.as_ref().is_none_or(Client::is_closed) {
            *slot = Some(
                tokio::time::timeout(RPC_TIMEOUT, self.connect())
                    .await
                    .map_err(|_| anyhow::anyhow!("upstream MCP initialization timed out"))??,
            );
        }
        Ok(slot.as_mut().expect("connected client"))
    }
}

#[async_trait]
impl ToolProvider for HttpMcp {
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
                    .map_err(|_| anyhow::anyhow!("upstream discovery timed out after reconnect; initial failure: {first}"))?
                    .map_err(|second| anyhow::anyhow!("upstream discovery failed after reconnect: {second}; initial failure: {first}"))
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
        .map_err(|_| anyhow::anyhow!("upstream MCP tool call timed out"))?;
        if result.is_err() && client.is_closed() {
            *slot = None;
        }
        Ok(serde_json::to_value(result?)?)
    }

    async fn close(&self) -> anyhow::Result<()> {
        if let Some(mut client) = self.client.lock().await.take() {
            client.close_with_timeout(RPC_TIMEOUT).await?;
        }
        Ok(())
    }
}
