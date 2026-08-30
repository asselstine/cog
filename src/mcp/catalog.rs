use super::model::{
    META_CLIENT_ACCESS_GRANTED, META_INTEGRATION_LABEL, META_REQUIRED_SCOPE, META_SECURITY_SCHEMES,
    Tool, insert_meta, meta_bool, meta_string, security_schemes,
};
use async_trait::async_trait;
use serde_json::{Value, json};
use std::{collections::HashMap, sync::Arc};

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

#[async_trait]
pub trait RuntimeHost: Send + Sync {
    async fn search(&self, query: &str) -> anyhow::Result<Value>;
    async fn describe(&self, target: &str) -> anyhow::Result<Value>;
    async fn call(&self, target: &str, args: Value) -> anyhow::Result<Value>;
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
    pub fn retain_runtime_integrations(&mut self, declared: &std::collections::HashSet<String>) {
        self.providers
            .retain(|id, _| id == "git" || id == "cog" || declared.contains(id));
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
                let required_scope = meta_string(&tool, META_REQUIRED_SCOPE)
                    .map(str::to_owned)
                    .unwrap_or_else(|| format!("integration:{id}"));
                let client_access_granted = meta_bool(&tool, META_CLIENT_ACCESS_GRANTED)
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
                tool.name = format!("{prefix}{}", tool.name).into();
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
                tool.name = format!("{id}.{}", tool.name).into();
                insert_meta(
                    &mut tool,
                    META_SECURITY_SCHEMES,
                    security_schemes([format!("integration:{id}")]),
                );
                insert_meta(
                    &mut tool,
                    META_REQUIRED_SCOPE,
                    json!(format!("integration:{id}")),
                );
                insert_meta(
                    &mut tool,
                    META_CLIENT_ACCESS_GRANTED,
                    json!(entry.client_access_granted),
                );
                insert_meta(&mut tool, META_INTEGRATION_LABEL, json!(entry.label));
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

#[async_trait]
impl RuntimeHost for Catalog {
    async fn search(&self, query: &str) -> anyhow::Result<Value> {
        Catalog::search(self, query).await
    }

    async fn describe(&self, target: &str) -> anyhow::Result<Value> {
        Catalog::describe(self, target).await
    }

    async fn call(&self, target: &str, args: Value) -> anyhow::Result<Value> {
        Catalog::call(self, target, args).await
    }
}
