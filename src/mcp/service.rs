pub use crate::mcp::tools::{
    admin::{safe_integration, upstream_connection_state},
    git::git_provider,
};
use crate::{
    diagnostics::safe_error,
    mcp::tools::{admin::AdminProvider, git::GitControlProvider},
    mcp::{Catalog, HttpMcp, StdioMcp, Tool, ToolProvider, UpstreamInsufficientScope},
    server::*,
};
use serde_json::{Value, json};
use std::{
    collections::{HashMap, HashSet},
    sync::{Arc, atomic::Ordering},
};

pub struct MeasuredProvider {
    pub inner: Arc<dyn ToolProvider>,
    pub metrics: Arc<Metrics>,
}

pub struct PolicyProvider {
    pub inner: Arc<dyn ToolProvider>,
    pub allow: Option<HashSet<String>>,
    pub deny: HashSet<String>,
}

pub struct OAuthStepUpProvider {
    pub inner: Arc<dyn ToolProvider>,
    pub app: App,
    pub user: String,
    pub integration: String,
}

impl PolicyProvider {
    fn permitted(&self, tool: &str) -> bool {
        self.allow.as_ref().is_none_or(|allow| allow.contains(tool)) && !self.deny.contains(tool)
    }
}

#[async_trait::async_trait]
impl ToolProvider for PolicyProvider {
    async fn tools(&self) -> anyhow::Result<Vec<Tool>> {
        Ok(self
            .inner
            .tools()
            .await?
            .into_iter()
            .filter(|tool| self.permitted(&tool.name))
            .collect())
    }

    async fn call(&self, name: &str, args: Value) -> anyhow::Result<Value> {
        anyhow::ensure!(self.permitted(name), "tool denied by integration policy");
        self.inner.call(name, args).await
    }

    async fn close(&self) -> anyhow::Result<()> {
        self.inner.close().await
    }
}

#[async_trait::async_trait]
impl ToolProvider for OAuthStepUpProvider {
    async fn tools(&self) -> anyhow::Result<Vec<Tool>> {
        self.inner.tools().await
    }

    async fn advertised_tools(&self) -> anyhow::Result<Vec<Tool>> {
        self.inner.advertised_tools().await
    }

    async fn call(&self, name: &str, args: Value) -> anyhow::Result<Value> {
        match self.inner.call(name, args).await {
            Ok(value) => Ok(value),
            Err(error) => {
                let Some(challenge) = error.downcast_ref::<UpstreamInsufficientScope>() else {
                    return Err(error);
                };
                if let Some(token) = self.app.db.upstream_oauth_token(&self.integration)? {
                    let granted = token.scope.split_ascii_whitespace().collect::<HashSet<_>>();
                    if challenge
                        .scopes
                        .iter()
                        .all(|scope| granted.contains(scope.as_str()))
                    {
                        anyhow::bail!(
                            "upstream MCP repeated an insufficient_scope challenge after consent; the operation was retried once and will not be retried again"
                        );
                    }
                }
                let authorization_url =
                    start_upstream_step_up(&self.app, &self.user, &self.integration, challenge)
                        .await?;
                anyhow::bail!(
                    "upstream OAuth consent is required for scopes [{}]. Open this one-time URL without prefetching it, complete consent, then retry this operation once: {}",
                    challenge.scopes.join(" "),
                    authorization_url
                )
            }
        }
    }

    async fn close(&self) -> anyhow::Result<()> {
        self.inner.close().await
    }
}

#[async_trait::async_trait]
impl ToolProvider for MeasuredProvider {
    async fn tools(&self) -> anyhow::Result<Vec<Tool>> {
        self.metrics.upstream_calls.fetch_add(1, Ordering::Relaxed);
        self.inner.tools().await.inspect_err(|_| {
            self.metrics
                .upstream_failures
                .fetch_add(1, Ordering::Relaxed);
        })
    }

    async fn call(&self, name: &str, args: Value) -> anyhow::Result<Value> {
        self.metrics.upstream_calls.fetch_add(1, Ordering::Relaxed);
        self.inner.call(name, args).await.inspect_err(|_| {
            self.metrics
                .upstream_failures
                .fetch_add(1, Ordering::Relaxed);
        })
    }

    async fn close(&self) -> anyhow::Result<()> {
        self.inner.close().await
    }
}

pub async fn catalog(a: &App, auth: &AuthContext) -> anyhow::Result<Catalog> {
    let _agent_id = &auth.agent;
    let mut c = Catalog::new();
    c.add_labeled(
        "git".into(),
        "COG Git repository access".into(),
        Arc::new(GitControlProvider {
            app: a.clone(),
            auth: auth.clone(),
        }),
    );
    c.add_labeled(
        "cog".into(),
        "Clanker Operations Gateway administration".into(),
        Arc::new(AdminProvider {
            app: a.clone(),
            auth: auth.clone(),
        }),
    );
    let compatibility_all = auth.scopes.contains("admin");
    for i in
        a.db.list_integrations(&auth.user)?
            .into_iter()
            .filter(|i| i.enabled && (compatibility_all || i.identity_id == auth.identity))
    {
        let authorized = compatibility_all || auth.integrations.contains(&i.id);
        let oauth_enabled = i.config.get("oauth").is_some_and(|value| !value.is_null());
        if !oauth_enabled && let Some(provider) = a.providers.lock().await.get(&i.id).cloned() {
            if authorized {
                c.add_labeled(i.id, i.name, provider);
            } else {
                c.add_discoverable(i.id, i.name, provider);
            }
            continue;
        }
        let cfg = i
            .config
            .as_object()
            .ok_or_else(|| anyhow::anyhow!("invalid integration config"))?;
        let provider: Option<Arc<dyn ToolProvider>> = match i.transport.as_str() {
            "http" | "sse" => {
                let url = cfg
                    .get("url")
                    .and_then(Value::as_str)
                    .ok_or_else(|| anyhow::anyhow!("url required"))?
                    .to_owned();
                let mut headers = HashMap::new();
                if let Some(secret) = a.db.integration_secret(&i.id, &auth.user)? {
                    headers = serde_json::from_slice(&a.secrets.open(&secret)?)?
                }
                if oauth_enabled {
                    let authorization = match upstream_authorization(a, &i.id).await {
                        Ok(Some(authorization)) => authorization,
                        Ok(None) => {
                            tracing::info!(integration_id = %i.id, "upstream OAuth connection required");
                            c.add_unavailable(i.id, i.name, "disconnected", authorized);
                            continue;
                        }
                        Err(error) => {
                            tracing::info!(integration_id = %i.id, error = %safe_error(error.as_ref()), "upstream OAuth connection unusable");
                            let (status, _) = upstream_connection_state(a, &i);
                            c.add_unavailable(i.id, i.name, status, authorized);
                            continue;
                        }
                    };
                    headers.insert("Authorization".into(), authorization);
                }
                let provider = if i.transport == "sse" {
                    HttpMcp::new_sse(url, headers)
                } else {
                    HttpMcp::new(url, headers)
                };
                Some(Arc::new(provider))
            }
            "stdio" => {
                anyhow::ensure!(
                    a.config.allow_stdio,
                    "stdio integration disabled by deployment policy"
                );
                let command = cfg
                    .get("command")
                    .and_then(Value::as_str)
                    .ok_or_else(|| anyhow::anyhow!("command required"))?
                    .to_owned();
                let args = serde_json::from_value(cfg.get("args").cloned().unwrap_or(json!([])))?;
                Some(Arc::new(StdioMcp::new(command, args, HashMap::new())))
            }
            _ => None,
        };
        if let Some(provider) = provider {
            let provider: Arc<dyn ToolProvider> =
                if let Some(policy) = integration_policy(&i.config)? {
                    Arc::new(PolicyProvider {
                        inner: provider,
                        allow: policy.allow_tools.map(|tools| tools.into_iter().collect()),
                        deny: policy.deny_tools.into_iter().collect(),
                    })
                } else {
                    provider
                };
            let provider: Arc<dyn ToolProvider> = if oauth_enabled {
                Arc::new(OAuthStepUpProvider {
                    inner: provider,
                    app: a.clone(),
                    user: auth.user.clone(),
                    integration: i.id.clone(),
                })
            } else {
                provider
            };
            let provider: Arc<dyn ToolProvider> = Arc::new(MeasuredProvider {
                inner: provider,
                metrics: a.metrics.clone(),
            });
            if !oauth_enabled {
                a.providers
                    .lock()
                    .await
                    .insert(i.id.clone(), provider.clone());
            }
            if authorized {
                c.add_labeled(i.id, i.name, provider);
            } else {
                c.add_discoverable(i.id, i.name, provider);
            }
        }
    }
    Ok(c)
}
pub fn native_admin_scope(tool: &str) -> Option<&'static str> {
    let definition = crate::mcp::tools::by_public_name(tool)?;
    (definition.namespace == crate::mcp::tools::NativeNamespace::Cog)
        .then_some(definition.required_scope)
}
