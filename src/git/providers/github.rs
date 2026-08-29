use super::GitProvider;
use crate::git::model::*;
use async_trait::async_trait;
use jsonwebtoken::{Algorithm, EncodingKey, Header, encode};
use serde::{Deserialize, Serialize};
use serde_json::json;
use std::{collections::HashMap, sync::Arc, time::Duration};
use tokio::sync::{Mutex, Notify};
type RefreshMap = HashMap<(String, GitOperation), Arc<Notify>>;

#[derive(Clone)]
pub struct GitHubProvider {
    app_id: String,
    installation_id: String,
    api_base: url::Url,
    key: Arc<EncodingKey>,
    client: reqwest::Client,
    cache: Arc<Mutex<HashMap<(String, GitOperation), CachedToken>>>,
    refresh: Arc<Mutex<RefreshMap>>,
}
#[derive(Clone)]
struct CachedToken {
    token: SecretValue,
    expires_at: i64,
}
#[derive(Serialize)]
struct Claims<'a> {
    iat: i64,
    exp: i64,
    iss: &'a str,
}
#[derive(Deserialize)]
struct Repo {
    id: u64,
    full_name: String,
    clone_url: String,
    #[serde(default)]
    private: bool,
}
#[derive(Deserialize)]
struct InstallationToken {
    token: String,
    expires_at: chrono::DateTime<chrono::Utc>,
}

impl GitHubProvider {
    pub fn new(
        app_id: String,
        installation_id: String,
        host: String,
        private_key_pem: &[u8],
    ) -> anyhow::Result<Self> {
        anyhow::ensure!(
            !app_id.is_empty() && !installation_id.is_empty(),
            "GitHub App and installation IDs are required"
        );
        let loopback = url::Url::parse(&format!("http://{host}/"))
            .ok()
            .and_then(|url| url.host_str().map(str::to_owned))
            .is_some_and(|host| matches!(host.as_str(), "localhost" | "127.0.0.1" | "::1"));
        anyhow::ensure!(
            host == "github.com" || host == "api.github.com" || loopback,
            "unsupported GitHub host"
        );
        let key = EncodingKey::from_rsa_pem(private_key_pem)
            .map_err(|_| anyhow::anyhow!("invalid GitHub App RSA private key"))?;
        let api_base = if matches!(host.as_str(), "github.com" | "api.github.com") {
            url::Url::parse("https://api.github.com/")?
        } else {
            url::Url::parse(&format!("http://{host}/"))?
        };
        let client = reqwest::Client::builder()
            .redirect(reqwest::redirect::Policy::none())
            .timeout(Duration::from_secs(30))
            .user_agent("cog-git")
            .build()?;
        Ok(Self {
            app_id,
            installation_id,
            api_base,
            key: Arc::new(key),
            client,
            cache: Default::default(),
            refresh: Default::default(),
        })
    }
    fn jwt(&self) -> anyhow::Result<String> {
        let now = chrono::Utc::now().timestamp();
        Ok(encode(
            &Header::new(Algorithm::RS256),
            &Claims {
                iat: now - 30,
                exp: now + 540,
                iss: &self.app_id,
            },
            &self.key,
        )?)
    }
    async fn lookup_token(&self) -> anyhow::Result<SecretValue> {
        validate_resolved_network(&self.api_base, self.api_base.scheme() == "http").await?;
        let endpoint = self.api_base.join(&format!(
            "app/installations/{}/access_tokens",
            self.installation_id
        ))?;
        let response = self
            .client
            .post(endpoint)
            .bearer_auth(self.jwt()?)
            .json(&json!({"permissions":{"contents":"read"}}))
            .send()
            .await?;
        anyhow::ensure!(
            response.status().is_success(),
            "GitHub installation token request failed with status {}",
            response.status()
        );
        let value: InstallationToken = response.json().await?;
        Ok(SecretValue::new(value.token))
    }
    async fn install_token(
        &self,
        repo: &ResolvedRepository,
        op: GitOperation,
    ) -> anyhow::Result<SecretValue> {
        let key = (repo.provider_repository_id.clone(), op);
        if let Some(hit) = self
            .cache
            .lock()
            .await
            .get(&key)
            .filter(|v| v.expires_at > chrono::Utc::now().timestamp() + 60)
            .cloned()
        {
            return Ok(hit.token);
        }
        let (notify, leader) = {
            let mut active = self.refresh.lock().await;
            if let Some(n) = active.get(&key) {
                (n.clone(), false)
            } else {
                let n = Arc::new(Notify::new());
                active.insert(key.clone(), n.clone());
                (n, true)
            }
        };
        if !leader {
            notify.notified().await;
            return self
                .cache
                .lock()
                .await
                .get(&key)
                .filter(|v| v.expires_at > chrono::Utc::now().timestamp())
                .map(|v| v.token.clone())
                .ok_or_else(|| anyhow::anyhow!("GitHub credential refresh failed"));
        }
        let result = async {
            validate_resolved_network(&self.api_base, self.api_base.scheme() == "http").await?;
            let id = repo.provider_repository_id.parse::<u64>()?;
            let endpoint = self.api_base.join(&format!(
                "app/installations/{}/access_tokens",
                self.installation_id
            ))?;
            let permissions = match op {
                GitOperation::Read => json!({"contents":"read"}),
                GitOperation::Write => json!({"contents":"write","workflows":"write"}),
            };
            let response = self
                .client
                .post(endpoint)
                .bearer_auth(self.jwt()?)
                .json(&json!({"repository_ids":[id],"permissions":permissions}))
                .send()
                .await?;
            anyhow::ensure!(
                response.status().is_success(),
                "GitHub installation token request failed with status {}",
                response.status()
            );
            let value: InstallationToken = response.json().await?;
            let cached = CachedToken {
                token: SecretValue::new(value.token),
                expires_at: value.expires_at.timestamp(),
            };
            self.cache.lock().await.insert(key.clone(), cached.clone());
            Ok(cached.token)
        }
        .await;
        self.refresh.lock().await.remove(&key);
        notify.notify_waiters();
        result
    }
    pub async fn clear_cache(&self) {
        self.cache.lock().await.clear()
    }
}

#[async_trait]
impl GitProvider for GitHubProvider {
    async fn resolve_repository(
        &self,
        reference: &RepositoryReference,
    ) -> anyhow::Result<ResolvedRepository> {
        anyhow::ensure!(
            reference.0.split('/').count() == 2 && !reference.0.contains(".."),
            "GitHub repository must be owner/name"
        );
        validate_resolved_network(&self.api_base, self.api_base.scheme() == "http").await?;
        let token = self.lookup_token().await?;
        let response = self
            .client
            .get(self.api_base.join(&format!("repos/{}", reference.0))?)
            .bearer_auth(token.expose())
            .send()
            .await?;
        anyhow::ensure!(
            response.status().is_success(),
            "GitHub repository lookup failed with status {}",
            response.status()
        );
        let r: Repo = response.json().await?;
        let upstream = url::Url::parse(&r.clone_url)?;
        validate_upstream(&upstream, "github.com", false)?;
        validate_resolved_network(&upstream, false).await?;
        Ok(ResolvedRepository {
            provider_repository_id: r.id.to_string(),
            display_name: r.full_name,
            upstream_url: upstream,
            metadata: json!({"private":r.private}),
        })
    }
    async fn authorize_upstream(
        &self,
        repo: &ResolvedRepository,
        operation: GitOperation,
    ) -> anyhow::Result<UpstreamAuthorization> {
        Ok(UpstreamAuthorization::Basic {
            username: SecretValue::new("x-access-token"),
            password: self.install_token(repo, operation).await?,
        })
    }
    fn upstream_url(&self, repository: &ResolvedRepository) -> anyhow::Result<url::Url> {
        validate_upstream(&repository.upstream_url, "github.com", false)?;
        Ok(repository.upstream_url.clone())
    }
}
