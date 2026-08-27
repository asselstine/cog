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
        let result=async{
   validate_resolved_network(&self.api_base,self.api_base.scheme()=="http").await?;
   let id=repo.provider_repository_id.parse::<u64>()?;
   let endpoint=self.api_base.join(&format!("app/installations/{}/access_tokens",self.installation_id))?;
   let response=self.client.post(endpoint).bearer_auth(self.jwt()?).json(&json!({"repository_ids":[id],"permissions":{"contents":if op==GitOperation::Write{"write"}else{"read"}}})).send().await?;
   anyhow::ensure!(response.status().is_success(),"GitHub installation token request failed with status {}",response.status());
   let value:InstallationToken=response.json().await?;let cached=CachedToken{token:SecretValue::new(value.token),expires_at:value.expires_at.timestamp()};self.cache.lock().await.insert(key.clone(),cached.clone());Ok(cached.token)
  }.await;
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

#[cfg(test)]
mod tests {
    use super::*;
    use axum::{Json, Router, extract::State, routing::post};
    use serde_json::Value;
    use std::sync::atomic::{AtomicUsize, Ordering};

    const KEY: &[u8] = br#"-----BEGIN PRIVATE KEY-----
MIIEvgIBADANBgkqhkiG9w0BAQEFAASCBKgwggSkAgEAAoIBAQDJETqse41HRBsc
7cfcq3ak4oZWFCoZlcic525A3FfO4qW9BMtRO/iXiyCCHn8JhiL9y8j5JdVP2Q9Z
IpfElcFd3/guS9w+5RqQGgCR+H56IVUyHZWtTJbKPcwWXQdNUX0rBFcsBzCRESJL
eelOEdHIjG7LRkx5l/FUvlqsyHDVJEQsHwegZ8b8C0fz0EgT2MMEdn10t6Ur1rXz
jMB/wvCg8vG8lvciXmedyo9xJ8oMOh0wUEgxziVDMMovmC+aJctcHUAYubwoGN8T
yzcvnGqL7JSh36Pwy28iPzXZ2RLhAyJFU39vLaHdljwthUaupldlNyCfa6Ofy4qN
ctlUPlN1AgMBAAECggEAdESTQjQ70O8QIp1ZSkCYXeZjuhj081CK7jhhp/4ChK7J
GlFQZMwiBze7d6K84TwAtfQGZhQ7km25E1kOm+3hIDCoKdVSKch/oL54f/BK6sKl
qlIzQEAenho4DuKCm3I4yAw9gEc0DV70DuMTR0LEpYyXcNJY3KNBOTjN5EYQAR9s
2MeurpgK2MdJlIuZaIbzSGd+diiz2E6vkmcufJLtmYUT/k/ddWvEtz+1DnO6bRHh
xuuDMeJA/lGB/EYloSLtdyCF6sII6C6slJJtgfb0bPy7l8VtL5iDyz46IKyzdyzW
tKAn394dm7MYR1RlUBEfqFUyNK7C+pVMVoTwCC2V4QKBgQD64syfiQ2oeUlLYDm4
CcKSP3RnES02bcTyEDFSuGyyS1jldI4A8GXHJ/lG5EYgiYa1RUivge4lJrlNfjyf
dV230xgKms7+JiXqag1FI+3mqjAgg4mYiNjaao8N8O3/PD59wMPeWYImsWXNyeHS
55rUKiHERtCcvdzKl4u35ZtTqQKBgQDNKnX2bVqOJ4WSqCgHRhOm386ugPHfy+8j
m6cicmUR46ND6ggBB03bCnEG9OtGisxTo/TuYVRu3WP4KjoJs2LD5fwdwJqpgtHl
yVsk45Y1Hfo+7M6lAuR8rzCi6kHHNb0HyBmZjysHWZsn79ZM+sQnLpgaYgQGRbKV
DZWlbw7g7QKBgQCl1u+98UGXAP1jFutwbPsx40IVszP4y5ypCe0gqgon3UiY/G+1
zTLp79GGe/SjI2VpQ7AlW7TI2A0bXXvDSDi3/5Dfya9ULnFXv9yfvH1QwWToySpW
Kvd1gYSoiX84/WCtjZOr0e0HmLIb0vw0hqZA4szJSqoxQgvF22EfIWaIaQKBgQCf
34+OmMYw8fEvSCPxDxVvOwW2i7pvV14hFEDYIeZKW2W1HWBhVMzBfFB5SE8yaCQy
pRfOzj9aKOCm2FjjiErVNpkQoi6jGtLvScnhZAt/lr2TXTrl8OwVkPrIaN0bG/AS
aUYxmBPCpXu3UjhfQiWqFq/mFyzlqlgvuCc9g95HPQKBgAscKP8mLxdKwOgX8yFW
GcZ0izY/30012ajdHY+/QK5lsMoxTnn0skdS+spLxaS5ZEO4qvPVb8RAoCkWMMal
2pOhmquJQVDPDLuZHdrIiKiDM20dy9sMfHygWcZjQ4WSxf/J7T9canLZIXFhHAZT
3wc9h4G8BBCtWN2TN/LsGZdB
-----END PRIVATE KEY-----"#;

    #[derive(Clone)]
    struct Fixture {
        calls: Arc<AtomicUsize>,
        bodies: Arc<Mutex<Vec<Value>>>,
    }

    async fn token(State(state): State<Fixture>, Json(body): Json<Value>) -> Json<Value> {
        let call = state.calls.fetch_add(1, Ordering::SeqCst) + 1;
        state.bodies.lock().await.push(body);
        Json(json!({
            "token": format!("installation-secret-{call}"),
            "expires_at": "2099-01-01T00:00:00Z"
        }))
    }

    async fn expiring_token(State(state): State<Fixture>, Json(body): Json<Value>) -> Json<Value> {
        let call = state.calls.fetch_add(1, Ordering::SeqCst) + 1;
        state.bodies.lock().await.push(body);
        Json(json!({
            "token": format!("short-lived-secret-{call}"),
            "expires_at": (chrono::Utc::now() + chrono::Duration::seconds(30)).to_rfc3339()
        }))
    }

    #[tokio::test]
    async fn installation_tokens_are_least_privilege_cached_and_redacted() {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let fixture = Fixture {
            calls: Arc::new(AtomicUsize::new(0)),
            bodies: Arc::new(Mutex::new(Vec::new())),
        };
        let server = tokio::spawn(
            axum::serve(
                listener,
                Router::new()
                    .route("/app/installations/7/access_tokens", post(token))
                    .with_state(fixture.clone()),
            )
            .into_future(),
        );
        let provider =
            GitHubProvider::new("1".into(), "7".into(), address.to_string(), KEY).unwrap();
        let repository = ResolvedRepository {
            provider_repository_id: "42".into(),
            display_name: "owner/repo".into(),
            upstream_url: url::Url::parse("https://github.com/owner/repo.git").unwrap(),
            metadata: json!({}),
        };

        let read = provider
            .authorize_upstream(&repository, GitOperation::Read)
            .await
            .unwrap();
        assert!(!format!("{read:?}").contains("installation-secret"));
        provider
            .authorize_upstream(&repository, GitOperation::Read)
            .await
            .unwrap();
        provider
            .authorize_upstream(&repository, GitOperation::Write)
            .await
            .unwrap();
        assert_eq!(fixture.calls.load(Ordering::SeqCst), 2);
        let bodies = fixture.bodies.lock().await;
        assert_eq!(bodies[0]["repository_ids"], json!([42]));
        assert_eq!(bodies[0]["permissions"]["contents"], "read");
        assert_eq!(bodies[1]["permissions"]["contents"], "write");
        drop(bodies);
        provider.clear_cache().await;
        provider
            .authorize_upstream(&repository, GitOperation::Read)
            .await
            .unwrap();
        assert_eq!(fixture.calls.load(Ordering::SeqCst), 3);
        assert_eq!(
            provider.upstream_url(&repository).unwrap(),
            repository.upstream_url
        );
        server.abort();
    }

    #[test]
    fn configuration_and_repository_validation_fail_closed() {
        assert!(GitHubProvider::new("".into(), "7".into(), "github.com".into(), KEY).is_err());
        assert!(GitHubProvider::new("1".into(), "7".into(), "evil.example".into(), KEY).is_err());
        assert!(GitHubProvider::new("1".into(), "7".into(), "github.com".into(), b"bad").is_err());
        let provider =
            GitHubProvider::new("1".into(), "7".into(), "github.com".into(), KEY).unwrap();
        assert!(provider.jwt().is_ok());
        let bad = ResolvedRepository {
            provider_repository_id: "1".into(),
            display_name: "owner/repo".into(),
            upstream_url: url::Url::parse("https://example.com/owner/repo.git").unwrap(),
            metadata: json!({}),
        };
        assert!(provider.upstream_url(&bad).is_err());
    }

    #[tokio::test]
    async fn expiration_refreshes_and_redirects_fail_closed() {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let fixture = Fixture {
            calls: Arc::new(AtomicUsize::new(0)),
            bodies: Arc::new(Mutex::new(Vec::new())),
        };
        let server = tokio::spawn(
            axum::serve(
                listener,
                Router::new()
                    .route("/app/installations/7/access_tokens", post(expiring_token))
                    .with_state(fixture.clone()),
            )
            .into_future(),
        );
        let provider =
            GitHubProvider::new("1".into(), "7".into(), address.to_string(), KEY).unwrap();
        let repository = ResolvedRepository {
            provider_repository_id: "42".into(),
            display_name: "owner/repo".into(),
            upstream_url: url::Url::parse("https://github.com/owner/repo.git").unwrap(),
            metadata: json!({}),
        };
        provider
            .authorize_upstream(&repository, GitOperation::Read)
            .await
            .unwrap();
        provider
            .authorize_upstream(&repository, GitOperation::Read)
            .await
            .unwrap();
        assert_eq!(fixture.calls.load(Ordering::SeqCst), 2);
        server.abort();

        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let redirect_server = tokio::spawn(
            axum::serve(
                listener,
                Router::new().route(
                    "/app/installations/7/access_tokens",
                    post(|| async { axum::response::Redirect::temporary("https://example.com/") }),
                ),
            )
            .into_future(),
        );
        let provider =
            GitHubProvider::new("1".into(), "7".into(), address.to_string(), KEY).unwrap();
        let error = provider
            .authorize_upstream(&repository, GitOperation::Read)
            .await
            .unwrap_err()
            .to_string();
        assert!(error.contains("status 307"));
        assert!(!error.contains("short-lived-secret"));
        redirect_server.abort();
    }
}
