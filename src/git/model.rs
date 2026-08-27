use serde::{Deserialize, Serialize};
use std::fmt;
use url::Url;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum GitOperation {
    Read,
    Write,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RepositoryReference(pub String);

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ResolvedRepository {
    pub provider_repository_id: String,
    pub display_name: String,
    pub upstream_url: Url,
    #[serde(default)]
    pub metadata: serde_json::Value,
}

#[derive(Clone)]
pub struct SecretValue(String);
impl SecretValue {
    pub fn new(value: impl Into<String>) -> Self {
        Self(value.into())
    }
    pub(crate) fn expose(&self) -> &str {
        &self.0
    }
}
impl fmt::Debug for SecretValue {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("[REDACTED]")
    }
}
impl fmt::Display for SecretValue {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("[REDACTED]")
    }
}

#[derive(Clone)]
pub enum UpstreamAuthorization {
    Basic {
        username: SecretValue,
        password: SecretValue,
    },
    Bearer {
        token: SecretValue,
    },
    Anonymous,
}
impl fmt::Debug for UpstreamAuthorization {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("UpstreamAuthorization([REDACTED])")
    }
}

#[derive(Debug, Clone, Serialize)]
pub struct GitRepository {
    pub id: String,
    pub user_id: String,
    pub integration_id: String,
    pub provider_repository_id: String,
    pub display_name: String,
    pub upstream_url: String,
    pub metadata: serde_json::Value,
}

#[derive(Debug, Clone, Serialize)]
pub struct RepositoryGrant {
    pub repository: GitRepository,
    pub permission: String,
    pub last_used_at: Option<i64>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PendingRepositoryRequest {
    pub id: String,
    pub repository_id: String,
    pub integration_id: String,
    pub display_name: String,
    pub permission: String,
    pub expires_at: i64,
}

pub fn valid_repository_id(id: &str) -> bool {
    id.len() == 36 && uuid::Uuid::parse_str(id).is_ok() && !id.contains(['/', '\\'])
}

pub fn classify(
    method: &str,
    endpoint: &str,
    service: Option<&str>,
) -> anyhow::Result<GitOperation> {
    match (method, endpoint, service) {
        ("GET", "info/refs", Some("git-upload-pack")) | ("POST", "git-upload-pack", None) => {
            Ok(GitOperation::Read)
        }
        ("GET", "info/refs", Some("git-receive-pack")) | ("POST", "git-receive-pack", None) => {
            Ok(GitOperation::Write)
        }
        _ => anyhow::bail!("unsupported Git smart-HTTP request"),
    }
}

pub fn validate_upstream(
    url: &Url,
    expected_host: &str,
    allow_loopback_http: bool,
) -> anyhow::Result<()> {
    anyhow::ensure!(
        url.username().is_empty() && url.password().is_none() && url.fragment().is_none(),
        "upstream URL may not contain credentials or a fragment"
    );
    anyhow::ensure!(
        url.host_str()
            .is_some_and(|h| h.eq_ignore_ascii_case(expected_host)),
        "upstream host does not match integration host"
    );
    let loopback = matches!(url.host_str(), Some("localhost" | "127.0.0.1" | "::1"));
    anyhow::ensure!(
        url.scheme() == "https" || (allow_loopback_http && url.scheme() == "http" && loopback),
        "upstream Git URL must use HTTPS"
    );
    Ok(())
}

pub async fn validate_resolved_network(url: &Url, allow_loopback: bool) -> anyhow::Result<()> {
    let host = url
        .host_str()
        .ok_or_else(|| anyhow::anyhow!("upstream host is required"))?;
    let port = url
        .port_or_known_default()
        .ok_or_else(|| anyhow::anyhow!("upstream port is required"))?;
    let addresses = tokio::net::lookup_host((host, port))
        .await?
        .collect::<Vec<_>>();
    anyhow::ensure!(!addresses.is_empty(), "upstream host did not resolve");
    for address in addresses {
        let ip = address.ip();
        let forbidden = ip.is_unspecified()
            || ip.is_multicast()
            || ip.is_loopback()
            || match ip {
                std::net::IpAddr::V4(v) => {
                    v.is_private() || v.is_link_local() || v.is_broadcast() || v.octets()[0] == 0
                }
                std::net::IpAddr::V6(v) => v.is_unique_local() || v.is_unicast_link_local(),
            };
        anyhow::ensure!(
            !forbidden || (allow_loopback && ip.is_loopback()),
            "upstream resolves to a prohibited network"
        )
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn routes_are_strict() {
        assert_eq!(
            classify("GET", "info/refs", Some("git-upload-pack")).unwrap(),
            GitOperation::Read
        );
        assert_eq!(
            classify("POST", "git-receive-pack", None).unwrap(),
            GitOperation::Write
        );
        assert!(classify("POST", "git-upload-pack", Some("git-receive-pack")).is_err());
        assert_eq!(
            classify("GET", "info/refs", Some("git-receive-pack")).unwrap(),
            GitOperation::Write
        );
        assert_eq!(
            classify("POST", "git-upload-pack", None).unwrap(),
            GitOperation::Read
        );
        assert!(classify("GET", "info/refs", None).is_err());
        assert!(classify("DELETE", "git-upload-pack", None).is_err());
        assert!(!valid_repository_id("../x"));
        assert!(valid_repository_id(&uuid::Uuid::new_v4().to_string()));
    }
    #[test]
    fn secrets_redact() {
        let s = SecretValue::new("secret");
        assert_eq!(format!("{s:?}"), "[REDACTED]");
        assert_eq!(format!("{s}"), "[REDACTED]");
        assert_eq!(
            format!("{:?}", UpstreamAuthorization::Anonymous),
            "UpstreamAuthorization([REDACTED])"
        );
    }

    #[test]
    fn upstream_urls_are_canonical_and_credential_free() {
        let valid = Url::parse("https://github.com/owner/repo.git").unwrap();
        validate_upstream(&valid, "GitHub.COM", false).unwrap();
        for invalid in [
            "http://github.com/owner/repo.git",
            "https://user:secret@github.com/owner/repo.git",
            "https://example.com/owner/repo.git",
            "https://github.com/owner/repo.git#secret",
        ] {
            assert!(validate_upstream(&Url::parse(invalid).unwrap(), "github.com", false).is_err());
        }
        validate_upstream(
            &Url::parse("http://127.0.0.1/repo.git").unwrap(),
            "127.0.0.1",
            true,
        )
        .unwrap();
    }

    #[tokio::test]
    async fn network_policy_rejects_private_destinations() {
        assert!(
            validate_resolved_network(&Url::parse("http://127.0.0.1/repo").unwrap(), false)
                .await
                .is_err()
        );
        validate_resolved_network(&Url::parse("http://127.0.0.1/repo").unwrap(), true)
            .await
            .unwrap();
    }
}
