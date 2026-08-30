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
