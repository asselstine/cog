//! Transport-neutral Git request metadata and smart-HTTP framing helpers.

use crate::git::{GitOperation, UpstreamAuthorization};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Transport {
    Http,
    Ssh,
}

impl Transport {
    pub const fn metric_label(self) -> &'static str {
        match self {
            Self::Http => "http",
            Self::Ssh => "ssh",
        }
    }
}

#[derive(Debug, Clone)]
pub struct RequestContext {
    pub repository_id: String,
    pub operation: GitOperation,
    pub user_id: String,
    pub identity_id: String,
    pub agent_id: String,
    pub client_id: String,
    pub integration_id: String,
    pub transport: Transport,
    pub protocol: Option<String>,
}

pub fn apply_authorization(
    request: reqwest::RequestBuilder,
    authorization: &UpstreamAuthorization,
) -> reqwest::RequestBuilder {
    match authorization {
        UpstreamAuthorization::Basic { username, password } => {
            request.basic_auth(username.expose(), Some(password.expose()))
        }
        UpstreamAuthorization::Bearer { token } => request.bearer_auth(token.expose()),
        UpstreamAuthorization::Anonymous => request,
    }
}

/// Remove only smart HTTP's bounded service announcement. Pack and pkt-line
/// data remain untouched and can continue to stream with backpressure.
pub fn strip_service_preamble<'a>(body: &'a [u8], service: &str) -> anyhow::Result<&'a [u8]> {
    if body.len() >= 14 && body.get(4..14) == Some(b"version 2\n") {
        return Ok(body);
    }
    let expected = format!("# service={service}\n");
    anyhow::ensure!(body.len() >= 8, "upstream advertisement is truncated");
    let length = usize::from_str_radix(std::str::from_utf8(&body[..4])?, 16)?;
    anyhow::ensure!(
        length == expected.len() + 4 && body.get(4..length) == Some(expected.as_bytes()),
        "upstream advertisement has an invalid service preamble"
    );
    anyhow::ensure!(
        body.get(length..length + 4) == Some(b"0000"),
        "upstream advertisement is missing its preamble flush"
    );
    Ok(&body[length + 4..])
}
