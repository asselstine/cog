use super::*;
use crate::mcp::service::{catalog, native_admin_scope};

use crate::mcp::{self, RpcRequest, RpcResponse};
use axum::{
    Json,
    extract::Query,
    extract::State,
    http::{HeaderMap, StatusCode, header},
    response::{IntoResponse, Response},
};
use serde::Deserialize;
use serde_json::Value;
use std::sync::{Arc, atomic::Ordering};

pub(super) fn resource_metadata_url(a: &App) -> String {
    format!(
        "{}/.well-known/oauth-protected-resource",
        a.config.base_url.as_str().trim_end_matches('/')
    )
}

pub(super) fn mcp_http_response(response: RpcResponse) -> Response {
    let challenge = response
        .result
        .as_ref()
        .and_then(|result| result.pointer("/_meta/mcp~1www_authenticate/0"))
        .and_then(Value::as_str)
        .map(str::to_owned);
    let mut response = Json(response).into_response();
    if let Some(challenge) = challenge {
        *response.status_mut() = StatusCode::FORBIDDEN;
        response.headers_mut().insert(
            header::WWW_AUTHENTICATE,
            challenge
                .parse()
                .expect("internally generated OAuth challenge is a valid header"),
        );
    }
    response
}

pub(super) fn mcp_origin_allowed(a: &App, auth: &AuthContext, headers: &HeaderMap) -> bool {
    let Some(origin) = headers
        .get(http::header::ORIGIN)
        .and_then(|value| value.to_str().ok())
    else {
        // Non-browser MCP clients generally do not send Origin. A supplied
        // Origin is always validated below, which blocks DNS-rebinding input.
        return true;
    };
    if origin == a.config.base_url.origin().ascii_serialization() {
        return true;
    }
    a.db.client_info(&auth.client)
        .ok()
        .flatten()
        .is_some_and(|(_, redirects)| {
            redirects.iter().any(|redirect| {
                url::Url::parse(redirect)
                    .ok()
                    .is_some_and(|url| url.origin().ascii_serialization() == origin)
            })
        })
}

pub(super) fn mcp_protocol_version_valid(headers: &HeaderMap) -> bool {
    headers
        .get("MCP-Protocol-Version")
        .and_then(|value| value.to_str().ok())
        .is_none_or(mcp::protocol_version_supported)
}
pub(super) async fn mcp_endpoint(
    State(a): State<App>,
    Query(options): Query<McpOptions>,
    headers: HeaderMap,
    Json(req): Json<RpcRequest>,
) -> impl IntoResponse {
    if let Err(e) = a.lease.assert_live() {
        return (StatusCode::SERVICE_UNAVAILABLE, e.to_string()).into_response();
    }
    let auth = match auth_context(&a, &headers) {
        Ok(v) if v.allows("mcp") => v,
        Ok(_) => return auth_failure(&a, AuthFailure::Insufficient, "mcp"),
        Err(failure) => return auth_failure(&a, failure, "mcp"),
    };
    if !mcp_origin_allowed(&a, &auth, &headers) {
        return (StatusCode::FORBIDDEN, "invalid origin").into_response();
    }
    if !mcp_protocol_version_valid(&headers) {
        return (StatusCode::BAD_REQUEST, "unsupported MCP protocol version").into_response();
    }
    // JSON-RPC notifications deliberately have no response object. Streamable
    // HTTP acknowledges an accepted notification with 202 and an empty body.
    // Do this after authentication and lease validation, but before catalog
    // construction: an unavailable upstream must not break base protocol
    // notifications such as rmcp/Codex's `notifications/initialized`.
    if req.id.is_none() {
        return StatusCode::ACCEPTED.into_response();
    }
    if !options.codemode
        && req.method == "tools/call"
        && let Some(name) = req.params.get("name").and_then(Value::as_str)
        && let Some(required) = native_admin_scope(name)
        && name != "cog_integrations_list"
        && !auth.allows(required)
    {
        return mcp_http_response(mcp::insufficient_scope_result(
            req.id.clone(),
            &[required.to_owned()],
            &resource_metadata_url(&a),
        ));
    }
    // Code-mode clients name an immutable integration in describe/call. Check
    // that reference before V8 execution so incremental authorization remains
    // an actionable RFC 6750 HTTP challenge.
    if req.method == "tools/call"
        && req.params.get("name").and_then(Value::as_str) == Some("execute")
        && let Some(code) = req
            .params
            .pointer("/arguments/code")
            .and_then(Value::as_str)
    {
        let mut required_scopes = Vec::new();
        for integration in a.db.list_integrations(&auth.user).unwrap_or_default() {
            let referenced = ["codemode.call", "codemode.describe"]
                .iter()
                .any(|operation| {
                    [
                        format!("{operation}('{}", integration.id),
                        format!("{operation}(\"{}", integration.id),
                    ]
                    .iter()
                    .any(|needle| code.contains(needle))
                });
            if referenced
                && !auth.integrations.contains(&integration.id)
                && !auth.scopes.contains("admin")
            {
                required_scopes.push(format!("integration:{}", integration.id));
            }
        }
        if !required_scopes.is_empty() {
            return mcp_http_response(mcp::insufficient_scope_result(
                req.id.clone(),
                &required_scopes,
                &resource_metadata_url(&a),
            ));
        }
    }
    if req.method == "tools/call"
        && let Some(response) = rate_limit(&a, "mcp_tool", &auth.client, 600)
    {
        return response;
    }
    match catalog(&a, &auth).await {
        Ok(c) => {
            let metadata = resource_metadata_url(&a);
            let response = mcp::handle_with_options(
                req,
                a.runtime.clone(),
                Arc::new(c),
                &metadata,
                options.codemode,
            )
            .await;
            if response
                .result
                .as_ref()
                .and_then(|result| result.get("isError"))
                .and_then(Value::as_bool)
                .unwrap_or(false)
            {
                a.metrics.execution_failures.fetch_add(1, Ordering::Relaxed);
                if response
                    .result
                    .as_ref()
                    .and_then(|result| result.pointer("/content/0/text"))
                    .and_then(Value::as_str)
                    .is_some_and(|message| message.contains("limit") || message.contains("heap"))
                {
                    a.metrics.v8_limit_hits.fetch_add(1, Ordering::Relaxed);
                }
            }
            mcp_http_response(response)
        }
        Err(e) => (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()).into_response(),
    }
}

#[derive(Deserialize)]
pub(super) struct McpOptions {
    #[serde(default = "default_codemode")]
    codemode: bool,
}

pub(super) fn default_codemode() -> bool {
    false
}
