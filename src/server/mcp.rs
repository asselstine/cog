use super::*;
use axum::{
    Router,
    body::{Body, to_bytes},
    extract::{Request, State},
    middleware::{self, Next},
    response::{IntoResponse, Response},
};
use rmcp::transport::streamable_http_server::{
    StreamableHttpServerConfig, StreamableHttpService, session::local::LocalSessionManager,
};
use std::sync::Arc;

pub(super) fn resource_metadata_url(a: &App) -> String {
    format!(
        "{}/.well-known/oauth-protected-resource",
        a.config.base_url.as_str().trim_end_matches('/')
    )
}

pub(super) fn mcp_origin_allowed(a: &App, auth: &AuthContext, headers: &HeaderMap) -> bool {
    let Some(origin) = headers
        .get(http::header::ORIGIN)
        .and_then(|value| value.to_str().ok())
    else {
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

async fn mcp_guard(State(app): State<App>, mut request: Request, next: Next) -> Response {
    if let Err(error) = app.lease.assert_live() {
        return (StatusCode::SERVICE_UNAVAILABLE, error.to_string()).into_response();
    }
    let auth = match auth_context(&app, request.headers()) {
        Ok(auth) if auth.allows("mcp") => auth,
        Ok(_) => return auth_failure(&app, AuthFailure::Insufficient, "mcp"),
        Err(failure) => return auth_failure(&app, failure, "mcp"),
    };
    if !mcp_origin_allowed(&app, &auth, request.headers()) {
        return (StatusCode::FORBIDDEN, "invalid origin").into_response();
    }
    if request.uri().query().is_some_and(|query| {
        query.split('&').any(|part| {
            part.starts_with("codemode=")
                && !matches!(
                    part,
                    "codemode=true" | "codemode=false" | "codemode=1" | "codemode=0"
                )
        })
    }) {
        return (StatusCode::BAD_REQUEST, "codemode must be true or false").into_response();
    }
    if request.method() == http::Method::POST
        && let Some(response) = rate_limit(&app, "mcp", &auth.client, 1200)
    {
        return response;
    }
    if request.method() == http::Method::POST {
        let (parts, body) = request.into_parts();
        let bytes = match to_bytes(body, crate::mcp::client::MAX_MESSAGE_BYTES).await {
            Ok(bytes) => bytes,
            Err(error) => return (StatusCode::BAD_REQUEST, error.to_string()).into_response(),
        };
        if let Ok(value) = serde_json::from_slice::<serde_json::Value>(&bytes)
            && value.get("method").and_then(serde_json::Value::as_str) == Some("tools/call")
        {
            let name = value
                .pointer("/params/name")
                .and_then(serde_json::Value::as_str);
            let codemode = parts.uri.query().is_some_and(|query| {
                query
                    .split('&')
                    .any(|part| matches!(part, "codemode=true" | "codemode=1"))
            });
            if !codemode
                && let Some(definition) = name.and_then(crate::mcp::tools::by_public_name)
                && definition.id != crate::mcp::tools::NativeToolId::Execute
                && !auth.allows(definition.required_scope)
            {
                return insufficient_scope_http(&app, &[definition.required_scope.to_owned()]);
            }
            if name == Some("execute")
                && let Some(declared) = value
                    .pointer("/params/arguments/integrations")
                    .and_then(serde_json::Value::as_array)
            {
                let known = match app.db.list_integrations(&auth.user) {
                    Ok(integrations) => integrations
                        .into_iter()
                        .map(|integration| integration.id)
                        .collect::<std::collections::HashSet<_>>(),
                    Err(_) => {
                        return (
                            StatusCode::INTERNAL_SERVER_ERROR,
                            "integration authorization lookup failed",
                        )
                            .into_response();
                    }
                };
                let missing = declared
                    .iter()
                    .filter_map(serde_json::Value::as_str)
                    .filter(|id| known.contains(*id))
                    .filter(|id| !auth.allows_integration(id))
                    .map(|id| format!("integration:{id}"))
                    .collect::<Vec<_>>();
                if !missing.is_empty() {
                    return insufficient_scope_http(&app, &missing);
                }
            }
        }
        request = Request::from_parts(parts, Body::from(bytes));
    }
    request.extensions_mut().insert(auth);
    if !request.headers().contains_key(http::header::HOST)
        && let Some(host) = app.config.base_url.host_str()
    {
        request.headers_mut().insert(
            http::header::HOST,
            host.parse().expect("configured host is a valid header"),
        );
    }
    if !request.headers().contains_key(http::header::ACCEPT) {
        request.headers_mut().insert(
            http::header::ACCEPT,
            "application/json, text/event-stream".parse().unwrap(),
        );
    }
    if request.method() == http::Method::POST
        && !request.headers().contains_key("MCP-Protocol-Version")
    {
        request
            .headers_mut()
            .insert("MCP-Protocol-Version", "2025-11-25".parse().unwrap());
    }
    next.run(request).await
}

fn insufficient_scope_http(app: &App, scopes: &[String]) -> Response {
    let mut required = vec!["mcp".to_owned()];
    required.extend(
        scopes
            .iter()
            .filter(|scope| scope.as_str() != "mcp")
            .cloned(),
    );
    let challenge = format!(
        "Bearer resource_metadata=\"{}\", error=\"insufficient_scope\", error_description=\"Additional authorization is required\", scope=\"{}\"",
        resource_metadata_url(app),
        required.join(" ")
    );
    (
        StatusCode::FORBIDDEN,
        [(http::header::WWW_AUTHENTICATE, challenge)],
        "additional authorization is required",
    )
        .into_response()
}

pub(super) fn mcp_router(app: App) -> Router {
    let service: StreamableHttpService<crate::mcp::CogServer, LocalSessionManager> =
        StreamableHttpService::new(
            {
                let app = app.clone();
                move || Ok(crate::mcp::CogServer::new(app.clone()))
            },
            Arc::new(LocalSessionManager::default()),
            StreamableHttpServerConfig::default()
                .with_legacy_session_mode(true)
                .with_json_response(true)
                .with_max_request_body_bytes(crate::mcp::client::MAX_MESSAGE_BYTES),
        );
    Router::new()
        .nest_service("/mcp", service)
        .route_layer(DefaultBodyLimit::max(crate::mcp::client::MAX_MESSAGE_BYTES))
        .route_layer(middleware::from_fn_with_state(app, mcp_guard))
}
