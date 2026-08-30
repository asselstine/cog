use super::*;

pub async fn list_integrations(State(a): State<App>, h: HeaderMap) -> impl IntoResponse {
    let auth = match auth_context(&a, &h) {
        Ok(auth) if auth.allows("integrations:read") => auth,
        Ok(_) => return auth_failure(&a, AuthFailure::Insufficient, "integrations:read"),
        Err(failure) => return auth_failure(&a, failure, "integrations:read"),
    };
    match a.db.list_integrations(&auth.user) {
        Ok(integrations) => Json(json!(
            integrations
                .into_iter()
                .map(|integration| {
                    let access = auth.scopes.contains("admin")
                        || auth.integrations.contains(&integration.id);
                    safe_integration(&a, integration, access)
                })
                .collect::<Vec<_>>()
        ))
        .into_response(),
        Err(_) => StatusCode::INTERNAL_SERVER_ERROR.into_response(),
    }
}
pub async fn get_integration(
    State(a): State<App>,
    Path(id): Path<String>,
    headers: HeaderMap,
) -> impl IntoResponse {
    let user = match scoped_user(&a, &headers, "integrations:read") {
        Ok(user) => user,
        Err(failure) => return auth_failure(&a, failure, "integrations:read"),
    };
    match a.db.integration(&id, &user) {
        Ok(Some(integration)) => Json(integration).into_response(),
        Ok(None) => StatusCode::NOT_FOUND.into_response(),
        Err(error) => (StatusCode::INTERNAL_SERVER_ERROR, error.to_string()).into_response(),
    }
}

pub async fn list_agent_clients(State(a): State<App>, headers: HeaderMap) -> impl IntoResponse {
    let user = match scoped_user(&a, &headers, "agents:read") {
        Ok(user) => user,
        Err(failure) => return auth_failure(&a, failure, "agents:read"),
    };
    match a.db.agent_clients(&user) {
        Ok(clients) => Json(json!(clients)).into_response(),
        Err(error) => (StatusCode::INTERNAL_SERVER_ERROR, error.to_string()).into_response(),
    }
}

pub async fn list_agent_tokens(State(a): State<App>, headers: HeaderMap) -> impl IntoResponse {
    let user = match scoped_user(&a, &headers, "agents:read") {
        Ok(user) => user,
        Err(failure) => return auth_failure(&a, failure, "agents:read"),
    };
    match a.db.agent_tokens(&user) {
        Ok(tokens) => Json(json!(tokens)).into_response(),
        Err(error) => (StatusCode::INTERNAL_SERVER_ERROR, error.to_string()).into_response(),
    }
}

pub async fn revoke_agent_client(
    State(a): State<App>,
    Path(client): Path<String>,
    headers: HeaderMap,
) -> impl IntoResponse {
    let user = match scoped_user(&a, &headers, "agents:write") {
        Ok(user) => user,
        Err(failure) => return auth_failure(&a, failure, "agents:write"),
    };
    match admin_revoke_client(&a, &user, &client).await {
        Ok(_) => StatusCode::NO_CONTENT.into_response(),
        Err(error) if error.to_string().contains("not found") => {
            StatusCode::NOT_FOUND.into_response()
        }
        Err(error) => (StatusCode::BAD_REQUEST, error.to_string()).into_response(),
    }
}

pub async fn revoke_agent_grant(
    State(a): State<App>,
    Path((client, integration)): Path<(String, String)>,
    headers: HeaderMap,
) -> impl IntoResponse {
    let user = match scoped_user(&a, &headers, "agents:write") {
        Ok(user) => user,
        Err(failure) => return auth_failure(&a, failure, "agents:write"),
    };
    match admin_revoke_grant(&a, &user, &client, &integration).await {
        Ok(_) => StatusCode::NO_CONTENT.into_response(),
        Err(error) if error.to_string().contains("not found") => {
            StatusCode::NOT_FOUND.into_response()
        }
        Err(error) => (StatusCode::BAD_REQUEST, error.to_string()).into_response(),
    }
}

pub async fn revoke_agent_token(
    State(a): State<App>,
    Path(token): Path<String>,
    headers: HeaderMap,
) -> impl IntoResponse {
    let user = match scoped_user(&a, &headers, "agents:write") {
        Ok(user) => user,
        Err(failure) => return auth_failure(&a, failure, "agents:write"),
    };
    match admin_revoke_token(&a, &user, &token).await {
        Ok(_) => StatusCode::NO_CONTENT.into_response(),
        Err(error) if error.to_string().contains("not found") => {
            StatusCode::NOT_FOUND.into_response()
        }
        Err(error) => (StatusCode::BAD_REQUEST, error.to_string()).into_response(),
    }
}

#[derive(Deserialize)]
pub struct AuditQuery {
    #[serde(default = "default_audit_limit")]
    pub limit: u32,
}

pub(super) fn default_audit_limit() -> u32 {
    100
}

pub async fn list_audit_events(
    State(a): State<App>,
    headers: HeaderMap,
    axum::extract::Query(query): axum::extract::Query<AuditQuery>,
) -> impl IntoResponse {
    let user = match scoped_user(&a, &headers, "audit:read") {
        Ok(user) => user,
        Err(failure) => return auth_failure(&a, failure, "audit:read"),
    };
    match a.db.audit_events_for_user(&user, query.limit) {
        Ok(events) => Json(json!(events)).into_response(),
        Err(error) => (StatusCode::INTERNAL_SERVER_ERROR, error.to_string()).into_response(),
    }
}
#[derive(Deserialize)]
pub(super) struct NewIntegration {
    name: String,
    transport: String,
    config: Value,
    headers: Option<HashMap<String, String>>,
}

#[derive(Clone, Deserialize)]
pub(super) struct HttpTransportConfig {
    pub(super) url: url::Url,
    #[serde(default)]
    pub(super) oauth: Option<UpstreamOAuthConfig>,
}

#[derive(Clone, Default, Deserialize)]
pub(super) struct UpstreamOAuthConfig {
    pub(super) resource_metadata_url: Option<url::Url>,
    pub(super) resource: Option<String>,
    pub(super) issuer: Option<url::Url>,
    pub(super) authorization_endpoint: Option<url::Url>,
    pub(super) token_endpoint: Option<url::Url>,
    pub(super) registration_endpoint: Option<url::Url>,
    pub(super) client_id: Option<String>,
    pub(super) client_secret: Option<String>,
    pub(super) scope: Option<String>,
}

#[derive(Deserialize)]
pub(super) struct StdioTransportConfig {
    command: String,
    #[serde(default)]
    args: Vec<String>,
}

#[derive(Clone, Default, Deserialize)]
pub struct IntegrationPolicy {
    pub allow_tools: Option<Vec<String>>,
    #[serde(default)]
    pub deny_tools: Vec<String>,
}

pub fn integration_policy(config: &Value) -> anyhow::Result<Option<IntegrationPolicy>> {
    config
        .get("policy")
        .filter(|value| !value.is_null())
        .cloned()
        .map(serde_json::from_value)
        .transpose()
        .map_err(Into::into)
}

pub fn validate_policy(config: &Value) -> anyhow::Result<()> {
    if let Some(policy) = integration_policy(config)? {
        let names = policy
            .allow_tools
            .iter()
            .flatten()
            .chain(policy.deny_tools.iter());
        for name in names {
            anyhow::ensure!(
                !name.is_empty()
                    && name.len() <= 128
                    && name
                        .bytes()
                        .all(|byte| byte.is_ascii_alphanumeric()
                            || matches!(byte, b'_' | b'-' | b'.')),
                "policy contains an invalid tool name"
            );
        }
    }
    Ok(())
}

pub fn validate_transport(
    transport: &str,
    config: &Value,
    headers: Option<&HashMap<String, String>>,
    allow_stdio: bool,
) -> anyhow::Result<()> {
    validate_policy(config)?;
    match transport {
        "http" | "sse" => {
            let parsed: HttpTransportConfig = serde_json::from_value(config.clone())?;
            anyhow::ensure!(
                matches!(parsed.url.scheme(), "http" | "https"),
                "HTTP transport URL must use http or https"
            );
            anyhow::ensure!(
                parsed.url.username().is_empty() && parsed.url.password().is_none(),
                "credentials must be submitted through encrypted secret fields, not URLs"
            );
            if let Some(oauth) = parsed.oauth {
                anyhow::ensure!(
                    oauth
                        .scope
                        .as_deref()
                        .is_none_or(|scope| !scope.trim().is_empty()),
                    "OAuth scope cannot be empty"
                );
                anyhow::ensure!(
                    oauth.client_secret.is_none(),
                    "OAuth client secrets cannot be stored in integration configuration; use dynamic registration"
                );
                if let Some(resource) = oauth.resource.as_ref() {
                    validate_oauth_uri(&url::Url::parse(resource)?, "OAuth resource")?;
                }
                for endpoint in [
                    oauth.resource_metadata_url,
                    oauth.issuer,
                    oauth.authorization_endpoint,
                    oauth.token_endpoint,
                    oauth.registration_endpoint,
                ]
                .into_iter()
                .flatten()
                {
                    anyhow::ensure!(
                        endpoint.scheme() == "https"
                            || (endpoint.scheme() == "http"
                                && matches!(
                                    endpoint.host_str(),
                                    Some("localhost" | "127.0.0.1" | "::1")
                                )),
                        "OAuth endpoints must use HTTPS except loopback"
                    );
                    anyhow::ensure!(
                        endpoint.username().is_empty() && endpoint.password().is_none(),
                        "OAuth endpoint URLs cannot contain credentials"
                    );
                }
            }
        }
        "stdio" => {
            anyhow::ensure!(
                allow_stdio,
                "stdio integrations are disabled by deployment policy"
            );
            let parsed: StdioTransportConfig = serde_json::from_value(config.clone())?;
            anyhow::ensure!(
                !parsed.command.trim().is_empty(),
                "stdio command is required"
            );
            anyhow::ensure!(
                parsed.args.iter().all(|argument| !argument.contains('\0')),
                "stdio arguments cannot contain NUL"
            );
        }
        "git" => {
            anyhow::ensure!(
                config.get("kind").and_then(Value::as_str) == Some("git"),
                "Git integration kind must be git"
            );
            anyhow::ensure!(
                config.get("provider").and_then(Value::as_str) == Some("github"),
                "only the GitHub provider is currently supported"
            );
            let provider = config
                .get("providerConfig")
                .and_then(Value::as_object)
                .ok_or_else(|| anyhow::anyhow!("providerConfig is required"))?;
            anyhow::ensure!(
                provider
                    .get("appId")
                    .and_then(Value::as_str)
                    .is_some_and(|v| !v.is_empty())
                    && provider
                        .get("installationId")
                        .and_then(Value::as_str)
                        .is_some_and(|v| !v.is_empty()),
                "GitHub App and installation IDs are required"
            );
            let key = headers
                .and_then(|h| h.get("privateKey"))
                .ok_or_else(|| anyhow::anyhow!("GitHub App privateKey secret is required"))?;
            GitHubProvider::new(
                provider["appId"].as_str().unwrap().to_owned(),
                provider["installationId"].as_str().unwrap().to_owned(),
                config
                    .get("host")
                    .and_then(Value::as_str)
                    .unwrap_or("github.com")
                    .to_owned(),
                key.as_bytes(),
            )?;
        }
        _ => anyhow::bail!("unsupported transport"),
    }
    if let Some(headers) = headers {
        for (name, value) in headers {
            http::HeaderName::try_from(name)?;
            http::HeaderValue::try_from(value)?;
        }
    }
    Ok(())
}

pub fn validate_oauth_uri(uri: &url::Url, label: &str) -> anyhow::Result<()> {
    anyhow::ensure!(uri.has_host(), "{label} must be an absolute URI");
    anyhow::ensure!(
        uri.username().is_empty() && uri.password().is_none(),
        "{label} cannot contain userinfo"
    );
    anyhow::ensure!(
        uri.fragment().is_none(),
        "{label} cannot contain a fragment"
    );
    anyhow::ensure!(
        uri.scheme() == "https"
            || (uri.scheme() == "http"
                && matches!(uri.host_str(), Some("localhost" | "127.0.0.1" | "::1"))),
        "{label} must use HTTPS except loopback"
    );
    Ok(())
}
pub(super) async fn add_integration(
    State(a): State<App>,
    h: HeaderMap,
    Json(n): Json<NewIntegration>,
) -> impl IntoResponse {
    let u = match scoped_user(&a, &h, "integrations:write") {
        Ok(v) => v,
        Err(failure) => return auth_failure(&a, failure, "integrations:write"),
    };
    match admin_create(
        &a,
        &u,
        json!({"name":n.name,"transport":n.transport,"config":n.config,"headers":n.headers}),
    )
    .await
    {
        Ok(value) => (StatusCode::CREATED, Json(value)).into_response(),
        Err(error) => (StatusCode::BAD_REQUEST, error.to_string()).into_response(),
    }
}

#[derive(Deserialize)]
pub(super) struct UpdateIntegration {
    name: Option<String>,
    config: Option<Value>,
    enabled: Option<bool>,
    headers: Option<HashMap<String, String>>,
}

pub async fn admin_create(a: &App, user: &str, args: Value) -> anyhow::Result<Value> {
    let _mutation = a.mutations.lock().await;
    a.lease.assert_live()?;
    let request: NewIntegration = serde_json::from_value(args)?;
    validate_transport(
        &request.transport,
        &request.config,
        request.headers.as_ref(),
        a.config.allow_stdio,
    )?;
    let secret = request
        .headers
        .map(|headers| a.secrets.seal(&serde_json::to_vec(&headers)?))
        .transpose()?;
    let id = a.db.create_integration(
        user,
        &request.name,
        &request.transport,
        &request.config,
        secret.as_deref(),
    )?;
    audit(a, Some(user), "integration.create", Some(&id), "success")?;
    persist(a).await?;
    Ok(json!({"id":id}))
}

pub async fn admin_update(a: &App, user: &str, id: String, args: Value) -> anyhow::Result<Value> {
    let _mutation = a.mutations.lock().await;
    a.lease.assert_live()?;
    let update: UpdateIntegration = serde_json::from_value(args)?;
    let current =
        a.db.integration(&id, user)?
            .ok_or_else(|| anyhow::anyhow!("integration not found"))?;
    validate_transport(
        &current.transport,
        update.config.as_ref().unwrap_or(&current.config),
        update.headers.as_ref(),
        a.config.allow_stdio,
    )?;
    let secret = update
        .headers
        .as_ref()
        .map(|headers| a.secrets.seal(&serde_json::to_vec(headers)?))
        .transpose()?;
    a.db.update_integration(
        &id,
        user,
        update.name.as_deref(),
        update.config.as_ref(),
        update.enabled,
        secret.as_deref(),
    )?;
    if update.config.is_some() {
        a.db.clear_upstream_oauth(&id)?;
    }
    disconnect_provider(a, &id).await;
    a.git_providers.lock().await.remove(&id);
    audit(a, Some(user), "integration.update", Some(&id), "success")?;
    persist(a).await?;
    Ok(json!({"id":id,"updated":true}))
}

pub async fn admin_reconnect(a: &App, user: &str, id: &str) -> anyhow::Result<Value> {
    admin_disconnect(a, user, id).await?;
    let integration =
        a.db.integration(id, user)?
            .ok_or_else(|| anyhow::anyhow!("integration not found"))?;
    if !integration
        .config
        .get("oauth")
        .is_some_and(|value| !value.is_null())
    {
        return Ok(json!({
            "id": id,
            "deprecatedOperation": "integration_reconnect",
            "reconnected": false,
            "upstreamConnected": true,
            "upstreamStatus": "configured",
            "message": "Static credentials were removed. Configure new credentials with integration_update; use integration_disconnect for future credential removal."
        }));
    }
    let mut result = admin_authorize(a, user, id).await?;
    if let Some(object) = result.as_object_mut() {
        object.insert("deprecatedOperation".into(), json!("integration_reconnect"));
        object.insert("reconnected".into(), json!(false));
        object.insert("message".into(), json!("Credentials were removed; reauthorization must complete before the integration is reconnected."));
    }
    Ok(result)
}

pub async fn admin_disconnect(a: &App, user: &str, id: &str) -> anyhow::Result<Value> {
    let _mutation = a.mutations.lock().await;
    a.lease.assert_live()?;
    anyhow::ensure!(
        a.db.clear_integration_credentials(id, user)?,
        "integration not found"
    );
    disconnect_provider(a, id).await;
    a.git_providers.lock().await.remove(id);
    audit(a, Some(user), "integration.disconnect", Some(id), "success")?;
    persist(a).await?;
    let integration =
        a.db.integration(id, user)?
            .expect("integration was preserved");
    Ok(safe_integration(a, integration, false))
}

pub async fn admin_delete(a: &App, user: &str, id: &str) -> anyhow::Result<Value> {
    let _mutation = a.mutations.lock().await;
    a.lease.assert_live()?;
    anyhow::ensure!(a.db.delete_integration(id, user)?, "integration not found");
    disconnect_provider(a, id).await;
    a.git_providers.lock().await.remove(id);
    audit(a, Some(user), "integration.delete", Some(id), "success")?;
    persist(a).await?;
    Ok(json!({"id":id,"deleted":true}))
}

pub async fn admin_revoke_client(a: &App, user: &str, id: &str) -> anyhow::Result<Value> {
    let _mutation = a.mutations.lock().await;
    a.lease.assert_live()?;
    anyhow::ensure!(a.db.revoke_agent_client(user, id)?, "client not found");
    audit(a, Some(user), "agent_client.revoke", Some(id), "success")?;
    persist(a).await?;
    Ok(json!({"id":id,"revoked":true}))
}

pub async fn admin_revoke_token(a: &App, user: &str, id: &str) -> anyhow::Result<Value> {
    let _mutation = a.mutations.lock().await;
    a.lease.assert_live()?;
    anyhow::ensure!(a.db.revoke_agent_token(user, id)?, "token not found");
    audit(a, Some(user), "agent_token.revoke", Some(id), "success")?;
    persist(a).await?;
    Ok(json!({"id":id,"revoked":true}))
}

pub async fn admin_revoke_grant(
    a: &App,
    user: &str,
    client: &str,
    integration: &str,
) -> anyhow::Result<Value> {
    let _mutation = a.mutations.lock().await;
    a.lease.assert_live()?;
    anyhow::ensure!(
        a.db.revoke_client_integration_grant(user, client, integration)?,
        "grant not found"
    );
    audit(a, Some(user), "agent_grant.revoke", Some(client), "success")?;
    persist(a).await?;
    Ok(json!({"client_id":client,"integration_id":integration,"revoked":true}))
}

pub async fn admin_authorize(a: &App, user: &str, id: &str) -> anyhow::Result<Value> {
    let _mutation = a.mutations.lock().await;
    a.lease.assert_live()?;
    let integration =
        a.db.integration(id, user)?
            .ok_or_else(|| anyhow::anyhow!("integration not found"))?;
    anyhow::ensure!(
        integration
            .config
            .get("oauth")
            .is_some_and(|value| !value.is_null()),
        "integration does not use upstream OAuth"
    );
    let (status, connected) = upstream_connection_state(a, &integration);
    if connected {
        return Ok(json!({
            "id": id,
            "alreadyConnected": true,
            "upstreamConnected": true,
            "upstreamStatus": status,
            "reconnectRequired": true
        }));
    }
    let client = resolve_upstream_client(a, &integration).await?;
    let state = crate::crypto::random_token(32);
    let verifier = crate::crypto::random_token(48);
    use base64::Engine;
    use sha2::Digest;
    let challenge = base64::engine::general_purpose::URL_SAFE_NO_PAD
        .encode(sha2::Sha256::digest(verifier.as_bytes()));
    let redirect = format!(
        "{}/oauth/upstream/callback",
        a.config.base_url.as_str().trim_end_matches('/')
    );
    let sealed = a.secrets.seal(verifier.as_bytes())?;
    a.db.store_oauth_state(
        &token_hash(&state),
        user,
        id,
        &sealed,
        &redirect,
        chrono::Utc::now().timestamp() + 600,
        client.resource.as_deref(),
    )?;
    audit(
        a,
        Some(user),
        "integration.oauth_start",
        Some(id),
        "success",
    )?;
    persist(a).await?;
    let mut url = url::Url::parse(&client.authorization_endpoint)?;
    let mut pairs = url.query_pairs_mut();
    pairs
        .append_pair("response_type", "code")
        .append_pair("client_id", &client.client_id)
        .append_pair("redirect_uri", &redirect)
        .append_pair("state", &state)
        .append_pair("code_challenge", &challenge)
        .append_pair("code_challenge_method", "S256");
    if !client.scope.is_empty() {
        pairs.append_pair("scope", &client.scope);
    }
    if let Some(resource) = client.resource.as_deref() {
        pairs.append_pair("resource", resource);
    }
    drop(pairs);
    Ok(
        json!({"id":id,"alreadyConnected":false,"upstreamConnected":false,"upstreamStatus":status,"authorization_url":url,"one_time":true,"prefetched":false}),
    )
}

pub(super) async fn update_integration(
    State(a): State<App>,
    Path(id): Path<String>,
    headers: HeaderMap,
    Json(update): Json<UpdateIntegration>,
) -> impl IntoResponse {
    let user = match scoped_user(&a, &headers, "integrations:write") {
        Ok(user) => user,
        Err(failure) => return auth_failure(&a, failure, "integrations:write"),
    };
    match admin_update(&a, &user, id, json!({"name":update.name,"config":update.config,"enabled":update.enabled,"headers":update.headers})).await {
        Ok(_) => StatusCode::NO_CONTENT.into_response(), Err(error) if error.to_string().contains("not found") => StatusCode::NOT_FOUND.into_response(), Err(error) => (StatusCode::BAD_REQUEST, error.to_string()).into_response()
    }
}

pub async fn reconnect_integration(
    State(a): State<App>,
    Path(id): Path<String>,
    headers: HeaderMap,
) -> impl IntoResponse {
    let user = match scoped_user(&a, &headers, "integrations:write") {
        Ok(user) => user,
        Err(failure) => return auth_failure(&a, failure, "integrations:write"),
    };
    match admin_reconnect(&a, &user, &id).await {
        Ok(_) => StatusCode::NO_CONTENT.into_response(),
        Err(error) if error.to_string().contains("not found") => {
            StatusCode::NOT_FOUND.into_response()
        }
        Err(error) => (StatusCode::BAD_REQUEST, error.to_string()).into_response(),
    }
}

pub async fn disconnect_integration(
    State(a): State<App>,
    Path(id): Path<String>,
    headers: HeaderMap,
) -> impl IntoResponse {
    let user = match scoped_user(&a, &headers, "integrations:write") {
        Ok(user) => user,
        Err(failure) => return auth_failure(&a, failure, "integrations:write"),
    };
    match admin_disconnect(&a, &user, &id).await {
        Ok(value) => Json(value).into_response(),
        Err(error) if error.to_string().contains("not found") => {
            StatusCode::NOT_FOUND.into_response()
        }
        Err(error) => (StatusCode::BAD_REQUEST, error.to_string()).into_response(),
    }
}

pub async fn delete_integration(
    State(a): State<App>,
    Path(id): Path<String>,
    headers: HeaderMap,
) -> impl IntoResponse {
    let user = match scoped_user(&a, &headers, "integrations:write") {
        Ok(user) => user,
        Err(failure) => return auth_failure(&a, failure, "integrations:write"),
    };
    match admin_delete(&a, &user, &id).await {
        Ok(_) => StatusCode::NO_CONTENT.into_response(),
        Err(error) if error.to_string().contains("not found") => {
            StatusCode::NOT_FOUND.into_response()
        }
        Err(error) => (StatusCode::BAD_REQUEST, error.to_string()).into_response(),
    }
}

pub(super) async fn disconnect_provider(a: &App, id: &str) {
    let provider = a.providers.lock().await.remove(id);
    if let Some(provider) = provider
        && let Err(error) = provider.close().await
    {
        tracing::warn!(error = %safe_error(error.as_ref()), integration_id = id, "upstream cleanup failed");
    }
}

pub(super) async fn oauth_json(request: reqwest::RequestBuilder) -> anyhow::Result<Value> {
    const MAX_OAUTH_RESPONSE: usize = 1024 * 1024;
    let response = request.send().await?.error_for_status()?;
    anyhow::ensure!(
        response.content_length().unwrap_or(0) <= MAX_OAUTH_RESPONSE as u64,
        "upstream OAuth response too large"
    );
    let bytes = response.bytes().await?;
    anyhow::ensure!(
        bytes.len() <= MAX_OAUTH_RESPONSE,
        "upstream OAuth response too large"
    );
    Ok(serde_json::from_slice(&bytes)?)
}
