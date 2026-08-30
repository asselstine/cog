use super::*;

pub fn well_known(base: &url::Url, name: &str) -> anyhow::Result<url::Url> {
    let mut url = base.clone();
    let issuer_path = base.path().trim_start_matches('/');
    let path = if issuer_path.is_empty() {
        format!("/.well-known/{name}")
    } else {
        format!("/.well-known/{name}/{issuer_path}")
    };
    url.set_path(&path);
    url.set_query(None);
    url.set_fragment(None);
    Ok(url)
}

pub(super) fn oidc_well_known(issuer: &url::Url) -> anyhow::Result<url::Url> {
    let mut url = issuer.clone();
    let path = format!(
        "{}/.well-known/openid-configuration",
        issuer.path().trim_end_matches('/')
    );
    url.set_path(&path);
    url.set_query(None);
    url.set_fragment(None);
    Ok(url)
}

pub async fn authorization_server_metadata(
    http: &reqwest::Client,
    issuer: &url::Url,
) -> anyhow::Result<Value> {
    let oauth_url = well_known(issuer, "oauth-authorization-server")?;
    match oauth_json(http.get(oauth_url)).await {
        Ok(metadata) => Ok(metadata),
        Err(oauth_error) => {
            let oidc_url = oidc_well_known(issuer)?;
            oauth_json(http.get(oidc_url)).await.map_err(|oidc_error| {
                anyhow::anyhow!(
                    "authorization-server metadata discovery failed (OAuth: {oauth_error}; OIDC: {oidc_error})"
                )
            })
        }
    }
}

pub async fn resolve_upstream_client(
    a: &App,
    integration: &crate::db::Integration,
) -> anyhow::Result<UpstreamOAuthClient> {
    if let Some(client) = a.db.upstream_oauth_client(&integration.id)? {
        return Ok(client);
    }
    let transport: HttpTransportConfig = serde_json::from_value(integration.config.clone())?;
    let oauth = transport
        .oauth
        .ok_or_else(|| anyhow::anyhow!("integration has no OAuth configuration"))?;
    let http = reqwest::Client::builder()
        .timeout(Duration::from_secs(15))
        .build()?;
    let mut issuer = oauth.issuer.clone();
    // Keep the issuer's advertised representation for RFC 9207 callback
    // comparison. `url::Url::to_string()` adds `/` to an origin-only URL,
    // which would turn an exact advertised issuer such as
    // `https://mcp.cloudflare.com` into a different issuer identifier.
    let mut advertised_issuer = issuer.as_ref().map(|value| value.as_str().to_owned());
    let mut authorization = oauth.authorization_endpoint.clone();
    let mut token = oauth.token_endpoint.clone();
    let mut registration = oauth.registration_endpoint.clone();
    let mut scope = oauth.scope.clone();
    let explicit_resource = oauth.resource.clone();
    let mut resource = None;
    let mut client_id_metadata_supported = false;

    if (authorization.is_none() || token.is_none()) && issuer.is_none() {
        let resource_metadata = match oauth.resource_metadata_url {
            Some(url) => url,
            None => well_known(&transport.url, "oauth-protected-resource")?,
        };
        let metadata = oauth_json(http.get(resource_metadata)).await?;
        resource = metadata
            .get("resource")
            .and_then(Value::as_str)
            .map(str::to_owned);
        if let Some(discovered) = resource.as_ref() {
            validate_oauth_uri(&url::Url::parse(discovered)?, "discovered OAuth resource")?;
        }
        if let (Some(explicit), Some(discovered)) = (&explicit_resource, &resource) {
            anyhow::ensure!(
                explicit == discovered,
                "explicit OAuth resource conflicts with protected-resource metadata"
            );
        }
        let authorization_server = metadata
            .get("authorization_servers")
            .and_then(Value::as_array)
            .and_then(|servers| servers.first())
            .and_then(Value::as_str);
        issuer = authorization_server.map(url::Url::parse).transpose()?;
        advertised_issuer = authorization_server.map(str::to_owned);
        anyhow::ensure!(
            issuer.is_some(),
            "protected-resource metadata has no authorization server"
        );
    }

    if authorization.is_none()
        || token.is_none()
        || (oauth.client_id.is_none() && registration.is_none())
    {
        let issuer = issuer
            .clone()
            .ok_or_else(|| anyhow::anyhow!("OAuth issuer is required for discovery"))?;
        let metadata = authorization_server_metadata(&http, &issuer).await?;
        client_id_metadata_supported = metadata
            .get("client_id_metadata_document_supported")
            .and_then(Value::as_bool)
            .unwrap_or(false);
        if scope.is_none() {
            scope = metadata
                .get("scopes_supported")
                .and_then(Value::as_array)
                .and_then(|scopes| {
                    scopes
                        .iter()
                        .filter_map(Value::as_str)
                        .find(|candidate| *candidate == "mcp")
                        .or_else(|| scopes.iter().find_map(Value::as_str))
                })
                .map(str::to_owned);
        }
        if let Some(discovered_issuer) = metadata.get("issuer").and_then(Value::as_str) {
            anyhow::ensure!(
                url::Url::parse(discovered_issuer)? == issuer,
                "authorization-server issuer mismatch"
            );
            advertised_issuer = Some(discovered_issuer.to_owned());
        }
        authorization = authorization.or_else(|| {
            metadata
                .get("authorization_endpoint")
                .and_then(Value::as_str)
                .and_then(|value| url::Url::parse(value).ok())
        });
        token = token.or_else(|| {
            metadata
                .get("token_endpoint")
                .and_then(Value::as_str)
                .and_then(|value| url::Url::parse(value).ok())
        });
        registration = registration.or_else(|| {
            metadata
                .get("registration_endpoint")
                .and_then(Value::as_str)
                .and_then(|value| url::Url::parse(value).ok())
        });
        anyhow::ensure!(
            metadata
                .get("code_challenge_methods_supported")
                .and_then(Value::as_array)
                .is_some_and(|methods| methods.iter().any(|method| method == "S256")),
            "upstream authorization server does not advertise PKCE S256"
        );
    }
    let authorization =
        authorization.ok_or_else(|| anyhow::anyhow!("authorization endpoint missing"))?;
    let token = token.ok_or_else(|| anyhow::anyhow!("token endpoint missing"))?;
    let (client_id, client_secret) = if let Some(client_id) = oauth.client_id {
        (client_id, oauth.client_secret)
    } else if client_id_metadata_supported {
        (
            format!(
                "{}/.well-known/oauth-client",
                a.config.base_url.as_str().trim_end_matches('/')
            ),
            None,
        )
    } else {
        let registration = registration
            .ok_or_else(|| anyhow::anyhow!("upstream does not advertise dynamic registration"))?;
        let redirect = format!(
            "{}/oauth/upstream/callback",
            a.config.base_url.as_str().trim_end_matches('/')
        );
        let response = oauth_json(http.post(registration).json(&json!({
            "client_name":"cog",
            "redirect_uris":[redirect],
            "grant_types":["authorization_code","refresh_token"],
            "response_types":["code"],
            "token_endpoint_auth_method":"client_secret_post"
        })))
        .await?;
        (
            response
                .get("client_id")
                .and_then(Value::as_str)
                .ok_or_else(|| anyhow::anyhow!("registration response has no client_id"))?
                .to_owned(),
            response
                .get("client_secret")
                .and_then(Value::as_str)
                .map(str::to_owned),
        )
    };
    let client = UpstreamOAuthClient {
        client_id,
        client_secret_ciphertext: client_secret
            .map(|secret| a.secrets.seal(secret.as_bytes()))
            .transpose()?,
        authorization_endpoint: authorization.to_string(),
        token_endpoint: token.to_string(),
        scope: scope.unwrap_or_default(),
        resource: resource.or(explicit_resource),
        issuer: advertised_issuer,
    };
    a.db.put_upstream_oauth_client(&integration.id, &client)?;
    Ok(client)
}

pub fn open_secret_text(a: &App, ciphertext: &str) -> anyhow::Result<String> {
    Ok(String::from_utf8(a.secrets.open(ciphertext)?)?)
}

pub fn oauth_authorization_value(token_type: &str, access_token: &str) -> String {
    // OAuth token type identifiers are case-insensitive (RFC 6749 §7.1), but
    // some protected resources accept only the conventional HTTP spelling.
    let scheme = if token_type.eq_ignore_ascii_case("bearer") {
        "Bearer"
    } else {
        token_type
    };
    format!("{scheme} {access_token}")
}

pub async fn upstream_authorization(a: &App, integration: &str) -> anyhow::Result<Option<String>> {
    let Some(mut token) = a.db.upstream_oauth_token(integration)? else {
        return Ok(None);
    };
    let now = chrono::Utc::now().timestamp();
    if token.expires_at.is_none_or(|expires| expires > now + 30) {
        return Ok(Some(oauth_authorization_value(
            &token.token_type,
            &open_secret_text(a, &token.access_token_ciphertext)?,
        )));
    }

    let _mutation = a.mutations.lock().await;
    // Another request may have refreshed while we waited for the mutation gate.
    token =
        a.db.upstream_oauth_token(integration)?
            .ok_or_else(|| anyhow::anyhow!("upstream OAuth token disappeared"))?;
    let now = chrono::Utc::now().timestamp();
    if token.expires_at.is_none_or(|expires| expires > now + 30) {
        return Ok(Some(oauth_authorization_value(
            &token.token_type,
            &open_secret_text(a, &token.access_token_ciphertext)?,
        )));
    }
    anyhow::ensure!(
        token.refresh_expires_at.is_none_or(|expires| expires > now),
        "upstream refresh token expired; reconnect required"
    );
    let refresh_ciphertext = token
        .refresh_token_ciphertext
        .as_deref()
        .ok_or_else(|| anyhow::anyhow!("upstream access token expired; reconnect required"))?;
    let refresh = open_secret_text(a, refresh_ciphertext)?;
    let client =
        a.db.upstream_oauth_client(integration)?
            .ok_or_else(|| anyhow::anyhow!("upstream OAuth client missing"))?;
    let mut form = vec![
        ("grant_type", "refresh_token".to_owned()),
        ("refresh_token", refresh),
        ("client_id", client.client_id.clone()),
    ];
    if let Some(resource) = client.resource.clone() {
        form.push(("resource", resource));
    }
    if let Some(secret) = client.client_secret_ciphertext.as_deref() {
        form.push(("client_secret", open_secret_text(a, secret)?));
    }
    let http = reqwest::Client::builder()
        .timeout(Duration::from_secs(15))
        .build()?;
    let response = oauth_json(http.post(&client.token_endpoint).form(&form)).await?;
    let access = response
        .get("access_token")
        .and_then(Value::as_str)
        .ok_or_else(|| anyhow::anyhow!("refresh response has no access_token"))?;
    let rotated_refresh = response
        .get("refresh_token")
        .and_then(Value::as_str)
        .map(|value| a.secrets.seal(value.as_bytes()))
        .transpose()?
        .or_else(|| token.refresh_token_ciphertext.clone());
    let refreshed = UpstreamOAuthToken {
        access_token_ciphertext: a.secrets.seal(access.as_bytes())?,
        refresh_token_ciphertext: rotated_refresh,
        token_type: response
            .get("token_type")
            .and_then(Value::as_str)
            .unwrap_or(&token.token_type)
            .to_owned(),
        scope: response
            .get("scope")
            .and_then(Value::as_str)
            .unwrap_or(&token.scope)
            .to_owned(),
        expires_at: response
            .get("expires_in")
            .and_then(Value::as_i64)
            .map(|seconds| now + seconds),
        refresh_expires_at: response
            .get("refresh_expires_in")
            .and_then(Value::as_i64)
            .map(|seconds| now + seconds)
            .or(token.refresh_expires_at),
    };
    a.db.put_upstream_oauth_token(integration, &refreshed)?;
    persist(a).await?;
    Ok(Some(oauth_authorization_value(
        &refreshed.token_type,
        access,
    )))
}

pub async fn start_upstream_step_up(
    a: &App,
    user: &str,
    integration_id: &str,
    challenge: &UpstreamInsufficientScope,
) -> anyhow::Result<url::Url> {
    let _mutation = a.mutations.lock().await;
    a.lease.assert_live()?;
    anyhow::ensure!(
        a.db.integration(integration_id, user)?.is_some(),
        "integration not found"
    );
    let mut client =
        a.db.upstream_oauth_client(integration_id)?
            .ok_or_else(|| anyhow::anyhow!("upstream OAuth client missing"))?;
    let metadata = oauth_json(
        reqwest::Client::builder()
            .timeout(Duration::from_secs(15))
            .build()?
            .get(&challenge.resource_metadata),
    )
    .await?;
    let challenged_resource = metadata
        .get("resource")
        .and_then(Value::as_str)
        .ok_or_else(|| anyhow::anyhow!("upstream resource metadata has no resource"))?;
    validate_oauth_uri(
        &url::Url::parse(challenged_resource)?,
        "challenged OAuth resource",
    )?;
    anyhow::ensure!(
        client.resource.as_deref() == Some(challenged_resource),
        "upstream scope challenge is for an unexpected resource"
    );

    let mut scopes = client
        .scope
        .split_ascii_whitespace()
        .map(str::to_owned)
        .collect::<Vec<_>>();
    if let Some(token) = a.db.upstream_oauth_token(integration_id)? {
        for scope in token.scope.split_ascii_whitespace() {
            if !scopes.iter().any(|existing| existing == scope) {
                scopes.push(scope.to_owned());
            }
        }
    }
    for scope in &challenge.scopes {
        if !scopes.contains(scope) {
            scopes.push(scope.clone());
        }
    }
    client.scope = scopes.join(" ");
    a.db.put_upstream_oauth_client(integration_id, &client)?;

    let state = crate::crypto::random_token(32);
    let verifier = crate::crypto::random_token(48);
    use base64::Engine;
    use sha2::Digest;
    let code_challenge = base64::engine::general_purpose::URL_SAFE_NO_PAD
        .encode(sha2::Sha256::digest(verifier.as_bytes()));
    let redirect = format!(
        "{}/oauth/upstream/callback",
        a.config.base_url.as_str().trim_end_matches('/')
    );
    a.db.store_oauth_state(
        &token_hash(&state),
        user,
        integration_id,
        &a.secrets.seal(verifier.as_bytes())?,
        &redirect,
        chrono::Utc::now().timestamp() + 600,
        client.resource.as_deref(),
    )?;
    audit_details(
        a,
        Some(user),
        "integration.oauth_step_up",
        Some(integration_id),
        "required",
        &json!({"scopes":challenge.scopes}),
    )?;
    persist(a).await?;

    let mut url = url::Url::parse(&client.authorization_endpoint)?;
    url.query_pairs_mut()
        .append_pair("response_type", "code")
        .append_pair("client_id", &client.client_id)
        .append_pair("redirect_uri", &redirect)
        .append_pair("state", &state)
        .append_pair("code_challenge", &code_challenge)
        .append_pair("code_challenge_method", "S256")
        .append_pair("scope", &client.scope)
        .append_pair("resource", challenged_resource);
    Ok(url)
}

pub async fn upstream_oauth_start(
    State(a): State<App>,
    Path(id): Path<String>,
    h: HeaderMap,
) -> impl IntoResponse {
    let _mutation = a.mutations.lock().await;
    if let Err(e) = a.lease.assert_live() {
        return (StatusCode::SERVICE_UNAVAILABLE, e.to_string()).into_response();
    }
    let u = match scoped_user(&a, &h, "integrations:write") {
        Ok(v) => v,
        Err(failure) => return auth_failure(&a, failure, "integrations:write"),
    };
    let Some(i) = a.db.integration(&id, &u).ok().flatten() else {
        return StatusCode::NOT_FOUND.into_response();
    };
    if !i.config.get("oauth").is_some_and(|value| !value.is_null()) {
        return (
            StatusCode::BAD_REQUEST,
            "integration does not use upstream OAuth",
        )
            .into_response();
    }
    let (status, connected) = upstream_connection_state(&a, &i);
    if connected {
        return Json(json!({
            "id": id,
            "alreadyConnected": true,
            "upstreamConnected": true,
            "upstreamStatus": status,
            "reconnectRequired": true
        }))
        .into_response();
    }
    let client = match resolve_upstream_client(&a, &i).await {
        Ok(client) => client,
        Err(error) => return (StatusCode::BAD_GATEWAY, error.to_string()).into_response(),
    };
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
    let sealed = match a.secrets.seal(verifier.as_bytes()) {
        Ok(v) => v,
        Err(e) => return (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()).into_response(),
    };
    if let Err(e) = a.db.store_oauth_state(
        &token_hash(&state),
        &u,
        &id,
        &sealed,
        &redirect,
        chrono::Utc::now().timestamp() + 600,
        client.resource.as_deref(),
    ) {
        return (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()).into_response();
    }
    if let Err(error) = audit(
        &a,
        Some(&u),
        "integration.oauth_start",
        Some(&id),
        "success",
    ) {
        return (StatusCode::INTERNAL_SERVER_ERROR, error.to_string()).into_response();
    }
    if let Err(e) = persist(&a).await {
        return (StatusCode::SERVICE_UNAVAILABLE, e.to_string()).into_response();
    }
    let mut url = match url::Url::parse(&client.authorization_endpoint) {
        Ok(v) => v,
        Err(e) => return (StatusCode::BAD_REQUEST, e.to_string()).into_response(),
    };
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
    Json(json!({"id":id,"alreadyConnected":false,"upstreamConnected":false,"upstreamStatus":status,"authorization_url":url,"one_time":true,"prefetched":false})).into_response()
}
#[derive(Deserialize)]
pub struct UpstreamCallback {
    pub code: Option<String>,
    pub state: String,
    pub error: Option<String>,
    pub error_description: Option<String>,
    pub iss: Option<String>,
}
pub async fn upstream_callback(
    State(a): State<App>,
    axum::extract::Query(q): axum::extract::Query<UpstreamCallback>,
) -> impl IntoResponse {
    let _mutation = a.mutations.lock().await;
    if let Err(e) = a.lease.assert_live() {
        return (StatusCode::SERVICE_UNAVAILABLE, e.to_string()).into_response();
    }
    if let Some(e) = q.error {
        let description = q
            .error_description
            .as_deref()
            .unwrap_or("authorization was rejected");
        return (
            StatusCode::BAD_REQUEST,
            Html(standalone_page(
                "Integration authorization",
                "Connection was not completed",
                &format!(
                    "<p class=\"lead\">The upstream provider returned an authorization error.</p><div class=\"notice danger\"><strong>{}</strong><br>{}</div><div class=\"actions\"><a class=\"button secondary\" href=\"/\">Return to cog</a></div>",
                    html_escape(&e),
                    html_escape(description)
                ),
                "status",
            )),
        )
            .into_response();
    }
    let Some(code) = q.code else {
        return browser_error(
            StatusCode::BAD_REQUEST,
            "Missing authorization code",
            "The upstream provider returned without an authorization code.",
        );
    };
    let Some((user, id, sealed, redirect, expires, state_resource)) =
        a.db.redeem_oauth_state(&token_hash(&q.state))
            .ok()
            .flatten()
    else {
        return browser_error(
            StatusCode::BAD_REQUEST,
            "Authorization request expired",
            "This authorization link is invalid or has already been used. Start a fresh connection from cog.",
        );
    };
    if expires < chrono::Utc::now().timestamp() {
        return browser_error(
            StatusCode::BAD_REQUEST,
            "Authorization request expired",
            "This authorization request took too long. Start a fresh connection from cog.",
        );
    }
    let verifier = match a
        .secrets
        .open(&sealed)
        .and_then(|v| Ok(String::from_utf8(v)?))
    {
        Ok(v) => v,
        Err(_) => {
            return browser_error(
                StatusCode::BAD_REQUEST,
                "Authorization request is invalid",
                "Clanker Operations Gateway could not verify this authorization request. Start a fresh connection.",
            );
        }
    };
    let Some(_integration) = a.db.integration(&id, &user).ok().flatten() else {
        return browser_error(
            StatusCode::NOT_FOUND,
            "Integration not found",
            "The integration associated with this request no longer exists.",
        );
    };
    let Some(client) = a.db.upstream_oauth_client(&id).ok().flatten() else {
        return browser_error(
            StatusCode::BAD_REQUEST,
            "Connection must be restarted",
            "The saved upstream authorization client is missing.",
        );
    };
    if state_resource != client.resource {
        return browser_error(
            StatusCode::BAD_REQUEST,
            "Connection details changed",
            "OAuth resource changed; reconnect required",
        );
    }
    if let Some(callback_issuer) = q.iss.as_deref()
        && client
            .issuer
            .as_deref()
            .is_some_and(|issuer| issuer != callback_issuer)
    {
        return browser_error(
            StatusCode::BAD_REQUEST,
            "Provider verification failed",
            "The authorization response came from an unexpected issuer.",
        );
    }
    let mut form = vec![
        ("grant_type", "authorization_code".to_owned()),
        ("code", code),
        ("client_id", client.client_id.clone()),
        ("redirect_uri", redirect),
        ("code_verifier", verifier),
    ];
    if let Some(secret) = client.client_secret_ciphertext.as_deref() {
        let secret = match a
            .secrets
            .open(secret)
            .and_then(|value| Ok(String::from_utf8(value)?))
        {
            Ok(secret) => secret,
            Err(_) => {
                return browser_error(
                    StatusCode::INTERNAL_SERVER_ERROR,
                    "Connection could not be completed",
                    "Clanker Operations Gateway could not open the saved provider credentials.",
                );
            }
        };
        form.push(("client_secret", secret));
    }
    if let Some(resource) = client.resource.clone() {
        form.push(("resource", resource));
    }
    let http = match reqwest::Client::builder()
        .timeout(Duration::from_secs(15))
        .build()
    {
        Ok(client) => client,
        Err(_) => {
            return browser_error(
                StatusCode::INTERNAL_SERVER_ERROR,
                "Connection could not be completed",
                "Clanker Operations Gateway could not prepare the provider token request.",
            );
        }
    };
    let token = match oauth_json(http.post(&client.token_endpoint).form(&form)).await {
        Ok(token) => token,
        Err(_) => {
            return browser_error(
                StatusCode::BAD_GATEWAY,
                "Provider token exchange failed",
                "The upstream provider did not accept or complete the token exchange.",
            );
        }
    };
    let Some(access) = token.get("access_token").and_then(Value::as_str) else {
        return browser_error(
            StatusCode::BAD_GATEWAY,
            "Provider response was incomplete",
            "The upstream provider did not return an access token.",
        );
    };
    let now = chrono::Utc::now().timestamp();
    let stored = match (|| -> anyhow::Result<UpstreamOAuthToken> {
        let refresh = token.get("refresh_token").and_then(Value::as_str);
        Ok(UpstreamOAuthToken {
            access_token_ciphertext: a.secrets.seal(access.as_bytes())?,
            refresh_token_ciphertext: refresh
                .map(|token| a.secrets.seal(token.as_bytes()))
                .transpose()?,
            token_type: token
                .get("token_type")
                .and_then(Value::as_str)
                .unwrap_or("Bearer")
                .to_owned(),
            scope: token
                .get("scope")
                .and_then(Value::as_str)
                .unwrap_or(&client.scope)
                .to_owned(),
            expires_at: token
                .get("expires_in")
                .and_then(Value::as_i64)
                .map(|seconds| now + seconds),
            refresh_expires_at: token
                .get("refresh_expires_in")
                .and_then(Value::as_i64)
                .map(|seconds| now + seconds),
        })
    })() {
        Ok(token) => token,
        Err(_) => {
            return browser_error(
                StatusCode::INTERNAL_SERVER_ERROR,
                "Connection could not be saved",
                "Clanker Operations Gateway could not protect the provider credentials.",
            );
        }
    };
    if a.db.put_upstream_oauth_token(&id, &stored).is_err() {
        return browser_error(
            StatusCode::INTERNAL_SERVER_ERROR,
            "Connection could not be saved",
            "Clanker Operations Gateway could not store the provider credentials.",
        );
    }
    if audit(
        &a,
        Some(&user),
        "integration.oauth_connect",
        Some(&id),
        "success",
    )
    .is_err()
    {
        return browser_error(
            StatusCode::INTERNAL_SERVER_ERROR,
            "Connection could not be completed",
            "Clanker Operations Gateway could not record the authorization result.",
        );
    }
    disconnect_provider(&a, &id).await;
    if persist(&a).await.is_err() {
        return browser_error(
            StatusCode::SERVICE_UNAVAILABLE,
            "Connection is not durable yet",
            "Clanker Operations Gateway could not safely persist this authorization. Check service health before retrying.",
        );
    }
    Html(standalone_page(
        "Integration connected",
        "Connection complete",
        "<p class=\"lead\">Clanker Operations Gateway securely received and stored the integration authorization.</p><div class=\"notice success\">You can close this window or return to the dashboard.</div><div class=\"actions\"><a class=\"button\" href=\"/\">Return to cog</a></div>",
        "status",
    ))
    .into_response()
}
