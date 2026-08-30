use super::*;

pub(super) fn cookie(headers: &HeaderMap, name: &str) -> Option<String> {
    headers
        .get(http::header::COOKIE)?
        .to_str()
        .ok()?
        .split(';')
        .filter_map(|part| part.trim().split_once('='))
        .find_map(|(key, value)| (key == name).then(|| value.to_owned()))
}

pub(super) fn origin_allowed(a: &App, headers: &HeaderMap) -> bool {
    let Some(origin) = headers
        .get(http::header::ORIGIN)
        .and_then(|value| value.to_str().ok())
    else {
        return false;
    };
    let expected = a.config.base_url.origin().ascii_serialization();
    origin == expected
}

pub(super) fn browser_session(a: &App, headers: &HeaderMap, csrf: Option<&str>) -> Option<String> {
    let session = cookie(headers, "cog_session")?;
    let csrf_hash = csrf.map(token_hash);
    a.db.session_user(
        &token_hash(&session),
        csrf_hash.as_ref().map(<[u8; 32]>::as_slice),
        chrono::Utc::now().timestamp(),
    )
    .ok()
    .flatten()
}

pub fn rate_limit(
    a: &App,
    action: &str,
    subject: &str,
    maximum: usize,
) -> Option<axum::response::Response> {
    if a.auth_rate_limit.allow(
        format!("{action}:{}", subject.to_ascii_lowercase()),
        maximum,
        Duration::from_secs(60),
    ) {
        None
    } else {
        Some(
            (
                StatusCode::TOO_MANY_REQUESTS,
                [(http::header::RETRY_AFTER, "60")],
                "rate limit exceeded",
            )
                .into_response(),
        )
    }
}

pub(super) fn audit(
    a: &App,
    actor: Option<&str>,
    action: &str,
    target: Option<&str>,
    outcome: &str,
) -> anyhow::Result<()> {
    a.db.record_audit(actor, action, target, outcome, &json!({}))
}

pub(super) fn audit_details(
    a: &App,
    actor: Option<&str>,
    action: &str,
    target: Option<&str>,
    outcome: &str,
    details: &Value,
) -> anyhow::Result<()> {
    a.db.record_audit(actor, action, target, outcome, details)
}

pub(super) async fn login_page() -> Response {
    ui_shell()
}

#[derive(Deserialize)]
pub(super) struct LoginForm {
    email: String,
    password: String,
}

pub(super) async fn login(
    State(a): State<App>,
    headers: HeaderMap,
    Form(form): Form<LoginForm>,
) -> impl IntoResponse {
    if let Some(response) = rate_limit(&a, "login", &form.email, 10) {
        return response;
    }
    if !origin_allowed(&a, &headers) {
        return (StatusCode::FORBIDDEN, "invalid origin").into_response();
    }
    let Some((user, hash)) = a.db.user_by_email(&form.email).ok().flatten() else {
        if audit(&a, Some(&form.email), "session.login", None, "denied").is_ok() {
            let _ = persist(&a).await;
        }
        return (StatusCode::UNAUTHORIZED, "invalid credentials").into_response();
    };
    let valid = PasswordHash::new(&hash).ok().is_some_and(|hash| {
        Argon2::default()
            .verify_password(form.password.as_bytes(), &hash)
            .is_ok()
    });
    if !valid {
        if audit(&a, Some(&form.email), "session.login", None, "denied").is_ok() {
            let _ = persist(&a).await;
        }
        return (StatusCode::UNAUTHORIZED, "invalid credentials").into_response();
    }
    let session = crate::crypto::random_token(32);
    let csrf = crate::crypto::random_token(32);
    if let Err(error) = a.db.create_session(
        &token_hash(&session),
        &user,
        &token_hash(&csrf),
        chrono::Utc::now().timestamp() + 12 * 3600,
    ) {
        return (StatusCode::INTERNAL_SERVER_ERROR, error.to_string()).into_response();
    }
    if let Err(error) = audit(&a, Some(&user), "session.login", None, "success") {
        return (StatusCode::INTERNAL_SERVER_ERROR, error.to_string()).into_response();
    }
    if let Err(error) = persist(&a).await {
        return (StatusCode::SERVICE_UNAVAILABLE, error.to_string()).into_response();
    }
    let secure = if a.config.base_url.scheme() == "https" {
        "; Secure"
    } else {
        ""
    };
    let session_cookie =
        format!("cog_session={session}; Path=/; HttpOnly; SameSite=Lax; Max-Age=43200{secure}");
    let csrf_cookie = format!("cog_csrf={csrf}; Path=/; SameSite=Lax; Max-Age=43200{secure}");
    let mut response = (StatusCode::SEE_OTHER, [(http::header::LOCATION, "/")]).into_response();
    response.headers_mut().append(
        http::header::SET_COOKIE,
        http::HeaderValue::from_str(&session_cookie).expect("generated session cookie is valid"),
    );
    response.headers_mut().append(
        http::header::SET_COOKIE,
        http::HeaderValue::from_str(&csrf_cookie).expect("generated CSRF cookie is valid"),
    );
    response
}

#[derive(Deserialize)]
pub struct CsrfForm {
    pub csrf_token: String,
}

pub(super) async fn logout(
    State(a): State<App>,
    headers: HeaderMap,
    Form(form): Form<CsrfForm>,
) -> impl IntoResponse {
    if !origin_allowed(&a, &headers) {
        return (StatusCode::FORBIDDEN, "invalid session or CSRF token").into_response();
    }
    let Some(user) = browser_session(&a, &headers, Some(&form.csrf_token)) else {
        return (StatusCode::FORBIDDEN, "invalid session or CSRF token").into_response();
    };
    let session = cookie(&headers, "cog_session").expect("validated session cookie");
    if let Err(error) = a.db.delete_session(&token_hash(&session)) {
        return (StatusCode::INTERNAL_SERVER_ERROR, error.to_string()).into_response();
    }
    if let Err(error) = audit(&a, Some(&user), "session.logout", None, "success") {
        return (StatusCode::INTERNAL_SERVER_ERROR, error.to_string()).into_response();
    }
    if let Err(error) = persist(&a).await {
        return (StatusCode::SERVICE_UNAVAILABLE, error.to_string()).into_response();
    }
    let mut response = (StatusCode::SEE_OTHER, [(http::header::LOCATION, "/")]).into_response();
    for cookie in [
        "cog_session=; Path=/; HttpOnly; SameSite=Lax; Max-Age=0",
        "cog_csrf=; Path=/; SameSite=Lax; Max-Age=0",
    ] {
        response.headers_mut().append(
            http::header::SET_COOKIE,
            http::HeaderValue::from_static(cookie),
        );
    }
    response
}

pub(super) fn html_escape(value: &str) -> String {
    value
        .replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('"', "&quot;")
        .replace('\'', "&#39;")
}

pub(super) async fn admin_ui(State(a): State<App>, headers: HeaderMap) -> Response {
    if browser_session(&a, &headers, None).is_none() {
        return Redirect::to("/login").into_response();
    }
    ui_shell()
}

pub(super) async fn ui_bootstrap(State(a): State<App>, headers: HeaderMap) -> impl IntoResponse {
    let Some(user) = browser_session(&a, &headers, None) else {
        return Json(json!({"mode": "login"})).into_response();
    };
    let Some(csrf) = cookie(&headers, "cog_csrf") else {
        return (StatusCode::FORBIDDEN, "CSRF cookie missing").into_response();
    };
    let integrations = match a.db.list_integrations(&user) {
        Ok(items) => items
            .into_iter()
            .map(|integration| {
                let token = a.db.upstream_oauth_token(&integration.id).ok().flatten();
                let oauth = if integration.config.get("oauth").is_none() {
                    "not configured"
                } else if token.is_some() {
                    "connected"
                } else {
                    "connection required"
                };
                let oauth_scopes = token
                    .map(|token| {
                        token
                            .scope
                            .split_ascii_whitespace()
                            .map(str::to_owned)
                            .collect::<Vec<_>>()
                    })
                    .unwrap_or_default();
                json!({
                    "id": integration.id,
                    "identity_id":integration.identity_id,
                    "name": integration.name,
                    "display_name":integration.name,
                    "provider_name":integration.provider_name,
                    "provider_account":integration.provider_account,
                    "transport": integration.transport,
                    "enabled": integration.enabled,
                    "oauth": oauth,
                    "oauth_scopes": oauth_scopes,
                })
            })
            .collect::<Vec<_>>(),
        Err(error) => {
            return (StatusCode::INTERNAL_SERVER_ERROR, error.to_string()).into_response();
        }
    };
    let clients = a.db.agent_clients(&user).unwrap_or_default();
    let tokens = a.db.agent_tokens(&user).unwrap_or_default();
    let identities=a.db.list_identities(&user).unwrap_or_default().into_iter().map(|identity|{
        let connections=integrations.iter().filter(|connection|connection.get("identity_id").and_then(Value::as_str)==Some(identity.id.as_str())).cloned().collect::<Vec<_>>();
        let agents=a.db.agents_for_identity(&user,&identity.id).unwrap_or_default();
        let grants=a.db.identity_grants(&user,&identity.id).unwrap_or_default();
        json!({"id":identity.id,"name":identity.name,"created_at":identity.created_at,"updated_at":identity.updated_at,"connections":connections,"agents":agents,"grants":grants})
    }).collect::<Vec<_>>();
    let ssh_keys = a.db.ssh_keys().unwrap_or_default().into_iter().map(|key| json!({
        "id":key.id,
        "purpose":key.purpose,
        "algorithm":key.algorithm,
        "fingerprint":ssh_key::PublicKey::from_openssh(&key.public_key).ok().map(|key| crate::git::ssh::fingerprint(&key)),
        "created_at":key.created_at,
        "active":key.active,
        "retirement_time":key.retirement_time
    })).collect::<Vec<_>>();
    Json(json!({
        "mode": "admin",
        "user": user,
        "csrf_token": csrf,
        "integrations": integrations,
        "clients": clients,
        "tokens": tokens,
        "identities": identities,
        "ssh": {
            "configured": a.config.ssh_listen.is_some(),
            "ready": a.ssh_ready.load(Ordering::Acquire),
            "public_host": a.config.ssh_public_host,
            "public_port": a.config.ssh_public_port.or_else(|| a.config.ssh_listen.map(|address| address.port())),
            "key_lease_ttl_seconds": a.config.ssh_key_lease_ttl_secs,
            "keys": ssh_keys
        },
        "git_transport_usage": {
            "ssh_operations": a.metrics.ssh_read_operations.load(Ordering::Relaxed) + a.metrics.ssh_write_operations.load(Ordering::Relaxed)
        }
    }))
    .into_response()
}

#[derive(Deserialize)]
pub struct UiIntegrationForm {
    pub name: String,
    pub url: url::Url,
    pub csrf_token: String,
}
#[derive(Deserialize)]
pub struct UiNameForm {
    pub name: String,
    pub csrf_token: String,
}

pub async fn ui_prepare_ssh_key(
    State(a): State<App>,
    Path(purpose): Path<String>,
    headers: HeaderMap,
    Form(form): Form<CsrfForm>,
) -> Response {
    let _mutation = a.mutations.lock().await;
    let user = match ui_user(&a, &headers, &form.csrf_token) {
        Ok(user) => user,
        Err(error) => return (StatusCode::FORBIDDEN, error).into_response(),
    };
    let result = (|| -> anyhow::Result<crate::db::SshKeyRecord> {
        a.lease.assert_live()?;
        anyhow::ensure!(purpose == "host", "invalid SSH key purpose");
        let key = crate::git::ssh::generate_key()?;
        let public = key.public_key().to_openssh()?;
        let encrypted = a.secrets.seal(&crate::git::ssh::encode_private(&key)?)?;
        a.db.prepare_ssh_key(&purpose, &public, &encrypted)
    })();
    match result {
        Ok(key) => {
            let fingerprint = ssh_key::PublicKey::from_openssh(&key.public_key)
                .map(|key| crate::git::ssh::fingerprint(&key))
                .unwrap_or_else(|_| "invalid".into());
            if let Err(error) = a.db.record_audit(
                Some(&user),
                "git.ssh_key.prepare",
                Some(&key.id),
                "success",
                &json!({"purpose":purpose,"fingerprint":fingerprint}),
            ) {
                return (
                    StatusCode::INTERNAL_SERVER_ERROR,
                    safe_error(error.as_ref()),
                )
                    .into_response();
            }
            if let Err(error) = persist(&a).await {
                return (StatusCode::SERVICE_UNAVAILABLE, safe_error(error.as_ref()))
                    .into_response();
            }
            Redirect::to("/ui").into_response()
        }
        Err(error) => (StatusCode::BAD_REQUEST, safe_error(error.as_ref())).into_response(),
    }
}

pub async fn ui_activate_ssh_key(
    State(a): State<App>,
    Path((purpose, id)): Path<(String, String)>,
    headers: HeaderMap,
    Form(form): Form<CsrfForm>,
) -> Response {
    let _mutation = a.mutations.lock().await;
    let user = match ui_user(&a, &headers, &form.csrf_token) {
        Ok(user) => user,
        Err(error) => return (StatusCode::FORBIDDEN, error).into_response(),
    };
    if purpose == "host" && a.ssh_ready.load(Ordering::Acquire) {
        return (
            StatusCode::CONFLICT,
            "disable SSH and restart COG before activating a prepared host key",
        )
            .into_response();
    }
    let overlap = 86_400;
    let result =
        a.db.activate_ssh_key(&id, &purpose, chrono::Utc::now().timestamp() + overlap);
    if let Err(error) = result {
        return (StatusCode::BAD_REQUEST, safe_error(error.as_ref())).into_response();
    }
    if let Err(error) = a.db.record_audit(
        Some(&user),
        "git.ssh_key.activate",
        Some(&id),
        "success",
        &json!({"purpose":purpose,"overlap_until":chrono::Utc::now().timestamp()+overlap}),
    ) {
        return (
            StatusCode::INTERNAL_SERVER_ERROR,
            safe_error(error.as_ref()),
        )
            .into_response();
    }
    if let Err(error) = persist(&a).await {
        return (StatusCode::SERVICE_UNAVAILABLE, safe_error(error.as_ref())).into_response();
    }
    Redirect::to("/ui").into_response()
}

pub async fn ui_retire_ssh_key(
    State(a): State<App>,
    Path((purpose, id)): Path<(String, String)>,
    headers: HeaderMap,
    Form(form): Form<CsrfForm>,
) -> Response {
    let _mutation = a.mutations.lock().await;
    let user = match ui_user(&a, &headers, &form.csrf_token) {
        Ok(user) => user,
        Err(error) => return (StatusCode::FORBIDDEN, error).into_response(),
    };
    match a.db.retire_ssh_key(&id, chrono::Utc::now().timestamp()) {
        Ok(()) => {
            let _ = a.db.record_audit(
                Some(&user),
                "git.ssh_key.retire",
                Some(&id),
                "success",
                &json!({"purpose":purpose}),
            );
            match persist(&a).await {
                Ok(()) => Redirect::to("/ui").into_response(),
                Err(error) => {
                    (StatusCode::SERVICE_UNAVAILABLE, safe_error(error.as_ref())).into_response()
                }
            }
        }
        Err(error) => (StatusCode::BAD_REQUEST, safe_error(error.as_ref())).into_response(),
    }
}
pub async fn ui_create_identity(
    State(a): State<App>,
    headers: HeaderMap,
    Form(form): Form<UiNameForm>,
) -> impl IntoResponse {
    let user = match ui_user(&a, &headers, &form.csrf_token) {
        Ok(user) => user,
        Err(error) => return (StatusCode::FORBIDDEN, error).into_response(),
    };
    match a.db.create_identity(&user, &form.name) {
        Ok(id) => {
            let _ = a.db.record_audit(
                Some(&user),
                "identity.create",
                Some(&id),
                "success",
                &json!({"identity_id":id}),
            );
            if let Err(error) = persist(&a).await {
                return (StatusCode::SERVICE_UNAVAILABLE, error.to_string()).into_response();
            }
            StatusCode::NO_CONTENT.into_response()
        }
        Err(error) => (StatusCode::BAD_REQUEST, error.to_string()).into_response(),
    }
}
pub async fn ui_rename_identity(
    State(a): State<App>,
    Path(id): Path<String>,
    headers: HeaderMap,
    Form(form): Form<UiNameForm>,
) -> impl IntoResponse {
    let user = match ui_user(&a, &headers, &form.csrf_token) {
        Ok(user) => user,
        Err(error) => return (StatusCode::FORBIDDEN, error).into_response(),
    };
    match a.db.rename_identity(&user, &id, &form.name) {
        Ok(true) => {
            let _ = a.db.record_audit(
                Some(&user),
                "identity.rename",
                Some(&id),
                "success",
                &json!({"identity_id":id}),
            );
            let _ = persist(&a).await;
            StatusCode::NO_CONTENT.into_response()
        }
        Ok(false) => StatusCode::NOT_FOUND.into_response(),
        Err(error) => (StatusCode::BAD_REQUEST, error.to_string()).into_response(),
    }
}
pub async fn ui_delete_identity(
    State(a): State<App>,
    Path(id): Path<String>,
    headers: HeaderMap,
    Form(form): Form<CsrfForm>,
) -> impl IntoResponse {
    let user = match ui_user(&a, &headers, &form.csrf_token) {
        Ok(user) => user,
        Err(error) => return (StatusCode::FORBIDDEN, error).into_response(),
    };
    match a.db.delete_identity(&user, &id) {
        Ok(true) => {
            let _ = a.db.record_audit(
                Some(&user),
                "identity.delete",
                Some(&id),
                "success",
                &json!({"identity_id":id}),
            );
            let _ = persist(&a).await;
            StatusCode::NO_CONTENT.into_response()
        }
        Ok(false) => StatusCode::NOT_FOUND.into_response(),
        Err(error) => (StatusCode::BAD_REQUEST, error.to_string()).into_response(),
    }
}
pub async fn ui_rename_agent(
    State(a): State<App>,
    Path(id): Path<String>,
    headers: HeaderMap,
    Form(form): Form<UiNameForm>,
) -> impl IntoResponse {
    let user = match ui_user(&a, &headers, &form.csrf_token) {
        Ok(user) => user,
        Err(error) => return (StatusCode::FORBIDDEN, error).into_response(),
    };
    match a.db.rename_agent(&user, &id, &form.name) {
        Ok(true) => {
            let _ = a.db.record_audit(
                Some(&user),
                "agent.rename",
                Some(&id),
                "success",
                &json!({"agent_id":id}),
            );
            let _ = persist(&a).await;
            StatusCode::NO_CONTENT.into_response()
        }
        Ok(false) => StatusCode::NOT_FOUND.into_response(),
        Err(error) => (StatusCode::BAD_REQUEST, error.to_string()).into_response(),
    }
}

pub(super) fn ui_user(a: &App, headers: &HeaderMap, csrf: &str) -> Result<String, &'static str> {
    if !origin_allowed(a, headers) {
        return Err("invalid origin");
    }
    browser_session(a, headers, Some(csrf)).ok_or("invalid session or CSRF token")
}

pub async fn ui_add_integration(
    State(a): State<App>,
    headers: HeaderMap,
    Form(form): Form<UiIntegrationForm>,
) -> impl IntoResponse {
    let user = match ui_user(&a, &headers, &form.csrf_token) {
        Ok(user) => user,
        Err(error) => return (StatusCode::FORBIDDEN, error).into_response(),
    };
    if !matches!(form.url.scheme(), "http" | "https") {
        return (StatusCode::BAD_REQUEST, "HTTP URL required").into_response();
    }
    let id =
        match a
            .db
            .create_integration(&user, &form.name, "http", &json!({"url":form.url}), None)
        {
            Ok(id) => id,
            Err(error) => return (StatusCode::BAD_REQUEST, error.to_string()).into_response(),
        };
    if let Err(error) = audit(&a, Some(&user), "integration.create", Some(&id), "success") {
        return (StatusCode::INTERNAL_SERVER_ERROR, error.to_string()).into_response();
    }
    match persist(&a).await {
        Ok(()) => Redirect::to("/ui").into_response(),
        Err(error) => (StatusCode::SERVICE_UNAVAILABLE, error.to_string()).into_response(),
    }
}

pub async fn ui_delete_integration(
    State(a): State<App>,
    Path(id): Path<String>,
    headers: HeaderMap,
    Form(form): Form<CsrfForm>,
) -> impl IntoResponse {
    let _mutation = a.mutations.lock().await;
    let user = match ui_user(&a, &headers, &form.csrf_token) {
        Ok(user) => user,
        Err(error) => return (StatusCode::FORBIDDEN, error).into_response(),
    };
    match a.db.delete_integration(&id, &user) {
        Ok(true) => {
            disconnect_provider(&a, &id).await;
            if let Err(error) = audit(&a, Some(&user), "integration.delete", Some(&id), "success") {
                return (StatusCode::INTERNAL_SERVER_ERROR, error.to_string()).into_response();
            }
            match persist(&a).await {
                Ok(()) => Redirect::to("/ui").into_response(),
                Err(error) => (StatusCode::SERVICE_UNAVAILABLE, error.to_string()).into_response(),
            }
        }
        Ok(false) => StatusCode::NOT_FOUND.into_response(),
        Err(error) => (StatusCode::INTERNAL_SERVER_ERROR, error.to_string()).into_response(),
    }
}

pub async fn ui_disconnect_integration(
    State(a): State<App>,
    Path(id): Path<String>,
    headers: HeaderMap,
    Form(form): Form<CsrfForm>,
) -> impl IntoResponse {
    let user = match ui_user(&a, &headers, &form.csrf_token) {
        Ok(user) => user,
        Err(error) => return (StatusCode::FORBIDDEN, error).into_response(),
    };
    match admin_disconnect(&a, &user, &id).await {
        Ok(_) => Redirect::to("/ui").into_response(),
        Err(error) if error.to_string().contains("not found") => {
            StatusCode::NOT_FOUND.into_response()
        }
        Err(error) => (StatusCode::BAD_REQUEST, error.to_string()).into_response(),
    }
}

pub async fn ui_revoke_token(
    State(a): State<App>,
    Path(id): Path<String>,
    headers: HeaderMap,
    Form(form): Form<CsrfForm>,
) -> impl IntoResponse {
    let _mutation = a.mutations.lock().await;
    let user = match ui_user(&a, &headers, &form.csrf_token) {
        Ok(user) => user,
        Err(error) => return (StatusCode::FORBIDDEN, error).into_response(),
    };
    match a.db.revoke_agent_token(&user, &id) {
        Ok(true) => {
            if let Err(error) = audit(&a, Some(&user), "agent_token.revoke", Some(&id), "success") {
                return (StatusCode::INTERNAL_SERVER_ERROR, error.to_string()).into_response();
            }
            match persist(&a).await {
                Ok(()) => Redirect::to("/ui").into_response(),
                Err(error) => (StatusCode::SERVICE_UNAVAILABLE, error.to_string()).into_response(),
            }
        }
        Ok(false) => StatusCode::NOT_FOUND.into_response(),
        Err(error) => (StatusCode::INTERNAL_SERVER_ERROR, error.to_string()).into_response(),
    }
}

pub async fn ui_revoke_client(
    State(a): State<App>,
    Path(id): Path<String>,
    headers: HeaderMap,
    Form(form): Form<CsrfForm>,
) -> impl IntoResponse {
    let _mutation = a.mutations.lock().await;
    let user = match ui_user(&a, &headers, &form.csrf_token) {
        Ok(user) => user,
        Err(error) => return (StatusCode::FORBIDDEN, error).into_response(),
    };
    match a.db.revoke_agent_client(&user, &id) {
        Ok(true) => {
            if let Err(error) = audit(&a, Some(&user), "agent_client.revoke", Some(&id), "success")
            {
                return (StatusCode::INTERNAL_SERVER_ERROR, error.to_string()).into_response();
            }
            match persist(&a).await {
                Ok(()) => Redirect::to("/ui").into_response(),
                Err(error) => (StatusCode::SERVICE_UNAVAILABLE, error.to_string()).into_response(),
            }
        }
        Ok(false) => StatusCode::NOT_FOUND.into_response(),
        Err(error) => (StatusCode::INTERNAL_SERVER_ERROR, error.to_string()).into_response(),
    }
}

pub async fn ui_revoke_grant(
    State(a): State<App>,
    Path((client, integration)): Path<(String, String)>,
    headers: HeaderMap,
    Form(form): Form<CsrfForm>,
) -> impl IntoResponse {
    let user = match ui_user(&a, &headers, &form.csrf_token) {
        Ok(user) => user,
        Err(error) => return (StatusCode::FORBIDDEN, error).into_response(),
    };
    match admin_revoke_grant(&a, &user, &client, &integration).await {
        Ok(_) => Redirect::to("/ui").into_response(),
        Err(error) => (StatusCode::BAD_REQUEST, error.to_string()).into_response(),
    }
}

pub async fn ui_grant_integration(
    State(a): State<App>,
    Path((client, integration)): Path<(String, String)>,
    headers: HeaderMap,
    Form(form): Form<CsrfForm>,
) -> impl IntoResponse {
    let _mutation = a.mutations.lock().await;
    let user = match ui_user(&a, &headers, &form.csrf_token) {
        Ok(user) => user,
        Err(error) => return (StatusCode::FORBIDDEN, error).into_response(),
    };
    match a.db.grant_client_integration(&user, &client, &integration) {
        Ok(_) => {
            if let Err(error) = audit(
                &a,
                Some(&user),
                "agent_client.integration_grant",
                Some(&integration),
                "success",
            ) {
                return (
                    StatusCode::INTERNAL_SERVER_ERROR,
                    safe_error(error.as_ref()),
                )
                    .into_response();
            }
            match persist(&a).await {
                Ok(()) => Redirect::to("/ui").into_response(),
                Err(error) => {
                    (StatusCode::SERVICE_UNAVAILABLE, safe_error(error.as_ref())).into_response()
                }
            }
        }
        Err(error) => (StatusCode::BAD_REQUEST, safe_error(error.as_ref())).into_response(),
    }
}
