use super::*;

pub(super) async fn auth_metadata(State(a): State<App>) -> Json<Value> {
    let b = a.config.base_url.as_str().trim_end_matches('/');
    let scopes = vec![
        "mcp".to_owned(),
        "integrations:read".to_owned(),
        "integrations:write".to_owned(),
        "agents:read".to_owned(),
        "agents:write".to_owned(),
        "audit:read".to_owned(),
        "git:read".to_owned(),
        "git:write".to_owned(),
    ];
    Json(
        json!({"issuer":b,"authorization_endpoint":format!("{b}/oauth/authorize"),"token_endpoint":format!("{b}/oauth/token"),"revocation_endpoint":format!("{b}/oauth/revoke"),"registration_endpoint":format!("{b}/oauth/register"),"response_types_supported":["code"],"grant_types_supported":["authorization_code","refresh_token"],"code_challenge_methods_supported":["S256"],"token_endpoint_auth_methods_supported":["none"],"scopes_supported":scopes}),
    )
}
pub(super) async fn resource_metadata(State(a): State<App>) -> Json<Value> {
    let b = a.config.base_url.as_str().trim_end_matches('/');
    Json(
        json!({"resource":format!("{b}/mcp"),"authorization_servers":[b],"scopes_supported":["mcp","git:read","git:write"]}),
    )
}

pub(super) async fn oauth_client_metadata(State(a): State<App>) -> Json<Value> {
    let b = a.config.base_url.as_str().trim_end_matches('/');
    Json(json!({
        "client_id": format!("{b}/.well-known/oauth-client"),
        "client_name": "cog",
        "client_uri": b,
        "redirect_uris": [format!("{b}/oauth/upstream/callback")],
        "grant_types": ["authorization_code", "refresh_token"],
        "response_types": ["code"],
        "token_endpoint_auth_method": "none"
    }))
}
pub(super) async fn register(
    State(a): State<App>,
    Json(r): Json<oauth::RegistrationRequest>,
) -> impl IntoResponse {
    if let Some(response) = rate_limit(&a, "registration", "global", 20) {
        return response;
    }
    let _mutation = a.mutations.lock().await;
    if let Err(e) = a.lease.assert_live() {
        return (
            StatusCode::SERVICE_UNAVAILABLE,
            Json(json!({"error":"temporarily_unavailable","error_description":e.to_string()})),
        )
            .into_response();
    }
    match oauth::register(&a.db, r) {
        Ok(result) => {
            if result.created
                && let Err(error) = audit(
                    &a,
                    None,
                    "oauth.register",
                    Some(&result.response.client_id),
                    "success",
                )
            {
                return (
                    StatusCode::INTERNAL_SERVER_ERROR,
                    Json(json!({"error":"server_error","error_description":error.to_string()})),
                )
                    .into_response();
            }
            match if result.changed { persist(&a).await } else { Ok(()) } {
            Ok(()) => (StatusCode::CREATED, Json(json!(result.response))).into_response(),
            Err(e) => (
                StatusCode::SERVICE_UNAVAILABLE,
                Json(json!({"error":"temporarily_unavailable","error_description":e.to_string()})),
            )
                .into_response(),
            }
        }
        Err(e) => (
            StatusCode::BAD_REQUEST,
            Json(json!({"error":"invalid_client_metadata","error_description":e.to_string()})),
        )
            .into_response(),
    }
}
#[derive(Deserialize)]
pub struct Authorize {
    #[serde(default = "response_code")]
    pub response_type: String,
    pub client_id: String,
    pub redirect_uri: String,
    pub state: String,
    pub code_challenge: String,
    #[serde(default = "challenge_s256")]
    pub code_challenge_method: String,
    #[serde(default = "scope_mcp")]
    pub scope: String,
    pub resource: String,
}

#[derive(Serialize, Deserialize)]
pub struct ConsentRequest {
    pub response_type: String,
    pub client_id: String,
    pub redirect_uri: String,
    pub state: String,
    pub code_challenge: String,
    pub code_challenge_method: String,
    pub requested_scope: String,
    pub resource: String,
    pub user: String,
    pub allowed_identity_ids: Vec<String>,
    pub fixed_identity_id: Option<String>,
    pub expires_at: i64,
    #[serde(default)]
    pub git_pending_ids: Vec<String>,
}

#[derive(Deserialize)]
pub struct ConsentForm {
    pub consent: String,
    pub csrf_token: String,
    pub decision: String,
    #[serde(flatten)]
    pub fields: HashMap<String, String>,
}
pub fn response_code() -> String {
    "code".into()
}
pub fn challenge_s256() -> String {
    "S256".into()
}
pub fn scope_mcp() -> String {
    "mcp".into()
}

pub(super) fn standalone_page(eyebrow: &str, title: &str, body: &str, _tone: &str) -> String {
    format!(
        r##"<!doctype html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><meta name="color-scheme" content="light dark"><meta name="theme-color" content="#fafafa"><title>{title} · Clanker Operations Gateway</title><style>
:root{{color-scheme:light;font-family:Inter,ui-sans-serif,system-ui,-apple-system,BlinkMacSystemFont,"Segoe UI",sans-serif;color:#18181b;background:#fafafa;font-synthesis:none}}*{{box-sizing:border-box}}body{{margin:0;min-width:320px;min-height:100vh;background:radial-gradient(circle at 20% 0%,#dbeafe 0,transparent 32rem),#fafafa}}main{{width:min(100% - 2rem,720px);min-height:100vh;margin:auto;padding:2rem 0;display:grid;grid-template-rows:auto 1fr auto}}header{{display:flex;align-items:center;gap:.75rem}}.mark{{width:2.5rem;height:2.5rem;display:grid;place-items:center;border-radius:.75rem;background:#3b82f6;color:white;box-shadow:0 10px 25px rgba(59,130,246,.25)}}.brand{{font-size:1.05rem;font-weight:750;letter-spacing:-.02em}}.tagline,.muted{{color:#71717a}}.tagline{{font-size:.75rem}}.stage{{display:grid;place-items:center;padding:2.5rem 0}}.card{{width:100%;padding:clamp(1.35rem,5vw,2.25rem);border:1px solid #e4e4e7;border-radius:1.25rem;background:rgba(255,255,255,.88);box-shadow:0 22px 55px rgba(39,39,42,.12);backdrop-filter:blur(14px)}}.eyebrow{{margin:0;color:#2563eb;font-size:.72rem;font-weight:750;text-transform:uppercase;letter-spacing:.18em}}h1{{margin:.65rem 0 0;font-size:clamp(1.75rem,5vw,2.35rem);line-height:1.1;letter-spacing:-.035em}}p{{line-height:1.65}}.lead{{margin:.85rem 0 0;color:#52525b}}.notice{{margin:1.4rem 0 0;padding:1rem;border:1px solid #e4e4e7;border-radius:.8rem;background:#fafafa;color:#52525b;font-size:.9rem}}.notice.success{{border-color:#bbf7d0;background:#f0fdf4;color:#166534}}.notice.warning{{border-color:#fde68a;background:#fffbeb;color:#92400e}}.notice.danger{{border-color:#fecaca;background:#fef2f2;color:#991b1b}}.button{{appearance:none;border:0;border-radius:.65rem;padding:.72rem 1rem;background:#3b82f6;color:white;font:inherit;font-size:.9rem;font-weight:700;cursor:pointer;text-decoration:none;display:inline-flex;align-items:center;justify-content:center;transition:background .15s,transform .15s}}.button:hover{{background:#2563eb}}.button:active{{transform:translateY(1px)}}.button.secondary{{border:1px solid #e4e4e7;background:white;color:#3f3f46}}.button.secondary:hover{{background:#f4f4f5}}.actions{{display:flex;gap:.75rem;margin-top:1.5rem}}footer{{padding:.5rem 0;color:#a1a1aa;text-align:center;font-size:.72rem}}code{{font-family:ui-monospace,SFMono-Regular,Menlo,monospace}}
@media(max-width:520px){{.actions{{flex-direction:column}}.button{{width:100%}}}}
@media(prefers-color-scheme:dark){{:root{{color-scheme:dark;color:#e4e4e7;background:#09090b}}body{{background:radial-gradient(circle at 20% 0%,#18233b 0,transparent 32rem),#09090b}}.card{{border-color:rgba(255,255,255,.1);background:rgba(24,24,27,.82);box-shadow:0 24px 70px rgba(0,0,0,.3)}}.tagline,.muted{{color:#a1a1aa}}.lead{{color:#a1a1aa}}.notice{{border-color:rgba(255,255,255,.1);background:rgba(0,0,0,.22);color:#d4d4d8}}.notice.success{{border-color:rgba(34,197,94,.25);background:rgba(34,197,94,.1);color:#bbf7d0}}.notice.warning{{border-color:rgba(245,158,11,.25);background:rgba(245,158,11,.1);color:#fde68a}}.notice.danger{{border-color:rgba(239,68,68,.25);background:rgba(239,68,68,.1);color:#fecaca}}.button.secondary{{border-color:rgba(255,255,255,.12);background:rgba(255,255,255,.05);color:#e4e4e7}}.button.secondary:hover{{background:rgba(255,255,255,.1)}}}}
</style></head><body><main><header><div class="mark" aria-hidden="true"><svg width="21" height="21" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round"><path d="M4 14.9V9.1a2 2 0 0 1 1-1.73l6-3.46a2 2 0 0 1 2 0l6 3.46a2 2 0 0 1 1 1.73v5.8a2 2 0 0 1-1 1.73l-6 3.46a2 2 0 0 1-2 0l-6-3.46a2 2 0 0 1-1-1.73Z"/><path d="m8.5 10 3.5 2 3.5-2M12 12v4"/></svg></div><div><div class="brand">COG</div><div class="tagline">Clanker Operations Gateway</div></div></header><section class="stage"><article class="card"><p class="eyebrow">{eyebrow}</p><h1>{title}</h1>{body}</article></section><footer>Secure authorization by Clanker Operations Gateway</footer></main></body></html>"##,
        eyebrow = html_escape(eyebrow),
        title = html_escape(title),
        body = body,
    )
}

pub(super) fn browser_error(status: StatusCode, title: &str, message: &str) -> Response {
    (
        status,
        Html(standalone_page(
            "Authorization error",
            title,
            &format!(
                "<p class=\"lead\">{}</p><div class=\"actions\"><a class=\"button secondary\" href=\"/\">Return to cog</a></div>",
                html_escape(message)
            ),
            "status",
        )),
    )
        .into_response()
}

pub fn permission_copy(scope: &str, integration_name: Option<&str>) -> (String, String) {
    if let Some(name) = integration_name {
        return (
            format!("Use {name}"),
            "Discover and call tools from this integration.".into(),
        );
    }
    match scope {
        "mcp" => (
            "Connect to cog".into(),
            "Use cog's MCP execution surface.".into(),
        ),
        "integrations:read" => (
            "View integrations".into(),
            "See configured MCP integrations and their status.".into(),
        ),
        "integrations:write" => (
            "Manage integrations".into(),
            "Create, change, reconnect, enable, or delete integrations.".into(),
        ),
        "agents:read" => (
            "View agent access".into(),
            "See authorized clients and issued credentials.".into(),
        ),
        "agents:write" => (
            "Manage agent access".into(),
            "Revoke clients, credentials, and integration grants.".into(),
        ),
        "audit:read" => (
            "Read audit history".into(),
            "Review security and administration activity.".into(),
        ),
        "git:read" => (
            "Read Git repositories".into(),
            "Clone, fetch, and pull only from individually approved repositories.".into(),
        ),
        "git:write" => (
            "Write Git repositories".into(),
            "Push to individually approved repositories, subject to provider rules.".into(),
        ),
        "admin" => (
            "Legacy administrator access".into(),
            "Compatibility access equivalent to all administrative permissions.".into(),
        ),
        other => (
            other.into(),
            "Additional access requested by this client.".into(),
        ),
    }
}

pub fn selected_scopes(requested: &str, fields: &HashMap<String, String>) -> String {
    requested
        .split_ascii_whitespace()
        .enumerate()
        .filter(|(index, scope)| *scope == "mcp" || fields.contains_key(&format!("scope_{index}")))
        .map(|(_, scope)| scope)
        .collect::<Vec<_>>()
        .join(" ")
}

pub(super) fn available_consent_scopes(a: &App, user: &str) -> Vec<String> {
    let mut scopes = vec![
        "mcp".to_owned(),
        "integrations:read".to_owned(),
        "integrations:write".to_owned(),
        "agents:read".to_owned(),
        "agents:write".to_owned(),
        "audit:read".to_owned(),
        "git:read".to_owned(),
        "git:write".to_owned(),
    ];
    if let Ok(integrations) = a.db.list_integrations(user) {
        scopes.extend(
            integrations
                .into_iter()
                .map(|integration| format!("integration:{}", integration.id)),
        );
    }
    scopes
}

pub(super) enum ConsentPermissionKind {
    New,
    Approved,
    ApprovedNotRequested,
    Required { new: bool },
    Other,
}

pub(super) fn consent_permission_json(
    a: &App,
    user: &str,
    scope: &str,
    index: Option<usize>,
    kind: ConsentPermissionKind,
) -> Value {
    let integration = scope.strip_prefix("integration:").and_then(|id| {
        a.db.integration(id, user)
            .ok()
            .flatten()
            .map(|integration| integration.name)
    });
    let (label, description) = permission_copy(scope, integration.as_deref());
    let (checked, disabled, badge, tone) = match kind {
        ConsentPermissionKind::New => (true, false, "New access", "new"),
        ConsentPermissionKind::Approved => (true, false, "Approved", "approved"),
        ConsentPermissionKind::ApprovedNotRequested => (true, true, "Approved", "approved"),
        ConsentPermissionKind::Required { new } => {
            (true, true, "Required", if new { "new" } else { "approved" })
        }
        ConsentPermissionKind::Other => (false, true, "Not requested", "other"),
    };
    json!({
        "scope": scope,
        "field": index.map(|index| format!("scope_{index}")),
        "label": label,
        "description": description,
        "checked": checked,
        "disabled": disabled,
        "badge": badge,
        "tone": tone,
    })
}

pub(super) fn consent_api_error(status: StatusCode, error: &str, message: &str) -> Response {
    (status, Json(json!({"error":error,"message":message}))).into_response()
}

pub(super) async fn authorize_page() -> Response {
    ui_shell()
}

pub async fn authorize_consent(
    State(a): State<App>,
    headers: HeaderMap,
    axum::extract::Query(q): axum::extract::Query<Authorize>,
) -> impl IntoResponse {
    if let Err(e) = a.lease.assert_live() {
        return (StatusCode::SERVICE_UNAVAILABLE, e.to_string()).into_response();
    }
    if q.response_type != "code" || q.code_challenge_method != "S256" {
        return consent_api_error(
            StatusCode::BAD_REQUEST,
            "Unsupported authorization request",
            "response_type=code and PKCE S256 are required",
        );
    }
    let expected_resource = format!("{}/mcp", a.config.base_url.as_str().trim_end_matches('/'));
    if q.resource != expected_resource {
        return consent_api_error(
            StatusCode::BAD_REQUEST,
            "Invalid OAuth resource",
            "The authorization request is not bound to this MCP server.",
        );
    }
    let Some((client_name, _)) = a.db.client_info(&q.client_id).ok().flatten() else {
        return consent_api_error(
            StatusCode::BAD_REQUEST,
            "Unknown client",
            "Clanker Operations Gateway does not recognize the application that started this request.",
        );
    };
    if !a
        .db
        .client_redirect_allowed(&q.client_id, &q.redirect_uri)
        .unwrap_or(false)
    {
        return consent_api_error(
            StatusCode::BAD_REQUEST,
            "Invalid return address",
            "The application's callback address is not registered with cog.",
        );
    }
    if browser_session(&a, &headers, None).is_none() {
        return consent_api_error(
            StatusCode::UNAUTHORIZED,
            "Sign in to continue",
            "Your cog session is missing or expired. Sign in, then restart the authorization request from your agent.",
        );
    }
    let Some(csrf) = cookie(&headers, "cog_csrf") else {
        return consent_api_error(
            StatusCode::FORBIDDEN,
            "Session verification failed",
            "The browser security cookie is missing. Sign in and start a fresh authorization request.",
        );
    };
    let user = browser_session(&a, &headers, None).expect("session checked");
    let existing_agent = a.db.agent_for_client(&q.client_id).ok().flatten();
    if let Some(agent) = &existing_agent
        && a.db
            .identity(&user, &agent.identity_id)
            .ok()
            .flatten()
            .is_none()
    {
        return consent_api_error(
            StatusCode::FORBIDDEN,
            "Conflicting agent binding",
            "This OAuth client is already bound to an identity owned by another user.",
        );
    }
    let identities = a.db.list_identities(&user).unwrap_or_default();
    let git_pending =
        a.db.git_pending_requests(&user, &q.client_id, chrono::Utc::now().timestamp())
            .unwrap_or_default();
    let consent = ConsentRequest {
        response_type: q.response_type,
        client_id: q.client_id,
        redirect_uri: q.redirect_uri,
        state: q.state,
        code_challenge: q.code_challenge,
        code_challenge_method: q.code_challenge_method,
        requested_scope: q.scope,
        resource: q.resource,
        user: user.clone(),
        allowed_identity_ids: identities
            .iter()
            .map(|identity| identity.id.clone())
            .collect(),
        fixed_identity_id: existing_agent
            .as_ref()
            .map(|agent| agent.identity_id.clone()),
        expires_at: chrono::Utc::now().timestamp() + 600,
        git_pending_ids: git_pending
            .iter()
            .map(|request| request.id.clone())
            .collect(),
    };
    let serialized = match serde_json::to_vec(&consent) {
        Ok(serialized) => serialized,
        Err(error) => {
            return (StatusCode::INTERNAL_SERVER_ERROR, error.to_string()).into_response();
        }
    };
    let sealed = match a.secrets.seal(&serialized) {
        Ok(sealed) => sealed,
        Err(error) => {
            return (StatusCode::INTERNAL_SERVER_ERROR, error.to_string()).into_response();
        }
    };
    let requested = consent
        .requested_scope
        .split_ascii_whitespace()
        .collect::<Vec<_>>();
    if requested.is_empty() {
        return consent_api_error(
            StatusCode::BAD_REQUEST,
            "No access requested",
            "The client did not request any OAuth scope.",
        );
    }
    let granted = match a.db.client_granted_scopes(&user, &consent.client_id) {
        Ok(scopes) => scopes.into_iter().collect::<HashSet<_>>(),
        Err(error) => {
            return (StatusCode::INTERNAL_SERVER_ERROR, error.to_string()).into_response();
        }
    };
    let requested_set = requested.iter().copied().collect::<HashSet<_>>();
    let available = available_consent_scopes(&a, &user);
    let mut new_permissions = Vec::new();
    let mut approved_permissions = Vec::new();
    for (index, scope) in requested.iter().enumerate() {
        let required = *scope == "mcp";
        let previously_granted = granted.contains(*scope);
        let permission = consent_permission_json(
            &a,
            &user,
            scope,
            Some(index),
            if required {
                ConsentPermissionKind::Required {
                    new: !previously_granted,
                }
            } else if previously_granted {
                ConsentPermissionKind::Approved
            } else {
                ConsentPermissionKind::New
            },
        );
        if previously_granted {
            approved_permissions.push(permission);
        } else {
            new_permissions.push(permission);
        }
    }
    for scope in &available {
        if granted.contains(scope) && !requested_set.contains(scope.as_str()) {
            approved_permissions.push(consent_permission_json(
                &a,
                &user,
                scope,
                None,
                ConsentPermissionKind::ApprovedNotRequested,
            ));
        }
    }
    let mut remaining_grants = granted
        .iter()
        .filter(|scope| {
            !requested_set.contains(scope.as_str()) && !available.iter().any(|item| item == *scope)
        })
        .collect::<Vec<_>>();
    remaining_grants.sort();
    for scope in remaining_grants {
        approved_permissions.push(consent_permission_json(
            &a,
            &user,
            scope,
            None,
            ConsentPermissionKind::ApprovedNotRequested,
        ));
    }
    let mut other_permissions = Vec::new();
    for scope in available {
        if !requested_set.contains(scope.as_str()) && !granted.contains(&scope) {
            other_permissions.push(consent_permission_json(
                &a,
                &user,
                &scope,
                None,
                ConsentPermissionKind::Other,
            ));
        }
    }
    let mut permission_groups = Vec::new();
    if !new_permissions.is_empty() {
        permission_groups
            .push(json!({"title":"Newly requested","tone":"new","permissions":new_permissions}));
    }
    if !approved_permissions.is_empty() {
        permission_groups.push(json!({"title":"Previously approved","tone":"approved","permissions":approved_permissions}));
    }
    if !other_permissions.is_empty() {
        permission_groups.push(json!({"title":"Other available permissions","tone":"other","permissions":other_permissions}));
    }
    if !git_pending.is_empty() {
        let requests=git_pending.iter().enumerate().map(|(index,request)|json!({
            "field":format!("git_request_{index}"),
            "label":request.display_name,
            "description":format!("{} access through integration {}",request.permission,request.integration_id),
            "checked":true,
            "disabled":false,
            "badge":"Repository",
            "tone":"new",
        })).collect::<Vec<_>>();
        permission_groups
            .push(json!({"title":"Exact repository access","tone":"new","permissions":requests}));
    }
    let redirect_host = url::Url::parse(&consent.redirect_uri)
        .ok()
        .and_then(|url| url.host_str().map(str::to_owned))
        .unwrap_or_else(|| consent.redirect_uri.clone());
    let fixed_identity = consent.fixed_identity_id.as_ref().map(|id| {
        let name = identities
            .iter()
            .find(|item| &item.id == id)
            .map(|item| item.name.as_str())
            .unwrap_or("Unknown identity");
        json!({"id":id,"name":name})
    });
    let identities = identities
        .into_iter()
        .map(|identity| json!({"id":identity.id,"name":identity.name}))
        .collect::<Vec<_>>();
    let mut response = Json(json!({
        "client":{"name":client_name,"id":consent.client_id.chars().take(12).collect::<String>(),"redirectHost":redirect_host},
        "consent":sealed,
        "csrfToken":csrf,
        "identities":identities,
        "fixedIdentity":fixed_identity,
        "permissionGroups":permission_groups,
    })).into_response();
    response.headers_mut().insert(
        header::CACHE_CONTROL,
        header::HeaderValue::from_static("no-store"),
    );
    response
}
pub async fn authorize_post(
    State(a): State<App>,
    headers: HeaderMap,
    Form(form): Form<ConsentForm>,
) -> impl IntoResponse {
    let mutation = a.mutations.lock().await;
    if let Err(e) = a.lease.assert_live() {
        return (StatusCode::SERVICE_UNAVAILABLE, e.to_string()).into_response();
    }
    let consent = match a
        .secrets
        .open(&form.consent)
        .and_then(|value| Ok(serde_json::from_slice::<ConsentRequest>(&value)?))
    {
        Ok(consent) => consent,
        Err(_) => return (StatusCode::BAD_REQUEST, "invalid consent request").into_response(),
    };
    if consent.expires_at < chrono::Utc::now().timestamp()
        || consent.response_type != "code"
        || consent.code_challenge_method != "S256"
        || consent.resource != format!("{}/mcp", a.config.base_url.as_str().trim_end_matches('/'))
        || !a
            .db
            .client_redirect_allowed(&consent.client_id, &consent.redirect_uri)
            .unwrap_or(false)
    {
        return (StatusCode::BAD_REQUEST, "invalid authorization request").into_response();
    }
    if !origin_allowed(&a, &headers) {
        return (StatusCode::FORBIDDEN, "invalid origin").into_response();
    }
    let Some(user) = browser_session(&a, &headers, Some(&form.csrf_token)) else {
        return (StatusCode::UNAUTHORIZED, "invalid session or CSRF token").into_response();
    };
    if user != consent.user {
        return (
            StatusCode::FORBIDDEN,
            "consent request belongs to another session",
        )
            .into_response();
    }
    if let Some(response) = rate_limit(&a, "authorization", &user, 30) {
        return response;
    }
    if form.decision == "deny" {
        if let Err(error) = a.db.consume_git_pending_requests(
            &user,
            &consent.client_id,
            &[],
            chrono::Utc::now().timestamp(),
        ) {
            return (StatusCode::INTERNAL_SERVER_ERROR, error.to_string()).into_response();
        }
        if let Err(error) = audit_details(
            &a,
            Some(&user),
            "oauth.consent",
            Some(&consent.client_id),
            "denied",
            &json!({"requested_scopes": consent.requested_scope.split_ascii_whitespace().collect::<Vec<_>>(), "granted_scopes": []}),
        ) {
            return (StatusCode::INTERNAL_SERVER_ERROR, error.to_string()).into_response();
        }
        if let Err(error) = persist(&a).await {
            return (StatusCode::SERVICE_UNAVAILABLE, error.to_string()).into_response();
        }
        let mut url = match url::Url::parse(&consent.redirect_uri) {
            Ok(url) => url,
            Err(error) => return (StatusCode::BAD_REQUEST, error.to_string()).into_response(),
        };
        url.query_pairs_mut()
            .append_pair("error", "access_denied")
            .append_pair("state", &consent.state);
        return Redirect::to(url.as_str()).into_response();
    }
    if form.decision != "allow" {
        return (StatusCode::BAD_REQUEST, "invalid consent decision").into_response();
    }
    let selected_identity = form
        .fields
        .get("identity_id")
        .map(String::as_str)
        .or(consent.fixed_identity_id.as_deref())
        .unwrap_or("");
    let identity_id = if let Some(fixed) = &consent.fixed_identity_id {
        if selected_identity != fixed {
            return (
                StatusCode::FORBIDDEN,
                "agent identity binding cannot be changed",
            )
                .into_response();
        }
        fixed.clone()
    } else if selected_identity.is_empty() {
        let name = form
            .fields
            .get("new_identity_name")
            .map(String::as_str)
            .unwrap_or("");
        match a.db.create_identity(&user, name) {
            Ok(id) => id,
            Err(error) => return (StatusCode::BAD_REQUEST, error.to_string()).into_response(),
        }
    } else {
        if !consent
            .allowed_identity_ids
            .iter()
            .any(|id| id == selected_identity)
            || a.db
                .identity(&user, selected_identity)
                .ok()
                .flatten()
                .is_none()
        {
            return (
                StatusCode::FORBIDDEN,
                "identity is unavailable or belongs to another user",
            )
                .into_response();
        }
        selected_identity.to_owned()
    };
    let agent = match a.db.bind_agent(&user, &identity_id, &consent.client_id) {
        Ok(agent) => agent,
        Err(error) => return (StatusCode::FORBIDDEN, error.to_string()).into_response(),
    };
    let requested = consent
        .requested_scope
        .split_ascii_whitespace()
        .collect::<HashSet<_>>();
    let mut granted =
        a.db.client_granted_scopes(&user, &consent.client_id)
            .unwrap_or_default()
            .into_iter()
            .filter(|scope| !requested.contains(scope.as_str()))
            .collect::<Vec<_>>();
    for scope in selected_scopes(&consent.requested_scope, &form.fields).split_ascii_whitespace() {
        if !granted.iter().any(|item| item == scope) {
            granted.push(scope.to_owned());
        }
    }
    let granted_scope = granted.join(" ");
    if let Err(error) = a.db.set_identity_grants(&user, &identity_id, &granted) {
        return (StatusCode::BAD_REQUEST, error.to_string()).into_response();
    }
    let selected_git = consent
        .git_pending_ids
        .iter()
        .enumerate()
        .filter(|(index, _)| form.fields.contains_key(&format!("git_request_{index}")))
        .map(|(_, id)| id.clone())
        .collect::<Vec<_>>();
    let approved_git = match a.db.consume_git_pending_requests(
        &user,
        &consent.client_id,
        &selected_git,
        chrono::Utc::now().timestamp(),
    ) {
        Ok(value) => value,
        Err(error) => return (StatusCode::BAD_REQUEST, error.to_string()).into_response(),
    };
    match oauth::issue_code(
        &a.db,
        &consent.client_id,
        &user,
        &consent.redirect_uri,
        &granted_scope,
        &consent.code_challenge,
    ) {
        Ok(code) => {
            if let Err(error) = audit_details(
                &a,
                Some(&user),
                "oauth.consent",
                Some(&consent.client_id),
                "allowed",
                &json!({"identity_id":identity_id,"agent_id":agent.id,"client_id":consent.client_id,"requested_scopes": consent.requested_scope.split_ascii_whitespace().collect::<Vec<_>>(), "granted_scopes": granted_scope.split_ascii_whitespace().collect::<Vec<_>>(),"git_repository_grants":approved_git}),
            ) {
                return (StatusCode::INTERNAL_SERVER_ERROR, error.to_string()).into_response();
            }
            if let Err(e) = persist(&a).await {
                return (StatusCode::SERVICE_UNAVAILABLE, e.to_string()).into_response();
            }
            let mut url = url::Url::parse(&consent.redirect_uri).unwrap();
            url.query_pairs_mut()
                .append_pair("code", &code)
                .append_pair("state", &consent.state);
            drop(mutation);
            match a.config.server_local_callbacks {
                crate::config::ServerLocalCallbacks::Off => {
                    Redirect::to(url.as_str()).into_response()
                }
                mode => match deliver_loopback_callback(&url).await {
                    CallbackDelivery::Delivered => Html(standalone_page(
                        "Authorization complete",
                        "You're all set",
                        "<p class=\"lead\">The authorization was delivered securely to your local agent.</p><div class=\"notice success\">You can close this window and return to your agent.</div><div class=\"actions\"><a class=\"button\" href=\"/\">Return to cog</a></div>",
                        "status",
                    ))
                    .into_response(),
                    CallbackDelivery::NotSent
                        if mode == crate::config::ServerLocalCallbacks::Auto =>
                    {
                        Redirect::to(url.as_str()).into_response()
                    }
                    CallbackDelivery::NotSent => (
                        StatusCode::BAD_GATEWAY,
                        Html(standalone_page(
                            "Delivery failed",
                            "Authorization was not delivered",
                            "<p class=\"lead\">Clanker Operations Gateway could not reach the required local callback. No browser redirect was attempted.</p><div class=\"notice warning\">Return to your agent and start a fresh authorization request.</div>",
                            "status",
                        )),
                    )
                        .into_response(),
                    CallbackDelivery::Indeterminate => (
                        StatusCode::BAD_GATEWAY,
                        Html(standalone_page(
                            "Delivery uncertain",
                            "Check your agent",
                            "<p class=\"lead\">The callback may have received the authorization. To prevent duplicate delivery, cog did not try another channel.</p><div class=\"notice warning\">Check your agent before starting a new authorization request.</div>",
                            "status",
                        )),
                    )
                        .into_response(),
                },
            }
        }
        Err(e) => (StatusCode::BAD_REQUEST, e.to_string()).into_response(),
    }
}

#[derive(Debug, PartialEq, Eq)]
pub enum CallbackDelivery {
    NotSent,
    Delivered,
    Indeterminate,
}

/// Delivers an already-durable authorization response without proxies,
/// redirects, credentials, cookies, or response-body buffering. `NotSent` is
/// returned only when cog can prove no callback bytes left this process.
pub async fn deliver_loopback_callback(url: &url::Url) -> CallbackDelivery {
    if url.scheme() != "http"
        || !url.username().is_empty()
        || url.password().is_some()
        || url.fragment().is_some()
    {
        return CallbackDelivery::NotSent;
    }
    let ip = match url.host() {
        Some(url::Host::Ipv4(ip)) if ip == std::net::Ipv4Addr::LOCALHOST => IpAddr::V4(ip),
        Some(url::Host::Ipv6(ip)) if ip == std::net::Ipv6Addr::LOCALHOST => IpAddr::V6(ip),
        _ => return CallbackDelivery::NotSent,
    };
    let address = SocketAddr::new(ip, url.port().unwrap_or(80));
    let Ok(Ok(mut stream)) = tokio::time::timeout(
        Duration::from_secs(2),
        tokio::net::TcpStream::connect(address),
    )
    .await
    else {
        return CallbackDelivery::NotSent;
    };
    let target = match url.query() {
        Some(query) => format!("{}?{query}", url.path()),
        None => url.path().to_owned(),
    };
    let host = match ip {
        IpAddr::V4(ip) => format!("{ip}:{}", address.port()),
        IpAddr::V6(ip) => format!("[{ip}]:{}", address.port()),
    };
    let request = format!(
        "GET {target} HTTP/1.1\r\nHost: {host}\r\nConnection: close\r\nUser-Agent: cog-local-callback\r\n\r\n"
    );
    let bytes = request.as_bytes();
    let mut sent = 0;
    while sent < bytes.len() {
        match tokio::time::timeout(Duration::from_secs(2), stream.write(&bytes[sent..])).await {
            Ok(Ok(0)) | Ok(Err(_)) | Err(_) => {
                return if sent == 0 {
                    CallbackDelivery::NotSent
                } else {
                    CallbackDelivery::Indeterminate
                };
            }
            Ok(Ok(written)) => sent += written,
        }
    }
    let mut response = Vec::with_capacity(1024);
    loop {
        let mut chunk = [0_u8; 1024];
        match tokio::time::timeout(Duration::from_secs(3), stream.read(&mut chunk)).await {
            Ok(Ok(0)) => break,
            Ok(Ok(read)) => {
                response.extend_from_slice(&chunk[..read]);
                if response.windows(4).any(|window| window == b"\r\n\r\n") {
                    break;
                }
                if response.len() >= 16 * 1024 {
                    return CallbackDelivery::Indeterminate;
                }
            }
            Ok(Err(_)) | Err(_) => return CallbackDelivery::Indeterminate,
        }
    }
    let status = response
        .split(|byte| *byte == b'\n')
        .next()
        .unwrap_or_default();
    if status.starts_with(b"HTTP/1.1 2") || status.starts_with(b"HTTP/1.0 2") {
        CallbackDelivery::Delivered
    } else {
        CallbackDelivery::Indeterminate
    }
}

#[derive(Deserialize)]
pub(super) struct RevocationRequest {
    token: String,
}

pub(super) async fn revoke_token(
    State(a): State<App>,
    Form(request): Form<RevocationRequest>,
) -> impl IntoResponse {
    let _mutation = a.mutations.lock().await;
    if let Some(response) = rate_limit(&a, "revocation", "global", 120) {
        return response;
    }
    if let Err(error) = a.lease.assert_live() {
        return (StatusCode::SERVICE_UNAVAILABLE, error.to_string()).into_response();
    }
    match a.db.revoke_token(&token_hash(&request.token)) {
        Ok(changed) => {
            if let Err(error) = audit(
                &a,
                None,
                "oauth.revoke",
                None,
                if changed { "success" } else { "not_found" },
            ) {
                return (StatusCode::INTERNAL_SERVER_ERROR, error.to_string()).into_response();
            }
            if let Err(error) = persist(&a).await {
                return (StatusCode::SERVICE_UNAVAILABLE, error.to_string()).into_response();
            }
            StatusCode::OK.into_response()
        }
        Err(error) => (StatusCode::INTERNAL_SERVER_ERROR, error.to_string()).into_response(),
    }
}
pub(super) async fn token(
    State(a): State<App>,
    Form(r): Form<oauth::TokenRequest>,
) -> impl IntoResponse {
    let _mutation = a.mutations.lock().await;
    if let Some(response) = rate_limit(&a, "token", &r.client_id, 60) {
        return response;
    }
    let audit_client = r.client_id.clone();
    let expected_resource = format!("{}/mcp", a.config.base_url.as_str().trim_end_matches('/'));
    if r.resource.as_deref() != Some(expected_resource.as_str()) {
        return (
            StatusCode::BAD_REQUEST,
            Json(json!({"error":"invalid_target","error_description":"resource must identify this MCP server"})),
        )
            .into_response();
    }
    if let Err(e) = a.lease.assert_live() {
        return (
            StatusCode::SERVICE_UNAVAILABLE,
            Json(json!({"error":"temporarily_unavailable","error_description":e.to_string()})),
        )
            .into_response();
    }
    match oauth::redeem(&a.db, r) {
        Ok(v) => {
            if let Err(error) = audit(&a, Some(&audit_client), "oauth.token", None, "success") {
                return (StatusCode::INTERNAL_SERVER_ERROR, error.to_string()).into_response();
            }
            match persist(&a).await {
            Ok(()) => Json(json!(v)).into_response(),
            Err(e) => (
                StatusCode::SERVICE_UNAVAILABLE,
                Json(json!({"error":"temporarily_unavailable","error_description":e.to_string()})),
            )
                .into_response(),
            }
        }
        Err(e) => {
            a.metrics.oauth_failures.fetch_add(1, Ordering::Relaxed);
            if audit(&a, Some(&audit_client), "oauth.token", None, "denied").is_ok() {
                let _ = persist(&a).await;
            }
            (
                StatusCode::BAD_REQUEST,
                Json(json!({"error":"invalid_grant","error_description":e.to_string()})),
            )
                .into_response()
        }
    }
}
pub(super) fn bearer(headers: &HeaderMap) -> Option<&str> {
    headers
        .get(http::header::AUTHORIZATION)?
        .to_str()
        .ok()?
        .strip_prefix("Bearer ")
}
#[derive(Debug)]
pub enum AuthFailure {
    Missing,
    Invalid,
    Insufficient,
    Internal,
}

#[derive(Clone)]
pub struct AuthContext {
    pub user: String,
    pub agent: String,
    pub client: String,
    pub identity: String,
    pub scopes: HashSet<String>,
    pub integrations: HashSet<String>,
}

impl AuthContext {
    pub fn allows(&self, required: &str) -> bool {
        self.scopes.contains(required)
            || (self.scopes.contains("admin")
                && matches!(
                    required,
                    "integrations:read"
                        | "integrations:write"
                        | "agents:read"
                        | "agents:write"
                        | "audit:read"
                ))
    }

    pub fn allows_integration(&self, integration_id: &str) -> bool {
        self.scopes.contains("admin") || self.integrations.contains(integration_id)
    }
}

pub(super) fn auth_context(a: &App, h: &HeaderMap) -> Result<AuthContext, AuthFailure> {
    let token = bearer(h).ok_or(AuthFailure::Missing)?;
    let row =
        a.db.token_context(&token_hash(token), chrono::Utc::now().timestamp())
            .map_err(|_| AuthFailure::Internal)?
            .ok_or(AuthFailure::Invalid)?;
    Ok(AuthContext {
        user: row.user_id,
        agent: row.agent_id,
        client: row.client_id,
        identity: row.identity_id,
        scopes: row.scopes.into_iter().collect(),
        integrations: row.integration_ids.into_iter().collect(),
    })
}

pub fn scoped_user(a: &App, h: &HeaderMap, scope: &str) -> Result<String, AuthFailure> {
    let context = auth_context(a, h)?;
    if !context.allows(scope) {
        return Err(AuthFailure::Insufficient);
    }
    Ok(context.user)
}

pub fn auth_failure(a: &App, failure: AuthFailure, scope: &str) -> axum::response::Response {
    if matches!(failure, AuthFailure::Internal) {
        return StatusCode::INTERNAL_SERVER_ERROR.into_response();
    }
    let metadata = resource_metadata_url(a);
    let (status, error) = match failure {
        AuthFailure::Missing => (StatusCode::UNAUTHORIZED, None),
        AuthFailure::Invalid => (StatusCode::UNAUTHORIZED, Some("invalid_token")),
        AuthFailure::Insufficient => (StatusCode::FORBIDDEN, Some("insufficient_scope")),
        AuthFailure::Internal => unreachable!(),
    };
    let mut challenge = format!("Bearer resource_metadata=\"{metadata}\", scope=\"{scope}\"");
    if let Some(error) = error {
        challenge.push_str(&format!(", error=\"{error}\""));
    }
    (
        status,
        [(http::header::WWW_AUTHENTICATE, challenge)],
        "unauthorized",
    )
        .into_response()
}
