use super::*;

pub fn github_app_install_url(slug: &str) -> anyhow::Result<String> {
    anyhow::ensure!(
        !slug.is_empty()
            && slug
                .bytes()
                .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || byte == b'-'),
        "GitHub returned an invalid App slug"
    );
    Ok(format!("https://github.com/apps/{slug}/installations/new"))
}

pub async fn admin_github_app_setup_start(
    a: &App,
    user: &str,
    args: Value,
) -> anyhow::Result<Value> {
    let name = args
        .get("name")
        .and_then(Value::as_str)
        .map(str::trim)
        .filter(|name| !name.is_empty())
        .ok_or_else(|| anyhow::anyhow!("name is required"))?;
    anyhow::ensure!(name.len() <= 128, "name is too long");
    let state = crate::crypto::random_token(32);
    let expires_at = chrono::Utc::now().timestamp() + 20 * 60;
    let _mutation = a.mutations.lock().await;
    a.lease.assert_live()?;
    let id =
        a.db.create_github_app_setup(user, name, &token_hash(&state), expires_at)?;
    audit(
        a,
        Some(user),
        "github_app.setup.start",
        Some(&id),
        "pending",
    )?;
    persist(a).await?;
    let browser_url = format!(
        "{}/github/app/setup/{state}",
        a.config.base_url.as_str().trim_end_matches('/')
    );
    Ok(json!({
        "id": id,
        "status": "manifest_pending",
        "browserUrl": browser_url,
        "callbackOrigin": a.config.base_url.origin().ascii_serialization(),
        "browserRequirement": "The browser completing GitHub setup must be able to reach callbackOrigin; use the public COG URL, a private-network route, or an SSH tunnel.",
        "expiresAt": expires_at,
        "action": "openBrowserUrlThenWaitForGitHubSetup"
    }))
}

pub async fn admin_github_app_setup_status(a: &App, user: &str, id: &str) -> anyhow::Result<Value> {
    let integration =
        a.db.integration(id, user)?
            .ok_or_else(|| anyhow::anyhow!("integration not found"))?;
    anyhow::ensure!(
        integration.transport == "git"
            && integration.config.get("provider").and_then(Value::as_str) == Some("github"),
        "integration is not GitHub"
    );
    let provider = integration
        .config
        .get("providerConfig")
        .and_then(Value::as_object);
    let app_created = provider
        .and_then(|provider| provider.get("appId"))
        .and_then(Value::as_str)
        .is_some_and(|value| !value.is_empty());
    let installed = provider
        .and_then(|provider| provider.get("installationId"))
        .and_then(Value::as_str)
        .is_some_and(|value| !value.is_empty());
    let app_slug = provider
        .and_then(|provider| provider.get("appSlug"))
        .and_then(Value::as_str);
    let pending =
        a.db.github_app_setup_for_integration(user, id, chrono::Utc::now().timestamp())?;
    let status = if installed {
        "installed"
    } else if app_created
        || pending
            .as_ref()
            .is_some_and(|setup| setup.manifest_completed_at.is_some())
    {
        "installation_pending"
    } else if pending.is_some() {
        "manifest_pending"
    } else {
        "setup_expired"
    };
    let mut result = json!({
        "id": id,
        "status": status,
        "appCreated": app_created,
        "installed": installed,
        "credentialsConfigured": app_created && a.db.integration_secret(id, user)?.is_some()
    });
    if let Some(slug) = app_slug
        && let Some(object) = result.as_object_mut()
    {
        object.insert(
            "repositorySelectionUrl".into(),
            json!(github_app_install_url(slug)?),
        );
    }
    Ok(result)
}

pub(super) async fn github_app_setup_launch(
    State(a): State<App>,
    Path(state): Path<String>,
) -> Response {
    if state.len() > 256 {
        return (StatusCode::BAD_REQUEST, "GitHub App setup link is invalid").into_response();
    }
    let now = chrono::Utc::now().timestamp();
    let setup = match a.db.github_app_setup_by_state(&token_hash(&state), now) {
        Ok(Some(setup)) if setup.manifest_completed_at.is_none() => setup,
        _ => {
            return (
                StatusCode::BAD_REQUEST,
                "GitHub App setup link is invalid or expired",
            )
                .into_response();
        }
    };
    let callback = format!(
        "{}/github/app/manifest/callback",
        a.config.base_url.as_str().trim_end_matches('/')
    );
    let encoded_state = url::form_urlencoded::byte_serialize(state.as_bytes()).collect::<String>();
    let installation_callback = format!(
        "{}/github/app/installation/callback?state={}",
        a.config.base_url.as_str().trim_end_matches('/'),
        encoded_state
    );
    let suffix = setup.integration_id.chars().take(8).collect::<String>();
    let manifest = json!({
        "name": format!("COG {suffix}"),
        "url": a.config.base_url.as_str(),
        "redirect_url": callback,
        "setup_url": installation_callback,
        "public": false,
        "default_permissions": {"contents": "write", "workflows": "write"},
        "default_events": []
    });
    let body = format!(
        "<!doctype html><html><head><meta charset=\"utf-8\"><title>Continue to GitHub</title></head><body><p>Continuing to GitHub App creation…</p><form id=\"github-manifest\" method=\"post\" action=\"https://github.com/settings/apps/new?state={}\"><input type=\"hidden\" name=\"manifest\" value=\"{}\"></form><script>document.getElementById('github-manifest').submit()</script><noscript><button form=\"github-manifest\" type=\"submit\">Continue to GitHub</button></noscript></body></html>",
        html_escape(&encoded_state),
        html_escape(&manifest.to_string())
    );
    Html(body).into_response()
}

#[derive(Deserialize)]
pub(super) struct GitHubManifestCallbackQuery {
    code: String,
    state: String,
}
#[derive(Deserialize)]
pub(super) struct GitHubManifestConversion {
    id: u64,
    slug: String,
    pem: String,
}

pub(super) async fn github_app_manifest_callback(
    State(a): State<App>,
    Query(query): Query<GitHubManifestCallbackQuery>,
) -> Response {
    let now = chrono::Utc::now().timestamp();
    if query.code.len() > 512 || query.state.len() > 256 {
        return (StatusCode::BAD_REQUEST, "GitHub App callback is invalid").into_response();
    }
    let state_hash = token_hash(&query.state);
    let setup = match a.db.github_app_setup_by_state(&state_hash, now) {
        Ok(Some(setup)) if setup.manifest_completed_at.is_none() => setup,
        _ => {
            return (
                StatusCode::BAD_REQUEST,
                "GitHub App setup state is invalid or expired",
            )
                .into_response();
        }
    };
    if let Err(error) = a.lease.assert_live() {
        return (StatusCode::SERVICE_UNAVAILABLE, error.to_string()).into_response();
    }
    let client = match reqwest::Client::builder()
        .redirect(reqwest::redirect::Policy::none())
        .timeout(Duration::from_secs(30))
        .user_agent("cog-github-app-setup")
        .build()
    {
        Ok(client) => client,
        Err(_) => return StatusCode::INTERNAL_SERVER_ERROR.into_response(),
    };
    let encoded_code =
        url::form_urlencoded::byte_serialize(query.code.as_bytes()).collect::<String>();
    let conversion_url = match a
        .github_api_base
        .join(&format!("app-manifests/{encoded_code}/conversions"))
    {
        Ok(url) => url,
        Err(_) => return StatusCode::INTERNAL_SERVER_ERROR.into_response(),
    };
    let response = match client
        .post(conversion_url)
        .header(header::ACCEPT, "application/vnd.github+json")
        .header("X-GitHub-Api-Version", "2022-11-28")
        .send()
        .await
    {
        Ok(response) => response,
        Err(_) => {
            return (
                StatusCode::BAD_GATEWAY,
                "GitHub App creation could not be completed",
            )
                .into_response();
        }
    };
    if !response.status().is_success() {
        return (
            StatusCode::BAD_GATEWAY,
            "GitHub rejected the App manifest conversion",
        )
            .into_response();
    }
    let body = match response.bytes().await {
        Ok(body) if body.len() <= 1024 * 1024 => body,
        _ => {
            return (
                StatusCode::BAD_GATEWAY,
                "GitHub returned an invalid App manifest response",
            )
                .into_response();
        }
    };
    let conversion: GitHubManifestConversion = match serde_json::from_slice(&body) {
        Ok(conversion) => conversion,
        Err(_) => {
            return (
                StatusCode::BAD_GATEWAY,
                "GitHub returned an invalid App manifest response",
            )
                .into_response();
        }
    };
    if jsonwebtoken::EncodingKey::from_rsa_pem(conversion.pem.as_bytes()).is_err()
        || github_app_install_url(&conversion.slug).is_err()
    {
        return (
            StatusCode::BAD_GATEWAY,
            "GitHub returned invalid App credentials",
        )
            .into_response();
    }
    let secret_json = match serde_json::to_vec(&json!({"privateKey": conversion.pem})) {
        Ok(secret) => secret,
        Err(_) => return StatusCode::INTERNAL_SERVER_ERROR.into_response(),
    };
    let secret = match a.secrets.seal(&secret_json) {
        Ok(secret) => secret,
        Err(_) => return StatusCode::INTERNAL_SERVER_ERROR.into_response(),
    };
    let config = json!({
        "kind": "git",
        "provider": "github",
        "host": "github.com",
        "providerConfig": {
            "appId": conversion.id.to_string(),
            "appSlug": conversion.slug
        },
        "setupStatus": "installation_pending"
    });
    let _mutation = a.mutations.lock().await;
    if let Err(error) = a.lease.assert_live() {
        return (StatusCode::SERVICE_UNAVAILABLE, error.to_string()).into_response();
    }
    match a.db.complete_github_app_manifest(
        &state_hash,
        &config,
        &secret,
        config
            .pointer("/providerConfig/appSlug")
            .and_then(Value::as_str)
            .unwrap_or_default(),
        now,
    ) {
        Ok(true) => {}
        Ok(false) => {
            return (
                StatusCode::CONFLICT,
                "GitHub App setup was already completed",
            )
                .into_response();
        }
        Err(_) => return StatusCode::INTERNAL_SERVER_ERROR.into_response(),
    }
    if audit(
        &a,
        Some(&setup.user_id),
        "github_app.manifest.complete",
        Some(&setup.integration_id),
        "success",
    )
    .is_err()
        || persist(&a).await.is_err()
    {
        return StatusCode::SERVICE_UNAVAILABLE.into_response();
    }
    let slug = config
        .pointer("/providerConfig/appSlug")
        .and_then(Value::as_str)
        .unwrap_or_default();
    match github_app_install_url(slug) {
        Ok(url) => Redirect::to(&url).into_response(),
        Err(_) => StatusCode::INTERNAL_SERVER_ERROR.into_response(),
    }
}

#[derive(Deserialize)]
pub(super) struct GitHubInstallationCallbackQuery {
    installation_id: String,
    state: String,
    #[serde(default)]
    setup_action: Option<String>,
}

pub(super) async fn github_app_installation_callback(
    State(a): State<App>,
    Query(query): Query<GitHubInstallationCallbackQuery>,
) -> Response {
    if query.installation_id.is_empty()
        || query.installation_id.len() > 32
        || query.state.len() > 256
        || !query
            .installation_id
            .bytes()
            .all(|byte| byte.is_ascii_digit())
        || query
            .setup_action
            .as_deref()
            .is_some_and(|action| action != "install" && action != "update")
    {
        return (
            StatusCode::BAD_REQUEST,
            "GitHub installation callback is invalid",
        )
            .into_response();
    }
    let now = chrono::Utc::now().timestamp();
    let state_hash = token_hash(&query.state);
    let setup = match a.db.github_app_setup_by_state(&state_hash, now) {
        Ok(Some(setup)) if setup.manifest_completed_at.is_some() => setup,
        _ => {
            return (
                StatusCode::BAD_REQUEST,
                "GitHub installation state is invalid or expired",
            )
                .into_response();
        }
    };
    let integration = match a.db.integration(&setup.integration_id, &setup.user_id) {
        Ok(Some(integration)) => integration,
        _ => return StatusCode::BAD_REQUEST.into_response(),
    };
    let mut config = integration.config;
    let Some(provider) = config
        .get_mut("providerConfig")
        .and_then(Value::as_object_mut)
    else {
        return StatusCode::INTERNAL_SERVER_ERROR.into_response();
    };
    provider.insert("installationId".into(), json!(query.installation_id));
    if let Some(object) = config.as_object_mut() {
        object.insert("setupStatus".into(), json!("installed"));
    }
    let _mutation = a.mutations.lock().await;
    if let Err(error) = a.lease.assert_live() {
        return (StatusCode::SERVICE_UNAVAILABLE, error.to_string()).into_response();
    }
    let id = match a
        .db
        .complete_github_app_installation(&state_hash, &config, now)
    {
        Ok(Some(id)) => id,
        Ok(None) => {
            return (
                StatusCode::CONFLICT,
                "GitHub installation was already completed",
            )
                .into_response();
        }
        Err(_) => return StatusCode::INTERNAL_SERVER_ERROR.into_response(),
    };
    if audit(
        &a,
        Some(&setup.user_id),
        "github_app.installation.complete",
        Some(&id),
        "success",
    )
    .is_err()
        || persist(&a).await.is_err()
    {
        return StatusCode::SERVICE_UNAVAILABLE.into_response();
    }
    Redirect::to(&format!(
        "/github/app/installation/complete?integration_id={}",
        id
    ))
    .into_response()
}
