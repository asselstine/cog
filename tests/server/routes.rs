use argon2::{
    Argon2, PasswordHasher,
    password_hash::{SaltString, rand_core::OsRng},
};
use axum::{
    Json, Router,
    body::Body,
    extract::{Form, Path, Query, State},
    http::{HeaderMap, Request, StatusCode},
    response::{IntoResponse, Response},
    routing::{get, post},
};
use cog::server::*;
use cog::{
    Config,
    crypto::{SecretBox, token_hash},
    db::{Database, UpstreamOAuthClient, UpstreamOAuthToken},
    git::providers::GitProvider,
    git::{GitOperation, RepositoryReference, ResolvedRepository},
    lease::LeaseGuard,
    ltx::Replicator,
    runtime::CodeRuntime,
    upstream::{Catalog, Tool, ToolProvider, UpstreamInsufficientScope},
};
use http_body_util::BodyExt;
use object_store::memory::InMemory;
use object_store::{ObjectStore, path::Path as ObjectPath};
use serde_json::{Value, json};
use std::{
    collections::{HashMap, HashSet},
    sync::{
        Arc,
        atomic::{AtomicBool, AtomicU64, AtomicUsize, Ordering},
    },
    time::Duration,
};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tower::ServiceExt;

#[test]
fn client_stream_limit_is_isolated_and_permits_release_on_drop() {
    let limiter = Arc::new(ClientStreamLimiter::default());
    let first = limiter.try_acquire("client-a", 1).unwrap();
    assert!(limiter.try_acquire("client-a", 1).is_none());
    let other = limiter.try_acquire("client-b", 1).unwrap();
    drop(first);
    assert!(limiter.try_acquire("client-a", 1).is_some());
    drop(other);
    assert!(limiter.active.lock().unwrap().get("client-b").is_none());
}

struct PolicyFixture;
#[async_trait::async_trait]
impl ToolProvider for PolicyFixture {
    async fn tools(&self) -> anyhow::Result<Vec<Tool>> {
        Ok(["read", "write"]
            .into_iter()
            .map(|name| Tool {
                name: name.into(),
                description: None,
                input_schema: json!({}),
                extra: Default::default(),
            })
            .collect())
    }
    async fn call(&self, name: &str, _args: Value) -> anyhow::Result<Value> {
        Ok(json!(name))
    }
}

struct FailingFixture;
#[async_trait::async_trait]
impl ToolProvider for FailingFixture {
    async fn tools(&self) -> anyhow::Result<Vec<Tool>> {
        anyhow::bail!("expected tools failure")
    }
    async fn call(&self, _name: &str, _args: Value) -> anyhow::Result<Value> {
        anyhow::bail!("expected call failure")
    }
    async fn close(&self) -> anyhow::Result<()> {
        anyhow::bail!("expected close failure")
    }
}

struct ScopeChallengeFixture {
    challenge: UpstreamInsufficientScope,
}
#[async_trait::async_trait]
impl ToolProvider for ScopeChallengeFixture {
    async fn tools(&self) -> anyhow::Result<Vec<Tool>> {
        Ok(vec![Tool {
            name: "search".into(),
            description: Some("Search provider operations".into()),
            input_schema: json!({"type":"object"}),
            extra: Default::default(),
        }])
    }
    async fn call(&self, _name: &str, _args: Value) -> anyhow::Result<Value> {
        Err(self.challenge.clone().into())
    }
}

#[derive(Clone)]
struct OAuthFixture {
    base: String,
    refreshes: Arc<AtomicUsize>,
    client_metadata: Arc<AtomicBool>,
}

async fn resource(State(state): State<OAuthFixture>) -> Json<Value> {
    Json(json!({
        "resource": format!("{}/mcp", state.base),
        "authorization_servers":[state.base.as_str()]
    }))
}

async fn authorization_metadata(State(state): State<OAuthFixture>) -> Json<Value> {
    Json(json!({
        "issuer":state.base.as_str(),
        "authorization_endpoint":format!("{}/authorize",state.base),
        "token_endpoint":format!("{}/token",state.base),
        "registration_endpoint":format!("{}/register",state.base),
        "code_challenge_methods_supported":["S256"],
        "client_id_metadata_document_supported":state.client_metadata.load(Ordering::SeqCst)
    }))
}

async fn dynamic_registration(body: axum::body::Bytes) -> Json<Value> {
    let request: Value = serde_json::from_slice(&body).unwrap();
    assert_eq!(request["token_endpoint_auth_method"], "client_secret_post");
    Json(json!({"client_id":"dynamic-client","client_secret":"dynamic-secret"}))
}

async fn refresh_token(State(state): State<OAuthFixture>, body: String) -> Json<Value> {
    assert!(body.contains("grant_type=refresh_token"));
    assert!(body.contains("refresh_token=old-refresh"));
    assert!(body.contains("client_secret=dynamic-secret"));
    let resource_values: Vec<_> = url::form_urlencoded::parse(body.as_bytes())
        .filter(|(name, _)| name == "resource")
        .map(|(_, value)| value.into_owned())
        .collect();
    assert_eq!(resource_values, vec![format!("{}/mcp", state.base)]);
    assert!(!body.contains("scope="));
    state.refreshes.fetch_add(1, Ordering::SeqCst);
    Json(json!({
        "access_token":"new-access",
        "refresh_token":"new-refresh",
        "token_type":"Bearer",
        "scope":"mcp",
        "expires_in":3600,
        "refresh_expires_in":7200
    }))
}

#[tokio::test]
async fn upstream_authorization_discovery_falls_back_to_oidc() {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    let state = OAuthFixture {
        base: format!("http://{address}"),
        refreshes: Arc::new(AtomicUsize::new(0)),
        client_metadata: Arc::new(AtomicBool::new(true)),
    };
    let server = tokio::spawn(
        axum::serve(
            listener,
            Router::new()
                .route(
                    "/.well-known/openid-configuration",
                    get(authorization_metadata),
                )
                .with_state(state.clone()),
        )
        .into_future(),
    );
    let metadata =
        authorization_server_metadata(&reqwest::Client::new(), &state.base.parse().unwrap())
            .await
            .unwrap();
    assert_eq!(metadata["issuer"], state.base);
    assert_eq!(metadata["client_id_metadata_document_supported"], true);
    server.abort();
}

#[tokio::test]
async fn upstream_discovery_dcr_and_refresh_rotation() {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    let state = OAuthFixture {
        base: format!("http://{address}"),
        refreshes: Arc::new(AtomicUsize::new(0)),
        client_metadata: Arc::new(AtomicBool::new(false)),
    };
    let server = tokio::spawn(
        axum::serve(
            listener,
            Router::new()
                .route("/.well-known/oauth-protected-resource/mcp", get(resource))
                .route(
                    "/.well-known/oauth-authorization-server",
                    get(authorization_metadata),
                )
                .route("/register", post(dynamic_registration))
                .route("/token", post(refresh_token))
                .with_state(state.clone()),
        )
        .into_future(),
    );

    let directory = tempfile::tempdir().unwrap();
    let store: Arc<dyn ObjectStore> = Arc::new(InMemory::new());
    let lease = LeaseGuard::acquire(
        store.clone(),
        ObjectPath::from("lease"),
        Duration::from_secs(30),
    )
    .await
    .unwrap();
    let db_path = directory.path().join("cog.sqlite");
    let db = Database::open(&db_path).unwrap();
    let replicator = Arc::new(Replicator::new(
        store,
        "app/".into(),
        db_path,
        lease.generation(),
    ));
    replicator.sync().await.unwrap();
    let master_key = cog::crypto::random_token(32);
    let app = App {
        config: Config {
            listen: "127.0.0.1:0".parse().unwrap(),
            base_url: "http://localhost:4788".parse().unwrap(),
            data_dir: directory.path().to_path_buf(),
            s3_bucket: Some("test".into()),
            s3_prefix: "app/".into(),
            s3_endpoint: None,
            s3_region: "us-east-1".into(),
            s3_allow_http: true,
            master_key: master_key.clone(),
            lease_ttl_secs: 30,
            v8_heap_mb: 16,
            execution_timeout_secs: 1,
            allow_stdio: false,
            git_max_request_bytes: 1024 * 1024,
            git_max_response_bytes: 1024 * 1024,
            git_timeout_secs: 30,
            git_idle_timeout_secs: 10,
            git_max_streams: 4,
            git_max_streams_per_client: 2,
            ssh_listen: None,
            ssh_public_host: None,
            ssh_public_port: None,
            ssh_certificate_ttl_secs: 900,
            ssh_certificate_max_ttl_secs: 900,
            ssh_handshake_timeout_secs: 15,
            ssh_auth_timeout_secs: 15,
            ssh_channel_timeout_secs: 30,
            ssh_max_connections: 64,
            ssh_max_channels_per_connection: 1,
            server_local_callbacks: crate::config::ServerLocalCallbacks::Off,
        },
        db: db.clone(),
        secrets: SecretBox::new(master_key.as_bytes()),
        runtime: Arc::new(CodeRuntime::new(16, Duration::from_secs(1))),
        lease: Authority::S3(lease),
        replicator: Durability::S3(replicator),
        providers: Arc::new(tokio::sync::Mutex::new(HashMap::new())),
        metrics: Arc::new(Metrics::default()),
        mutations: Arc::new(tokio::sync::Mutex::new(())),
        auth_rate_limit: Arc::new(RateLimiter::default()),
        git_providers: Arc::new(tokio::sync::Mutex::new(HashMap::new())),
        git_streams: Arc::new(tokio::sync::Semaphore::new(4)),
        git_client_streams: Arc::new(ClientStreamLimiter::default()),
        ssh_keys: None,
        ssh_ready: Arc::new(AtomicBool::new(false)),
        ssh_connections: Arc::new(tokio::sync::Semaphore::new(64)),
        github_api_base: "https://api.github.com/".parse().unwrap(),
    };
    let user = db.create_user("owner@example.com", "hash").unwrap();
    let missing = auth_failure(&app, AuthFailure::Missing, "mcp");
    assert_eq!(missing.status(), StatusCode::UNAUTHORIZED);
    assert!(
        missing.headers()[http::header::WWW_AUTHENTICATE]
            .to_str()
            .unwrap()
            .contains("resource_metadata=")
    );
    db.register_client(
        "test-client",
        Some(&user),
        "test",
        &["http://localhost/callback".into()],
    )
    .unwrap();
    db.store_access_token(
        &token_hash("admin-token"),
        "test-client",
        &user,
        "admin",
        chrono::Utc::now().timestamp() + 60,
        None,
        None,
    )
    .unwrap();
    let mut auth_headers = HeaderMap::new();
    auth_headers.insert(
        http::header::AUTHORIZATION,
        "Bearer admin-token".parse().unwrap(),
    );
    assert_eq!(scoped_user(&app, &auth_headers, "mcp").unwrap(), user);
    let integration_id = db
        .create_integration(
            &user,
            "remote",
            "http",
            &json!({"url":format!("{}/mcp",state.base),"oauth":{}}),
            None,
        )
        .unwrap();
    let integration = db.integration(&integration_id, &user).unwrap().unwrap();
    let client = resolve_upstream_client(&app, &integration).await.unwrap();
    assert_eq!(client.client_id, "dynamic-client");
    assert_eq!(client.issuer.as_deref(), Some(state.base.as_str()));
    // Cloudflare's MCP metadata has this shape: PKCE endpoints, but no
    // scopes_supported. An unconfigured scope must remain absent rather
    // than silently becoming the invalid `mcp` scope.
    assert!(client.scope.is_empty());
    let expected_resource = format!("{}/mcp", state.base);
    assert_eq!(client.resource.as_deref(), Some(expected_resource.as_str()));
    assert_ne!(
        client.client_secret_ciphertext.as_deref(),
        Some("dynamic-secret")
    );
    state.client_metadata.store(true, Ordering::SeqCst);
    let metadata_integration_id = db
        .create_integration(
            &user,
            "remote metadata client",
            "http",
            &json!({"url":format!("{}/mcp",state.base),"oauth":{}}),
            None,
        )
        .unwrap();
    let metadata_integration = db
        .integration(&metadata_integration_id, &user)
        .unwrap()
        .unwrap();
    let metadata_client = resolve_upstream_client(&app, &metadata_integration)
        .await
        .unwrap();
    assert_eq!(
        metadata_client.client_id,
        "http://localhost:4788/.well-known/oauth-client"
    );
    assert!(metadata_client.client_secret_ciphertext.is_none());
    let start = upstream_oauth_start(
        State(app.clone()),
        Path(integration_id.clone()),
        auth_headers.clone(),
    )
    .await
    .into_response();
    assert_eq!(start.status(), StatusCode::OK);
    let start: Value =
        serde_json::from_slice(&start.into_body().collect().await.unwrap().to_bytes()).unwrap();
    let authorization_url = url::Url::parse(start["authorization_url"].as_str().unwrap()).unwrap();
    assert!(
        authorization_url
            .query_pairs()
            .all(|(name, _)| name != "scope")
    );
    let resources: Vec<_> = authorization_url
        .query_pairs()
        .filter(|(name, _)| name == "resource")
        .map(|(_, value)| value.into_owned())
        .collect();
    assert_eq!(resources, vec![format!("{}/mcp", state.base)]);

    db.put_upstream_oauth_token(
        &integration_id,
        &UpstreamOAuthToken {
            access_token_ciphertext: app.secrets.seal(b"expired-access").unwrap(),
            refresh_token_ciphertext: Some(app.secrets.seal(b"old-refresh").unwrap()),
            token_type: "Bearer".into(),
            scope: "mcp".into(),
            expires_at: Some(chrono::Utc::now().timestamp() - 1),
            refresh_expires_at: Some(chrono::Utc::now().timestamp() + 60),
        },
    )
    .unwrap();
    assert_eq!(
        upstream_authorization(&app, &integration_id)
            .await
            .unwrap()
            .as_deref(),
        Some("Bearer new-access")
    );
    assert_eq!(state.refreshes.load(Ordering::SeqCst), 1);
    let rotated = db.upstream_oauth_token(&integration_id).unwrap().unwrap();
    assert_eq!(
        open_secret_text(&app, &rotated.refresh_token_ciphertext.unwrap()).unwrap(),
        "new-refresh"
    );
    server.abort();
}

#[tokio::test]
async fn local_callback_rejects_non_literal_loopback_and_falls_back_only_before_writes() {
    for rejected in [
        "http://localhost:1234/cb?code=x&state=y",
        "http://127.0.0.2:1234/cb?code=x&state=y",
        "http://2130706433:1234/cb?code=x&state=y",
        "http://user@127.0.0.1:1234/cb?code=x&state=y",
        "http://127.0.0.1:1234/cb?code=x&state=y#fragment",
        "https://127.0.0.1:1234/cb?code=x&state=y",
    ] {
        assert_eq!(
            deliver_loopback_callback(&url::Url::parse(rejected).unwrap()).await,
            CallbackDelivery::NotSent
        );
    }
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    drop(listener);
    let refused = url::Url::parse(&format!(
        "http://{address}/callback?code=secret&state=opaque"
    ))
    .unwrap();
    assert_eq!(
        deliver_loopback_callback(&refused).await,
        CallbackDelivery::NotSent
    );
}

#[tokio::test]
async fn local_callback_sends_no_credentials_and_does_not_follow_redirects() {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    let receiver = tokio::spawn(async move {
        let (mut stream, _) = listener.accept().await.unwrap();
        let mut request = Vec::new();
        loop {
            let mut chunk = [0_u8; 512];
            let read = stream.read(&mut chunk).await.unwrap();
            if read == 0 {
                break;
            }
            request.extend_from_slice(&chunk[..read]);
            if request.windows(4).any(|window| window == b"\r\n\r\n") {
                break;
            }
        }
        stream
            .write_all(b"HTTP/1.1 204 No Content\r\nLocation: http://example.com/evil\r\nContent-Length: 999999\r\n\r\n")
            .await
            .unwrap();
        String::from_utf8(request).unwrap()
    });
    let callback = url::Url::parse(&format!(
        "http://{address}/callback?existing=1&code=secret&state=opaque"
    ))
    .unwrap();
    assert_eq!(
        deliver_loopback_callback(&callback).await,
        CallbackDelivery::Delivered
    );
    let request = receiver.await.unwrap();
    assert!(request.starts_with("GET /callback?existing=1&code=secret&state=opaque HTTP/1.1"));
    assert!(!request.to_ascii_lowercase().contains("authorization:"));
    assert!(!request.to_ascii_lowercase().contains("cookie:"));
}

#[tokio::test]
async fn local_callback_indeterminate_response_boundaries() {
    for response in [
        b"HTTP/1.1 500 Nope\r\nContent-Length: 0\r\n\r\n".to_vec(),
        b"not-http\r\n\r\n".to_vec(),
        vec![b'x'; 17 * 1024],
    ] {
        let listener = tokio::net::TcpListener::bind("[::1]:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let receiver = tokio::spawn(async move {
            let (mut stream, _) = listener.accept().await.unwrap();
            let mut request = [0_u8; 2048];
            let _ = stream.read(&mut request).await.unwrap();
            stream.write_all(&response).await.unwrap();
        });
        let callback =
            url::Url::parse(&format!("http://[::1]:{}/callback", address.port())).unwrap();
        assert_eq!(
            deliver_loopback_callback(&callback).await,
            CallbackDelivery::Indeterminate
        );
        receiver.await.unwrap();
    }
}

async fn route_test_app() -> (App, tempfile::TempDir) {
    let directory = tempfile::tempdir().unwrap();
    let store: Arc<dyn ObjectStore> = Arc::new(InMemory::new());
    let lease = LeaseGuard::acquire(
        store.clone(),
        ObjectPath::from("route-test-lease"),
        Duration::from_secs(30),
    )
    .await
    .unwrap();
    let db_path = directory.path().join("cog.sqlite");
    let db = Database::open(&db_path).unwrap();
    let replicator = Arc::new(Replicator::new(
        store,
        "routes/".into(),
        db_path,
        lease.generation(),
    ));
    replicator.sync().await.unwrap();
    let master_key = cog::crypto::random_token(32);
    (
        App {
            config: Config {
                listen: "127.0.0.1:0".parse().unwrap(),
                base_url: "http://localhost:4788".parse().unwrap(),
                data_dir: directory.path().to_path_buf(),
                s3_bucket: Some("test".into()),
                s3_prefix: "routes/".into(),
                s3_endpoint: None,
                s3_region: "us-east-1".into(),
                s3_allow_http: true,
                master_key: master_key.clone(),
                lease_ttl_secs: 30,
                v8_heap_mb: 16,
                execution_timeout_secs: 1,
                allow_stdio: false,
                git_max_request_bytes: 1024 * 1024,
                git_max_response_bytes: 1024 * 1024,
                git_timeout_secs: 30,
                git_idle_timeout_secs: 10,
                git_max_streams: 4,
                git_max_streams_per_client: 2,
                ssh_listen: None,
                ssh_public_host: None,
                ssh_public_port: None,
                ssh_certificate_ttl_secs: 900,
                ssh_certificate_max_ttl_secs: 900,
                ssh_handshake_timeout_secs: 15,
                ssh_auth_timeout_secs: 15,
                ssh_channel_timeout_secs: 30,
                ssh_max_connections: 64,
                ssh_max_channels_per_connection: 1,
                server_local_callbacks: crate::config::ServerLocalCallbacks::Off,
            },
            db,
            secrets: SecretBox::new(master_key.as_bytes()),
            runtime: Arc::new(CodeRuntime::new(16, Duration::from_secs(1))),
            lease: Authority::S3(lease),
            replicator: Durability::S3(replicator),
            providers: Arc::new(tokio::sync::Mutex::new(HashMap::new())),
            metrics: Arc::new(Metrics::default()),
            mutations: Arc::new(tokio::sync::Mutex::new(())),
            auth_rate_limit: Arc::new(RateLimiter::default()),
            git_providers: Arc::new(tokio::sync::Mutex::new(HashMap::new())),
            git_streams: Arc::new(tokio::sync::Semaphore::new(4)),
            git_client_streams: Arc::new(ClientStreamLimiter::default()),
            ssh_keys: None,
            ssh_ready: Arc::new(AtomicBool::new(false)),
            ssh_connections: Arc::new(tokio::sync::Semaphore::new(64)),
            github_api_base: "https://api.github.com/".parse().unwrap(),
        },
        directory,
    )
}

fn encoded_form(pairs: &[(&str, &str)]) -> String {
    let mut serializer = url::form_urlencoded::Serializer::new(String::new());
    serializer.extend_pairs(pairs.iter().copied());
    serializer.finish()
}

async fn response_json(response: axum::response::Response) -> Value {
    let bytes = response.into_body().collect().await.unwrap().to_bytes();
    serde_json::from_slice(&bytes).unwrap()
}

async fn response_text(response: axum::response::Response) -> String {
    String::from_utf8(
        response
            .into_body()
            .collect()
            .await
            .unwrap()
            .to_bytes()
            .to_vec(),
    )
    .unwrap()
}

#[tokio::test]
async fn github_manifest_setup_returns_browser_handoff_and_pending_repository_result() {
    let (app, _directory) = route_test_app().await;
    let user = app
        .db
        .create_user("github-manifest@example.com", "hash")
        .unwrap();
    let started = admin_github_app_setup_start(&app, &user, json!({"name":"GitHub"}))
        .await
        .unwrap();
    let integration = started["id"].as_str().unwrap();
    assert_eq!(started["status"], "manifest_pending");
    let browser_url = url::Url::parse(started["browserUrl"].as_str().unwrap()).unwrap();
    let response = build_router(app.clone())
        .oneshot(
            Request::builder()
                .uri(browser_url.path())
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    let page = response_text(response).await;
    assert!(page.contains("https://github.com/settings/apps/new"));
    assert!(page.contains("github/app/manifest/callback&quot;"));
    assert!(page.contains("settings/apps/new?state="));
    assert!(page.contains("github/app/installation/callback?state="));
    assert!(page.contains("&quot;contents&quot;:&quot;write&quot;"));
    assert!(page.contains("&quot;workflows&quot;:&quot;write&quot;"));
    assert!(!page.contains("&quot;hook_attributes&quot;"));
    assert!(!page.contains("privateKey"));

    let status = admin_github_app_setup_status(&app, &user, integration)
        .await
        .unwrap();
    assert_eq!(status["status"], "manifest_pending");
    assert_eq!(status["credentialsConfigured"], false);
    let control = GitControlProvider {
        app: app.clone(),
        auth: AuthContext {
            user,
            agent: "test-agent".into(),
            identity: "test-identity".into(),
            client: "manifest-client".into(),
            scopes: HashSet::from([format!("integration:{integration}")]),
            integrations: HashSet::from([integration.to_owned()]),
        },
    };
    let result = control
        .call(
            "repository_access",
            json!({"integrationId":integration,"repository":"asselstine/cog"}),
        )
        .await
        .unwrap();
    assert_eq!(result["error"], "github_app_installation_required");
    assert_eq!(result["action"], "completeGitHubSetupThenRetry");
}

#[tokio::test]
async fn ssh_certificate_status_reuses_existing_identity_and_certificate() {
    let (mut app, _directory) = route_test_app().await;
    app.config.ssh_listen = Some("127.0.0.1:0".parse().unwrap());
    app.config.ssh_public_host = Some("localhost".into());
    app.config.ssh_public_port = Some(2222);
    app.ssh_keys = Some(Arc::new(std::sync::RwLock::new(
        crate::git::ssh::KeySet::load_or_create(&app.db, &app.secrets).unwrap(),
    )));
    app.ssh_ready.store(true, Ordering::Release);

    let user = app
        .db
        .create_user("ssh-status@example.com", "hash")
        .unwrap();
    let client = "status-client";
    app.db
        .register_client(
            client,
            Some(&user),
            "status agent",
            &["http://localhost/callback".into()],
        )
        .unwrap();
    let agent = app.db.agent_for_client(client).unwrap().unwrap();
    let integration = app
        .db
        .create_integration(
            &user,
            "GitHub",
            "git",
            &json!({"kind":"git","provider":"github","host":"github.com"}),
            None,
        )
        .unwrap();
    let repository = app
        .db
        .upsert_git_repository(
            &user,
            &integration,
            &ResolvedRepository {
                provider_repository_id: "status-repository".into(),
                display_name: "owner/status-repository".into(),
                upstream_url: "https://github.com/owner/status-repository.git"
                    .parse()
                    .unwrap(),
                metadata: json!({}),
            },
        )
        .unwrap();
    let auth = AuthContext {
        user: user.clone(),
        agent: agent.id,
        identity: agent.identity_id,
        client: client.into(),
        scopes: HashSet::from([format!("integration:{integration}")]),
        integrations: HashSet::from([integration.clone()]),
    };
    app.db
        .set_git_grant(&user, &auth.client, &repository.id, "write")
        .unwrap();
    let control = GitControlProvider { app, auth };
    let tools = control.tools().await.unwrap();
    assert_eq!(tools.len(), 4);
    let repository_tool = tools
        .iter()
        .find(|tool| tool.name == "repository_access")
        .unwrap();
    assert_eq!(repository_tool.extra["annotations"]["readOnlyHint"], false);
    assert_eq!(repository_tool.extra["annotations"]["openWorldHint"], true);
    let renewal_tool = tools
        .iter()
        .find(|tool| tool.name == "renew_ssh_certificate")
        .unwrap();
    assert_eq!(renewal_tool.extra["annotations"]["readOnlyHint"], false);
    assert!(
        renewal_tool.input_schema["properties"]["publicKey"]["description"]
            .as_str()
            .unwrap()
            .contains("same")
    );
    for args in [
        json!({}),
        json!({"repositoryId":repository.id,"permission":"owner"}),
        json!({"repositoryId":"missing","permission":"read","publicKey":"bad"}),
    ] {
        assert!(control.call("ssh_certificate", args).await.is_err());
    }
    assert!(
        control
            .call("ssh_certificate_status", json!({}))
            .await
            .is_err()
    );
    assert!(control.call("unknown", json!({})).await.is_err());
    let identity = crate::git::ssh::generate_key().unwrap();
    let public_key = identity.public_key().to_openssh().unwrap();
    let issued = control
        .call(
            "ssh_certificate",
            json!({"repositoryId":repository.id,"publicKey":public_key,"permission":"write"}),
        )
        .await
        .unwrap();
    assert!(issued.get("privateKeyGeneration").is_none());
    assert_eq!(
        issued["sshOptions"]["certificateFile"],
        "path to the saved COG certificate"
    );

    let status = control
        .call(
            "ssh_certificate_status",
            json!({"repositoryId":repository.id,"publicKey":public_key,"certificate":issued["certificate"]}),
        )
        .await
        .unwrap();
    assert_eq!(status["valid"], true);
    assert_eq!(status["action"], "reuse");
    assert_eq!(status["permission"], "write");
    assert!(status["usableForSeconds"].as_i64().unwrap() > 0);

    let now = chrono::Utc::now().timestamp();
    let expired_binding = crate::git::ssh::Binding {
        version: 1,
        issuance_id: uuid::Uuid::new_v4().to_string(),
        user_id: control.auth.user.clone(),
        identity_id: control.auth.identity.clone(),
        agent_id: control.auth.agent.clone(),
        client_id: control.auth.client.clone(),
        integration_id: integration.clone(),
        repository_id: repository.id.clone(),
        permission: "write".into(),
        fingerprint: crate::git::ssh::fingerprint(
            &crate::git::ssh::parse_public_key(&public_key).unwrap(),
        ),
        issued_at: now - 1000,
        expires_at: now - 100,
    };
    let expired_certificate = {
        let keys = control.app.ssh_keys.as_ref().unwrap().read().unwrap();
        crate::git::ssh::sign(
            &keys.user_ca,
            &crate::git::ssh::parse_public_key(&public_key).unwrap(),
            &expired_binding,
            crate::git::ssh::stable_serial(&expired_binding.issuance_id),
        )
        .unwrap()
    };
    let renewed = control
        .call(
            "renew_ssh_certificate",
            json!({"repositoryId":repository.id,"publicKey":public_key,"previousCertificate":expired_certificate}),
        )
        .await
        .unwrap();
    assert_eq!(renewed["action"], "renewedExistingIdentity");
    assert_eq!(renewed["permission"], "write");
    assert_ne!(renewed["certificate"], issued["certificate"]);
    assert_eq!(
        renewed["authenticationFailureRecovery"]["prohibitedAction"],
        "generateOrReplaceSshIdentity"
    );

    let other_identity = crate::git::ssh::generate_key().unwrap();
    let invalid = control
        .call(
            "ssh_certificate_status",
            json!({"repositoryId":repository.id,"publicKey":other_identity.public_key().to_openssh().unwrap(),"certificate":issued["certificate"]}),
        )
        .await
        .unwrap();
    assert_eq!(invalid["valid"], false);
    assert_eq!(invalid["action"], "renewWithSamePublicKey");
    assert!(control
        .call(
            "renew_ssh_certificate",
            json!({"repositoryId":repository.id,"publicKey":other_identity.public_key().to_openssh().unwrap(),"previousCertificate":issued["certificate"]}),
        )
        .await
        .is_err());
    let mismatched = GitControlProvider {
        app: control.app.clone(),
        auth: AuthContext {
            agent: "different-agent".into(),
            ..control.auth.clone()
        },
    }
    .call(
        "ssh_certificate_status",
        json!({"repositoryId":repository.id,"publicKey":public_key,"certificate":issued["certificate"]}),
    )
    .await
    .unwrap();
    assert_eq!(mismatched["action"], "requestCertificateForSamePublicKey");
    let denied = GitControlProvider {
        app: control.app.clone(),
        auth: AuthContext {
            scopes: HashSet::new(),
            integrations: HashSet::new(),
            ..control.auth.clone()
        },
    };
    assert!(denied.call("ssh_certificate_status", json!({"repositoryId":repository.id,"publicKey":public_key,"certificate":issued["certificate"]})).await.unwrap_err().downcast_ref::<crate::authz::InsufficientScope>().is_some());
}

#[test]
fn consent_selection_is_least_privilege_and_cannot_add_scopes() {
    let mut selected = HashMap::new();
    selected.insert("scope_2".into(), "on".into());
    selected.insert("scope_99".into(), "on".into());
    assert_eq!(
        selected_scopes("mcp integrations:read integrations:write", &selected),
        "mcp integrations:write"
    );
    assert_eq!(selected_scopes("mcp admin", &HashMap::new()), "mcp");
    assert_eq!(permission_copy("custom:scope", None).0, "custom:scope");
}

#[test]
fn progressive_consent_preserves_prior_grants_and_adds_selected_integration() {
    let requested = "mcp audit:read integration:cloudflare";
    let fields = HashMap::from([
        ("scope_1".to_owned(), "on".to_owned()),
        ("scope_2".to_owned(), "on".to_owned()),
    ]);
    assert_eq!(
        selected_scopes(requested, &fields),
        "mcp audit:read integration:cloudflare"
    );
}

#[tokio::test]
async fn consent_get_and_post_validation_matrix() {
    let (app, _directory) = route_test_app().await;
    let user = app
        .db
        .create_user("consent-matrix@example.com", "hash")
        .unwrap();
    let other = app
        .db
        .create_user("consent-other@example.com", "hash")
        .unwrap();
    app.db
        .register_client(
            "consent-client",
            None,
            "Consent Client",
            &["http://localhost/callback".into()],
        )
        .unwrap();
    let session = "consent-session";
    let csrf = "consent-csrf";
    app.db
        .create_session(
            &token_hash(session),
            &user,
            &token_hash(csrf),
            chrono::Utc::now().timestamp() + 600,
        )
        .unwrap();
    let mut headers = HeaderMap::new();
    headers.insert(
        http::header::COOKIE,
        format!("cog_session={session}; cog_csrf={csrf}")
            .parse()
            .unwrap(),
    );
    headers.insert(
        http::header::ORIGIN,
        "http://localhost:4788".parse().unwrap(),
    );
    let valid = || Authorize {
        response_type: response_code(),
        client_id: "consent-client".into(),
        redirect_uri: "http://localhost/callback".into(),
        state: "state".into(),
        code_challenge: "challenge".into(),
        code_challenge_method: challenge_s256(),
        scope: scope_mcp(),
        resource: "http://localhost:4788/mcp".into(),
    };
    let mut wrong = valid();
    wrong.response_type = "token".into();
    assert_eq!(
        authorize_consent(State(app.clone()), headers.clone(), Query(wrong))
            .await
            .into_response()
            .status(),
        StatusCode::BAD_REQUEST
    );
    let mut wrong = valid();
    wrong.resource = "https://other.example/mcp".into();
    assert_eq!(
        authorize_consent(State(app.clone()), headers.clone(), Query(wrong))
            .await
            .into_response()
            .status(),
        StatusCode::BAD_REQUEST
    );
    let mut wrong = valid();
    wrong.client_id = "missing".into();
    assert_eq!(
        authorize_consent(State(app.clone()), headers.clone(), Query(wrong))
            .await
            .into_response()
            .status(),
        StatusCode::BAD_REQUEST
    );
    let mut wrong = valid();
    wrong.redirect_uri = "http://localhost/other".into();
    assert_eq!(
        authorize_consent(State(app.clone()), headers.clone(), Query(wrong))
            .await
            .into_response()
            .status(),
        StatusCode::BAD_REQUEST
    );
    assert_eq!(
        authorize_consent(State(app.clone()), HeaderMap::new(), Query(valid()))
            .await
            .into_response()
            .status(),
        StatusCode::UNAUTHORIZED
    );
    let mut no_csrf = headers.clone();
    no_csrf.insert(
        http::header::COOKIE,
        format!("cog_session={session}").parse().unwrap(),
    );
    assert_eq!(
        authorize_consent(State(app.clone()), no_csrf, Query(valid()))
            .await
            .into_response()
            .status(),
        StatusCode::FORBIDDEN
    );
    let mut empty = valid();
    empty.scope.clear();
    assert_eq!(
        authorize_consent(State(app.clone()), headers.clone(), Query(empty))
            .await
            .into_response()
            .status(),
        StatusCode::BAD_REQUEST
    );
    let consent = ConsentRequest {
        response_type: "code".into(),
        client_id: "consent-client".into(),
        redirect_uri: "http://localhost/callback".into(),
        state: "state".into(),
        code_challenge: "challenge".into(),
        code_challenge_method: "S256".into(),
        requested_scope: "mcp integrations:read".into(),
        resource: "http://localhost:4788/mcp".into(),
        user: user.clone(),
        allowed_identity_ids: Vec::new(),
        fixed_identity_id: None,
        expires_at: chrono::Utc::now().timestamp() + 600,
        git_pending_ids: Vec::new(),
    };
    let seal = |consent: &ConsentRequest| {
        app.secrets
            .seal(&serde_json::to_vec(consent).unwrap())
            .unwrap()
    };
    let form = |sealed: String, decision: &str, fields: HashMap<String, String>| ConsentForm {
        consent: sealed,
        csrf_token: csrf.into(),
        decision: decision.into(),
        fields,
    };
    assert_eq!(
        authorize_post(
            State(app.clone()),
            headers.clone(),
            Form(form("invalid".into(), "allow", HashMap::new()))
        )
        .await
        .into_response()
        .status(),
        StatusCode::BAD_REQUEST
    );
    let mut expired = ConsentRequest { ..consent };
    expired.expires_at = 0;
    assert_eq!(
        authorize_post(
            State(app.clone()),
            headers.clone(),
            Form(form(seal(&expired), "allow", HashMap::new()))
        )
        .await
        .into_response()
        .status(),
        StatusCode::BAD_REQUEST
    );
    expired.expires_at = chrono::Utc::now().timestamp() + 600;
    let mut bad_origin = headers.clone();
    bad_origin.insert(
        http::header::ORIGIN,
        "https://evil.example".parse().unwrap(),
    );
    assert_eq!(
        authorize_post(
            State(app.clone()),
            bad_origin,
            Form(form(seal(&expired), "allow", HashMap::new()))
        )
        .await
        .into_response()
        .status(),
        StatusCode::FORBIDDEN
    );
    let mut wrong_csrf = form(seal(&expired), "allow", HashMap::new());
    wrong_csrf.csrf_token = "wrong".into();
    assert_eq!(
        authorize_post(State(app.clone()), headers.clone(), Form(wrong_csrf))
            .await
            .into_response()
            .status(),
        StatusCode::UNAUTHORIZED
    );
    expired.user = other;
    assert_eq!(
        authorize_post(
            State(app.clone()),
            headers.clone(),
            Form(form(seal(&expired), "allow", HashMap::new()))
        )
        .await
        .into_response()
        .status(),
        StatusCode::FORBIDDEN
    );
    expired.user = user;
    assert_eq!(
        authorize_post(
            State(app.clone()),
            headers.clone(),
            Form(form(seal(&expired), "maybe", HashMap::new()))
        )
        .await
        .into_response()
        .status(),
        StatusCode::BAD_REQUEST
    );
    assert_eq!(
        authorize_post(
            State(app.clone()),
            headers.clone(),
            Form(form(seal(&expired), "allow", HashMap::new()))
        )
        .await
        .into_response()
        .status(),
        StatusCode::BAD_REQUEST
    );
    let mut unavailable = HashMap::new();
    unavailable.insert("identity_id".into(), "missing".into());
    assert_eq!(
        authorize_post(
            State(app.clone()),
            headers,
            Form(form(seal(&expired), "allow", unavailable))
        )
        .await
        .into_response()
        .status(),
        StatusCode::FORBIDDEN
    );
}

#[tokio::test]
async fn mcp_http_origin_version_and_incremental_scope_boundaries() {
    let (app, _directory) = route_test_app().await;
    let user = app
        .db
        .create_user("mcp-boundary@example.com", "hash")
        .unwrap();
    app.db
        .register_client(
            "mcp-boundary",
            Some(&user),
            "MCP",
            &["http://localhost/callback".into()],
        )
        .unwrap();
    app.db
        .store_access_token(
            &token_hash("mcp-boundary-token"),
            "mcp-boundary",
            &user,
            "mcp",
            chrono::Utc::now().timestamp() + 600,
            None,
            None,
        )
        .unwrap();
    let integration = app
        .db
        .create_integration(
            &user,
            "Fixture",
            "http",
            &json!({"url":"http://localhost:9999/mcp"}),
            None,
        )
        .unwrap();
    let router = build_router(app);
    let rpc = |body: Value| {
        Request::post("/mcp")
            .header(http::header::AUTHORIZATION, "Bearer mcp-boundary-token")
            .header(http::header::CONTENT_TYPE, "application/json")
            .body(Body::from(body.to_string()))
            .unwrap()
    };
    let mut request = rpc(json!({"jsonrpc":"2.0","id":1,"method":"ping"}));
    request.headers_mut().insert(
        http::header::ORIGIN,
        "https://evil.example".parse().unwrap(),
    );
    assert_eq!(
        router.clone().oneshot(request).await.unwrap().status(),
        StatusCode::FORBIDDEN
    );
    let mut request = rpc(json!({"jsonrpc":"2.0","id":1,"method":"ping"}));
    request
        .headers_mut()
        .insert("MCP-Protocol-Version", "1900-01-01".parse().unwrap());
    assert_eq!(
        router.clone().oneshot(request).await.unwrap().status(),
        StatusCode::BAD_REQUEST
    );
    let response = router.clone().oneshot(Request::post("/mcp?codemode=false").header(http::header::AUTHORIZATION, "Bearer mcp-boundary-token").header(http::header::CONTENT_TYPE, "application/json").body(Body::from(json!({"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"cog_integration_create","arguments":{}}}).to_string())).unwrap()).await.unwrap();
    assert_eq!(response.status(), StatusCode::FORBIDDEN);
    assert!(
        response
            .headers()
            .contains_key(http::header::WWW_AUTHENTICATE)
    );
    let response = router.clone().oneshot(rpc(json!({"jsonrpc":"2.0","id":2,"method":"tools/call","params":{"name":"execute","arguments":{"code":format!("return codemode.describe('{integration}.tool');")}}}))).await.unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    let response = router.oneshot(rpc(json!({"jsonrpc":"2.0","id":3,"method":"tools/call","params":{"name":"execute","arguments":{"code":"return undefined;"}}}))).await.unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    assert_eq!(response_json(response).await["result"]["isError"], true);
}

#[tokio::test]
async fn route_flow_covers_metadata_consent_tokens_mcp_and_admin_scopes() {
    let (mut app, _directory) = route_test_app().await;
    app.config.allow_stdio = true;
    let salt = SaltString::generate(&mut OsRng);
    let hash = Argon2::default()
        .hash_password(b"long-test-password", &salt)
        .unwrap()
        .to_string();
    let owner = app.db.create_user("owner@example.com", &hash).unwrap();
    let integration = app
        .db
        .create_integration(
            &owner,
            "metadata fixture",
            "stdio",
            &json!({
                "command":"sh",
                "args":[format!("{}/tests/fixtures/stdio-mcp.sh", env!("CARGO_MANIFEST_DIR"))]
            }),
            None,
        )
        .unwrap();
    let router = build_router(app.clone());
    let origin = "http://localhost:4788";

    for path in [
        "/.well-known/oauth-authorization-server",
        "/.well-known/oauth-protected-resource",
        "/.well-known/oauth-client",
    ] {
        let response = router
            .clone()
            .oneshot(
                axum::http::Request::get(path)
                    .body(axum::body::Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        let metadata = response_json(response).await;
        assert!(metadata.is_object());
        if path == "/.well-known/oauth-protected-resource" {
            assert_eq!(
                metadata["scopes_supported"],
                json!(["mcp", "git:read", "git:write"])
            );
        } else if path == "/.well-known/oauth-client" {
            assert_eq!(
                metadata["client_id"],
                "http://localhost:4788/.well-known/oauth-client"
            );
            assert_eq!(
                metadata["redirect_uris"],
                json!(["http://localhost:4788/oauth/upstream/callback"])
            );
        }
    }

    let registration = router
        .clone()
        .oneshot(
            axum::http::Request::post("/oauth/register")
                .header(http::header::CONTENT_TYPE, "application/json")
                .body(axum::body::Body::from(
                    json!({"client_name":"route fixture","redirect_uris":["http://localhost/callback"]}).to_string(),
                ))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(registration.status(), StatusCode::CREATED);
    let client_id = response_json(registration).await["client_id"]
        .as_str()
        .unwrap()
        .to_owned();
    let oauth_repository = app
        .db
        .upsert_git_repository(
            &owner,
            &integration,
            &ResolvedRepository {
                provider_repository_id: "oauth-repository".into(),
                display_name: "owner/oauth-repository".into(),
                upstream_url: "https://github.com/owner/oauth-repository.git"
                    .parse()
                    .unwrap(),
                metadata: json!({}),
            },
        )
        .unwrap();
    let identity = app.db.list_identities(&owner).unwrap()[0].id.clone();
    app.db.bind_agent(&owner, &identity, &client_id).unwrap();
    app.db
        .create_git_pending_request(
            &owner,
            &client_id,
            &integration,
            &oauth_repository.id,
            "read",
            600,
        )
        .unwrap();

    let login_response = router
        .clone()
        .oneshot(
            axum::http::Request::post("/login")
                .header(http::header::ORIGIN, origin)
                .header(
                    http::header::CONTENT_TYPE,
                    "application/x-www-form-urlencoded",
                )
                .body(axum::body::Body::from(encoded_form(&[
                    ("email", "owner@example.com"),
                    ("password", "long-test-password"),
                ])))
                .unwrap(),
        )
        .await
        .unwrap();
    assert!(login_response.status().is_redirection());
    let cookies = login_response
        .headers()
        .get_all(http::header::SET_COOKIE)
        .iter()
        .map(|value| {
            value
                .to_str()
                .unwrap()
                .split(';')
                .next()
                .unwrap()
                .to_owned()
        })
        .collect::<Vec<_>>();
    assert_eq!(cookies.len(), 2);
    let cookie_header = cookies.join("; ");
    let csrf = cookies
        .iter()
        .find_map(|cookie| cookie.strip_prefix("cog_csrf="))
        .unwrap()
        .to_owned();
    let verifier = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789-._~";
    use base64::Engine;
    use sha2::Digest;
    let challenge = base64::engine::general_purpose::URL_SAFE_NO_PAD
        .encode(sha2::Sha256::digest(verifier.as_bytes()));
    let query = encoded_form(&[
        ("response_type", "code"),
        ("client_id", &client_id),
        ("redirect_uri", "http://localhost/callback"),
        ("state", "route-state"),
        ("code_challenge", &challenge),
        ("code_challenge_method", "S256"),
        ("scope", "mcp admin git:read"),
        ("resource", "http://localhost:4788/mcp"),
    ]);
    let consent = router
        .clone()
        .oneshot(
            axum::http::Request::get(format!("/oauth/authorize?{query}"))
                .header(http::header::COOKIE, &cookie_header)
                .body(axum::body::Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(consent.status(), StatusCode::OK);
    let consent_page = response_text(consent).await;
    assert!(consent_page.starts_with("<!doctype html>"));
    assert!(!consent_page.contains("Any grant change affects every agent"));
    let consent = router
        .clone()
        .oneshot(
            axum::http::Request::get(format!("/api/oauth/consent?{query}"))
                .header(http::header::COOKIE, &cookie_header)
                .body(axum::body::Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(consent.status(), StatusCode::OK);
    assert_eq!(consent.headers()[http::header::CACHE_CONTROL], "no-store");
    let consent_data = response_json(consent).await;
    assert_eq!(consent_data["client"]["name"], "route fixture");
    assert_eq!(
        consent_data["permissionGroups"][0]["title"],
        "Newly requested"
    );
    assert!(
        consent_data["permissionGroups"]
            .as_array()
            .unwrap()
            .iter()
            .any(|group| group["title"] == "Other available permissions")
    );
    assert!(
        consent_data["permissionGroups"]
            .as_array()
            .unwrap()
            .iter()
            .flat_map(|group| group["permissions"].as_array().unwrap())
            .any(|permission| permission["label"] == "Legacy administrator access")
    );
    let sealed_consent = consent_data["consent"].as_str().unwrap().to_owned();

    let mut tampered = sealed_consent.clone().into_bytes();
    let middle = tampered.len() / 2;
    tampered[middle] = if tampered[middle] == b'A' { b'B' } else { b'A' };
    let tampered = String::from_utf8(tampered).unwrap();
    let rejected = router
        .clone()
        .oneshot(
            axum::http::Request::post("/api/oauth/consent")
                .header(http::header::ORIGIN, origin)
                .header(http::header::COOKIE, &cookie_header)
                .header(
                    http::header::CONTENT_TYPE,
                    "application/x-www-form-urlencoded",
                )
                .body(axum::body::Body::from(encoded_form(&[
                    ("consent", &tampered),
                    ("csrf_token", &csrf),
                    ("decision", "allow"),
                    ("scope_99", "on"),
                ])))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(rejected.status(), StatusCode::BAD_REQUEST);

    let authorization = router
        .clone()
        .oneshot(
            axum::http::Request::post("/api/oauth/consent")
                .header(http::header::ORIGIN, origin)
                .header(http::header::COOKIE, &cookie_header)
                .header(
                    http::header::CONTENT_TYPE,
                    "application/x-www-form-urlencoded",
                )
                .body(axum::body::Body::from(encoded_form(&[
                    ("consent", &sealed_consent),
                    ("csrf_token", &csrf),
                    ("decision", "allow"),
                    ("scope_1", "on"),
                    ("scope_2", "on"),
                    ("git_request_0", "on"),
                ])))
                .unwrap(),
        )
        .await
        .unwrap();
    assert!(authorization.status().is_redirection());
    let location = authorization.headers()[http::header::LOCATION]
        .to_str()
        .unwrap();
    let code = url::Url::parse(location)
        .unwrap()
        .query_pairs()
        .find_map(|(key, value)| (key == "code").then(|| value.into_owned()))
        .unwrap();
    let token_response = router
        .clone()
        .oneshot(
            axum::http::Request::post("/oauth/token")
                .header(
                    http::header::CONTENT_TYPE,
                    "application/x-www-form-urlencoded",
                )
                .body(axum::body::Body::from(encoded_form(&[
                    ("grant_type", "authorization_code"),
                    ("code", &code),
                    ("client_id", &client_id),
                    ("redirect_uri", "http://localhost/callback"),
                    ("code_verifier", verifier),
                    ("resource", "http://localhost:4788/mcp"),
                ])))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(token_response.status(), StatusCode::OK);
    let access = response_json(token_response).await["access_token"]
        .as_str()
        .unwrap()
        .to_owned();
    assert_eq!(
        app.db
            .git_grant_permission(&owner, &client_id, &oauth_repository.id)
            .unwrap()
            .as_deref(),
        Some("read")
    );
    let access_context = app
        .db
        .token_context(&token_hash(&access), chrono::Utc::now().timestamp())
        .unwrap()
        .unwrap();
    assert!(
        access_context
            .scopes
            .iter()
            .any(|scope| scope == "git:read")
    );

    let unauthenticated = router
        .clone()
        .oneshot(
            axum::http::Request::post("/mcp")
                .header(http::header::CONTENT_TYPE, "application/json")
                .body(axum::body::Body::from(
                    json!({"jsonrpc":"2.0","id":1,"method":"ping"}).to_string(),
                ))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(unauthenticated.status(), StatusCode::UNAUTHORIZED);
    assert!(
        unauthenticated.headers()[http::header::WWW_AUTHENTICATE]
            .to_str()
            .unwrap()
            .contains("scope=\"mcp\"")
    );

    let mcp = router
        .clone()
        .oneshot(
            axum::http::Request::post("/mcp")
                .header(http::header::AUTHORIZATION, format!("Bearer {access}"))
                .header(http::header::CONTENT_TYPE, "application/json")
                .body(axum::body::Body::from(
                    json!({"jsonrpc":"2.0","id":2,"method":"tools/list"}).to_string(),
                ))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(mcp.status(), StatusCode::OK);
    let code_mode_tools = response_json(mcp).await["result"]["tools"]
        .as_array()
        .unwrap()
        .clone();
    assert!(code_mode_tools.iter().any(|tool| tool["name"] == "execute"));

    assert!(
        code_mode_tools
            .iter()
            .any(|tool| tool["name"] == "repository_access")
    );
    assert!(
        !code_mode_tools
            .iter()
            .any(|tool| tool["name"] == format!("{integration}.echo"))
    );

    let code_mode_only = router
        .clone()
        .oneshot(
            axum::http::Request::post("/mcp?codemode=true")
                .header(http::header::AUTHORIZATION, format!("Bearer {access}"))
                .header(http::header::CONTENT_TYPE, "application/json")
                .body(axum::body::Body::from(
                    json!({"jsonrpc":"2.0","id":21,"method":"tools/list"}).to_string(),
                ))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(code_mode_only.status(), StatusCode::OK);
    let code_mode_only_tools = response_json(code_mode_only).await["result"]["tools"]
        .as_array()
        .unwrap()
        .clone();
    assert_eq!(code_mode_only_tools.len(), 1);
    assert_eq!(code_mode_only_tools[0]["name"], "execute");

    let malformed_mode = router
        .clone()
        .oneshot(
            axum::http::Request::post("/mcp?codemode=maybe")
                .header(http::header::AUTHORIZATION, format!("Bearer {access}"))
                .header(http::header::CONTENT_TYPE, "application/json")
                .body(axum::body::Body::from(
                    json!({"jsonrpc":"2.0","id":22,"method":"ping"}).to_string(),
                ))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(malformed_mode.status(), StatusCode::BAD_REQUEST);

    for (header, expected) in [
        (
            ("MCP-Protocol-Version", "2024-11-05"),
            StatusCode::BAD_REQUEST,
        ),
        (
            (http::header::ORIGIN.as_str(), "https://evil.example"),
            StatusCode::FORBIDDEN,
        ),
    ] {
        let rejected = router
            .clone()
            .oneshot(
                axum::http::Request::post("/mcp")
                    .header(http::header::AUTHORIZATION, format!("Bearer {access}"))
                    .header(http::header::CONTENT_TYPE, "application/json")
                    .header(header.0, header.1)
                    .body(axum::body::Body::from(
                        json!({"jsonrpc":"2.0","id":20,"method":"ping"}).to_string(),
                    ))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(rejected.status(), expected);
    }

    app.db
        .store_access_token(
            &token_hash("step-up-token"),
            &client_id,
            &owner,
            "mcp integrations:read",
            chrono::Utc::now().timestamp() + 60,
            None,
            None,
        )
        .unwrap();
    let hidden_integration_call = router
        .clone()
        .oneshot(
            axum::http::Request::post("/mcp?codemode=false")
                .header(http::header::AUTHORIZATION, "Bearer step-up-token")
                .header(http::header::CONTENT_TYPE, "application/json")
                .body(axum::body::Body::from(
                    json!({
                        "jsonrpc":"2.0",
                        "id":24,
                        "method":"tools/call",
                        "params":{
                            "name":format!("{integration}.echo"),
                            "arguments":{}
                        }
                    })
                    .to_string(),
                ))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(hidden_integration_call.status(), StatusCode::OK);
    let hidden_integration_call = response_json(hidden_integration_call).await;
    assert!(
        hidden_integration_call["error"]["message"]
            .as_str()
            .unwrap()
            .contains("unknown tool")
    );
    let step_up = router
        .clone()
        .oneshot(
            axum::http::Request::post("/mcp")
                .header(http::header::AUTHORIZATION, "Bearer step-up-token")
                .header(http::header::CONTENT_TYPE, "application/json")
                .body(axum::body::Body::from(
                    json!({
                        "jsonrpc":"2.0",
                        "id":3,
                        "method":"tools/call",
                        "params":{
                            "name":"execute",
                            "arguments":{
                                "code":format!("return codemode.describe('{integration}.tool');")
                            }
                        }
                    })
                    .to_string(),
                ))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(step_up.status(), StatusCode::OK);
    let step_up = response_json(step_up).await;
    assert_ne!(step_up["result"]["isError"], true);

    // A capable MCP client accumulates its existing scopes with the scope
    // from the 403 challenge, performs a fresh authorization-code flow,
    // and retries the exact operation with the widened token.
    let elevated_scope = format!("mcp integrations:read integration:{integration}");
    let elevated_query = encoded_form(&[
        ("response_type", "code"),
        ("client_id", &client_id),
        ("redirect_uri", "http://localhost/callback"),
        ("state", "step-up-state"),
        ("code_challenge", &challenge),
        ("code_challenge_method", "S256"),
        ("scope", &elevated_scope),
        ("resource", "http://localhost:4788/mcp"),
    ]);
    let elevated_consent = router
        .clone()
        .oneshot(
            axum::http::Request::get(format!("/api/oauth/consent?{elevated_query}"))
                .header(http::header::COOKIE, &cookie_header)
                .body(axum::body::Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(elevated_consent.status(), StatusCode::OK);
    let elevated_data = response_json(elevated_consent).await;
    let groups = elevated_data["permissionGroups"].as_array().unwrap();
    assert_eq!(groups[0]["title"], "Newly requested");
    assert_eq!(groups[1]["title"], "Previously approved");
    assert_eq!(groups[2]["title"], "Other available permissions");
    assert!(
        groups
            .iter()
            .flat_map(|group| group["permissions"].as_array().unwrap())
            .any(|permission| permission["label"] == "Use metadata fixture")
    );
    assert!(
        groups
            .iter()
            .flat_map(|group| group["permissions"].as_array().unwrap())
            .any(|permission| permission["field"] == "scope_1" && permission["checked"] == true)
    );
    assert!(
        groups
            .iter()
            .flat_map(|group| group["permissions"].as_array().unwrap())
            .any(|permission| permission["field"] == "scope_2" && permission["checked"] == true)
    );
    let elevated_consent = elevated_data["consent"].as_str().unwrap().to_owned();
    let elevated_authorization = router
        .clone()
        .oneshot(
            axum::http::Request::post("/api/oauth/consent")
                .header(http::header::ORIGIN, origin)
                .header(http::header::COOKIE, &cookie_header)
                .header(
                    http::header::CONTENT_TYPE,
                    "application/x-www-form-urlencoded",
                )
                .body(axum::body::Body::from(encoded_form(&[
                    ("consent", &elevated_consent),
                    ("csrf_token", &csrf),
                    ("decision", "allow"),
                    ("scope_1", "on"),
                    ("scope_2", "on"),
                ])))
                .unwrap(),
        )
        .await
        .unwrap();
    assert!(elevated_authorization.status().is_redirection());
    let elevated_code = url::Url::parse(
        elevated_authorization.headers()[http::header::LOCATION]
            .to_str()
            .unwrap(),
    )
    .unwrap()
    .query_pairs()
    .find_map(|(key, value)| (key == "code").then(|| value.into_owned()))
    .unwrap();
    let elevated_token = router
        .clone()
        .oneshot(
            axum::http::Request::post("/oauth/token")
                .header(
                    http::header::CONTENT_TYPE,
                    "application/x-www-form-urlencoded",
                )
                .body(axum::body::Body::from(encoded_form(&[
                    ("grant_type", "authorization_code"),
                    ("code", &elevated_code),
                    ("client_id", &client_id),
                    ("redirect_uri", "http://localhost/callback"),
                    ("code_verifier", verifier),
                    ("resource", "http://localhost:4788/mcp"),
                ])))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(elevated_token.status(), StatusCode::OK);
    let elevated_access = response_json(elevated_token).await["access_token"]
        .as_str()
        .unwrap()
        .to_owned();
    let retried = router
        .clone()
        .oneshot(
            axum::http::Request::post("/mcp")
                .header(
                    http::header::AUTHORIZATION,
                    format!("Bearer {elevated_access}"),
                )
                .header(http::header::CONTENT_TYPE, "application/json")
                .body(axum::body::Body::from(
                    json!({
                        "jsonrpc":"2.0",
                        "id":3,
                        "method":"tools/call",
                        "params":{
                            "name":"execute",
                            "arguments":{
                                "code":format!("return codemode.describe('{integration}.echo');")
                            }
                        }
                    })
                    .to_string(),
                ))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(retried.status(), StatusCode::OK);
    let retried = response_json(retried).await;
    assert_ne!(retried["result"]["isError"], true);
    assert_eq!(retried["result"]["structuredContent"]["name"], "echo");

    let hidden_elevated_integration_call = router
        .clone()
        .oneshot(
            axum::http::Request::post("/mcp?codemode=false")
                .header(
                    http::header::AUTHORIZATION,
                    format!("Bearer {elevated_access}"),
                )
                .header(http::header::CONTENT_TYPE, "application/json")
                .body(axum::body::Body::from(
                    json!({
                        "jsonrpc":"2.0",
                        "id":23,
                        "method":"tools/call",
                        "params":{
                            "name":format!("{integration}.echo"),
                            "arguments":{"message":"direct"}
                        }
                    })
                    .to_string(),
                ))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(hidden_elevated_integration_call.status(), StatusCode::OK);
    let hidden_elevated_integration_call = response_json(hidden_elevated_integration_call).await;
    assert!(
        hidden_elevated_integration_call["error"]["message"]
            .as_str()
            .unwrap()
            .contains("unknown tool")
    );

    let dynamic_step_up = router
        .clone()
        .oneshot(
            axum::http::Request::post("/mcp")
                .header(http::header::AUTHORIZATION, "Bearer step-up-token")
                .header(http::header::CONTENT_TYPE, "application/json")
                .body(axum::body::Body::from(
                    json!({
                        "jsonrpc":"2.0",
                        "id":4,
                        "method":"tools/call",
                        "params":{
                            "name":"execute",
                            "arguments":{
                                "code":"const matches = codemode.search('metadata fixture'); return codemode.describe(matches[0].integration + '.tool');"
                            }
                        }
                    })
                    .to_string(),
                ))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(dynamic_step_up.status(), StatusCode::OK);
    let dynamic_step_up = response_json(dynamic_step_up).await;
    assert_ne!(dynamic_step_up["result"]["isError"], true);
    let admin_step_up = router
        .clone()
        .oneshot(
            axum::http::Request::post("/mcp")
                .header(http::header::AUTHORIZATION, "Bearer step-up-token")
                .header(http::header::CONTENT_TYPE, "application/json")
                .body(axum::body::Body::from(
                    json!({"jsonrpc":"2.0","id":5,"method":"tools/call","params":{"name":"cog_integration_create","arguments":{}}}).to_string(),
                ))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(admin_step_up.status(), StatusCode::OK);
    let admin_step_up = response_json(admin_step_up).await;
    assert!(admin_step_up.get("error").is_some() || admin_step_up["result"]["isError"] == true);

    // rmcp/Codex sends this as a JSON-RPC notification immediately after
    // initialize. Streamable HTTP requires an empty acknowledgement, not
    // a response with a missing or null id.
    let initialized = router
        .clone()
        .oneshot(
            axum::http::Request::post("/mcp")
                .header(http::header::AUTHORIZATION, format!("Bearer {access}"))
                .header(http::header::CONTENT_TYPE, "application/json")
                .body(axum::body::Body::from(
                    json!({"jsonrpc":"2.0","method":"notifications/initialized"}).to_string(),
                ))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(initialized.status(), StatusCode::ACCEPTED);
    assert!(
        initialized
            .into_body()
            .collect()
            .await
            .unwrap()
            .to_bytes()
            .is_empty()
    );

    let admin = router
        .clone()
        .oneshot(
            axum::http::Request::get("/api/integrations")
                .header(http::header::AUTHORIZATION, format!("Bearer {access}"))
                .body(axum::body::Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(admin.status(), StatusCode::OK);

    for path in ["/", "/healthz", "/readyz", "/version", "/metrics", "/login"] {
        let response = router
            .clone()
            .oneshot(
                axum::http::Request::get(path)
                    .header(http::header::COOKIE, &cookie_header)
                    .body(axum::body::Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK, "{path}");
    }

    let created = router
        .clone()
        .oneshot(
            axum::http::Request::post("/api/integrations")
                .header(http::header::AUTHORIZATION, format!("Bearer {access}"))
                .header(http::header::CONTENT_TYPE, "application/json")
                .body(axum::body::Body::from(
                    json!({"name":"fixture","transport":"http","config":{"url":"http://localhost:9999/mcp"}}).to_string(),
                ))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(created.status(), StatusCode::CREATED);
    let integration_id = response_json(created).await["id"]
        .as_str()
        .unwrap()
        .to_owned();

    let inspected = router
        .clone()
        .oneshot(
            axum::http::Request::get(format!("/api/integrations/{integration_id}"))
                .header(http::header::AUTHORIZATION, format!("Bearer {access}"))
                .body(axum::body::Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(inspected.status(), StatusCode::OK);
    assert_eq!(response_json(inspected).await["name"], "fixture");

    let updated = router
        .clone()
        .oneshot(
            axum::http::Request::patch(format!("/api/integrations/{integration_id}"))
                .header(http::header::AUTHORIZATION, format!("Bearer {access}"))
                .header(http::header::CONTENT_TYPE, "application/json")
                .body(axum::body::Body::from(
                    json!({"name":"renamed","enabled":false}).to_string(),
                ))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(updated.status(), StatusCode::NO_CONTENT);

    let reconnected = router
        .clone()
        .oneshot(
            axum::http::Request::post(format!("/api/integrations/{integration_id}/reconnect"))
                .header(http::header::AUTHORIZATION, format!("Bearer {access}"))
                .body(axum::body::Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(reconnected.status(), StatusCode::NO_CONTENT);

    for path in ["/api/clients", "/api/tokens", "/api/audit"] {
        let response = router
            .clone()
            .oneshot(
                axum::http::Request::get(path)
                    .header(http::header::AUTHORIZATION, format!("Bearer {access}"))
                    .body(axum::body::Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK, "{path}");
        assert!(response_json(response).await.is_array());
    }

    let ui = router
        .clone()
        .oneshot(
            axum::http::Request::get("/ui")
                .header(http::header::COOKIE, &cookie_header)
                .body(axum::body::Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(ui.status(), StatusCode::OK);

    let deleted = router
        .clone()
        .oneshot(
            axum::http::Request::delete(format!("/api/integrations/{integration_id}"))
                .header(http::header::AUTHORIZATION, format!("Bearer {access}"))
                .body(axum::body::Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(deleted.status(), StatusCode::NO_CONTENT);

    let logout_response = router
        .oneshot(
            axum::http::Request::post("/logout")
                .header(http::header::ORIGIN, origin)
                .header(http::header::COOKIE, &cookie_header)
                .header(
                    http::header::CONTENT_TYPE,
                    "application/x-www-form-urlencoded",
                )
                .body(axum::body::Body::from(encoded_form(&[(
                    "csrf_token",
                    &csrf,
                )])))
                .unwrap(),
        )
        .await
        .unwrap();
    assert!(logout_response.status().is_redirection());
    assert_eq!(
        logout_response
            .headers()
            .get_all(http::header::SET_COOKIE)
            .iter()
            .count(),
        2
    );
}

#[tokio::test]
async fn administration_ui_revocation_and_upstream_callback_routes() {
    let (app, _directory) = route_test_app().await;
    let user = app.db.create_user("admin@example.com", "hash").unwrap();
    let session = "browser-session";
    let csrf = "browser-csrf";
    app.db
        .create_session(
            &token_hash(session),
            &user,
            &token_hash(csrf),
            chrono::Utc::now().timestamp() + 3600,
        )
        .unwrap();
    app.db
        .register_client(
            "admin-client",
            Some(&user),
            "admin",
            &["http://localhost/callback".into()],
        )
        .unwrap();
    app.db
        .store_access_token(
            &token_hash("admin-access"),
            "admin-client",
            &user,
            "mcp admin",
            chrono::Utc::now().timestamp() + 3600,
            None,
            None,
        )
        .unwrap();
    for client in [
        "api-target",
        "ui-target",
        "api-client-target",
        "ui-token-target",
    ] {
        app.db
            .register_client(
                client,
                Some(&user),
                client,
                &["http://localhost/callback".into()],
            )
            .unwrap();
        app.db
            .store_access_token(
                &token_hash(&format!("{client}-access")),
                client,
                &user,
                "mcp",
                chrono::Utc::now().timestamp() + 3600,
                None,
                None,
            )
            .unwrap();
    }
    app.replicator.sync().await.unwrap();
    let router = build_router(app.clone());
    let origin = "http://localhost:4788";
    let cookies = format!("cog_session={session}; cog_csrf={csrf}");

    let unauthenticated = router
        .clone()
        .oneshot(
            axum::http::Request::get("/ui")
                .body(axum::body::Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert!(unauthenticated.status().is_redirection());
    let ui = router
        .clone()
        .oneshot(
            axum::http::Request::get("/ui")
                .header(http::header::COOKIE, &cookies)
                .body(axum::body::Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(ui.status(), StatusCode::OK);

    let add = router
        .clone()
        .oneshot(
            axum::http::Request::post("/ui/integrations")
                .header(http::header::ORIGIN, origin)
                .header(http::header::COOKIE, &cookies)
                .header(
                    http::header::CONTENT_TYPE,
                    "application/x-www-form-urlencoded",
                )
                .body(axum::body::Body::from(encoded_form(&[
                    ("name", "ui-http"),
                    ("url", "http://localhost:9999/mcp"),
                    ("csrf_token", csrf),
                ])))
                .unwrap(),
        )
        .await
        .unwrap();
    assert!(add.status().is_redirection());
    let ui_integration = app
        .db
        .list_integrations(&user)
        .unwrap()
        .into_iter()
        .find(|integration| integration.name == "ui-http")
        .unwrap();
    let delete = router
        .clone()
        .oneshot(
            axum::http::Request::post(format!("/ui/integrations/{}/delete", ui_integration.id))
                .header(http::header::ORIGIN, origin)
                .header(http::header::COOKIE, &cookies)
                .header(
                    http::header::CONTENT_TYPE,
                    "application/x-www-form-urlencoded",
                )
                .body(axum::body::Body::from(encoded_form(&[(
                    "csrf_token",
                    csrf,
                )])))
                .unwrap(),
        )
        .await
        .unwrap();
    assert!(delete.status().is_redirection());

    let tokens = app.db.agent_tokens(&user).unwrap();
    let api_token = tokens
        .iter()
        .find(|token| token.client_id == "api-target")
        .unwrap();
    let revoked = router
        .clone()
        .oneshot(
            axum::http::Request::delete(format!("/api/tokens/{}", api_token.token_id))
                .header(http::header::AUTHORIZATION, "Bearer admin-access")
                .body(axum::body::Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(revoked.status(), StatusCode::NO_CONTENT);
    let revoked = router
        .clone()
        .oneshot(
            axum::http::Request::post(format!("/ui/clients/{}/revoke", "ui-target"))
                .header(http::header::ORIGIN, origin)
                .header(http::header::COOKIE, &cookies)
                .header(
                    http::header::CONTENT_TYPE,
                    "application/x-www-form-urlencoded",
                )
                .body(axum::body::Body::from(encoded_form(&[(
                    "csrf_token",
                    csrf,
                )])))
                .unwrap(),
        )
        .await
        .unwrap();
    assert!(revoked.status().is_redirection());

    let revoked = router
        .clone()
        .oneshot(
            axum::http::Request::delete("/api/clients/api-client-target")
                .header(http::header::AUTHORIZATION, "Bearer admin-access")
                .body(axum::body::Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(revoked.status(), StatusCode::NO_CONTENT);
    let ui_token = app
        .db
        .agent_tokens(&user)
        .unwrap()
        .into_iter()
        .find(|token| token.client_id == "ui-token-target")
        .unwrap();
    let revoked = router
        .clone()
        .oneshot(
            axum::http::Request::post(format!("/ui/tokens/{}/revoke", ui_token.token_id))
                .header(http::header::ORIGIN, origin)
                .header(http::header::COOKIE, &cookies)
                .header(
                    http::header::CONTENT_TYPE,
                    "application/x-www-form-urlencoded",
                )
                .body(axum::body::Body::from(encoded_form(&[(
                    "csrf_token",
                    csrf,
                )])))
                .unwrap(),
        )
        .await
        .unwrap();
    assert!(revoked.status().is_redirection());

    let token_listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let token_address = token_listener.local_addr().unwrap();
    let token_server = tokio::spawn(
        axum::serve(
            token_listener,
            Router::new().route(
                "/token",
                post(|body: String| async move {
                    let resources: Vec<_> = url::form_urlencoded::parse(body.as_bytes())
                        .filter(|(name, _)| name == "resource")
                        .map(|(_, value)| value.into_owned())
                        .collect();
                    assert_eq!(resources, vec!["http://127.0.0.1:9999/mcp"]);
                    Json(json!({
                        "access_token":"connected-access",
                        "refresh_token":"connected-refresh",
                        "token_type":"Bearer",
                        "scope":"mcp",
                        "expires_in":3600
                    }))
                }),
            ),
        )
        .into_future(),
    );
    let oauth_id = app
        .db
        .create_integration(
            &user,
            "oauth-http",
            "http",
            &json!({
                "url":"http://localhost:9999/mcp",
                "oauth":{
                    "authorization_endpoint":format!("http://{token_address}/authorize"),
                    "token_endpoint":format!("http://{token_address}/token"),
                    "client_id":"configured-client",
                    "scope":"mcp",
                    "resource":"http://127.0.0.1:9999/mcp"
                }
            }),
            None,
        )
        .unwrap();
    let pending_ui = router
        .clone()
        .oneshot(
            axum::http::Request::get("/api/ui")
                .header(http::header::COOKIE, &cookies)
                .body(axum::body::Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert!(
        String::from_utf8(
            pending_ui
                .into_body()
                .collect()
                .await
                .unwrap()
                .to_bytes()
                .to_vec()
        )
        .unwrap()
        .contains("connection required")
    );
    let started = router
        .clone()
        .oneshot(
            axum::http::Request::post(format!("/api/integrations/{oauth_id}/oauth/start"))
                .header(http::header::AUTHORIZATION, "Bearer admin-access")
                .body(axum::body::Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(started.status(), StatusCode::OK);
    let authorization_url = response_json(started).await["authorization_url"]
        .as_str()
        .unwrap()
        .to_owned();
    let state = url::Url::parse(&authorization_url)
        .unwrap()
        .query_pairs()
        .find_map(|(key, value)| (key == "state").then(|| value.into_owned()))
        .unwrap();
    let callback = router
        .clone()
        .oneshot(
            axum::http::Request::get(format!(
                "/oauth/upstream/callback?code=test-code&state={state}"
            ))
            .body(axum::body::Body::empty())
            .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(callback.status(), StatusCode::OK);
    assert!(app.db.upstream_oauth_token(&oauth_id).unwrap().is_some());
    let connected_ui = router
        .clone()
        .oneshot(
            axum::http::Request::get("/api/ui")
                .header(http::header::COOKIE, &cookies)
                .body(axum::body::Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    let connected_ui = response_json(connected_ui).await;
    let connected = connected_ui["integrations"]
        .as_array()
        .unwrap()
        .iter()
        .find(|integration| integration["id"] == oauth_id)
        .unwrap();
    assert_eq!(connected["oauth"], "connected");
    assert_eq!(connected["oauth_scopes"], json!(["mcp"]));
    token_server.abort();
}

#[tokio::test]
async fn ui_mutation_success_and_failure_matrix() {
    let (app, _directory) = route_test_app().await;
    let user = app.db.create_user("ui-matrix@example.com", "hash").unwrap();
    let session = "ui-matrix-session";
    let csrf = "ui-matrix-csrf";
    app.db
        .create_session(
            &token_hash(session),
            &user,
            &token_hash(csrf),
            chrono::Utc::now().timestamp() + 600,
        )
        .unwrap();
    let mut headers = HeaderMap::new();
    headers.insert(
        http::header::ORIGIN,
        "http://localhost:4788".parse().unwrap(),
    );
    headers.insert(
        http::header::COOKIE,
        format!("cog_session={session}; cog_csrf={csrf}")
            .parse()
            .unwrap(),
    );
    let name = |value: &str| UiNameForm {
        name: value.into(),
        csrf_token: csrf.into(),
    };
    let csrf_form = || CsrfForm {
        csrf_token: csrf.into(),
    };

    assert_eq!(
        ui_create_identity(State(app.clone()), headers.clone(), Form(name("work")))
            .await
            .into_response()
            .status(),
        StatusCode::NO_CONTENT
    );
    assert_eq!(
        ui_create_identity(State(app.clone()), headers.clone(), Form(name(" ")))
            .await
            .into_response()
            .status(),
        StatusCode::BAD_REQUEST
    );
    let identity = app
        .db
        .list_identities(&user)
        .unwrap()
        .into_iter()
        .find(|identity| identity.name == "work")
        .unwrap();
    assert_eq!(
        ui_rename_identity(
            State(app.clone()),
            Path(identity.id.clone()),
            headers.clone(),
            Form(name("renamed")),
        )
        .await
        .into_response()
        .status(),
        StatusCode::NO_CONTENT
    );
    for (id, value, expected) in [
        (identity.id.as_str(), "", StatusCode::BAD_REQUEST),
        ("missing", "name", StatusCode::NOT_FOUND),
    ] {
        assert_eq!(
            ui_rename_identity(
                State(app.clone()),
                Path(id.to_owned()),
                headers.clone(),
                Form(name(value)),
            )
            .await
            .into_response()
            .status(),
            expected
        );
    }
    assert_eq!(
        ui_delete_identity(
            State(app.clone()),
            Path("missing".into()),
            headers.clone(),
            Form(csrf_form()),
        )
        .await
        .into_response()
        .status(),
        StatusCode::NOT_FOUND
    );
    assert_eq!(
        ui_delete_identity(
            State(app.clone()),
            Path(identity.id),
            headers.clone(),
            Form(csrf_form()),
        )
        .await
        .into_response()
        .status(),
        StatusCode::NO_CONTENT
    );

    app.db
        .register_client(
            "matrix-client",
            Some(&user),
            "matrix",
            &["http://localhost/callback".into()],
        )
        .unwrap();
    app.db
        .store_access_token(
            &token_hash("matrix-access"),
            "matrix-client",
            &user,
            "mcp admin",
            chrono::Utc::now().timestamp() + 600,
            None,
            None,
        )
        .unwrap();
    let agent = app.db.agent_for_client("matrix-client").unwrap().unwrap();
    assert_eq!(
        ui_rename_agent(
            State(app.clone()),
            Path(agent.id.clone()),
            headers.clone(),
            Form(name("renamed agent")),
        )
        .await
        .into_response()
        .status(),
        StatusCode::NO_CONTENT
    );
    for (id, value, expected) in [
        (agent.id.as_str(), "", StatusCode::BAD_REQUEST),
        ("missing", "agent", StatusCode::NOT_FOUND),
    ] {
        assert_eq!(
            ui_rename_agent(
                State(app.clone()),
                Path(id.into()),
                headers.clone(),
                Form(name(value)),
            )
            .await
            .into_response()
            .status(),
            expected
        );
    }

    assert_eq!(
        ui_add_integration(
            State(app.clone()),
            headers.clone(),
            Form(UiIntegrationForm {
                name: "file".into(),
                url: "file:///tmp/socket".parse().unwrap(),
                csrf_token: csrf.into(),
            }),
        )
        .await
        .into_response()
        .status(),
        StatusCode::BAD_REQUEST
    );
    for response in [
        ui_delete_integration(
            State(app.clone()),
            Path("missing".into()),
            headers.clone(),
            Form(csrf_form()),
        )
        .await
        .into_response(),
        ui_disconnect_integration(
            State(app.clone()),
            Path("missing".into()),
            headers.clone(),
            Form(csrf_form()),
        )
        .await
        .into_response(),
        ui_revoke_token(
            State(app.clone()),
            Path("missing".into()),
            headers.clone(),
            Form(csrf_form()),
        )
        .await
        .into_response(),
        ui_revoke_client(
            State(app.clone()),
            Path("missing".into()),
            headers.clone(),
            Form(csrf_form()),
        )
        .await
        .into_response(),
    ] {
        assert_eq!(response.status(), StatusCode::NOT_FOUND);
    }

    let integration = app
        .db
        .create_integration(
            &user,
            "matrix integration",
            "http",
            &json!({"url":"http://localhost:9999/mcp"}),
            None,
        )
        .unwrap();
    assert!(
        ui_grant_integration(
            State(app.clone()),
            Path(("matrix-client".into(), integration.clone())),
            headers.clone(),
            Form(csrf_form()),
        )
        .await
        .into_response()
        .status()
        .is_redirection()
    );
    assert!(
        ui_grant_integration(
            State(app.clone()),
            Path(("matrix-client".into(), integration.clone())),
            headers.clone(),
            Form(csrf_form()),
        )
        .await
        .into_response()
        .status()
        .is_redirection()
    );
    assert!(
        ui_revoke_grant(
            State(app.clone()),
            Path(("matrix-client".into(), integration.clone())),
            headers.clone(),
            Form(csrf_form()),
        )
        .await
        .into_response()
        .status()
        .is_redirection()
    );
    assert_eq!(
        ui_revoke_grant(
            State(app.clone()),
            Path(("matrix-client".into(), integration)),
            headers.clone(),
            Form(csrf_form()),
        )
        .await
        .into_response()
        .status(),
        StatusCode::BAD_REQUEST
    );

    assert_eq!(
        ui_prepare_ssh_key(
            State(app.clone()),
            Path("invalid".into()),
            headers.clone(),
            Form(csrf_form()),
        )
        .await
        .status(),
        StatusCode::BAD_REQUEST
    );
    assert!(
        ui_prepare_ssh_key(
            State(app.clone()),
            Path("user_ca".into()),
            headers.clone(),
            Form(csrf_form()),
        )
        .await
        .status()
        .is_redirection()
    );
    let prepared = app
        .db
        .ssh_keys()
        .unwrap()
        .into_iter()
        .find(|key| key.purpose == "user_ca" && !key.active)
        .unwrap();
    assert!(
        ui_activate_ssh_key(
            State(app.clone()),
            Path(("user_ca".into(), prepared.id.clone())),
            headers.clone(),
            Form(csrf_form()),
        )
        .await
        .status()
        .is_redirection()
    );
    assert_eq!(
        ui_retire_ssh_key(
            State(app.clone()),
            Path(("user_ca".into(), prepared.id)),
            headers.clone(),
            Form(csrf_form()),
        )
        .await
        .status(),
        StatusCode::BAD_REQUEST
    );
    app.ssh_ready.store(true, Ordering::Release);
    assert_eq!(
        ui_activate_ssh_key(
            State(app.clone()),
            Path(("host".into(), "missing".into())),
            headers,
            Form(csrf_form()),
        )
        .await
        .status(),
        StatusCode::CONFLICT
    );

    let mut api_headers = HeaderMap::new();
    api_headers.insert(
        http::header::AUTHORIZATION,
        "Bearer matrix-access".parse().unwrap(),
    );
    for response in [
        list_integrations(State(app.clone()), api_headers.clone())
            .await
            .into_response(),
        list_agent_clients(State(app.clone()), api_headers.clone())
            .await
            .into_response(),
        list_agent_tokens(State(app.clone()), api_headers.clone())
            .await
            .into_response(),
        list_audit_events(
            State(app.clone()),
            api_headers.clone(),
            Query(AuditQuery { limit: 10 }),
        )
        .await
        .into_response(),
    ] {
        assert_eq!(response.status(), StatusCode::OK);
    }
    assert_eq!(
        get_integration(
            State(app.clone()),
            Path("missing".into()),
            api_headers.clone(),
        )
        .await
        .into_response()
        .status(),
        StatusCode::NOT_FOUND
    );
    for response in [
        revoke_agent_client(
            State(app.clone()),
            Path("missing".into()),
            api_headers.clone(),
        )
        .await
        .into_response(),
        revoke_agent_token(
            State(app.clone()),
            Path("missing".into()),
            api_headers.clone(),
        )
        .await
        .into_response(),
        revoke_agent_grant(
            State(app.clone()),
            Path(("missing".into(), "missing".into())),
            api_headers.clone(),
        )
        .await
        .into_response(),
        reconnect_integration(
            State(app.clone()),
            Path("missing".into()),
            api_headers.clone(),
        )
        .await
        .into_response(),
        disconnect_integration(
            State(app.clone()),
            Path("missing".into()),
            api_headers.clone(),
        )
        .await
        .into_response(),
        delete_integration(State(app.clone()), Path("missing".into()), api_headers)
            .await
            .into_response(),
    ] {
        assert_eq!(response.status(), StatusCode::NOT_FOUND);
    }
}

async fn request_status(
    router: &Router,
    method: http::Method,
    uri: impl AsRef<str>,
    authorization: Option<&str>,
    content_type: Option<&str>,
    body: impl Into<axum::body::Body>,
) -> StatusCode {
    let mut request = axum::http::Request::builder()
        .method(method)
        .uri(uri.as_ref());
    if let Some(value) = authorization {
        request = request.header(http::header::AUTHORIZATION, value);
    }
    if let Some(value) = content_type {
        request = request.header(http::header::CONTENT_TYPE, value);
    }
    router
        .clone()
        .oneshot(request.body(body.into()).unwrap())
        .await
        .unwrap()
        .status()
}

#[tokio::test]
async fn route_validation_authentication_and_not_found_paths() {
    let (app, _directory) = route_test_app().await;
    let user = app
        .db
        .create_user("errors@example.com", "not-a-password-hash")
        .unwrap();
    app.db
        .register_client(
            "limited-client",
            Some(&user),
            "limited",
            &["http://localhost/callback".into()],
        )
        .unwrap();
    app.db
        .store_access_token(
            &token_hash("mcp-only"),
            "limited-client",
            &user,
            "mcp",
            chrono::Utc::now().timestamp() + 3600,
            None,
            None,
        )
        .unwrap();
    app.replicator.sync().await.unwrap();
    let router = build_router(app.clone());

    for path in [
        "/api/integrations",
        "/api/clients",
        "/api/tokens",
        "/api/audit",
    ] {
        assert_eq!(
            request_status(&router, http::Method::GET, path, None, None, "").await,
            StatusCode::UNAUTHORIZED
        );
        assert_eq!(
            request_status(
                &router,
                http::Method::GET,
                path,
                Some("Bearer unknown"),
                None,
                "",
            )
            .await,
            StatusCode::UNAUTHORIZED
        );
        assert_eq!(
            request_status(
                &router,
                http::Method::GET,
                path,
                Some("Bearer mcp-only"),
                None,
                "",
            )
            .await,
            StatusCode::FORBIDDEN
        );
    }

    for (method, path) in [
        (http::Method::GET, "/api/integrations/missing"),
        (http::Method::DELETE, "/api/integrations/missing"),
        (http::Method::POST, "/api/integrations/missing/reconnect"),
        (http::Method::POST, "/api/integrations/missing/oauth/start"),
        (http::Method::DELETE, "/api/clients/missing"),
        (http::Method::DELETE, "/api/tokens/missing"),
    ] {
        assert_eq!(
            request_status(&router, method, path, Some("Bearer mcp-only"), None, "",).await,
            StatusCode::FORBIDDEN
        );
    }

    for registration in [
        json!({"client_name":"bad","redirect_uris":[]}),
        json!({"client_name":"bad","redirect_uris":["https://example.com/cb#fragment"]}),
    ] {
        assert_eq!(
            request_status(
                &router,
                http::Method::POST,
                "/oauth/register",
                None,
                Some("application/json"),
                registration.to_string(),
            )
            .await,
            StatusCode::BAD_REQUEST
        );
    }

    for query in [
        "response_type=token&client_id=limited-client&redirect_uri=http%3A%2F%2Flocalhost%2Fcallback&state=x&code_challenge=x&code_challenge_method=S256",
        "response_type=code&client_id=unknown&redirect_uri=http%3A%2F%2Flocalhost%2Fcallback&state=x&code_challenge=x&code_challenge_method=S256",
        "response_type=code&client_id=limited-client&redirect_uri=http%3A%2F%2Fevil.example%2Fcallback&state=x&code_challenge=x&code_challenge_method=S256",
        "response_type=code&client_id=limited-client&redirect_uri=http%3A%2F%2Flocalhost%2Fcallback&state=x&code_challenge=x&code_challenge_method=S256",
    ] {
        assert!(matches!(
            request_status(
                &router,
                http::Method::GET,
                format!("/api/oauth/consent?{query}"),
                None,
                None,
                "",
            )
            .await,
            StatusCode::BAD_REQUEST | StatusCode::UNAUTHORIZED
        ));
    }

    assert_eq!(
        request_status(
            &router,
            http::Method::POST,
            "/oauth/token",
            None,
            Some("application/x-www-form-urlencoded"),
            encoded_form(&[
                ("grant_type", "authorization_code"),
                ("code", "missing"),
                ("client_id", "limited-client"),
                ("redirect_uri", "http://localhost/callback"),
                ("code_verifier", "invalid"),
            ]),
        )
        .await,
        StatusCode::BAD_REQUEST
    );
    for token in ["unknown-token", "mcp-only"] {
        assert_eq!(
            request_status(
                &router,
                http::Method::POST,
                "/oauth/revoke",
                None,
                Some("application/x-www-form-urlencoded"),
                encoded_form(&[("token", token)]),
            )
            .await,
            StatusCode::OK
        );
    }

    app.db
        .store_access_token(
            &token_hash("admin-errors"),
            "limited-client",
            &user,
            "admin",
            chrono::Utc::now().timestamp() + 3600,
            None,
            None,
        )
        .unwrap();
    for body in [
        json!({"name":"bad","transport":"ftp","config":{}}),
        json!({"name":"bad","transport":"http","config":{"url":"ftp://example.com"}}),
        json!({"name":"bad","transport":"http","config":{"url":"https://user:secret@example.com/mcp"}}),
        json!({"name":"bad","transport":"stdio","config":{"command":"echo"}}),
    ] {
        assert_eq!(
            request_status(
                &router,
                http::Method::POST,
                "/api/integrations",
                Some("Bearer admin-errors"),
                Some("application/json"),
                body.to_string(),
            )
            .await,
            StatusCode::BAD_REQUEST
        );
    }

    let forbidden_form = encoded_form(&[("csrf_token", "wrong")]);
    for path in [
        "/logout",
        "/ui/integrations/missing/delete",
        "/ui/tokens/missing/revoke",
        "/ui/clients/missing/revoke",
    ] {
        assert_eq!(
            request_status(
                &router,
                http::Method::POST,
                path,
                None,
                Some("application/x-www-form-urlencoded"),
                forbidden_form.clone(),
            )
            .await,
            StatusCode::FORBIDDEN
        );
    }

    for (method, path, expected) in [
        (
            http::Method::GET,
            "/api/integrations/missing",
            StatusCode::NOT_FOUND,
        ),
        (
            http::Method::PATCH,
            "/api/integrations/missing",
            StatusCode::NOT_FOUND,
        ),
        (
            http::Method::DELETE,
            "/api/integrations/missing",
            StatusCode::NOT_FOUND,
        ),
        (
            http::Method::POST,
            "/api/integrations/missing/reconnect",
            StatusCode::NOT_FOUND,
        ),
        (
            http::Method::POST,
            "/api/integrations/missing/oauth/start",
            StatusCode::NOT_FOUND,
        ),
        (
            http::Method::DELETE,
            "/api/clients/missing",
            StatusCode::NOT_FOUND,
        ),
        (
            http::Method::DELETE,
            "/api/tokens/missing",
            StatusCode::NOT_FOUND,
        ),
    ] {
        assert_eq!(
            request_status(
                &router,
                method,
                path,
                Some("Bearer admin-errors"),
                Some("application/json"),
                "{}"
            )
            .await,
            expected
        );
    }
    for query in [
        "state=missing&error=access_denied",
        "state=missing",
        "state=missing&code=code",
    ] {
        assert_eq!(
            request_status(
                &router,
                http::Method::GET,
                format!("/oauth/upstream/callback?{query}"),
                None,
                None,
                ""
            )
            .await,
            StatusCode::BAD_REQUEST
        );
    }
    assert_eq!(
        request_status(&router, http::Method::POST, "/setup", None, None, "").await,
        StatusCode::NOT_FOUND
    );
    for (origin, email, password, expected) in [
        (None, "errors@example.com", "wrong", StatusCode::FORBIDDEN),
        (
            Some("http://localhost:4788"),
            "missing@example.com",
            "wrong",
            StatusCode::UNAUTHORIZED,
        ),
        (
            Some("http://localhost:4788"),
            "errors@example.com",
            "wrong",
            StatusCode::UNAUTHORIZED,
        ),
    ] {
        let mut request = axum::http::Request::post("/login").header(
            http::header::CONTENT_TYPE,
            "application/x-www-form-urlencoded",
        );
        if let Some(origin) = origin {
            request = request.header(http::header::ORIGIN, origin);
        }
        let response = router
            .clone()
            .oneshot(
                request
                    .body(axum::body::Body::from(encoded_form(&[
                        ("email", email),
                        ("password", password),
                    ])))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), expected);
    }

    let session = "error-session";
    let csrf = "error-csrf";
    app.db
        .create_session(
            &token_hash(session),
            &user,
            &token_hash(csrf),
            chrono::Utc::now().timestamp() + 600,
        )
        .unwrap();
    let cookies = format!("cog_session={session}; cog_csrf={csrf}");
    let query = "response_type=code&client_id=limited-client&redirect_uri=http%3A%2F%2Flocalhost%2Fcallback&state=denied&code_challenge=challenge&code_challenge_method=S256&scope=mcp&resource=http%3A%2F%2Flocalhost%3A4788%2Fmcp";
    let consent = router
        .clone()
        .oneshot(
            axum::http::Request::get(format!("/api/oauth/consent?{query}"))
                .header(http::header::COOKIE, &cookies)
                .body(axum::body::Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(consent.status(), StatusCode::OK);
    let sealed_consent = response_json(consent).await["consent"]
        .as_str()
        .unwrap()
        .to_owned();
    let denied = router
        .clone()
        .oneshot(
            axum::http::Request::post("/api/oauth/consent")
                .header(http::header::ORIGIN, "http://localhost:4788")
                .header(http::header::COOKIE, &cookies)
                .header(
                    http::header::CONTENT_TYPE,
                    "application/x-www-form-urlencoded",
                )
                .body(axum::body::Body::from(encoded_form(&[
                    ("consent", &sealed_consent),
                    ("csrf_token", csrf),
                    ("decision", "deny"),
                ])))
                .unwrap(),
        )
        .await
        .unwrap();
    assert!(denied.status().is_redirection());
}

#[tokio::test]
async fn authentication_rate_limit_is_bounded_per_subject() {
    let limiter = RateLimiter::default();
    assert!(limiter.allow("login:a".into(), 2, Duration::from_secs(60)));
    assert!(limiter.allow("login:a".into(), 2, Duration::from_secs(60)));
    assert!(!limiter.allow("login:a".into(), 2, Duration::from_secs(60)));
    assert!(limiter.allow("login:b".into(), 2, Duration::from_secs(60)));
    let (app, _directory) = route_test_app().await;
    for _ in 0..2 {
        assert!(rate_limit(&app, "test", "subject", 2).is_none());
    }
    assert_eq!(
        rate_limit(&app, "test", "subject", 2).unwrap().status(),
        StatusCode::TOO_MANY_REQUESTS
    );
    assert_eq!(
        build_router(app.clone())
            .oneshot(
                axum::http::Request::get("/")
                    .body(axum::body::Body::empty())
                    .unwrap()
            )
            .await
            .unwrap()
            .status(),
        StatusCode::OK
    );
    let mut endpoint = app.config.clone();
    endpoint.s3_endpoint = Some("http://localhost:9000".into());
    assert!(build_store(&endpoint).is_ok());
}

#[tokio::test]
async fn dynamic_registration_has_global_and_body_limits() {
    let (app, _directory) = route_test_app().await;
    let router = build_router(app);
    for index in 0..20 {
        let response = router
            .clone()
            .oneshot(
                axum::http::Request::post("/oauth/register")
                    .header(http::header::CONTENT_TYPE, "application/json")
                    .body(axum::body::Body::from(
                        json!({
                            "client_name": format!("client-{index}"),
                            "redirect_uris": [format!("http://localhost/callback/{index}")]
                        })
                        .to_string(),
                    ))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::CREATED);
    }
    let limited = router
        .clone()
        .oneshot(
            axum::http::Request::post("/oauth/register")
                .header(http::header::CONTENT_TYPE, "application/json")
                .body(axum::body::Body::from(
                    json!({
                        "client_name": "one-too-many",
                        "redirect_uris": ["http://localhost/callback/limited"]
                    })
                    .to_string(),
                ))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(limited.status(), StatusCode::TOO_MANY_REQUESTS);

    let oversized = router
        .oneshot(
            axum::http::Request::post("/oauth/register")
                .header(http::header::CONTENT_TYPE, "application/json")
                .body(axum::body::Body::from("x".repeat(32 * 1_024 + 1)))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(oversized.status(), StatusCode::PAYLOAD_TOO_LARGE);
}

#[test]
fn bearer_authorization_uses_conventional_http_scheme_case() {
    assert_eq!(oauth_authorization_value("bearer", "token"), "Bearer token");
    assert_eq!(oauth_authorization_value("BEARER", "token"), "Bearer token");
    assert_eq!(oauth_authorization_value("DPoP", "token"), "DPoP token");
}

#[tokio::test]
async fn instance_credentials_are_refetched_before_expiration() {
    use object_store::aws::AmazonS3Builder;

    let fetches = Arc::new(AtomicU64::new(0));
    let credential_fetches = fetches.clone();
    let metadata = Router::new()
        .route(
            "/latest/api/token",
            axum::routing::put(|| async { "metadata-token" }),
        )
        .route(
            "/latest/meta-data/iam/security-credentials/",
            get(|| async { "cog-role" }),
        )
        .route(
            "/latest/meta-data/iam/security-credentials/cog-role",
            get(move || {
                let credential_fetches = credential_fetches.clone();
                async move {
                    let generation = credential_fetches.fetch_add(1, Ordering::SeqCst) + 1;
                    Json(json!({
                        "AccessKeyId": format!("refresh-key-{generation}"),
                        "SecretAccessKey": "refresh-secret",
                        "Token": format!("refresh-token-{generation}"),
                        // The provider's five-minute safety window makes
                        // this credential eligible for refresh immediately.
                        "Expiration": (chrono::Utc::now() + chrono::Duration::seconds(60))
                            .to_rfc3339(),
                    }))
                }
            }),
        );
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let endpoint = format!("http://{}", listener.local_addr().unwrap());
    let server = tokio::spawn(async move { axum::serve(listener, metadata).await.unwrap() });

    let store = AmazonS3Builder::new()
        .with_bucket_name("credential-test")
        .with_metadata_endpoint(endpoint)
        .build()
        .unwrap();
    let first = store.credentials().get_credential().await.unwrap();
    tokio::time::sleep(Duration::from_millis(110)).await;
    let second = store.credentials().get_credential().await.unwrap();
    assert_ne!(first.key_id, second.key_id);
    assert!(fetches.load(Ordering::SeqCst) >= 2);
    server.abort();
}

#[tokio::test]
async fn per_integration_tool_policy_filters_discovery_and_calls() {
    let provider = PolicyProvider {
        inner: Arc::new(PolicyFixture),
        allow: Some(HashSet::from(["read".into(), "write".into()])),
        deny: HashSet::from(["write".into()]),
    };
    assert_eq!(provider.tools().await.unwrap()[0].name, "read");
    assert_eq!(provider.call("read", json!({})).await.unwrap(), "read");
    assert!(provider.call("write", json!({})).await.is_err());
    assert!(validate_policy(&json!({"policy":{"allow_tools":["bad name"]}})).is_err());
    assert!(
        validate_transport(
            "http",
            &json!({"url":"https://user:secret@example.com/mcp"}),
            None,
            false,
        )
        .is_err()
    );
    assert!(
        validate_transport(
            "git",
            &json!({
                "kind":"git",
                "provider":"github",
                "providerConfig":{"appId":"1","installationId":"2"}
            }),
            Some(&HashMap::from([(
                "privateKey".into(),
                "invalid pem".into()
            )])),
            false,
        )
        .is_err()
    );
    let oauth = json!({"url":"https://example.com/mcp","oauth":{"resource_metadata_url":"https://example.com/resource","issuer":"https://issuer.example/path","authorization_endpoint":"http://localhost/authorize","token_endpoint":"http://127.0.0.1/token","registration_endpoint":"http://localhost/register","client_id":"client","scope":"mcp"}});
    assert!(
        validate_transport(
            "http",
            &oauth,
            Some(&HashMap::from([("X-Test".into(), "ok".into())])),
            false
        )
        .is_ok()
    );
    assert!(validate_transport("http", &json!({"url":"https://example.com/mcp","oauth":{"issuer":"http://remote.example/issuer"}}), None, false).is_err());
    assert!(validate_transport("http", &json!({"url":"https://example.com/mcp","oauth":{"issuer":"https://user:secret@example.com/issuer"}}), None, false).is_err());
    assert!(
        validate_transport(
            "http",
            &json!({"url":"https://example.com/mcp","oauth":{"scope":" "}}),
            None,
            false
        )
        .is_err()
    );
    assert!(
        validate_transport(
            "stdio",
            &json!({"command":"echo","args":["ok"]}),
            None,
            true
        )
        .is_ok()
    );
    assert!(validate_transport("stdio", &json!({"command":" ","args":[]}), None, true).is_err());
    assert!(
        validate_transport(
            "stdio",
            &json!({"command":"echo","args":["bad\u{0}"]}),
            None,
            true
        )
        .is_err()
    );
    assert!(
        validate_transport(
            "http",
            &json!({"url":"https://example.com"}),
            Some(&HashMap::from([("bad header".into(), "x".into())])),
            false
        )
        .is_err()
    );
    assert!(
        validate_transport(
            "http",
            &json!({"url":"https://example.com"}),
            Some(&HashMap::from([("X-Test".into(), "bad\nvalue".into())])),
            false
        )
        .is_err()
    );
    provider.close().await.unwrap();
    assert!(
        validate_transport(
            "http",
            &json!({"url":"https://example.com/mcp","oauth":{"client_secret":"secret"}}),
            None,
            false,
        )
        .is_err()
    );
}

#[tokio::test]
async fn provider_metrics_catalog_construction_and_oauth_shortcuts() {
    let metrics = Arc::new(Metrics::default());
    let measured = MeasuredProvider {
        inner: Arc::new(FailingFixture),
        metrics: metrics.clone(),
    };
    assert!(measured.tools().await.is_err());
    assert!(measured.call("x", json!({})).await.is_err());
    assert!(measured.close().await.is_err());
    assert_eq!(metrics.upstream_calls.load(Ordering::Relaxed), 2);
    assert_eq!(metrics.upstream_failures.load(Ordering::Relaxed), 2);

    let (mut app, _directory) = route_test_app().await;
    let user = app.db.create_user("catalog@example.com", "hash").unwrap();
    let auth = AuthContext {
        user: user.clone(),
        agent: "test-agent".into(),
        identity: "test-identity".into(),
        client: "test-client".into(),
        scopes: HashSet::from(["admin".into()]),
        integrations: HashSet::new(),
    };
    let cached = app
        .db
        .create_integration(
            &user,
            "cached",
            "http",
            &json!({"url":"http://localhost:9999/mcp"}),
            None,
        )
        .unwrap();
    app.providers
        .lock()
        .await
        .insert(cached.clone(), Arc::new(PolicyFixture));
    let plain = app.db.create_integration(&user, "plain", "http", &json!({"url":"http://localhost:9998/mcp","policy":{"allow_tools":["read"],"deny_tools":["write"]}}), Some(&app.secrets.seal(br#"{"X-Test":"secret"}"#).unwrap())).unwrap();
    let _sse = app
        .db
        .create_integration(
            &user,
            "events",
            "sse",
            &json!({"url":"http://localhost:9997/sse"}),
            None,
        )
        .unwrap();
    let _unknown = app
        .db
        .create_integration(&user, "unknown", "future", &json!({}), None)
        .unwrap();
    let built = catalog(&app, &auth).await.unwrap();
    assert_eq!(
        built
            .call(&format!("{cached}.read"), json!({}))
            .await
            .unwrap(),
        "read"
    );
    assert!(app.providers.lock().await.contains_key(&plain));

    let oauth = app.db.create_integration(&user, "needs-oauth", "http", &json!({"url":"http://localhost:9996/mcp","oauth":{"authorization_endpoint":"http://localhost/authorize","token_endpoint":"http://localhost/token","client_id":"client"}}), None).unwrap();
    let identity = app.db.list_identities(&user).unwrap()[0].id.clone();
    // An integration awaiting upstream OAuth remains visible to an
    // ungranted downstream client, with the two authorization states kept
    // separate.
    let chatgpt = AuthContext {
        user: user.clone(),
        agent: "test-agent".into(),
        identity,
        client: "chatgpt".into(),
        scopes: HashSet::from(["mcp".into()]),
        integrations: HashSet::new(),
    };
    let awaiting = catalog(&app, &chatgpt)
        .await
        .unwrap()
        .search("needs-oauth")
        .await
        .unwrap();
    assert_eq!(awaiting[0]["upstreamConnected"], false);
    assert_eq!(awaiting[0]["upstreamStatus"], "disconnected");
    assert_eq!(awaiting[0]["clientAccessGranted"], false);
    assert_eq!(awaiting[0]["requiredScope"], format!("integration:{oauth}"));

    let authorization = admin_authorize(&app, &user, &oauth).await.unwrap();
    assert_eq!(authorization["alreadyConnected"], false);
    let authorization_url =
        url::Url::parse(authorization["authorization_url"].as_str().unwrap()).unwrap();
    let parameters = authorization_url
        .query_pairs()
        .into_owned()
        .collect::<HashMap<_, _>>();
    assert_eq!(parameters["client_id"], "client");
    assert!(!parameters.contains_key("scope"));
    assert!(parameters.contains_key("state"));
    assert!(parameters.contains_key("code_challenge"));

    app.db
        .put_upstream_oauth_token(
            &oauth,
            &UpstreamOAuthToken {
                access_token_ciphertext: app.secrets.seal(b"access").unwrap(),
                refresh_token_ciphertext: None,
                token_type: "Bearer".into(),
                scope: "mcp".into(),
                expires_at: Some(chrono::Utc::now().timestamp() + 3600),
                refresh_expires_at: None,
            },
        )
        .unwrap();
    let connected = catalog(&app, &chatgpt)
        .await
        .unwrap()
        .search("needs-oauth")
        .await
        .unwrap();
    assert_eq!(connected[0]["clientAccessGranted"], false);
    assert_eq!(
        connected[0]["requiredScope"],
        format!("integration:{oauth}")
    );
    assert!(connected[0].get("authorization_url").is_none());
    let result = admin_authorize(&app, &user, &oauth).await.unwrap();
    assert_eq!(result["alreadyConnected"], true);
    assert!(result.get("authorization_url").is_none());
    app.db.delete_integration(&oauth, &user).unwrap();
    assert_eq!(upstream_authorization(&app, "missing").await.unwrap(), None);
    assert_eq!(
        well_known(
            &"https://issuer.example".parse().unwrap(),
            "oauth-authorization-server"
        )
        .unwrap()
        .path(),
        "/.well-known/oauth-authorization-server"
    );

    let stdio = app
        .db
        .create_integration(
            &user,
            "local",
            "stdio",
            &json!({"command":"echo","args":[]}),
            None,
        )
        .unwrap();
    assert!(catalog(&app, &auth).await.is_err());
    app.db.delete_integration(&stdio, &user).unwrap();
    app.config.allow_stdio = true;
    let stdio = app
        .db
        .create_integration(
            &user,
            "local-enabled",
            "stdio",
            &json!({"command":"echo","args":[]}),
            None,
        )
        .unwrap();
    assert!(catalog(&app, &auth).await.is_ok());
    app.db.delete_integration(&stdio, &user).unwrap();
}

#[tokio::test]
async fn administration_provider_is_least_privilege_and_redacts_secrets() {
    let (app, _directory) = route_test_app().await;
    let user = app.db.create_user("least@example.com", "hash").unwrap();
    let id = app.db.create_integration(&user, "Cloudflare", "http", &json!({"url":"https://example.com/mcp","access_token":"never","nested":{"client_secret":"never"}}), Some("ciphertext-never")).unwrap();
    let read = AdminProvider {
        app: app.clone(),
        auth: AuthContext {
            user: user.clone(),
            agent: "test-agent".into(),
            identity: "test-identity".into(),
            client: "test-client".into(),
            scopes: HashSet::from(["integrations:read".into()]),
            integrations: HashSet::new(),
        },
    };
    let names = read
        .tools()
        .await
        .unwrap()
        .into_iter()
        .map(|tool| (tool.name, tool.extra))
        .collect::<HashMap<_, _>>();
    assert!(names.contains_key("integrations_list"));
    assert!(names.contains_key("integration_delete"));
    assert_eq!(
        names["integration_delete"]["x-cog-clientAccessGranted"],
        false
    );
    assert_eq!(
        names["integration_delete"]["x-cog-requiredScope"],
        "integrations:write"
    );
    assert!(
        read.call("integration_delete", json!({"id":id}))
            .await
            .unwrap_err()
            .downcast_ref::<crate::authz::InsufficientScope>()
            .is_some()
    );
    let mut code_catalog = Catalog::new();
    code_catalog.add_labeled(
        "cog".into(),
        "Clanker Operations Gateway administration".into(),
        Arc::new(AdminProvider {
            app: app.clone(),
            auth: read.auth.clone(),
        }),
    );
    let discovered = code_catalog.search("integration_delete").await.unwrap();
    assert_eq!(discovered[0]["target"], "cog.integration_delete");
    assert_eq!(discovered[0]["clientAccessGranted"], false);
    assert_eq!(discovered[0]["requiredScope"], "integrations:write");
    assert!(
        code_catalog
            .call("cog.integration_delete", json!({"id":id}))
            .await
            .unwrap_err()
            .downcast_ref::<crate::authz::InsufficientScope>()
            .is_some()
    );
    let value = read
        .call("integration_get", json!({"id":id}))
        .await
        .unwrap();
    let encoded = value.to_string();
    assert!(!encoded.contains("never"));
    assert!(!encoded.contains("ciphertext"));
}

#[tokio::test]
async fn administration_provider_exercises_every_database_backed_operation() {
    let (app, _directory) = route_test_app().await;
    let user = app
        .db
        .create_user("admin-tools@example.com", "hash")
        .unwrap();
    app.db
        .register_client(
            "admin-tools",
            Some(&user),
            "admin tools",
            &["http://localhost/callback".into()],
        )
        .unwrap();
    app.db
        .store_access_token(
            &token_hash("admin-tools-token"),
            "admin-tools",
            &user,
            "mcp integrations:read integrations:write agents:read agents:write audit:read",
            chrono::Utc::now().timestamp() + 3600,
            None,
            None,
        )
        .unwrap();
    let provider = AdminProvider {
        app: app.clone(),
        auth: AuthContext {
            user: user.clone(),
            agent: "test-agent".into(),
            identity: "test-identity".into(),
            client: "admin-tools".into(),
            scopes: HashSet::from([
                "mcp".into(),
                "integrations:read".into(),
                "integrations:write".into(),
                "agents:read".into(),
                "agents:write".into(),
                "audit:read".into(),
            ]),
            integrations: HashSet::new(),
        },
    };

    assert_eq!(provider.advertised_tools().await.unwrap().len(), 19);
    assert_eq!(provider.tools().await.unwrap().len(), 19);
    let created = provider
        .call(
            "integration_create",
            json!({"name":"fixture","transport":"http","config":{"url":"http://localhost:9876/mcp"}}),
        )
        .await
        .unwrap();
    let id = created["id"].as_str().unwrap().to_owned();
    assert_eq!(
        provider
            .call("integrations_list", json!({}))
            .await
            .unwrap()
            .as_array()
            .unwrap()
            .len(),
        1
    );
    assert_eq!(
        provider
            .call("integration_get", json!({"id":id}))
            .await
            .unwrap()["name"],
        "fixture"
    );
    provider
        .call(
            "integration_update",
            json!({"id":id,"name":"renamed","config":{"url":"http://localhost:9877/mcp"}}),
        )
        .await
        .unwrap();
    provider
        .call("integration_set_enabled", json!({"id":id,"enabled":false}))
        .await
        .unwrap();
    provider
        .call("integration_disconnect", json!({"id":id}))
        .await
        .unwrap();

    assert!(
        provider
            .call("agents_list", json!({}))
            .await
            .unwrap()
            .is_array()
    );
    let tokens = provider.call("tokens_list", json!({})).await.unwrap();
    assert!(tokens.is_array());
    assert!(
        provider
            .call("audit_list", json!({"limit":10}))
            .await
            .unwrap()
            .is_array()
    );

    app.db
        .register_client(
            "revoke-client",
            Some(&user),
            "revoke me",
            &["http://localhost/revoke".into()],
        )
        .unwrap();
    app.db
        .store_access_token(
            &token_hash("revoke-token"),
            "revoke-client",
            &user,
            "mcp",
            chrono::Utc::now().timestamp() + 3600,
            None,
            None,
        )
        .unwrap();
    let token_id = app
        .db
        .agent_tokens(&user)
        .unwrap()
        .into_iter()
        .find(|token| token.client_id == "revoke-client")
        .unwrap()
        .token_id;
    provider
        .call("token_revoke", json!({"id":token_id}))
        .await
        .unwrap();
    app.db
        .register_client(
            "revoke-client-only",
            Some(&user),
            "revoke client",
            &["http://localhost/revoke-client".into()],
        )
        .unwrap();
    app.db
        .store_access_token(
            &token_hash("revoke-client-token"),
            "revoke-client-only",
            &user,
            "mcp",
            chrono::Utc::now().timestamp() + 3600,
            None,
            None,
        )
        .unwrap();
    provider
        .call("agent_revoke", json!({"id":"revoke-client-only"}))
        .await
        .unwrap();

    app.db
        .grant_client_integration(&user, "admin-tools", &id)
        .unwrap();
    provider
        .call(
            "identity_grant_revoke",
            json!({"client_id":"admin-tools","integration_id":id}),
        )
        .await
        .unwrap();
    provider
        .call("integration_delete", json!({"id":id}))
        .await
        .unwrap();
    assert!(provider.call("does_not_exist", json!({})).await.is_err());
}

#[test]
fn native_administration_tools_have_precise_safety_and_scope_metadata() {
    let create = admin_tool("integration_create", "Create an integration.");
    assert_eq!(create.extra["annotations"]["readOnlyHint"], false);
    assert_eq!(create.extra["annotations"]["destructiveHint"], false);
    assert_eq!(create.extra["annotations"]["openWorldHint"], true);
    assert_eq!(
        create.extra["securitySchemes"][0]["scopes"],
        json!(["integrations:write"])
    );
    assert_eq!(
        create.extra["_meta"]["securitySchemes"],
        create.extra["securitySchemes"]
    );
    assert_eq!(
        create.input_schema["required"],
        json!(["name", "transport", "config"])
    );
    let audit = admin_tool("audit_list", "Read recent audit events.");
    assert_eq!(audit.input_schema["properties"]["limit"]["maximum"], 1000);
    assert_eq!(
        native_admin_scope("cog_integration_create"),
        Some("integrations:write")
    );
    assert_eq!(
        native_admin_scope("cog_integrations_list"),
        Some("integrations:read")
    );
    assert_eq!(native_admin_scope("execute"), None);

    let disconnect = admin_tool(
        "integration_disconnect",
        "Disconnect credentials while preserving the integration.",
    );
    assert_eq!(disconnect.extra["annotations"]["readOnlyHint"], false);
    assert_eq!(disconnect.extra["annotations"]["destructiveHint"], true);
    assert_eq!(disconnect.extra["annotations"]["idempotentHint"], true);
    assert_eq!(disconnect.extra["annotations"]["openWorldHint"], false);
    assert_eq!(
        disconnect.extra["securitySchemes"][0]["scopes"],
        json!(["integrations:write"])
    );
    assert_eq!(
        disconnect.extra["_meta"]["securitySchemes"],
        disconnect.extra["securitySchemes"]
    );
}

#[tokio::test]
async fn disconnect_is_idempotent_preserves_target_and_grant_while_delete_removes_both() {
    let (app, _directory) = route_test_app().await;
    let user = app
        .db
        .create_user("disconnect@example.com", "hash")
        .unwrap();
    let integration = app
        .db
        .create_integration(
            &user,
            "Cloudflare",
            "http",
            &json!({"url":"http://localhost:9999/mcp","oauth":{"client_id":"fixture"}}),
            Some(
                &app.secrets
                    .seal(br#"{"Authorization":"Bearer secret"}"#)
                    .unwrap(),
            ),
        )
        .unwrap();
    let identity = app.db.list_identities(&user).unwrap()[0].id.clone();
    let auth = AuthContext {
        user: user.clone(),
        agent: "test-agent".into(),
        identity,
        client: "agent".into(),
        scopes: HashSet::from(["mcp".into(), "integrations:write".into()]),
        integrations: HashSet::from([integration.clone()]),
    };
    app.db
        .put_upstream_oauth_token(
            &integration,
            &UpstreamOAuthToken {
                access_token_ciphertext: app.secrets.seal(b"first-access").unwrap(),
                refresh_token_ciphertext: None,
                token_type: "Bearer".into(),
                scope: "mcp".into(),
                expires_at: Some(chrono::Utc::now().timestamp() + 3600),
                refresh_expires_at: None,
            },
        )
        .unwrap();
    app.providers
        .lock()
        .await
        .insert(integration.clone(), Arc::new(PolicyFixture));
    let admin = AdminProvider {
        app: app.clone(),
        auth: auth.clone(),
    };

    for _ in 0..2 {
        let disconnected = admin
            .call("integration_disconnect", json!({"id":integration}))
            .await
            .unwrap();
        assert_eq!(disconnected["id"], integration);
        assert_eq!(disconnected["upstreamConnected"], false);
        assert_eq!(disconnected["upstreamStatus"], "disconnected");
        let discovery = catalog(&app, &auth)
            .await
            .unwrap()
            .search("Cloudflare")
            .await
            .unwrap();
        assert_eq!(discovery[0]["integration"], integration);
        assert_eq!(discovery[0]["clientAccessGranted"], true);
    }

    // Reauthorization attaches a provider to the same durable integration,
    // so the previously granted immutable target immediately works again.
    app.db
        .put_upstream_oauth_token(
            &integration,
            &UpstreamOAuthToken {
                access_token_ciphertext: app.secrets.seal(b"second-access").unwrap(),
                refresh_token_ciphertext: None,
                token_type: "Bearer".into(),
                scope: "mcp".into(),
                expires_at: Some(chrono::Utc::now().timestamp() + 3600),
                refresh_expires_at: None,
            },
        )
        .unwrap();
    let mut reauthorized = Catalog::new();
    reauthorized.add_labeled(
        integration.clone(),
        "Cloudflare".into(),
        Arc::new(PolicyFixture),
    );
    assert_eq!(
        reauthorized
            .call(&format!("{integration}.read"), json!({}))
            .await
            .unwrap(),
        "read"
    );

    admin
        .call("integration_delete", json!({"id":integration}))
        .await
        .unwrap();
    assert!(app.db.integration(&integration, &user).unwrap().is_none());
    assert!(
        catalog(&app, &auth)
            .await
            .unwrap()
            .call(&format!("{integration}.read"), json!({}))
            .await
            .is_err()
    );
}

#[test]
fn integration_ui_distinguishes_disconnect_from_permanent_delete() {
    let source = include_str!("../../frontend/src/main.jsx");
    assert!(source.contains("Disconnect credentials but preserve this connection?"));
    assert!(source.contains("Delete this connection and every descendant?"));
    assert!(source.contains("all of its connections, agents, credentials, and grants"));
    assert!(source.contains("function Consent()"));
    assert!(source.contains("payload.identities[0]?.id"));
    assert!(source.contains("identity === \"\""));
    assert!(source.contains("action=\"/api/oauth/consent\""));
    assert!(source.contains("function GitHubInstallationComplete()"));
    assert!(source.contains("/github/app/installation/complete"));
}

#[test]
fn integration_access_follows_identity_membership_without_incremental_scope() {
    let integration = "identity-integration".to_owned();
    let auth = AuthContext {
        user: "user".into(),
        agent: "agent".into(),
        client: "client".into(),
        identity: "identity".into(),
        scopes: HashSet::from(["mcp".into()]),
        integrations: HashSet::from([integration.clone()]),
    };
    assert!(auth.allows_integration(&integration));
    assert!(!auth.allows_integration("another-integration"));
}

#[tokio::test]
async fn repeated_scope_challenge_after_consent_is_bounded_and_preserves_credentials() {
    let (app, _directory) = route_test_app().await;
    let user = app
        .db
        .create_user("bounded-step-up@example.com", "hash")
        .unwrap();
    let integration = app
        .db
        .create_integration(
            &user,
            "Cloudflare",
            "http",
            &json!({"url":"https://example.com/mcp"}),
            None,
        )
        .unwrap();
    let ciphertext = app.secrets.seal(b"still-valid").unwrap();
    app.db
        .put_upstream_oauth_token(
            &integration,
            &UpstreamOAuthToken {
                access_token_ciphertext: ciphertext.clone(),
                refresh_token_ciphertext: None,
                token_type: "Bearer".into(),
                scope: "mcp workers:write".into(),
                expires_at: Some(chrono::Utc::now().timestamp() + 3600),
                refresh_expires_at: None,
            },
        )
        .unwrap();
    let provider = OAuthStepUpProvider {
        inner: Arc::new(ScopeChallengeFixture {
            challenge: UpstreamInsufficientScope {
                scopes: vec!["workers:write".into()],
                resource_metadata: "https://example.com/.well-known/oauth-protected-resource"
                    .into(),
            },
        }),
        app: app.clone(),
        user,
        integration: integration.clone(),
    };
    let error = provider
        .call("search", json!({}))
        .await
        .unwrap_err()
        .to_string();
    assert!(error.contains("retried once"));
    assert!(!error.contains("https://"));
    assert_eq!(
        app.db
            .upstream_oauth_token(&integration)
            .unwrap()
            .unwrap()
            .access_token_ciphertext,
        ciphertext
    );
}

#[tokio::test]
async fn browser_health_assets_and_identity_lifecycles() {
    let (app, _directory) = route_test_app().await;
    create_user_record(
        &app.db,
        "browser@example.com",
        "correct horse battery staple",
    )
    .unwrap();
    app.replicator.sync().await.unwrap();
    let router = build_router(app.clone());

    for path in [
        "/",
        "/login",
        "/healthz",
        "/readyz",
        "/version",
        "/metrics",
        "/.well-known/oauth-authorization-server",
        "/.well-known/oauth-protected-resource",
        "/.well-known/oauth-client",
        "/oauth/authorize",
        "/github/app/installation/complete",
    ] {
        let response = router
            .clone()
            .oneshot(
                axum::http::Request::get(path)
                    .body(axum::body::Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK, "{path}");
    }
    assert_eq!(
        request_status(
            &router,
            http::Method::GET,
            "/ui/assets/missing.js",
            None,
            None,
            ""
        )
        .await,
        StatusCode::NOT_FOUND
    );
    assert_eq!(
        request_status(
            &router,
            http::Method::GET,
            "/ui/assets/../index.html",
            None,
            None,
            ""
        )
        .await,
        StatusCode::OK
    );

    let login = router
        .clone()
        .oneshot(
            axum::http::Request::post("/login")
                .header(http::header::ORIGIN, "http://localhost:4788")
                .header(
                    http::header::CONTENT_TYPE,
                    "application/x-www-form-urlencoded",
                )
                .body(axum::body::Body::from(encoded_form(&[
                    ("email", "browser@example.com"),
                    ("password", "correct horse battery staple"),
                ])))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(login.status(), StatusCode::SEE_OTHER);
    let set_cookies = login
        .headers()
        .get_all(http::header::SET_COOKIE)
        .iter()
        .map(|value| value.to_str().unwrap().split(';').next().unwrap())
        .collect::<Vec<_>>();
    let cookie_header = set_cookies.join("; ");
    let csrf = set_cookies
        .iter()
        .find_map(|cookie| cookie.strip_prefix("cog_csrf="))
        .unwrap()
        .to_owned();
    let origin = "http://localhost:4788";
    let post_form = |path: String, pairs: Vec<(&str, &str)>| {
        axum::http::Request::post(path)
            .header(http::header::ORIGIN, origin)
            .header(http::header::COOKIE, &cookie_header)
            .header(
                http::header::CONTENT_TYPE,
                "application/x-www-form-urlencoded",
            )
            .body(axum::body::Body::from(encoded_form(&pairs)))
            .unwrap()
    };

    let bootstrap = router
        .clone()
        .oneshot(
            axum::http::Request::get("/api/ui")
                .header(http::header::COOKIE, &cookie_header)
                .body(axum::body::Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response_json(bootstrap).await["mode"], "admin");

    let created = router
        .clone()
        .oneshot(post_form(
            "/ui/identities".into(),
            vec![("name", "Primary"), ("csrf_token", &csrf)],
        ))
        .await
        .unwrap();
    assert_eq!(created.status(), StatusCode::NO_CONTENT);
    let user = app
        .db
        .user_by_email("browser@example.com")
        .unwrap()
        .unwrap()
        .0;
    app.db
        .register_client(
            "browser-agent",
            Some(&user),
            "Browser Agent",
            &["http://localhost/callback".into()],
        )
        .unwrap();
    let agent = app.db.agent_for_client("browser-agent").unwrap().unwrap();
    let identity = app.db.list_identities(&user).unwrap().pop().unwrap();
    let renamed = router
        .clone()
        .oneshot(post_form(
            format!("/ui/identities/{}/rename", identity.id),
            vec![("name", "Renamed"), ("csrf_token", &csrf)],
        ))
        .await
        .unwrap();
    assert_eq!(renamed.status(), StatusCode::NO_CONTENT);
    let missing = router
        .clone()
        .oneshot(post_form(
            "/ui/identities/missing/rename".into(),
            vec![("name", "Nope"), ("csrf_token", &csrf)],
        ))
        .await
        .unwrap();
    assert_eq!(missing.status(), StatusCode::NOT_FOUND);
    let invalid_rename = router
        .clone()
        .oneshot(post_form(
            format!("/ui/identities/{}/rename", identity.id),
            vec![("name", "  "), ("csrf_token", &csrf)],
        ))
        .await
        .unwrap();
    assert_eq!(invalid_rename.status(), StatusCode::BAD_REQUEST);
    let renamed_agent = router
        .clone()
        .oneshot(post_form(
            format!("/ui/agents/{}/rename", agent.id),
            vec![("name", "Renamed Agent"), ("csrf_token", &csrf)],
        ))
        .await
        .unwrap();
    assert_eq!(renamed_agent.status(), StatusCode::NO_CONTENT);
    let missing_agent = router
        .clone()
        .oneshot(post_form(
            "/ui/agents/missing/rename".into(),
            vec![("name", "Nope"), ("csrf_token", &csrf)],
        ))
        .await
        .unwrap();
    assert_eq!(missing_agent.status(), StatusCode::NOT_FOUND);
    let invalid_agent = router
        .clone()
        .oneshot(post_form(
            format!("/ui/agents/{}/rename", agent.id),
            vec![("name", ""), ("csrf_token", &csrf)],
        ))
        .await
        .unwrap();
    assert_eq!(invalid_agent.status(), StatusCode::BAD_REQUEST);

    let prepared = router
        .clone()
        .oneshot(post_form(
            "/ui/ssh/host/prepare".into(),
            vec![("csrf_token", &csrf)],
        ))
        .await
        .unwrap();
    assert!(prepared.status().is_redirection());
    let key = app
        .db
        .ssh_keys()
        .unwrap()
        .into_iter()
        .find(|key| key.purpose == "host" && !key.active)
        .unwrap();
    let activated = router
        .clone()
        .oneshot(post_form(
            format!("/ui/ssh/host/{}/activate", key.id),
            vec![("csrf_token", &csrf)],
        ))
        .await
        .unwrap();
    assert!(activated.status().is_redirection());
    let retired = router
        .clone()
        .oneshot(post_form(
            format!("/ui/ssh/host/{}/retire", key.id),
            vec![("csrf_token", &csrf)],
        ))
        .await
        .unwrap();
    assert_eq!(retired.status(), StatusCode::BAD_REQUEST);
    let invalid_key = router
        .clone()
        .oneshot(post_form(
            "/ui/ssh/invalid/prepare".into(),
            vec![("csrf_token", &csrf)],
        ))
        .await
        .unwrap();
    assert_eq!(invalid_key.status(), StatusCode::BAD_REQUEST);

    let deleted = router
        .clone()
        .oneshot(post_form(
            format!("/ui/identities/{}/delete", identity.id),
            vec![("csrf_token", &csrf)],
        ))
        .await
        .unwrap();
    assert_eq!(deleted.status(), StatusCode::NO_CONTENT);
    let logout = router
        .clone()
        .oneshot(post_form("/logout".into(), vec![("csrf_token", &csrf)]))
        .await
        .unwrap();
    assert_eq!(logout.status(), StatusCode::SEE_OTHER);
}

#[tokio::test]
async fn login_readiness_assets_and_connection_state_boundaries() {
    let (mut app, _directory) = route_test_app().await;
    create_user_record(&app.db, "boundary@example.com", "correct password value").unwrap();
    app.replicator.sync().await.unwrap();
    let router = build_router(app.clone());
    let login_request = |origin: &str, email: &str, password: &str| {
        Request::post("/login")
            .header(http::header::ORIGIN, origin)
            .header(
                http::header::CONTENT_TYPE,
                "application/x-www-form-urlencoded",
            )
            .body(Body::from(encoded_form(&[
                ("email", email),
                ("password", password),
            ])))
            .unwrap()
    };
    assert_eq!(
        router
            .clone()
            .oneshot(login_request(
                "https://evil.example",
                "boundary@example.com",
                "correct password value",
            ))
            .await
            .unwrap()
            .status(),
        StatusCode::FORBIDDEN
    );
    assert_eq!(
        router
            .clone()
            .oneshot(login_request(
                "http://localhost:4788",
                "missing@example.com",
                "wrong",
            ))
            .await
            .unwrap()
            .status(),
        StatusCode::UNAUTHORIZED
    );
    for _ in 0..9 {
        let response = router
            .clone()
            .oneshot(login_request(
                "http://localhost:4788",
                "boundary@example.com",
                "wrong",
            ))
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
    }
    assert_eq!(
        router
            .oneshot(login_request(
                "http://localhost:4788",
                "boundary@example.com",
                "wrong",
            ))
            .await
            .unwrap()
            .status(),
        StatusCode::TOO_MANY_REQUESTS
    );

    app.config.ssh_listen = Some("127.0.0.1:2222".parse().unwrap());
    assert_eq!(
        readiness(State(app.clone())).await.into_response().status(),
        StatusCode::SERVICE_UNAVAILABLE
    );
    app.ssh_ready.store(true, Ordering::Release);
    assert_eq!(
        readiness(State(app.clone())).await.into_response().status(),
        StatusCode::OK
    );

    let js = Frontend::iter().find(|path| path.ends_with(".js")).unwrap();
    let css = Frontend::iter()
        .find(|path| path.ends_with(".css"))
        .unwrap();
    assert_eq!(
        frontend_response(js.as_ref()).headers()[http::header::CONTENT_TYPE],
        "text/javascript; charset=utf-8"
    );
    assert_eq!(
        frontend_response(css.as_ref()).headers()[http::header::CONTENT_TYPE],
        "text/css; charset=utf-8"
    );
    assert_eq!(
        frontend_response("missing.bin").status(),
        StatusCode::NOT_FOUND
    );

    let user = app
        .db
        .user_by_email("boundary@example.com")
        .unwrap()
        .unwrap()
        .0;
    let setup = app
        .db
        .create_integration(
            &user,
            "Git setup",
            "git",
            &json!({"kind":"git","providerConfig":{"appId":"1"}}),
            None,
        )
        .unwrap();
    let setup = app.db.integration(&setup, &user).unwrap().unwrap();
    assert_eq!(
        upstream_connection_state(&app, &setup),
        ("setup_required", false)
    );
    let configured = app
        .db
        .create_integration(
            &user,
            "Git configured",
            "git",
            &json!({"kind":"git","providerConfig":{"appId":"1","installationId":"2"}}),
            Some("sealed"),
        )
        .unwrap();
    let configured = app.db.integration(&configured, &user).unwrap().unwrap();
    assert_eq!(
        upstream_connection_state(&app, &configured),
        ("configured", true)
    );

    let oauth = app
        .db
        .create_integration(
            &user,
            "Expired OAuth",
            "http",
            &json!({"url":"http://localhost/mcp","oauth":{}}),
            None,
        )
        .unwrap();
    app.db
        .put_upstream_oauth_token(
            &oauth,
            &UpstreamOAuthToken {
                access_token_ciphertext: app.secrets.seal(b"expired").unwrap(),
                refresh_token_ciphertext: None,
                token_type: "Bearer".into(),
                scope: "mcp".into(),
                expires_at: Some(chrono::Utc::now().timestamp() - 1),
                refresh_expires_at: None,
            },
        )
        .unwrap();
    let oauth = app.db.integration(&oauth, &user).unwrap().unwrap();
    assert_eq!(upstream_connection_state(&app, &oauth), ("expired", false));
}

#[tokio::test]
async fn github_callback_and_setup_rejections_are_bounded() {
    let (app, _directory) = route_test_app().await;
    let router = build_router(app.clone());

    let cases = [
        (
            format!("/github/app/setup/{}", "x".repeat(257)),
            StatusCode::BAD_REQUEST,
        ),
        ("/github/app/setup/unknown".into(), StatusCode::BAD_REQUEST),
        (
            "/github/app/manifest/callback?code=x&state=unknown".into(),
            StatusCode::BAD_REQUEST,
        ),
        (
            format!(
                "/github/app/manifest/callback?code={}&state=x",
                "x".repeat(513)
            ),
            StatusCode::BAD_REQUEST,
        ),
        (
            "/github/app/installation/callback?installation_id=&state=x".into(),
            StatusCode::BAD_REQUEST,
        ),
        (
            "/github/app/installation/callback?installation_id=abc&state=x".into(),
            StatusCode::BAD_REQUEST,
        ),
        (
            "/github/app/installation/callback?installation_id=1&state=x&setup_action=remove"
                .into(),
            StatusCode::BAD_REQUEST,
        ),
        (
            "/github/app/installation/callback?installation_id=1&state=unknown".into(),
            StatusCode::BAD_REQUEST,
        ),
    ];
    for (uri, expected) in cases {
        let response = router
            .clone()
            .oneshot(Request::get(uri).body(Body::empty()).unwrap())
            .await
            .unwrap();
        assert_eq!(response.status(), expected);
        assert!(response_text(response).await.len() < 1_024);
    }

    for slug in ["", "Upper", "under_score", "slash/name", "dot.name"] {
        assert!(github_app_install_url(slug).is_err(), "{slug}");
    }
    assert_eq!(
        github_app_install_url("valid-app-123").unwrap(),
        "https://github.com/apps/valid-app-123/installations/new"
    );
}

#[tokio::test]
async fn upstream_callback_rejections_do_not_reflect_secrets() {
    let (app, _directory) = route_test_app().await;
    let router = build_router(app);
    let cases = [
        (
            "/oauth/upstream/callback?state=x&error=denied&error_description=provider-secret",
            "provider-secret",
        ),
        ("/oauth/upstream/callback?state=x", ""),
        (
            "/oauth/upstream/callback?state=unknown&code=provider-secret",
            "provider-secret",
        ),
    ];
    for (uri, secret) in cases {
        let response = router
            .clone()
            .oneshot(Request::get(uri).body(Body::empty()).unwrap())
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::BAD_REQUEST);
        let body = response_text(response).await;
        if !secret.is_empty() && !uri.contains("error_description") {
            assert!(!body.contains(secret));
        }
        assert!(body.len() < 16 * 1_024);
    }
}

#[test]
fn oauth_uri_transport_and_redaction_boundaries() {
    for accepted in [
        "https://example.com/path?query=ok",
        "http://localhost:1234/path",
        "http://127.0.0.1/path",
    ] {
        validate_oauth_uri(&accepted.parse().unwrap(), "test URI").unwrap();
    }
    for rejected in [
        "relative/path",
        "https://user@example.com/path",
        "https://example.com/path#fragment",
        "http://example.com/path",
        "ftp://example.com/path",
        "http://[::1]/path",
    ] {
        let uri = url::Url::parse(rejected)
            .unwrap_or_else(|_| url::Url::parse("file:///relative/path").unwrap());
        assert!(validate_oauth_uri(&uri, "test URI").is_err(), "{rejected}");
    }

    let redacted = redact_value(json!({
        "safe": {"value": 1},
        "items": [{"token":"hidden", "visible":true}],
        "clientSecret":"hidden",
        "ciphertext":"hidden",
        "headers":{"Authorization":"hidden"},
        "authorization":"hidden"
    }));
    assert_eq!(redacted["safe"]["value"], 1);
    assert_eq!(redacted["items"][0]["visible"], true);
    assert!(redacted["items"][0].get("token").is_none());
    for key in ["clientSecret", "ciphertext", "headers", "authorization"] {
        assert!(redacted.get(key).is_none(), "{key}");
    }

    let valid = [
        ("http", json!({"url":"https://example.com/mcp"}), false),
        ("sse", json!({"url":"https://example.com/sse"}), false),
        ("stdio", json!({"command":"safe-command","args":[]}), true),
    ];
    for (transport, config, allow_stdio) in valid {
        validate_transport(transport, &config, None, allow_stdio).unwrap();
    }
    let invalid = [
        ("unknown", json!({}), false),
        ("http", json!({}), false),
        ("http", json!({"url":"file:///tmp/socket"}), false),
        ("stdio", json!({"command":"safe-command"}), false),
        ("stdio", json!({"command":"   "}), true),
    ];
    for (transport, config, allow_stdio) in invalid {
        assert!(
            validate_transport(transport, &config, None, allow_stdio).is_err(),
            "{transport}: {config}"
        );
    }
    assert!(
        validate_transport(
            "http",
            &json!({"url":"https://example.com"}),
            Some(&HashMap::from([("bad header\n".into(), "value".into())])),
            false,
        )
        .is_err()
    );
}

#[cfg(unix)]
#[tokio::test]
async fn github_manifest_and_installation_callbacks_complete_against_mock_api() {
    async fn conversion(Path(code): Path<String>, State(pem): State<String>) -> Response {
        match code.as_str() {
            "rejected" => StatusCode::BAD_REQUEST.into_response(),
            "malformed" => "not-json".into_response(),
            "incomplete" => Json(json!({"id":42})).into_response(),
            "bad-credentials" => {
                Json(json!({"id":42,"slug":"INVALID_SLUG","pem":"bad"})).into_response()
            }
            _ => Json(json!({"id":42,"slug":"cog-fixture","pem":pem})).into_response(),
        }
    }
    let directory = tempfile::tempdir().unwrap();
    let pem_path = directory.path().join("github.pem");
    let generated = std::process::Command::new("openssl")
        .args(["genrsa", "-traditional", "-out"])
        .arg(&pem_path)
        .arg("2048")
        .output()
        .unwrap();
    assert!(generated.status.success());
    let pem = std::fs::read_to_string(&pem_path).unwrap();
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    let provider = tokio::spawn(
        axum::serve(
            listener,
            Router::new()
                .route("/app-manifests/{code}/conversions", post(conversion))
                .with_state(pem),
        )
        .into_future(),
    );
    let (mut app, _app_directory) = route_test_app().await;
    app.github_api_base = format!("http://{address}/").parse().unwrap();
    let user = app
        .db
        .create_user("github-flow@example.com", "hash")
        .unwrap();
    for (code, expected) in [
        ("rejected", StatusCode::BAD_GATEWAY),
        ("malformed", StatusCode::BAD_GATEWAY),
        ("incomplete", StatusCode::BAD_GATEWAY),
        ("bad-credentials", StatusCode::BAD_GATEWAY),
    ] {
        let failed = admin_github_app_setup_start(&app, &user, json!({"name":code}))
            .await
            .unwrap();
        let failed_state = failed["browserUrl"]
            .as_str()
            .unwrap()
            .rsplit('/')
            .next()
            .unwrap();
        let response = build_router(app.clone())
            .oneshot(
                Request::get(format!(
                    "/github/app/manifest/callback?code={code}&state={failed_state}"
                ))
                .body(Body::empty())
                .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), expected, "{code}");
    }
    let setup = admin_github_app_setup_start(&app, &user, json!({"name":"GitHub"}))
        .await
        .unwrap();
    let state = setup["browserUrl"]
        .as_str()
        .unwrap()
        .rsplit('/')
        .next()
        .unwrap()
        .to_owned();
    let router = build_router(app.clone());
    let launch = router
        .clone()
        .oneshot(
            Request::get(format!("/github/app/setup/{state}"))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(launch.status(), StatusCode::OK);
    assert!(response_text(launch).await.contains("github-manifest"));
    let manifest = router
        .clone()
        .oneshot(
            Request::get(format!(
                "/github/app/manifest/callback?code=conversion-code&state={state}"
            ))
            .body(Body::empty())
            .unwrap(),
        )
        .await
        .unwrap();
    assert!(manifest.status().is_redirection());
    assert_eq!(
        manifest.headers()[http::header::LOCATION],
        "https://github.com/apps/cog-fixture/installations/new"
    );
    let integration = setup["id"].as_str().unwrap();
    let status = admin_github_app_setup_status(&app, &user, integration)
        .await
        .unwrap();
    assert_eq!(status["status"], "installation_pending");
    assert_eq!(status["credentialsConfigured"], true);
    let installed = router
        .clone()
        .oneshot(Request::get(format!("/github/app/installation/callback?installation_id=99&state={state}&setup_action=install")).body(Body::empty()).unwrap())
        .await
        .unwrap();
    assert!(installed.status().is_redirection());
    assert!(
        installed.headers()[http::header::LOCATION]
            .to_str()
            .unwrap()
            .contains(integration)
    );
    let status = admin_github_app_setup_status(&app, &user, integration)
        .await
        .unwrap();
    assert_eq!(status["status"], "installed");
    let installed_integration = app.db.integration(integration, &user).unwrap().unwrap();
    assert!(git_provider(&app, &installed_integration).await.is_ok());
    assert!(app.git_providers.lock().await.contains_key(integration));
    assert_eq!(
        installed_integration.config["providerConfig"]["installationId"],
        "99"
    );
    let replay = router
        .oneshot(
            Request::get(format!(
                "/github/app/installation/callback?installation_id=99&state={state}"
            ))
            .body(Body::empty())
            .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(replay.status(), StatusCode::BAD_REQUEST);
    provider.abort();
}

#[tokio::test]
async fn upstream_oauth_callback_exchanges_and_stores_rotating_tokens() {
    async fn exchange(body: String) -> Json<Value> {
        assert!(body.contains("grant_type=authorization_code"));
        assert!(body.contains("code=provider-code"));
        assert!(body.contains("code_verifier=pkce-verifier"));
        assert!(body.contains("client_secret=provider-secret"));
        Json(
            json!({"access_token":"provider-access","refresh_token":"provider-refresh","token_type":"bearer","scope":"read write","expires_in":60,"refresh_expires_in":120}),
        )
    }
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    let provider = tokio::spawn(
        axum::serve(listener, Router::new().route("/token", post(exchange))).into_future(),
    );
    let (app, _directory) = route_test_app().await;
    let user = app
        .db
        .create_user("oauth-callback@example.com", "hash")
        .unwrap();
    let integration = app
        .db
        .create_integration(
            &user,
            "OAuth",
            "http",
            &json!({"url":"https://example.com/mcp","oauth":{}}),
            None,
        )
        .unwrap();
    app.db
        .put_upstream_oauth_client(
            &integration,
            &UpstreamOAuthClient {
                client_id: "provider-client".into(),
                client_secret_ciphertext: Some(app.secrets.seal(b"provider-secret").unwrap()),
                authorization_endpoint: format!("http://{address}/authorize"),
                token_endpoint: format!("http://{address}/token"),
                scope: "read".into(),
                resource: Some("https://resource.example/mcp".into()),
                issuer: Some("https://issuer.example".into()),
            },
        )
        .unwrap();
    let state = "callback-state";
    app.db
        .store_oauth_state(
            &token_hash(state),
            &user,
            &integration,
            &app.secrets.seal(b"pkce-verifier").unwrap(),
            "http://localhost:4788/oauth/upstream/callback",
            chrono::Utc::now().timestamp() + 60,
            Some("https://resource.example/mcp"),
        )
        .unwrap();
    let response = build_router(app.clone()).oneshot(Request::get(format!("/oauth/upstream/callback?code=provider-code&state={state}&iss=https%3A%2F%2Fissuer.example")).body(Body::empty()).unwrap()).await.unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    assert!(
        response_text(response)
            .await
            .contains("Connection complete")
    );
    let stored = app.db.upstream_oauth_token(&integration).unwrap().unwrap();
    assert_eq!(
        open_secret_text(&app, &stored.access_token_ciphertext).unwrap(),
        "provider-access"
    );
    assert_eq!(
        open_secret_text(&app, stored.refresh_token_ciphertext.as_deref().unwrap()).unwrap(),
        "provider-refresh"
    );
    assert_eq!(stored.scope, "read write");
    assert!(
        app.db
            .redeem_oauth_state(&token_hash(state))
            .unwrap()
            .is_none()
    );
    provider.abort();
}

#[tokio::test]
async fn upstream_scope_step_up_merges_existing_and_challenged_scopes() {
    async fn resource(State(resource): State<String>) -> Json<Value> {
        Json(json!({"resource":resource}))
    }
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    let resource_url = format!("http://{address}/mcp");
    let provider = tokio::spawn(
        axum::serve(
            listener,
            Router::new()
                .route("/metadata", get(resource))
                .with_state(resource_url.clone()),
        )
        .into_future(),
    );
    let (app, _directory) = route_test_app().await;
    let user = app.db.create_user("step-up@example.com", "hash").unwrap();
    let integration = app
        .db
        .create_integration(
            &user,
            "OAuth",
            "http",
            &json!({"url":resource_url,"oauth":{}}),
            None,
        )
        .unwrap();
    app.db
        .put_upstream_oauth_client(
            &integration,
            &UpstreamOAuthClient {
                client_id: "client".into(),
                client_secret_ciphertext: None,
                authorization_endpoint: format!("http://{address}/authorize"),
                token_endpoint: format!("http://{address}/token"),
                scope: "base".into(),
                resource: Some(resource_url.clone()),
                issuer: None,
            },
        )
        .unwrap();
    app.db
        .put_upstream_oauth_token(
            &integration,
            &UpstreamOAuthToken {
                access_token_ciphertext: app.secrets.seal(b"access").unwrap(),
                refresh_token_ciphertext: None,
                token_type: "Bearer".into(),
                scope: "existing".into(),
                expires_at: None,
                refresh_expires_at: None,
            },
        )
        .unwrap();
    let url = start_upstream_step_up(
        &app,
        &user,
        &integration,
        &UpstreamInsufficientScope {
            scopes: vec!["existing".into(), "extra".into()],
            resource_metadata: format!("http://{address}/metadata"),
        },
    )
    .await
    .unwrap();
    let pairs = url.query_pairs().into_owned().collect::<HashMap<_, _>>();
    assert_eq!(pairs["scope"], "base existing extra");
    assert_eq!(pairs["resource"], resource_url);
    assert_eq!(pairs["code_challenge_method"], "S256");
    assert_eq!(
        app.db
            .upstream_oauth_client(&integration)
            .unwrap()
            .unwrap()
            .scope,
        "base existing extra"
    );
    provider.abort();
}

#[tokio::test]
async fn upstream_callback_valid_state_failure_matrix_is_bounded() {
    async fn incomplete() -> Json<Value> {
        Json(json!({"token_type":"Bearer"}))
    }
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    let provider = tokio::spawn(
        axum::serve(
            listener,
            Router::new().route("/incomplete", post(incomplete)),
        )
        .into_future(),
    );
    let (app, _directory) = route_test_app().await;
    let user = app
        .db
        .create_user("callback-failures@example.com", "hash")
        .unwrap();
    let make = |name: &str| {
        app.db
            .create_integration(
                &user,
                name,
                "http",
                &json!({"url":"https://example.com/mcp","oauth":{}}),
                None,
            )
            .unwrap()
    };
    let store =
        |state: &str, integration: &str, sealed: &str, expires: i64, resource: Option<&str>| {
            app.db
                .store_oauth_state(
                    &token_hash(state),
                    &user,
                    integration,
                    sealed,
                    "http://localhost/callback",
                    expires,
                    resource,
                )
                .unwrap()
        };
    let client =
        |integration: &str, endpoint: String, resource: Option<&str>, issuer: Option<&str>| {
            app.db
                .put_upstream_oauth_client(
                    integration,
                    &UpstreamOAuthClient {
                        client_id: "client".into(),
                        client_secret_ciphertext: None,
                        authorization_endpoint: "https://issuer.example/authorize".into(),
                        token_endpoint: endpoint,
                        scope: "mcp".into(),
                        resource: resource.map(str::to_owned),
                        issuer: issuer.map(str::to_owned),
                    },
                )
                .unwrap()
        };
    let now = chrono::Utc::now().timestamp();
    let sealed = app.secrets.seal(b"verifier").unwrap();

    let expired = make("expired");
    client(&expired, format!("http://{address}/incomplete"), None, None);
    store("expired-state", &expired, &sealed, now - 1, None);
    let missing_client = make("missing-client");
    store(
        "missing-client-state",
        &missing_client,
        &sealed,
        now + 60,
        None,
    );
    let bad_seal = make("bad-seal");
    client(
        &bad_seal,
        format!("http://{address}/incomplete"),
        None,
        None,
    );
    store(
        "bad-seal-state",
        &bad_seal,
        "not-ciphertext",
        now + 60,
        None,
    );
    let changed = make("changed");
    client(
        &changed,
        format!("http://{address}/incomplete"),
        Some("https://new.example/mcp"),
        None,
    );
    store(
        "changed-state",
        &changed,
        &sealed,
        now + 60,
        Some("https://old.example/mcp"),
    );
    let issuer = make("issuer");
    client(
        &issuer,
        format!("http://{address}/incomplete"),
        None,
        Some("https://issuer.example"),
    );
    store("issuer-state", &issuer, &sealed, now + 60, None);
    let rejected = make("rejected");
    client(&rejected, format!("http://{address}/missing"), None, None);
    store("rejected-state", &rejected, &sealed, now + 60, None);
    let incomplete_id = make("incomplete");
    client(
        &incomplete_id,
        format!("http://{address}/incomplete"),
        None,
        None,
    );
    store("incomplete-state", &incomplete_id, &sealed, now + 60, None);

    for (state, iss, expected) in [
        ("expired-state", None, StatusCode::BAD_REQUEST),
        ("missing-client-state", None, StatusCode::BAD_REQUEST),
        ("bad-seal-state", None, StatusCode::BAD_REQUEST),
        ("changed-state", None, StatusCode::BAD_REQUEST),
        (
            "issuer-state",
            Some("https://evil.example"),
            StatusCode::BAD_REQUEST,
        ),
        ("rejected-state", None, StatusCode::BAD_GATEWAY),
        ("incomplete-state", None, StatusCode::BAD_GATEWAY),
    ] {
        let response = upstream_callback(
            State(app.clone()),
            Query(UpstreamCallback {
                code: Some("code".into()),
                state: state.into(),
                error: None,
                error_description: None,
                iss: iss.map(str::to_owned),
            }),
        )
        .await
        .into_response();
        assert_eq!(response.status(), expected, "{state}");
        assert!(response_text(response).await.len() < 16 * 1024);
    }
    provider.abort();
}

#[cfg(unix)]
struct SshGitFixture {
    upstream: url::Url,
}

#[cfg(unix)]
#[async_trait::async_trait]
impl GitProvider for SshGitFixture {
    async fn resolve_repository(
        &self,
        reference: &RepositoryReference,
    ) -> anyhow::Result<ResolvedRepository> {
        Ok(ResolvedRepository {
            provider_repository_id: "fixture".into(),
            display_name: reference.0.clone(),
            upstream_url: self.upstream.clone(),
            metadata: json!({"fixture":true}),
        })
    }
    async fn authorize_upstream(
        &self,
        _repository: &ResolvedRepository,
        _operation: GitOperation,
    ) -> anyhow::Result<crate::git::UpstreamAuthorization> {
        Ok(crate::git::UpstreamAuthorization::Anonymous)
    }
    fn upstream_url(&self, _repository: &ResolvedRepository) -> anyhow::Result<url::Url> {
        Ok(self.upstream.clone())
    }
}

#[cfg(unix)]
#[tokio::test]
async fn production_ssh_handler_authenticates_and_proxies_upload_pack() {
    use russh::server::Server as _;
    let upstream_listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let upstream_address = upstream_listener.local_addr().unwrap();
    async fn discovery(Query(query): Query<HashMap<String, String>>) -> impl IntoResponse {
        let service = query
            .get("service")
            .map(String::as_str)
            .unwrap_or("git-upload-pack");
        (
            [(
                http::header::CONTENT_TYPE,
                format!("application/x-{service}-advertisement"),
            )],
            format!("{:04x}# service={service}\n00000000", service.len() + 15),
        )
    }
    async fn upload_rpc() -> impl IntoResponse {
        (
            [(
                http::header::CONTENT_TYPE,
                "application/x-git-upload-pack-result",
            )],
            "PACK",
        )
    }
    async fn receive_rpc() -> impl IntoResponse {
        (
            [(
                http::header::CONTENT_TYPE,
                "application/x-git-receive-pack-result",
            )],
            "0000",
        )
    }
    let upstream_task = tokio::spawn(
        axum::serve(
            upstream_listener,
            Router::new()
                .route("/repository.git/info/refs", get(discovery))
                .route("/repository.git/git-upload-pack", post(upload_rpc))
                .route("/repository.git/git-receive-pack", post(receive_rpc)),
        )
        .into_future(),
    );

    let (mut app, directory) = route_test_app().await;
    let user = app.db.create_user("ssh-route@example.com", "hash").unwrap();
    app.db
        .register_client(
            "ssh-client",
            Some(&user),
            "SSH Agent",
            &["http://localhost/cb".into()],
        )
        .unwrap();
    let agent = app.db.agent_for_client("ssh-client").unwrap().unwrap();
    let integration = app
        .db
        .create_integration(
            &user,
            "Git",
            "git",
            &json!({"kind":"git","provider":"github"}),
            Some("sealed"),
        )
        .unwrap();
    let resolved = ResolvedRepository {
        provider_repository_id: "fixture".into(),
        display_name: "owner/repository".into(),
        upstream_url: format!("http://{upstream_address}/repository.git")
            .parse()
            .unwrap(),
        metadata: json!({}),
    };
    let repository = app
        .db
        .upsert_git_repository(&user, &integration, &resolved)
        .unwrap();
    app.db
        .set_git_grant(&user, "ssh-client", &repository.id, "write")
        .unwrap();
    app.git_providers.lock().await.insert(
        integration.clone(),
        Arc::new(SshGitFixture {
            upstream: resolved.upstream_url.clone(),
        }),
    );

    let keys = crate::git::ssh::KeySet::load_or_create(&app.db, &app.secrets).unwrap();
    let host_encoded = crate::git::ssh::encode_private(&keys.host).unwrap();
    let host_key = russh::keys::PrivateKey::from_openssh(&host_encoded).unwrap();
    let subject = crate::git::ssh::generate_key().unwrap();
    let now = chrono::Utc::now().timestamp();
    let binding = crate::git::ssh::Binding {
        version: 1,
        issuance_id: uuid::Uuid::new_v4().to_string(),
        user_id: user,
        identity_id: agent.identity_id,
        agent_id: agent.id,
        client_id: "ssh-client".into(),
        integration_id: integration,
        repository_id: repository.id.clone(),
        permission: "write".into(),
        fingerprint: crate::git::ssh::fingerprint(subject.public_key()),
        issued_at: now,
        expires_at: now + 300,
    };
    let certificate = crate::git::ssh::sign(
        &keys.user_ca,
        subject.public_key(),
        &binding,
        crate::git::ssh::stable_serial(&binding.issuance_id),
    )
    .unwrap();
    app.ssh_keys = Some(Arc::new(std::sync::RwLock::new(keys)));
    app.ssh_ready.store(true, Ordering::Release);
    app.config.ssh_listen = Some("127.0.0.1:22".parse().unwrap());
    app.config.ssh_public_host = Some("localhost".into());
    app.config.ssh_public_port = Some(22);
    let access = GitControlProvider {
        app: app.clone(),
        auth: AuthContext {
            user: binding.user_id.clone(),
            identity: binding.identity_id.clone(),
            agent: binding.agent_id.clone(),
            client: binding.client_id.clone(),
            scopes: HashSet::from([format!("integration:{}", binding.integration_id)]),
            integrations: HashSet::from([binding.integration_id.clone()]),
        },
    }
    .call(
        "repository_access",
        json!({"integrationId":binding.integration_id,"repository":"owner/repository"}),
    )
    .await
    .unwrap();
    assert_eq!(access["repositoryId"], repository.id);
    assert_eq!(access["remotes"]["ssh"]["publicPort"], 22);

    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    let config = Arc::new(russh::server::Config {
        methods: russh::MethodSet::from(&[russh::MethodKind::PublicKey][..]),
        auth_rejection_time: Duration::ZERO,
        auth_rejection_time_initial: Some(Duration::ZERO),
        keys: vec![host_key],
        ..Default::default()
    });
    let server_app = app.clone();
    let server_task = tokio::spawn(async move {
        let mut factory = SshServerFactory { app: server_app };
        factory.run_on_socket(config, &listener).await
    });

    let key_path = directory.path().join("id_ed25519");
    let cert_path = directory.path().join("id_ed25519-cert.pub");
    std::fs::write(
        &key_path,
        crate::git::ssh::encode_private(&subject).unwrap(),
    )
    .unwrap();
    std::fs::write(&cert_path, format!("{certificate}\n")).unwrap();
    use std::os::unix::fs::PermissionsExt;
    std::fs::set_permissions(&key_path, std::fs::Permissions::from_mode(0o600)).unwrap();
    let output = tokio::process::Command::new("ssh")
        .args(["-F", "/dev/null", "-i"])
        .arg(&key_path)
        .args(["-o"])
        .arg(format!("CertificateFile={}", cert_path.display()))
        .args([
            "-o",
            "StrictHostKeyChecking=no",
            "-o",
            "UserKnownHostsFile=/dev/null",
            "-o",
            "LogLevel=ERROR",
            "-p",
            &address.port().to_string(),
            "git@127.0.0.1",
            &format!("git-upload-pack '{}'", repository.id),
        ])
        .output()
        .await
        .unwrap();
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(output.stdout.starts_with(b"0000"));
    assert_eq!(app.metrics.ssh_auth_success.load(Ordering::Relaxed), 1);
    assert_eq!(app.metrics.ssh_read_operations.load(Ordering::Relaxed), 1);

    let raw_key_path = directory.path().join("raw_ed25519");
    std::fs::write(
        &raw_key_path,
        crate::git::ssh::encode_private(&subject).unwrap(),
    )
    .unwrap();
    std::fs::set_permissions(&raw_key_path, std::fs::Permissions::from_mode(0o600)).unwrap();
    let common = |identity: &std::path::Path, certificate: Option<&std::path::Path>| {
        let mut command = tokio::process::Command::new("ssh");
        command.args(["-F", "/dev/null", "-i"]).arg(identity).args([
            "-o",
            "IdentitiesOnly=yes",
            "-o",
            "StrictHostKeyChecking=no",
            "-o",
            "UserKnownHostsFile=/dev/null",
            "-o",
            "LogLevel=ERROR",
            "-p",
            &address.port().to_string(),
        ]);
        if let Some(certificate) = certificate {
            command
                .arg("-o")
                .arg(format!("CertificateFile={}", certificate.display()));
        }
        command
    };
    let mut raw = common(&raw_key_path, None);
    raw.args(["git@127.0.0.1", "true"]);
    assert!(!raw.output().await.unwrap().status.success());

    let mut wrong_user = common(&key_path, Some(&cert_path));
    wrong_user.args(["root@127.0.0.1", "true"]);
    assert!(!wrong_user.output().await.unwrap().status.success());

    let mut malformed = common(&key_path, Some(&cert_path));
    malformed.args(["git@127.0.0.1", "not-a-git-command"]);
    assert!(!malformed.output().await.unwrap().status.success());

    let mut receive = common(&key_path, Some(&cert_path));
    receive
        .stdin(std::process::Stdio::piped())
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped())
        .args([
            "git@127.0.0.1",
            &format!("git-receive-pack '{}'", repository.id),
        ]);
    let mut receive = receive.spawn().unwrap();
    receive
        .stdin
        .take()
        .unwrap()
        .write_all(b"0000")
        .await
        .unwrap();
    let receive = receive.wait_with_output().await.unwrap();
    assert!(
        receive.status.success(),
        "{}",
        String::from_utf8_lossy(&receive.stderr)
    );
    assert_eq!(app.metrics.ssh_write_operations.load(Ordering::Relaxed), 1);

    assert!(
        app.db
            .revoke_git_grant(&binding.user_id, &binding.client_id, &repository.id)
            .unwrap()
    );
    let mut revoked = common(&key_path, Some(&cert_path));
    revoked.args([
        "git@127.0.0.1",
        &format!("git-upload-pack '{}'", repository.id),
    ]);
    let revoked = revoked.output().await.unwrap();
    assert!(!revoked.status.success());
    assert!(!revoked.stderr.is_empty());
    assert_eq!(app.metrics.ssh_upstream_failures.load(Ordering::Relaxed), 1);

    let mut shell = common(&key_path, Some(&cert_path));
    shell.args(["-T", "git@127.0.0.1"]);
    assert!(!shell.output().await.unwrap().status.success());
    assert!(app.metrics.ssh_auth_denied.load(Ordering::Relaxed) >= 2);
    server_task.abort();
    upstream_task.abort();
}
