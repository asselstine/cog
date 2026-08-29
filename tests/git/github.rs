use crate::common::github_app_signing_key;
use axum::{
    Json, Router,
    extract::State,
    routing::{get, post},
};
use cog::git::providers::GitProvider;
use cog::git::providers::github::*;
use cog::git::{GitOperation, RepositoryReference, ResolvedRepository};
use serde_json::{Value, json};
use std::sync::{
    Arc,
    atomic::{AtomicUsize, Ordering},
};
use tokio::sync::Mutex;

#[derive(Clone)]
struct Fixture {
    calls: Arc<AtomicUsize>,
    bodies: Arc<Mutex<Vec<Value>>>,
}

async fn token(State(state): State<Fixture>, Json(body): Json<Value>) -> Json<Value> {
    let call = state.calls.fetch_add(1, Ordering::SeqCst) + 1;
    state.bodies.lock().await.push(body);
    Json(json!({
        "token": format!("installation-secret-{call}"),
        "expires_at": "2099-01-01T00:00:00Z"
    }))
}

async fn expiring_token(State(state): State<Fixture>, Json(body): Json<Value>) -> Json<Value> {
    let call = state.calls.fetch_add(1, Ordering::SeqCst) + 1;
    state.bodies.lock().await.push(body);
    Json(json!({
        "token": format!("short-lived-secret-{call}"),
        "expires_at": (chrono::Utc::now() + chrono::Duration::seconds(30)).to_rfc3339()
    }))
}

#[tokio::test]
async fn installation_tokens_are_least_privilege_cached_and_redacted() {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    let fixture = Fixture {
        calls: Arc::new(AtomicUsize::new(0)),
        bodies: Arc::new(Mutex::new(Vec::new())),
    };
    let server = tokio::spawn(
        axum::serve(
            listener,
            Router::new()
                .route("/app/installations/7/access_tokens", post(token))
                .with_state(fixture.clone()),
        )
        .into_future(),
    );
    let provider = GitHubProvider::new(
        "1".into(),
        "7".into(),
        address.to_string(),
        github_app_signing_key(),
    )
    .unwrap();
    let repository = ResolvedRepository {
        provider_repository_id: "42".into(),
        display_name: "owner/repo".into(),
        upstream_url: url::Url::parse("https://github.com/owner/repo.git").unwrap(),
        metadata: json!({}),
    };

    let read = provider
        .authorize_upstream(&repository, GitOperation::Read)
        .await
        .unwrap();
    assert!(!format!("{read:?}").contains("installation-secret"));
    provider
        .authorize_upstream(&repository, GitOperation::Read)
        .await
        .unwrap();
    provider
        .authorize_upstream(&repository, GitOperation::Write)
        .await
        .unwrap();
    assert_eq!(fixture.calls.load(Ordering::SeqCst), 2);
    let bodies = fixture.bodies.lock().await;
    assert_eq!(bodies[0]["repository_ids"], json!([42]));
    assert_eq!(bodies[0]["permissions"]["contents"], "read");
    assert!(bodies[0]["permissions"].get("workflows").is_none());
    assert_eq!(bodies[1]["permissions"]["contents"], "write");
    assert_eq!(bodies[1]["permissions"]["workflows"], "write");
    drop(bodies);
    provider.clear_cache().await;
    provider
        .authorize_upstream(&repository, GitOperation::Read)
        .await
        .unwrap();
    assert_eq!(fixture.calls.load(Ordering::SeqCst), 3);
    assert_eq!(
        provider.upstream_url(&repository).unwrap(),
        repository.upstream_url
    );
    server.abort();
}

#[test]
fn configuration_and_repository_validation_fail_closed() {
    assert!(
        GitHubProvider::new(
            "".into(),
            "7".into(),
            "github.com".into(),
            github_app_signing_key()
        )
        .is_err()
    );
    assert!(
        GitHubProvider::new(
            "1".into(),
            "7".into(),
            "evil.example".into(),
            github_app_signing_key()
        )
        .is_err()
    );
    assert!(GitHubProvider::new("1".into(), "7".into(), "github.com".into(), b"bad").is_err());
    let provider = GitHubProvider::new(
        "1".into(),
        "7".into(),
        "github.com".into(),
        github_app_signing_key(),
    )
    .unwrap();
    let bad = ResolvedRepository {
        provider_repository_id: "1".into(),
        display_name: "owner/repo".into(),
        upstream_url: url::Url::parse("https://example.com/owner/repo.git").unwrap(),
        metadata: json!({}),
    };
    assert!(provider.upstream_url(&bad).is_err());
}

#[tokio::test]
async fn expiration_refreshes_and_redirects_fail_closed() {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    let fixture = Fixture {
        calls: Arc::new(AtomicUsize::new(0)),
        bodies: Arc::new(Mutex::new(Vec::new())),
    };
    let server = tokio::spawn(
        axum::serve(
            listener,
            Router::new()
                .route("/app/installations/7/access_tokens", post(expiring_token))
                .with_state(fixture.clone()),
        )
        .into_future(),
    );
    let provider = GitHubProvider::new(
        "1".into(),
        "7".into(),
        address.to_string(),
        github_app_signing_key(),
    )
    .unwrap();
    let repository = ResolvedRepository {
        provider_repository_id: "42".into(),
        display_name: "owner/repo".into(),
        upstream_url: url::Url::parse("https://github.com/owner/repo.git").unwrap(),
        metadata: json!({}),
    };
    provider
        .authorize_upstream(&repository, GitOperation::Read)
        .await
        .unwrap();
    provider
        .authorize_upstream(&repository, GitOperation::Read)
        .await
        .unwrap();
    assert_eq!(fixture.calls.load(Ordering::SeqCst), 2);
    server.abort();

    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    let redirect_server = tokio::spawn(
        axum::serve(
            listener,
            Router::new().route(
                "/app/installations/7/access_tokens",
                post(|| async { axum::response::Redirect::temporary("https://example.com/") }),
            ),
        )
        .into_future(),
    );
    let provider = GitHubProvider::new(
        "1".into(),
        "7".into(),
        address.to_string(),
        github_app_signing_key(),
    )
    .unwrap();
    let error = provider
        .authorize_upstream(&repository, GitOperation::Read)
        .await
        .unwrap_err()
        .to_string();
    assert!(error.contains("status 307"));
    assert!(!error.contains("short-lived-secret"));
    redirect_server.abort();
}

#[tokio::test]
async fn repository_resolution_success_status_and_shape_boundaries() {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    let fixture = Fixture {
        calls: Arc::new(AtomicUsize::new(0)),
        bodies: Arc::new(Mutex::new(Vec::new())),
    };
    let server = tokio::spawn(
        axum::serve(
            listener,
            Router::new()
                .route("/app/installations/7/access_tokens", post(token))
                .route(
                    "/repos/owner/repo",
                    get(|| async {
                        Json(json!({
                            "id":42,
                            "full_name":"owner/repo",
                            "clone_url":"https://github.com/owner/repo.git",
                            "private":true
                        }))
                    }),
                )
                .route(
                    "/repos/owner/malformed",
                    get(|| async { Json(json!({"id":"wrong"})) }),
                )
                .with_state(fixture.clone()),
        )
        .into_future(),
    );
    let provider = GitHubProvider::new(
        "1".into(),
        "7".into(),
        address.to_string(),
        github_app_signing_key(),
    )
    .unwrap();
    for invalid in ["owner", "owner/repo/extra", "../repo"] {
        assert!(
            provider
                .resolve_repository(&RepositoryReference(invalid.into()))
                .await
                .is_err()
        );
    }
    let repository = provider
        .resolve_repository(&RepositoryReference("owner/repo".into()))
        .await
        .unwrap();
    assert_eq!(repository.provider_repository_id, "42");
    assert_eq!(repository.display_name, "owner/repo");
    assert_eq!(repository.metadata["private"], true);
    assert!(
        provider
            .resolve_repository(&RepositoryReference("owner/missing".into()))
            .await
            .unwrap_err()
            .to_string()
            .contains("status 404")
    );
    assert!(
        provider
            .resolve_repository(&RepositoryReference("owner/malformed".into()))
            .await
            .is_err()
    );
    server.abort();
}
