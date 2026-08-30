use super::*;

pub fn build_router(app: App) -> Router {
    Router::new()
        .route("/", get(home))
        .route("/healthz", get(health))
        .route("/readyz", get(readiness))
        .route("/version", get(version))
        .route("/metrics", get(metrics))
        .route("/login", get(login_page).post(login))
        .route("/logout", post(logout))
        .route("/ui", get(admin_ui))
        .route("/ui/", get(admin_ui))
        .route("/ui/assets/{*path}", get(ui_asset))
        .route("/ui/integrations", post(ui_add_integration))
        .route("/ui/identities", post(ui_create_identity))
        .route("/ui/identities/{id}/rename", post(ui_rename_identity))
        .route("/ui/identities/{id}/delete", post(ui_delete_identity))
        .route("/ui/agents/{id}/rename", post(ui_rename_agent))
        .route("/ui/integrations/{id}/delete", post(ui_delete_integration))
        .route(
            "/ui/integrations/{id}/disconnect",
            post(ui_disconnect_integration),
        )
        .route("/ui/tokens/{id}/revoke", post(ui_revoke_token))
        .route("/ui/clients/{id}/revoke", post(ui_revoke_client))
        .route("/ui/ssh/{purpose}/prepare", post(ui_prepare_ssh_key))
        .route("/ui/ssh/{purpose}/{id}/activate", post(ui_activate_ssh_key))
        .route("/ui/ssh/{purpose}/{id}/retire", post(ui_retire_ssh_key))
        .route(
            "/ui/clients/{client}/integrations/{integration}/revoke",
            post(ui_revoke_grant),
        )
        .route(
            "/ui/clients/{client}/integrations/{integration}/grant",
            post(ui_grant_integration),
        )
        .route(
            "/.well-known/oauth-authorization-server",
            get(auth_metadata),
        )
        .route(
            "/.well-known/oauth-protected-resource",
            get(resource_metadata),
        )
        .route("/.well-known/oauth-client", get(oauth_client_metadata))
        .route(
            "/oauth/register",
            post(register).layer(DefaultBodyLimit::max(32 * 1_024)),
        )
        .route("/oauth/authorize", get(authorize_page))
        .route("/oauth/token", post(token))
        .route("/oauth/revoke", post(revoke_token))
        .route("/mcp", post(mcp_endpoint))
        .route("/github/app/setup/{state}", get(github_app_setup_launch))
        .route(
            "/github/app/manifest/callback",
            get(github_app_manifest_callback),
        )
        .route(
            "/github/app/installation/callback",
            get(github_app_installation_callback),
        )
        .route("/github/app/installation/complete", get(authorize_page))
        .route(
            "/api/integrations",
            get(list_integrations).post(add_integration),
        )
        .route(
            "/api/integrations/{id}",
            get(get_integration)
                .patch(update_integration)
                .delete(delete_integration),
        )
        .route(
            "/api/integrations/{id}/reconnect",
            post(reconnect_integration),
        )
        .route(
            "/api/integrations/{id}/credentials",
            axum::routing::delete(disconnect_integration),
        )
        .route(
            "/api/integrations/{id}/oauth/start",
            post(upstream_oauth_start),
        )
        .route("/api/clients", get(list_agent_clients))
        .route(
            "/api/clients/{id}",
            axum::routing::delete(revoke_agent_client),
        )
        .route(
            "/api/clients/{client}/integrations/{integration}",
            axum::routing::delete(revoke_agent_grant),
        )
        .route("/api/tokens", get(list_agent_tokens))
        .route(
            "/api/tokens/{id}",
            axum::routing::delete(revoke_agent_token),
        )
        .route("/api/audit", get(list_audit_events))
        .route("/api/ui", get(ui_bootstrap))
        .route(
            "/api/oauth/consent",
            get(authorize_consent).post(authorize_post),
        )
        .route("/oauth/upstream/callback", get(upstream_callback))
        .with_state(app)
}
