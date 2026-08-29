use cog::db::*;
use rusqlite::Connection;
#[test]
fn storage_mode_is_persistent_and_cannot_be_changed_implicitly() {
    let directory = tempfile::tempdir().unwrap();
    let local_path = directory.path().join("local.sqlite");
    assert_eq!(Database::inspect_storage_mode(&local_path).unwrap(), None);
    Database::open_with_mode(&local_path, StorageMode::Local).unwrap();
    assert_eq!(
        Database::inspect_storage_mode(&local_path).unwrap(),
        Some(StorageMode::Local)
    );
    assert!(Database::open_with_mode(&local_path, StorageMode::S3).is_err());

    let remote_path = directory.path().join("remote.sqlite");
    Database::open_with_mode(&remote_path, StorageMode::S3).unwrap();
    assert_eq!(
        Database::inspect_storage_mode(&remote_path).unwrap(),
        Some(StorageMode::S3)
    );
    assert!(Database::open_with_mode(&remote_path, StorageMode::Local).is_err());
}

#[test]
fn public_registration_ceiling_and_abandoned_cleanup() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("registration.db");
    let db = Database::open(&path).unwrap();
    let now = chrono::Utc::now().timestamp();
    let first = db
        .register_or_reuse_public_client(
            "first",
            "first",
            &["http://localhost/first".into()],
            now,
            1,
        )
        .unwrap();
    assert_eq!(first, ("first".into(), true, true));
    assert!(
        db.register_or_reuse_public_client(
            "second",
            "second",
            &["http://localhost/second".into()],
            now,
            1,
        )
        .is_err()
    );
    Connection::open(&path)
        .unwrap()
        .execute(
            "UPDATE oauth_clients SET created_at=? WHERE client_id='first'",
            [now - 172800],
        )
        .unwrap();
    let second = db
        .register_or_reuse_public_client(
            "second",
            "second",
            &["http://localhost/second".into()],
            now,
            1,
        )
        .unwrap();
    assert_eq!(second, ("second".into(), true, true));
    assert!(db.client_info("first").unwrap().is_none());
}

#[test]
fn token_context_does_not_update_last_used_at() {
    let dir = tempfile::tempdir().unwrap();
    let db = Database::open(&dir.path().join("token-context.db")).unwrap();
    let user = db.create_user("token-context@example.com", "hash").unwrap();
    db.register_client(
        "client",
        Some(&user),
        "agent",
        &["http://localhost/cb".into()],
    )
    .unwrap();
    db.store_access_token(b"access", "client", &user, "mcp", 1000, None, None)
        .unwrap();

    assert!(db.token_context(b"access", 1).unwrap().is_some());
    assert_eq!(db.agent_tokens(&user).unwrap()[0].last_used_at, None);
}

#[test]
fn token_scope_cannot_authorize_connections_outside_the_identity() {
    let dir = tempfile::tempdir().unwrap();
    let db = Database::open(&dir.path().join("grants.db")).unwrap();
    let user = db.create_user("grants@example.com", "hash").unwrap();
    db.register_client(
        "client",
        Some(&user),
        "agent",
        &["http://localhost/cb".into()],
    )
    .unwrap();
    db.store_access_token(
        b"access",
        "client",
        &user,
        "mcp integration:stable-id",
        1000,
        Some(b"refresh"),
        Some(2000),
    )
    .unwrap();
    let context = db.token_context(b"access", 1).unwrap().unwrap();
    assert!(context.integration_ids.is_empty());
}

#[test]
fn deleting_an_integration_removes_its_scope_from_every_client() {
    let dir = tempfile::tempdir().unwrap();
    let db = Database::open(&dir.path().join("delete-grants.db")).unwrap();
    let user = db.create_user("delete-grants@example.com", "hash").unwrap();
    let integration = db
        .create_integration(
            &user,
            "provider",
            "http",
            &serde_json::json!({"url":"http://localhost"}),
            None,
        )
        .unwrap();
    let integration_scope = format!("integration:{integration}");
    for (index, client) in ["first", "second"].into_iter().enumerate() {
        db.register_client(client, Some(&user), client, &["http://localhost/cb".into()])
            .unwrap();
        db.store_access_token(
            format!("access-{index}").as_bytes(),
            client,
            &user,
            &format!("mcp {integration_scope} integrations:read"),
            1000,
            None,
            None,
        )
        .unwrap();
    }

    assert!(db.delete_integration(&integration, &user).unwrap());
    for index in 0..2 {
        let context = db
            .token_context(format!("access-{index}").as_bytes(), 1)
            .unwrap()
            .unwrap();
        assert_eq!(context.scopes, ["mcp", "integrations:read"]);
        assert!(context.integration_ids.is_empty());
    }
}

#[test]
fn disconnect_clears_every_credential_and_preserves_integration_and_grants() {
    let dir = tempfile::tempdir().unwrap();
    let db = Database::open(&dir.path().join("disconnect.db")).unwrap();
    let user = db.create_user("disconnect@example.com", "hash").unwrap();
    let integration = db
        .create_integration(
            &user,
            "provider",
            "http",
            &serde_json::json!({"url":"https://provider.example/mcp","oauth":{}}),
            Some("sealed-static-headers"),
        )
        .unwrap();
    db.register_client(
        "client",
        Some(&user),
        "client",
        &["http://localhost/cb".into()],
    )
    .unwrap();
    db.store_access_token(
        b"access",
        "client",
        &user,
        &format!("mcp integration:{integration}"),
        1000,
        None,
        None,
    )
    .unwrap();
    db.put_upstream_oauth_client(
        &integration,
        &UpstreamOAuthClient {
            client_id: "client-id".into(),
            client_secret_ciphertext: Some("sealed-client-secret".into()),
            authorization_endpoint: "https://issuer.example/authorize".into(),
            token_endpoint: "https://issuer.example/token".into(),
            scope: "mcp".into(),
            resource: None,
            issuer: None,
        },
    )
    .unwrap();
    db.put_upstream_oauth_token(
        &integration,
        &UpstreamOAuthToken {
            access_token_ciphertext: "sealed-access".into(),
            refresh_token_ciphertext: Some("sealed-refresh".into()),
            token_type: "Bearer".into(),
            scope: "mcp".into(),
            expires_at: None,
            refresh_expires_at: None,
        },
    )
    .unwrap();
    db.store_oauth_state(
        b"pending",
        &user,
        &integration,
        "sealed-pkce",
        "http://cb",
        999,
        None,
    )
    .unwrap();

    assert!(
        db.clear_integration_credentials(&integration, &user)
            .unwrap()
    );
    assert!(
        db.clear_integration_credentials(&integration, &user)
            .unwrap()
    );
    assert!(db.integration(&integration, &user).unwrap().is_some());
    assert!(
        db.integration_secret(&integration, &user)
            .unwrap()
            .is_none()
    );
    assert!(db.upstream_oauth_client(&integration).unwrap().is_none());
    assert!(db.upstream_oauth_token(&integration).unwrap().is_none());
    assert!(db.redeem_oauth_state(b"pending").unwrap().is_none());
    assert!(
        db.token_context(b"access", 1)
            .unwrap()
            .unwrap()
            .integration_ids
            .contains(&integration)
    );
}
#[test]
fn users_and_integrations() {
    let dir = tempfile::tempdir().unwrap();
    let db = Database::open(&dir.path().join("x.db")).unwrap();
    assert_eq!(db.user_count().unwrap(), 0);
    let id = db.create_user("a@b.c", "hash").unwrap();
    db.create_session(b"session", &id, b"csrf", 999).unwrap();
    assert_eq!(
        db.session_user(b"session", Some(b"csrf"), 1).unwrap(),
        Some(id.clone())
    );
    assert!(
        db.session_user(b"session", Some(b"wrong"), 1)
            .unwrap()
            .is_none()
    );
    assert!(db.delete_session(b"session").unwrap());
    assert!(db.session_user(b"session", None, 1).unwrap().is_none());
    db.record_audit(
        Some(&id),
        "test.action",
        None,
        "success",
        &serde_json::json!({"safe":true}),
    )
    .unwrap();
    let events = db.audit_events(10).unwrap();
    assert_eq!(events[0].action, "test.action");
    assert_eq!(events[0].details["safe"], true);
    assert_eq!(db.user_by_email("a@b.c").unwrap().unwrap().0, id);
    assert!(db.user_by_email("none").unwrap().is_none());
    assert!(db.create_user("a@b.c", "x").is_err());
    assert!(db.list_integrations(&id).unwrap().is_empty());
    let integration = db
        .create_integration(
            &id,
            "mail",
            "http",
            &serde_json::json!({"url":"x"}),
            Some("encrypted"),
        )
        .unwrap();
    assert_eq!(db.list_integrations(&id).unwrap()[0].name, "mail");
    assert_eq!(
        db.integration_secret(&integration, &id).unwrap().as_deref(),
        Some("encrypted")
    );
    assert!(db.integration("none", &id).unwrap().is_none());
    db.set_integration_secret(&integration, &id, "new").unwrap();
    assert_eq!(
        db.integration_secret(&integration, &id).unwrap().as_deref(),
        Some("new")
    );
    assert!(db.set_integration_secret("none", &id, "x").is_err());
    let upstream_client = UpstreamOAuthClient {
        client_id: "client".into(),
        client_secret_ciphertext: Some("sealed-client-secret".into()),
        authorization_endpoint: "https://issuer.example/authorize".into(),
        token_endpoint: "https://issuer.example/token".into(),
        scope: "mcp".into(),
        resource: Some("https://resource.example/mcp".into()),
        issuer: Some("https://issuer.example".into()),
    };
    db.put_upstream_oauth_client(&integration, &upstream_client)
        .unwrap();
    assert_eq!(
        db.upstream_oauth_client(&integration).unwrap(),
        Some(upstream_client)
    );
    let upstream_token = UpstreamOAuthToken {
        access_token_ciphertext: "sealed-access".into(),
        refresh_token_ciphertext: Some("sealed-refresh".into()),
        token_type: "Bearer".into(),
        scope: "mcp".into(),
        expires_at: Some(1000),
        refresh_expires_at: Some(2000),
    };
    db.put_upstream_oauth_token(&integration, &upstream_token)
        .unwrap();
    assert_eq!(
        db.upstream_oauth_token(&integration).unwrap(),
        Some(upstream_token)
    );
    let state = b"state";
    db.store_oauth_state(
        state,
        &id,
        &integration,
        "verifier",
        "http://cb",
        999,
        Some("https://resource.example/mcp"),
    )
    .unwrap();
    assert!(db.redeem_oauth_state(b"none").unwrap().is_none());
    assert_eq!(
        db.redeem_oauth_state(state).unwrap().unwrap().1,
        integration
    );
    assert!(db.redeem_oauth_state(state).unwrap().is_none());
    db.checkpoint().unwrap();
}

#[test]
fn identity_agent_grant_audit_and_empty_getter_lifecycles() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("lifecycle.db");
    let db = Database::open(&path).unwrap();
    let user = db.create_user("lifecycle@example.com", "hash").unwrap();
    let other = db.create_user("other@example.com", "hash").unwrap();
    let identity = db.create_identity(&user, "Primary").unwrap();
    assert!(db.identity(&user, &identity).unwrap().is_some());
    assert!(db.identity(&other, &identity).unwrap().is_none());
    assert!(db.rename_identity(&user, &identity, "Renamed").unwrap());
    assert!(!db.rename_identity(&other, &identity, "Nope").unwrap());
    assert!(db.create_identity(&user, "  ").is_err());
    db.register_client(
        "lifecycle-client",
        None,
        "Lifecycle Agent",
        &["http://localhost/cb".into()],
    )
    .unwrap();
    assert!(
        db.bind_agent(&other, &identity, "lifecycle-client")
            .is_err()
    );
    let agent = db.bind_agent(&user, &identity, "lifecycle-client").unwrap();
    assert_eq!(
        db.bind_agent(&user, &identity, "lifecycle-client")
            .unwrap()
            .id,
        agent.id
    );
    assert_eq!(
        db.agent_for_client("lifecycle-client").unwrap().unwrap().id,
        agent.id
    );
    assert_eq!(db.agents_for_identity(&user, &identity).unwrap().len(), 1);
    assert!(db.rename_agent(&user, &agent.id, "Owner Name").unwrap());
    assert!(db.rename_self(&agent.id, "Self Name").unwrap());
    assert!(!db.rename_self("missing", "Nope").unwrap());
    db.set_identity_grants(
        &user,
        &identity,
        &["integration:one".into(), "git:repo:write".into()],
    )
    .unwrap();
    assert_eq!(
        db.identity_grants(&user, &identity).unwrap(),
        ["git:repo:write", "integration:one", "mcp"]
    );
    assert_eq!(
        db.client_granted_scopes(&user, "lifecycle-client").unwrap(),
        ["git:repo:write", "integration:one", "mcp"]
    );
    assert!(db.identity_grants(&other, &identity).unwrap().is_empty());
    assert!(db.set_identity_grants(&other, &identity, &[]).is_err());
    assert!(
        db.client_granted_scopes(&user, "missing")
            .unwrap()
            .is_empty()
    );
    db.record_audit(
        Some(&user),
        "first",
        Some(&identity),
        "success",
        &serde_json::json!({"n":1}),
    )
    .unwrap();
    db.record_audit(
        Some(&other),
        "second",
        None,
        "failure",
        &serde_json::json!({"n":2}),
    )
    .unwrap();
    assert_eq!(
        db.audit_events_for_user(&user, 1).unwrap()[0].action,
        "first"
    );
    let integration = db
        .create_integration(&user, "Provider", "http", &serde_json::json!({}), None)
        .unwrap();
    assert_eq!(
        db.integration_scopes().unwrap(),
        [format!("integration:{integration}")]
    );
    assert!(db.delete_identity(&user, &identity).unwrap());
    assert!(!db.delete_identity(&user, &identity).unwrap());
    drop(db);
    let conn = Connection::open(&path).unwrap();
    conn.execute(
        "UPDATE cog_meta SET value='future' WHERE key='storage_mode'",
        [],
    )
    .unwrap();
    drop(conn);
    assert!(Database::inspect_storage_mode(&path).is_err());
}

#[test]
fn legacy_schema_requires_explicit_clean_initialization() {
    let directory = tempfile::tempdir().unwrap();
    let path = directory.path().join("legacy.sqlite");
    {
        let connection = Connection::open(&path).unwrap();
        connection
            .execute_batch(
                "CREATE TABLE oauth_tokens(token_hash BLOB PRIMARY KEY,client_id TEXT,user_id TEXT,scope TEXT,expires_at INTEGER,refresh_hash BLOB);
                 CREATE TABLE sessions(session_hash BLOB PRIMARY KEY,user_id TEXT,expires_at INTEGER);",
            )
            .unwrap();
    }
    let error = Database::open(&path)
        .err()
        .expect("legacy schema must fail closed");
    assert!(error.to_string().contains("explicitly initialize"));
}

#[test]
fn git_pending_grants_and_cascades() {
    let dir = tempfile::tempdir().unwrap();
    let db = Database::open(&dir.path().join("git.db")).unwrap();
    let user = db.create_user("git@example.com", "hash").unwrap();
    db.register_client(
        "client",
        Some(&user),
        "agent",
        &["http://localhost/callback".into()],
    )
    .unwrap();
    let integration = db
        .create_integration(
            &user,
            "GitHub",
            "git",
            &serde_json::json!({"kind":"git"}),
            Some("sealed"),
        )
        .unwrap();
    let resolved = crate::git::ResolvedRepository {
        provider_repository_id: "42".into(),
        display_name: "acme/repo".into(),
        upstream_url: "https://github.com/acme/repo.git".parse().unwrap(),
        metadata: serde_json::json!({}),
    };
    let repository = db
        .upsert_git_repository(&user, &integration, &resolved)
        .unwrap();
    let now = chrono::Utc::now().timestamp();
    db.store_access_token(
        b"access",
        "client",
        &user,
        &format!("mcp git:write integration:{integration}"),
        now + 60,
        None,
        None,
    )
    .unwrap();
    let pending = db
        .create_git_pending_request(&user, "client", &integration, &repository.id, "read", 600)
        .unwrap();
    assert_eq!(
        db.git_pending_requests(&user, "client", now).unwrap().len(),
        1
    );
    assert_eq!(
        db.consume_git_pending_requests(&user, "client", std::slice::from_ref(&pending), now)
            .unwrap()
            .len(),
        1
    );
    assert_eq!(
        db.git_grant_permission(&user, "client", &repository.id)
            .unwrap()
            .as_deref(),
        Some("read")
    );
    db.set_git_grant(&user, "client", &repository.id, "write")
        .unwrap();
    db.touch_git_grant(&user, "client", &repository.id, now + 1)
        .unwrap();
    let grants = db.list_git_grants(&user, "client").unwrap();
    assert_eq!(grants.len(), 1);
    assert_eq!(grants[0].permission, "write");
    assert_eq!(grants[0].last_used_at, Some(now + 1));
    let all = db.all_git_grants(&user).unwrap();
    assert_eq!(all.len(), 1);
    assert_eq!(all[0]["repository_id"], repository.id);
    assert!(
        db.set_git_grant(&user, "client", &repository.id, "owner")
            .is_err()
    );
    assert!(
        db.create_git_pending_request(&user, "client", &integration, &repository.id, "owner", 60)
            .is_err()
    );
    assert!(
        db.consume_git_pending_requests(&user, "client", &["not-hex".into()], now)
            .is_err()
    );
    db.revoke_git_grant(&user, "client", &repository.id)
        .unwrap();
    assert!(
        db.git_grant_permission(&user, "client", &repository.id)
            .unwrap()
            .is_none()
    );
    assert!(db.list_git_grants(&user, "client").unwrap().is_empty());
    assert!(db.all_git_grants(&user).unwrap().is_empty());
    assert!(
        !db.revoke_git_grant(&user, "missing", &repository.id)
            .unwrap()
    );
    assert!(db.delete_integration(&integration, &user).unwrap());
    assert!(db.git_repository(&repository.id).unwrap().is_none());
}

#[test]
fn github_app_setup_transitions_credentials_and_installation_atomically() {
    let dir = tempfile::tempdir().unwrap();
    let db = Database::open(&dir.path().join("github-setup.db")).unwrap();
    let user = db.create_user("github-setup@example.com", "hash").unwrap();
    let now = chrono::Utc::now().timestamp();
    let state = crate::crypto::token_hash("manifest-state");
    let integration = db
        .create_github_app_setup(&user, "GitHub", &state, now + 1200)
        .unwrap();
    let pending = db.github_app_setup_by_state(&state, now).unwrap().unwrap();
    assert_eq!(pending.integration_id, integration);
    assert!(pending.manifest_completed_at.is_none());
    let placeholder = db.integration(&integration, &user).unwrap().unwrap();
    assert!(!placeholder.enabled);
    assert_eq!(placeholder.config["setupStatus"], "manifest_pending");

    let manifest_config = serde_json::json!({
        "kind":"git","provider":"github","host":"github.com",
        "providerConfig":{"appId":"42","appSlug":"cog-fixture"},
        "setupStatus":"installation_pending"
    });
    assert!(
        db.complete_github_app_manifest(
            &state,
            &manifest_config,
            "sealed-pem",
            "cog-fixture",
            now,
        )
        .unwrap()
    );
    assert!(
        !db.complete_github_app_manifest(
            &state,
            &manifest_config,
            "replacement",
            "cog-fixture",
            now,
        )
        .unwrap()
    );
    let pending = db
        .github_app_setup_for_integration(&user, &integration, now)
        .unwrap()
        .unwrap();
    assert_eq!(pending.app_slug.as_deref(), Some("cog-fixture"));
    assert!(pending.manifest_completed_at.is_some());
    assert_eq!(
        db.integration_secret(&integration, &user)
            .unwrap()
            .as_deref(),
        Some("sealed-pem")
    );

    let installed_config = serde_json::json!({
        "kind":"git","provider":"github","host":"github.com",
        "providerConfig":{"appId":"42","appSlug":"cog-fixture","installationId":"99"},
        "setupStatus":"installed"
    });
    assert_eq!(
        db.complete_github_app_installation(&state, &installed_config, now)
            .unwrap()
            .as_deref(),
        Some(integration.as_str())
    );
    assert!(
        db.complete_github_app_installation(&state, &installed_config, now)
            .unwrap()
            .is_none()
    );
    let installed = db.integration(&integration, &user).unwrap().unwrap();
    assert!(installed.enabled);
    assert_eq!(installed.config["providerConfig"]["installationId"], "99");
}

#[test]
fn every_schema_upgrade_path_and_repeated_open_succeeds() {
    for old_version in 1..SCHEMA_VERSION {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join(format!("v{old_version}.db"));
        drop(Database::open(&path).unwrap());
        let connection = Connection::open(&path).unwrap();
        if old_version == 2 {
            connection
                .execute_batch(
                    "DROP TABLE schema_meta;
                     CREATE TABLE schema_meta(version INTEGER NOT NULL CHECK(version = 2));
                     INSERT INTO schema_meta VALUES(2);",
                )
                .unwrap();
        } else {
            connection
                .execute("UPDATE schema_meta SET version=?", [old_version])
                .unwrap();
        }
        drop(connection);
        let upgraded = Database::open(&path).unwrap();
        assert_eq!(upgraded.schema_version().unwrap(), SCHEMA_VERSION);
        drop(upgraded);
        assert_eq!(
            Database::open(&path).unwrap().schema_version().unwrap(),
            SCHEMA_VERSION
        );
    }
}

#[test]
fn newer_schema_is_rejected() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("future.db");
    drop(Database::open(&path).unwrap());
    let connection = Connection::open(&path).unwrap();
    connection
        .execute("UPDATE schema_meta SET version=?", [SCHEMA_VERSION + 1])
        .unwrap();
    drop(connection);
    assert!(
        Database::open(&path)
            .err()
            .unwrap()
            .to_string()
            .contains("newer")
    );
}

#[test]
fn failed_migration_keeps_previous_version() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("broken.db");
    drop(Database::open(&path).unwrap());
    let connection = Connection::open(&path).unwrap();
    connection
        .execute_batch(
            "PRAGMA foreign_keys=OFF; DROP TABLE oauth_tokens; UPDATE schema_meta SET version=2;",
        )
        .unwrap();
    drop(connection);
    assert!(
        Database::open(&path)
            .err()
            .unwrap()
            .to_string()
            .contains("rolled back")
    );
    let connection = Connection::open(&path).unwrap();
    let version: i64 = connection
        .query_row("SELECT version FROM schema_meta", [], |row| row.get(0))
        .unwrap();
    assert_eq!(version, 2);
}

#[test]
fn token_lookup_rotation_boundaries_and_full_integration_update() {
    let dir = tempfile::tempdir().unwrap();
    let db = Database::open(&dir.path().join("tokens.db")).unwrap();
    let user = db.create_user("tokens@example.com", "hash").unwrap();
    db.register_client(
        "token-client",
        Some(&user),
        "Token client",
        &["http://localhost/callback".into()],
    )
    .unwrap();
    db.store_access_token(
        b"access-one",
        "token-client",
        &user,
        "mcp agents:read",
        200,
        Some(b"refresh-one"),
        Some(300),
    )
    .unwrap();
    assert_eq!(
        db.token_user(b"access-one", 100).unwrap(),
        Some(user.clone())
    );
    assert!(db.token_user(b"access-one", 200).unwrap().is_none());
    assert_eq!(
        db.token_user_for_scope(b"access-one", 100, "agents:read")
            .unwrap(),
        Some(user.clone())
    );
    assert!(
        db.token_user_for_scope(b"access-one", 100, "agents:write")
            .unwrap()
            .is_none()
    );
    assert!(
        db.token_user_for_scope(b"missing", 100, "mcp")
            .unwrap()
            .is_none()
    );
    assert_eq!(
        db.token_user_and_scope(b"access-one", 100).unwrap(),
        Some((user.clone(), "mcp agents:read".into()))
    );
    assert!(db.token_user_and_scope(b"missing", 100).unwrap().is_none());
    assert!(
        db.rotate_refresh_token(
            b"refresh-one",
            "wrong-client",
            100,
            b"access-two",
            400,
            b"refresh-two",
            500,
        )
        .unwrap()
        .is_none()
    );
    assert!(db.token_user(b"access-one", 100).unwrap().is_none());

    let integration = db
        .create_integration(
            &user,
            "Before",
            "http",
            &serde_json::json!({"url":"http://before.example"}),
            None,
        )
        .unwrap();
    db.update_integration(
        &integration,
        &user,
        Some("After"),
        Some(&serde_json::json!({"url":"http://after.example"})),
        Some(false),
        Some("sealed-secret"),
    )
    .unwrap();
    let updated = db.integration(&integration, &user).unwrap().unwrap();
    assert_eq!(updated.name, "After");
    assert!(!updated.enabled);
    assert_eq!(updated.config["url"], "http://after.example");
    assert_eq!(
        db.integration_secret(&integration, &user)
            .unwrap()
            .as_deref(),
        Some("sealed-secret")
    );
    assert!(
        db.update_integration("missing", &user, None, None, None, None)
            .is_err()
    );
}
