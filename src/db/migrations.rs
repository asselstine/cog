use super::*;

pub const SCHEMA_VERSION: i64 = 7;

const INITIAL_SCHEMA: &str = r#"
PRAGMA foreign_keys=ON;
CREATE TABLE IF NOT EXISTS schema_meta(version INTEGER NOT NULL);
INSERT INTO schema_meta(version) SELECT 5 WHERE NOT EXISTS (SELECT 1 FROM schema_meta);
CREATE TABLE IF NOT EXISTS cog_meta(key TEXT PRIMARY KEY, value TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS users(
 id TEXT PRIMARY KEY, email TEXT NOT NULL UNIQUE, password_hash TEXT NOT NULL,
 created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
);
CREATE TABLE IF NOT EXISTS sessions(
 token_hash BLOB PRIMARY KEY, user_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
 expires_at INTEGER NOT NULL, csrf_hash BLOB
);
CREATE TABLE IF NOT EXISTS identities(
 id TEXT PRIMARY KEY, user_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
 name TEXT NOT NULL, created_at INTEGER NOT NULL, updated_at INTEGER NOT NULL,
 UNIQUE(user_id,name)
);
CREATE TABLE IF NOT EXISTS integrations(
 id TEXT PRIMARY KEY, identity_id TEXT NOT NULL REFERENCES identities(id) ON DELETE CASCADE,
 user_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
 display_name TEXT NOT NULL, provider_name TEXT, provider_account TEXT,
 name TEXT NOT NULL,
 transport TEXT NOT NULL, config_json TEXT NOT NULL,
 secret_ciphertext TEXT, enabled INTEGER NOT NULL DEFAULT 1,
 created_at INTEGER NOT NULL, updated_at INTEGER NOT NULL,
 UNIQUE(identity_id,display_name)
);
CREATE TABLE IF NOT EXISTS oauth_clients(
 client_id TEXT PRIMARY KEY, user_id TEXT REFERENCES users(id) ON DELETE CASCADE,
 redirect_uris TEXT NOT NULL, registered_name TEXT NOT NULL, client_name TEXT NOT NULL,
 created_at INTEGER NOT NULL DEFAULT (unixepoch())
);
CREATE TABLE IF NOT EXISTS agents(
 id TEXT PRIMARY KEY, identity_id TEXT NOT NULL REFERENCES identities(id) ON DELETE CASCADE,
 oauth_client_id TEXT NOT NULL UNIQUE REFERENCES oauth_clients(client_id) ON DELETE CASCADE,
 display_name TEXT NOT NULL, created_at INTEGER NOT NULL, updated_at INTEGER NOT NULL,
 last_used_at INTEGER
);
CREATE TABLE IF NOT EXISTS identity_grants(
 identity_id TEXT NOT NULL REFERENCES identities(id) ON DELETE CASCADE,
 capability TEXT NOT NULL, resource_id TEXT NOT NULL DEFAULT '',
 permission TEXT NOT NULL DEFAULT '', created_at INTEGER NOT NULL, revoked_at INTEGER,
 PRIMARY KEY(identity_id,capability,resource_id)
);
CREATE TABLE IF NOT EXISTS oauth_codes(
 code_hash BLOB PRIMARY KEY, client_id TEXT NOT NULL REFERENCES oauth_clients(client_id) ON DELETE CASCADE,
 agent_id TEXT NOT NULL REFERENCES agents(id) ON DELETE CASCADE,
 identity_id TEXT NOT NULL REFERENCES identities(id) ON DELETE CASCADE, redirect_uri TEXT NOT NULL,
 user_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
 scope TEXT NOT NULL, challenge TEXT NOT NULL, expires_at INTEGER NOT NULL
);
CREATE TABLE IF NOT EXISTS oauth_tokens(
 token_hash BLOB PRIMARY KEY, token_id TEXT UNIQUE, client_id TEXT NOT NULL REFERENCES oauth_clients(client_id) ON DELETE CASCADE,
 agent_id TEXT NOT NULL REFERENCES agents(id) ON DELETE CASCADE, scope TEXT NOT NULL,
 user_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
 issued_at INTEGER NOT NULL, expires_at INTEGER NOT NULL, refresh_hash BLOB UNIQUE, refresh_expires_at INTEGER,
 last_used_at INTEGER
);
CREATE TABLE IF NOT EXISTS oauth_states(
 state_hash BLOB PRIMARY KEY, user_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
 integration_id TEXT NOT NULL REFERENCES integrations(id) ON DELETE CASCADE,
 verifier_ciphertext TEXT NOT NULL, redirect_uri TEXT NOT NULL, expires_at INTEGER NOT NULL,
 resource TEXT
);
CREATE TABLE IF NOT EXISTS upstream_oauth_clients(
 integration_id TEXT PRIMARY KEY REFERENCES integrations(id) ON DELETE CASCADE,
 client_id TEXT NOT NULL, client_secret_ciphertext TEXT,
 authorization_endpoint TEXT NOT NULL, token_endpoint TEXT NOT NULL,
 scope TEXT NOT NULL, resource TEXT, issuer TEXT
);
CREATE TABLE IF NOT EXISTS upstream_oauth_tokens(
 integration_id TEXT PRIMARY KEY REFERENCES integrations(id) ON DELETE CASCADE,
 access_token_ciphertext TEXT NOT NULL, refresh_token_ciphertext TEXT,
 token_type TEXT NOT NULL, scope TEXT NOT NULL,
 expires_at INTEGER, refresh_expires_at INTEGER
);
CREATE TABLE IF NOT EXISTS audit_log(
 id INTEGER PRIMARY KEY AUTOINCREMENT, occurred_at INTEGER NOT NULL,
 actor TEXT, action TEXT NOT NULL, target TEXT, outcome TEXT NOT NULL,
 details_json TEXT NOT NULL DEFAULT '{}'
);
CREATE TABLE IF NOT EXISTS git_repositories(
 id TEXT PRIMARY KEY, user_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
 integration_id TEXT NOT NULL REFERENCES integrations(id) ON DELETE CASCADE,
 provider_repository_id TEXT NOT NULL, display_name TEXT NOT NULL, upstream_url TEXT NOT NULL,
 metadata_json TEXT NOT NULL DEFAULT '{}', created_at INTEGER NOT NULL, updated_at INTEGER NOT NULL,
 UNIQUE(integration_id,provider_repository_id)
);
CREATE TABLE IF NOT EXISTS git_repository_grants(
 identity_id TEXT NOT NULL REFERENCES identities(id) ON DELETE CASCADE,
 user_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
 client_id TEXT NOT NULL REFERENCES oauth_clients(client_id) ON DELETE CASCADE,
 repository_id TEXT NOT NULL REFERENCES git_repositories(id) ON DELETE CASCADE,
 permission TEXT NOT NULL CHECK(permission IN ('read','write')), created_at INTEGER NOT NULL,
 revoked_at INTEGER, last_used_at INTEGER, PRIMARY KEY(identity_id,repository_id)
);
CREATE TABLE IF NOT EXISTS git_pending_requests(
 id_hash BLOB PRIMARY KEY, identity_id TEXT NOT NULL REFERENCES identities(id) ON DELETE CASCADE,
 user_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
 client_id TEXT NOT NULL REFERENCES oauth_clients(client_id) ON DELETE CASCADE,
 integration_id TEXT NOT NULL REFERENCES integrations(id) ON DELETE CASCADE,
 repository_id TEXT NOT NULL REFERENCES git_repositories(id) ON DELETE CASCADE,
 permission TEXT NOT NULL CHECK(permission IN ('read','write')), expires_at INTEGER NOT NULL,
 consumed_at INTEGER
);
CREATE TABLE IF NOT EXISTS ssh_keys(
 id TEXT PRIMARY KEY, purpose TEXT NOT NULL CHECK(purpose = 'host'),
 algorithm TEXT NOT NULL, public_key TEXT NOT NULL, private_ciphertext TEXT NOT NULL,
 created_at INTEGER NOT NULL, active INTEGER NOT NULL DEFAULT 0,
 retirement_time INTEGER
);
CREATE UNIQUE INDEX IF NOT EXISTS ssh_keys_one_active ON ssh_keys(purpose) WHERE active=1;
CREATE TABLE IF NOT EXISTS agent_ssh_keys(
 agent_id TEXT PRIMARY KEY REFERENCES agents(id) ON DELETE CASCADE,
 public_key TEXT NOT NULL UNIQUE, fingerprint TEXT NOT NULL UNIQUE,
 lease_expires_at INTEGER NOT NULL, created_at INTEGER NOT NULL, updated_at INTEGER NOT NULL,
 revoked_at INTEGER
);
CREATE TABLE IF NOT EXISTS github_app_setups(
 state_hash BLOB PRIMARY KEY,
 user_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
 integration_id TEXT NOT NULL UNIQUE REFERENCES integrations(id) ON DELETE CASCADE,
 expires_at INTEGER NOT NULL, app_slug TEXT, manifest_completed_at INTEGER
);
CREATE INDEX IF NOT EXISTS identities_user_id ON identities(user_id);
CREATE INDEX IF NOT EXISTS agents_identity_id ON agents(identity_id);
CREATE INDEX IF NOT EXISTS integrations_identity_id ON integrations(identity_id);
CREATE INDEX IF NOT EXISTS identity_grants_active ON identity_grants(identity_id,revoked_at);
CREATE INDEX IF NOT EXISTS oauth_tokens_client_id ON oauth_tokens(client_id);
"#;

fn apply_migration(tx: &rusqlite::Transaction<'_>, version: i64) -> anyhow::Result<()> {
    match version {
        // Version 2 introduced identities and the OAuth/upstream model. The
        // idempotent schema statements also repair partial pre-release v1 DBs.
        2 => tx.execute_batch(INITIAL_SCHEMA)?,
        // Version 3 added token lifecycle, CSRF, and OAuth audience metadata.
        3 => {
            // Development versions constrained schema_meta to exactly v2.
            // Rebuild it before advancing so schema versions can evolve.
            tx.execute_batch(
                "CREATE TABLE schema_meta_migration(version INTEGER NOT NULL);
                 INSERT INTO schema_meta_migration(version) SELECT version FROM schema_meta;
                 DROP TABLE schema_meta;
                 ALTER TABLE schema_meta_migration RENAME TO schema_meta;",
            )?;
            for (table, column, definition) in [
                ("oauth_tokens", "refresh_expires_at", "INTEGER"),
                ("oauth_tokens", "token_id", "TEXT"),
                ("oauth_tokens", "issued_at", "INTEGER"),
                ("oauth_tokens", "last_used_at", "INTEGER"),
                ("sessions", "csrf_hash", "BLOB"),
                ("upstream_oauth_clients", "resource", "TEXT"),
                ("upstream_oauth_clients", "issuer", "TEXT"),
                ("oauth_states", "resource", "TEXT"),
            ] {
                if !column_exists(tx, table, column)? {
                    tx.execute_batch(&format!(
                        "ALTER TABLE {table} ADD COLUMN {column} {definition}"
                    ))?;
                }
            }
            tx.execute_batch(
                "UPDATE oauth_tokens SET issued_at=expires_at-3600 WHERE issued_at IS NULL;
                 UPDATE oauth_tokens SET token_id=lower(hex(token_hash)) WHERE token_id IS NULL;
                 CREATE UNIQUE INDEX IF NOT EXISTS oauth_tokens_token_id ON oauth_tokens(token_id);",
            )?;
        }
        // Version 4 added the Git credential and repository schema. Running
        // the complete idempotent DDL keeps upgrades from development builds
        // (which shipped parts of this schema under v2) safe.
        4 => tx.execute_batch(INITIAL_SCHEMA)?,
        // Version 5 introduced encrypted, durable SSH host and user-CA keys.
        5 => tx.execute_batch(
            "CREATE TABLE IF NOT EXISTS ssh_keys(
               id TEXT PRIMARY KEY,
               purpose TEXT NOT NULL CHECK(purpose IN ('host','user_ca')),
               algorithm TEXT NOT NULL,
               public_key TEXT NOT NULL,
               private_ciphertext TEXT NOT NULL,
               created_at INTEGER NOT NULL,
               active INTEGER NOT NULL DEFAULT 0,
               retirement_time INTEGER
             );
             CREATE UNIQUE INDEX IF NOT EXISTS ssh_keys_one_active ON ssh_keys(purpose) WHERE active=1;",
        )?,
        // Version 6 removes the superseded downstream HTTPS credential path.
        6 => tx.execute_batch("DROP TABLE IF EXISTS git_credentials;")?,
        // Version 7 replaces short-lived user certificates with registered
        // agent public keys whose authorization is a renewable server lease.
        7 => tx.execute_batch(
            "CREATE TABLE IF NOT EXISTS agent_ssh_keys(
               agent_id TEXT PRIMARY KEY REFERENCES agents(id) ON DELETE CASCADE,
               public_key TEXT NOT NULL UNIQUE,
               fingerprint TEXT NOT NULL UNIQUE,
               lease_expires_at INTEGER NOT NULL,
               created_at INTEGER NOT NULL,
               updated_at INTEGER NOT NULL,
               revoked_at INTEGER
             );
             DELETE FROM ssh_keys WHERE purpose<>'host';
             DROP INDEX IF EXISTS ssh_keys_one_active;
             CREATE TABLE ssh_keys_v7(
               id TEXT PRIMARY KEY,
               purpose TEXT NOT NULL CHECK(purpose='host'),
               algorithm TEXT NOT NULL,
               public_key TEXT NOT NULL,
               private_ciphertext TEXT NOT NULL,
               created_at INTEGER NOT NULL,
               active INTEGER NOT NULL DEFAULT 0,
               retirement_time INTEGER
             );
             INSERT INTO ssh_keys_v7 SELECT * FROM ssh_keys;
             DROP TABLE ssh_keys;
             ALTER TABLE ssh_keys_v7 RENAME TO ssh_keys;
             CREATE UNIQUE INDEX ssh_keys_one_active ON ssh_keys(purpose) WHERE active=1;",
        )?,
        _ => anyhow::bail!("unsupported migration target {version}"),
    }
    Ok(())
}

fn column_exists(
    tx: &rusqlite::Transaction<'_>,
    table: &str,
    column: &str,
) -> anyhow::Result<bool> {
    let mut statement = tx.prepare(&format!("PRAGMA table_info({table})"))?;
    Ok(statement
        .query_map([], |row| row.get::<_, String>(1))?
        .collect::<Result<Vec<_>, _>>()?
        .iter()
        .any(|candidate| candidate == column))
}

fn restrict_database_file(path: &Path) -> anyhow::Result<()> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600))?;
    }
    #[cfg(windows)]
    {
        let username =
            std::env::var("USERNAME").map_err(|_| anyhow::anyhow!("USERNAME is not set"))?;
        let status = std::process::Command::new("icacls")
            .arg(path)
            .args(["/inheritance:r", "/grant:r", &format!("{username}:(R,W)")])
            .status()?;
        anyhow::ensure!(
            status.success(),
            "could not restrict access to {}",
            path.display()
        );
    }
    Ok(())
}

impl Database {
    pub fn open(path: &Path) -> anyhow::Result<Self> {
        Self::open_with_mode(path, StorageMode::S3)
    }

    pub fn inspect_storage_mode(path: &Path) -> anyhow::Result<Option<StorageMode>> {
        if !path.exists() {
            return Ok(None);
        }
        let conn = Connection::open_with_flags(path, rusqlite::OpenFlags::SQLITE_OPEN_READ_ONLY)?;
        let has_meta: bool = conn.query_row(
            "SELECT EXISTS(SELECT 1 FROM sqlite_master WHERE type='table' AND name='cog_meta')",
            [],
            |row| row.get(0),
        )?;
        if !has_meta {
            return Ok(None);
        }
        let value = conn
            .query_row(
                "SELECT value FROM cog_meta WHERE key='storage_mode'",
                [],
                |row| row.get::<_, String>(0),
            )
            .optional()?;
        match value.as_deref() {
            None => Ok(None),
            Some("local") => Ok(Some(StorageMode::Local)),
            Some("s3") => Ok(Some(StorageMode::S3)),
            Some(other) => anyhow::bail!("unsupported cog storage mode {other:?}"),
        }
    }

    pub fn open_with_mode(path: &Path, mode: StorageMode) -> anyhow::Result<Self> {
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent)?;
        }
        let mut conn = Connection::open(path)?;
        conn.pragma_update(None, "journal_mode", "WAL")?;
        conn.pragma_update(None, "synchronous", "FULL")?;
        // In S3 mode the replication capture connection owns checkpoint
        // policy. Local mode retains SQLite's bounded default WAL behavior.
        if mode == StorageMode::S3 {
            conn.pragma_update(None, "wal_autocheckpoint", 0)?;
        }
        let has_schema_meta: bool = conn.query_row(
            "SELECT EXISTS(SELECT 1 FROM sqlite_master WHERE type='table' AND name='schema_meta')",
            [],
            |row| row.get(0),
        )?;
        let has_legacy_tables:bool=conn.query_row("SELECT EXISTS(SELECT 1 FROM sqlite_master WHERE type='table' AND name NOT LIKE 'sqlite_%' AND name!='schema_meta')",[],|row|row.get(0))?;
        anyhow::ensure!(
            has_schema_meta || !has_legacy_tables,
            "legacy database detected; back up and explicitly initialize a clean identity schema"
        );
        if !has_schema_meta {
            conn.execute_batch(INITIAL_SCHEMA).map_err(|error| anyhow::anyhow!(
                "database migration 1 failed; the transaction was rolled back—back up the database before recovery: {error}"
            ))?;
        }
        let mut schema_version: i64 =
            conn.query_row("SELECT version FROM schema_meta LIMIT 1", [], |row| {
                row.get(0)
            })?;
        anyhow::ensure!(
            schema_version <= SCHEMA_VERSION,
            "database schema version {schema_version} is newer than this binary supports ({SCHEMA_VERSION}); upgrade cog and do not modify the database"
        );
        while schema_version < SCHEMA_VERSION {
            let target = schema_version + 1;
            let tx = conn.transaction()?;
            let result = apply_migration(&tx, target).and_then(|()| {
                tx.execute("UPDATE schema_meta SET version=?", [target])?;
                Ok(())
            });
            match result {
                Ok(()) => tx.commit().map_err(anyhow::Error::from)?,
                Err(error) => {
                    return Err(anyhow::anyhow!(
                        "database migration {target} failed; the transaction was rolled back—back up the database before recovery: {error}"
                    ));
                }
            }
            schema_version = target;
        }
        let existing_mode = conn
            .query_row(
                "SELECT value FROM cog_meta WHERE key='storage_mode'",
                [],
                |row| row.get::<_, String>(0),
            )
            .optional()?;
        if let Some(existing) = existing_mode {
            anyhow::ensure!(
                existing == mode.as_str(),
                "database storage mode is {existing}, but cog was started in {} mode",
                mode.as_str()
            );
        } else {
            conn.execute(
                "INSERT INTO cog_meta(key,value) VALUES('storage_mode',?)",
                [mode.as_str()],
            )?;
        }
        conn.execute(
            "INSERT INTO cog_meta(key,value) VALUES('last_opened_by_version',?) ON CONFLICT(key) DO UPDATE SET value=excluded.value",
            [env!("CARGO_PKG_VERSION")],
        )?;
        restrict_database_file(path)?;
        Ok(Self(Arc::new(Mutex::new(conn))))
    }

    pub fn schema_version(&self) -> anyhow::Result<i64> {
        let conn = self
            .0
            .lock()
            .map_err(|_| anyhow::anyhow!("database lock poisoned"))?;
        Ok(
            conn.query_row("SELECT version FROM schema_meta LIMIT 1", [], |row| {
                row.get(0)
            })?,
        )
    }

    pub fn transact<T>(
        &self,
        f: impl FnOnce(&rusqlite::Transaction<'_>) -> anyhow::Result<T>,
    ) -> anyhow::Result<T> {
        let mut conn = self
            .0
            .lock()
            .map_err(|_| anyhow::anyhow!("database lock poisoned"))?;
        let tx = conn.transaction()?;
        let value = f(&tx)?;
        tx.commit()?;
        Ok(value)
    }
}
