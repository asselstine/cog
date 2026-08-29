use rusqlite::{Connection, OptionalExtension, params};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::{
    path::Path,
    sync::{Arc, Mutex},
};
use uuid::Uuid;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum StorageMode {
    Local,
    S3,
}

impl StorageMode {
    fn as_str(self) -> &'static str {
        match self {
            Self::Local => "local",
            Self::S3 => "s3",
        }
    }
}

pub const SCHEMA_VERSION: i64 = 6;

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
 id TEXT PRIMARY KEY, purpose TEXT NOT NULL CHECK(purpose IN ('host','user_ca')),
 algorithm TEXT NOT NULL, public_key TEXT NOT NULL, private_ciphertext TEXT NOT NULL,
 created_at INTEGER NOT NULL, active INTEGER NOT NULL DEFAULT 0,
 retirement_time INTEGER
);
CREATE UNIQUE INDEX IF NOT EXISTS ssh_keys_one_active ON ssh_keys(purpose) WHERE active=1;
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

#[derive(Clone)]
pub struct Database(Arc<Mutex<Connection>>);
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Integration {
    pub id: String,
    pub user_id: String,
    pub identity_id: String,
    pub name: String,
    pub provider_name: Option<String>,
    pub provider_account: Option<String>,
    pub transport: String,
    pub config: serde_json::Value,
    pub enabled: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Identity {
    pub id: String,
    pub user_id: String,
    pub name: String,
    pub created_at: i64,
    pub updated_at: i64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Agent {
    pub id: String,
    pub identity_id: String,
    pub oauth_client_id: String,
    pub registered_name: String,
    pub display_name: String,
    pub created_at: i64,
    pub updated_at: i64,
    pub last_used_at: Option<i64>,
}

#[derive(Debug, Clone)]
pub struct GitHubAppSetup {
    pub user_id: String,
    pub integration_id: String,
    pub expires_at: i64,
    pub app_slug: Option<String>,
    pub manifest_completed_at: Option<i64>,
}
pub type AuthorizationCodeRow = (String, String, String, String, String, i64);
pub type UpstreamOAuthStateRow = (String, String, String, String, i64, Option<String>);
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UpstreamOAuthClient {
    pub client_id: String,
    pub client_secret_ciphertext: Option<String>,
    pub authorization_endpoint: String,
    pub token_endpoint: String,
    /// Empty in the database means the authorization server did not advertise
    /// scopes and the integration did not explicitly request one.
    pub scope: String,
    pub resource: Option<String>,
    pub issuer: Option<String>,
}
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UpstreamOAuthToken {
    pub access_token_ciphertext: String,
    pub refresh_token_ciphertext: Option<String>,
    pub token_type: String,
    pub scope: String,
    pub expires_at: Option<i64>,
    pub refresh_expires_at: Option<i64>,
}
#[derive(Debug, Clone, Serialize)]
pub struct AuditEvent {
    pub id: i64,
    pub occurred_at: i64,
    pub actor: Option<String>,
    pub action: String,
    pub target: Option<String>,
    pub outcome: String,
    pub details: serde_json::Value,
}
#[derive(Debug, Clone, Serialize)]
pub struct AgentClient {
    pub client_id: String,
    pub client_name: String,
    pub redirect_uris: Vec<String>,
    pub created_at: i64,
    pub scopes: Vec<String>,
    pub integration_ids: Vec<String>,
}
#[derive(Debug, Clone, Serialize)]
pub struct AgentToken {
    pub token_id: String,
    pub client_id: String,
    pub scope: String,
    pub issued_at: i64,
    pub expires_at: i64,
    pub refresh_expires_at: Option<i64>,
    pub last_used_at: Option<i64>,
    pub integration_ids: Vec<String>,
    pub refresh_capable: bool,
}
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TokenContext {
    pub user_id: String,
    pub agent_id: String,
    pub client_id: String,
    pub identity_id: String,
    pub scopes: Vec<String>,
    pub integration_ids: Vec<String>,
}

#[derive(Debug, Clone, Serialize)]
pub struct SshKeyRecord {
    pub id: String,
    pub purpose: String,
    pub algorithm: String,
    pub public_key: String,
    #[serde(skip_serializing)]
    pub private_ciphertext: String,
    pub created_at: i64,
    pub active: bool,
    pub retirement_time: Option<i64>,
}
type RefreshTokenRow = (Vec<u8>, String, String, String, Option<i64>);
fn git_repo_row(row: &rusqlite::Row<'_>) -> rusqlite::Result<crate::git::GitRepository> {
    Ok(crate::git::GitRepository {
        id: row.get(0)?,
        user_id: row.get(1)?,
        integration_id: row.get(2)?,
        provider_repository_id: row.get(3)?,
        display_name: row.get(4)?,
        upstream_url: row.get(5)?,
        metadata: serde_json::from_str(&row.get::<_, String>(6)?).unwrap_or_default(),
    })
}

fn normalize_display_name(value: &str) -> anyhow::Result<String> {
    let normalized = value.split_whitespace().collect::<Vec<_>>().join(" ");
    anyhow::ensure!(!normalized.is_empty(), "name is required");
    anyhow::ensure!(normalized.chars().count() <= 128, "name is too long");
    anyhow::ensure!(
        normalized.chars().all(|c| !c.is_control()),
        "name contains control characters"
    );
    Ok(normalized)
}
fn split_grant(scope: &str) -> (String, String) {
    if let Some(id) = scope.strip_prefix("integration:") {
        ("integration".into(), id.into())
    } else {
        (scope.into(), String::new())
    }
}
fn agent_row(row: &rusqlite::Row<'_>) -> rusqlite::Result<Agent> {
    Ok(Agent {
        id: row.get(0)?,
        identity_id: row.get(1)?,
        oauth_client_id: row.get(2)?,
        registered_name: row.get(3)?,
        display_name: row.get(4)?,
        created_at: row.get(5)?,
        updated_at: row.get(6)?,
        last_used_at: row.get(7)?,
    })
}
fn agent_for_client_conn(conn: &Connection, client: &str) -> anyhow::Result<Option<Agent>> {
    Ok(conn.query_row("SELECT a.id,a.identity_id,a.oauth_client_id,c.registered_name,a.display_name,a.created_at,a.updated_at,a.last_used_at FROM agents a JOIN oauth_clients c ON c.client_id=a.oauth_client_id WHERE a.oauth_client_id=?",[client],agent_row).optional()?)
}
fn agent_for_client_tx(
    tx: &rusqlite::Transaction<'_>,
    client: &str,
) -> anyhow::Result<Option<Agent>> {
    Ok(tx.query_row("SELECT a.id,a.identity_id,a.oauth_client_id,c.registered_name,a.display_name,a.created_at,a.updated_at,a.last_used_at FROM agents a JOIN oauth_clients c ON c.client_id=a.oauth_client_id WHERE a.oauth_client_id=?",[client],agent_row).optional()?)
}

impl Database {
    pub fn ssh_keys(&self) -> anyhow::Result<Vec<SshKeyRecord>> {
        let conn = self
            .0
            .lock()
            .map_err(|_| anyhow::anyhow!("database lock poisoned"))?;
        let mut statement = conn.prepare(
            "SELECT id,purpose,algorithm,public_key,private_ciphertext,created_at,active,retirement_time FROM ssh_keys ORDER BY purpose,created_at DESC",
        )?;
        Ok(statement
            .query_map([], |row| {
                Ok(SshKeyRecord {
                    id: row.get(0)?,
                    purpose: row.get(1)?,
                    algorithm: row.get(2)?,
                    public_key: row.get(3)?,
                    private_ciphertext: row.get(4)?,
                    created_at: row.get(5)?,
                    active: row.get::<_, i64>(6)? != 0,
                    retirement_time: row.get(7)?,
                })
            })?
            .collect::<Result<Vec<_>, _>>()?)
    }

    pub fn active_ssh_key(&self, purpose: &str) -> anyhow::Result<Option<SshKeyRecord>> {
        anyhow::ensure!(
            matches!(purpose, "host" | "user_ca"),
            "invalid SSH key purpose"
        );
        let conn = self
            .0
            .lock()
            .map_err(|_| anyhow::anyhow!("database lock poisoned"))?;
        Ok(conn.query_row(
            "SELECT id,purpose,algorithm,public_key,private_ciphertext,created_at,active,retirement_time FROM ssh_keys WHERE purpose=? AND active=1",
            [purpose],
            |row| Ok(SshKeyRecord { id: row.get(0)?, purpose: row.get(1)?, algorithm: row.get(2)?, public_key: row.get(3)?, private_ciphertext: row.get(4)?, created_at: row.get(5)?, active: row.get::<_, i64>(6)? != 0, retirement_time: row.get(7)? }),
        ).optional()?)
    }

    /// Atomically installs a first key. A concurrent creator loses the insert
    /// race and receives the already-active durable record.
    pub fn install_initial_ssh_key(
        &self,
        purpose: &str,
        public_key: &str,
        private_ciphertext: &str,
    ) -> anyhow::Result<SshKeyRecord> {
        anyhow::ensure!(
            matches!(purpose, "host" | "user_ca"),
            "invalid SSH key purpose"
        );
        let id = Uuid::new_v4().to_string();
        let now = chrono::Utc::now().timestamp();
        self.transact(|tx| {
            tx.execute(
                "INSERT OR IGNORE INTO ssh_keys(id,purpose,algorithm,public_key,private_ciphertext,created_at,active) VALUES(?,?,'ssh-ed25519',?,?,?,1)",
                params![id, purpose, public_key, private_ciphertext, now],
            )?;
            Ok(())
        })?;
        self.active_ssh_key(purpose)?
            .ok_or_else(|| anyhow::anyhow!("SSH key initialization did not converge"))
    }

    pub fn prepare_ssh_key(
        &self,
        purpose: &str,
        public_key: &str,
        private_ciphertext: &str,
    ) -> anyhow::Result<SshKeyRecord> {
        anyhow::ensure!(
            matches!(purpose, "host" | "user_ca"),
            "invalid SSH key purpose"
        );
        let id = Uuid::new_v4().to_string();
        let now = chrono::Utc::now().timestamp();
        self.transact(|tx| {
            tx.execute(
                "INSERT INTO ssh_keys(id,purpose,algorithm,public_key,private_ciphertext,created_at,active) VALUES(?,?,'ssh-ed25519',?,?,?,0)",
                params![id, purpose, public_key, private_ciphertext, now],
            )?;
            Ok(())
        })?;
        self.ssh_keys()?
            .into_iter()
            .find(|key| key.id == id)
            .ok_or_else(|| anyhow::anyhow!("prepared SSH key was not found"))
    }

    pub fn activate_ssh_key(
        &self,
        id: &str,
        purpose: &str,
        retirement_time: i64,
    ) -> anyhow::Result<()> {
        anyhow::ensure!(
            matches!(purpose, "host" | "user_ca"),
            "invalid SSH key purpose"
        );
        self.transact(|tx| {
            let exists: bool = tx.query_row(
                "SELECT EXISTS(SELECT 1 FROM ssh_keys WHERE id=? AND purpose=? AND active=0 AND retirement_time IS NULL)",
                params![id, purpose],
                |row| row.get(0),
            )?;
            anyhow::ensure!(exists, "prepared SSH key not found");
            tx.execute(
                "UPDATE ssh_keys SET active=0,retirement_time=? WHERE purpose=? AND active=1",
                params![retirement_time, purpose],
            )?;
            tx.execute("UPDATE ssh_keys SET active=1 WHERE id=?", [id])?;
            Ok(())
        })
    }

    pub fn retire_ssh_key(&self, id: &str, now: i64) -> anyhow::Result<()> {
        self.transact(|tx| {
            let changed = tx.execute(
                "DELETE FROM ssh_keys WHERE id=? AND active=0 AND retirement_time IS NOT NULL AND retirement_time<=?",
                params![id, now],
            )?;
            anyhow::ensure!(changed == 1, "SSH key is active or its overlap window has not elapsed");
            Ok(())
        })
    }

    pub fn upsert_git_repository(
        &self,
        user: &str,
        integration: &str,
        resolved: &crate::git::ResolvedRepository,
    ) -> anyhow::Result<crate::git::GitRepository> {
        let now = chrono::Utc::now().timestamp();
        let id = Uuid::new_v4().to_string();
        self.transact(|tx|{tx.execute("INSERT INTO git_repositories(id,user_id,integration_id,provider_repository_id,display_name,upstream_url,metadata_json,created_at,updated_at) VALUES(?,?,?,?,?,?,?,?,?) ON CONFLICT(integration_id,provider_repository_id) DO UPDATE SET display_name=excluded.display_name,upstream_url=excluded.upstream_url,metadata_json=excluded.metadata_json,updated_at=excluded.updated_at",params![id,user,integration,resolved.provider_repository_id,resolved.display_name,resolved.upstream_url.as_str(),resolved.metadata.to_string(),now,now])?;Ok(())})?;
        self.git_repository_by_provider(user, integration, &resolved.provider_repository_id)?
            .ok_or_else(|| anyhow::anyhow!("repository write failed"))
    }
    pub fn git_repository_by_provider(
        &self,
        user: &str,
        integration: &str,
        provider_id: &str,
    ) -> anyhow::Result<Option<crate::git::GitRepository>> {
        let conn = self
            .0
            .lock()
            .map_err(|_| anyhow::anyhow!("database lock poisoned"))?;
        Ok(conn.query_row("SELECT id,user_id,integration_id,provider_repository_id,display_name,upstream_url,metadata_json FROM git_repositories WHERE user_id=? AND integration_id=? AND provider_repository_id=?",params![user,integration,provider_id],git_repo_row).optional()?)
    }
    pub fn git_repository(&self, id: &str) -> anyhow::Result<Option<crate::git::GitRepository>> {
        let conn = self
            .0
            .lock()
            .map_err(|_| anyhow::anyhow!("database lock poisoned"))?;
        Ok(conn.query_row("SELECT id,user_id,integration_id,provider_repository_id,display_name,upstream_url,metadata_json FROM git_repositories WHERE id=?",[id],git_repo_row).optional()?)
    }
    pub fn set_git_grant(
        &self,
        user: &str,
        client: &str,
        repository: &str,
        permission: &str,
    ) -> anyhow::Result<()> {
        anyhow::ensure!(
            matches!(permission, "read" | "write"),
            "invalid Git permission"
        );
        let now = chrono::Utc::now().timestamp();
        self.transact(|tx|{let identity:String=tx.query_row("SELECT a.identity_id FROM agents a JOIN identities i ON i.id=a.identity_id JOIN git_repositories r ON r.id=? JOIN integrations n ON n.id=r.integration_id WHERE a.oauth_client_id=? AND i.user_id=? AND n.identity_id=a.identity_id",params![repository,client,user],|r|r.get(0))?;tx.execute("INSERT INTO git_repository_grants(identity_id,user_id,client_id,repository_id,permission,created_at,revoked_at) VALUES(?,?,?,?,?,?,NULL) ON CONFLICT(identity_id,repository_id) DO UPDATE SET permission=excluded.permission,revoked_at=NULL",params![identity,user,client,repository,permission,now])?;Ok(())})
    }
    pub fn revoke_git_grant(
        &self,
        user: &str,
        client: &str,
        repository: &str,
    ) -> anyhow::Result<bool> {
        let now = chrono::Utc::now().timestamp();
        self.transact(|tx|{let identity:Option<String>=tx.query_row("SELECT a.identity_id FROM agents a JOIN identities i ON i.id=a.identity_id WHERE a.oauth_client_id=? AND i.user_id=?",params![client,user],|r|r.get(0)).optional()?;let Some(identity)=identity else{return Ok(false)};let changed=tx.execute("UPDATE git_repository_grants SET revoked_at=? WHERE identity_id=? AND repository_id=? AND revoked_at IS NULL",params![now,identity,repository])?;Ok(changed>0)})
    }
    pub fn git_grant_permission(
        &self,
        user: &str,
        client: &str,
        repository: &str,
    ) -> anyhow::Result<Option<String>> {
        let conn = self
            .0
            .lock()
            .map_err(|_| anyhow::anyhow!("database lock poisoned"))?;
        Ok(conn.query_row("SELECT g.permission FROM git_repository_grants g JOIN agents a ON a.identity_id=g.identity_id JOIN identities i ON i.id=a.identity_id WHERE i.user_id=? AND a.oauth_client_id=? AND g.repository_id=? AND g.revoked_at IS NULL",params![user,client,repository],|r|r.get(0)).optional()?)
    }
    pub fn touch_git_grant(
        &self,
        user: &str,
        client: &str,
        repository: &str,
        now: i64,
    ) -> anyhow::Result<()> {
        self.transact(|tx|{tx.execute("UPDATE git_repository_grants SET last_used_at=? WHERE repository_id=? AND identity_id IN(SELECT a.identity_id FROM agents a JOIN identities i ON i.id=a.identity_id WHERE a.oauth_client_id=? AND i.user_id=?) AND revoked_at IS NULL",params![now,repository,client,user])?;Ok(())})
    }
    pub fn list_git_grants(
        &self,
        user: &str,
        client: &str,
    ) -> anyhow::Result<Vec<crate::git::model::RepositoryGrant>> {
        let conn = self
            .0
            .lock()
            .map_err(|_| anyhow::anyhow!("database lock poisoned"))?;
        let mut s=conn.prepare("SELECT r.id,r.user_id,r.integration_id,r.provider_repository_id,r.display_name,r.upstream_url,r.metadata_json,g.permission,g.last_used_at FROM git_repository_grants g JOIN git_repositories r ON r.id=g.repository_id JOIN agents a ON a.identity_id=g.identity_id JOIN identities i ON i.id=a.identity_id WHERE i.user_id=? AND a.oauth_client_id=? AND g.revoked_at IS NULL ORDER BY r.display_name")?;
        let rows = s.query_map(params![user, client], |r| {
            Ok(crate::git::model::RepositoryGrant {
                repository: crate::git::GitRepository {
                    id: r.get(0)?,
                    user_id: r.get(1)?,
                    integration_id: r.get(2)?,
                    provider_repository_id: r.get(3)?,
                    display_name: r.get(4)?,
                    upstream_url: r.get(5)?,
                    metadata: serde_json::from_str(&r.get::<_, String>(6)?).unwrap_or_default(),
                },
                permission: r.get(7)?,
                last_used_at: r.get(8)?,
            })
        })?;
        Ok(rows.collect::<Result<Vec<_>, _>>()?)
    }
    pub fn all_git_grants(&self, user: &str) -> anyhow::Result<Vec<serde_json::Value>> {
        let conn = self
            .0
            .lock()
            .map_err(|_| anyhow::anyhow!("database lock poisoned"))?;
        let mut s=conn.prepare("SELECT g.client_id,c.client_name,r.id,r.integration_id,r.display_name,g.permission,g.created_at,g.last_used_at FROM git_repository_grants g JOIN git_repositories r ON r.id=g.repository_id JOIN oauth_clients c ON c.client_id=g.client_id WHERE g.user_id=? AND g.revoked_at IS NULL ORDER BY r.display_name,c.client_name")?;
        let rows=s.query_map([user],|r|Ok(serde_json::json!({"client_id":r.get::<_,String>(0)?,"client_name":r.get::<_,String>(1)?,"repository_id":r.get::<_,String>(2)?,"integration_id":r.get::<_,String>(3)?,"display_name":r.get::<_,String>(4)?,"permission":r.get::<_,String>(5)?,"created_at":r.get::<_,i64>(6)?,"last_used_at":r.get::<_,Option<i64>>(7)?})))?;
        Ok(rows.collect::<Result<Vec<_>, _>>()?)
    }
    pub fn create_git_pending_request(
        &self,
        user: &str,
        client: &str,
        integration: &str,
        repository: &str,
        permission: &str,
        ttl: i64,
    ) -> anyhow::Result<String> {
        anyhow::ensure!(
            matches!(permission, "read" | "write"),
            "invalid Git permission"
        );
        let capability = crate::crypto::random_token(32);
        let hash = crate::crypto::token_hash(&capability);
        let id = hex::encode(hash);
        let now = chrono::Utc::now().timestamp();
        self.transact(|tx|{tx.execute("DELETE FROM git_pending_requests WHERE expires_at<=? OR consumed_at IS NOT NULL",[now])?;let identity:String=tx.query_row("SELECT a.identity_id FROM agents a JOIN identities i ON i.id=a.identity_id JOIN integrations n ON n.identity_id=a.identity_id WHERE a.oauth_client_id=? AND i.user_id=? AND n.id=?",params![client,user,integration],|r|r.get(0))?;tx.execute("INSERT INTO git_pending_requests(id_hash,identity_id,user_id,client_id,integration_id,repository_id,permission,expires_at) VALUES(?,?,?,?,?,?,?,?)",params![hash.as_slice(),identity,user,client,integration,repository,permission,now+ttl])?;Ok(())})?;
        Ok(id)
    }
    pub fn git_pending_requests(
        &self,
        user: &str,
        client: &str,
        now: i64,
    ) -> anyhow::Result<Vec<crate::git::model::PendingRepositoryRequest>> {
        let conn = self
            .0
            .lock()
            .map_err(|_| anyhow::anyhow!("database lock poisoned"))?;
        let mut s=conn.prepare("SELECT lower(hex(p.id_hash)),p.repository_id,p.integration_id,r.display_name,p.permission,p.expires_at FROM git_pending_requests p JOIN git_repositories r ON r.id=p.repository_id WHERE p.user_id=? AND p.client_id=? AND p.expires_at>? AND p.consumed_at IS NULL ORDER BY p.expires_at")?;
        let rows = s.query_map(params![user, client, now], |r| {
            Ok(crate::git::model::PendingRepositoryRequest {
                id: r.get(0)?,
                repository_id: r.get(1)?,
                integration_id: r.get(2)?,
                display_name: r.get(3)?,
                permission: r.get(4)?,
                expires_at: r.get(5)?,
            })
        })?;
        Ok(rows.collect::<Result<Vec<_>, _>>()?)
    }
    pub fn consume_git_pending_requests(
        &self,
        user: &str,
        client: &str,
        approved: &[String],
        now: i64,
    ) -> anyhow::Result<Vec<(String, String)>> {
        self.transact(|tx|{let mut grants=Vec::new();for id in approved{let hash=hex::decode(id)?;let row:Option<(String,String,String)>=tx.query_row("SELECT repository_id,permission,identity_id FROM git_pending_requests WHERE id_hash=? AND user_id=? AND client_id=? AND expires_at>? AND consumed_at IS NULL",params![hash,user,client,now],|r|Ok((r.get(0)?,r.get(1)?,r.get(2)?))).optional()?;if let Some((repository,permission,identity))=row{tx.execute("INSERT INTO git_repository_grants(identity_id,user_id,client_id,repository_id,permission,created_at,revoked_at) VALUES(?,?,?,?,?,?,NULL) ON CONFLICT(identity_id,repository_id) DO UPDATE SET permission=CASE WHEN git_repository_grants.permission='write' OR excluded.permission='write' THEN 'write' ELSE 'read' END,revoked_at=NULL",params![identity,user,client,repository,permission,now])?;tx.execute("UPDATE git_pending_requests SET consumed_at=? WHERE id_hash=?",params![now,hash])?;grants.push((repository,permission));}}
        tx.execute("UPDATE git_pending_requests SET consumed_at=? WHERE user_id=? AND client_id=? AND consumed_at IS NULL",params![now,user,client])?;Ok(grants)})
    }
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
    pub fn create_user(&self, email: &str, password_hash: &str) -> anyhow::Result<String> {
        let id = Uuid::new_v4().to_string();
        self.transact(|tx| {
            tx.execute(
                "INSERT INTO users(id,email,password_hash) VALUES(?,?,?)",
                params![id, email, password_hash],
            )?;
            Ok(())
        })?;
        Ok(id)
    }
    pub fn user_by_email(&self, email: &str) -> anyhow::Result<Option<(String, String)>> {
        let conn = self
            .0
            .lock()
            .map_err(|_| anyhow::anyhow!("database lock poisoned"))?;
        Ok(conn
            .query_row(
                "SELECT id,password_hash FROM users WHERE email=?",
                [email],
                |r| Ok((r.get(0)?, r.get(1)?)),
            )
            .optional()?)
    }
    pub fn user_count(&self) -> anyhow::Result<u64> {
        let conn = self
            .0
            .lock()
            .map_err(|_| anyhow::anyhow!("database lock poisoned"))?;
        Ok(conn.query_row("SELECT count(*) FROM users", [], |r| r.get(0))?)
    }
    pub fn create_identity(&self, user: &str, name: &str) -> anyhow::Result<String> {
        let name = normalize_display_name(name)?;
        let id = Uuid::new_v4().to_string();
        let now = chrono::Utc::now().timestamp();
        self.transact(|tx| {
            tx.execute(
                "INSERT INTO identities(id,user_id,name,created_at,updated_at) VALUES(?,?,?,?,?)",
                params![id, user, name, now, now],
            )?;
            tx.execute(
                "INSERT INTO identity_grants(identity_id,capability,created_at) VALUES(?,'mcp',?)",
                params![id, now],
            )?;
            Ok(())
        })?;
        Ok(id)
    }
    pub fn list_identities(&self, user: &str) -> anyhow::Result<Vec<Identity>> {
        let conn = self
            .0
            .lock()
            .map_err(|_| anyhow::anyhow!("database lock poisoned"))?;
        let mut statement = conn.prepare("SELECT id,user_id,name,created_at,updated_at FROM identities WHERE user_id=? ORDER BY name,id")?;
        Ok(statement
            .query_map([user], |row| {
                Ok(Identity {
                    id: row.get(0)?,
                    user_id: row.get(1)?,
                    name: row.get(2)?,
                    created_at: row.get(3)?,
                    updated_at: row.get(4)?,
                })
            })?
            .collect::<Result<Vec<_>, _>>()?)
    }
    pub fn identity(&self, user: &str, id: &str) -> anyhow::Result<Option<Identity>> {
        let conn = self
            .0
            .lock()
            .map_err(|_| anyhow::anyhow!("database lock poisoned"))?;
        Ok(conn.query_row("SELECT id,user_id,name,created_at,updated_at FROM identities WHERE id=? AND user_id=?",params![id,user],|row|Ok(Identity{id:row.get(0)?,user_id:row.get(1)?,name:row.get(2)?,created_at:row.get(3)?,updated_at:row.get(4)?})).optional()?)
    }
    pub fn rename_identity(&self, user: &str, id: &str, name: &str) -> anyhow::Result<bool> {
        let name = normalize_display_name(name)?;
        self.transact(|tx| {
            Ok(tx.execute(
                "UPDATE identities SET name=?,updated_at=? WHERE id=? AND user_id=?",
                params![name, chrono::Utc::now().timestamp(), id, user],
            )? > 0)
        })
    }
    pub fn delete_identity(&self, user: &str, id: &str) -> anyhow::Result<bool> {
        self.transact(|tx| {
            Ok(tx.execute(
                "DELETE FROM identities WHERE id=? AND user_id=?",
                params![id, user],
            )? > 0)
        })
    }
    pub fn bind_agent(&self, user: &str, identity: &str, client: &str) -> anyhow::Result<Agent> {
        let now = chrono::Utc::now().timestamp();
        self.transact(|tx| {
            let owned: bool=tx.query_row("SELECT EXISTS(SELECT 1 FROM identities WHERE id=? AND user_id=?)",params![identity,user],|row|row.get(0))?;
            anyhow::ensure!(owned,"identity not found");
            if let Some(existing)=agent_for_client_tx(tx,client)? {
                anyhow::ensure!(existing.identity_id==identity,"agent is already bound to another identity");
                return Ok(existing);
            }
            let registered: String=tx.query_row("SELECT registered_name FROM oauth_clients WHERE client_id=?",[client],|row|row.get(0))?;
            let display=normalize_display_name(&registered)?;
            let id=Uuid::new_v4().to_string();
            tx.execute("INSERT INTO agents(id,identity_id,oauth_client_id,display_name,created_at,updated_at) VALUES(?,?,?,?,?,?)",params![id,identity,client,display,now,now])?;
            agent_for_client_tx(tx,client)?.ok_or_else(||anyhow::anyhow!("agent binding failed"))
        })
    }
    pub fn agent_for_client(&self, client: &str) -> anyhow::Result<Option<Agent>> {
        let conn = self
            .0
            .lock()
            .map_err(|_| anyhow::anyhow!("database lock poisoned"))?;
        agent_for_client_conn(&conn, client)
    }
    pub fn agents_for_identity(&self, user: &str, identity: &str) -> anyhow::Result<Vec<Agent>> {
        let conn = self
            .0
            .lock()
            .map_err(|_| anyhow::anyhow!("database lock poisoned"))?;
        let mut statement=conn.prepare("SELECT a.id,a.identity_id,a.oauth_client_id,c.registered_name,a.display_name,a.created_at,a.updated_at,a.last_used_at FROM agents a JOIN oauth_clients c ON c.client_id=a.oauth_client_id JOIN identities i ON i.id=a.identity_id WHERE i.user_id=? AND i.id=? ORDER BY a.display_name,a.id")?;
        Ok(statement
            .query_map(params![user, identity], agent_row)?
            .collect::<Result<Vec<_>, _>>()?)
    }
    pub fn rename_agent(&self, user: &str, agent: &str, name: &str) -> anyhow::Result<bool> {
        let name = normalize_display_name(name)?;
        self.transact(|tx|Ok(tx.execute("UPDATE agents SET display_name=?,updated_at=? WHERE id=? AND identity_id IN (SELECT id FROM identities WHERE user_id=?)",params![name,chrono::Utc::now().timestamp(),agent,user])?>0))
    }
    pub fn rename_self(&self, agent: &str, name: &str) -> anyhow::Result<bool> {
        let name = normalize_display_name(name)?;
        self.transact(|tx| {
            Ok(tx.execute(
                "UPDATE agents SET display_name=?,updated_at=? WHERE id=?",
                params![name, chrono::Utc::now().timestamp(), agent],
            )? > 0)
        })
    }
    pub fn identity_grants(&self, user: &str, identity: &str) -> anyhow::Result<Vec<String>> {
        let conn = self
            .0
            .lock()
            .map_err(|_| anyhow::anyhow!("database lock poisoned"))?;
        let mut statement=conn.prepare("SELECT capability,resource_id,permission FROM identity_grants WHERE identity_id=? AND revoked_at IS NULL AND EXISTS(SELECT 1 FROM identities WHERE id=? AND user_id=?) ORDER BY capability,resource_id")?;
        Ok(statement
            .query_map(params![identity, identity, user], |row| {
                let c: String = row.get(0)?;
                let r: String = row.get(1)?;
                let p: String = row.get(2)?;
                Ok(if r.is_empty() {
                    c
                } else if p.is_empty() {
                    format!("{c}:{r}")
                } else {
                    format!("{c}:{r}:{p}")
                })
            })?
            .collect::<Result<Vec<_>, _>>()?)
    }
    pub fn set_identity_grants(
        &self,
        user: &str,
        identity: &str,
        scopes: &[String],
    ) -> anyhow::Result<()> {
        let now = chrono::Utc::now().timestamp();
        self.transact(|tx|{
            let owned:bool=tx.query_row("SELECT EXISTS(SELECT 1 FROM identities WHERE id=? AND user_id=?)",params![identity,user],|row|row.get(0))?;
            anyhow::ensure!(owned,"identity not found");
            tx.execute("UPDATE identity_grants SET revoked_at=? WHERE identity_id=? AND revoked_at IS NULL",params![now,identity])?;
            let mut values=scopes.to_vec(); if !values.iter().any(|v|v=="mcp"){values.push("mcp".into());}
            for scope in values { let (capability,resource)=split_grant(&scope); tx.execute("INSERT INTO identity_grants(identity_id,capability,resource_id,created_at,revoked_at) VALUES(?,?,?,?,NULL) ON CONFLICT(identity_id,capability,resource_id) DO UPDATE SET revoked_at=NULL,created_at=excluded.created_at",params![identity,capability,resource,now])?; }
            Ok(())
        })
    }
    pub fn create_session(
        &self,
        token_hash: &[u8],
        user: &str,
        csrf_hash: &[u8],
        expires_at: i64,
    ) -> anyhow::Result<()> {
        self.transact(|tx| {
            tx.execute(
                "INSERT INTO sessions(token_hash,user_id,expires_at,csrf_hash) VALUES(?,?,?,?)",
                params![token_hash, user, expires_at, csrf_hash],
            )?;
            Ok(())
        })
    }
    pub fn session_user(
        &self,
        token_hash: &[u8],
        csrf_hash: Option<&[u8]>,
        now: i64,
    ) -> anyhow::Result<Option<String>> {
        let conn = self
            .0
            .lock()
            .map_err(|_| anyhow::anyhow!("database lock poisoned"))?;
        let row = if let Some(csrf_hash) = csrf_hash {
            conn.query_row(
                "SELECT user_id FROM sessions WHERE token_hash=? AND csrf_hash=? AND expires_at>?",
                params![token_hash, csrf_hash, now],
                |row| row.get(0),
            )
            .optional()?
        } else {
            conn.query_row(
                "SELECT user_id FROM sessions WHERE token_hash=? AND expires_at>?",
                params![token_hash, now],
                |row| row.get(0),
            )
            .optional()?
        };
        Ok(row)
    }
    pub fn delete_session(&self, token_hash: &[u8]) -> anyhow::Result<bool> {
        self.transact(|tx| {
            Ok(tx.execute("DELETE FROM sessions WHERE token_hash=?", [token_hash])? > 0)
        })
    }
    pub fn record_audit(
        &self,
        actor: Option<&str>,
        action: &str,
        target: Option<&str>,
        outcome: &str,
        details: &serde_json::Value,
    ) -> anyhow::Result<()> {
        self.transact(|tx| {
            tx.execute(
                "INSERT INTO audit_log(occurred_at,actor,action,target,outcome,details_json) VALUES(?,?,?,?,?,?)",
                params![chrono::Utc::now().timestamp(),actor,action,target,outcome,details.to_string()],
            )?;
            Ok(())
        })
    }
    pub fn audit_events(&self, limit: u32) -> anyhow::Result<Vec<AuditEvent>> {
        let conn = self
            .0
            .lock()
            .map_err(|_| anyhow::anyhow!("database lock poisoned"))?;
        let mut statement = conn.prepare("SELECT id,occurred_at,actor,action,target,outcome,details_json FROM audit_log ORDER BY id DESC LIMIT ?")?;
        let rows = statement.query_map([limit.min(1000)], |row| {
            let details: String = row.get(6)?;
            Ok(AuditEvent {
                id: row.get(0)?,
                occurred_at: row.get(1)?,
                actor: row.get(2)?,
                action: row.get(3)?,
                target: row.get(4)?,
                outcome: row.get(5)?,
                details: serde_json::from_str(&details).unwrap_or(Value::Null),
            })
        })?;
        Ok(rows.collect::<Result<Vec<_>, _>>()?)
    }
    pub fn audit_events_for_user(&self, user: &str, limit: u32) -> anyhow::Result<Vec<AuditEvent>> {
        let conn = self
            .0
            .lock()
            .map_err(|_| anyhow::anyhow!("database lock poisoned"))?;
        let mut statement = conn.prepare("SELECT id,occurred_at,actor,action,target,outcome,details_json FROM audit_log WHERE actor=? ORDER BY id DESC LIMIT ?")?;
        let rows = statement.query_map(params![user, limit.min(1000)], |row| {
            let details: String = row.get(6)?;
            Ok(AuditEvent {
                id: row.get(0)?,
                occurred_at: row.get(1)?,
                actor: row.get(2)?,
                action: row.get(3)?,
                target: row.get(4)?,
                outcome: row.get(5)?,
                details: serde_json::from_str(&details).unwrap_or(Value::Null),
            })
        })?;
        Ok(rows.collect::<Result<Vec<_>, _>>()?)
    }
    pub fn list_integrations(&self, user: &str) -> anyhow::Result<Vec<Integration>> {
        let conn = self
            .0
            .lock()
            .map_err(|_| anyhow::anyhow!("database lock poisoned"))?;
        let mut stmt=conn.prepare("SELECT id,user_id,display_name,transport,config_json,enabled,identity_id,provider_name,provider_account FROM integrations WHERE user_id=? ORDER BY display_name")?;
        let rows = stmt.query_map([user], |r| {
            Ok(Integration {
                id: r.get(0)?,
                user_id: r.get(1)?,
                identity_id: r.get(6)?,
                name: r.get(2)?,
                provider_name: r.get(7)?,
                provider_account: r.get(8)?,
                transport: r.get(3)?,
                config: serde_json::from_str(&r.get::<_, String>(4)?).unwrap_or_default(),
                enabled: r.get(5)?,
            })
        })?;
        Ok(rows.collect::<Result<Vec<_>, _>>()?)
    }
    pub fn integration_scopes(&self) -> anyhow::Result<Vec<String>> {
        let conn = self
            .0
            .lock()
            .map_err(|_| anyhow::anyhow!("database lock poisoned"))?;
        let mut statement = conn.prepare("SELECT id FROM integrations ORDER BY id")?;
        let ids = statement
            .query_map([], |row| row.get::<_, String>(0))?
            .collect::<Result<Vec<_>, _>>()?;
        Ok(ids
            .into_iter()
            .map(|id| format!("integration:{id}"))
            .collect())
    }
    pub fn checkpoint(&self) -> anyhow::Result<()> {
        let conn = self
            .0
            .lock()
            .map_err(|_| anyhow::anyhow!("database lock poisoned"))?;
        conn.execute_batch("PRAGMA wal_checkpoint(PASSIVE)")?;
        Ok(())
    }
    pub fn create_integration(
        &self,
        user: &str,
        name: &str,
        transport: &str,
        config: &serde_json::Value,
        secret: Option<&str>,
    ) -> anyhow::Result<String> {
        let identity = match self.list_identities(user)?.into_iter().next() {
            Some(identity) => identity.id,
            None => self.create_identity(user, "Default")?,
        };
        self.create_connection(user, &identity, name, transport, config, secret)
    }
    pub fn create_connection(
        &self,
        user: &str,
        identity: &str,
        name: &str,
        transport: &str,
        config: &Value,
        secret: Option<&str>,
    ) -> anyhow::Result<String> {
        let name = normalize_display_name(name)?;
        let id = Uuid::new_v4().to_string();
        let now = chrono::Utc::now().timestamp();
        self.transact(|tx|{let owned:bool=tx.query_row("SELECT EXISTS(SELECT 1 FROM identities WHERE id=? AND user_id=?)",params![identity,user],|row|row.get(0))?;anyhow::ensure!(owned,"identity not found");tx.execute("INSERT INTO integrations(id,identity_id,user_id,display_name,name,transport,config_json,secret_ciphertext,created_at,updated_at) VALUES(?,?,?,?,?,?,?,?,?,?)",params![id,identity,user,name,name,transport,config.to_string(),secret,now,now])?;Ok(())})?;
        Ok(id)
    }

    pub fn create_github_app_setup(
        &self,
        user: &str,
        name: &str,
        state_hash: &[u8],
        expires_at: i64,
    ) -> anyhow::Result<String> {
        let id = Uuid::new_v4().to_string();
        let identity = match self.list_identities(user)?.into_iter().next() {
            Some(identity) => identity.id,
            None => self.create_identity(user, "Default")?,
        };
        let now = chrono::Utc::now().timestamp();
        let config = serde_json::json!({
            "kind": "git",
            "provider": "github",
            "host": "github.com",
            "providerConfig": {},
            "setupStatus": "manifest_pending"
        });
        self.transact(|tx| {
            tx.execute(
                "DELETE FROM github_app_setups WHERE expires_at<=?",
                [chrono::Utc::now().timestamp()],
            )?;
            tx.execute(
                "INSERT INTO integrations(id,identity_id,user_id,display_name,name,transport,config_json,enabled,created_at,updated_at) VALUES(?,?,?,?,?,?,?,0,?,?)",
                params![id,identity,user,name,name,"git",config.to_string(),now,now],
            )?;
            tx.execute(
                "INSERT INTO github_app_setups(state_hash,user_id,integration_id,expires_at) VALUES(?,?,?,?)",
                params![state_hash, user, id, expires_at],
            )?;
            Ok(())
        })?;
        Ok(id)
    }

    pub fn github_app_setup_by_state(
        &self,
        state_hash: &[u8],
        now: i64,
    ) -> anyhow::Result<Option<GitHubAppSetup>> {
        let conn = self
            .0
            .lock()
            .map_err(|_| anyhow::anyhow!("database lock poisoned"))?;
        Ok(conn
            .query_row(
                "SELECT user_id,integration_id,expires_at,app_slug,manifest_completed_at FROM github_app_setups WHERE state_hash=? AND expires_at>?",
                params![state_hash, now],
                |row| {
                    Ok(GitHubAppSetup {
                        user_id: row.get(0)?,
                        integration_id: row.get(1)?,
                        expires_at: row.get(2)?,
                        app_slug: row.get(3)?,
                        manifest_completed_at: row.get(4)?,
                    })
                },
            )
            .optional()?)
    }

    pub fn github_app_setup_for_integration(
        &self,
        user: &str,
        integration: &str,
        now: i64,
    ) -> anyhow::Result<Option<GitHubAppSetup>> {
        let conn = self
            .0
            .lock()
            .map_err(|_| anyhow::anyhow!("database lock poisoned"))?;
        Ok(conn
            .query_row(
                "SELECT user_id,integration_id,expires_at,app_slug,manifest_completed_at FROM github_app_setups WHERE user_id=? AND integration_id=? AND expires_at>?",
                params![user, integration, now],
                |row| {
                    Ok(GitHubAppSetup {
                        user_id: row.get(0)?,
                        integration_id: row.get(1)?,
                        expires_at: row.get(2)?,
                        app_slug: row.get(3)?,
                        manifest_completed_at: row.get(4)?,
                    })
                },
            )
            .optional()?)
    }

    pub fn complete_github_app_manifest(
        &self,
        state_hash: &[u8],
        config: &Value,
        secret_ciphertext: &str,
        app_slug: &str,
        now: i64,
    ) -> anyhow::Result<bool> {
        self.transact(|tx| {
            let integration = tx
                .query_row(
                    "SELECT integration_id FROM github_app_setups WHERE state_hash=? AND expires_at>? AND manifest_completed_at IS NULL",
                    params![state_hash, now],
                    |row| row.get::<_, String>(0),
                )
                .optional()?;
            let Some(integration) = integration else {
                return Ok(false);
            };
            tx.execute(
                "UPDATE integrations SET config_json=?,secret_ciphertext=? WHERE id=?",
                params![config.to_string(), secret_ciphertext, integration],
            )?;
            tx.execute(
                "UPDATE github_app_setups SET app_slug=?,manifest_completed_at=? WHERE state_hash=?",
                params![app_slug, now, state_hash],
            )?;
            Ok(true)
        })
    }

    pub fn complete_github_app_installation(
        &self,
        state_hash: &[u8],
        config: &Value,
        now: i64,
    ) -> anyhow::Result<Option<String>> {
        self.transact(|tx| {
            let integration = tx
                .query_row(
                    "SELECT integration_id FROM github_app_setups WHERE state_hash=? AND expires_at>? AND manifest_completed_at IS NOT NULL",
                    params![state_hash, now],
                    |row| row.get::<_, String>(0),
                )
                .optional()?;
            let Some(integration) = integration else {
                return Ok(None);
            };
            tx.execute(
                "UPDATE integrations SET config_json=?,enabled=1 WHERE id=?",
                params![config.to_string(), integration],
            )?;
            tx.execute("DELETE FROM github_app_setups WHERE state_hash=?", [state_hash])?;
            Ok(Some(integration))
        })
    }
    pub fn integration_secret(&self, id: &str, user: &str) -> anyhow::Result<Option<String>> {
        let conn = self
            .0
            .lock()
            .map_err(|_| anyhow::anyhow!("database lock poisoned"))?;
        Ok(conn
            .query_row(
                "SELECT secret_ciphertext FROM integrations WHERE id=? AND user_id=?",
                params![id, user],
                |r| r.get(0),
            )
            .optional()?
            .flatten())
    }
    pub fn register_client(
        &self,
        client_id: &str,
        user: Option<&str>,
        name: &str,
        redirects: &[String],
    ) -> anyhow::Result<()> {
        self.transact(|tx|{tx.execute("INSERT INTO oauth_clients(client_id,user_id,redirect_uris,registered_name,client_name) VALUES(?,?,?,?,?)",params![client_id,user,serde_json::to_string(redirects)?,name,name])?;Ok(())})?;
        if let Some(user) = user {
            let identity = match self.list_identities(user)?.into_iter().next() {
                Some(identity) => identity.id,
                None => self.create_identity(user, "Default")?,
            };
            self.bind_agent(user, &identity, client_id)?;
        }
        Ok(())
    }
    pub fn register_or_reuse_public_client(
        &self,
        client_id: &str,
        name: &str,
        redirects: &[String],
        now: i64,
        maximum_unused: u64,
    ) -> anyhow::Result<(String, bool, bool)> {
        self.transact(|tx| {
            let deleted = tx.execute(
                "DELETE FROM oauth_clients
                 WHERE user_id IS NULL
                   AND created_at < ? - 86400
                   AND NOT EXISTS (SELECT 1 FROM oauth_tokens t WHERE t.client_id=oauth_clients.client_id)
                   AND NOT EXISTS (SELECT 1 FROM oauth_codes c WHERE c.client_id=oauth_clients.client_id AND c.expires_at>?)",
                params![now,now],
            )?;
            let redirects = serde_json::to_string(redirects)?;
            let existing: Option<String> = tx
                .query_row(
                    "SELECT client_id FROM oauth_clients c
                     WHERE c.user_id IS NULL AND c.client_name=? AND c.redirect_uris=?
                       AND c.created_at >= ? - 86400
                       AND NOT EXISTS (SELECT 1 FROM oauth_tokens t WHERE t.client_id=c.client_id)
                       AND NOT EXISTS (SELECT 1 FROM oauth_codes o WHERE o.client_id=c.client_id AND o.expires_at>?)
                     ORDER BY c.created_at DESC LIMIT 1",
                    params![name, redirects, now,now],
                    |row| row.get(0),
                )
                .optional()?;
            if let Some(existing) = existing {
                return Ok((existing, false, deleted > 0));
            }
            let unused: u64 = tx.query_row(
                "SELECT count(*) FROM oauth_clients c
                 WHERE c.user_id IS NULL
                   AND NOT EXISTS (SELECT 1 FROM oauth_tokens t WHERE t.client_id=c.client_id)
                   AND NOT EXISTS (SELECT 1 FROM oauth_codes o WHERE o.client_id=c.client_id AND o.expires_at>?)",
                [now],
                |row| row.get(0),
            )?;
            anyhow::ensure!(
                unused < maximum_unused,
                "too many unused client registrations; retry later"
            );
            tx.execute(
                "INSERT INTO oauth_clients(client_id,user_id,redirect_uris,registered_name,client_name,created_at) VALUES(?,NULL,?,?,?,?)",
                params![client_id, redirects, name,name,now],
            )?;
            Ok((client_id.to_owned(), true, true))
        })
    }
    pub fn client_redirect_allowed(&self, client: &str, redirect: &str) -> anyhow::Result<bool> {
        let conn = self
            .0
            .lock()
            .map_err(|_| anyhow::anyhow!("database lock poisoned"))?;
        let value: Option<String> = conn
            .query_row(
                "SELECT redirect_uris FROM oauth_clients WHERE client_id=?",
                [client],
                |r| r.get(0),
            )
            .optional()?;
        Ok(value
            .map(|v| {
                serde_json::from_str::<Vec<String>>(&v)
                    .unwrap_or_default()
                    .iter()
                    .any(|x| x == redirect)
            })
            .unwrap_or(false))
    }
    pub fn client_info(&self, client: &str) -> anyhow::Result<Option<(String, Vec<String>)>> {
        let conn = self
            .0
            .lock()
            .map_err(|_| anyhow::anyhow!("database lock poisoned"))?;
        let row: Option<(String, String)> = conn
            .query_row(
                "SELECT client_name,redirect_uris FROM oauth_clients WHERE client_id=?",
                [client],
                |row| Ok((row.get(0)?, row.get(1)?)),
            )
            .optional()?;
        row.map(|(name, redirects)| Ok((name, serde_json::from_str(&redirects)?)))
            .transpose()
    }
    #[allow(clippy::too_many_arguments)]
    pub fn store_code(
        &self,
        hash: &[u8],
        client: &str,
        user: &str,
        redirect: &str,
        scope: &str,
        challenge: &str,
        expires: i64,
    ) -> anyhow::Result<()> {
        self.transact(|tx|{let changed=tx.execute("INSERT INTO oauth_codes(code_hash,client_id,agent_id,identity_id,user_id,redirect_uri,scope,challenge,expires_at) SELECT ?,?,a.id,a.identity_id,i.user_id,?,?,?,? FROM agents a JOIN identities i ON i.id=a.identity_id WHERE a.oauth_client_id=? AND i.user_id=?",params![hash,client,redirect,scope,challenge,expires,client,user])?;anyhow::ensure!(changed==1,"OAuth client is not an authorized agent");Ok(())})
    }
    pub fn redeem_code(&self, hash: &[u8]) -> anyhow::Result<Option<AuthorizationCodeRow>> {
        self.transact(|tx|{let row=tx.query_row("SELECT client_id,user_id,redirect_uri,scope,challenge,expires_at FROM oauth_codes WHERE code_hash=?",[hash],|r|Ok((r.get(0)?,r.get(1)?,r.get(2)?,r.get(3)?,r.get(4)?,r.get(5)?))).optional()?;tx.execute("DELETE FROM oauth_codes WHERE code_hash=?",[hash])?;Ok(row)})
    }
    #[allow(clippy::too_many_arguments)]
    pub fn store_access_token(
        &self,
        hash: &[u8],
        client: &str,
        user: &str,
        scope: &str,
        expires: i64,
        refresh: Option<&[u8]>,
        refresh_expires: Option<i64>,
    ) -> anyhow::Result<()> {
        let token_id = Uuid::new_v4().to_string();
        let issued_at = chrono::Utc::now().timestamp();
        self.transact(|tx|{let changed=tx.execute("INSERT INTO oauth_tokens(token_hash,token_id,client_id,agent_id,user_id,scope,issued_at,expires_at,refresh_hash,refresh_expires_at) SELECT ?,?,?,a.id,i.user_id,?,?,?,?,? FROM agents a JOIN identities i ON i.id=a.identity_id WHERE a.oauth_client_id=? AND i.user_id=?",params![hash,token_id,client,scope,issued_at,expires,refresh,refresh_expires,client,user])?;anyhow::ensure!(changed==1,"OAuth client is not an authorized agent");let trusted:bool=tx.query_row("SELECT user_id IS NOT NULL FROM oauth_clients WHERE client_id=?",[client],|r|r.get(0))?;if trusted{let identity:String=tx.query_row("SELECT identity_id FROM agents WHERE oauth_client_id=?",[client],|r|r.get(0))?;for value in scope.split_ascii_whitespace(){let(capability,resource)=split_grant(value);tx.execute("INSERT INTO identity_grants(identity_id,capability,resource_id,created_at,revoked_at) VALUES(?,?,?,?,NULL) ON CONFLICT(identity_id,capability,resource_id) DO UPDATE SET revoked_at=NULL",params![identity,capability,resource,issued_at])?;}}Ok(())})
    }

    #[allow(clippy::too_many_arguments)]
    pub fn rotate_refresh_token(
        &self,
        old_refresh: &[u8],
        client: &str,
        now: i64,
        access_hash: &[u8],
        access_expires: i64,
        refresh_hash: &[u8],
        refresh_expires: i64,
    ) -> anyhow::Result<Option<(String, String)>> {
        self.transact(|tx| {
            let row: Option<RefreshTokenRow> = tx
                .query_row(
                    "SELECT token_hash,client_id,user_id,scope,refresh_expires_at FROM oauth_tokens WHERE refresh_hash=?",
                    [old_refresh],
                    |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?, row.get(3)?, row.get(4)?)),
                )
                .optional()?;
            let Some((old_access, stored_client, user, _scope, expires)) = row else {
                return Ok(None);
            };
            if stored_client != client || expires.unwrap_or(0) <= now {
                tx.execute("DELETE FROM oauth_tokens WHERE token_hash=?", [old_access])?;
                return Ok(None);
            }
            tx.execute("DELETE FROM oauth_tokens WHERE token_hash=?", [old_access])?;
            let agent:String=tx.query_row("SELECT id FROM agents WHERE oauth_client_id=?",[client],|row|row.get(0))?;
            let identity:String=tx.query_row("SELECT identity_id FROM agents WHERE id=?",[&agent],|row|row.get(0))?;
            let mut statement=tx.prepare("SELECT capability,resource_id,permission FROM identity_grants WHERE identity_id=? AND revoked_at IS NULL ORDER BY capability,resource_id")?;
            let scope=statement.query_map([identity],|row|{let c:String=row.get(0)?;let r:String=row.get(1)?;let p:String=row.get(2)?;Ok(if r.is_empty(){c}else if p.is_empty(){format!("{c}:{r}")}else{format!("{c}:{r}:{p}")})})?.collect::<Result<Vec<_>,_>>()?.join(" ");
            tx.execute(
                "INSERT INTO oauth_tokens(token_hash,token_id,client_id,agent_id,user_id,scope,issued_at,expires_at,refresh_hash,refresh_expires_at) VALUES(?,?,?,?,?,?,?,?,?,?)",
                params![access_hash,Uuid::new_v4().to_string(),client,agent,user,scope,now,access_expires,refresh_hash,refresh_expires],
            )?;
            Ok(Some((user, scope)))
        })
    }

    pub fn revoke_token(&self, hash: &[u8]) -> anyhow::Result<bool> {
        self.transact(|tx| {
            Ok(tx.execute(
                "DELETE FROM oauth_tokens WHERE token_hash=? OR refresh_hash=?",
                params![hash, hash],
            )? > 0)
        })
    }
    pub fn token_user(&self, hash: &[u8], now: i64) -> anyhow::Result<Option<String>> {
        let conn = self
            .0
            .lock()
            .map_err(|_| anyhow::anyhow!("database lock poisoned"))?;
        Ok(conn
            .query_row(
                "SELECT user_id FROM oauth_tokens WHERE token_hash=? AND expires_at>?",
                params![hash, now],
                |r| r.get(0),
            )
            .optional()?)
    }
    pub fn token_user_for_scope(
        &self,
        hash: &[u8],
        now: i64,
        required: &str,
    ) -> anyhow::Result<Option<String>> {
        let conn = self
            .0
            .lock()
            .map_err(|_| anyhow::anyhow!("database lock poisoned"))?;
        let row: Option<(String, String)> = conn
            .query_row(
                "SELECT user_id,scope FROM oauth_tokens WHERE token_hash=? AND expires_at>?",
                params![hash, now],
                |r| Ok((r.get(0)?, r.get(1)?)),
            )
            .optional()?;
        Ok(row.and_then(|(user, scope)| {
            scope
                .split_ascii_whitespace()
                .any(|s| s == required)
                .then_some(user)
        }))
    }
    pub fn token_user_and_scope(
        &self,
        hash: &[u8],
        now: i64,
    ) -> anyhow::Result<Option<(String, String)>> {
        let conn = self
            .0
            .lock()
            .map_err(|_| anyhow::anyhow!("database lock poisoned"))?;
        Ok(conn
            .query_row(
                "SELECT user_id,scope FROM oauth_tokens WHERE token_hash=? AND expires_at>?",
                params![hash, now],
                |row| Ok((row.get(0)?, row.get(1)?)),
            )
            .optional()?)
    }
    pub fn token_context(&self, hash: &[u8], now: i64) -> anyhow::Result<Option<TokenContext>> {
        let conn = self
            .0
            .lock()
            .map_err(|_| anyhow::anyhow!("database lock poisoned"))?;
        let row: Option<(String, String, String, String, String)> = conn
            .query_row(
                "SELECT i.user_id,t.client_id,t.scope,a.id,i.id
                 FROM oauth_tokens t JOIN agents a ON a.id=t.agent_id
                 JOIN identities i ON i.id=a.identity_id
                 WHERE t.token_hash=? AND t.expires_at>?",
                params![hash, now],
                |row| {
                    Ok((
                        row.get(0)?,
                        row.get(1)?,
                        row.get(2)?,
                        row.get(3)?,
                        row.get(4)?,
                    ))
                },
            )
            .optional()?;
        let Some((user_id, client_id, _snapshot_scope, agent_id, identity_id)) = row else {
            return Ok(None);
        };
        let mut grants = conn.prepare("SELECT capability,resource_id,permission FROM identity_grants WHERE identity_id=? AND revoked_at IS NULL")?;
        let scopes = grants
            .query_map([&identity_id], |row| {
                let capability: String = row.get(0)?;
                let resource: String = row.get(1)?;
                let permission: String = row.get(2)?;
                Ok(if resource.is_empty() {
                    capability
                } else if permission.is_empty() {
                    format!("{capability}:{resource}")
                } else {
                    format!("{capability}:{resource}:{permission}")
                })
            })?
            .collect::<Result<Vec<_>, _>>()?;
        let mut connections = conn
            .prepare("SELECT id FROM integrations WHERE identity_id=? AND enabled=1 ORDER BY id")?;
        let integration_ids = connections
            .query_map([&identity_id], |row| row.get(0))?
            .collect::<Result<Vec<_>, _>>()?;
        Ok(Some(TokenContext {
            user_id,
            agent_id,
            client_id,
            identity_id,
            scopes,
            integration_ids,
        }))
    }
    pub fn agent_clients(&self, user: &str) -> anyhow::Result<Vec<AgentClient>> {
        let conn = self
            .0
            .lock()
            .map_err(|_| anyhow::anyhow!("database lock poisoned"))?;
        let mut statement = conn.prepare("SELECT c.client_id,c.client_name,c.redirect_uris,c.created_at,group_concat(t.scope,' ') FROM oauth_clients c JOIN oauth_tokens t ON t.client_id=c.client_id WHERE t.user_id=? GROUP BY c.client_id,c.client_name,c.redirect_uris,c.created_at ORDER BY c.created_at DESC")?;
        let rows = statement.query_map([user], |row| {
            let redirects: String = row.get(2)?;
            let scope: String = row.get(4)?;
            let mut scopes = scope
                .split_ascii_whitespace()
                .map(str::to_owned)
                .collect::<Vec<_>>();
            scopes.sort();
            scopes.dedup();
            let integration_ids = scopes
                .iter()
                .filter_map(|scope| scope.strip_prefix("integration:").map(str::to_owned))
                .collect();
            Ok(AgentClient {
                client_id: row.get(0)?,
                client_name: row.get(1)?,
                redirect_uris: serde_json::from_str(&redirects).unwrap_or_default(),
                created_at: row.get(3)?,
                scopes,
                integration_ids,
            })
        })?;
        Ok(rows.collect::<Result<Vec<_>, _>>()?)
    }
    pub fn client_granted_scopes(
        &self,
        user: &str,
        client_id: &str,
    ) -> anyhow::Result<Vec<String>> {
        let conn = self
            .0
            .lock()
            .map_err(|_| anyhow::anyhow!("database lock poisoned"))?;
        let identity:Option<String>=conn.query_row("SELECT a.identity_id FROM agents a JOIN identities i ON i.id=a.identity_id WHERE a.oauth_client_id=? AND i.user_id=?",params![client_id,user],|row|row.get(0)).optional()?;
        let Some(identity) = identity else {
            return Ok(Vec::new());
        };
        let mut statement=conn.prepare("SELECT capability,resource_id,permission FROM identity_grants WHERE identity_id=? AND revoked_at IS NULL ORDER BY capability,resource_id")?;
        Ok(statement
            .query_map([identity], |row| {
                let c: String = row.get(0)?;
                let r: String = row.get(1)?;
                let p: String = row.get(2)?;
                Ok(if r.is_empty() {
                    c
                } else if p.is_empty() {
                    format!("{c}:{r}")
                } else {
                    format!("{c}:{r}:{p}")
                })
            })?
            .collect::<Result<Vec<_>, _>>()?)
    }
    pub fn agent_tokens(&self, user: &str) -> anyhow::Result<Vec<AgentToken>> {
        let conn = self
            .0
            .lock()
            .map_err(|_| anyhow::anyhow!("database lock poisoned"))?;
        let mut statement = conn.prepare("SELECT token_id,client_id,scope,issued_at,expires_at,refresh_expires_at,last_used_at,refresh_hash IS NOT NULL FROM oauth_tokens WHERE user_id=? ORDER BY expires_at DESC")?;
        let rows = statement.query_map([user], |row| {
            let scope: String = row.get(2)?;
            let integration_ids = scope
                .split_ascii_whitespace()
                .filter_map(|scope| scope.strip_prefix("integration:").map(str::to_owned))
                .collect();
            Ok(AgentToken {
                token_id: row.get(0)?,
                client_id: row.get(1)?,
                scope,
                issued_at: row.get(3)?,
                expires_at: row.get(4)?,
                refresh_expires_at: row.get(5)?,
                last_used_at: row.get(6)?,
                refresh_capable: row.get(7)?,
                integration_ids,
            })
        })?;
        Ok(rows.collect::<Result<Vec<_>, _>>()?)
    }
    pub fn revoke_agent_token(&self, user: &str, token_id: &str) -> anyhow::Result<bool> {
        self.transact(|tx| {
            Ok(tx.execute(
                "DELETE FROM oauth_tokens WHERE user_id=? AND token_id=?",
                params![user, token_id],
            )? > 0)
        })
    }
    pub fn revoke_agent_client(&self, user: &str, client_id: &str) -> anyhow::Result<bool> {
        self.transact(|tx| {
            let authorized: bool = tx.query_row(
                "SELECT EXISTS(SELECT 1 FROM oauth_tokens WHERE user_id=? AND client_id=?)",
                params![user, client_id],
                |row| row.get(0),
            )?;
            if !authorized {
                return Ok(false);
            }
            Ok(tx.execute("DELETE FROM oauth_clients WHERE client_id=?", [client_id])? > 0)
        })
    }
    pub fn revoke_client_integration_grant(
        &self,
        user: &str,
        client_id: &str,
        integration_id: &str,
    ) -> anyhow::Result<bool> {
        self.transact(|tx| {
            let mut statement = tx.prepare(
                "SELECT token_hash,scope FROM oauth_tokens WHERE user_id=? AND client_id=?",
            )?;
            let rows = statement
                .query_map(params![user, client_id], |row| {
                    Ok((row.get::<_, Vec<u8>>(0)?, row.get::<_, String>(1)?))
                })?
                .collect::<Result<Vec<_>, _>>()?;
            drop(statement);
            let target = format!("integration:{integration_id}");
            let mut changed = false;
            for (hash, scope) in rows {
                let filtered = scope
                    .split_ascii_whitespace()
                    .filter(|item| *item != target)
                    .collect::<Vec<_>>()
                    .join(" ");
                if filtered != scope {
                    tx.execute(
                        "UPDATE oauth_tokens SET scope=? WHERE token_hash=?",
                        params![filtered, hash],
                    )?;
                    changed = true;
                }
            }
            Ok(changed)
        })
    }

    pub fn grant_client_integration(
        &self,
        user: &str,
        client_id: &str,
        integration_id: &str,
    ) -> anyhow::Result<bool> {
        self.transact(|tx| {
            let owned: bool = tx.query_row(
                "SELECT EXISTS(SELECT 1 FROM integrations WHERE user_id=? AND id=?)",
                params![user, integration_id],
                |row| row.get(0),
            )?;
            anyhow::ensure!(owned, "integration not found");
            let mut statement = tx.prepare(
                "SELECT token_hash,scope FROM oauth_tokens WHERE user_id=? AND client_id=?",
            )?;
            let rows = statement
                .query_map(params![user, client_id], |row| {
                    Ok((row.get::<_, Vec<u8>>(0)?, row.get::<_, String>(1)?))
                })?
                .collect::<Result<Vec<_>, _>>()?;
            drop(statement);
            anyhow::ensure!(!rows.is_empty(), "authorized client not found");
            let target = format!("integration:{integration_id}");
            let mut changed = false;
            for (hash, scope) in rows {
                if !scope.split_ascii_whitespace().any(|item| item == target) {
                    tx.execute(
                        "UPDATE oauth_tokens SET scope=? WHERE token_hash=?",
                        params![format!("{scope} {target}"), hash],
                    )?;
                    changed = true;
                }
            }
            Ok(changed)
        })
    }
    #[allow(clippy::too_many_arguments)]
    pub fn store_oauth_state(
        &self,
        hash: &[u8],
        user: &str,
        integration: &str,
        verifier: &str,
        redirect: &str,
        expires: i64,
        resource: Option<&str>,
    ) -> anyhow::Result<()> {
        self.transact(|tx| { tx.execute("INSERT INTO oauth_states(state_hash,user_id,integration_id,verifier_ciphertext,redirect_uri,expires_at,resource) VALUES(?,?,?,?,?,?,?)", params![hash,user,integration,verifier,redirect,expires,resource])?; Ok(()) })
    }
    pub fn redeem_oauth_state(&self, hash: &[u8]) -> anyhow::Result<Option<UpstreamOAuthStateRow>> {
        self.transact(|tx| { let row=tx.query_row("SELECT user_id,integration_id,verifier_ciphertext,redirect_uri,expires_at,resource FROM oauth_states WHERE state_hash=?",[hash],|r|Ok((r.get(0)?,r.get(1)?,r.get(2)?,r.get(3)?,r.get(4)?,r.get(5)?))).optional()?; tx.execute("DELETE FROM oauth_states WHERE state_hash=?",[hash])?; Ok(row) })
    }
    pub fn put_upstream_oauth_client(
        &self,
        integration: &str,
        client: &UpstreamOAuthClient,
    ) -> anyhow::Result<()> {
        self.transact(|tx| {
            tx.execute(
                "INSERT INTO upstream_oauth_clients(integration_id,client_id,client_secret_ciphertext,authorization_endpoint,token_endpoint,scope,resource,issuer) VALUES(?,?,?,?,?,?,?,?) ON CONFLICT(integration_id) DO UPDATE SET client_id=excluded.client_id,client_secret_ciphertext=excluded.client_secret_ciphertext,authorization_endpoint=excluded.authorization_endpoint,token_endpoint=excluded.token_endpoint,scope=excluded.scope,resource=excluded.resource,issuer=excluded.issuer",
                params![integration,client.client_id,client.client_secret_ciphertext,client.authorization_endpoint,client.token_endpoint,client.scope,client.resource,client.issuer],
            )?;
            Ok(())
        })
    }
    pub fn upstream_oauth_client(
        &self,
        integration: &str,
    ) -> anyhow::Result<Option<UpstreamOAuthClient>> {
        let conn = self
            .0
            .lock()
            .map_err(|_| anyhow::anyhow!("database lock poisoned"))?;
        Ok(conn.query_row(
            "SELECT client_id,client_secret_ciphertext,authorization_endpoint,token_endpoint,scope,resource,issuer FROM upstream_oauth_clients WHERE integration_id=?",
            [integration],
            |row| Ok(UpstreamOAuthClient { client_id: row.get(0)?, client_secret_ciphertext: row.get(1)?, authorization_endpoint: row.get(2)?, token_endpoint: row.get(3)?, scope: row.get(4)?, resource: row.get(5)?, issuer: row.get(6)? }),
        ).optional()?)
    }
    pub fn put_upstream_oauth_token(
        &self,
        integration: &str,
        token: &UpstreamOAuthToken,
    ) -> anyhow::Result<()> {
        self.transact(|tx| {
            tx.execute(
                "INSERT INTO upstream_oauth_tokens(integration_id,access_token_ciphertext,refresh_token_ciphertext,token_type,scope,expires_at,refresh_expires_at) VALUES(?,?,?,?,?,?,?) ON CONFLICT(integration_id) DO UPDATE SET access_token_ciphertext=excluded.access_token_ciphertext,refresh_token_ciphertext=excluded.refresh_token_ciphertext,token_type=excluded.token_type,scope=excluded.scope,expires_at=excluded.expires_at,refresh_expires_at=excluded.refresh_expires_at",
                params![integration,token.access_token_ciphertext,token.refresh_token_ciphertext,token.token_type,token.scope,token.expires_at,token.refresh_expires_at],
            )?;
            Ok(())
        })
    }
    pub fn upstream_oauth_token(
        &self,
        integration: &str,
    ) -> anyhow::Result<Option<UpstreamOAuthToken>> {
        let conn = self
            .0
            .lock()
            .map_err(|_| anyhow::anyhow!("database lock poisoned"))?;
        Ok(conn.query_row(
            "SELECT access_token_ciphertext,refresh_token_ciphertext,token_type,scope,expires_at,refresh_expires_at FROM upstream_oauth_tokens WHERE integration_id=?",
            [integration],
            |row| Ok(UpstreamOAuthToken { access_token_ciphertext: row.get(0)?, refresh_token_ciphertext: row.get(1)?, token_type: row.get(2)?, scope: row.get(3)?, expires_at: row.get(4)?, refresh_expires_at: row.get(5)? }),
        ).optional()?)
    }
    pub fn clear_integration_credentials(
        &self,
        integration: &str,
        user: &str,
    ) -> anyhow::Result<bool> {
        self.transact(|tx| {
            let exists: bool = tx.query_row(
                "SELECT EXISTS(SELECT 1 FROM integrations WHERE id=? AND user_id=?)",
                params![integration, user],
                |row| row.get(0),
            )?;
            if !exists {
                return Ok(false);
            }
            tx.execute(
                "UPDATE integrations SET secret_ciphertext=NULL WHERE id=? AND user_id=?",
                params![integration, user],
            )?;
            tx.execute(
                "DELETE FROM upstream_oauth_tokens WHERE integration_id=?",
                [integration],
            )?;
            tx.execute(
                "DELETE FROM upstream_oauth_clients WHERE integration_id=?",
                [integration],
            )?;
            tx.execute(
                "DELETE FROM oauth_states WHERE integration_id=?",
                [integration],
            )?;
            Ok(true)
        })
    }

    pub fn clear_upstream_oauth(&self, integration: &str) -> anyhow::Result<()> {
        self.transact(|tx| {
            tx.execute(
                "DELETE FROM upstream_oauth_tokens WHERE integration_id=?",
                [integration],
            )?;
            tx.execute(
                "DELETE FROM upstream_oauth_clients WHERE integration_id=?",
                [integration],
            )?;
            tx.execute(
                "DELETE FROM oauth_states WHERE integration_id=?",
                [integration],
            )?;
            Ok(())
        })
    }
    pub fn integration(&self, id: &str, user: &str) -> anyhow::Result<Option<Integration>> {
        let conn = self
            .0
            .lock()
            .map_err(|_| anyhow::anyhow!("database lock poisoned"))?;
        Ok(conn.query_row("SELECT id,user_id,name,transport,config_json,enabled,identity_id,provider_name,provider_account FROM integrations WHERE id=? AND user_id=?",params![id,user],|r|Ok(Integration{id:r.get(0)?,user_id:r.get(1)?,name:r.get(2)?,transport:r.get(3)?,config:serde_json::from_str(&r.get::<_,String>(4)?).unwrap_or_default(),enabled:r.get(5)?,identity_id:r.get(6)?,provider_name:r.get(7)?,provider_account:r.get(8)?})).optional()?)
    }
    pub fn set_integration_secret(&self, id: &str, user: &str, secret: &str) -> anyhow::Result<()> {
        self.transact(|tx| {
            let n = tx.execute(
                "UPDATE integrations SET secret_ciphertext=? WHERE id=? AND user_id=?",
                params![secret, id, user],
            )?;
            anyhow::ensure!(n == 1, "integration not found");
            Ok(())
        })
    }

    pub fn update_integration(
        &self,
        id: &str,
        user: &str,
        name: Option<&str>,
        config: Option<&serde_json::Value>,
        enabled: Option<bool>,
        secret: Option<&str>,
    ) -> anyhow::Result<()> {
        self.transact(|tx| {
            let exists: bool = tx.query_row(
                "SELECT EXISTS(SELECT 1 FROM integrations WHERE id=? AND user_id=?)",
                params![id, user],
                |row| row.get(0),
            )?;
            anyhow::ensure!(exists, "integration not found");
            if let Some(name) = name {
                let name=normalize_display_name(name)?;
                tx.execute(
                    "UPDATE integrations SET name=?,display_name=?,updated_at=? WHERE id=? AND user_id=?",
                    params![name,name,chrono::Utc::now().timestamp(),id,user],
                )?;
            }
            if let Some(config) = config {
                tx.execute(
                    "UPDATE integrations SET config_json=? WHERE id=? AND user_id=?",
                    params![config.to_string(), id, user],
                )?;
            }
            if let Some(enabled) = enabled {
                tx.execute(
                    "UPDATE integrations SET enabled=? WHERE id=? AND user_id=?",
                    params![enabled, id, user],
                )?;
            }
            if let Some(secret) = secret {
                tx.execute(
                    "UPDATE integrations SET secret_ciphertext=? WHERE id=? AND user_id=?",
                    params![secret, id, user],
                )?;
            }
            Ok(())
        })
    }

    pub fn delete_integration(&self, id: &str, user: &str) -> anyhow::Result<bool> {
        self.transact(|tx| {
            let deleted = tx.execute(
                "DELETE FROM integrations WHERE id=? AND user_id=?",
                params![id, user],
            )? > 0;
            if !deleted {
                return Ok(false);
            }
            tx.execute("UPDATE identity_grants SET revoked_at=? WHERE capability='integration' AND resource_id=? AND revoked_at IS NULL",params![chrono::Utc::now().timestamp(),id])?;

            let target = format!("integration:{id}");
            let mut statement = tx.prepare("SELECT token_hash,scope FROM oauth_tokens")?;
            let rows = statement
                .query_map([], |row| {
                    Ok((row.get::<_, Vec<u8>>(0)?, row.get::<_, String>(1)?))
                })?
                .collect::<Result<Vec<_>, _>>()?;
            drop(statement);
            for (hash, scope) in rows {
                let filtered = scope
                    .split_ascii_whitespace()
                    .filter(|item| *item != target)
                    .collect::<Vec<_>>()
                    .join(" ");
                if filtered != scope {
                    tx.execute(
                        "UPDATE oauth_tokens SET scope=? WHERE token_hash=?",
                        params![filtered, hash],
                    )?;
                }
            }
            Ok(true)
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
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
        let db = Database::open(&dir.path().join("registration.db")).unwrap();
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
        db.0.lock()
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
            db.create_git_pending_request(
                &user,
                "client",
                &integration,
                &repository.id,
                "owner",
                60
            )
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
        connection.execute_batch(
            "PRAGMA foreign_keys=OFF; DROP TABLE oauth_tokens; UPDATE schema_meta SET version=2;",
        ).unwrap();
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
}
