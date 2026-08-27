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

const MIGRATIONS: &str = r#"
PRAGMA foreign_keys=ON;
CREATE TABLE IF NOT EXISTS schema_meta(version INTEGER NOT NULL);
INSERT INTO schema_meta(version) SELECT 1 WHERE NOT EXISTS (SELECT 1 FROM schema_meta);
CREATE TABLE IF NOT EXISTS cog_meta(key TEXT PRIMARY KEY, value TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS users(
 id TEXT PRIMARY KEY, email TEXT NOT NULL UNIQUE, password_hash TEXT NOT NULL,
 created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
);
CREATE TABLE IF NOT EXISTS sessions(
 token_hash BLOB PRIMARY KEY, user_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
 expires_at INTEGER NOT NULL, csrf_hash BLOB
);
CREATE TABLE IF NOT EXISTS integrations(
 id TEXT PRIMARY KEY, user_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
 name TEXT NOT NULL, transport TEXT NOT NULL, config_json TEXT NOT NULL,
 secret_ciphertext TEXT, enabled INTEGER NOT NULL DEFAULT 1,
 created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP, UNIQUE(user_id,name)
);
CREATE TABLE IF NOT EXISTS oauth_clients(
 client_id TEXT PRIMARY KEY, user_id TEXT REFERENCES users(id) ON DELETE CASCADE,
 redirect_uris TEXT NOT NULL, client_name TEXT NOT NULL, created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
);
CREATE TABLE IF NOT EXISTS oauth_codes(
 code_hash BLOB PRIMARY KEY, client_id TEXT NOT NULL REFERENCES oauth_clients(client_id) ON DELETE CASCADE,
 user_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE, redirect_uri TEXT NOT NULL,
 scope TEXT NOT NULL, challenge TEXT NOT NULL, expires_at INTEGER NOT NULL
);
CREATE TABLE IF NOT EXISTS oauth_tokens(
 token_hash BLOB PRIMARY KEY, token_id TEXT UNIQUE, client_id TEXT NOT NULL REFERENCES oauth_clients(client_id) ON DELETE CASCADE,
 user_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE, scope TEXT NOT NULL,
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
 user_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
 client_id TEXT NOT NULL REFERENCES oauth_clients(client_id) ON DELETE CASCADE,
 repository_id TEXT NOT NULL REFERENCES git_repositories(id) ON DELETE CASCADE,
 permission TEXT NOT NULL CHECK(permission IN ('read','write')), created_at INTEGER NOT NULL,
 revoked_at INTEGER, last_used_at INTEGER, PRIMARY KEY(client_id,repository_id)
);
CREATE TABLE IF NOT EXISTS git_credentials(
 credential_hash BLOB PRIMARY KEY, user_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
 client_id TEXT NOT NULL REFERENCES oauth_clients(client_id) ON DELETE CASCADE,
 repository_id TEXT NOT NULL REFERENCES git_repositories(id) ON DELETE CASCADE,
 permission TEXT NOT NULL CHECK(permission IN ('read','write')), issued_at INTEGER NOT NULL,
 expires_at INTEGER NOT NULL, last_used_at INTEGER, revoked_at INTEGER
);
CREATE TABLE IF NOT EXISTS git_credential_bootstraps(
 bootstrap_hash BLOB PRIMARY KEY, user_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
 client_id TEXT NOT NULL REFERENCES oauth_clients(client_id) ON DELETE CASCADE,
 repository_id TEXT NOT NULL REFERENCES git_repositories(id) ON DELETE CASCADE,
 permission TEXT NOT NULL CHECK(permission IN ('read','write')), issued_at INTEGER NOT NULL,
 expires_at INTEGER NOT NULL, consumed_at INTEGER, revoked_at INTEGER
);
CREATE TABLE IF NOT EXISTS git_pending_requests(
 id_hash BLOB PRIMARY KEY, user_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
 client_id TEXT NOT NULL REFERENCES oauth_clients(client_id) ON DELETE CASCADE,
 integration_id TEXT NOT NULL REFERENCES integrations(id) ON DELETE CASCADE,
 repository_id TEXT NOT NULL REFERENCES git_repositories(id) ON DELETE CASCADE,
 permission TEXT NOT NULL CHECK(permission IN ('read','write')), expires_at INTEGER NOT NULL,
 consumed_at INTEGER
);
CREATE TABLE IF NOT EXISTS github_app_setups(
 state_hash BLOB PRIMARY KEY,
 user_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
 integration_id TEXT NOT NULL UNIQUE REFERENCES integrations(id) ON DELETE CASCADE,
 expires_at INTEGER NOT NULL, app_slug TEXT, manifest_completed_at INTEGER
);
"#;

#[derive(Clone)]
pub struct Database(Arc<Mutex<Connection>>);
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Integration {
    pub id: String,
    pub user_id: String,
    pub name: String,
    pub transport: String,
    pub config: serde_json::Value,
    pub enabled: bool,
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
    pub created_at: String,
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
    pub client_id: String,
    pub scopes: Vec<String>,
    pub integration_ids: Vec<String>,
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

impl Database {
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
        self.transact(|tx|{let owned:bool=tx.query_row("SELECT EXISTS(SELECT 1 FROM git_repositories WHERE id=? AND user_id=?)",params![repository,user],|r|r.get(0))?;anyhow::ensure!(owned,"repository not found");tx.execute("INSERT INTO git_repository_grants(user_id,client_id,repository_id,permission,created_at,revoked_at) VALUES(?,?,?,?,?,NULL) ON CONFLICT(client_id,repository_id) DO UPDATE SET permission=excluded.permission,revoked_at=NULL",params![user,client,repository,permission,now])?;if permission=="read"{tx.execute("UPDATE git_credentials SET revoked_at=? WHERE user_id=? AND client_id=? AND repository_id=? AND permission='write' AND revoked_at IS NULL",params![now,user,client,repository])?;tx.execute("UPDATE git_credential_bootstraps SET revoked_at=? WHERE user_id=? AND client_id=? AND repository_id=? AND permission='write' AND revoked_at IS NULL",params![now,user,client,repository])?;}Ok(())})
    }
    pub fn revoke_git_grant(
        &self,
        user: &str,
        client: &str,
        repository: &str,
    ) -> anyhow::Result<bool> {
        let now = chrono::Utc::now().timestamp();
        self.transact(|tx|{let changed=tx.execute("UPDATE git_repository_grants SET revoked_at=? WHERE user_id=? AND client_id=? AND repository_id=? AND revoked_at IS NULL",params![now,user,client,repository])?;tx.execute("UPDATE git_credentials SET revoked_at=? WHERE user_id=? AND client_id=? AND repository_id=? AND revoked_at IS NULL",params![now,user,client,repository])?;tx.execute("UPDATE git_credential_bootstraps SET revoked_at=? WHERE user_id=? AND client_id=? AND repository_id=? AND revoked_at IS NULL",params![now,user,client,repository])?;Ok(changed>0)})
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
        Ok(conn.query_row("SELECT permission FROM git_repository_grants WHERE user_id=? AND client_id=? AND repository_id=? AND revoked_at IS NULL",params![user,client,repository],|r|r.get(0)).optional()?)
    }
    pub fn touch_git_grant(
        &self,
        user: &str,
        client: &str,
        repository: &str,
        now: i64,
    ) -> anyhow::Result<()> {
        self.transact(|tx|{tx.execute("UPDATE git_repository_grants SET last_used_at=? WHERE user_id=? AND client_id=? AND repository_id=? AND revoked_at IS NULL",params![now,user,client,repository])?;Ok(())})
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
        let mut s=conn.prepare("SELECT r.id,r.user_id,r.integration_id,r.provider_repository_id,r.display_name,r.upstream_url,r.metadata_json,g.permission,g.last_used_at FROM git_repository_grants g JOIN git_repositories r ON r.id=g.repository_id WHERE g.user_id=? AND g.client_id=? AND g.revoked_at IS NULL ORDER BY r.display_name")?;
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
    pub fn issue_git_credential(
        &self,
        user: &str,
        client: &str,
        repository: &str,
        permission: &str,
        ttl: i64,
    ) -> anyhow::Result<String> {
        let token = format!("cog_git_{}", crate::crypto::random_token(32));
        let now = chrono::Utc::now().timestamp();
        self.transact(|tx|{tx.execute("INSERT INTO git_credentials(credential_hash,user_id,client_id,repository_id,permission,issued_at,expires_at) VALUES(?,?,?,?,?,?,?)",params![crate::crypto::token_hash(&token).as_slice(),user,client,repository,permission,now,now+ttl])?;Ok(())})?;
        Ok(token)
    }
    pub fn issue_git_bootstrap(
        &self,
        user: &str,
        client: &str,
        repository: &str,
        permission: &str,
        ttl: i64,
    ) -> anyhow::Result<String> {
        anyhow::ensure!(
            matches!(permission, "read" | "write"),
            "invalid Git permission"
        );
        anyhow::ensure!(
            (1..=120).contains(&ttl),
            "Git bootstrap lifetime is invalid"
        );
        let capability = format!("cog_bootstrap_{}", crate::crypto::random_token(32));
        let hash = crate::crypto::token_hash(&capability);
        let now = chrono::Utc::now().timestamp();
        self.transact(|tx| {
            tx.execute("DELETE FROM git_credential_bootstraps WHERE expires_at<=? OR consumed_at IS NOT NULL OR revoked_at IS NOT NULL", [now])?;
            tx.execute("INSERT INTO git_credential_bootstraps(bootstrap_hash,user_id,client_id,repository_id,permission,issued_at,expires_at) VALUES(?,?,?,?,?,?,?)", params![hash.as_slice(),user,client,repository,permission,now,now+ttl])?;
            Ok(())
        })?;
        Ok(capability)
    }
    pub fn exchange_git_bootstrap(
        &self,
        capability: &str,
        user: &str,
        client: &str,
        repository: &str,
        requested_permission: &str,
        now: i64,
    ) -> anyhow::Result<Option<String>> {
        anyhow::ensure!(
            matches!(requested_permission, "read" | "write"),
            "invalid Git permission"
        );
        let hash = crate::crypto::token_hash(capability);
        self.transact(|tx| {
            let ceiling: Option<String> = tx.query_row(
                "SELECT permission FROM git_credential_bootstraps WHERE bootstrap_hash=? AND user_id=? AND client_id=? AND repository_id=? AND expires_at>? AND consumed_at IS NULL AND revoked_at IS NULL",
                params![hash.as_slice(),user,client,repository,now], |r| r.get(0)
            ).optional()?;
            let Some(ceiling) = ceiling else { return Ok(None) };
            anyhow::ensure!(ceiling == "write" || requested_permission == "read", "Git bootstrap permission ceiling exceeded");
            let changed = tx.execute("UPDATE git_credential_bootstraps SET consumed_at=? WHERE bootstrap_hash=? AND consumed_at IS NULL", params![now,hash.as_slice()])?;
            anyhow::ensure!(changed == 1, "Git bootstrap was already consumed");
            let token = format!("cog_git_{}", crate::crypto::random_token(32));
            tx.execute("INSERT INTO git_credentials(credential_hash,user_id,client_id,repository_id,permission,issued_at,expires_at) VALUES(?,?,?,?,?,?,?)", params![crate::crypto::token_hash(&token).as_slice(),user,client,repository,requested_permission,now,now+900])?;
            Ok(Some(token))
        })
    }
    pub fn revoke_git_bootstraps(
        &self,
        user: &str,
        client: &str,
        repository: &str,
    ) -> anyhow::Result<usize> {
        let now = chrono::Utc::now().timestamp();
        self.transact(|tx| Ok(tx.execute("UPDATE git_credential_bootstraps SET revoked_at=? WHERE user_id=? AND client_id=? AND repository_id=? AND consumed_at IS NULL AND revoked_at IS NULL", params![now,user,client,repository])?))
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
        self.transact(|tx|{tx.execute("DELETE FROM git_pending_requests WHERE expires_at<=? OR consumed_at IS NOT NULL",[now])?;tx.execute("INSERT INTO git_pending_requests(id_hash,user_id,client_id,integration_id,repository_id,permission,expires_at) VALUES(?,?,?,?,?,?,?)",params![hash.as_slice(),user,client,integration,repository,permission,now+ttl])?;Ok(())})?;
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
        self.transact(|tx|{let mut grants=Vec::new();for id in approved{let hash=hex::decode(id)?;let row:Option<(String,String)>=tx.query_row("SELECT repository_id,permission FROM git_pending_requests WHERE id_hash=? AND user_id=? AND client_id=? AND expires_at>? AND consumed_at IS NULL",params![hash,user,client,now],|r|Ok((r.get(0)?,r.get(1)?))).optional()?;if let Some((repository,permission))=row{tx.execute("INSERT INTO git_repository_grants(user_id,client_id,repository_id,permission,created_at,revoked_at) VALUES(?,?,?,?,?,NULL) ON CONFLICT(client_id,repository_id) DO UPDATE SET permission=CASE WHEN git_repository_grants.permission='write' OR excluded.permission='write' THEN 'write' ELSE 'read' END,revoked_at=NULL",params![user,client,repository,permission,now])?;tx.execute("UPDATE git_pending_requests SET consumed_at=? WHERE id_hash=?",params![now,hash])?;grants.push((repository,permission));}}
        tx.execute("UPDATE git_pending_requests SET consumed_at=? WHERE user_id=? AND client_id=? AND consumed_at IS NULL",params![now,user,client])?;Ok(grants)})
    }
    pub fn git_credential_context(
        &self,
        token: &str,
        repository: &str,
        now: i64,
    ) -> anyhow::Result<Option<TokenContext>> {
        let hash = crate::crypto::token_hash(token);
        self.transact(|tx|{let row=tx.query_row("SELECT c.user_id,c.client_id,c.permission,r.integration_id FROM git_credentials c JOIN git_repositories r ON r.id=c.repository_id JOIN git_repository_grants g ON g.client_id=c.client_id AND g.repository_id=c.repository_id AND g.user_id=c.user_id AND g.revoked_at IS NULL WHERE c.credential_hash=? AND c.repository_id=? AND c.expires_at>? AND c.revoked_at IS NULL AND (g.permission='write' OR c.permission='read') AND EXISTS(SELECT 1 FROM oauth_tokens t WHERE t.client_id=c.client_id AND t.user_id=c.user_id AND t.expires_at>? AND (' '||t.scope||' ') LIKE ('% integration:'||r.integration_id||' %'))",params![hash.as_slice(),repository,now,now],|r|Ok((r.get::<_,String>(0)?,r.get::<_,String>(1)?,r.get::<_,String>(2)?,r.get::<_,String>(3)?))).optional()?;if let Some((user,client,permission,integration))=row{tx.execute("UPDATE git_credentials SET last_used_at=? WHERE credential_hash=?",params![now,hash.as_slice()])?;Ok(Some(TokenContext{user_id:user,client_id:client,scopes:vec![format!("git:{permission}"),format!("integration:{integration}")],integration_ids:vec![integration]}))}else{Ok(None)}})
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
        let conn = Connection::open(path)?;
        conn.pragma_update(None, "journal_mode", "WAL")?;
        conn.pragma_update(None, "synchronous", "FULL")?;
        // In S3 mode the replication capture connection owns checkpoint
        // policy. Local mode retains SQLite's bounded default WAL behavior.
        if mode == StorageMode::S3 {
            conn.pragma_update(None, "wal_autocheckpoint", 0)?;
        }
        conn.execute_batch(MIGRATIONS)?;
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
        let has_refresh_expiry = {
            let mut statement = conn.prepare("PRAGMA table_info(oauth_tokens)")?;
            statement
                .query_map([], |row| row.get::<_, String>(1))?
                .collect::<Result<Vec<_>, _>>()?
                .iter()
                .any(|column| column == "refresh_expires_at")
        };
        if !has_refresh_expiry {
            conn.execute_batch("ALTER TABLE oauth_tokens ADD COLUMN refresh_expires_at INTEGER")?;
        }
        let has_token_id = {
            let mut statement = conn.prepare("PRAGMA table_info(oauth_tokens)")?;
            statement
                .query_map([], |row| row.get::<_, String>(1))?
                .collect::<Result<Vec<_>, _>>()?
                .iter()
                .any(|column| column == "token_id")
        };
        if !has_token_id {
            conn.execute_batch("ALTER TABLE oauth_tokens ADD COLUMN token_id TEXT")?;
        }
        let has_issued_at = {
            let mut statement = conn.prepare("PRAGMA table_info(oauth_tokens)")?;
            statement
                .query_map([], |row| row.get::<_, String>(1))?
                .collect::<Result<Vec<_>, _>>()?
                .iter()
                .any(|column| column == "issued_at")
        };
        if !has_issued_at {
            conn.execute_batch("ALTER TABLE oauth_tokens ADD COLUMN issued_at INTEGER")?;
        }
        let has_last_used_at = {
            let mut statement = conn.prepare("PRAGMA table_info(oauth_tokens)")?;
            statement
                .query_map([], |row| row.get::<_, String>(1))?
                .collect::<Result<Vec<_>, _>>()?
                .iter()
                .any(|column| column == "last_used_at")
        };
        if !has_last_used_at {
            conn.execute_batch("ALTER TABLE oauth_tokens ADD COLUMN last_used_at INTEGER")?;
        }
        // Access tokens have always had a one-hour lifetime. This gives tokens
        // created before issued_at was recorded an accurate lifecycle start.
        conn.execute_batch(
            "UPDATE oauth_tokens SET issued_at=expires_at-3600 WHERE issued_at IS NULL",
        )?;
        conn.execute_batch("UPDATE oauth_tokens SET token_id=lower(hex(token_hash)) WHERE token_id IS NULL; CREATE UNIQUE INDEX IF NOT EXISTS oauth_tokens_token_id ON oauth_tokens(token_id)")?;
        let has_session_csrf = {
            let mut statement = conn.prepare("PRAGMA table_info(sessions)")?;
            statement
                .query_map([], |row| row.get::<_, String>(1))?
                .collect::<Result<Vec<_>, _>>()?
                .iter()
                .any(|column| column == "csrf_hash")
        };
        if !has_session_csrf {
            conn.execute_batch("ALTER TABLE sessions ADD COLUMN csrf_hash BLOB")?;
        }
        for (table, column) in [
            ("upstream_oauth_clients", "resource"),
            ("upstream_oauth_clients", "issuer"),
            ("oauth_states", "resource"),
        ] {
            let mut statement = conn.prepare(&format!("PRAGMA table_info({table})"))?;
            let present = statement
                .query_map([], |row| row.get::<_, String>(1))?
                .collect::<Result<Vec<_>, _>>()?
                .iter()
                .any(|candidate| candidate == column);
            if !present {
                conn.execute_batch(&format!("ALTER TABLE {table} ADD COLUMN {column} TEXT"))?;
            }
        }
        Ok(Self(Arc::new(Mutex::new(conn))))
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
        let mut stmt=conn.prepare("SELECT id,user_id,name,transport,config_json,enabled FROM integrations WHERE user_id=? ORDER BY name")?;
        let rows = stmt.query_map([user], |r| {
            Ok(Integration {
                id: r.get(0)?,
                user_id: r.get(1)?,
                name: r.get(2)?,
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
        let id = Uuid::new_v4().to_string();
        self.transact(|tx|{tx.execute("INSERT INTO integrations(id,user_id,name,transport,config_json,secret_ciphertext) VALUES(?,?,?,?,?,?)",params![id,user,name,transport,config.to_string(),secret])?;Ok(())})?;
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
                "INSERT INTO integrations(id,user_id,name,transport,config_json,enabled) VALUES(?,?,?,?,?,0)",
                params![id, user, name, "git", config.to_string()],
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
        self.transact(|tx|{tx.execute("INSERT INTO oauth_clients(client_id,user_id,redirect_uris,client_name) VALUES(?,?,?,?)",params![client_id,user,serde_json::to_string(redirects)?,name])?;Ok(())})
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
                   AND created_at < datetime('now', '-1 day')
                   AND NOT EXISTS (SELECT 1 FROM oauth_tokens t WHERE t.client_id=oauth_clients.client_id)
                   AND NOT EXISTS (SELECT 1 FROM oauth_codes c WHERE c.client_id=oauth_clients.client_id AND c.expires_at>?)",
                [now],
            )?;
            let redirects = serde_json::to_string(redirects)?;
            let existing: Option<String> = tx
                .query_row(
                    "SELECT client_id FROM oauth_clients c
                     WHERE c.user_id IS NULL AND c.client_name=? AND c.redirect_uris=?
                       AND c.created_at >= datetime('now', '-1 day')
                       AND NOT EXISTS (SELECT 1 FROM oauth_tokens t WHERE t.client_id=c.client_id)
                       AND NOT EXISTS (SELECT 1 FROM oauth_codes o WHERE o.client_id=c.client_id AND o.expires_at>?)
                     ORDER BY c.created_at DESC LIMIT 1",
                    params![name, redirects, now],
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
                "INSERT INTO oauth_clients(client_id,user_id,redirect_uris,client_name) VALUES(?,NULL,?,?)",
                params![client_id, redirects, name],
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
        self.transact(|tx|{tx.execute("INSERT INTO oauth_codes(code_hash,client_id,user_id,redirect_uri,scope,challenge,expires_at) VALUES(?,?,?,?,?,?,?)",params![hash,client,user,redirect,scope,challenge,expires])?;Ok(())})
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
        self.transact(|tx|{tx.execute("INSERT INTO oauth_tokens(token_hash,token_id,client_id,user_id,scope,issued_at,expires_at,refresh_hash,refresh_expires_at) VALUES(?,?,?,?,?,?,?,?,?)",params![hash,token_id,client,user,scope,issued_at,expires,refresh,refresh_expires])?;Ok(())})
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
            let Some((old_access, stored_client, user, scope, expires)) = row else {
                return Ok(None);
            };
            if stored_client != client || expires.unwrap_or(0) <= now {
                tx.execute("DELETE FROM oauth_tokens WHERE token_hash=?", [old_access])?;
                return Ok(None);
            }
            tx.execute("DELETE FROM oauth_tokens WHERE token_hash=?", [old_access])?;
            tx.execute(
                "INSERT INTO oauth_tokens(token_hash,token_id,client_id,user_id,scope,issued_at,expires_at,refresh_hash,refresh_expires_at) VALUES(?,?,?,?,?,?,?,?,?)",
                params![access_hash,Uuid::new_v4().to_string(),client,user,scope,now,access_expires,refresh_hash,refresh_expires],
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
        let row: Option<(String, String, String)> = conn
            .query_row(
                "SELECT user_id,client_id,scope FROM oauth_tokens WHERE token_hash=? AND expires_at>?",
                params![hash, now],
                |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
            )
            .optional()?;
        let Some((user_id, client_id, scope)) = row else {
            return Ok(None);
        };
        let scopes = scope
            .split_ascii_whitespace()
            .map(str::to_owned)
            .collect::<Vec<_>>();
        let integration_ids = scopes
            .iter()
            .filter_map(|scope| scope.strip_prefix("integration:").map(str::to_owned))
            .collect();
        Ok(Some(TokenContext {
            user_id,
            client_id,
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
        let mut statement =
            conn.prepare("SELECT scope FROM oauth_tokens WHERE user_id=? AND client_id=?")?;
        let scopes = statement
            .query_map(params![user, client_id], |row| row.get::<_, String>(0))?
            .collect::<Result<Vec<_>, _>>()?;
        let mut granted = scopes
            .iter()
            .flat_map(|scope| scope.split_ascii_whitespace())
            .map(str::to_owned)
            .collect::<Vec<_>>();
        granted.sort();
        granted.dedup();
        Ok(granted)
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
        Ok(conn.query_row("SELECT id,user_id,name,transport,config_json,enabled FROM integrations WHERE id=? AND user_id=?",params![id,user],|r|Ok(Integration{id:r.get(0)?,user_id:r.get(1)?,name:r.get(2)?,transport:r.get(3)?,config:serde_json::from_str(&r.get::<_,String>(4)?).unwrap_or_default(),enabled:r.get(5)?})).optional()?)
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
                tx.execute(
                    "UPDATE integrations SET name=? WHERE id=? AND user_id=?",
                    params![name, id, user],
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
                "UPDATE oauth_clients SET created_at=datetime('now', '-2 days') WHERE client_id='first'",
                [],
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
    fn immutable_integration_grants_are_immediately_constrained() {
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
        assert_eq!(
            db.token_context(b"access", 1)
                .unwrap()
                .unwrap()
                .integration_ids,
            vec!["stable-id"]
        );
        assert!(
            db.revoke_client_integration_grant(&user, "client", "stable-id")
                .unwrap()
        );
        let after = db.token_context(b"access", 2).unwrap().unwrap();
        assert!(after.scopes.contains(&"mcp".into()));
        assert!(after.integration_ids.is_empty());
        assert!(
            !db.revoke_client_integration_grant(&user, "client", "stable-id")
                .unwrap()
        );
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
    fn legacy_schema_and_token_edge_cases_are_supported() {
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
        let db = Database::open(&path).unwrap();
        let user = db.create_user("legacy@example.com", "hash").unwrap();
        db.register_client(
            "legacy-client",
            None,
            "Legacy",
            &["http://localhost/cb".into()],
        )
        .unwrap();
        let now = chrono::Utc::now().timestamp();
        db.store_access_token(
            b"access",
            "legacy-client",
            &user,
            "mcp admin",
            now + 60,
            Some(b"refresh"),
            Some(now + 60),
        )
        .unwrap();
        assert_eq!(
            db.token_user_for_scope(b"access", now, "admin").unwrap(),
            Some(user.clone())
        );
        assert_eq!(
            db.token_user_for_scope(b"access", now, "missing").unwrap(),
            None
        );
        assert_eq!(
            db.token_user_for_scope(b"missing", now, "admin").unwrap(),
            None
        );
        assert!(
            db.rotate_refresh_token(
                b"refresh",
                "wrong-client",
                now,
                b"new",
                now + 60,
                b"new-refresh",
                now + 60
            )
            .unwrap()
            .is_none()
        );
        assert!(!db.revoke_agent_client(&user, "legacy-client").unwrap());

        let integration = db
            .create_integration(
                &user,
                "before",
                "http",
                &serde_json::json!({"url":"http://localhost"}),
                None,
            )
            .unwrap();
        db.update_integration(
            &integration,
            &user,
            Some("after"),
            Some(&serde_json::json!({"url":"http://localhost/new"})),
            Some(false),
            Some("sealed"),
        )
        .unwrap();
        let updated = db.integration(&integration, &user).unwrap().unwrap();
        assert_eq!(updated.name, "after");
        assert!(!updated.enabled);
        assert_eq!(
            db.integration_secret(&integration, &user)
                .unwrap()
                .as_deref(),
            Some("sealed")
        );
        assert!(
            db.update_integration("missing", &user, None, None, None, None)
                .is_err()
        );
    }

    #[test]
    fn git_pending_grants_credentials_and_cascades() {
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
        let bootstrap = db
            .issue_git_bootstrap(&user, "client", &repository.id, "write", 60)
            .unwrap();
        assert!(
            db.exchange_git_bootstrap(
                &bootstrap,
                &user,
                "wrong-client",
                &repository.id,
                "read",
                now
            )
            .unwrap()
            .is_none()
        );
        assert!(
            db.exchange_git_bootstrap(
                &bootstrap,
                &user,
                "client",
                &uuid::Uuid::new_v4().to_string(),
                "read",
                now
            )
            .unwrap()
            .is_none()
        );
        assert!(
            db.exchange_git_bootstrap(&bootstrap, &user, "client", &repository.id, "write", now)
                .unwrap()
                .is_some()
        );
        assert!(
            db.exchange_git_bootstrap(&bootstrap, &user, "client", &repository.id, "read", now)
                .unwrap()
                .is_none()
        );
        let read_bootstrap = db
            .issue_git_bootstrap(&user, "client", &repository.id, "read", 60)
            .unwrap();
        assert!(
            db.exchange_git_bootstrap(
                &read_bootstrap,
                &user,
                "client",
                &repository.id,
                "write",
                now
            )
            .is_err()
        );
        let expired = db
            .issue_git_bootstrap(&user, "client", &repository.id, "read", 1)
            .unwrap();
        assert!(
            db.exchange_git_bootstrap(&expired, &user, "client", &repository.id, "read", now + 2)
                .unwrap()
                .is_none()
        );
        let revoked = db
            .issue_git_bootstrap(&user, "client", &repository.id, "read", 60)
            .unwrap();
        assert!(
            db.revoke_git_bootstraps(&user, "client", &repository.id)
                .unwrap()
                >= 1
        );
        assert!(
            db.exchange_git_bootstrap(&revoked, &user, "client", &repository.id, "read", now)
                .unwrap()
                .is_none()
        );
        let credential = db
            .issue_git_credential(&user, "client", &repository.id, "write", 60)
            .unwrap();
        assert!(
            db.git_credential_context(&credential, &repository.id, now)
                .unwrap()
                .is_some()
        );
        db.revoke_git_grant(&user, "client", &repository.id)
            .unwrap();
        assert!(
            db.git_grant_permission(&user, "client", &repository.id)
                .unwrap()
                .is_none()
        );
        assert!(
            db.git_credential_context(&credential, &repository.id, now)
                .unwrap()
                .is_none()
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
}
