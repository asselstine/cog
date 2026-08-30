use super::*;

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
}
