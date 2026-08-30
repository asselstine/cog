use super::*;

impl Database {
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
}
