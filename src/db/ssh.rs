use super::*;

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
        anyhow::ensure!(purpose == "host", "invalid SSH key purpose");
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

    pub fn install_initial_ssh_key(
        &self,
        purpose: &str,
        public_key: &str,
        private_ciphertext: &str,
    ) -> anyhow::Result<SshKeyRecord> {
        anyhow::ensure!(purpose == "host", "invalid SSH key purpose");
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
        anyhow::ensure!(purpose == "host", "invalid SSH key purpose");
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
        anyhow::ensure!(purpose == "host", "invalid SSH key purpose");
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

    pub fn register_agent_ssh_key(
        &self,
        user: &str,
        agent: &str,
        client: &str,
        public_key: &str,
        fingerprint: &str,
        lease_expires_at: i64,
    ) -> anyhow::Result<AgentSshKey> {
        let now = chrono::Utc::now().timestamp();
        self.transact(|tx| {
            let owner: bool = tx.query_row(
                "SELECT EXISTS(SELECT 1 FROM agents a JOIN identities i ON i.id=a.identity_id WHERE a.id=? AND a.oauth_client_id=? AND i.user_id=?)",
                params![agent, client, user],
                |row| row.get(0),
            )?;
            anyhow::ensure!(owner, "agent identity is not authorized");
            let existing: Option<String> = tx
                .query_row(
                    "SELECT public_key FROM agent_ssh_keys WHERE agent_id=?",
                    [agent],
                    |row| row.get(0),
                )
                .optional()?;
            match existing {
                Some(existing) => anyhow::ensure!(
                    existing == public_key,
                    "agent already has a different SSH key; revoke it before explicit rotation"
                ),
                None => {
                    tx.execute(
                        "INSERT INTO agent_ssh_keys(agent_id,public_key,fingerprint,lease_expires_at,created_at,updated_at) VALUES(?,?,?,?,?,?)",
                        params![agent, public_key, fingerprint, lease_expires_at, now, now],
                    )?;
                }
            }
            Ok(())
        })?;
        self.agent_ssh_key(user, agent)?
            .ok_or_else(|| anyhow::anyhow!("registered SSH key was not found"))
    }

    pub fn renew_agent_ssh_key_lease(
        &self,
        user: &str,
        identity: &str,
        agent: &str,
        client: &str,
        public_key: &str,
        lease_expires_at: i64,
    ) -> anyhow::Result<AgentSshKey> {
        let now = chrono::Utc::now().timestamp();
        self.transact(|tx| {
            let changed = tx.execute(
                "UPDATE agent_ssh_keys SET lease_expires_at=?,updated_at=? WHERE agent_id=? AND public_key=? AND revoked_at IS NULL AND EXISTS(SELECT 1 FROM agents a JOIN identities i ON i.id=a.identity_id WHERE a.id=agent_ssh_keys.agent_id AND a.identity_id=? AND a.oauth_client_id=? AND i.user_id=?)",
                params![lease_expires_at, now, agent, public_key, identity, client, user],
            )?;
            anyhow::ensure!(changed == 1, "registered SSH key not found for this agent");
            Ok(())
        })?;
        self.agent_ssh_key(user, agent)?
            .ok_or_else(|| anyhow::anyhow!("renewed SSH key was not found"))
    }

    pub fn agent_ssh_key(&self, user: &str, agent: &str) -> anyhow::Result<Option<AgentSshKey>> {
        let conn = self
            .0
            .lock()
            .map_err(|_| anyhow::anyhow!("database lock poisoned"))?;
        Ok(conn
            .query_row(
                "SELECT k.agent_id,k.public_key,k.fingerprint,k.lease_expires_at,k.created_at,k.updated_at,k.revoked_at FROM agent_ssh_keys k JOIN agents a ON a.id=k.agent_id JOIN identities i ON i.id=a.identity_id WHERE k.agent_id=? AND i.user_id=?",
                params![agent, user],
                |row| {
                    Ok(AgentSshKey {
                        agent_id: row.get(0)?,
                        public_key: row.get(1)?,
                        fingerprint: row.get(2)?,
                        lease_expires_at: row.get(3)?,
                        created_at: row.get(4)?,
                        updated_at: row.get(5)?,
                        revoked_at: row.get(6)?,
                    })
                },
            )
            .optional()?)
    }

    pub fn active_agent_ssh_key(
        &self,
        public_key: &str,
        now: i64,
    ) -> anyhow::Result<Option<AgentSshBinding>> {
        let conn = self
            .0
            .lock()
            .map_err(|_| anyhow::anyhow!("database lock poisoned"))?;
        Ok(conn
            .query_row(
                "SELECT i.user_id,a.identity_id,a.id,a.oauth_client_id,k.public_key,k.fingerprint,k.lease_expires_at FROM agent_ssh_keys k JOIN agents a ON a.id=k.agent_id JOIN identities i ON i.id=a.identity_id WHERE k.public_key=? AND k.revoked_at IS NULL AND k.lease_expires_at>?",
                params![public_key, now],
                |row| {
                    Ok(AgentSshBinding {
                        user_id: row.get(0)?,
                        identity_id: row.get(1)?,
                        agent_id: row.get(2)?,
                        client_id: row.get(3)?,
                        public_key: row.get(4)?,
                        fingerprint: row.get(5)?,
                        lease_expires_at: row.get(6)?,
                    })
                },
            )
            .optional()?)
    }
}
