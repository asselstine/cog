use super::*;

impl Database {
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
