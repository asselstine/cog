use super::*;

impl Database {
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
}
