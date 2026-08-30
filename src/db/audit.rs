use super::*;

impl Database {
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
}
