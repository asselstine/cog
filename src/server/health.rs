use super::*;

pub(super) async fn health() -> Json<Value> {
    Json(json!({"status":"ok"}))
}
pub async fn readiness(State(a): State<App>) -> impl IntoResponse {
    let live = a.lease.is_live();
    let pending = a.replicator.pending_txids();
    let ssh_configured = a.config.ssh_listen.is_some();
    let ssh_ready = a.ssh_ready.load(Ordering::Acquire);
    let status = if live && pending == 0 && (!ssh_configured || ssh_ready) {
        StatusCode::OK
    } else {
        StatusCode::SERVICE_UNAVAILABLE
    };
    (
        status,
        Json(json!({
            "ready": status == StatusCode::OK,
            "lease": {
                "live": live,
                "generation": a.lease.generation(),
                "authority_until_ms": a.lease.authority_until_ms()
            },
            "replication": {
                "durable_txid": a.replicator.durable_txid(),
                "pending_txids": pending
            },
            "ssh": {
                "configured": ssh_configured,
                "ready": ssh_ready,
                "listen": a.config.ssh_listen.map(|address| address.to_string()),
                "publicHost": a.config.ssh_public_host,
                "publicPort": a.config.ssh_public_port.or_else(|| a.config.ssh_listen.map(|address| address.port())),
                "hostKeyFingerprint": a.ssh_keys.as_ref().and_then(|keys| keys.read().ok().map(|keys| crate::git::ssh::fingerprint(keys.host.public_key())))
            }
        })),
    )
}
pub(super) async fn version(State(a): State<App>) -> Json<Value> {
    Json(json!({
        "name":"cog",
        "version":env!("CARGO_PKG_VERSION"),
        "schemaVersion": a.db.schema_version().unwrap_or(crate::db::SCHEMA_VERSION),
        "supportedSchemaVersion": crate::db::SCHEMA_VERSION
    }))
}
pub(super) async fn metrics(State(a): State<App>) -> impl IntoResponse {
    let body = format!(
        concat!(
            "# TYPE cog_lease_live gauge\ncog_lease_live {}\n",
            "# TYPE cog_lease_generation gauge\ncog_lease_generation {}\n",
            "# TYPE cog_replication_durable_txid gauge\ncog_replication_durable_txid {}\n",
            "# TYPE cog_replication_lag_txids gauge\ncog_replication_lag_txids {}\n",
            "# TYPE cog_oauth_failures_total counter\ncog_oauth_failures_total {}\n",
            "# TYPE cog_execution_failures_total counter\ncog_execution_failures_total {}\n",
            "# TYPE cog_v8_limit_hits_total counter\ncog_v8_limit_hits_total {}\n",
            "# TYPE cog_upstream_calls_total counter\ncog_upstream_calls_total {}\n",
            "# TYPE cog_upstream_failures_total counter\ncog_upstream_failures_total {}\n",
            "# TYPE cog_ssh_handshakes_total counter\ncog_ssh_handshakes_total {}\n",
            "# TYPE cog_ssh_auth_total counter\ncog_ssh_auth_total{{result=\"success\"}} {}\ncog_ssh_auth_total{{result=\"denied\"}} {}\n",
            "# TYPE cog_ssh_active_sessions gauge\ncog_ssh_active_sessions {}\n",
            "# TYPE cog_ssh_operations_total counter\ncog_ssh_operations_total{{operation=\"read\"}} {}\ncog_ssh_operations_total{{operation=\"write\"}} {}\n",
            "# TYPE cog_ssh_bytes_total counter\ncog_ssh_bytes_total{{direction=\"request\"}} {}\ncog_ssh_bytes_total{{direction=\"response\"}} {}\n",
            "# TYPE cog_ssh_timeouts_total counter\ncog_ssh_timeouts_total {}\n",
            "# TYPE cog_ssh_limit_rejections_total counter\ncog_ssh_limit_rejections_total {}\n",
            "# TYPE cog_ssh_upstream_failures_total counter\ncog_ssh_upstream_failures_total {}\n",
            "# TYPE cog_ssh_keys_total counter\ncog_ssh_keys_total{{operation=\"register\"}} {}\ncog_ssh_keys_total{{operation=\"lease_renew\"}} {}\n"
        ),
        u8::from(a.lease.is_live()),
        a.lease.generation(),
        a.replicator.durable_txid(),
        a.replicator.pending_txids(),
        a.metrics.oauth_failures.load(Ordering::Relaxed),
        a.metrics.execution_failures.load(Ordering::Relaxed),
        a.metrics.v8_limit_hits.load(Ordering::Relaxed),
        a.metrics.upstream_calls.load(Ordering::Relaxed),
        a.metrics.upstream_failures.load(Ordering::Relaxed),
        a.metrics.ssh_handshakes.load(Ordering::Relaxed),
        a.metrics.ssh_auth_success.load(Ordering::Relaxed),
        a.metrics.ssh_auth_denied.load(Ordering::Relaxed),
        a.metrics.ssh_active_sessions.load(Ordering::Relaxed),
        a.metrics.ssh_read_operations.load(Ordering::Relaxed),
        a.metrics.ssh_write_operations.load(Ordering::Relaxed),
        a.metrics.ssh_request_bytes.load(Ordering::Relaxed),
        a.metrics.ssh_response_bytes.load(Ordering::Relaxed),
        a.metrics.ssh_timeouts.load(Ordering::Relaxed),
        a.metrics.ssh_limit_rejections.load(Ordering::Relaxed),
        a.metrics.ssh_upstream_failures.load(Ordering::Relaxed),
        a.metrics.ssh_key_registrations.load(Ordering::Relaxed),
        a.metrics.ssh_key_lease_renewals.load(Ordering::Relaxed),
    );
    (
        [(http::header::CONTENT_TYPE, "text/plain; version=0.0.4")],
        body,
    )
}
