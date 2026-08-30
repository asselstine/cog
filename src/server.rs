use crate::{
    Config,
    crypto::{SecretBox, token_hash},
    db::{Database, StorageMode, UpstreamOAuthClient, UpstreamOAuthToken},
    diagnostics::{
        StartupError, StartupPhase, credential_provider_class, redacted_error, safe_endpoint,
        safe_error, safe_git_error,
    },
    git::providers::{GitProvider, github::GitHubProvider},
    git::{GitOperation, ResolvedRepository},
    lease::{LeaseGuard, probe_conditional_writes},
    ltx::Replicator,
    mcp::{ToolProvider, UpstreamInsufficientScope},
    oauth,
    runtime::CodeRuntime,
};
use anyhow::Context;
use argon2::{
    Argon2, PasswordHash, PasswordHasher, PasswordVerifier,
    password_hash::{SaltString, rand_core::OsRng},
};
use axum::{
    Json, Router,
    extract::{DefaultBodyLimit, Form, Path, Query, State},
    http::{HeaderMap, StatusCode, header},
    response::{Html, IntoResponse, Redirect, Response},
    routing::{get, post},
};
use futures_util::StreamExt;
use object_store::{ObjectStore, aws::AmazonS3Builder, path::Path as ObjectPath};
use russh::server::{Msg as SshMsg, Server as _, Session as SshSession};
use russh::{Channel, ChannelId};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use std::{
    collections::{HashMap, HashSet, VecDeque},
    net::{IpAddr, SocketAddr},
    sync::{
        Arc,
        atomic::{AtomicBool, AtomicU64, Ordering},
    },
    time::{Duration, Instant},
};
use tokio::io::{AsyncReadExt, AsyncWriteExt};

mod administration;
mod authorization_server;
mod frontend;
mod github;
mod health;
mod mcp;
mod router;
mod session;
mod ssh;
mod startup;
mod upstream_oauth;

pub use crate::mcp::service::{
    MeasuredProvider, OAuthStepUpProvider, PolicyProvider, catalog, git_provider,
    native_admin_scope, safe_integration, upstream_connection_state,
};
pub use crate::mcp::tools::{
    admin::{AdminProvider, redact_value},
    git::GitControlProvider,
};
pub use administration::*;
pub use authorization_server::*;
pub use frontend::*;
pub use github::*;
pub use health::*;
use mcp::*;
pub use router::*;
pub use session::*;
pub use ssh::*;
pub use startup::*;
pub use upstream_oauth::*;

#[derive(Clone)]
pub struct App {
    pub config: Config,
    pub db: Database,
    pub secrets: SecretBox,
    pub runtime: Arc<CodeRuntime>,
    pub lease: Authority,
    pub replicator: Durability,
    pub providers: Arc<tokio::sync::Mutex<HashMap<String, Arc<dyn ToolProvider>>>>,
    pub metrics: Arc<Metrics>,
    /// Serializes each committed mutation with its LTX durability proof. This
    /// prevents another request from advancing the WAL between a mutation and
    /// the acknowledgement position captured for it.
    pub mutations: Arc<tokio::sync::Mutex<()>>,
    pub auth_rate_limit: Arc<RateLimiter>,
    pub git_providers: Arc<tokio::sync::Mutex<HashMap<String, Arc<dyn GitProvider>>>>,
    pub git_streams: Arc<tokio::sync::Semaphore>,
    pub git_client_streams: Arc<ClientStreamLimiter>,
    pub ssh_keys: Option<Arc<std::sync::RwLock<crate::git::ssh::KeySet>>>,
    pub ssh_ready: Arc<AtomicBool>,
    pub ssh_connections: Arc<tokio::sync::Semaphore>,
    pub github_api_base: url::Url,
}

#[derive(Clone)]
pub enum Authority {
    Local,
    S3(LeaseGuard),
}

impl Authority {
    fn is_live(&self) -> bool {
        match self {
            Self::Local => true,
            Self::S3(lease) => lease.is_live(),
        }
    }
    pub fn assert_live(&self) -> anyhow::Result<()> {
        match self {
            Self::Local => Ok(()),
            Self::S3(lease) => lease.assert_live(),
        }
    }
    fn generation(&self) -> u64 {
        match self {
            Self::Local => 0,
            Self::S3(lease) => lease.generation(),
        }
    }
    fn authority_until_ms(&self) -> u64 {
        match self {
            Self::Local => 0,
            Self::S3(lease) => lease.authority_until_ms(),
        }
    }
    fn stop_renewal(&self) {
        if let Self::S3(lease) = self {
            lease.stop_renewal();
        }
    }
}

#[derive(Clone)]
pub enum Durability {
    Local,
    S3(Arc<Replicator>),
}

impl Durability {
    pub async fn sync(&self) -> anyhow::Result<u64> {
        match self {
            Self::Local => Ok(1),
            Self::S3(repl) => repl.sync().await,
        }
    }
    fn durable_txid(&self) -> u64 {
        match self {
            Self::Local => 0,
            Self::S3(repl) => repl.durable_txid(),
        }
    }
    fn pending_txids(&self) -> u64 {
        match self {
            Self::Local => 0,
            Self::S3(repl) => repl.pending_txids(),
        }
    }
}
#[derive(Default)]
pub struct Metrics {
    pub oauth_failures: AtomicU64,
    pub execution_failures: AtomicU64,
    pub v8_limit_hits: AtomicU64,
    pub upstream_calls: AtomicU64,
    pub upstream_failures: AtomicU64,
    pub ssh_handshakes: AtomicU64,
    pub ssh_auth_success: AtomicU64,
    pub ssh_auth_denied: AtomicU64,
    pub ssh_active_sessions: AtomicU64,
    pub ssh_read_operations: AtomicU64,
    pub ssh_write_operations: AtomicU64,
    pub ssh_request_bytes: AtomicU64,
    pub ssh_response_bytes: AtomicU64,
    pub ssh_timeouts: AtomicU64,
    pub ssh_limit_rejections: AtomicU64,
    pub ssh_upstream_failures: AtomicU64,
    pub ssh_key_registrations: AtomicU64,
    pub ssh_key_lease_renewals: AtomicU64,
}

#[derive(Default)]
pub struct ClientStreamLimiter {
    pub active: std::sync::Mutex<HashMap<String, usize>>,
}
pub struct ClientStreamPermit {
    limiter: Arc<ClientStreamLimiter>,
    client: String,
}
impl ClientStreamLimiter {
    pub fn try_acquire(
        self: &Arc<Self>,
        client: &str,
        maximum: usize,
    ) -> Option<ClientStreamPermit> {
        let mut active = self.active.lock().ok()?;
        let count = active.entry(client.to_owned()).or_default();
        if *count >= maximum {
            return None;
        }
        *count += 1;
        Some(ClientStreamPermit {
            limiter: self.clone(),
            client: client.to_owned(),
        })
    }
}
impl Drop for ClientStreamPermit {
    fn drop(&mut self) {
        if let Ok(mut active) = self.limiter.active.lock()
            && let Some(count) = active.get_mut(&self.client)
        {
            *count -= 1;
            if *count == 0 {
                active.remove(&self.client);
            }
        }
    }
}

#[derive(Default)]
pub struct RateLimiter {
    attempts: std::sync::Mutex<HashMap<String, VecDeque<Instant>>>,
}

impl RateLimiter {
    pub fn allow(&self, key: String, maximum: usize, window: Duration) -> bool {
        let Ok(mut attempts) = self.attempts.lock() else {
            return false;
        };
        let now = Instant::now();
        let queue = attempts.entry(key).or_default();
        while queue
            .front()
            .is_some_and(|attempt| now.duration_since(*attempt) >= window)
        {
            queue.pop_front();
        }
        if queue.len() >= maximum {
            return false;
        }
        queue.push_back(now);
        true
    }
}
