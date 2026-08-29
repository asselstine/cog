use crate::diagnostics::redacted_error;
use bytes::Bytes;
use object_store::{ObjectStore, ObjectStoreExt, PutMode, PutOptions, UpdateVersion, path::Path};
use serde::{Deserialize, Serialize};
use std::{
    sync::{
        Arc,
        atomic::{AtomicBool, AtomicU64, Ordering},
    },
    time::{Duration, SystemTime, UNIX_EPOCH},
};
use tokio::sync::watch;
use uuid::Uuid;

#[derive(Debug, Clone, Serialize, Deserialize)]
struct LeaseRecord {
    owner: String,
    generation: u64,
    expires_ms: u64,
}

#[derive(Clone)]
pub struct LeaseGuard {
    store: Arc<dyn ObjectStore>,
    key: Path,
    record: LeaseRecord,
    version: UpdateVersion,
    ttl: Duration,
    live: Arc<AtomicBool>,
    authority_until: Arc<AtomicU64>,
    stop: watch::Sender<bool>,
}

#[derive(Debug, thiserror::Error)]
pub enum LeaseError {
    #[error("another cog instance holds the S3 lease until {0}")]
    Held(u64),
    #[error(transparent)]
    Store(#[from] object_store::Error),
    #[error(transparent)]
    Json(#[from] serde_json::Error),
}

fn now_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis() as u64
}

impl LeaseGuard {
    pub async fn acquire(
        store: Arc<dyn ObjectStore>,
        key: Path,
        ttl: Duration,
    ) -> Result<Self, LeaseError> {
        let owner = Uuid::new_v4().to_string();
        let current = store
            .get_opts(&key, object_store::GetOptions::default())
            .await;
        let (generation, mode) = match current {
            Ok(result) => {
                let meta = result.meta.clone();
                let old: LeaseRecord = serde_json::from_slice(&result.bytes().await?)?;
                if old.expires_ms > now_ms() {
                    return Err(LeaseError::Held(old.expires_ms));
                }
                (
                    old.generation + 1,
                    PutMode::Update(UpdateVersion {
                        e_tag: meta.e_tag,
                        version: meta.version,
                    }),
                )
            }
            Err(object_store::Error::NotFound { .. }) => (1, PutMode::Create),
            Err(e) => return Err(e.into()),
        };
        let record = LeaseRecord {
            owner,
            generation,
            expires_ms: now_ms() + ttl.as_millis() as u64,
        };
        let result = store
            .put_opts(
                &key,
                Bytes::from(serde_json::to_vec(&record)?).into(),
                PutOptions {
                    mode,
                    ..Default::default()
                },
            )
            .await?;
        let version = UpdateVersion {
            e_tag: result.e_tag,
            version: result.version,
        };
        let (stop, _) = watch::channel(false);
        let authority_until = record.expires_ms;
        Ok(Self {
            store,
            key,
            record,
            version,
            ttl,
            live: Arc::new(AtomicBool::new(true)),
            authority_until: Arc::new(AtomicU64::new(authority_until)),
            stop,
        })
    }
    pub fn generation(&self) -> u64 {
        self.record.generation
    }
    pub fn owner(&self) -> &str {
        &self.record.owner
    }
    pub fn authority_until_ms(&self) -> u64 {
        self.authority_until.load(Ordering::Acquire)
    }
    pub fn is_live(&self) -> bool {
        self.live.load(Ordering::Acquire) && self.authority_until.load(Ordering::Acquire) > now_ms()
    }
    pub fn assert_live(&self) -> anyhow::Result<()> {
        anyhow::ensure!(self.is_live(), "S3 lease authority expired");
        Ok(())
    }
    pub fn spawn_renewal(mut self) -> tokio::task::JoinHandle<()> {
        let mut stop = self.stop.subscribe();
        tokio::spawn(async move {
            let cadence = self.ttl / 3;
            loop {
                let authority_until = self.authority_until.load(Ordering::Acquire);
                if now_ms() >= authority_until {
                    break;
                }
                let remaining = Duration::from_millis(authority_until.saturating_sub(now_ms()));
                tokio::select! {
                    _=tokio::time::sleep(cadence)=>{
                        // Authority is monotonic: once the last proven lease
                        // deadline passes, this process may never regain it.
                        if now_ms() >= self.authority_until.load(Ordering::Acquire) {
                            break;
                        }
                        self.record.expires_ms=now_ms()+self.ttl.as_millis() as u64;
                        let body=match serde_json::to_vec(&self.record){Ok(v)=>v,Err(_)=>break};
                        let mode=PutMode::Update(self.version.clone());
                        match self.store.put_opts(&self.key,Bytes::from(body).into(),PutOptions{mode,..Default::default()}).await {
                            Ok(r)=>{self.version=UpdateVersion{e_tag:r.e_tag,version:r.version};self.authority_until.store(self.record.expires_ms,Ordering::Release)},
                            Err(object_store::Error::Precondition { .. })=>{
                                tracing::error!("SELF-FENCE: lease update precondition failed");
                                break
                            }
                            Err(e)=>{
                                // A transport failure does not revoke authority
                                // already proven by the last successful CAS. Retry
                                // only until that fixed deadline; is_live() stops
                                // request admission independently at the boundary.
                                tracing::warn!(error = redacted_error(&e), "S3 lease renewal transient failure");
                            }
                        }
                    },
                    _=tokio::time::sleep(remaining)=>break,
                    _=stop.changed()=>break,
                }
            }
            self.live.store(false, Ordering::Release);
        })
    }

    pub fn stop_renewal(&self) {
        let _ = self.stop.send(true);
    }

    /// Relinquish ownership only if the bucket still contains this guard's
    /// owner and generation. A takeover or ambiguous read leaves the record
    /// untouched and local authority remains fenced.
    pub async fn relinquish(&self) -> anyhow::Result<()> {
        self.stop_renewal();
        self.live.store(false, Ordering::Release);
        let result = self.store.get(&self.key).await?;
        let meta = result.meta.clone();
        let mut record: LeaseRecord = serde_json::from_slice(&result.bytes().await?)?;
        anyhow::ensure!(
            record.owner == self.record.owner && record.generation == self.record.generation,
            "lease ownership changed before relinquish"
        );
        record.expires_ms = now_ms();
        self.store
            .put_opts(
                &self.key,
                Bytes::from(serde_json::to_vec(&record)?).into(),
                PutOptions {
                    mode: PutMode::Update(UpdateVersion {
                        e_tag: meta.e_tag,
                        version: meta.version,
                    }),
                    ..Default::default()
                },
            )
            .await?;
        Ok(())
    }
}

pub async fn probe_conditional_writes(
    store: Arc<dyn ObjectStore>,
    key: Path,
) -> anyhow::Result<()> {
    let _ = store.delete(&key).await;
    let first = store
        .put_opts(
            &key,
            Bytes::from_static(b"a").into(),
            PutOptions {
                mode: PutMode::Create,
                ..Default::default()
            },
        )
        .await?;
    anyhow::ensure!(
        store
            .put_opts(
                &key,
                Bytes::from_static(b"b").into(),
                PutOptions {
                    mode: PutMode::Create,
                    ..Default::default()
                }
            )
            .await
            .is_err(),
        "S3 does not enforce create preconditions"
    );
    let current = UpdateVersion {
        e_tag: first.e_tag,
        version: first.version,
    };
    store
        .put_opts(
            &key,
            Bytes::from_static(b"c").into(),
            PutOptions {
                mode: PutMode::Update(current.clone()),
                ..Default::default()
            },
        )
        .await?;
    anyhow::ensure!(
        store
            .put_opts(
                &key,
                Bytes::from_static(b"d").into(),
                PutOptions {
                    mode: PutMode::Update(current),
                    ..Default::default()
                }
            )
            .await
            .is_err(),
        "S3 does not enforce update preconditions"
    );
    store.delete(&key).await?;
    Ok(())
}
