use bytes::Bytes;
use cog::lease::*;
use object_store::memory::InMemory;
use object_store::{ObjectStore, ObjectStoreExt, path::Path};
use std::{sync::Arc, time::Duration};

#[tokio::test]
async fn probe_acquire_exclude_and_expire() {
    let store: Arc<dyn ObjectStore> = Arc::new(InMemory::new());
    probe_conditional_writes(store.clone(), Path::from("probe/test"))
        .await
        .unwrap();
    let key = Path::from("lease");
    let first = LeaseGuard::acquire(store.clone(), key.clone(), Duration::from_millis(30))
        .await
        .unwrap();
    assert_eq!(first.generation(), 1);
    assert!(!first.owner().is_empty());
    assert!(first.assert_live().is_ok());
    assert!(matches!(
        LeaseGuard::acquire(store.clone(), key.clone(), Duration::from_secs(1)).await,
        Err(LeaseError::Held(_))
    ));
    tokio::time::sleep(Duration::from_millis(40)).await;
    assert!(!first.is_live());
    let second = LeaseGuard::acquire(store, key, Duration::from_secs(1))
        .await
        .unwrap();
    assert_eq!(second.generation(), 2);
}

#[tokio::test]
async fn renewal_keeps_authority() {
    let store: Arc<dyn ObjectStore> = Arc::new(InMemory::new());
    let guard = LeaseGuard::acquire(store, Path::from("lease"), Duration::from_millis(30))
        .await
        .unwrap();
    let observer = guard.clone();
    let task = guard.spawn_renewal();
    tokio::time::sleep(Duration::from_millis(45)).await;
    assert!(observer.is_live());
    task.abort();
}

#[tokio::test]
async fn relinquish_expires_only_own_lease() {
    let store: Arc<dyn ObjectStore> = Arc::new(InMemory::new());
    let key = Path::from("lease");
    let first = LeaseGuard::acquire(store.clone(), key.clone(), Duration::from_secs(1))
        .await
        .unwrap();
    first.relinquish().await.unwrap();
    assert!(!first.is_live());
    let second = LeaseGuard::acquire(store, key, Duration::from_secs(1))
        .await
        .unwrap();
    assert_eq!(second.generation(), 2);
}

#[tokio::test]
async fn stale_etag_self_fences_terminally() {
    let store: Arc<dyn ObjectStore> = Arc::new(InMemory::new());
    let key = Path::from("lease");
    let guard = LeaseGuard::acquire(store.clone(), key.clone(), Duration::from_millis(90))
        .await
        .unwrap();
    let observer = guard.clone();
    let task = guard.spawn_renewal();

    // Simulate an external writer changing the object version. The next
    // conditional renewal must fail and terminate instead of retrying.
    store
        .put(&key, Bytes::from_static(b"superseded").into())
        .await
        .unwrap();
    tokio::time::timeout(Duration::from_millis(100), task)
        .await
        .expect("renewer did not self-fence")
        .unwrap();
    assert!(!observer.is_live());
    assert!(observer.assert_live().is_err());
}

#[tokio::test]
async fn missing_lease_retries_only_until_proven_deadline() {
    let store: Arc<dyn ObjectStore> = Arc::new(InMemory::new());
    let key = Path::from("lease");
    let guard = LeaseGuard::acquire(store.clone(), key.clone(), Duration::from_millis(90))
        .await
        .unwrap();
    let observer = guard.clone();
    let task = guard.spawn_renewal();
    store.delete(&key).await.unwrap();
    tokio::time::timeout(Duration::from_millis(150), task)
        .await
        .expect("renewer served beyond proven authority")
        .unwrap();
    assert!(!observer.is_live());
}

#[tokio::test]
async fn delayed_renewal_never_extends_authority_after_clock_boundary() {
    use object_store::throttle::{ThrottleConfig, ThrottledStore};
    let throttled = Arc::new(ThrottledStore::new(
        InMemory::new(),
        ThrottleConfig::default(),
    ));
    let store: Arc<dyn ObjectStore> = throttled.clone();
    let guard = LeaseGuard::acquire(store, Path::from("lease"), Duration::from_millis(90))
        .await
        .unwrap();
    let observer = guard.clone();
    throttled.config_mut(|config| config.wait_put_per_call = Duration::from_millis(120));
    let task = guard.spawn_renewal();
    tokio::time::sleep(Duration::from_millis(95)).await;
    assert!(
        !observer.is_live(),
        "delayed I/O served past proven authority"
    );
    tokio::time::timeout(Duration::from_millis(100), task)
        .await
        .expect("delayed renewer did not terminate")
        .unwrap();
    assert!(!observer.is_live(), "authority was regained after expiry");
}
