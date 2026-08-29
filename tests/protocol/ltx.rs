use cog::ltx::*;
use futures_util::TryStreamExt;
use object_store::{ObjectStore, ObjectStoreExt, PutMode, PutOptions, path::Path};
use proptest::prelude::*;
use rustyriver::{ReplicaClient, TXID, restore};
use std::sync::Arc;

#[test]
fn generation_from_replica_key() {
    assert_eq!(
        parse_generation(
            "app/ltx/g00000000000000000042/0000/0000000000000001-0000000000000001.ltx"
        ),
        Some(42)
    );
    assert_eq!(parse_generation("app/ltx/not-a-generation/file"), None);
}

#[tokio::test]
async fn replica_client_ranges_cleanup_and_empty_compaction() {
    let store: Arc<dyn ObjectStore> = Arc::new(object_store::memory::InMemory::new());
    let client = ReplicaStoreClient::new(store.clone(), "range/g00000000000000000001".into());
    assert_eq!(client.type_name(), "object_store");
    let header = rustyriver::ltx::Header {
        version: rustyriver::ltx::VERSION,
        flags: rustyriver::ltx::HEADER_FLAG_NO_CHECKSUM,
        page_size: 512,
        commit: 1,
        min_txid: TXID(1),
        max_txid: TXID(1),
        ..Default::default()
    };
    let raw = rustyriver::ltx::encode_file(&header, &[(1, vec![7; 512])], 0).unwrap();
    client
        .write_ltx_file(0, TXID(1), TXID(1), &raw)
        .await
        .unwrap();
    assert_eq!(
        client
            .open_ltx_file(0, TXID(1), TXID(1), 0, 0)
            .await
            .unwrap(),
        raw
    );
    assert_eq!(
        client
            .open_ltx_file(0, TXID(1), TXID(1), 0, 8)
            .await
            .unwrap(),
        raw[..8]
    );
    assert!(
        client
            .open_ltx_file(0, TXID(1), TXID(1), -1, 1)
            .await
            .is_err()
    );
    assert!(
        client
            .open_ltx_file(0, TXID(1), TXID(1), i64::MAX, 1)
            .await
            .is_err()
    );
    client.delete_all().await.unwrap();
    assert!(
        client
            .ltx_files(0, TXID::ZERO, false)
            .await
            .unwrap()
            .is_empty()
    );
    let directory = tempfile::tempdir().unwrap();
    let replicator = Replicator::new(store, "range/".into(), directory.path().join("db"), 1);
    assert_eq!(replicator.db_path(), directory.path().join("db"));
    assert!(!replicator.compact().await.unwrap());
    assert!(decode_reference_ltx(&[0xff; 32]).is_err());
    let mut cursor = 0;
    assert!(take_uvarint(&[0xff; 10], &mut cursor).is_err());
}

fn legacy_fixture(fill: u8) -> Vec<u8> {
    let page = vec![fill; 512];
    let checksum = rustyriver::CHECKSUM_FLAG
        | (rustyriver::CHECKSUM_FLAG ^ rustyriver::ltx::checksum_page(1, &page));
    rustyriver::ltx::encode_file(
        &rustyriver::ltx::Header {
            version: rustyriver::ltx::VERSION,
            page_size: 512,
            commit: 1,
            min_txid: TXID(1),
            max_txid: TXID(1),
            ..Default::default()
        },
        &[(1, page)],
        checksum,
    )
    .unwrap()
}

#[test]
fn reference_codec_detects_corruption_and_truncation() {
    let encoded = encode_reference_ltx(&legacy_fixture(7)).unwrap();
    assert!(decode_reference_ltx(&encoded).is_ok());
    assert!(decode_reference_ltx(&encoded[..encoded.len() - 1]).is_err());
    let mut corrupt = encoded;
    corrupt[110] ^= 1;
    assert!(decode_reference_ltx(&corrupt).is_err());
}

#[tokio::test]
async fn immutable_uploads_are_idempotent_but_never_replace_bytes() {
    let store: Arc<dyn ObjectStore> = Arc::new(object_store::memory::InMemory::new());
    let client = ReplicaStoreClient::new(store.clone(), "app/ltx/g00000000000000000001".into());
    let first = legacy_fixture(1);
    client
        .write_ltx_file(0, TXID(1), TXID(1), &first)
        .await
        .unwrap();
    client
        .write_ltx_file(0, TXID(1), TXID(1), &first)
        .await
        .unwrap();
    assert!(
        client
            .write_ltx_file(0, TXID(1), TXID(1), &legacy_fixture(2))
            .await
            .is_err()
    );

    // Simulate S3 committing the exact bytes while the response is lost.
    // Retrying through the client must prove equality and succeed.
    let ambiguous = legacy_fixture(3);
    let remote = encode_reference_ltx(&ambiguous).unwrap();
    let key = Path::from(format!(
        "app/ltx/g00000000000000000001/0000/{}",
        rustyriver::ltx::format_filename(TXID(2), TXID(2))
    ));
    store
        .put_opts(
            &key,
            bytes::Bytes::from(remote).into(),
            PutOptions {
                mode: PutMode::Create,
                ..Default::default()
            },
        )
        .await
        .unwrap();
    client
        .write_ltx_file(0, TXID(2), TXID(2), &ambiguous)
        .await
        .unwrap();
}

#[tokio::test]
async fn restore_rejects_corrupt_remote_ltx() {
    let store: Arc<dyn ObjectStore> = Arc::new(object_store::memory::InMemory::new());
    let directory = tempfile::tempdir().unwrap();
    let source = directory.path().join("source.db");
    let database = crate::db::Database::open(&source).unwrap();
    database.create_user("first@example.com", "hash").unwrap();
    let first = Replicator::new(store.clone(), "corrupt/".into(), source, 1);
    first.sync().await.unwrap();
    first.commit_generation().await.unwrap();
    let object = store
        .list(Some(&Path::from("corrupt/ltx/g00000000000000000001/0000")))
        .try_next()
        .await
        .unwrap()
        .unwrap();
    let mut bytes = store
        .get(&object.location)
        .await
        .unwrap()
        .bytes()
        .await
        .unwrap()
        .to_vec();
    bytes[110] ^= 1;
    store.put(&object.location, bytes.into()).await.unwrap();
    let restore = Replicator::new(
        store,
        "corrupt/".into(),
        directory.path().join("restored.db"),
        2,
    );
    assert!(restore.restore().await.is_err());
}

#[tokio::test]
async fn truncated_wal_is_not_published() {
    let store: Arc<dyn ObjectStore> = Arc::new(object_store::memory::InMemory::new());
    let directory = tempfile::tempdir().unwrap();
    let source = directory.path().join("source.db");
    let database = crate::db::Database::open(&source).unwrap();
    database.create_user("first@example.com", "hash").unwrap();
    let wal = std::path::PathBuf::from(format!("{}-wal", source.display()));
    let length = std::fs::metadata(&wal).unwrap().len();
    std::fs::OpenOptions::new()
        .write(true)
        .open(&wal)
        .unwrap()
        .set_len(length / 2)
        .unwrap();
    let replicator = Replicator::new(store.clone(), "wal/".into(), source, 1);
    assert!(replicator.sync().await.is_err());
    assert!(
        store
            .list(Some(&Path::from("wal/ltx")))
            .try_next()
            .await
            .unwrap()
            .is_none()
    );
}

#[tokio::test]
async fn replicate_incrementally_and_restore_latest_generation() {
    let store: Arc<dyn ObjectStore> = Arc::new(object_store::memory::InMemory::new());
    let dir = tempfile::tempdir().unwrap();
    let source = dir.path().join("source.db");
    let database = crate::db::Database::open(&source).unwrap();
    let first = Replicator::new(store.clone(), "app/".into(), source.clone(), 1);

    database.create_user("first@example.com", "hash").unwrap();
    first.sync().await.unwrap();
    database.create_user("second@example.com", "hash").unwrap();
    first.sync().await.unwrap();
    first.commit_generation().await.unwrap();

    let objects = store
        .list(Some(&Path::from("app/ltx/g00000000000000000001/0000")))
        .try_collect::<Vec<_>>()
        .await
        .unwrap();
    assert_eq!(objects.len(), 2, "snapshot plus incremental L0 segment");

    // An interruption after publishing a verified anchor but before L0
    // deletion leaves redundant objects, not a broken restore chain.
    let staging = dir.path().join("anchor-source.db");
    restore(&first.client(1), &staging, TXID(2)).await.unwrap();
    let anchor = encode_snapshot(&staging, 2).unwrap();
    first
        .client(1)
        .write_ltx_file(9, TXID(1), TXID(2), &anchor)
        .await
        .unwrap();
    let interrupted_path = dir.path().join("interrupted-restore.db");
    let interrupted = Replicator::new(store.clone(), "app/".into(), interrupted_path.clone(), 2);
    assert!(interrupted.restore().await.unwrap());
    assert_eq!(
        crate::db::Database::open(&interrupted_path)
            .unwrap()
            .user_count()
            .unwrap(),
        2
    );
    assert!(first.compact().await.unwrap());
    let l0 = store
        .list(Some(&Path::from("app/ltx/g00000000000000000001/0000")))
        .try_collect::<Vec<_>>()
        .await
        .unwrap();
    let snapshots = store
        .list(Some(&Path::from("app/ltx/g00000000000000000001/0009")))
        .try_collect::<Vec<_>>()
        .await
        .unwrap();
    assert!(l0.is_empty());
    assert_eq!(snapshots.len(), 1);

    // A newer generation with a valid but incomplete historical prefix
    // must not hide the last committed generation.
    let partial_path = dir.path().join("partial.db");
    let partial_database = crate::db::Database::open(&partial_path).unwrap();
    partial_database
        .create_user("partial@example.com", "hash")
        .unwrap();
    let partial = Replicator::new(store.clone(), "app/".into(), partial_path, 2);
    partial.sync().await.unwrap();
    drop(partial_database);
    drop(partial);

    drop(database);
    drop(first);
    let restored = dir.path().join("restored.db");
    let next = Replicator::new(store, "app/".into(), restored.clone(), 2);
    assert!(next.restore().await.unwrap());
    let database = crate::db::Database::open(&restored).unwrap();
    assert_eq!(database.user_count().unwrap(), 2);
}

#[tokio::test]
async fn restore_fails_closed_when_only_uncommitted_generations_exist() {
    let store: Arc<dyn ObjectStore> = Arc::new(object_store::memory::InMemory::new());
    let directory = tempfile::tempdir().unwrap();
    let source = directory.path().join("source.db");
    let database = crate::db::Database::open(&source).unwrap();
    database.create_user("partial@example.com", "hash").unwrap();
    let partial = Replicator::new(store.clone(), "uncommitted/".into(), source, 1);
    partial.sync().await.unwrap();
    let restored = Replicator::new(
        store,
        "uncommitted/".into(),
        directory.path().join("restored.db"),
        2,
    );
    assert!(restored.restore().await.is_err());
}

proptest! {
    #[test]
    fn reference_ltx_round_trips_arbitrary_pages(page in prop::collection::vec(any::<u8>(), 512)) {
        let checksum = rustyriver::CHECKSUM_FLAG
            | (rustyriver::CHECKSUM_FLAG ^ rustyriver::ltx::checksum_page(1, &page));
        let legacy = rustyriver::ltx::encode_file(
            &rustyriver::ltx::Header {
                version: rustyriver::ltx::VERSION,
                page_size: 512,
                commit: 1,
                min_txid: TXID(1),
                max_txid: TXID(1),
                ..Default::default()
            },
            &[(1, page)],
            checksum,
        ).unwrap();
        let reference = encode_reference_ltx(&legacy).unwrap();
        prop_assert_eq!(decode_reference_ltx(&reference).unwrap(), legacy);
    }

    #[test]
    fn reference_ltx_decoder_never_panics(bytes in prop::collection::vec(any::<u8>(), 0..4096)) {
        let _ = decode_reference_ltx(&bytes);
    }
}
