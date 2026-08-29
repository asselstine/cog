use cog::lease::{LeaseError, LeaseGuard, probe_conditional_writes};
use cog::{db::Database, ltx::Replicator};
use futures_util::StreamExt;
use object_store::{
    ObjectStore, ObjectStoreExt, aws::AmazonS3Builder, memory::InMemory, path::Path,
};
use std::{
    fs,
    process::{Child, Command, Stdio},
    sync::Arc,
    time::Duration,
};

fn store() -> Arc<dyn ObjectStore> {
    Arc::new(
        AmazonS3Builder::new()
            .with_bucket_name("cog-test")
            .with_region("us-east-1")
            .with_endpoint("http://127.0.0.1:19000")
            .with_allow_http(true)
            .with_access_key_id("cog-test")
            .with_secret_access_key("cog-test-secret")
            .with_virtual_hosted_style_request(false)
            .build()
            .unwrap(),
    )
}

#[tokio::test]
#[ignore = "requires tests/infrastructure/compose.yml MinIO"]
async fn conditional_lease_excludes_second_owner() {
    let s = store();
    let prefix = format!("tests/{}/", uuid::Uuid::new_v4());
    probe_conditional_writes(s.clone(), Path::from(format!("{prefix}probe")))
        .await
        .unwrap();
    let first = LeaseGuard::acquire(
        s.clone(),
        Path::from(format!("{prefix}lease")),
        Duration::from_secs(30),
    )
    .await
    .unwrap();
    assert!(first.is_live());
    let second = LeaseGuard::acquire(
        s,
        Path::from(format!("{prefix}lease")),
        Duration::from_secs(30),
    )
    .await;
    assert!(matches!(second, Err(LeaseError::Held(_))));
}

#[tokio::test]
#[ignore = "requires tests/infrastructure/compose.yml MinIO"]
async fn incremental_replication_restores_across_generation() {
    let s = store();
    let prefix = format!("tests/{}/", uuid::Uuid::new_v4());
    let directory = tempfile::tempdir().unwrap();
    let source = directory.path().join("source.sqlite");
    let database = Database::open(&source).unwrap();
    let first = Replicator::new(s.clone(), prefix.clone(), source, 1);
    database.create_user("first@example.com", "hash").unwrap();
    first.sync().await.unwrap();
    database.create_user("second@example.com", "hash").unwrap();
    first.sync().await.unwrap();
    first.commit_generation().await.unwrap();
    assert_eq!(first.durable_txid(), 2);
    drop(database);
    drop(first);

    let restored = directory.path().join("restored.sqlite");
    let second = Replicator::new(s.clone(), prefix.clone(), restored.clone(), 2);
    assert!(second.restore().await.unwrap());
    let database = Database::open(&restored).unwrap();
    assert_eq!(database.user_count().unwrap(), 2);

    let objects = s.list(Some(&Path::from(prefix))).collect::<Vec<_>>().await;
    for object in objects.into_iter().flatten() {
        s.delete(&object.location).await.unwrap();
    }
}

#[tokio::test]
#[ignore = "requires tests/infrastructure/compose.yml MinIO"]
async fn ssh_host_identity_survives_s3_takeover() {
    let s = store();
    let prefix = format!("ssh-takeover/{}/", uuid::Uuid::new_v4());
    let directory = tempfile::tempdir().unwrap();
    let first_path = directory.path().join("first.sqlite");
    let first = Database::open(&first_path).unwrap();
    let master_key = cog::crypto::random_token(32);
    let secrets = cog::crypto::SecretBox::new(master_key.as_bytes());
    let first_keys = cog::git::ssh::KeySet::load_or_create(&first, &secrets).unwrap();
    let host = first_keys.host.public_key().to_openssh().unwrap();
    let generation1 = Replicator::new(s.clone(), prefix.clone(), first_path, 1);
    generation1.sync().await.unwrap();
    generation1.commit_generation().await.unwrap();
    drop(first);
    drop(first_keys);

    let second_path = directory.path().join("second.sqlite");
    let generation2 = Replicator::new(s, prefix, second_path.clone(), 2);
    assert!(generation2.restore().await.unwrap());
    let second = Database::open(&second_path).unwrap();
    let second_keys = cog::git::ssh::KeySet::load_or_create(&second, &secrets).unwrap();
    assert_eq!(second_keys.host.public_key().to_openssh().unwrap(), host);
}

#[tokio::test]
#[ignore = "requires tests/infrastructure/compose.yml MinIO"]
async fn git_grant_acknowledgements_have_covering_durable_ltx_positions() {
    let s = store();
    let prefix = format!("git-durable-ack/{}/", uuid::Uuid::new_v4());
    let directory = tempfile::tempdir().unwrap();
    let source = directory.path().join("owner.sqlite");
    let database = Database::open(&source).unwrap();
    let user = database.create_user("durable@example.com", "hash").unwrap();
    database
        .register_client(
            "agent",
            Some(&user),
            "agent",
            &["http://localhost/cb".into()],
        )
        .unwrap();
    let integration = database
        .create_integration(
            &user,
            "Git",
            "git",
            &serde_json::json!({"kind":"git"}),
            None,
        )
        .unwrap();
    let repository = database
        .upsert_git_repository(
            &user,
            &integration,
            &cog::git::ResolvedRepository {
                provider_repository_id: "durable-provider-id".into(),
                display_name: "owner/durable".into(),
                upstream_url: "https://github.com/owner/durable.git".parse().unwrap(),
                metadata: serde_json::json!({}),
            },
        )
        .unwrap();
    let replicator = Replicator::new(s.clone(), prefix.clone(), source, 1);
    let baseline = replicator.sync().await.unwrap();

    database
        .set_git_grant(&user, "agent", &repository.id, "write")
        .unwrap();
    let granted = replicator.sync().await.unwrap();
    assert!(granted > baseline);
    assert_eq!(replicator.durable_txid(), granted);

    database
        .revoke_git_grant(&user, "agent", &repository.id)
        .unwrap();
    let revoked = replicator.sync().await.unwrap();
    assert!(revoked > granted);
    assert_eq!(replicator.durable_txid(), revoked);
    replicator.commit_generation().await.unwrap();
    drop(database);

    let restored = directory.path().join("successor.sqlite");
    let successor = Replicator::new(s, prefix, restored.clone(), 2);
    assert!(successor.restore().await.unwrap());
    let database = Database::open(&restored).unwrap();
    assert!(
        database
            .git_grant_permission(&user, "agent", &repository.id)
            .unwrap()
            .is_none()
    );
}

#[tokio::test]
#[ignore = "requires tests/infrastructure/compose.yml MinIO"]
async fn two_process_takeover_restores_and_excludes_stale_owner() {
    let directory = tempfile::tempdir().unwrap();
    let prefix = format!("process-tests/{}/", uuid::Uuid::new_v4());
    let first_dir = directory.path().join("first");
    let second_dir = directory.path().join("second");
    let master_key = cog::crypto::random_token(32);
    let status = configure_cog(
        Command::new(env!("CARGO_BIN_EXE_cog")),
        &first_dir,
        &prefix,
        19188,
        &master_key,
    )
    .args(["create-user", "owner@example.com", "--password-stdin"])
    .stdin(Stdio::piped())
    .spawn()
    .and_then(|mut child| {
        use std::io::Write;
        child
            .stdin
            .as_mut()
            .unwrap()
            .write_all(b"long-test-password\n")?;
        child.wait()
    })
    .unwrap();
    assert!(status.success());
    let mut first = spawn_cog(&first_dir, &prefix, 19188, &master_key);
    wait_ready(19188).await;

    let mut excluded = spawn_cog(&second_dir, &prefix, 19189, &master_key);
    let status = tokio::time::timeout(Duration::from_secs(3), async {
        loop {
            if let Some(status) = excluded.try_wait().unwrap() {
                break status;
            }
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
    })
    .await
    .expect("second process did not reject the held lease");
    assert!(!status.success());

    signal_interrupt(&first);
    assert!(first.wait().unwrap().success());
    let mut successor = spawn_cog(&second_dir, &prefix, 19189, &master_key);
    wait_ready(19189).await;
    signal_interrupt(&successor);
    assert!(successor.wait().unwrap().success());
}

fn spawn_cog(data_dir: &std::path::Path, prefix: &str, port: u16, master_key: &str) -> Child {
    configure_cog(
        Command::new(env!("CARGO_BIN_EXE_cog")),
        data_dir,
        prefix,
        port,
        master_key,
    )
    .spawn()
    .unwrap()
}

fn configure_cog(
    mut command: Command,
    data_dir: &std::path::Path,
    prefix: &str,
    port: u16,
    master_key: &str,
) -> Command {
    command
        // Each process needs its own SSH listener as well as its HTTP listener.
        // The application default (127.0.0.1:2222) otherwise makes this
        // intentional two-process lease test fail at bind time.
        .env("COG_SSH_LISTEN", format!("127.0.0.1:{}", port + 1_000))
        .env("COG_SSH_PUBLIC_HOST", "localhost")
        .env("COG_LISTEN", format!("127.0.0.1:{port}"))
        .env("COG_BASE_URL", format!("http://127.0.0.1:{port}"))
        .env("COG_DATA_DIR", data_dir)
        .env("COG_S3_BUCKET", "cog-test")
        .env("COG_S3_PREFIX", prefix)
        .env("COG_S3_ENDPOINT", "http://127.0.0.1:19000")
        .env("COG_S3_ALLOW_HTTP", "true")
        .env("AWS_ACCESS_KEY_ID", "cog-test")
        .env("AWS_SECRET_ACCESS_KEY", "cog-test-secret")
        .env("AWS_REGION", "us-east-1")
        .env("COG_MASTER_KEY", master_key)
        .env("COG_LEASE_TTL_SECS", "9")
        .stdout(Stdio::null())
        .stderr(Stdio::null());
    command
}

async fn wait_ready(port: u16) {
    let client = reqwest::Client::new();
    // Instrumented binaries can take several seconds to restore and acquire a
    // lease on slower CI runners. Keep polling bounded, but do not make the
    // takeover test depend on a three-second startup deadline.
    for _ in 0..500 {
        if client
            .get(format!("http://127.0.0.1:{port}/healthz"))
            .send()
            .await
            .is_ok()
        {
            return;
        }
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
    panic!("cog process on port {port} did not become ready");
}

#[cfg(unix)]
fn signal_interrupt(child: &Child) {
    assert!(
        Command::new("kill")
            .args(["-INT", &child.id().to_string()])
            .status()
            .unwrap()
            .success()
    );
}

/// Bidirectional differential test against the exact Litestream version pinned
/// by CI. This tests the wire format rather than merely round-tripping through
/// rustyriver on both sides.
#[tokio::test]
async fn ltx_is_compatible_with_litestream() {
    let litestream = match std::env::var_os("LITESTREAM_BIN") {
        Some(path) => path,
        None if std::env::var_os("CI").is_none() => return,
        None => panic!("CI must set LITESTREAM_BIN to the pinned reference binary"),
    };
    let directory = tempfile::tempdir().unwrap();

    // cog -> Litestream
    let source = directory.path().join("cog-source.sqlite");
    let database = Database::open(&source).unwrap();
    database.create_user("one@example.com", "hash").unwrap();
    let store: Arc<dyn ObjectStore> = Arc::new(InMemory::new());
    let replicator = Replicator::new(store.clone(), "app/".into(), source, 7);
    replicator.sync().await.unwrap();
    database.create_user("two@example.com", "hash").unwrap();
    replicator.sync().await.unwrap();
    replicator.commit_generation().await.unwrap();

    let replica = directory.path().join("cog-replica");
    copy_store_ltx_to_file_replica(store.as_ref(), "app/ltx/g00000000000000000007", &replica).await;
    let restored = directory.path().join("litestream-restored.sqlite");
    run_litestream(
        &litestream,
        &[
            "restore",
            "-integrity-check",
            "full",
            "-o",
            restored.to_str().unwrap(),
            &format!("file://{}", replica.display()),
        ],
    );
    assert_eq!(Database::open(&restored).unwrap().user_count().unwrap(), 2);

    // Litestream -> cog
    let reference_source = directory.path().join("reference-source.sqlite");
    let reference = Database::open(&reference_source).unwrap();
    reference
        .create_user("reference@example.com", "hash")
        .unwrap();
    drop(reference);
    let reference_replica = directory.path().join("reference-replica");
    run_litestream(
        &litestream,
        &[
            "replicate",
            "-once",
            reference_source.to_str().unwrap(),
            &format!("file://{}", reference_replica.display()),
        ],
    );
    let imported: Arc<dyn ObjectStore> = Arc::new(InMemory::new());
    copy_file_replica_to_store(
        &reference_replica,
        imported.as_ref(),
        "import/ltx/g00000000000000000011",
    )
    .await;
    imported
        .put(
            &Path::from("import/ltx/g00000000000000000011/complete.json"),
            bytes::Bytes::from_static(br#"{"version":1,"generation":11}"#).into(),
        )
        .await
        .unwrap();
    let imported_path = directory.path().join("cog-restored.sqlite");
    let importer = Replicator::new(imported, "import/".into(), imported_path.clone(), 12);
    assert!(importer.restore().await.unwrap());
    assert_eq!(
        Database::open(&imported_path)
            .unwrap()
            .user_count()
            .unwrap(),
        1
    );
}

fn run_litestream(binary: &std::ffi::OsStr, args: &[&str]) {
    let output = Command::new(binary).args(args).output().unwrap();
    assert!(
        output.status.success(),
        "litestream failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
}

async fn copy_store_ltx_to_file_replica(
    store: &dyn ObjectStore,
    prefix: &str,
    target: &std::path::Path,
) {
    let objects = store
        .list(Some(&Path::from(prefix)))
        .collect::<Vec<_>>()
        .await;
    for object in objects.into_iter().map(Result::unwrap) {
        let relative = object.location.as_ref().strip_prefix(prefix).unwrap();
        let relative = relative.trim_start_matches('/').replace("0000/", "0/");
        let destination = target.join("ltx").join(relative);
        fs::create_dir_all(destination.parent().unwrap()).unwrap();
        let bytes = store
            .get(&object.location)
            .await
            .unwrap()
            .bytes()
            .await
            .unwrap();
        fs::write(destination, bytes).unwrap();
    }
}

async fn copy_file_replica_to_store(
    source: &std::path::Path,
    store: &dyn ObjectStore,
    prefix: &str,
) {
    let level = source.join("ltx/0");
    for entry in fs::read_dir(level).unwrap() {
        let entry = entry.unwrap();
        let bytes = fs::read(entry.path()).unwrap();
        let key = Path::from(format!(
            "{prefix}/0000/{}",
            entry.file_name().to_string_lossy()
        ));
        store.put(&key, bytes.into()).await.unwrap();
    }
}
