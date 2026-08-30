use super::*;

pub async fn create_user(config: Config, email: &str, password: &str) -> anyhow::Result<()> {
    anyhow::ensure!(!email.trim().is_empty(), "email is required");
    anyhow::ensure!(
        password.len() >= 12,
        "password must be at least 12 characters"
    );
    std::fs::create_dir_all(&config.data_dir)?;
    if !config.s3_enabled() {
        ensure_local_database_compatible(&config)?;
        let db = Database::open_with_mode(&config.db_path(), StorageMode::Local)?;
        create_user_record(&db, email, password)?;
        println!("Created user {email}");
        return Ok(());
    }
    ensure_s3_database_compatible(&config)?;
    let store = build_store(&config)?;
    probe_conditional_writes(
        store.clone(),
        ObjectPath::from(format!("{}probe/conditional", config.s3_prefix)),
    )
    .await?;
    let lease = LeaseGuard::acquire(
        store.clone(),
        ObjectPath::from(format!("{}lease.json", config.s3_prefix)),
        config.lease_ttl(),
    )
    .await
    .map_err(|error| anyhow::anyhow!("cannot create a user while cog is running: {error}"))?;
    let mut renewal = lease.clone().spawn_renewal();
    let result = async {
        let replicator = Replicator::new(
            store,
            config.s3_prefix.clone(),
            config.db_path(),
            lease.generation(),
        );
        let _ = replicator.restore().await?;
        let db = Database::open_with_mode(&config.db_path(), StorageMode::S3)?;
        replicator.sync().await?;
        replicator.commit_generation().await?;

        create_user_record(&db, email, password)?;
        let durable_txid = replicator.sync().await?;
        anyhow::ensure!(
            durable_txid > 0,
            "user mutation has no durable LTX position"
        );
        lease.assert_live()?;
        Ok::<(), anyhow::Error>(())
    }
    .await;

    lease.stop_renewal();
    let _ = (&mut renewal).await;
    let relinquish = lease.relinquish().await;
    result?;
    relinquish?;
    println!("Created user {email}");
    Ok(())
}

pub fn create_user_record(db: &Database, email: &str, password: &str) -> anyhow::Result<()> {
    let salt = SaltString::generate(&mut OsRng);
    let hash = Argon2::default()
        .hash_password(password.as_bytes(), &salt)
        .map_err(|error| anyhow::anyhow!("could not hash password: {error}"))?
        .to_string();
    let user = db.create_user(email, &hash)?;
    db.record_audit(
        Some(&user),
        "user.create_cli",
        Some(&user),
        "success",
        &json!({}),
    )?;
    Ok(())
}

pub async fn run(config: Config) -> anyhow::Result<()> {
    std::fs::create_dir_all(&config.data_dir)
        .map_err(|error| StartupError::new(StartupPhase::DatabaseOpen, &error))?;
    let (db, lease, replicator, mut renewal) = if config.s3_enabled() {
        ensure_s3_database_compatible(&config)?;
        tracing::info!(
            credential_provider = credential_provider_class(),
            bucket = %config.s3_bucket.as_deref().unwrap_or_default(),
            region = %config.s3_region,
            endpoint = %safe_endpoint(&config),
            "initializing S3 storage"
        );
        let store = build_store(&config).map_err(|error| {
            StartupError::new(StartupPhase::StorageInitialization, error.as_ref())
        })?;
        probe_conditional_writes(
            store.clone(),
            ObjectPath::from(format!("{}probe/conditional", config.s3_prefix)),
        )
        .await
        .map_err(|error| StartupError::new(StartupPhase::ConditionalWriteProbe, error.as_ref()))?;
        let remote_lease = LeaseGuard::acquire(
            store.clone(),
            ObjectPath::from(format!("{}lease.json", config.s3_prefix)),
            config.lease_ttl(),
        )
        .await
        .map_err(|error| StartupError::new(StartupPhase::LeaseAcquisition, &error))?;
        let renewal = remote_lease.clone().spawn_renewal();
        let repl = Arc::new(Replicator::new(
            store,
            config.s3_prefix.clone(),
            config.db_path(),
            remote_lease.generation(),
        ));
        let _ = repl
            .restore()
            .await
            .map_err(|error| StartupError::new(StartupPhase::Restore, error.as_ref()))?;
        let db = Database::open_with_mode(&config.db_path(), StorageMode::S3)
            .map_err(|error| StartupError::new(StartupPhase::DatabaseOpen, error.as_ref()))?;
        repl.sync()
            .await
            .map_err(|error| StartupError::new(StartupPhase::InitialReplication, error.as_ref()))?;
        repl.commit_generation()
            .await
            .map_err(|error| StartupError::new(StartupPhase::InitialReplication, error.as_ref()))?;
        (
            db,
            Authority::S3(remote_lease),
            Durability::S3(repl),
            Some(renewal),
        )
    } else {
        ensure_local_database_compatible(&config)?;
        tracing::info!(path = %config.db_path().display(), "initializing local SQLite storage");
        let db = Database::open_with_mode(&config.db_path(), StorageMode::Local)
            .map_err(|error| StartupError::new(StartupPhase::DatabaseOpen, error.as_ref()))?;
        (db, Authority::Local, Durability::Local, None)
    };
    if db.user_count()? == 0 {
        lease.stop_renewal();
        if let Some(task) = renewal.as_mut() {
            let _ = task.await;
        }
        if let Authority::S3(remote) = &lease {
            remote.relinquish().await?;
        }
        eprintln!(
            "No users exist. Create the first user with:\n  cog create-user $EMAIL $PASSWORD"
        );
        return Ok(());
    }
    let secrets = SecretBox::new(config.master_key.as_bytes());
    let mut app = App {
        secrets,
        runtime: Arc::new(CodeRuntime::new(
            config.v8_heap_mb,
            Duration::from_secs(config.execution_timeout_secs),
        )),
        config: config.clone(),
        db,
        lease: lease.clone(),
        replicator: replicator.clone(),
        providers: Arc::new(tokio::sync::Mutex::new(HashMap::new())),
        metrics: Arc::new(Metrics::default()),
        mutations: Arc::new(tokio::sync::Mutex::new(())),
        auth_rate_limit: Arc::new(RateLimiter::default()),
        git_providers: Arc::new(tokio::sync::Mutex::new(HashMap::new())),
        git_streams: Arc::new(tokio::sync::Semaphore::new(config.git_max_streams)),
        git_client_streams: Arc::new(ClientStreamLimiter::default()),
        ssh_keys: None,
        ssh_ready: Arc::new(AtomicBool::new(false)),
        ssh_connections: Arc::new(tokio::sync::Semaphore::new(config.ssh_max_connections)),
        github_api_base: "https://api.github.com/"
            .parse()
            .expect("valid GitHub API URL"),
    };
    let ssh_listener = if let Some(address) = config.ssh_listen {
        let keys = Arc::new(std::sync::RwLock::new(
            crate::git::ssh::KeySet::load_or_create(&app.db, &app.secrets)?,
        ));
        app.ssh_keys = Some(keys);
        // Key creation is a durable mutation. In S3 mode it must be replicated
        // before either the public key or listener is advertised.
        persist(&app).await?;
        Some(
            tokio::net::TcpListener::bind(address)
                .await
                .with_context(|| format!("configured SSH listener {address} could not be bound"))?,
        )
    } else {
        None
    };
    let (ssh_shutdown, _) = tokio::sync::broadcast::channel::<()>(1);
    let ssh_task = if let Some(listener) = ssh_listener {
        let keys = app.ssh_keys.as_ref().expect("SSH keys loaded");
        let encoded = crate::git::ssh::encode_private(
            &keys
                .read()
                .map_err(|_| anyhow::anyhow!("SSH key lock poisoned"))?
                .host,
        )?;
        let host_key = russh::keys::PrivateKey::from_openssh(&encoded)?;
        let ssh_config = Arc::new(russh::server::Config {
            methods: russh::MethodSet::from(&[russh::MethodKind::PublicKey][..]),
            auth_rejection_time: Duration::from_secs(1),
            auth_rejection_time_initial: Some(Duration::ZERO),
            keys: vec![host_key],
            window_size: 256 * 1024,
            maximum_packet_size: 32 * 1024,
            channel_buffer_size: 8,
            event_buffer_size: 8,
            max_auth_attempts: 3,
            inactivity_timeout: Some(Duration::from_secs(config.ssh_channel_timeout_secs)),
            nodelay: true,
            ..Default::default()
        });
        let factory = SshServerFactory { app: app.clone() };
        let mut shutdown = ssh_shutdown.subscribe();
        app.ssh_ready.store(true, Ordering::Release);
        Some(tokio::spawn(async move {
            let mut factory = factory;
            let running = factory.run_on_socket(ssh_config, &listener);
            let handle = running.handle();
            tokio::pin!(running);
            tokio::select! {
                result = &mut running => result,
                _ = shutdown.recv() => {
                    handle.shutdown("COG is shutting down".into());
                    running.await
                }
            }
        }))
    } else {
        None
    };
    let shutdown_providers = app.providers.clone();
    let router = build_router(app.clone());
    let listener = tokio::net::TcpListener::bind(config.listen).await?;
    tracing::info!(address=%config.listen,"cog ready");
    axum::serve(listener, router)
        .with_graceful_shutdown(async move {
            tokio::select! {
                _ = tokio::signal::ctrl_c() => {
                    let _ = ssh_shutdown.send(());
                    // Stop admitting new work, capture the final committed
                    // position while authority is still proven, then stop the
                    // renewer and conditionally expire our ownership record.
                    if lease.is_live()
                        && let Err(error) = replicator.sync().await
                    {
                        tracing::error!(error = redacted_error(error.as_ref()), "final LTX sync failed during shutdown");
                    }
                    lease.stop_renewal();
                    if let Some(task) = renewal.as_mut() { let _ = task.await; }
                    if let Authority::S3(remote) = &lease
                        && let Err(error) = remote.relinquish().await {
                            tracing::warn!(error = redacted_error(error.as_ref()), "lease relinquish failed");
                    }
                }
                _ = async {
                    match renewal.as_mut() {
                        Some(task) => { let _ = task.await; }
                        None => std::future::pending::<()>().await,
                    }
                } => {
                    let _ = ssh_shutdown.send(());
                    tracing::error!("SELF-FENCE: lease renewal terminated; shutting down");
                }
            }
            let providers = {
                let mut providers = shutdown_providers.lock().await;
                providers
                    .drain()
                    .map(|(_, provider)| provider)
                    .collect::<Vec<_>>()
            };
            for provider in providers {
                if let Err(error) = provider.close().await {
                    tracing::warn!(error = %safe_error(error.as_ref()), "upstream cleanup failed");
                }
            }
        })
        .await?;
    app.ssh_ready.store(false, Ordering::Release);
    if let Some(mut task) = ssh_task
        && tokio::time::timeout(
            Duration::from_secs(config.ssh_channel_timeout_secs),
            &mut task,
        )
        .await
        .is_err()
    {
        task.abort();
    }
    Ok(())
}

pub fn build_store(c: &Config) -> anyhow::Result<Arc<dyn ObjectStore>> {
    // `from_env` selects object_store's expiration-aware web-identity,
    // container, or EC2 metadata provider when no static access key is set.
    // The resulting provider remains attached to this store, so every S3
    // operation (lease renewal, restore, replication, and final shutdown
    // sync/relinquish) asks the same cache for a currently valid credential.
    // The cache refreshes temporary credentials shortly before expiration.
    let mut b = AmazonS3Builder::from_env()
        .with_bucket_name(
            c.s3_bucket
                .as_deref()
                .context("S3 bucket is not configured")?,
        )
        .with_region(&c.s3_region)
        .with_allow_http(c.s3_allow_http)
        .with_virtual_hosted_style_request(false);
    if let Some(e) = &c.s3_endpoint {
        b = b.with_endpoint(e)
    }
    Ok(Arc::new(b.build()?))
}

pub(super) fn ensure_local_database_compatible(config: &Config) -> anyhow::Result<()> {
    match Database::inspect_storage_mode(&config.db_path())? {
        Some(StorageMode::Local) | None if !config.db_path().exists() => Ok(()),
        Some(StorageMode::S3) => anyhow::bail!(
            "the existing database is an S3 working copy; configure COG_S3_BUCKET or use a different data directory"
        ),
        Some(StorageMode::Local) => Ok(()),
        None => anyhow::bail!(
            "the existing database predates local storage mode and is treated as S3-backed; configure COG_S3_BUCKET or migrate it explicitly"
        ),
    }
}

pub(super) fn ensure_s3_database_compatible(config: &Config) -> anyhow::Result<()> {
    if Database::inspect_storage_mode(&config.db_path())? == Some(StorageMode::Local) {
        anyhow::bail!(
            "the existing database is local-only and cannot be started with S3; migrate it explicitly or use a different data directory"
        );
    }
    Ok(())
}

pub async fn persist(a: &App) -> anyhow::Result<()> {
    a.lease.assert_live()?;
    let durable_txid = match a.replicator.sync().await {
        Ok(txid) => txid,
        Err(error) => {
            // A committed SQLite mutation that cannot be proven in S3 makes
            // continued ownership unsafe. Stopping renewal drives the server's
            // terminal self-fence path; this process must not acknowledge or
            // perform subsequent mutations from an unreplicated state.
            a.lease.stop_renewal();
            return Err(error);
        }
    };
    anyhow::ensure!(durable_txid > 0, "mutation has no durable LTX position");
    a.lease.assert_live()?;
    tracing::debug!(durable_txid, "database mutation is durable");
    Ok(())
}
