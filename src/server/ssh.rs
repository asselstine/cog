use super::*;

#[derive(Clone)]
pub struct SshServerFactory {
    pub app: App,
}

pub struct SshConnection {
    app: App,
    binding: Option<crate::db::AgentSshBinding>,
    protocols: HashMap<ChannelId, String>,
    inputs: HashMap<ChannelId, tokio::sync::mpsc::Sender<anyhow::Result<bytes::Bytes>>>,
    opened_channel: bool,
    executed_channel: Option<ChannelId>,
    _connection_permit: Option<tokio::sync::OwnedSemaphorePermit>,
}

impl russh::server::Server for SshServerFactory {
    type Handler = SshConnection;

    fn new_client(&mut self, _peer_addr: Option<SocketAddr>) -> Self::Handler {
        self.app
            .metrics
            .ssh_handshakes
            .fetch_add(1, Ordering::Relaxed);
        let permit = self.app.ssh_connections.clone().try_acquire_owned().ok();
        if permit.is_none() {
            self.app
                .metrics
                .ssh_limit_rejections
                .fetch_add(1, Ordering::Relaxed);
        }
        SshConnection {
            app: self.app.clone(),
            binding: None,
            protocols: HashMap::new(),
            inputs: HashMap::new(),
            opened_channel: false,
            executed_channel: None,
            _connection_permit: permit,
        }
    }

    fn handle_session_error(&mut self, error: <Self::Handler as russh::server::Handler>::Error) {
        tracing::debug!(error = %safe_error(error.as_ref()), "SSH session ended with an error");
    }
}

impl Drop for SshConnection {
    fn drop(&mut self) {
        if self.binding.is_some() {
            self.app
                .metrics
                .ssh_active_sessions
                .fetch_sub(1, Ordering::Relaxed);
        }
    }
}

impl russh::server::Handler for SshConnection {
    type Error = anyhow::Error;

    async fn auth_publickey(
        &mut self,
        user: &str,
        key: &russh::keys::PublicKey,
    ) -> Result<russh::server::Auth, Self::Error> {
        let result = (|| -> anyhow::Result<crate::db::AgentSshBinding> {
            anyhow::ensure!(user == "git", "SSH username must be git");
            anyhow::ensure!(
                self._connection_permit.is_some(),
                "SSH connection limit exceeded"
            );
            self.app.lease.assert_live()?;
            let encoded = key.to_openssh()?;
            let public_key = crate::git::ssh::parse_public_key(&encoded)?;
            let canonical = public_key.to_openssh()?;
            self.app
                .db
                .active_agent_ssh_key(&canonical, chrono::Utc::now().timestamp())?
                .ok_or_else(|| anyhow::anyhow!("SSH key is not registered or its lease expired"))
        })();
        match result {
            Ok(binding) => {
                self.binding = Some(binding.clone());
                self.app
                    .metrics
                    .ssh_auth_success
                    .fetch_add(1, Ordering::Relaxed);
                self.app
                    .metrics
                    .ssh_active_sessions
                    .fetch_add(1, Ordering::Relaxed);
                let _ = self.app.db.record_audit(
                    Some(&binding.user_id),
                    "git.ssh_authentication",
                    Some(&binding.agent_id),
                    "success",
                    &json!({
                        "identity_id": binding.identity_id,
                        "agent_id": binding.agent_id,
                        "client_id": binding.client_id,
                        "fingerprint": binding.fingerprint,
                        "lease_expires_at": binding.lease_expires_at
                    }),
                );
                Ok(russh::server::Auth::Accept)
            }
            Err(_) => {
                self.app
                    .metrics
                    .ssh_auth_denied
                    .fetch_add(1, Ordering::Relaxed);
                Ok(russh::server::Auth::reject())
            }
        }
    }

    async fn channel_open_session(
        &mut self,
        _channel: Channel<SshMsg>,
        _session: &mut SshSession,
    ) -> Result<bool, Self::Error> {
        if self.binding.is_none() || self.opened_channel {
            self.app
                .metrics
                .ssh_limit_rejections
                .fetch_add(1, Ordering::Relaxed);
            return Ok(false);
        }
        self.opened_channel = true;
        Ok(true)
    }

    async fn env_request(
        &mut self,
        channel: ChannelId,
        variable_name: &str,
        variable_value: &str,
        session: &mut SshSession,
    ) -> Result<(), Self::Error> {
        if variable_name == "GIT_PROTOCOL"
            && crate::git::ssh::parse_git_protocol(variable_value).is_ok()
            && !self.protocols.contains_key(&channel)
        {
            self.protocols.insert(channel, variable_value.to_owned());
            let _ = session.channel_success(channel);
        } else {
            let _ = session.channel_failure(channel);
        }
        Ok(())
    }

    async fn exec_request(
        &mut self,
        channel: ChannelId,
        command: &[u8],
        session: &mut SshSession,
    ) -> Result<(), Self::Error> {
        if self.executed_channel.is_some() {
            let _ = session.channel_failure(channel);
            return Ok(());
        }
        let result = std::str::from_utf8(command)
            .map_err(anyhow::Error::from)
            .and_then(crate::git::ssh::parse_command);
        let Ok((service, repository_id)) = result else {
            let _ = session.channel_failure(channel);
            return Ok(());
        };
        let Some(binding) = self.binding.clone() else {
            let _ = session.channel_failure(channel);
            return Ok(());
        };
        let (sender, receiver) = tokio::sync::mpsc::channel(8);
        self.inputs.insert(channel, sender);
        self.executed_channel = Some(channel);
        let _ = session.channel_success(channel);
        let app = self.app.clone();
        let protocol = self.protocols.get(&channel).cloned();
        let handle = session.handle();
        tokio::spawn(async move {
            let result = tokio::time::timeout(
                Duration::from_secs(app.config.git_timeout_secs),
                run_ssh_git(
                    app.clone(),
                    binding.clone(),
                    service,
                    repository_id.clone(),
                    protocol,
                    SshGitIo {
                        input: receiver,
                        output: handle.clone(),
                        channel,
                    },
                ),
            )
            .await;
            let status = if matches!(result, Ok(Ok(()))) { 0 } else { 1 };
            if result.is_err() {
                app.metrics.ssh_timeouts.fetch_add(1, Ordering::Relaxed);
            }
            if status != 0 {
                app.metrics
                    .ssh_upstream_failures
                    .fetch_add(1, Ordering::Relaxed);
                let error_kind = match &result {
                    Ok(Err(error)) => safe_git_error(error.as_ref()),
                    Err(_) => "Git transport timed out",
                    Ok(Ok(())) => "Git transport operation failed",
                };
                tracing::warn!(
                    repository_id = %repository_id,
                    service = ?service,
                    error = error_kind,
                    "SSH Git operation failed"
                );
                let _ = app.db.record_audit(
                    Some(&binding.user_id),
                    "git.ssh_operation",
                    Some(&repository_id),
                    "failure",
                    &json!({"identity_id":binding.identity_id,"agent_id":binding.agent_id,"client_id":binding.client_id,"fingerprint":binding.fingerprint,"transport":"ssh","error":error_kind}),
                );
                let message = match &result {
                    Ok(Err(error)) => {
                        format!(
                            "COG Git operation failed: {}\n",
                            safe_git_error(error.as_ref())
                        )
                    }
                    Err(_) => "COG Git operation timed out\n".to_owned(),
                    Ok(Ok(())) => String::new(),
                };
                let _ = handle.extended_data(channel, 1, message).await;
            }
            let _ = handle.exit_status_request(channel, status).await;
            let _ = handle.eof(channel).await;
            let _ = handle.close(channel).await;
        });
        Ok(())
    }

    async fn data(
        &mut self,
        channel: ChannelId,
        data: &[u8],
        _session: &mut SshSession,
    ) -> Result<(), Self::Error> {
        if let Some(sender) = self.inputs.get(&channel) {
            sender
                .send(Ok(bytes::Bytes::copy_from_slice(data)))
                .await
                .map_err(|_| anyhow::anyhow!("SSH Git input closed"))?;
        }
        Ok(())
    }

    async fn channel_eof(
        &mut self,
        channel: ChannelId,
        _session: &mut SshSession,
    ) -> Result<(), Self::Error> {
        self.inputs.remove(&channel);
        Ok(())
    }

    async fn channel_close(
        &mut self,
        channel: ChannelId,
        _session: &mut SshSession,
    ) -> Result<(), Self::Error> {
        self.inputs.remove(&channel);
        Ok(())
    }

    async fn shell_request(
        &mut self,
        channel: ChannelId,
        session: &mut SshSession,
    ) -> Result<(), Self::Error> {
        let _ = session.channel_failure(channel);
        Ok(())
    }

    async fn subsystem_request(
        &mut self,
        channel: ChannelId,
        _name: &str,
        session: &mut SshSession,
    ) -> Result<(), Self::Error> {
        let _ = session.channel_failure(channel);
        Ok(())
    }

    async fn pty_request(
        &mut self,
        channel: ChannelId,
        _term: &str,
        _col_width: u32,
        _row_height: u32,
        _pix_width: u32,
        _pix_height: u32,
        _modes: &[(russh::Pty, u32)],
        session: &mut SshSession,
    ) -> Result<(), Self::Error> {
        let _ = session.channel_failure(channel);
        Ok(())
    }

    async fn agent_request(
        &mut self,
        channel: ChannelId,
        session: &mut SshSession,
    ) -> Result<bool, Self::Error> {
        let _ = session.channel_failure(channel);
        Ok(false)
    }
}

pub(super) struct SshGitIo {
    input: tokio::sync::mpsc::Receiver<anyhow::Result<bytes::Bytes>>,
    output: russh::server::Handle,
    channel: ChannelId,
}

pub(super) async fn run_ssh_git(
    app: App,
    binding: crate::db::AgentSshBinding,
    service: crate::git::ssh::Service,
    repository_id: String,
    git_protocol: Option<String>,
    io: SshGitIo,
) -> anyhow::Result<()> {
    let SshGitIo {
        input,
        output,
        channel,
    } = io;
    let operation = match service {
        crate::git::ssh::Service::UploadPack => GitOperation::Read,
        crate::git::ssh::Service::ReceivePack => GitOperation::Write,
    };
    match operation {
        GitOperation::Read => app
            .metrics
            .ssh_read_operations
            .fetch_add(1, Ordering::Relaxed),
        GitOperation::Write => app
            .metrics
            .ssh_write_operations
            .fetch_add(1, Ordering::Relaxed),
    };
    let _global = app
        .git_streams
        .clone()
        .try_acquire_owned()
        .map_err(|_| anyhow::anyhow!("global Git stream limit exceeded"))?;
    let _client = app
        .git_client_streams
        .try_acquire(&binding.client_id, app.config.git_max_streams_per_client)
        .ok_or_else(|| anyhow::anyhow!("client Git stream limit exceeded"))?;
    app.lease.assert_live()?;
    let repository = app
        .db
        .git_repository(&repository_id)?
        .filter(|repository| repository.user_id == binding.user_id)
        .ok_or_else(|| anyhow::anyhow!("repository is no longer available"))?;
    let live_key = app
        .db
        .agent_ssh_key(&binding.user_id, &binding.agent_id)?
        .filter(|key| {
            key.public_key == binding.public_key
                && key.revoked_at.is_none()
                && key.lease_expires_at > chrono::Utc::now().timestamp()
        })
        .ok_or_else(|| anyhow::anyhow!("SSH key lease has expired or been revoked"))?;
    let grant = app
        .db
        .git_grant_permission(&binding.user_id, &binding.client_id, &repository_id)?
        .ok_or_else(|| anyhow::anyhow!("repository grant has been revoked"))?;
    anyhow::ensure!(
        crate::git::grants::permits(&grant, operation),
        "repository grant does not permit the operation"
    );
    let integration = app
        .db
        .integration(&repository.integration_id, &binding.user_id)?
        .filter(|integration| integration.enabled && integration.identity_id == binding.identity_id)
        .ok_or_else(|| anyhow::anyhow!("integration is disabled or revoked"))?;
    let provider = git_provider(&app, &integration).await?;
    let resolved = ResolvedRepository {
        provider_repository_id: repository.provider_repository_id.clone(),
        display_name: repository.display_name.clone(),
        upstream_url: url::Url::parse(&repository.upstream_url)?,
        metadata: repository.metadata.clone(),
    };
    let authorization = provider.authorize_upstream(&resolved, operation).await?;
    let upstream = provider.upstream_url(&resolved)?;
    let service_name = match service {
        crate::git::ssh::Service::UploadPack => "git-upload-pack",
        crate::git::ssh::Service::ReceivePack => "git-receive-pack",
    };
    let client = reqwest::Client::builder()
        .redirect(reqwest::redirect::Policy::none())
        .timeout(Duration::from_secs(app.config.git_timeout_secs))
        .build()?;
    let mut discovery_url = upstream.clone();
    discovery_url.set_path(&format!(
        "{}.git/info/refs",
        upstream.path().trim_end_matches(".git")
    ));
    discovery_url.set_query(Some(&format!("service={service_name}")));
    let mut discovery = client.get(discovery_url);
    if let Some(protocol) = &git_protocol {
        discovery = discovery.header("Git-Protocol", protocol);
    }
    discovery = crate::git::service::apply_authorization(discovery, &authorization);
    let response = discovery.send().await?;
    anyhow::ensure!(response.status().is_success(), "upstream discovery failed");
    let advertisement = response.bytes().await?;
    let advertisement = crate::git::service::strip_service_preamble(&advertisement, service_name)?;
    output
        .data(channel, bytes::Bytes::copy_from_slice(advertisement))
        .await
        .map_err(|_| anyhow::anyhow!("SSH client disconnected"))?;

    // Revalidate the key lease and live grants immediately before the RPC.
    app.lease.assert_live()?;
    anyhow::ensure!(
        app.db
            .agent_ssh_key(&binding.user_id, &binding.agent_id)?
            .is_some_and(|key| key.public_key == live_key.public_key
                && key.revoked_at.is_none()
                && key.lease_expires_at > chrono::Utc::now().timestamp()),
        "SSH key lease has expired or been revoked"
    );
    anyhow::ensure!(
        app.db
            .git_grant_permission(&binding.user_id, &binding.client_id, &repository_id)?
            .is_some_and(|permission| crate::git::grants::permits(&permission, operation)),
        "repository grant has been revoked"
    );
    anyhow::ensure!(
        app.db
            .integration(&repository.integration_id, &binding.user_id)?
            .is_some_and(
                |integration| integration.enabled && integration.identity_id == binding.identity_id
            ),
        "integration is disabled"
    );
    let maximum = app.config.git_max_request_bytes;
    let idle = Duration::from_secs(app.config.git_idle_timeout_secs);
    let upload_pack_rounds = matches!(service, crate::git::ssh::Service::UploadPack);
    let receive_pack = matches!(service, crate::git::ssh::Service::ReceivePack);
    let input = Arc::new(tokio::sync::Mutex::new(input));
    let mut rpc_url = upstream;
    rpc_url.set_path(&format!(
        "{}.git/{service_name}",
        rpc_url.path().trim_end_matches(".git")
    ));
    let mut seen = 0_u64;
    loop {
        let round_input = input.clone();
        let request_metrics = app.metrics.clone();
        let request_stream = async_stream::stream! {
            let mut round_seen = 0_u64;
            let mut tail = Vec::with_capacity(9);
            let mut pack_boundary = crate::git::pack::ReceivePackBoundary::default();
            loop {
                let next = {
                    let mut input = round_input.lock().await;
                    tokio::time::timeout(idle, input.recv()).await
                };
                match next {
                    Err(_) => {
                        yield Err::<bytes::Bytes, std::io::Error>(std::io::Error::new(std::io::ErrorKind::TimedOut, "SSH Git request idle timeout"));
                        break;
                    }
                    Ok(None) => break,
                    Ok(Some(Err(error))) => {
                        yield Err(std::io::Error::other(safe_error(error.as_ref())));
                        break;
                    }
                    Ok(Some(Ok(bytes))) => {
                        round_seen = round_seen.saturating_add(bytes.len() as u64);
                        if round_seen > maximum {
                            yield Err(std::io::Error::new(std::io::ErrorKind::FileTooLarge, "SSH Git request byte limit exceeded"));
                            break;
                        }
                        request_metrics.ssh_request_bytes.fetch_add(bytes.len() as u64, Ordering::Relaxed);
                        if upload_pack_rounds {
                            tail.extend_from_slice(&bytes);
                            if tail.len() > 9 {
                                tail.drain(..tail.len() - 9);
                            }
                        }
                        let pack_complete = if receive_pack {
                            match pack_boundary.push(&bytes) {
                                Ok(complete) => complete,
                                Err(error) => {
                                    yield Err(std::io::Error::new(std::io::ErrorKind::InvalidData, safe_error(error.as_ref())));
                                    break;
                                }
                            }
                        } else {
                            false
                        };
                        yield Ok(bytes);
                        if (upload_pack_rounds && (tail.ends_with(b"0000") || tail.ends_with(b"0009done\n"))) || pack_complete {
                            break;
                        }
                    }
                }
            }
        };
        let mut request = client
            .post(rpc_url.clone())
            .header(
                header::CONTENT_TYPE,
                format!("application/x-{service_name}-request"),
            )
            .header(
                header::ACCEPT,
                format!("application/x-{service_name}-result"),
            )
            .body(reqwest::Body::wrap_stream(request_stream));
        if let Some(protocol) = &git_protocol {
            request = request.header("Git-Protocol", protocol);
        }
        request = crate::git::service::apply_authorization(request, &authorization);
        let response = request.send().await?;
        anyhow::ensure!(response.status().is_success(), "upstream Git RPC failed");
        let mut body = response.bytes_stream();
        let mut marker = Vec::new();
        let mut saw_packfile = false;
        while let Some(chunk) = tokio::time::timeout(idle, body.next())
            .await
            .map_err(|_| anyhow::anyhow!("SSH Git response idle timeout"))?
        {
            let chunk = chunk?;
            seen = seen.saturating_add(chunk.len() as u64);
            anyhow::ensure!(
                seen <= app.config.git_max_response_bytes,
                "SSH Git response byte limit exceeded"
            );
            marker.extend_from_slice(&chunk);
            saw_packfile |= marker.windows(9).any(|window| window == b"packfile\n")
                || marker.windows(4).any(|window| window == b"PACK");
            if marker.len() > 64 {
                marker.drain(..marker.len() - 64);
            }
            app.metrics
                .ssh_response_bytes
                .fetch_add(chunk.len() as u64, Ordering::Relaxed);
            output
                .data(channel, chunk)
                .await
                .map_err(|_| anyhow::anyhow!("SSH client disconnected"))?;
        }
        let final_round = receive_pack || saw_packfile;
        if final_round {
            break;
        }
    }
    app.db.record_audit(
        Some(&binding.user_id),
        match operation {
            GitOperation::Read => "git.ssh_read",
            GitOperation::Write => "git.ssh_write",
        },
        Some(&repository_id),
        "success",
        &json!({"identity_id":binding.identity_id,"agent_id":binding.agent_id,"client_id":binding.client_id,"integration_id":repository.integration_id,"fingerprint":binding.fingerprint,"transport":"ssh","protocol":git_protocol.as_deref().unwrap_or("version=0")}),
    )?;
    Ok(())
}
