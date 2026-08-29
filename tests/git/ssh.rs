use cog::git::ssh::*;
use cog::{crypto::SecretBox, db::Database};

#[cfg(unix)]
#[derive(Clone)]
struct InteropServer {
    public_key: String,
}

#[cfg(unix)]
impl russh::server::Server for InteropServer {
    type Handler = Self;

    fn new_client(&mut self, _peer_addr: Option<std::net::SocketAddr>) -> Self::Handler {
        self.clone()
    }
}

#[cfg(unix)]
impl russh::server::Handler for InteropServer {
    type Error = anyhow::Error;

    async fn auth_publickey(
        &mut self,
        user: &str,
        key: &russh::keys::PublicKey,
    ) -> Result<russh::server::Auth, Self::Error> {
        Ok(if user == "git" && key.to_openssh()? == self.public_key {
            russh::server::Auth::Accept
        } else {
            russh::server::Auth::reject()
        })
    }

    async fn channel_open_session(
        &mut self,
        _channel: russh::Channel<russh::server::Msg>,
        _session: &mut russh::server::Session,
    ) -> Result<bool, Self::Error> {
        Ok(true)
    }

    async fn exec_request(
        &mut self,
        channel: russh::ChannelId,
        command: &[u8],
        session: &mut russh::server::Session,
    ) -> Result<(), Self::Error> {
        if parse_command(std::str::from_utf8(command)?).is_ok() {
            let _ = session.channel_success(channel);
            session.data(channel, bytes::Bytes::from_static(b"interop-ok\n"))?;
            session.exit_status_request(channel, 0)?;
        } else {
            let _ = session.channel_failure(channel);
            session.exit_status_request(channel, 1)?;
        }
        session.eof(channel)?;
        session.close(channel)?;
        Ok(())
    }
}

#[test]
fn command_parser_is_exact() {
    let id = "550e8400-e29b-41d4-a716-446655440000";
    assert_eq!(
        parse_command(&format!("git-upload-pack '{id}'")).unwrap(),
        (Service::UploadPack, id.into())
    );
    assert_eq!(
        parse_command(&format!("git-upload-pack '/{id}'")).unwrap(),
        (Service::UploadPack, id.into())
    );
    for bad in [
        "sh",
        "git-upload-pack x",
        "git-upload-pack '../x'",
        "git-upload-pack '550e8400-e29b-41d4-a716-446655440000' extra",
        "git receive-pack '550e8400-e29b-41d4-a716-446655440000'",
    ] {
        assert!(parse_command(bad).is_err(), "accepted {bad:?}");
    }
}

#[test]
fn public_keys_must_be_canonical_ed25519_without_comments() {
    let key = generate_key().unwrap().public_key().to_openssh().unwrap();
    assert!(parse_public_key(&key).is_ok());
    assert!(parse_public_key(&format!("{key} comment")).is_err());
    assert!(parse_public_key(&key.replace(' ', "  ")).is_err());
    assert!(parse_public_key(&format!("{key}\n")).is_err());
    assert!(parse_public_key(&"x".repeat(MAX_PUBLIC_KEY_BYTES + 1)).is_err());
}

proptest::proptest! {
    #[test]
    fn parsers_never_panic(input in ".{0,4096}") {
        let _ = parse_command(&input);
        let _ = parse_git_protocol(&input);
        let _ = parse_public_key(&input);
    }
}

#[test]
fn durable_host_key_survives_restart_and_wrong_master_key_fails_closed() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("cog.sqlite");
    let master_key = cog::crypto::random_token(32);
    let secrets = SecretBox::new(master_key.as_bytes());
    let first = KeySet::load_or_create(&Database::open(&path).unwrap(), &secrets).unwrap();
    let first_host = first.host.public_key().to_openssh().unwrap();
    drop(first);
    let second = KeySet::load_or_create(&Database::open(&path).unwrap(), &secrets).unwrap();
    assert_eq!(second.host.public_key().to_openssh().unwrap(), first_host);
    let wrong_master_key = cog::crypto::random_token(32);
    let wrong = SecretBox::new(wrong_master_key.as_bytes());
    assert!(KeySet::load_or_create(&Database::open(&path).unwrap(), &wrong).is_err());
}

#[cfg(unix)]
#[tokio::test]
async fn stock_openssh_authenticates_registered_raw_key_and_executes() {
    use russh::server::Server as _;
    use std::os::unix::fs::PermissionsExt;

    if std::process::Command::new("ssh")
        .arg("-V")
        .output()
        .is_err()
    {
        return;
    }
    let directory = tempfile::tempdir().unwrap();
    let subject = generate_key().unwrap();
    let host = generate_key().unwrap();
    let repository = "550e8400-e29b-41d4-a716-446655440000";
    let private_path = directory.path().join("id_ed25519");
    let known_hosts_path = directory.path().join("known_hosts");
    std::fs::write(&private_path, encode_private(&subject).unwrap()).unwrap();
    std::fs::set_permissions(&private_path, std::fs::Permissions::from_mode(0o600)).unwrap();

    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();
    std::fs::write(
        &known_hosts_path,
        format!(
            "[127.0.0.1]:{port} {}\n",
            host.public_key().to_openssh().unwrap()
        ),
    )
    .unwrap();
    let host_key = russh::keys::PrivateKey::from_openssh(encode_private(&host).unwrap()).unwrap();
    let config = std::sync::Arc::new(russh::server::Config {
        methods: russh::MethodSet::from(&[russh::MethodKind::PublicKey][..]),
        keys: vec![host_key],
        ..Default::default()
    });
    let public_key = subject.public_key().to_openssh().unwrap();
    let task = tokio::spawn(async move {
        let mut server = InteropServer { public_key };
        server.run_on_socket(config, &listener).await
    });
    let output = tokio::process::Command::new("ssh")
        .args([
            "-F",
            "/dev/null",
            "-o",
            "BatchMode=yes",
            "-o",
            "IdentitiesOnly=yes",
            "-o",
            "StrictHostKeyChecking=yes",
            "-o",
            &format!("UserKnownHostsFile={}", known_hosts_path.display()),
            "-i",
            private_path.to_str().unwrap(),
            "-p",
            &port.to_string(),
            "git@127.0.0.1",
            &format!("git-upload-pack '{repository}'"),
        ])
        .output()
        .await
        .unwrap();
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert_eq!(output.stdout, b"interop-ok\n");
    task.abort();
}
