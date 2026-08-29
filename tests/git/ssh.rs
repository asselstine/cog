use cog::git::ssh::*;
use cog::{crypto::SecretBox, db::Database};
use ssh_key::PublicKey;

#[cfg(unix)]
#[derive(Clone)]
struct InteropServer {
    ca: PublicKey,
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

    async fn auth_openssh_certificate(
        &mut self,
        user: &str,
        certificate: &russh::keys::Certificate,
    ) -> Result<russh::server::Auth, Self::Error> {
        let encoded = certificate.to_openssh()?;
        let subject =
            russh::keys::PublicKey::new(certificate.public_key().clone(), "").to_openssh()?;
        let subject = parse_public_key(&subject)?;
        Ok(
            if user == "git"
                && verify_certificate(&encoded, &self.ca, &subject, chrono::Utc::now().timestamp())
                    .is_ok()
            {
                russh::server::Auth::Accept
            } else {
                russh::server::Auth::reject()
            },
        )
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
fn ed25519_certificate_round_trip() {
    let ca = generate_key().unwrap();
    let subject = generate_key().unwrap();
    let now = chrono::Utc::now().timestamp();
    let binding = Binding {
        version: 1,
        issuance_id: uuid::Uuid::new_v4().to_string(),
        user_id: "u".into(),
        identity_id: "i".into(),
        agent_id: "a".into(),
        client_id: "c".into(),
        integration_id: "n".into(),
        repository_id: "550e8400-e29b-41d4-a716-446655440000".into(),
        permission: "read".into(),
        fingerprint: fingerprint(subject.public_key()),
        issued_at: now,
        expires_at: now + 900,
    };
    let encoded = sign(
        &ca,
        subject.public_key(),
        &binding,
        stable_serial(&binding.issuance_id),
    )
    .unwrap();
    let cert = ssh_key::Certificate::from_openssh(&encoded).unwrap();
    assert_eq!(decode_binding(cert.key_id()).unwrap(), binding);
    assert_eq!(cert.valid_principals(), &[PRINCIPAL]);
    assert_eq!(
        verify_certificate(&encoded, ca.public_key(), subject.public_key(), now).unwrap(),
        binding
    );
    assert!(
        verify_certificate(
            &encoded,
            generate_key().unwrap().public_key(),
            subject.public_key(),
            now
        )
        .is_err()
    );
    assert!(
        verify_certificate(
            &encoded,
            ca.public_key(),
            generate_key().unwrap().public_key(),
            now
        )
        .is_err()
    );
    assert!(
        verify_certificate(&encoded, ca.public_key(), subject.public_key(), now + 901).is_err()
    );
    assert_eq!(
        verify_certificate_for_renewal(&encoded, ca.public_key(), subject.public_key()).unwrap(),
        binding
    );
    assert!(
        verify_certificate_for_renewal(
            &encoded,
            ca.public_key(),
            generate_key().unwrap().public_key()
        )
        .is_err()
    );
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
        let _ = decode_binding(&input);
    }
}

#[test]
fn durable_keys_survive_restart_and_wrong_master_key_fails_closed() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("cog.sqlite");
    let master_key = cog::crypto::random_token(32);
    let secrets = SecretBox::new(master_key.as_bytes());
    let first = KeySet::load_or_create(&Database::open(&path).unwrap(), &secrets).unwrap();
    let first_host = first.host.public_key().to_openssh().unwrap();
    let first_ca = first.user_ca.public_key().to_openssh().unwrap();
    drop(first);
    let second = KeySet::load_or_create(&Database::open(&path).unwrap(), &secrets).unwrap();
    assert_eq!(second.host.public_key().to_openssh().unwrap(), first_host);
    assert_eq!(second.user_ca.public_key().to_openssh().unwrap(), first_ca);
    let wrong_master_key = cog::crypto::random_token(32);
    let wrong = SecretBox::new(wrong_master_key.as_bytes());
    assert!(KeySet::load_or_create(&Database::open(&path).unwrap(), &wrong).is_err());
}

#[test]
fn ca_rotation_overlaps_existing_certificates_and_retires_after_deadline() {
    let directory = tempfile::tempdir().unwrap();
    let database = Database::open(&directory.path().join("cog.sqlite")).unwrap();
    let master_key = cog::crypto::random_token(32);
    let secrets = SecretBox::new(master_key.as_bytes());
    let original = KeySet::load_or_create(&database, &secrets).unwrap();
    let subject = generate_key().unwrap();
    let now = chrono::Utc::now().timestamp();
    let binding = Binding {
        version: 1,
        issuance_id: uuid::Uuid::new_v4().to_string(),
        user_id: "user".into(),
        identity_id: "identity".into(),
        agent_id: "agent".into(),
        client_id: "client".into(),
        integration_id: "integration".into(),
        repository_id: "550e8400-e29b-41d4-a716-446655440000".into(),
        permission: "read".into(),
        fingerprint: fingerprint(subject.public_key()),
        issued_at: now,
        expires_at: now + 300,
    };
    let certificate = sign(
        &original.user_ca,
        subject.public_key(),
        &binding,
        stable_serial(&binding.issuance_id),
    )
    .unwrap();
    let replacement = generate_key().unwrap();
    let prepared = database
        .prepare_ssh_key(
            "user_ca",
            &replacement.public_key().to_openssh().unwrap(),
            &secrets
                .seal(&encode_private(&replacement).unwrap())
                .unwrap(),
        )
        .unwrap();
    database
        .activate_ssh_key(&prepared.id, "user_ca", now + 301)
        .unwrap();
    assert_eq!(
        verify_certificate_with_durable_cas(&certificate, &database, subject.public_key(), now)
            .unwrap(),
        binding
    );
    let retiring = database
        .ssh_keys()
        .unwrap()
        .into_iter()
        .find(|key| key.purpose == "user_ca" && !key.active)
        .unwrap();
    assert!(database.retire_ssh_key(&retiring.id, now + 300).is_err());
    database.retire_ssh_key(&retiring.id, now + 301).unwrap();
    assert!(
        verify_certificate_with_durable_cas(&certificate, &database, subject.public_key(), now)
            .is_err()
    );
}

#[test]
fn certificate_clock_and_repository_boundaries_fail_closed() {
    let ca = generate_key().unwrap();
    let subject = generate_key().unwrap();
    let now = chrono::Utc::now().timestamp();
    let mut binding = Binding {
        version: 1,
        issuance_id: uuid::Uuid::new_v4().to_string(),
        user_id: "u".into(),
        identity_id: "i".into(),
        agent_id: "a".into(),
        client_id: "c".into(),
        integration_id: "n".into(),
        repository_id: "550e8400-e29b-41d4-a716-446655440000".into(),
        permission: "read".into(),
        fingerprint: fingerprint(subject.public_key()),
        issued_at: now + 60,
        expires_at: now + 120,
    };
    let future = sign(&ca, subject.public_key(), &binding, 1).unwrap();
    assert!(verify_certificate(&future, ca.public_key(), subject.public_key(), now).is_err());
    binding.issued_at = now;
    binding.expires_at = now + 60;
    binding.repository_id = "../repository".into();
    let invalid_repository = sign(&ca, subject.public_key(), &binding, 2).unwrap();
    assert!(
        verify_certificate(
            &invalid_repository,
            ca.public_key(),
            subject.public_key(),
            now
        )
        .is_err()
    );
}

#[cfg(unix)]
#[tokio::test]
async fn stock_openssh_authenticates_rust_signed_certificate_and_executes() {
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
    let ca = generate_key().unwrap();
    let subject = generate_key().unwrap();
    let host = generate_key().unwrap();
    let now = chrono::Utc::now().timestamp();
    let repository = "550e8400-e29b-41d4-a716-446655440000";
    let binding = Binding {
        version: 1,
        issuance_id: uuid::Uuid::new_v4().to_string(),
        user_id: "user".into(),
        identity_id: "identity".into(),
        agent_id: "agent".into(),
        client_id: "client".into(),
        integration_id: "integration".into(),
        repository_id: repository.into(),
        permission: "read".into(),
        fingerprint: fingerprint(subject.public_key()),
        issued_at: now,
        expires_at: now + 900,
    };
    let certificate = sign(
        &ca,
        subject.public_key(),
        &binding,
        stable_serial(&binding.issuance_id),
    )
    .unwrap();
    let private_path = directory.path().join("id_ed25519");
    let certificate_path = directory.path().join("id_ed25519-cert.pub");
    let known_hosts_path = directory.path().join("known_hosts");
    std::fs::write(&private_path, encode_private(&subject).unwrap()).unwrap();
    std::fs::set_permissions(&private_path, std::fs::Permissions::from_mode(0o600)).unwrap();
    std::fs::write(&certificate_path, format!("{certificate}\n")).unwrap();

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
    let ca_public = ca.public_key().clone();
    let task = tokio::spawn(async move {
        let mut server = InteropServer { ca: ca_public };
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
    task.abort();
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert_eq!(output.stdout, b"interop-ok\n");
}
