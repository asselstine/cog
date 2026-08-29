//! SSH key primitives shared by MCP registration and the SSH transport.
//!
//! COG owns only the server host key. Agent private keys remain local; MCP
//! registers their public keys and renews their server-side authorization lease.

use crate::{crypto::SecretBox, db::Database};
use ssh_key::{Algorithm, LineEnding, PrivateKey, PublicKey};

pub const MAX_PUBLIC_KEY_BYTES: usize = 1024;

pub struct KeySet {
    pub host: PrivateKey,
}

impl KeySet {
    pub fn load_or_create(db: &Database, secrets: &SecretBox) -> anyhow::Result<Self> {
        Ok(Self {
            host: load_or_create_key(db, secrets, "host")?,
        })
    }
}

fn load_or_create_key(
    db: &Database,
    secrets: &SecretBox,
    purpose: &str,
) -> anyhow::Result<PrivateKey> {
    let record = match db.active_ssh_key(purpose)? {
        Some(record) => record,
        None => {
            let generated = generate_key()?;
            let public = generated.public_key().to_openssh()?;
            let encrypted = secrets.seal(&encode_private(&generated)?)?;
            db.install_initial_ssh_key(purpose, &public, &encrypted)?
        }
    };
    anyhow::ensure!(
        record.algorithm == "ssh-ed25519",
        "unsupported durable SSH key algorithm"
    );
    let private = decode_private(&secrets.open(&record.private_ciphertext)?).map_err(|_| {
        anyhow::anyhow!(
            "active {purpose} SSH key cannot be decrypted; restore the matching COG master key"
        )
    })?;
    anyhow::ensure!(
        private.public_key().to_openssh()? == record.public_key,
        "active {purpose} SSH key does not match its public key"
    );
    Ok(private)
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Service {
    UploadPack,
    ReceivePack,
}

impl Service {
    pub fn permission(self) -> &'static str {
        match self {
            Self::UploadPack => "read",
            Self::ReceivePack => "write",
        }
    }
}

/// Parse exactly the command emitted by stock Git. No shell parser is used.
pub fn parse_command(command: &str) -> anyhow::Result<(Service, String)> {
    anyhow::ensure!(!command.contains(['\r', '\n', '\0']), "invalid SSH command");
    let (service, argument) = command
        .split_once(' ')
        .ok_or_else(|| anyhow::anyhow!("unsupported SSH command"))?;
    let service = match service {
        "git-upload-pack" => Service::UploadPack,
        "git-receive-pack" => Service::ReceivePack,
        _ => anyhow::bail!("unsupported SSH command"),
    };
    anyhow::ensure!(
        argument.starts_with('\'') && argument.ends_with('\'') && argument.len() > 2,
        "repository must be one single-quoted opaque ID"
    );
    let repository = argument[1..argument.len() - 1]
        .strip_prefix('/')
        .unwrap_or(&argument[1..argument.len() - 1]);
    anyhow::ensure!(
        !repository.contains('\'') && crate::git::valid_repository_id(repository),
        "invalid repository ID"
    );
    Ok((service, repository.to_owned()))
}

pub fn parse_git_protocol(value: &str) -> anyhow::Result<Option<&str>> {
    match value {
        "" => Ok(None),
        "version=0" | "version=1" | "version=2" => Ok(Some(value)),
        _ => anyhow::bail!("unsupported GIT_PROTOCOL value"),
    }
}

pub fn parse_public_key(input: &str) -> anyhow::Result<PublicKey> {
    anyhow::ensure!(
        input.len() <= MAX_PUBLIC_KEY_BYTES,
        "public key is too large"
    );
    anyhow::ensure!(input == input.trim(), "public key contains trailing data");
    anyhow::ensure!(
        input.split_ascii_whitespace().count() == 2,
        "public key comments are not accepted"
    );
    let key = PublicKey::from_openssh(input)
        .map_err(|_| anyhow::anyhow!("invalid OpenSSH public key"))?;
    anyhow::ensure!(
        key.algorithm() == Algorithm::Ed25519,
        "only Ed25519 public keys are supported"
    );
    anyhow::ensure!(
        key.to_openssh()? == input,
        "public key must use canonical OpenSSH encoding"
    );
    Ok(key)
}

pub fn fingerprint(key: &PublicKey) -> String {
    key.fingerprint(ssh_key::HashAlg::Sha256).to_string()
}

pub fn generate_key() -> anyhow::Result<PrivateKey> {
    Ok(PrivateKey::random(
        &mut rand::rngs::OsRng,
        Algorithm::Ed25519,
    )?)
}

pub fn encode_private(key: &PrivateKey) -> anyhow::Result<Vec<u8>> {
    Ok(key.to_openssh(LineEnding::LF)?.as_bytes().to_vec())
}

pub fn decode_private(bytes: &[u8]) -> anyhow::Result<PrivateKey> {
    Ok(PrivateKey::from_openssh(bytes)?)
}
