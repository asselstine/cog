use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use cog::git::sealed::{SealedCredentialEnvelope, SealedCredentialRequest};
use serde::{Deserialize, Serialize};
use std::{
    collections::HashMap,
    io::{self, BufRead, Read},
    path::{Path, PathBuf},
};

#[derive(Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct PendingChallenge {
    private_key: String,
    repository_id: String,
    origin: String,
    request_nonce: String,
    expires_at: i64,
}

fn main() {
    if let Err(error) = run() {
        eprintln!("git-credential-cog: {error}");
        std::process::exit(1)
    }
}
fn run() -> anyhow::Result<()> {
    let operation = std::env::args()
        .nth(1)
        .ok_or_else(|| anyhow::anyhow!("expected get, store, erase, prepare, or import"))?;
    if operation == "prepare" {
        let remote = std::env::args()
            .nth(2)
            .ok_or_else(|| anyhow::anyhow!("prepare requires a COG remote URL"))?;
        return prepare(&remote);
    }
    if operation == "import" {
        return import();
    }
    anyhow::ensure!(
        matches!(operation.as_str(), "get" | "store" | "erase"),
        "unsupported operation"
    );
    let fields = io::stdin()
        .lock()
        .lines()
        .map_while(Result::ok)
        .take_while(|line| !line.is_empty())
        .filter_map(|line| {
            line.split_once('=')
                .map(|(k, v)| (k.to_owned(), v.to_owned()))
        })
        .collect::<HashMap<_, _>>();
    let configured = url::Url::parse(
        &std::env::var("COG_GIT_ORIGIN")
            .map_err(|_| anyhow::anyhow!("COG_GIT_ORIGIN is required"))?,
    )?;
    let protocol = fields
        .get("protocol")
        .map(String::as_str)
        .unwrap_or("https");
    let host = fields
        .get("host")
        .ok_or_else(|| anyhow::anyhow!("host is required"))?;
    let request_origin = format!("{protocol}://{host}");
    anyhow::ensure!(
        configured.origin().ascii_serialization() == request_origin,
        "credential request is for an unrelated origin"
    );
    let path = fields
        .get("path")
        .ok_or_else(|| anyhow::anyhow!("Git credential.useHttpPath=true is required"))?;
    anyhow::ensure!(
        path.starts_with("git/") && path.ends_with(".git") && !path.contains(".."),
        "credential request has an invalid repository path"
    );
    let file = credential_file()?;
    let mut entries = read_entries(&file);
    let key = format!("{request_origin}/{path}");
    match operation.as_str() {
        "get" => {
            if let Some(password) = entries.get(&key) {
                println!("username=cog\npassword={password}")
            }
        }
        "store" => {
            anyhow::ensure!(
                fields.get("username").map(String::as_str) == Some("cog"),
                "username must be cog"
            );
            let password = fields
                .get("password")
                .ok_or_else(|| anyhow::anyhow!("password is required"))?;
            entries.insert(key, password.clone());
            write_entries(&file, &entries)?
        }
        "erase" => {
            entries.remove(&key);
            write_entries(&file, &entries)?
        }
        _ => unreachable!(),
    };
    Ok(())
}

fn prepare(remote: &str) -> anyhow::Result<()> {
    let (origin, repository_id) = parse_remote(remote)?;
    let (private, recipient_public_key) = cog::git::sealed::new_recipient();
    let request_nonce = cog::crypto::random_token(32);
    let challenge = PendingChallenge {
        private_key: URL_SAFE_NO_PAD.encode(private.to_bytes()),
        repository_id: repository_id.clone(),
        origin,
        request_nonce: request_nonce.clone(),
        expires_at: chrono::Utc::now().timestamp() + 60,
    };
    let path = challenge_file(&request_nonce)?;
    write_private_json(&path, &challenge)?;
    println!(
        "{}",
        serde_json::to_string(&SealedCredentialRequest {
            repository_id,
            recipient_public_key,
            request_nonce,
        })?
    );
    Ok(())
}

fn import() -> anyhow::Result<()> {
    let mut input = String::new();
    io::stdin().read_to_string(&mut input)?;
    let envelope: SealedCredentialEnvelope = serde_json::from_str(&input)?;
    let challenge_path = challenge_file(&envelope.request_nonce)?;
    let challenge: PendingChallenge = serde_json::from_slice(&std::fs::read(&challenge_path)?)?;
    anyhow::ensure!(
        challenge.expires_at > chrono::Utc::now().timestamp(),
        "sealed credential request expired"
    );
    anyhow::ensure!(
        envelope.repository_id == challenge.repository_id
            && envelope.origin == challenge.origin
            && envelope.request_nonce == challenge.request_nonce,
        "sealed credential does not match its request"
    );
    let private = x25519_dalek::StaticSecret::from(cog::git::sealed::decode_array::<32>(
        &challenge.private_key,
        "recipient private key",
    )?);
    let payload = cog::git::sealed::open(&envelope, &private)?;
    anyhow::ensure!(
        payload.username == "cog"
            && payload.repository_id == challenge.repository_id
            && payload.origin == challenge.origin
            && payload.expires_at > chrono::Utc::now().timestamp(),
        "sealed credential payload does not match its request"
    );
    let key = format!(
        "{}/git/{}.git",
        challenge.origin.trim_end_matches('/'),
        challenge.repository_id
    );
    let file = credential_file()?;
    let mut entries = read_entries(&file);
    entries.insert(key, payload.password);
    write_entries(&file, &entries)?;
    std::fs::remove_file(challenge_path)?;
    Ok(())
}

fn parse_remote(remote: &str) -> anyhow::Result<(String, String)> {
    let url = url::Url::parse(remote)?;
    anyhow::ensure!(
        url.username().is_empty() && url.password().is_none(),
        "remote URL must not contain credentials"
    );
    anyhow::ensure!(
        matches!(url.scheme(), "https" | "http"),
        "unsupported remote URL scheme"
    );
    let path = url.path().trim_start_matches('/');
    let repository_id = path
        .strip_prefix("git/")
        .and_then(|value| value.strip_suffix(".git"))
        .ok_or_else(|| anyhow::anyhow!("remote URL has an invalid repository path"))?;
    uuid::Uuid::parse_str(repository_id)
        .map_err(|_| anyhow::anyhow!("remote URL has a non-opaque repository path"))?;
    Ok((url.origin().ascii_serialization(), repository_id.to_owned()))
}

fn credential_file() -> anyhow::Result<PathBuf> {
    Ok(runtime_directory()?.join("git-credentials.json"))
}

fn challenge_file(request_nonce: &str) -> anyhow::Result<PathBuf> {
    anyhow::ensure!(
        !request_nonce.is_empty()
            && request_nonce
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_')),
        "invalid request nonce"
    );
    let directory = runtime_directory()?.join("git-challenges");
    std::fs::create_dir_all(&directory)?;
    set_private_directory(&directory)?;
    Ok(directory.join(format!("{request_nonce}.json")))
}

fn runtime_directory() -> anyhow::Result<PathBuf> {
    let base = std::env::var_os("XDG_RUNTIME_DIR")
        .map(PathBuf::from)
        .unwrap_or_else(|| {
            std::env::temp_dir().join(format!("cog-{}", unsafe { libc::geteuid() }))
        });
    std::fs::create_dir_all(&base)?;
    set_private_directory(&base)?;
    Ok(base)
}

fn set_private_directory(path: &Path) -> anyhow::Result<()> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o700))?
    }
    Ok(())
}
fn read_entries(path: &Path) -> HashMap<String, String> {
    std::fs::read(path)
        .ok()
        .and_then(|v| serde_json::from_slice(&v).ok())
        .unwrap_or_default()
}
fn write_entries(path: &Path, entries: &HashMap<String, String>) -> anyhow::Result<()> {
    write_private_json(path, entries)
}

fn write_private_json(path: &Path, value: &impl Serialize) -> anyhow::Result<()> {
    use std::io::Write;
    let temporary = path.with_extension("tmp");
    let mut options = std::fs::OpenOptions::new();
    options.create(true).truncate(true).write(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    let mut file = options.open(&temporary)?;
    file.write_all(&serde_json::to_vec(value)?)?;
    file.sync_all()?;
    std::fs::rename(temporary, path)?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn credential_file_round_trip_is_atomic_and_private() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("credentials.json");
        let entries = HashMap::from([("https://cog.example/git/id.git".into(), "secret".into())]);
        write_entries(&path, &entries).unwrap();
        assert_eq!(read_entries(&path), entries);
        assert!(!path.with_extension("tmp").exists());
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            assert_eq!(
                std::fs::metadata(path).unwrap().permissions().mode() & 0o777,
                0o600
            );
        }
    }

    #[test]
    fn malformed_or_missing_files_are_empty() {
        let directory = tempfile::tempdir().unwrap();
        let missing = directory.path().join("missing");
        assert!(read_entries(&missing).is_empty());
        std::fs::write(&missing, b"not-json").unwrap();
        assert!(read_entries(&missing).is_empty());
    }
}
