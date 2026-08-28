use serde::Deserialize;
use std::{
    collections::HashMap,
    io::{self, BufRead},
    path::PathBuf,
};

#[derive(Deserialize)]
struct ExchangedCredential {
    username: String,
    password: String,
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
        .ok_or_else(|| anyhow::anyhow!("expected get, store, or erase"))?;
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
            } else if let (Ok(bootstrap), Ok(oauth)) = (
                std::env::var("COG_GIT_BOOTSTRAP"),
                std::env::var("COG_OAUTH_TOKEN"),
            ) {
                let repository_id = path
                    .strip_prefix("git/")
                    .and_then(|value| value.strip_suffix(".git"))
                    .ok_or_else(|| {
                        anyhow::anyhow!("credential request has an invalid repository path")
                    })?;
                uuid::Uuid::parse_str(repository_id).map_err(|_| {
                    anyhow::anyhow!("credential request has a non-opaque repository path")
                })?;
                let response = reqwest::blocking::Client::builder()
                    .redirect(reqwest::redirect::Policy::none())
                    .build()?
                    .post(configured.join("git/bootstrap")?)
                    .bearer_auth(oauth)
                    .json(&serde_json::json!({"bootstrap":bootstrap,"repository_id":repository_id}))
                    .send()?;
                anyhow::ensure!(
                    response.status().is_success(),
                    "bootstrap exchange was rejected ({})",
                    response.status()
                );
                let exchanged: ExchangedCredential = response.json()?;
                anyhow::ensure!(
                    exchanged.username == "cog",
                    "bootstrap exchange returned an invalid username"
                );
                entries.insert(key, exchanged.password.clone());
                write_entries(&file, &entries)?;
                println!("username=cog\npassword={}", exchanged.password)
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
fn credential_file() -> anyhow::Result<PathBuf> {
    let base = std::env::var_os("XDG_RUNTIME_DIR")
        .map(PathBuf::from)
        .unwrap_or_else(|| {
            std::env::temp_dir().join(format!("cog-{}", unsafe { libc::geteuid() }))
        });
    std::fs::create_dir_all(&base)?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&base, std::fs::Permissions::from_mode(0o700))?
    }
    Ok(base.join("git-credentials.json"))
}
fn read_entries(path: &PathBuf) -> HashMap<String, String> {
    std::fs::read(path)
        .ok()
        .and_then(|v| serde_json::from_slice(&v).ok())
        .unwrap_or_default()
}
fn write_entries(path: &PathBuf, entries: &HashMap<String, String>) -> anyhow::Result<()> {
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
    file.write_all(&serde_json::to_vec(entries)?)?;
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
