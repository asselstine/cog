use std::{
    io::{Read, Write},
    net::TcpListener,
    path::Path,
    process::{Command, Output, Stdio},
};

fn helper(runtime: &Path, origin: Option<&str>, operation: &str, input: &str) -> Output {
    let mut command = Command::new(env!("CARGO_BIN_EXE_git-credential-cog"));
    command
        .arg(operation)
        .env("XDG_RUNTIME_DIR", runtime)
        .env_remove("COG_GIT_BOOTSTRAP")
        .env_remove("COG_OAUTH_TOKEN")
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    if let Some(origin) = origin {
        command.env("COG_GIT_ORIGIN", origin);
    } else {
        command.env_remove("COG_GIT_ORIGIN");
    }
    let mut child = command.spawn().unwrap();
    child
        .stdin
        .take()
        .unwrap()
        .write_all(input.as_bytes())
        .unwrap();
    child.wait_with_output().unwrap()
}

#[test]
fn store_get_erase_and_validation_are_origin_and_path_scoped() {
    let directory = tempfile::tempdir().unwrap();
    let repository = uuid::Uuid::new_v4();
    let input = format!(
        "protocol=https\nhost=cog.example\npath=git/{repository}.git\nusername=cog\npassword=derived-secret\n\n"
    );
    assert!(
        helper(
            directory.path(),
            Some("https://cog.example"),
            "store",
            &input
        )
        .status
        .success()
    );

    let query = format!("protocol=https\nhost=cog.example\npath=git/{repository}.git\n\n");
    let get = helper(directory.path(), Some("https://cog.example"), "get", &query);
    assert!(get.status.success());
    assert_eq!(
        String::from_utf8(get.stdout).unwrap(),
        "username=cog\npassword=derived-secret\n"
    );
    assert!(
        helper(
            directory.path(),
            Some("https://cog.example"),
            "erase",
            &query
        )
        .status
        .success()
    );
    assert!(
        helper(directory.path(), Some("https://cog.example"), "get", &query)
            .stdout
            .is_empty()
    );

    for (origin, operation, invalid) in [
        (None, "get", query.as_str()),
        (Some("https://other.example"), "get", query.as_str()),
        (Some("https://cog.example"), "unknown", query.as_str()),
        (
            Some("https://cog.example"),
            "get",
            "protocol=https\nhost=cog.example\npath=../secret.git\n\n",
        ),
        (
            Some("https://cog.example"),
            "store",
            "protocol=https\nhost=cog.example\npath=git/repo.git\nusername=other\npassword=x\n\n",
        ),
    ] {
        let output = helper(directory.path(), origin, operation, invalid);
        assert!(!output.status.success());
        assert!(String::from_utf8_lossy(&output.stderr).starts_with("git-credential-cog:"));
    }
}

#[test]
fn bootstrap_exchange_is_persisted_and_reused_without_a_second_exchange() {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let address = listener.local_addr().unwrap();
    let server = std::thread::spawn(move || {
        let (mut stream, _) = listener.accept().unwrap();
        let mut request = Vec::new();
        let mut buffer = [0_u8; 4096];
        loop {
            let count = stream.read(&mut buffer).unwrap();
            request.extend_from_slice(&buffer[..count]);
            if request.windows(4).any(|window| window == b"\r\n\r\n")
                && String::from_utf8_lossy(&request)
                    .split("\r\n\r\n")
                    .nth(1)
                    .is_some_and(|body| body.contains("repository_id"))
            {
                break;
            }
        }
        let text = String::from_utf8_lossy(&request);
        assert!(text.starts_with("POST /git/bootstrap HTTP/1.1"));
        assert!(
            text.to_ascii_lowercase()
                .contains("authorization: bearer oauth-token")
        );
        assert!(text.contains("bootstrap-secret"));
        let body = br#"{"username":"cog","password":"exchanged-secret"}"#;
        write!(
            stream,
            "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
            body.len()
        )
        .unwrap();
        stream.write_all(body).unwrap();
    });
    let directory = tempfile::tempdir().unwrap();
    let repository = uuid::Uuid::new_v4();
    let input = format!("protocol=http\nhost={address}\npath=git/{repository}.git\n\n");
    let mut command = Command::new(env!("CARGO_BIN_EXE_git-credential-cog"));
    let mut child = command
        .arg("get")
        .env("XDG_RUNTIME_DIR", directory.path())
        .env("COG_GIT_ORIGIN", format!("http://{address}"))
        .env("COG_GIT_BOOTSTRAP", "bootstrap-secret")
        .env("COG_OAUTH_TOKEN", "oauth-token")
        .env("COG_GIT_PERMISSION", "write")
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .spawn()
        .unwrap();
    child
        .stdin
        .take()
        .unwrap()
        .write_all(input.as_bytes())
        .unwrap();
    let output = child.wait_with_output().unwrap();
    assert!(output.status.success());
    assert!(String::from_utf8_lossy(&output.stdout).contains("password=exchanged-secret"));
    server.join().unwrap();

    let cached = helper(
        directory.path(),
        Some(&format!("http://{address}")),
        "get",
        &input,
    );
    assert!(cached.status.success());
    assert!(String::from_utf8_lossy(&cached.stdout).contains("password=exchanged-secret"));
}
