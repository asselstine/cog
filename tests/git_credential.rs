use std::{
    io::Write,
    path::Path,
    process::{Command, Output, Stdio},
};

fn helper(runtime: &Path, origin: Option<&str>, operation: &str, input: &str) -> Output {
    let mut command = Command::new(env!("CARGO_BIN_EXE_git-credential-cog"));
    command
        .arg(operation)
        .env("XDG_RUNTIME_DIR", runtime)
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
fn sealed_exchange_keeps_plaintext_out_of_agent_visible_steps() {
    let directory = tempfile::tempdir().unwrap();
    let repository = uuid::Uuid::new_v4();
    let origin = "https://cog.example";
    let prepare = Command::new(env!("CARGO_BIN_EXE_git-credential-cog"))
        .args(["prepare", &format!("{origin}/git/{repository}.git")])
        .env("XDG_RUNTIME_DIR", directory.path())
        .output()
        .unwrap();
    assert!(prepare.status.success());
    let request: cog::git::sealed::SealedCredentialRequest =
        serde_json::from_slice(&prepare.stdout).unwrap();
    let payload = cog::git::sealed::CredentialPayload {
        username: "cog".into(),
        password: "derived-secret".into(),
        repository_id: repository.to_string(),
        origin: origin.into(),
        expires_at: chrono::Utc::now().timestamp() + 900,
    };
    let envelope = cog::git::sealed::seal(&request, origin, &payload).unwrap();
    let visible = serde_json::to_vec(&envelope).unwrap();
    assert!(!String::from_utf8_lossy(&visible).contains("derived-secret"));

    let mut child = Command::new(env!("CARGO_BIN_EXE_git-credential-cog"))
        .arg("import")
        .env("XDG_RUNTIME_DIR", directory.path())
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .spawn()
        .unwrap();
    child.stdin.take().unwrap().write_all(&visible).unwrap();
    let output = child.wait_with_output().unwrap();
    assert!(output.status.success());
    assert!(output.stdout.is_empty());

    let input = format!("protocol=https\nhost=cog.example\npath=git/{repository}.git\n\n");
    let cached = helper(directory.path(), Some(origin), "get", &input);
    assert!(String::from_utf8_lossy(&cached.stdout).contains("password=derived-secret"));
}
