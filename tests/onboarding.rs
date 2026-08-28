use std::{
    io::Write,
    net::TcpListener,
    process::{Command, Stdio},
    thread,
    time::Duration,
};

fn command(home: &std::path::Path) -> Command {
    let mut command = Command::new(env!("CARGO_BIN_EXE_cog"));
    command
        .env("COG_HOME", home)
        .env_remove("COG_DATA_DIR")
        .env_remove("COG_MASTER_KEY")
        .env_remove("COG_S3_BUCKET");
    command
}

#[test]
fn readme_first_run_bootstraps_and_restarts() {
    let temp = tempfile::tempdir().unwrap();
    let first = command(temp.path()).output().unwrap();
    assert!(first.status.success());
    assert!(
        String::from_utf8_lossy(&first.stderr)
            .contains("cog create-user owner@example.com --password-stdin")
    );
    let key_path = temp.path().join("master.key");
    let database_path = temp.path().join("data/cog.sqlite");
    let key = std::fs::read(&key_path).unwrap();
    assert!(database_path.exists());

    let mut create = command(temp.path());
    create
        .args(["create-user", "owner@example.com", "--password-stdin"])
        .stdin(Stdio::piped());
    let mut child = create.spawn().unwrap();
    child
        .stdin
        .take()
        .unwrap()
        .write_all(b"a-secure-test-password\n")
        .unwrap();
    assert!(child.wait().unwrap().success());

    for _ in 0..2 {
        let port = TcpListener::bind("127.0.0.1:0")
            .unwrap()
            .local_addr()
            .unwrap()
            .port();
        let mut server = command(temp.path());
        server
            .env("COG_LISTEN", format!("127.0.0.1:{port}"))
            .stdout(Stdio::null())
            .stderr(Stdio::null());
        let mut child = server.spawn().unwrap();
        let url = format!("http://127.0.0.1:{port}/readyz");
        let mut ready = false;
        for _ in 0..100 {
            if reqwest::blocking::get(&url).is_ok_and(|response| response.status().is_success()) {
                ready = true;
                break;
            }
            if child.try_wait().unwrap().is_some() {
                break;
            }
            thread::sleep(Duration::from_millis(50));
        }
        child.kill().unwrap();
        let _ = child.wait();
        assert!(ready, "cog did not serve /readyz");
        assert_eq!(std::fs::read(&key_path).unwrap(), key);
    }
}
