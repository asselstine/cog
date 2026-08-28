use std::{
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
    let create = command(temp.path())
        .args(["create-user", "owner@example.com", "a-secure-test-password"])
        .output()
        .unwrap();
    assert!(create.status.success());
    let key_path = temp.path().join("master.key");
    let database_path = temp.path().join("data/cog.sqlite");
    let key = std::fs::read(&key_path).unwrap();
    assert!(database_path.exists());

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
