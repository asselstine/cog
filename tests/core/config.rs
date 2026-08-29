use clap::Parser;
use cog::config::*;
use std::{path::PathBuf, time::Duration};
use tempfile::tempdir;
#[test]
fn paths_and_validation() {
    let temp = tempdir().unwrap();
    let data = temp.path().join("data");
    let master_key = ["abcdefghijklmnopqrstuvwxyz", "123456"].concat();
    let mut c = Config::parse_from([
        "cog",
        "--data-dir",
        data.to_str().unwrap(),
        "--s3-bucket",
        "b",
        "--master-key",
        master_key.as_str(),
    ]);
    assert_eq!(c.db_path(), data.join("cog.sqlite"));
    assert_eq!(c.lease_ttl(), Duration::from_secs(30));
    assert!(c.s3_enabled());
    assert_eq!(c.ssh_listen, Some("127.0.0.1:2222".parse().unwrap()));
    c.initialize_with_home(&temp.path().join("home")).unwrap();
    assert_eq!(c.ssh_public_host.as_deref(), Some("localhost"));
    assert_eq!(c.ssh_public_port, Some(2222));
    assert!(c.validate().is_ok());
    let mut bad = c.clone();
    bad.s3_bucket = Some(String::new());
    assert!(bad.validate().is_err());
    bad = c.clone();
    bad.master_key = "short".into();
    assert!(bad.validate().is_err());
    bad = c.clone();
    bad.lease_ttl_secs = 1;
    assert!(bad.validate().is_err());

    let mut local = c.clone();
    local.s3_bucket = None;
    local.ssh_listen = None;
    assert!(!local.s3_enabled());
    assert!(local.validate().is_ok());
}

fn test_config(data: PathBuf) -> Config {
    Config::parse_from(["cog", "--data-dir", data.to_str().unwrap()])
}

#[test]
fn generates_reuses_and_overrides_master_key() {
    let temp = tempdir().unwrap();
    let home = temp.path().join("home");
    let mut first = test_config(temp.path().join("data"));
    first.initialize_with_home(&home).unwrap();
    assert_eq!(first.master_key.len(), 64);
    let stored = std::fs::read_to_string(home.join("master.key")).unwrap();
    assert_eq!(stored.trim(), first.master_key);

    let mut restarted = test_config(temp.path().join("data"));
    restarted.initialize_with_home(&home).unwrap();
    assert_eq!(restarted.master_key, first.master_key);

    let explicit = "x".repeat(32);
    let mut overridden = test_config(temp.path().join("other-data"));
    overridden.master_key.clone_from(&explicit);
    overridden.initialize_with_home(&home).unwrap();
    assert_eq!(overridden.master_key, explicit);
    assert_eq!(
        std::fs::read_to_string(home.join("master.key")).unwrap(),
        stored
    );
}

#[test]
fn invalid_or_missing_key_for_existing_database_is_not_replaced() {
    let temp = tempdir().unwrap();
    let home = temp.path().join("home");
    std::fs::create_dir_all(&home).unwrap();
    std::fs::write(home.join("master.key"), "short\n").unwrap();
    let mut config = test_config(temp.path().join("data"));
    assert!(
        config
            .initialize_with_home(&home)
            .unwrap_err()
            .to_string()
            .contains("malformed")
    );
    assert_eq!(
        std::fs::read_to_string(home.join("master.key")).unwrap(),
        "short\n"
    );

    std::fs::remove_file(home.join("master.key")).unwrap();
    std::fs::create_dir_all(&config.data_dir).unwrap();
    std::fs::write(config.db_path(), b"existing").unwrap();
    assert!(
        config
            .initialize_with_home(&home)
            .unwrap_err()
            .to_string()
            .contains("restore")
    );
    assert!(!home.join("master.key").exists());
}

#[test]
fn concurrent_initialization_converges_on_one_key() {
    let temp = tempdir().unwrap();
    let home = temp.path().join("home");
    let data = temp.path().join("data");
    let handles = (0..8)
        .map(|_| {
            let home = home.clone();
            let mut config = test_config(data.clone());
            std::thread::spawn(move || {
                config.initialize_with_home(&home).unwrap();
                config.master_key
            })
        })
        .collect::<Vec<_>>();
    let keys = handles
        .into_iter()
        .map(|handle| handle.join().unwrap())
        .collect::<Vec<_>>();
    assert!(keys.iter().all(|key| key == &keys[0]));
}
