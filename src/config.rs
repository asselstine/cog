use clap::{Parser, ValueEnum};
use std::{net::SocketAddr, path::PathBuf, time::Duration};
use url::Url;

#[derive(Debug, Clone, Parser)]
#[command(version, about)]
pub struct Config {
    #[arg(
        long,
        env = "COG_LISTEN",
        hide_env_values = true,
        default_value = "0.0.0.0:4788"
    )]
    pub listen: SocketAddr,
    #[arg(
        long,
        env = "COG_BASE_URL",
        hide_env_values = true,
        default_value = "http://localhost:4788"
    )]
    pub base_url: Url,
    #[arg(
        long,
        env = "COG_DATA_DIR",
        hide_env_values = true,
        default_value = "/data"
    )]
    pub data_dir: PathBuf,
    #[arg(long, env = "COG_S3_BUCKET", hide_env_values = true)]
    pub s3_bucket: Option<String>,
    #[arg(
        long,
        env = "COG_S3_PREFIX",
        hide_env_values = true,
        default_value = "cog/"
    )]
    pub s3_prefix: String,
    #[arg(long, env = "COG_S3_ENDPOINT", hide_env_values = true)]
    pub s3_endpoint: Option<String>,
    #[arg(
        long,
        env = "COG_S3_REGION",
        hide_env_values = true,
        default_value = "us-east-1"
    )]
    pub s3_region: String,
    #[arg(
        long,
        env = "COG_S3_ALLOW_HTTP",
        hide_env_values = true,
        default_value_t = false
    )]
    pub s3_allow_http: bool,
    #[arg(long, env = "COG_MASTER_KEY", hide_env_values = true)]
    pub master_key: String,
    #[arg(
        long,
        env = "COG_LEASE_TTL_SECS",
        hide_env_values = true,
        default_value_t = 30
    )]
    pub lease_ttl_secs: u64,
    #[arg(
        long,
        env = "COG_V8_HEAP_MB",
        hide_env_values = true,
        default_value_t = 128
    )]
    pub v8_heap_mb: usize,
    #[arg(
        long,
        env = "COG_EXECUTION_TIMEOUT_SECS",
        hide_env_values = true,
        default_value_t = 30
    )]
    pub execution_timeout_secs: u64,
    /// Explicitly permit administrators to launch configured local commands.
    #[arg(
        long,
        env = "COG_ALLOW_STDIO",
        hide_env_values = true,
        default_value_t = false
    )]
    pub allow_stdio: bool,
    #[arg(
        long,
        env = "COG_GIT_MAX_REQUEST_BYTES",
        hide_env_values = true,
        default_value_t = 2_147_483_648
    )]
    pub git_max_request_bytes: u64,
    #[arg(
        long,
        env = "COG_GIT_MAX_RESPONSE_BYTES",
        hide_env_values = true,
        default_value_t = 4_294_967_296
    )]
    pub git_max_response_bytes: u64,
    #[arg(
        long,
        env = "COG_GIT_TIMEOUT_SECS",
        hide_env_values = true,
        default_value_t = 3600
    )]
    pub git_timeout_secs: u64,
    #[arg(
        long,
        env = "COG_GIT_IDLE_TIMEOUT_SECS",
        hide_env_values = true,
        default_value_t = 120
    )]
    pub git_idle_timeout_secs: u64,
    #[arg(
        long,
        env = "COG_GIT_MAX_STREAMS",
        hide_env_values = true,
        default_value_t = 32
    )]
    pub git_max_streams: usize,
    #[arg(
        long,
        env = "COG_GIT_MAX_STREAMS_PER_CLIENT",
        hide_env_values = true,
        default_value_t = 4
    )]
    pub git_max_streams_per_client: usize,
    /// Deliver downstream OAuth callbacks from the cog host to literal
    /// loopback listeners. Disabled by default because this is a constrained
    /// server-side request feature, not part of standard browser OAuth.
    #[arg(
        long,
        env = "COG_SERVER_LOCAL_CALLBACKS",
        hide_env_values = true,
        value_enum,
        default_value_t = ServerLocalCallbacks::Off
    )]
    pub server_local_callbacks: ServerLocalCallbacks,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, ValueEnum)]
pub enum ServerLocalCallbacks {
    Off,
    Auto,
    Required,
}

impl Config {
    pub fn db_path(&self) -> PathBuf {
        self.data_dir.join("cog.sqlite")
    }
    pub fn lease_ttl(&self) -> Duration {
        Duration::from_secs(self.lease_ttl_secs)
    }
    pub fn s3_enabled(&self) -> bool {
        self.s3_bucket
            .as_deref()
            .is_some_and(|bucket| !bucket.trim().is_empty())
    }
    pub fn validate(&self) -> anyhow::Result<()> {
        anyhow::ensure!(
            self.s3_bucket
                .as_deref()
                .is_none_or(|bucket| !bucket.trim().is_empty()),
            "COG_S3_BUCKET cannot be empty"
        );
        anyhow::ensure!(
            self.git_max_streams > 0
                && self.git_max_streams_per_client > 0
                && self.git_timeout_secs > 0
                && self.git_idle_timeout_secs > 0
                && self.git_max_request_bytes > 0
                && self.git_max_response_bytes > 0,
            "Git limits must be positive"
        );
        anyhow::ensure!(
            self.master_key.len() >= 32,
            "COG_MASTER_KEY must be at least 32 characters"
        );
        if self.s3_enabled() {
            anyhow::ensure!(
                self.lease_ttl_secs >= 9,
                "lease TTL must be at least 9 seconds"
            );
        }
        anyhow::ensure!(
            !self.base_url.cannot_be_a_base(),
            "base URL must be absolute"
        );
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn paths_and_validation() {
        let c = Config::parse_from([
            "cog",
            "--data-dir",
            "/data",
            "--s3-bucket",
            "b",
            "--master-key",
            "abcdefghijklmnopqrstuvwxyz123456",
        ]);
        assert_eq!(c.db_path(), PathBuf::from("/data/cog.sqlite"));
        assert_eq!(c.lease_ttl(), Duration::from_secs(30));
        assert!(c.s3_enabled());
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
        assert!(!local.s3_enabled());
        assert!(local.validate().is_ok());
    }
}
