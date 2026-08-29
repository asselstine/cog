use clap::{Parser, ValueEnum};
use rand::{RngCore, rngs::OsRng};
use std::{
    fs::OpenOptions,
    io::{Read, Write},
    net::SocketAddr,
    path::{Path, PathBuf},
    time::Duration,
};
use url::Url;

#[derive(Debug, Clone, Parser)]
#[command(version, about)]
pub struct Config {
    #[arg(
        long,
        env = "COG_LISTEN",
        hide_env_values = true,
        default_value = "127.0.0.1:4788"
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
        default_value_os_t = default_data_dir()
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
    #[arg(
        long,
        env = "COG_MASTER_KEY",
        hide_env_values = true,
        default_value = ""
    )]
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
    /// Embedded Git-over-SSH listener. Defaults to loopback for safe local use.
    #[arg(
        long,
        env = "COG_SSH_LISTEN",
        hide_env_values = true,
        default_value = "127.0.0.1:2222"
    )]
    pub ssh_listen: Option<SocketAddr>,
    #[arg(long, env = "COG_SSH_PUBLIC_HOST", hide_env_values = true)]
    pub ssh_public_host: Option<String>,
    #[arg(long, env = "COG_SSH_PUBLIC_PORT", hide_env_values = true)]
    pub ssh_public_port: Option<u16>,
    #[arg(
        long,
        env = "COG_SSH_KEY_LEASE_TTL_SECS",
        hide_env_values = true,
        default_value_t = 900
    )]
    pub ssh_key_lease_ttl_secs: u64,
    #[arg(
        long,
        env = "COG_SSH_HANDSHAKE_TIMEOUT_SECS",
        hide_env_values = true,
        default_value_t = 15
    )]
    pub ssh_handshake_timeout_secs: u64,
    #[arg(
        long,
        env = "COG_SSH_AUTH_TIMEOUT_SECS",
        hide_env_values = true,
        default_value_t = 15
    )]
    pub ssh_auth_timeout_secs: u64,
    #[arg(
        long,
        env = "COG_SSH_CHANNEL_TIMEOUT_SECS",
        hide_env_values = true,
        default_value_t = 30
    )]
    pub ssh_channel_timeout_secs: u64,
    #[arg(
        long,
        env = "COG_SSH_MAX_CONNECTIONS",
        hide_env_values = true,
        default_value_t = 64
    )]
    pub ssh_max_connections: usize,
    #[arg(
        long,
        env = "COG_SSH_MAX_CHANNELS_PER_CONNECTION",
        hide_env_values = true,
        default_value_t = 1
    )]
    pub ssh_max_channels_per_connection: usize,
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
    /// Resolve native paths and the durable encryption key after clap has
    /// applied CLI-over-environment precedence.
    pub fn initialize(&mut self) -> anyhow::Result<()> {
        self.initialize_with_home(&cog_home()?)
    }

    /// Resolve native paths and durable state beneath an explicit application
    /// home. Embedders can use this when the process home is not authoritative.
    pub fn initialize_with_home(&mut self, home: &Path) -> anyhow::Result<()> {
        let listen = self.ssh_listen.expect("COG_SSH_LISTEN has a clap default");
        if self.ssh_public_host.is_none() {
            self.ssh_public_host = self.base_url.host_str().map(str::to_owned);
        }
        if self.ssh_public_port.is_none() {
            self.ssh_public_port = Some(listen.port());
        }
        create_private_dir(home)?;
        create_private_dir(&self.data_dir)?;
        if self.master_key.is_empty() {
            self.master_key = load_or_create_master_key(home, &self.db_path())?;
        }
        Ok(())
    }

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
            self.ssh_key_lease_ttl_secs > 0,
            "SSH key lease TTL must be positive"
        );
        if let Some(listen) = self.ssh_listen {
            let host = self.ssh_public_host.as_deref().unwrap_or_default().trim();
            anyhow::ensure!(
                !host.is_empty(),
                "COG_SSH_PUBLIC_HOST is required when SSH is enabled"
            );
            anyhow::ensure!(
                !host.contains(['/', '\\', '@', '[', ']']),
                "COG_SSH_PUBLIC_HOST is invalid"
            );
            anyhow::ensure!(
                self.ssh_public_port.unwrap_or(listen.port()) > 0,
                "COG_SSH_PUBLIC_PORT must be positive"
            );
            anyhow::ensure!(
                self.ssh_handshake_timeout_secs > 0
                    && self.ssh_auth_timeout_secs > 0
                    && self.ssh_channel_timeout_secs > 0
                    && self.ssh_max_connections > 0
                    && self.ssh_max_channels_per_connection == 1,
                "SSH timeouts and limits must be positive; exactly one channel per connection is supported"
            );
        }
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

fn cog_home() -> anyhow::Result<PathBuf> {
    if let Some(path) = std::env::var_os("COG_HOME").filter(|value| !value.is_empty()) {
        return Ok(path.into());
    }
    #[cfg(windows)]
    let base = std::env::var_os("LOCALAPPDATA")
        .ok_or_else(|| anyhow::anyhow!("LOCALAPPDATA is not set; set COG_HOME explicitly"))?;
    #[cfg(not(windows))]
    let base = std::env::var_os("HOME")
        .ok_or_else(|| anyhow::anyhow!("HOME is not set; set COG_HOME explicitly"))?;
    Ok(PathBuf::from(base).join(if cfg!(windows) { "cog" } else { ".cog" }))
}

fn default_data_dir() -> PathBuf {
    cog_home()
        .unwrap_or_else(|_| PathBuf::from(if cfg!(windows) { "cog" } else { ".cog" }))
        .join("data")
}

fn create_private_dir(path: &Path) -> anyhow::Result<()> {
    std::fs::create_dir_all(path)
        .map_err(|error| anyhow::anyhow!("cannot create {}: {error}", path.display()))?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o700))?;
    }
    #[cfg(windows)]
    restrict_windows_path(path, "(OI)(CI)(F)")?;
    Ok(())
}

fn load_or_create_master_key(home: &Path, database: &Path) -> anyhow::Result<String> {
    let path = home.join("master.key");
    match read_master_key(&path) {
        Ok(Some(key)) => return Ok(key),
        Ok(None) => {}
        Err(error) => return Err(error),
    }
    anyhow::ensure!(
        !database.exists(),
        "the database {} already exists but {} is missing; restore the original master key before starting cog",
        database.display(),
        path.display()
    );

    let mut bytes = [0_u8; 32];
    OsRng.fill_bytes(&mut bytes);
    let generated = hex::encode(bytes);
    let mut options = OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    match options.open(&path) {
        Ok(mut file) => {
            file.write_all(generated.as_bytes())?;
            file.write_all(b"\n")?;
            file.sync_all()?;
            restrict_key_file(&path)?;
            Ok(generated)
        }
        Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => read_master_key(&path)?
            .ok_or_else(|| anyhow::anyhow!("{} disappeared during initialization", path.display())),
        Err(error) => Err(anyhow::anyhow!("cannot create {}: {error}", path.display())),
    }
}

fn read_master_key(path: &Path) -> anyhow::Result<Option<String>> {
    let mut file = match std::fs::File::open(path) {
        Ok(file) => file,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(error) => return Err(anyhow::anyhow!("cannot read {}: {error}", path.display())),
    };
    let mut value = String::new();
    file.read_to_string(&mut value)
        .map_err(|error| anyhow::anyhow!("cannot read {}: {error}", path.display()))?;
    let value = value.trim_end_matches(['\r', '\n']);
    anyhow::ensure!(
        value.len() >= 32 && !value.chars().any(char::is_whitespace),
        "{} is empty or malformed; restore a valid master key of at least 32 non-whitespace characters",
        path.display()
    );
    restrict_key_file(path)?;
    Ok(Some(value.to_owned()))
}

fn restrict_key_file(path: &Path) -> anyhow::Result<()> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600))?;
    }
    #[cfg(windows)]
    {
        let username =
            std::env::var("USERNAME").map_err(|_| anyhow::anyhow!("USERNAME is not set"))?;
        let status = std::process::Command::new("icacls")
            .arg(path)
            .args(["/inheritance:r", "/grant:r", &format!("{username}:(R,W)")])
            .status()?;
        anyhow::ensure!(
            status.success(),
            "could not restrict access to {}",
            path.display()
        );
    }
    Ok(())
}

#[cfg(windows)]
fn restrict_windows_path(path: &Path, access: &str) -> anyhow::Result<()> {
    let username = std::env::var("USERNAME").map_err(|_| anyhow::anyhow!("USERNAME is not set"))?;
    let status = std::process::Command::new("icacls")
        .arg(path)
        .args([
            "/inheritance:r",
            "/grant:r",
            &format!("{username}:{access}"),
        ])
        .status()?;
    anyhow::ensure!(
        status.success(),
        "could not restrict access to {}",
        path.display()
    );
    Ok(())
}
