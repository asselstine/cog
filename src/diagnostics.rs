use crate::Config;
use std::fmt;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum StartupPhase {
    StorageInitialization,
    ConditionalWriteProbe,
    LeaseAcquisition,
    Restore,
    DatabaseOpen,
    InitialReplication,
}

impl fmt::Display for StartupPhase {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::StorageInitialization => "storage initialization",
            Self::ConditionalWriteProbe => "conditional-write probing",
            Self::LeaseAcquisition => "lease acquisition",
            Self::Restore => "database restore",
            Self::DatabaseOpen => "local database initialization",
            Self::InitialReplication => "initial replication",
        })
    }
}

#[derive(Debug)]
pub struct StartupError {
    phase: StartupPhase,
    kind: &'static str,
    guidance: &'static str,
}

impl StartupError {
    pub fn new(phase: StartupPhase, error: &(dyn std::error::Error + 'static)) -> Self {
        let kind = classify_error(error);
        let guidance = match (phase, kind) {
            (_, "credentials expired") => {
                "refresh the AWS credentials or configure a renewable credential provider"
            }
            (_, "credentials unavailable or rejected") => {
                "verify the selected AWS credential provider and its permissions"
            }
            (StartupPhase::ConditionalWriteProbe, _) => {
                "verify bucket access and support for conditional create and update requests"
            }
            (StartupPhase::LeaseAcquisition, _) => {
                "verify bucket access and check whether another cog instance owns the lease"
            }
            (StartupPhase::Restore, _) => {
                "verify access to the configured prefix and the integrity of its LTX objects"
            }
            (StartupPhase::StorageInitialization, _) => {
                "verify the bucket, region, endpoint, TLS settings, and AWS credential configuration"
            }
            (StartupPhase::DatabaseOpen, _) => {
                "verify the data directory is writable and contains a valid SQLite database"
            }
            (StartupPhase::InitialReplication, _) => {
                "verify lease authority, bucket access, and the restored database state"
            }
        };
        Self {
            phase,
            kind,
            guidance,
        }
    }
}

impl fmt::Display for StartupError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "cog startup failed during {}: {}; {}",
            self.phase, self.kind, self.guidance
        )
    }
}

impl std::error::Error for StartupError {}

fn classify_error(error: &(dyn std::error::Error + 'static)) -> &'static str {
    let mut text = String::new();
    let mut current = Some(error);
    while let Some(item) = current {
        text.push_str(&item.to_string().to_ascii_lowercase());
        text.push(' ');
        current = item.source();
    }
    if text.contains("expiredtoken")
        || text.contains("expired token")
        || text.contains("expired credential")
    {
        "credentials expired"
    } else if text.contains("credential")
        || text.contains("accessdenied")
        || text.contains("signature")
        || text.contains("unauthorized")
        || text.contains("forbidden")
        || text.contains("metadata")
    {
        "credentials unavailable or rejected"
    } else if text.contains("timeout") || text.contains("timed out") {
        "storage request timed out"
    } else if text.contains("connect") || text.contains("dns") {
        "storage endpoint could not be reached"
    } else if text.contains("precondition") || text.contains("conditional") {
        "storage conditional-write requirement was not met"
    } else if text.contains("not found") || text.contains("nosuchbucket") {
        "bucket or object was not found"
    } else {
        "storage operation failed (provider details redacted)"
    }
}

/// Produce a bounded description suitable for logs. The returned value never
/// contains the provider's raw message, response body, headers, or error chain.
pub fn redacted_error(error: &(dyn std::error::Error + 'static)) -> &'static str {
    classify_error(error)
}

/// Render an error for an API response without reflecting provider-controlled
/// messages, bodies, headers, or nested error chains.
pub fn safe_error(error: &(dyn std::error::Error + 'static)) -> String {
    let kind = classify_error(error);
    match kind {
        "storage operation failed (provider details redacted)" => kind.to_owned(),
        _ => format!("{kind} (provider details redacted)"),
    }
}

/// Classify Git transport failures without retaining request data, provider
/// response bodies, authorization material, URLs, or the raw error chain.
pub fn safe_git_error(error: &(dyn std::error::Error + 'static)) -> &'static str {
    let mut text = String::new();
    let mut current = Some(error);
    while let Some(item) = current {
        text.push_str(&item.to_string().to_ascii_lowercase());
        text.push(' ');
        current = item.source();
    }
    if text.contains("pack") || text.contains("zlib") || text.contains("deflate") {
        "invalid Git pack stream"
    } else if text.contains("upstream discovery") {
        "upstream Git discovery failed"
    } else if text.contains("upstream git rpc") || text.contains("error sending request") {
        "upstream Git request failed"
    } else if text.contains("idle timeout") || text.contains("timed out") {
        "Git transport timed out"
    } else if text.contains("byte limit") || text.contains("stream limit") {
        "Git transport limit exceeded"
    } else if text.contains("client disconnected") || text.contains("input closed") {
        "Git client disconnected"
    } else if text.contains("grant") || text.contains("permission") || text.contains("revoked") {
        "Git authorization is no longer valid"
    } else {
        "Git transport operation failed"
    }
}

pub fn credential_provider_class() -> &'static str {
    credential_provider_class_from(|name| std::env::var_os(name).is_some())
}

/// Classify the effective AWS credential source using a caller-supplied
/// environment lookup. This is useful to launchers that maintain their own
/// environment view rather than mutating the current process.
pub fn credential_provider_class_from(mut is_set: impl FnMut(&str) -> bool) -> &'static str {
    // Keep this precedence in lockstep with object_store's AmazonS3Builder.
    // In particular, environment credentials are deliberately static even
    // when AWS_SESSION_TOKEN is present: changing the process environment is
    // not a supported renewal mechanism.
    if is_set("AWS_ACCESS_KEY_ID") || is_set("AWS_SECRET_ACCESS_KEY") {
        "environment/static credentials (not renewable)"
    } else if is_set("AWS_WEB_IDENTITY_TOKEN_FILE") && is_set("AWS_ROLE_ARN") {
        "web identity credentials (renewable)"
    } else if is_set("AWS_CONTAINER_CREDENTIALS_RELATIVE_URI")
        || (is_set("AWS_CONTAINER_CREDENTIALS_FULL_URI")
            && is_set("AWS_CONTAINER_AUTHORIZATION_TOKEN_FILE"))
    {
        "container credentials (renewable)"
    } else {
        "EC2 instance metadata credentials (renewable)"
    }
}

pub fn safe_endpoint(config: &Config) -> String {
    let Some(endpoint) = &config.s3_endpoint else {
        return "AWS default".to_owned();
    };
    let Ok(mut url) = url::Url::parse(endpoint) else {
        return "custom endpoint (invalid URL redacted)".to_owned();
    };
    let _ = url.set_username("");
    let _ = url.set_password(None);
    url.set_query(None);
    url.set_fragment(None);
    url.to_string()
}
