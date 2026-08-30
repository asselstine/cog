pub mod auth;
pub mod http;
pub mod stdio;

pub use auth::{UpstreamInsufficientScope, bearer_parameter, parse_upstream_insufficient_scope};
pub use http::HttpMcp;
pub use stdio::StdioMcp;

use std::time::Duration;

pub(super) const RPC_TIMEOUT: Duration = Duration::from_secs(30);
pub const MAX_MESSAGE_BYTES: usize = 1024 * 1024;
pub const MAX_DIAGNOSTIC_BYTES: usize = 8 * 1024;
