pub mod auth;
pub mod http;
pub mod stdio;

pub use auth::{UpstreamInsufficientScope, bearer_parameter, parse_upstream_insufficient_scope};
pub use http::{HttpMcp, cancellation_guard, parse_sse_json};
pub use stdio::{StdioMcp, validate_initialize};

use std::time::Duration;

pub(super) const RPC_TIMEOUT: Duration = Duration::from_secs(30);
pub const MAX_MESSAGE_BYTES: usize = 1024 * 1024;
pub const MAX_TOOL_CATALOG_BYTES: usize = 32 * 1024 * 1024;
pub const MAX_DIAGNOSTIC_BYTES: usize = 8 * 1024;
pub const MCP_PROTOCOL_VERSION: &str = crate::mcp::LATEST_PROTOCOL_VERSION;
