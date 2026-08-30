pub mod catalog;
pub mod client;
pub mod model;
pub mod protocol;
pub mod service;
pub mod tools;

pub use catalog::{Catalog, RuntimeHost, ToolProvider};
pub use client::{HttpMcp, StdioMcp, UpstreamInsufficientScope};
pub use model::{SecurityScheme, Tool, ToolAnnotations};
pub use protocol::{
    LATEST_PROTOCOL_VERSION, RpcRequest, RpcResponse, SUPPORTED_PROTOCOL_VERSIONS, handle,
    handle_with_metadata, handle_with_options, insufficient_scope_result,
    protocol_version_supported,
};
