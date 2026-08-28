//! Code-mode control-plane schemas are implemented by the server's built-in
//! provider; this module keeps the public, provider-neutral operation names.
pub const OPERATIONS: &[&str] = &["repository_access", "sealed_credentials"];
