//! Provider-neutral Git smart-HTTP support.
pub mod auth;
pub mod control;
pub mod grants;
pub mod headers;
pub mod model;
pub mod providers;
pub mod proxy;

pub use model::*;
