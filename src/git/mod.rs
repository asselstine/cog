//! Provider-neutral Git smart-HTTP support.
pub mod grants;
pub mod model;
pub mod pack;
pub mod providers;
pub mod service;
pub mod ssh;

pub use model::*;
