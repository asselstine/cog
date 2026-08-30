use crate::upstream::Tool;
use serde_json::{Value, json};

pub mod admin;
pub mod execute;
pub mod git;

#[derive(Debug, Clone)]
pub struct NativeToolDefinition {
    pub tool: Tool,
    pub required_scope: &'static str,
}

pub fn annotations(
    required_scope: &'static str,
    read_only: bool,
    destructive: bool,
    idempotent: bool,
    open_world: bool,
) -> serde_json::Map<String, Value> {
    let security = json!([{"type":"oauth2","scopes":[required_scope]}]);
    serde_json::from_value(json!({
        "annotations": {
            "readOnlyHint": read_only,
            "destructiveHint": destructive,
            "idempotentHint": idempotent,
            "openWorldHint": open_world
        },
        "securitySchemes": security,
        "_meta": {"securitySchemes": security}
    }))
    .expect("native annotations are an object")
}
