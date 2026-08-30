use rmcp::model::MetaObject;
use serde_json::{Value, json};

pub use rmcp::model::{CallToolResult, ContentBlock, Tool, ToolAnnotations};

pub const META_SECURITY_SCHEMES: &str = "com.clanker.cog/securitySchemes";
pub const META_REQUIRED_SCOPE: &str = "com.clanker.cog/requiredScope";
pub const META_CLIENT_ACCESS_GRANTED: &str = "com.clanker.cog/clientAccessGranted";
pub const META_INTEGRATION_LABEL: &str = "com.clanker.cog/integrationLabel";

pub fn security_schemes(scopes: impl IntoIterator<Item = String>) -> Value {
    json!([{"type":"oauth2","scopes":scopes.into_iter().collect::<Vec<_>>() }])
}

pub fn native_tool_meta(required_scope: &str) -> MetaObject {
    let mut meta = MetaObject::new();
    meta.insert(
        META_SECURITY_SCHEMES.into(),
        security_schemes([required_scope.to_owned()]),
    );
    meta.insert(META_REQUIRED_SCOPE.into(), json!(required_scope));
    meta
}

pub fn meta_string<'a>(tool: &'a Tool, key: &str) -> Option<&'a str> {
    tool.meta.as_ref()?.get(key)?.as_str()
}

pub fn meta_bool(tool: &Tool, key: &str) -> Option<bool> {
    tool.meta.as_ref()?.get(key)?.as_bool()
}

pub fn insert_meta(tool: &mut Tool, key: &str, value: Value) {
    tool.meta
        .get_or_insert_with(MetaObject::new)
        .insert(key.to_owned(), value);
}
