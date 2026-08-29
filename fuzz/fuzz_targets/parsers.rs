#![no_main]

use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let _ = cog::ltx::decode_reference_ltx(data);
    if let Ok(text) = std::str::from_utf8(data) {
        let _ = cog::upstream::parse_sse_json(text, 1);
        let _ = cog::oauth::validate_redirect_uri(text);
        let _ = cog::git::auth::parse_authorization(text);
        let parts = text.split('\0').collect::<Vec<_>>();
        if parts.len() >= 3 { let _ = cog::git::model::classify(parts[0], parts[1], Some(parts[2])); }
    }
    let _ = serde_json::from_slice::<cog::mcp::RpcRequest>(data);
});
