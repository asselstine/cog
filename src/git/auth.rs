use base64::{Engine, engine::general_purpose::STANDARD};
pub fn credential(headers: &http::HeaderMap) -> Option<String> {
    let raw = headers.get(http::header::AUTHORIZATION)?.to_str().ok()?;
    parse_authorization(raw)
}
pub fn parse_authorization(raw: &str) -> Option<String> {
    if let Some(v) = raw.strip_prefix("Bearer ") {
        return Some(v.to_owned());
    }
    let b = raw.strip_prefix("Basic ")?;
    let decoded = STANDARD.decode(b).ok()?;
    let text = std::str::from_utf8(&decoded).ok()?;
    let (user, password) = text.split_once(':')?;
    (user == "cog").then(|| password.to_owned())
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn basic_is_scoped() {
        let mut h = http::HeaderMap::new();
        h.insert(
            http::header::AUTHORIZATION,
            "Basic Y29nOnRva2Vu".parse().unwrap(),
        );
        assert_eq!(credential(&h).as_deref(), Some("token"));
        assert_eq!(parse_authorization("Bearer direct"), Some("direct".into()));
        assert_eq!(parse_authorization("bearer wrong-case"), None);
        assert_eq!(parse_authorization("Basic !!!"), None);
        assert_eq!(parse_authorization("Basic dXNlcjpwYXNz"), None);
        assert_eq!(parse_authorization("Basic Y29n"), None);
    }
}
