use http::{HeaderMap, HeaderName, header};

pub fn request_headers(source: &HeaderMap) -> HeaderMap {
    let mut out = HeaderMap::new();
    for (name, value) in source {
        let lower = name.as_str().to_ascii_lowercase();
        if name == header::AUTHORIZATION
            || name == header::ORIGIN
            || name == header::REFERER
            || name == header::HOST
            || name == header::CONTENT_LENGTH
            || lower == "x-github-api-version"
            || lower.starts_with("sec-fetch-")
            || is_hop(name)
        {
            continue;
        }
        if name == header::CONTENT_TYPE || name == header::ACCEPT || lower == "git-protocol" {
            out.append(name.clone(), value.clone());
        }
    }
    out.insert(
        header::ACCEPT_ENCODING,
        http::HeaderValue::from_static("identity"),
    );
    out
}
pub fn response_headers(source: &HeaderMap) -> HeaderMap {
    source
        .iter()
        .filter(|(n, _)| {
            !is_hop(n)
                && *n != header::CONTENT_LENGTH
                && *n != header::AUTHORIZATION
                && *n != header::SET_COOKIE
        })
        .map(|(n, v)| (n.clone(), v.clone()))
        .collect()
}
fn is_hop(n: &HeaderName) -> bool {
    matches!(
        n.as_str().to_ascii_lowercase().as_str(),
        "connection"
            | "keep-alive"
            | "proxy-authenticate"
            | "proxy-authorization"
            | "te"
            | "trailer"
            | "transfer-encoding"
            | "upgrade"
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn strips_credentials() {
        let mut h = HeaderMap::new();
        h.insert(header::AUTHORIZATION, "Bearer cog".parse().unwrap());
        h.insert("Git-Protocol", "version=2".parse().unwrap());
        let got = request_headers(&h);
        assert!(got.get(header::AUTHORIZATION).is_none());
        assert_eq!(got["Git-Protocol"], "version=2");
        assert_eq!(got[header::ACCEPT_ENCODING], "identity");

        let mut response = HeaderMap::new();
        response.insert(
            header::CONTENT_TYPE,
            "application/x-git-result".parse().unwrap(),
        );
        response.insert(header::SET_COOKIE, "secret=yes".parse().unwrap());
        response.insert(header::CONTENT_LENGTH, "10".parse().unwrap());
        response.insert(header::CONNECTION, "close".parse().unwrap());
        let filtered = response_headers(&response);
        assert_eq!(filtered[header::CONTENT_TYPE], "application/x-git-result");
        assert!(filtered.get(header::SET_COOKIE).is_none());
        assert!(filtered.get(header::CONTENT_LENGTH).is_none());
        assert!(filtered.get(header::CONNECTION).is_none());
    }
}
