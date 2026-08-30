use super::*;
use rust_embed::RustEmbed;

#[derive(RustEmbed)]
#[folder = "frontend/dist"]
pub struct Frontend;

pub fn frontend_response(path: &str) -> Response {
    let Some(file) = Frontend::get(path) else {
        return StatusCode::NOT_FOUND.into_response();
    };
    let content_type = match path.rsplit_once('.').map(|(_, extension)| extension) {
        Some("html") => "text/html; charset=utf-8",
        Some("css") => "text/css; charset=utf-8",
        Some("js") => "text/javascript; charset=utf-8",
        Some("svg") => "image/svg+xml",
        Some("png") => "image/png",
        Some("woff2") => "font/woff2",
        _ => "application/octet-stream",
    };
    (
        [(header::CONTENT_TYPE, content_type)],
        bytes::Bytes::copy_from_slice(file.data.as_ref()),
    )
        .into_response()
}

pub(super) async fn ui_asset(Path(path): Path<String>) -> Response {
    frontend_response(&format!("assets/{path}"))
}

pub(super) fn ui_shell() -> Response {
    let mut response = frontend_response("index.html");
    response.headers_mut().insert(
        header::CACHE_CONTROL,
        header::HeaderValue::from_static("no-cache"),
    );
    response
}

pub(super) async fn home() -> Response {
    ui_shell()
}
