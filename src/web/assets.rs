//! Static files, built into the binary. URLs carry a version, so browsers
//! may cache them for good.

use std::sync::LazyLock;

use axum::extract::Path;
use axum::http::{HeaderValue, StatusCode, header};
use axum::response::{IntoResponse, Response};

const FILES: &[(&str, &str, &[u8])] = &[
    (
        "app.css",
        "text/css",
        include_bytes!("../../static/app.css"),
    ),
    (
        "app.js",
        "text/javascript",
        include_bytes!("../../static/app.js"),
    ),
    (
        "htmx.js",
        "text/javascript",
        include_bytes!("../../static/vendor/htmx-2.0.4.min.js"),
    ),
    (
        "htmx-sse.js",
        "text/javascript",
        include_bytes!("../../static/vendor/htmx-ext-sse-2.2.2.js"),
    ),
    (
        "uplot.js",
        "text/javascript",
        include_bytes!("../../static/vendor/uplot-1.6.31.iife.min.js"),
    ),
    (
        "uplot.css",
        "text/css",
        include_bytes!("../../static/vendor/uplot-1.6.31.min.css"),
    ),
];

/// A short hash of all files, used as the `?v=` cache buster.
pub fn version() -> &'static str {
    static VERSION: LazyLock<String> = LazyLock::new(|| {
        // FNV-1a: tiny and good enough to notice a change.
        let mut hash: u64 = 0xcbf2_9ce4_8422_2325;
        for (_, _, body) in FILES {
            for byte in body.iter() {
                hash = (hash ^ u64::from(*byte)).wrapping_mul(0x0100_0000_01b3);
            }
        }
        format!("{:08x}", hash >> 32)
    });
    &VERSION
}

pub async fn serve(Path(name): Path<String>) -> Response {
    let Some((_, mime, body)) = FILES.iter().find(|(file, _, _)| *file == name) else {
        return StatusCode::NOT_FOUND.into_response();
    };
    let mut response = body.into_response();
    let headers = response.headers_mut();
    headers.insert(header::CONTENT_TYPE, HeaderValue::from_static(mime));
    headers.insert(
        header::CACHE_CONTROL,
        HeaderValue::from_static("public, max-age=31536000, immutable"),
    );
    response
}
