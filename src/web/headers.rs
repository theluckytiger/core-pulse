//! Security headers on every response, and a same-origin check for every
//! request that changes something.

use axum::extract::Request;
use axum::http::{HeaderMap, HeaderValue, Method, StatusCode, header};
use axum::middleware::Next;
use axum::response::{IntoResponse, Response};

/// Everything is served by core-pulse itself: no inline scripts, no third parties.
const CSP: &str = "default-src 'none'; script-src 'self'; style-src 'self'; img-src 'self' data:; \
                   connect-src 'self'; font-src 'self'; form-action 'self'; frame-ancestors 'none'; \
                   base-uri 'none'";

pub async fn secure(request: Request, next: Next) -> Response {
    if !same_origin(request.method(), request.headers()) {
        return (StatusCode::FORBIDDEN, "cross-site request refused").into_response();
    }
    let is_static = request.uri().path().contains("/static/");
    let mut response = next.run(request).await;

    let headers = response.headers_mut();
    let set = |headers: &mut HeaderMap, name, value: &'static str| {
        headers.insert(name, HeaderValue::from_static(value));
    };
    set(headers, header::CONTENT_SECURITY_POLICY, CSP);
    set(headers, header::X_CONTENT_TYPE_OPTIONS, "nosniff");
    set(headers, header::X_FRAME_OPTIONS, "DENY");
    // Not "no-referrer": with it, browsers send `Origin: null` on our own forms.
    set(headers, header::REFERRER_POLICY, "same-origin");
    set(
        headers,
        header::HeaderName::from_static("cross-origin-opener-policy"),
        "same-origin",
    );
    set(
        headers,
        header::HeaderName::from_static("cross-origin-resource-policy"),
        "same-origin",
    );
    set(
        headers,
        header::HeaderName::from_static("permissions-policy"),
        "camera=(), microphone=(), geolocation=(), payment=(), usb=()",
    );
    if !is_static {
        // Dashboards hold private data: never keep them in any cache.
        set(headers, header::CACHE_CONTROL, "no-store");
    }
    response
}

/// Requests that change state must come from our own pages. Current browsers
/// say so in Sec-Fetch-Site, which pages cannot set. Older ones only send
/// Origin, which must then match the host.
fn same_origin(method: &Method, headers: &HeaderMap) -> bool {
    if matches!(*method, Method::GET | Method::HEAD | Method::OPTIONS) {
        return true;
    }
    let get = |name: &str| headers.get(name).and_then(|v| v.to_str().ok());
    if let Some(site) = get("sec-fetch-site") {
        // "none" means the user did it directly, such as reloading a page.
        return matches!(site, "same-origin" | "none");
    }
    match get("origin") {
        Some(origin) => {
            let origin_host = origin.split_once("://").map(|(_, rest)| rest);
            origin_host.is_some() && origin_host == get("host")
        }
        // Without Origin the CSRF token still has to match.
        None => true,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn headers(host: &str, origin: Option<&str>) -> HeaderMap {
        let mut h = HeaderMap::new();
        h.insert(header::HOST, host.parse().unwrap());
        if let Some(origin) = origin {
            h.insert(header::ORIGIN, origin.parse().unwrap());
        }
        h
    }

    fn from_site(origin: &str, site: &str) -> HeaderMap {
        let mut h = headers("example.com", Some(origin));
        h.insert("sec-fetch-site", site.parse().unwrap());
        h
    }

    #[test]
    fn trusts_sec_fetch_site_over_origin() {
        // A strict referrer setting turns Origin into "null" on our own form.
        assert!(same_origin(
            &Method::POST,
            &from_site("null", "same-origin")
        ));
        assert!(same_origin(&Method::POST, &from_site("null", "none")));
        for site in ["cross-site", "same-site"] {
            assert!(!same_origin(
                &Method::POST,
                &from_site("https://example.com", site)
            ));
        }
    }

    #[test]
    fn allows_same_origin_posts_only() {
        assert!(same_origin(
            &Method::POST,
            &headers("example.com", Some("https://example.com"))
        ));
        assert!(!same_origin(
            &Method::POST,
            &headers("example.com", Some("https://evil.example.net"))
        ));
        assert!(!same_origin(
            &Method::POST,
            &headers("example.com", Some("null"))
        ));
        assert!(same_origin(
            &Method::GET,
            &headers("example.com", Some("https://evil.example.net"))
        ));
    }
}
