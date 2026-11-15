//! Session cookies and the check that guards every dashboard route.

use axum::extract::{Request, State};
use axum::http::{HeaderMap, HeaderValue, header};
use axum::middleware::Next;
use axum::response::{IntoResponse, Redirect, Response};
use subtle::ConstantTimeEq;

use super::AppState;
use crate::{auth, clock};

pub const SESSION_COOKIE: &str = "__Secure-cp_session";
pub const LOGIN_COOKIE: &str = "__Secure-cp_login";

/// The signed-in user, for handlers behind `require`.
#[derive(Clone)]
pub struct CurrentUser {
    pub username: String,
    pub csrf_token: String,
    pub token: String,
}

pub async fn require(State(state): State<AppState>, mut request: Request, next: Next) -> Response {
    if state.0.demo {
        request.extensions_mut().insert(CurrentUser {
            username: "demo".into(),
            csrf_token: "demo".into(),
            token: String::new(),
        });
        return next.run(request).await;
    }

    let Some(token) = cookie(request.headers(), SESSION_COOKIE) else {
        return to_login(&state, request.headers());
    };
    let lookup = token.clone();
    match state
        .db(move |store| auth::session(store, &lookup, clock::now()))
        .await
    {
        Ok(Some(session)) => {
            request.extensions_mut().insert(CurrentUser {
                username: session.username,
                csrf_token: session.csrf_token,
                token,
            });
            next.run(request).await
        }
        Ok(None) => to_login(&state, request.headers()),
        Err(e) => e.into_response(),
    }
}

/// htmx follows HX-Redirect; normal page loads get a plain redirect.
fn to_login(state: &AppState, headers: &HeaderMap) -> Response {
    let login = state.path("/login");
    if headers.contains_key("hx-request") {
        let mut response = ().into_response();
        if let Ok(value) = HeaderValue::from_str(&login) {
            response.headers_mut().insert("hx-redirect", value);
        }
        return response;
    }
    Redirect::to(&login).into_response()
}

pub fn cookie(headers: &HeaderMap, name: &str) -> Option<String> {
    headers
        .get_all(header::COOKIE)
        .iter()
        .filter_map(|v| v.to_str().ok())
        .flat_map(|v| v.split(';'))
        .filter_map(|pair| pair.trim().split_once('='))
        .find(|(key, _)| *key == name)
        .map(|(_, value)| value.to_string())
        .filter(|value| !value.is_empty())
}

/// A Set-Cookie value. Secure, HttpOnly and SameSite=Strict always.
pub fn set_cookie(name: &str, value: &str, path: &str, max_age: i64) -> HeaderValue {
    let cookie = format!(
        "{name}={value}; Path={path}; Max-Age={max_age}; Secure; HttpOnly; SameSite=Strict"
    );
    HeaderValue::from_str(&cookie).unwrap_or_else(|_| HeaderValue::from_static(""))
}

pub fn tokens_match(a: &str, b: &str) -> bool {
    !a.is_empty() && bool::from(a.as_bytes().ct_eq(b.as_bytes()))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn reads_cookies() {
        let mut headers = HeaderMap::new();
        headers.insert(
            header::COOKIE,
            "a=1; __Secure-cp_session=abc; b=".parse().unwrap(),
        );
        assert_eq!(cookie(&headers, SESSION_COOKIE).as_deref(), Some("abc"));
        assert_eq!(cookie(&headers, "b"), None);
        assert_eq!(cookie(&headers, "missing"), None);
    }

    #[test]
    fn compares_tokens() {
        assert!(tokens_match("abc", "abc"));
        assert!(!tokens_match("abc", "abd"));
        assert!(!tokens_match("", ""));
    }
}
