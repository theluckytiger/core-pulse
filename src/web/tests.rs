//! End-to-end tests of the login flow through the real router.

use std::net::SocketAddr;
use std::sync::{Arc, Mutex};

use axum::Router;
use axum::body::{Body, to_bytes};
use axum::extract::connect_info::MockConnectInfo;
use axum::http::{Request, Response, StatusCode, header};
use tower::ServiceExt;

use super::session::{LOGIN_COOKIE, SESSION_COOKIE};
use super::{AppState, router};
use crate::auth::{MAX_FAILURES, password, totp};
use crate::clock;
use crate::config::Config;
use crate::geoip::GeoIp;
use crate::store::Store;

const BASE: &str = "/core-pulse";
const PASSWORD: &str = "correct horse battery";
const SECRET: &[u8] = b"12345678901234567890";

fn app() -> Router {
    let mut store = Store::open_in_memory().unwrap();
    store
        .add_user("admin", &password::hash(PASSWORD).unwrap(), SECRET, 0)
        .unwrap();
    let mut config = Config::default();
    config.server.base_path = BASE.into();
    router(
        AppState::new(
            &config,
            Arc::new(Mutex::new(store)),
            Default::default(),
            GeoIp::open(std::path::Path::new("/nonexistent/country.mmdb")),
            false,
        )
        .unwrap(),
    )
    .layer(MockConnectInfo(SocketAddr::from(([192, 0, 2, 1], 50_000))))
}

async fn send(app: &Router, request: Request<Body>) -> Response<Body> {
    app.clone().oneshot(request).await.unwrap()
}

async fn body(response: Response<Body>) -> String {
    let bytes = to_bytes(response.into_body(), usize::MAX).await.unwrap();
    String::from_utf8_lossy(&bytes).into_owned()
}

fn get(path: &str, cookie: Option<&str>) -> Request<Body> {
    let mut request = Request::get(format!("{BASE}{path}")).header(header::HOST, "example.com");
    if let Some(cookie) = cookie {
        request = request.header(header::COOKIE, cookie);
    }
    request.body(Body::empty()).unwrap()
}

fn post(path: &str, cookie: &str, form: &str, origin: &str) -> Request<Body> {
    post_with(path, cookie, form, &[("origin", origin)])
}

fn post_with(path: &str, cookie: &str, form: &str, extra: &[(&str, &str)]) -> Request<Body> {
    let mut request = Request::post(format!("{BASE}{path}"))
        .header(header::HOST, "example.com")
        .header(header::CONTENT_TYPE, "application/x-www-form-urlencoded")
        .header(header::COOKIE, cookie);
    for (name, value) in extra {
        request = request.header(*name, *value);
    }
    request.body(Body::from(form.to_string())).unwrap()
}

fn cookie_value(response: &Response<Body>, name: &str) -> Option<String> {
    response
        .headers()
        .get_all(header::SET_COOKIE)
        .iter()
        .filter_map(|v| v.to_str().ok())
        .filter_map(|v| v.split(';').next()?.split_once('='))
        .find(|(key, _)| *key == name)
        .map(|(_, value)| value.to_string())
        .filter(|value| !value.is_empty())
}

/// Opens the login form and returns its token.
async fn form_token(app: &Router) -> String {
    let response = send(app, get("/login", None)).await;
    assert_eq!(response.status(), StatusCode::OK);
    cookie_value(&response, LOGIN_COOKIE).unwrap()
}

async fn try_login(app: &Router, password: &str, code: &str) -> Response<Body> {
    let token = form_token(app).await;
    let form = format!(
        "username=admin&password={}&code={code}&csrf={token}",
        password.replace(' ', "+")
    );
    let cookie = format!("{LOGIN_COOKIE}={token}");
    send(app, post("/login", &cookie, &form, "https://example.com")).await
}

fn current_code() -> String {
    totp::code_at(SECRET, clock::now())
}

#[tokio::test]
async fn dashboard_needs_a_login() {
    let app = app();
    let response = send(&app, get("/", None)).await;
    assert_eq!(response.status(), StatusCode::SEE_OTHER);
    assert_eq!(response.headers()[header::LOCATION], "/core-pulse/login");

    let made_up = format!("{SESSION_COOKIE}=not-a-session");
    let response = send(&app, get("/", Some(&made_up))).await;
    assert_eq!(response.status(), StatusCode::SEE_OTHER);
}

#[tokio::test]
async fn password_and_code_open_the_dashboard() {
    let app = app();
    let response = try_login(&app, PASSWORD, &current_code()).await;
    assert_eq!(response.status(), StatusCode::SEE_OTHER);
    let set_cookie = response.headers()[header::SET_COOKIE]
        .to_str()
        .unwrap()
        .to_string();
    assert!(
        set_cookie.contains("HttpOnly")
            && set_cookie.contains("Secure")
            && set_cookie.contains("SameSite=Strict")
    );
    let session = cookie_value(&response, SESSION_COOKIE).unwrap();

    let response = send(&app, get("/", Some(&format!("{SESSION_COOKIE}={session}")))).await;
    assert_eq!(response.status(), StatusCode::OK);
    let headers = response.headers().clone();
    assert!(
        headers[header::CONTENT_SECURITY_POLICY]
            .to_str()
            .unwrap()
            .contains("default-src 'none'")
    );
    assert_eq!(headers[header::CACHE_CONTROL], "no-store");
    assert!(body(response).await.contains("Summary"));
}

#[tokio::test]
async fn a_wrong_code_is_refused() {
    let app = app();
    let wrong = if current_code() == "000000" {
        "111111"
    } else {
        "000000"
    };
    let response = try_login(&app, PASSWORD, wrong).await;
    assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
    assert!(cookie_value(&response, SESSION_COOKIE).is_none());
    assert!(
        body(response)
            .await
            .contains("Wrong username, password or code")
    );
}

#[tokio::test]
async fn repeated_failures_lock_the_account() {
    let app = app();
    for _ in 0..MAX_FAILURES {
        let response = try_login(&app, "wrong password!!", "000000").await;
        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
    }
    // The right password and code no longer work while locked.
    let response = try_login(&app, PASSWORD, &current_code()).await;
    assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
    assert!(cookie_value(&response, SESSION_COOKIE).is_none());
}

#[tokio::test]
async fn too_many_attempts_from_one_address_are_slowed_down() {
    let app = app();
    let mut last = StatusCode::OK;
    for _ in 0..=super::LOGIN_ATTEMPTS {
        last = try_login(&app, "wrong password!!", "000000").await.status();
    }
    assert_eq!(last, StatusCode::TOO_MANY_REQUESTS);
}

#[tokio::test]
async fn login_needs_the_form_token() {
    let app = app();
    let token = form_token(&app).await;
    let form = format!("username=admin&password=x&code=000000&csrf=forged{token}");
    let cookie = format!("{LOGIN_COOKIE}={token}");
    let response = send(&app, post("/login", &cookie, &form, "https://example.com")).await;
    assert_eq!(response.status(), StatusCode::FORBIDDEN);
}

#[tokio::test]
async fn cross_site_posts_are_refused() {
    let app = app();
    let token = form_token(&app).await;
    let form = format!("username=admin&password=x&code=000000&csrf={token}");
    let cookie = format!("{LOGIN_COOKIE}={token}");
    let response = send(
        &app,
        post("/login", &cookie, &form, "https://evil.example.net"),
    )
    .await;
    assert_eq!(response.status(), StatusCode::FORBIDDEN);
}

/// What a browser with a strict referrer setting sends from our own form.
#[tokio::test]
async fn login_works_when_the_browser_hides_the_origin() {
    let app = app();
    let token = form_token(&app).await;
    let form = format!(
        "username=admin&password={}&code={}&csrf={token}",
        PASSWORD.replace(' ', "+"),
        current_code()
    );
    let cookie = format!("{LOGIN_COOKIE}={token}");
    let browser = [("origin", "null"), ("sec-fetch-site", "same-origin")];
    let response = send(&app, post_with("/login", &cookie, &form, &browser)).await;
    assert_eq!(response.status(), StatusCode::SEE_OTHER);
    assert!(cookie_value(&response, SESSION_COOKIE).is_some());

    let token = form_token(&app).await;
    let form = format!("username=admin&password=x&code=000000&csrf={token}");
    let cookie = format!("{LOGIN_COOKIE}={token}");
    let other_site = [("origin", "null"), ("sec-fetch-site", "cross-site")];
    let response = send(&app, post_with("/login", &cookie, &form, &other_site)).await;
    assert_eq!(response.status(), StatusCode::FORBIDDEN);
}

#[tokio::test]
async fn logout_ends_the_session() {
    let app = app();
    let response = try_login(&app, PASSWORD, &current_code()).await;
    let session = format!(
        "{SESSION_COOKIE}={}",
        cookie_value(&response, SESSION_COOKIE).unwrap()
    );

    let page = body(send(&app, get("/", Some(&session))).await).await;
    let csrf = page
        .split("name=\"csrf\" value=\"")
        .nth(1)
        .and_then(|rest| rest.split('"').next())
        .unwrap()
        .to_string();

    let forged = send(
        &app,
        post("/logout", &session, "csrf=wrong", "https://example.com"),
    )
    .await;
    assert_eq!(forged.status(), StatusCode::FORBIDDEN);

    let response = send(
        &app,
        post(
            "/logout",
            &session,
            &format!("csrf={csrf}"),
            "https://example.com",
        ),
    )
    .await;
    assert_eq!(response.status(), StatusCode::SEE_OTHER);
    let response = send(&app, get("/", Some(&session))).await;
    assert_eq!(response.status(), StatusCode::SEE_OTHER);
}

#[tokio::test]
async fn health_and_static_files_need_no_login() {
    let app = app();
    assert_eq!(
        send(&app, get("/healthz", None)).await.status(),
        StatusCode::OK
    );
    let response = send(&app, get("/static/app.css", None)).await;
    assert_eq!(response.status(), StatusCode::OK);
    assert!(
        response.headers()[header::CACHE_CONTROL]
            .to_str()
            .unwrap()
            .contains("immutable")
    );
    assert_eq!(
        send(&app, get("/static/missing.js", None)).await.status(),
        StatusCode::NOT_FOUND
    );
}
