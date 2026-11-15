//! Login and logout.
//!
//! Failed logins are logged as
//!   login failed for user "admin" from 203.0.113.5
//! which a fail2ban filter can match.

use std::net::SocketAddr;

use axum::extract::{ConnectInfo, Extension, Form, State};
use axum::http::{HeaderMap, StatusCode, header};
use axum::response::{Html, IntoResponse, Redirect, Response};
use serde::Deserialize;

use super::session::{self, CurrentUser, LOGIN_COOKIE, SESSION_COOKIE};
use super::{AppError, AppState, view};
use crate::auth::{self, LoginError};
use crate::event::{SecurityEvent, SecurityKind};
use crate::{clock, device};

const LOGIN_FORM_LIFETIME: i64 = 15 * 60;

#[derive(Deserialize)]
pub struct LoginForm {
    username: String,
    password: String,
    code: String,
    csrf: String,
}

#[derive(Deserialize)]
pub struct LogoutForm {
    csrf: String,
}

pub async fn page(State(state): State<AppState>) -> Result<Response, AppError> {
    login_page(&state, None, StatusCode::OK)
}

/// Shows the form with a fresh token, set in a cookie as well. The two must
/// match on submit, so another site cannot post a login for the visitor.
fn login_page(
    state: &AppState,
    error: Option<&str>,
    status: StatusCode,
) -> Result<Response, AppError> {
    let token = auth::random_token().map_err(AppError)?;
    let html = view::login_page(&state.0.base, &token, error);
    let mut response = (status, Html(html)).into_response();
    response.headers_mut().insert(
        header::SET_COOKIE,
        session::set_cookie(
            LOGIN_COOKIE,
            &token,
            &state.path("/login"),
            LOGIN_FORM_LIFETIME,
        ),
    );
    Ok(response)
}

pub async fn submit(
    State(state): State<AppState>,
    ConnectInfo(peer): ConnectInfo<SocketAddr>,
    headers: HeaderMap,
    Form(form): Form<LoginForm>,
) -> Result<Response, AppError> {
    let expected = session::cookie(&headers, LOGIN_COOKIE).unwrap_or_default();
    if !session::tokens_match(&expected, &form.csrf) {
        return login_page(
            &state,
            Some("The form expired. Please try again."),
            StatusCode::FORBIDDEN,
        );
    }

    let ip = state.client_ip(peer, &headers);
    if !state.0.limiter.allow(ip, clock::now()) {
        tracing::warn!("login rate limited for {ip}");
        let message = "Too many attempts from your address. Wait a few minutes.";
        return login_page(&state, Some(message), StatusCode::TOO_MANY_REQUESTS);
    }

    let _slot = state
        .0
        .logins
        .acquire()
        .await
        .map_err(|e| AppError(anyhow::anyhow!("{e}")))?;
    let username: String = form.username.trim().chars().take(64).collect();
    let device = headers
        .get(header::USER_AGENT)
        .and_then(|v| v.to_str().ok())
        .map_or_else(|| "Unknown".to_string(), device::describe);
    let (name, client) = (username.clone(), ip.to_string());
    let result = state
        .db(move |store| {
            auth::login(
                store,
                &name,
                &form.password,
                &form.code,
                &client,
                clock::now(),
            )
        })
        .await?;

    let kind = if result.is_ok() {
        SecurityKind::Login
    } else {
        SecurityKind::LoginFail
    };
    let event = SecurityEvent {
        ts: clock::now(),
        kind,
        source: "core-pulse".into(),
        ip,
        port: None,
        detail: Some(format!("{username} · {device}")),
    };
    if let Err(e) = state.db(move |store| store.record(&event)).await {
        tracing::warn!("could not record the sign-in: {:#}", e.0);
    }

    match result {
        Ok(signed_in) => {
            tracing::info!("login for user {username:?} from {ip}");
            let mut response = Redirect::to(&state.path("/")).into_response();
            let lifetime = signed_in.expires - clock::now();
            let cookies = response.headers_mut();
            cookies.append(
                header::SET_COOKIE,
                session::set_cookie(SESSION_COOKIE, &signed_in.token, &state.path("/"), lifetime),
            );
            cookies.append(
                header::SET_COOKIE,
                session::set_cookie(LOGIN_COOKIE, "", &state.path("/login"), 0),
            );
            Ok(response)
        }
        Err(reason) => {
            match reason {
                LoginError::Invalid => {
                    tracing::warn!("login failed for user {username:?} from {ip}")
                }
                LoginError::Locked => {
                    tracing::warn!("login failed for user {username:?} from {ip} (locked)")
                }
            }
            let message = "Wrong username, password or code, or too many failed attempts.";
            login_page(&state, Some(message), StatusCode::UNAUTHORIZED)
        }
    }
}

pub async fn logout(
    State(state): State<AppState>,
    Extension(user): Extension<CurrentUser>,
    Form(form): Form<LogoutForm>,
) -> Result<Response, AppError> {
    if !session::tokens_match(&user.csrf_token, &form.csrf) {
        return Ok((
            StatusCode::FORBIDDEN,
            Html(view::error_page("The form expired. Reload the page.")),
        )
            .into_response());
    }
    let token = user.token.clone();
    state.db(move |store| auth::logout(store, &token)).await?;
    tracing::info!("logout for user {:?}", user.username);

    let mut response = Redirect::to(&state.path("/login")).into_response();
    response.headers_mut().insert(
        header::SET_COOKIE,
        session::set_cookie(SESSION_COOKIE, "", &state.path("/"), 0),
    );
    Ok(response)
}
