//! HTTP server: login, dashboards and live updates.

mod assets;
mod headers;
mod login;
mod overview;
mod pages;
mod session;
mod sse;
mod view;

use std::collections::{BTreeMap, HashSet};
use std::net::{IpAddr, SocketAddr};
use std::sync::{Arc, Mutex};

use anyhow::{Context, Result, anyhow};
use axum::Router;
use axum::extract::State;
use axum::http::{HeaderMap, StatusCode};
use axum::response::{IntoResponse, Redirect, Response};
use axum::routing::{get, post};
use axum::{middleware, response::Html};
use ipnet::IpNet;
use tokio::net::TcpListener;
use tokio::sync::Semaphore;
use tokio::task::JoinSet;

use crate::auth::Limiter;
use crate::clock::MINUTE;
use crate::config::Config;
use crate::geoip::GeoIp;
use crate::net;
use crate::probes::ProbeMatcher;
use crate::store::Store;

/// Login attempts per address per window.
const LOGIN_ATTEMPTS: u32 = 10;
const LOGIN_WINDOW: i64 = 15 * MINUTE;

#[derive(Clone)]
pub struct AppState(Arc<Inner>);

struct Inner {
    store: Arc<Mutex<Store>>,
    network: net::Live,
    base: String,
    trusted_proxies: Vec<IpNet>,
    limiter: Limiter,
    /// Password hashing is slow on purpose; bound how many run at once.
    logins: Semaphore,
    demo: bool,
    raw_days: u32,
    /// The probe rules, to tell an answered attack from an ignored one.
    probes: ProbeMatcher,
    geo: GeoIp,
    ssh_keys: BTreeMap<String, String>,
    customer_apps: HashSet<String>,
}

impl AppState {
    pub fn new(
        config: &Config,
        store: Arc<Mutex<Store>>,
        network: net::Live,
        geo: GeoIp,
        demo: bool,
    ) -> Result<Self> {
        Ok(Self(Arc::new(Inner {
            store,
            network,
            base: config.server.base_path.clone(),
            trusted_proxies: config.server.trusted_proxies.clone(),
            limiter: Limiter::new(LOGIN_ATTEMPTS, LOGIN_WINDOW),
            logins: Semaphore::new(2),
            demo,
            raw_days: config.storage.raw_retention_days,
            probes: ProbeMatcher::new(&config.probes)?,
            geo,
            ssh_keys: config.ssh_keys.clone(),
            customer_apps: config
                .nginx
                .iter()
                .flat_map(|source| &source.logins)
                .filter(|form| !form.staff)
                .map(|form| form.name.clone())
                .collect(),
        })))
    }

    /// Runs a database call on the blocking thread pool.
    async fn db<T, F>(&self, call: F) -> Result<T, AppError>
    where
        T: Send + 'static,
        F: FnOnce(&Store) -> Result<T> + Send + 'static,
    {
        let store = self.0.store.clone();
        tokio::task::spawn_blocking(move || {
            let store = store
                .lock()
                .map_err(|_| anyhow!("database lock poisoned"))?;
            call(&store)
        })
        .await
        .map_err(|e| AppError(anyhow!("database task failed: {e}")))?
        .map_err(AppError)
    }

    fn path(&self, path: &str) -> String {
        format!("{}{path}", self.0.base)
    }

    /// The visitor address: X-Real-IP when the request came through our
    /// own reverse proxy, otherwise the connecting address.
    fn client_ip(&self, peer: SocketAddr, headers: &HeaderMap) -> IpAddr {
        let peer = peer.ip();
        if self.0.trusted_proxies.iter().any(|net| net.contains(&peer)) {
            let real = headers
                .get("x-real-ip")
                .and_then(|v| v.to_str().ok())
                .and_then(|v| v.trim().parse().ok());
            if let Some(ip) = real {
                return ip;
            }
        }
        peer
    }
}

/// Logs the real error and shows the visitor nothing about it.
pub struct AppError(anyhow::Error);

impl IntoResponse for AppError {
    fn into_response(self) -> Response {
        tracing::error!("request failed: {:#}", self.0);
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            Html(view::error_page("Something went wrong.")),
        )
            .into_response()
    }
}

pub fn router(state: AppState) -> Router {
    let p = |path: &str| state.path(path);

    let protected = Router::new()
        .route(&p("/"), get(pages::overview))
        .route(&p("/traffic"), get(pages::traffic))
        .route(&p("/security"), get(pages::security))
        .route(&p("/network"), get(pages::network))
        .route(&p("/fragments/overview"), get(pages::overview_fragment))
        .route(&p("/fragments/traffic"), get(pages::traffic_fragment))
        .route(&p("/fragments/security"), get(pages::security_fragment))
        .route(&p("/fragments/network"), get(pages::network_fragment))
        .route(&p("/events"), get(sse::events))
        .route(&p("/logout"), post(login::logout))
        .route_layer(middleware::from_fn_with_state(
            state.clone(),
            session::require,
        ));

    let mut public = Router::new()
        .route(&p("/login"), get(login::page).post(login::submit))
        .route(&p("/static/{file}"), get(assets::serve))
        .route(&p("/healthz"), get(healthz));
    if !state.0.base.is_empty() {
        let home = p("/");
        public = public.route(
            &state.0.base,
            get(move || async move { Redirect::to(&home) }),
        );
    }

    public
        .merge(protected)
        .layer(middleware::from_fn(headers::secure))
        .with_state(state)
}

pub async fn serve(
    config: &Config,
    store: Arc<Mutex<Store>>,
    network: net::Live,
    geo: GeoIp,
    demo: bool,
) -> Result<()> {
    let app = router(AppState::new(config, store, network, geo, demo)?);

    let mut servers = JoinSet::new();
    for addr in &config.server.listen {
        let listener = TcpListener::bind(addr)
            .await
            .with_context(|| format!("cannot listen on {addr}"))?;
        tracing::info!("listening on http://{addr}{}/", config.server.base_path);
        let app = app
            .clone()
            .into_make_service_with_connect_info::<SocketAddr>();
        servers.spawn(async move {
            axum::serve(listener, app)
                .with_graceful_shutdown(shutdown_signal())
                .await
        });
    }

    while let Some(result) = servers.join_next().await {
        result
            .context("server task panicked")?
            .context("server error")?;
    }
    Ok(())
}

async fn healthz(State(state): State<AppState>) -> StatusCode {
    match state.db(|store| store.ping()).await {
        Ok(()) => StatusCode::OK,
        Err(_) => StatusCode::SERVICE_UNAVAILABLE,
    }
}

/// Resolves on Ctrl+C or SIGTERM (what systemd sends on stop).
async fn shutdown_signal() {
    let ctrl_c = async {
        let _ = tokio::signal::ctrl_c().await;
    };

    #[cfg(unix)]
    let terminate = async {
        use tokio::signal::unix::{SignalKind, signal};
        match signal(SignalKind::terminate()) {
            Ok(mut sigterm) => {
                sigterm.recv().await;
            }
            Err(_) => std::future::pending::<()>().await,
        }
    };
    #[cfg(not(unix))]
    let terminate = std::future::pending::<()>();

    tokio::select! {
        _ = ctrl_c => {}
        _ = terminate => {}
    }
    tracing::info!("shutting down");
}

#[cfg(test)]
mod tests;
