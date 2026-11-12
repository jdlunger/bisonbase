pub mod api;
pub mod auth;
pub mod config;
pub mod error;
pub mod oauth;
pub mod ratelimit;
pub mod state;
pub mod storage;
pub mod sysedit;
pub mod system;
pub mod web;

use axum::{
    Router,
    http::{HeaderValue, header},
    middleware,
};
use tower_http::{set_header::SetResponseHeaderLayer, trace::TraceLayer};

pub use state::AppState;

/// Build the full application router.
pub fn app(state: AppState) -> Router {
    Router::new()
        .merge(api::router())
        .merge(web::router(&state))
        .layer(SetResponseHeaderLayer::if_not_present(
            header::X_FRAME_OPTIONS,
            HeaderValue::from_static("DENY"),
        ))
        .layer(SetResponseHeaderLayer::if_not_present(
            header::REFERRER_POLICY,
            HeaderValue::from_static("same-origin"),
        ))
        .layer(SetResponseHeaderLayer::if_not_present(
            header::X_CONTENT_TYPE_OPTIONS,
            HeaderValue::from_static("nosniff"),
        ))
        .layer(middleware::from_fn_with_state(
            state.clone(),
            ratelimit::middleware,
        ))
        .layer(TraceLayer::new_for_http())
        .with_state(state)
}

/// If there are no users yet, create a one-time admin setup invite and return its URL.
pub async fn bootstrap_invite(state: &AppState) -> anyhow::Result<Option<String>> {
    if state.sys.user_count().await? > 0 {
        return Ok(None);
    }
    let token = state
        .sys
        .create_invite(None, true, "initial setup".into(), 24 * 3600)
        .await?;
    Ok(Some(format!("{}/signup?invite={token}", state.cfg.origin)))
}

/// Create a one-time account recovery link for `username` without the server running (or
/// while it runs: system.db can be shared). For when the only admin has lost their passkeys.
pub async fn recovery_link(mut cfg: config::Config, username: &str) -> anyhow::Result<String> {
    use anyhow::Context;

    let port = cfg
        .bind
        .rsplit(':')
        .next()
        .and_then(|p| p.parse().ok())
        .unwrap_or(8080);
    cfg.resolve(port)?;
    let path = cfg.data_dir.join("system.db");
    anyhow::ensure!(path.exists(), "no system.db in {}", cfg.data_dir.display());
    let sys = system::SystemDb::open(&path).context("opening system.db")?;
    let user = sys
        .user_by_name(username.to_string())
        .await?
        .with_context(|| format!("no user named {username:?}"))?;
    let token = sys.create_recovery(None, &user, 24 * 3600).await?;
    Ok(format!("{}/recover?token={token}", cfg.origin))
}

/// A running server, started with [`start`].
pub struct Server {
    addr: std::net::SocketAddr,
    origin: String,
    setup_url: Option<String>,
    shutdown: tokio::sync::oneshot::Sender<()>,
    task: tokio::task::JoinHandle<std::io::Result<()>>,
}

impl Server {
    /// The address the listener is bound to.
    pub fn local_addr(&self) -> std::net::SocketAddr {
        self.addr
    }

    /// The public origin of the web UI, e.g. `http://localhost:8080`.
    pub fn origin(&self) -> &str {
        &self.origin
    }

    /// The one-time admin signup link, if there were no users at startup.
    pub fn setup_url(&self) -> Option<&str> {
        self.setup_url.as_deref()
    }

    /// Stop accepting connections, let in-flight requests finish, and wait for that.
    pub async fn shutdown(self) -> anyhow::Result<()> {
        let _ = self.shutdown.send(());
        Ok(self.task.await??)
    }

    /// Run until `signal` resolves (then shut down gracefully) or the server fails.
    pub async fn run_until(
        mut self,
        signal: impl std::future::Future<Output = ()>,
    ) -> anyhow::Result<()> {
        tokio::select! {
            r = &mut self.task => Ok(r??),
            _ = signal => self.shutdown().await,
        }
    }
}

/// Open the data directory, bind `cfg.bind` and start serving in the background.
///
/// Must be called from inside a Tokio runtime. An empty `cfg.origin` becomes
/// `http://localhost:<bound port>`, so binding port 0 works.
pub async fn start(mut cfg: config::Config) -> anyhow::Result<Server> {
    use anyhow::Context;

    let listener = tokio::net::TcpListener::bind(&cfg.bind)
        .await
        .with_context(|| format!("binding {}", cfg.bind))?;
    let addr = listener.local_addr()?;
    cfg.resolve(addr.port())?;
    std::fs::create_dir_all(cfg.data_dir.join("users")).context("creating data dir")?;
    storage::fs::migrate_legacy_databases(&cfg.data_dir)
        .context("moving databases into user file trees")?;
    let sys =
        system::SystemDb::open(&cfg.data_dir.join("system.db")).context("opening system.db")?;
    let state = AppState::new(cfg, sys)?;

    let setup_url = bootstrap_invite(&state).await?;
    if let Some(url) = &setup_url {
        tracing::warn!("no users exist yet; create the admin account at:\n\n    {url}\n");
    }
    let origin = state.cfg.origin.clone();
    tracing::info!("listening on http://{addr} (public origin {origin})");

    let (shutdown, rx) = tokio::sync::oneshot::channel::<()>();
    let task = tokio::spawn(async move {
        axum::serve(
            listener,
            app(state).into_make_service_with_connect_info::<std::net::SocketAddr>(),
        )
        .with_graceful_shutdown(async {
            let _ = rx.await;
        })
        .await
    });
    Ok(Server {
        addr,
        origin,
        setup_url,
        shutdown,
        task,
    })
}

/// Run a server without managing a Tokio runtime yourself.
pub mod blocking {
    /// A running server with its own Tokio runtime. Dropping it stops the server.
    pub struct Server {
        inner: Option<crate::Server>,
        rt: tokio::runtime::Runtime,
    }

    /// Like [`crate::start`], but callable from ordinary synchronous code.
    pub fn start(cfg: crate::config::Config) -> anyhow::Result<Server> {
        let rt = tokio::runtime::Builder::new_multi_thread()
            .enable_all()
            .build()?;
        let inner = rt.block_on(crate::start(cfg))?;
        Ok(Server {
            inner: Some(inner),
            rt,
        })
    }

    impl Server {
        fn inner(&self) -> &crate::Server {
            self.inner.as_ref().expect("server is running")
        }

        /// The address the listener is bound to.
        pub fn local_addr(&self) -> std::net::SocketAddr {
            self.inner().local_addr()
        }

        /// The public origin of the web UI, e.g. `http://localhost:8080`.
        pub fn origin(&self) -> &str {
            self.inner().origin()
        }

        /// The one-time admin signup link, if there were no users at startup.
        pub fn setup_url(&self) -> Option<&str> {
            self.inner().setup_url()
        }

        /// Stop accepting connections and wait for in-flight requests.
        pub fn shutdown(mut self) -> anyhow::Result<()> {
            let s = self.inner.take().expect("server is running");
            self.rt.block_on(s.shutdown())
        }
    }

    impl Drop for Server {
        fn drop(&mut self) {
            if let Some(s) = self.inner.take() {
                let _ = self.rt.block_on(s.shutdown());
            }
        }
    }
}
