//! N-API bindings: start and stop a bisonbase server inside a Node.js process.

use napi::bindgen_prelude::*;
use napi_derive::napi;
use tokio::sync::Mutex;
use bisonbase::config::Config;

/// Options for `start()`. Every field is optional.
#[napi(object)]
pub struct StartOptions {
    /// Port to listen on (on 127.0.0.1); 0 picks a free one (default 8080).
    pub port: Option<u32>,
    /// Directory for system.db and user files (default "./data").
    pub data_dir: Option<String>,
    /// Log filter in `RUST_LOG` syntax (default "bisonbase=info"), or "off".
    /// Logging is set up by the first `start()` in a process.
    pub log: Option<String>,
}

fn config(o: StartOptions) -> Config {
    let mut cfg = Config::default();
    if let Some(port) = o.port {
        cfg.bind = format!("127.0.0.1:{port}");
    }
    if let Some(v) = o.data_dir {
        cfg.data_dir = v.into();
    }
    cfg
}

fn init_logging(filter: Option<&str>) {
    let filter = filter.unwrap_or("bisonbase=info");
    if filter == "off" {
        return;
    }
    // Only the first call in a process installs a subscriber; later ones are no-ops.
    let _ = tracing_subscriber::fmt()
        .with_env_filter(tracing_subscriber::EnvFilter::new(filter))
        .try_init();
}

fn err(e: anyhow::Error) -> Error {
    Error::from_reason(format!("{e:#}"))
}

/// Start a server. Resolves once it is listening.
#[napi]
pub async fn start(options: Option<StartOptions>) -> Result<NativeServer> {
    let mut o = options.unwrap_or(StartOptions {
        port: None,
        data_dir: None,
        log: None,
    });
    let log = o.log.take();
    init_logging(log.as_deref());
    let cfg = config(o);
    let server = bisonbase::start(cfg).await.map_err(err)?;
    let addr = server.local_addr();
    Ok(NativeServer {
        host: addr.ip().to_string(),
        port: addr.port() as u32,
        url: server.origin().to_string(),
        setup_url: server.setup_url().map(str::to_string),
        inner: Mutex::new(Some(server)),
    })
}

/// A running server. Use the JavaScript wrapper's `Server` instead of this directly.
#[napi]
pub struct NativeServer {
    host: String,
    port: u32,
    url: String,
    setup_url: Option<String>,
    inner: Mutex<Option<bisonbase::Server>>,
}

#[napi]
impl NativeServer {
    #[napi(getter)]
    pub fn host(&self) -> String {
        self.host.clone()
    }

    #[napi(getter)]
    pub fn port(&self) -> u32 {
        self.port
    }

    #[napi(getter)]
    pub fn url(&self) -> String {
        self.url.clone()
    }

    #[napi(getter)]
    pub fn setup_url(&self) -> Option<String> {
        self.setup_url.clone()
    }

    /// Stop accepting connections and wait for in-flight requests. Idempotent.
    #[napi]
    pub async fn close(&self) -> Result<()> {
        match self.inner.lock().await.take() {
            Some(s) => s.shutdown().await.map_err(err),
            None => Ok(()),
        }
    }
}
