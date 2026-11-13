use std::path::PathBuf;

/// Server settings. Everything has a sensible default; embedders override only what they need.
#[derive(Debug, Clone)]
pub struct Config {
    /// Address to listen on.
    pub bind: String,
    /// Root directory for system.db and user data.
    pub data_dir: PathBuf,
    /// Public origin of the web UI (scheme://host[:port]); used for WebAuthn and CSRF checks.
    /// Empty means `http://localhost:<bound port>`.
    pub origin: String,
    /// WebAuthn relying party id. Empty means the host name of `origin`.
    pub rp_id: String,
    /// Human-readable relying party name shown by authenticators.
    pub rp_name: String,
    /// Set the `Secure` attribute on the session cookie.
    pub cookie_secure: bool,
    pub limits: Limits,
    pub rate_limit: crate::ratelimit::RateLimitConfig,
}

#[derive(Debug, Clone)]
pub struct Limits {
    pub user_quota_bytes: u64,
    /// Storage for each registered app's own databases and files (shared by its users).
    pub app_quota_bytes: u64,
    pub max_upload_bytes: u64,
    pub max_db_bytes: u64,
    pub query_timeout_ms: u64,
    pub max_result_rows: usize,
}

impl Default for Config {
    fn default() -> Self {
        Self {
            bind: "127.0.0.1:8080".into(),
            data_dir: "./data".into(),
            origin: String::new(),
            rp_id: String::new(),
            rp_name: "bisonbase".into(),
            cookie_secure: false,
            limits: Limits::default(),
            rate_limit: Default::default(),
        }
    }
}

impl Default for Limits {
    fn default() -> Self {
        Self {
            user_quota_bytes: 1 << 30,
            app_quota_bytes: 1 << 30,
            max_upload_bytes: 100 << 20,
            max_db_bytes: 256 << 20,
            query_timeout_ms: 5000,
            max_result_rows: 10_000,
        }
    }
}

impl Config {
    /// Fill in an empty `origin` (from the port actually bound) and an empty `rp_id`
    /// (from the host name of `origin`).
    pub fn resolve(&mut self, port: u16) -> anyhow::Result<()> {
        if self.origin.is_empty() {
            self.origin = format!("http://localhost:{port}");
        }
        self.origin = self.origin.trim_end_matches('/').to_string();
        if self.rp_id.is_empty() {
            let url = webauthn_rs::prelude::Url::parse(&self.origin)
                .map_err(|e| anyhow::anyhow!("invalid origin {:?}: {e}", self.origin))?;
            self.rp_id = url
                .host_str()
                .ok_or_else(|| anyhow::anyhow!("origin {:?} has no host", self.origin))?
                .to_string();
        }
        Ok(())
    }
}
