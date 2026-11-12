//! Lightweight in-memory rate limiting (token buckets, one process).
//!
//! Two budgets, each "N requests per minute, with bursts of up to N":
//!
//! - **auth**: passkey ceremonies, account recovery and the OAuth endpoints, per client IP.
//!   These are the endpoints worth brute-forcing or flooding.
//! - **api**: the `/api/v1` file and database API, per bearer token (per client IP for
//!   requests without one).
//!
//! The web UI's own pages aren't limited: they need a session, which needs a passkey login.
//! Behind a reverse proxy every request comes from the proxy's address, so set
//! `trust_proxy_headers` to key on `X-Forwarded-For` / `X-Real-IP` instead.

use std::{
    collections::HashMap,
    net::{IpAddr, SocketAddr},
    sync::Mutex,
    time::{Duration, Instant},
};

use axum::{
    extract::{ConnectInfo, Request, State},
    http::{HeaderMap, HeaderValue, Method, header},
    middleware::Next,
    response::{IntoResponse, Response},
};
use serde_json::json;
use sha2::{Digest, Sha256};

use crate::state::AppState;

#[derive(Debug, Clone)]
pub struct RateLimitConfig {
    /// Requests per minute per client IP to login, signup, recovery and OAuth endpoints.
    /// 0 disables the limit.
    pub auth_per_minute: u32,
    /// Requests per minute per API token (or per client IP without one) to `/api/v1`.
    /// 0 disables the limit.
    pub api_per_minute: u32,
    /// Take the client IP from `X-Forwarded-For` (its last entry, the one your proxy added) or
    /// `X-Real-IP`. Only enable this behind a reverse proxy that sets those headers, or clients
    /// can pick their own IP.
    pub trust_proxy_headers: bool,
}

impl Default for RateLimitConfig {
    fn default() -> Self {
        Self {
            auth_per_minute: 30,
            api_per_minute: 1200,
            trust_proxy_headers: false,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
enum Kind {
    Auth,
    Api,
}

/// Which budget, if any, a request draws from.
fn classify(method: &Method, path: &str) -> Option<Kind> {
    if path.starts_with("/api/") {
        return (method != Method::OPTIONS).then_some(Kind::Api);
    }
    let auth = path.starts_with("/auth/")
        || path == "/oauth/token"
        || path == "/oauth/revoke"
        || path == "/oauth/authorize";
    (auth && method == Method::POST).then_some(Kind::Auth)
}

struct Bucket {
    tokens: f64,
    at: Instant,
}

#[derive(Default)]
pub struct RateLimiter {
    buckets: Mutex<Buckets>,
}

#[derive(Default)]
struct Buckets {
    map: HashMap<(Kind, String), Bucket>,
    swept: Option<Instant>,
}

const SWEEP_EVERY: Duration = Duration::from_secs(60);
const SWEEP_ABOVE: usize = 10_000;

impl RateLimiter {
    /// Take one token from `key`'s bucket. On refusal, returns how long until one is available.
    fn take(&self, kind: Kind, key: String, per_minute: u32) -> Result<(), Duration> {
        let cap = per_minute as f64;
        let rate = cap / 60.0;
        let now = Instant::now();
        let mut b = self.buckets.lock().unwrap_or_else(|p| p.into_inner());
        if b.map.len() > SWEEP_ABOVE && b.swept.is_none_or(|t| now - t > SWEEP_EVERY) {
            // Forget buckets that have refilled; they're indistinguishable from new ones.
            b.map
                .retain(|_, v| v.tokens + (now - v.at).as_secs_f64() * rate < cap);
            b.swept = Some(now);
        }
        let e = b.map.entry((kind, key)).or_insert(Bucket {
            tokens: cap,
            at: now,
        });
        e.tokens = (e.tokens + (now - e.at).as_secs_f64() * rate).min(cap);
        e.at = now;
        if e.tokens >= 1.0 {
            e.tokens -= 1.0;
            Ok(())
        } else {
            Err(Duration::from_secs_f64((1.0 - e.tokens) / rate))
        }
    }
}

/// The client's IP: the socket peer, or a proxy header when configured to trust them.
fn client_ip(req: &Request, trust_proxy: bool) -> Option<IpAddr> {
    if trust_proxy && let Some(ip) = forwarded_ip(req.headers()) {
        return Some(ip);
    }
    req.extensions()
        .get::<ConnectInfo<SocketAddr>>()
        .map(|c| c.0.ip())
}

fn forwarded_ip(h: &HeaderMap) -> Option<IpAddr> {
    // Only the last entry was added by our proxy; earlier ones come from the client.
    let last_forwarded = h
        .get_all("x-forwarded-for")
        .iter()
        .next_back()
        .and_then(|v| v.to_str().ok())
        .and_then(|v| v.rsplit(',').next())
        .and_then(|s| s.trim().parse().ok());
    last_forwarded.or_else(|| {
        h.get("x-real-ip")
            .and_then(|v| v.to_str().ok())
            .and_then(|s| s.trim().parse().ok())
    })
}

/// Group IPv6 clients by /64, since one host usually controls a whole /64.
fn ip_key(ip: Option<IpAddr>) -> String {
    match ip {
        Some(IpAddr::V4(v4)) => v4.to_string(),
        Some(IpAddr::V6(v6)) => match v6.to_ipv4_mapped() {
            Some(v4) => v4.to_string(),
            None => {
                let s = v6.segments();
                format!("{:x}:{:x}:{:x}:{:x}::/64", s[0], s[1], s[2], s[3])
            }
        },
        None => "unknown".into(),
    }
}

pub async fn middleware(State(state): State<AppState>, req: Request, next: Next) -> Response {
    let cfg = &state.cfg.rate_limit;
    let Some(kind) = classify(req.method(), req.uri().path()) else {
        return next.run(req).await;
    };
    let per_minute = match kind {
        Kind::Auth => cfg.auth_per_minute,
        Kind::Api => cfg.api_per_minute,
    };
    if per_minute == 0 {
        return next.run(req).await;
    }
    let bearer = req
        .headers()
        .get(header::AUTHORIZATION)
        .and_then(|v| v.to_str().ok())
        .and_then(|v| v.strip_prefix("Bearer "));
    let key = match (kind, bearer) {
        // Key on a hash so the limiter never holds tokens themselves.
        (Kind::Api, Some(t)) => format!("token:{}", hex::encode(&Sha256::digest(t)[..12])),
        _ => ip_key(client_ip(&req, cfg.trust_proxy_headers)),
    };
    match state.limiter.take(kind, key.clone(), per_minute) {
        Ok(()) => next.run(req).await,
        Err(wait) => {
            tracing::debug!(?kind, %key, "rate limited");
            too_many(wait)
        }
    }
}

fn too_many(wait: Duration) -> Response {
    let secs = wait.as_secs().max(1);
    let body = json!({ "error": {
        "code": "rate_limited",
        "message": format!("too many requests; try again in {secs} s"),
    }});
    let mut res = (axum::http::StatusCode::TOO_MANY_REQUESTS, axum::Json(body)).into_response();
    res.headers_mut()
        .insert(header::RETRY_AFTER, HeaderValue::from(secs));
    // The API's CORS layer sits inside this one, so add the header browsers need to read this.
    res.headers_mut().insert(
        header::ACCESS_CONTROL_ALLOW_ORIGIN,
        HeaderValue::from_static("*"),
    );
    res
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn buckets_refuse_after_burst() {
        let l = RateLimiter::default();
        for _ in 0..3 {
            assert!(l.take(Kind::Auth, "a".into(), 3).is_ok());
        }
        let wait = l.take(Kind::Auth, "a".into(), 3).unwrap_err();
        assert!(wait <= Duration::from_secs(20));
        // Other keys and kinds have their own buckets.
        assert!(l.take(Kind::Auth, "b".into(), 3).is_ok());
        assert!(l.take(Kind::Api, "a".into(), 3).is_ok());
    }

    #[test]
    fn classify_paths() {
        assert_eq!(
            classify(&Method::POST, "/auth/login/start"),
            Some(Kind::Auth)
        );
        assert_eq!(classify(&Method::POST, "/oauth/token"), Some(Kind::Auth));
        assert_eq!(classify(&Method::GET, "/oauth/authorize"), None);
        assert_eq!(classify(&Method::GET, "/api/v1/files/"), Some(Kind::Api));
        assert_eq!(classify(&Method::OPTIONS, "/api/v1/files/"), None);
        assert_eq!(classify(&Method::GET, "/files"), None);
    }

    #[test]
    fn proxy_headers() {
        let mut h = HeaderMap::new();
        h.insert("x-forwarded-for", "6.6.6.6, 10.0.0.1".parse().unwrap());
        assert_eq!(forwarded_ip(&h), Some("10.0.0.1".parse().unwrap()));
        let v6: IpAddr = "2001:db8:1:2:3:4:5:6".parse().unwrap();
        assert_eq!(ip_key(Some(v6)), "2001:db8:1:2::/64");
    }
}
