use std::{
    collections::HashMap,
    sync::{Arc, Mutex},
    time::{Duration, Instant},
};

use webauthn_rs::{
    Webauthn, WebauthnBuilder,
    prelude::{PasskeyAuthentication, PasskeyRegistration, Url},
};

use crate::{
    config::Config,
    storage::{
        fs::{UserLocks, UserStore},
        sql::SqlLimits,
    },
    system::{Invite, SystemDb, random_token},
};

#[derive(Clone)]
pub struct AppState {
    pub cfg: Arc<Config>,
    pub sys: SystemDb,
    pub webauthn: Arc<Webauthn>,
    pub ceremonies: Arc<Ceremonies>,
    pub locks: Arc<UserLocks>,
    pub limiter: Arc<crate::ratelimit::RateLimiter>,
    /// Cancelled when the server starts shutting down, so long-lived responses (change streams)
    /// end instead of holding up a graceful shutdown.
    pub closing: tokio_util::sync::CancellationToken,
}

impl AppState {
    pub fn new(cfg: Config, sys: SystemDb) -> anyhow::Result<Self> {
        let origin = Url::parse(&cfg.origin)?;
        let webauthn = WebauthnBuilder::new(&cfg.rp_id, &origin)?
            .rp_name(&cfg.rp_name)
            .build()?;
        Ok(Self {
            cfg: Arc::new(cfg),
            sys,
            webauthn: Arc::new(webauthn),
            ceremonies: Arc::new(Ceremonies::default()),
            locks: Arc::new(UserLocks::default()),
            limiter: Default::default(),
            closing: Default::default(),
        })
    }

    pub fn store(&self, user_id: uuid::Uuid) -> UserStore {
        UserStore::new(&self.cfg.data_dir, user_id, self.locks.get(user_id))
    }

    pub fn sql_limits(&self) -> SqlLimits {
        let l = &self.cfg.limits;
        SqlLimits {
            timeout: Duration::from_millis(l.query_timeout_ms),
            max_rows: l.max_result_rows,
            max_db_bytes: l.max_db_bytes,
        }
    }
}

/// In-flight WebAuthn ceremony state.
pub enum Ceremony {
    Register {
        user_id: uuid::Uuid,
        username: String,
        invite: Option<Invite>,
        state: PasskeyRegistration,
    },
    AddPasskey {
        user_id: uuid::Uuid,
        name: String,
        state: PasskeyRegistration,
    },
    Login {
        user_id: uuid::Uuid,
        state: PasskeyAuthentication,
    },
    Recover {
        user_id: uuid::Uuid,
        invite_id: i64,
        state: PasskeyRegistration,
    },
}

const CEREMONY_TTL: Duration = Duration::from_secs(300);

#[derive(Default)]
pub struct Ceremonies {
    inner: Mutex<HashMap<String, (Instant, Ceremony)>>,
}

impl Ceremonies {
    pub fn insert(&self, c: Ceremony) -> String {
        let id = random_token();
        let mut m = self.inner.lock().unwrap_or_else(|p| p.into_inner());
        m.retain(|_, (t, _)| t.elapsed() < CEREMONY_TTL);
        m.insert(id.clone(), (Instant::now(), c));
        id
    }

    pub fn take(&self, id: &str) -> Option<Ceremony> {
        let mut m = self.inner.lock().unwrap_or_else(|p| p.into_inner());
        m.remove(id)
            .filter(|(t, _)| t.elapsed() < CEREMONY_TTL)
            .map(|(_, c)| c)
    }
}
