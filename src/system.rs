//! Access to `system.db`: users, passkeys, sessions, API tokens, invites, settings, audit log.

use std::{
    path::Path,
    sync::{Arc, Mutex},
};

use rusqlite::{Connection, OptionalExtension, params};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::error::{AppError, AppResult};

const MIGRATIONS: &[&str] = &[
    r#"
CREATE TABLE users (
    id          TEXT PRIMARY KEY,
    username    TEXT NOT NULL UNIQUE COLLATE NOCASE,
    is_admin    INTEGER NOT NULL DEFAULT 0,
    created_at  INTEGER NOT NULL
);
CREATE TABLE passkeys (
    id           INTEGER PRIMARY KEY,
    user_id      TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    cred_id      TEXT NOT NULL UNIQUE,
    name         TEXT NOT NULL,
    data         TEXT NOT NULL,
    created_at   INTEGER NOT NULL,
    last_used_at INTEGER
);
CREATE TABLE sessions (
    token_hash  TEXT PRIMARY KEY,
    user_id     TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    created_at  INTEGER NOT NULL,
    expires_at  INTEGER NOT NULL
);
CREATE TABLE api_tokens (
    id           INTEGER PRIMARY KEY,
    user_id      TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    name         TEXT NOT NULL,
    token_hash   TEXT NOT NULL UNIQUE,
    scopes       TEXT NOT NULL,
    created_at   INTEGER NOT NULL,
    expires_at   INTEGER,
    last_used_at INTEGER
);
CREATE TABLE invites (
    id           INTEGER PRIMARY KEY,
    token_hash   TEXT NOT NULL UNIQUE,
    created_by   TEXT REFERENCES users(id) ON DELETE SET NULL,
    grants_admin INTEGER NOT NULL DEFAULT 0,
    note         TEXT NOT NULL DEFAULT '',
    created_at   INTEGER NOT NULL,
    expires_at   INTEGER NOT NULL,
    used_at      INTEGER,
    used_by      TEXT REFERENCES users(id) ON DELETE SET NULL
);
CREATE TABLE settings (
    key   TEXT PRIMARY KEY,
    value TEXT NOT NULL
);
"#,
    r#"
CREATE TABLE audit_log (
    id          INTEGER PRIMARY KEY,
    at          INTEGER NOT NULL,
    user_id     TEXT,
    username    TEXT NOT NULL,
    action      TEXT NOT NULL,
    table_name  TEXT NOT NULL,
    row_key     TEXT NOT NULL,
    detail      TEXT NOT NULL
);
"#,
    r#"
CREATE TABLE oauth_codes (
    code_hash      TEXT PRIMARY KEY,
    user_id        TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    client_id      TEXT NOT NULL,
    redirect_uri   TEXT NOT NULL,
    scopes         TEXT NOT NULL,
    code_challenge TEXT NOT NULL,
    expires_at     INTEGER NOT NULL
);
ALTER TABLE api_tokens ADD COLUMN client_id TEXT;
"#,
    r#"
CREATE TABLE apps (
    user_id    TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    id         TEXT NOT NULL,
    name       TEXT NOT NULL,
    origin     TEXT NOT NULL,
    created_at INTEGER NOT NULL,
    PRIMARY KEY (user_id, id)
);
ALTER TABLE oauth_codes ADD COLUMN app_id TEXT;
ALTER TABLE api_tokens ADD COLUMN app_id TEXT;
-- App tokens issued before apps had their own folders could reach every file.
DELETE FROM api_tokens WHERE client_id IS NOT NULL;
DELETE FROM oauth_codes;
"#,
    r#"
-- Account recovery links are invites that add a passkey to an existing user.
ALTER TABLE invites ADD COLUMN recovers_user TEXT REFERENCES users(id) ON DELETE CASCADE;
"#,
    r#"
-- Apps an admin registered: they get storage of their own (app-owned databases, shared by all
-- their users, with per-row ownership), and only their origin may sign in with their id.
CREATE TABLE registered_apps (
    id         TEXT PRIMARY KEY,
    name       TEXT NOT NULL,
    origin     TEXT NOT NULL,
    created_by TEXT REFERENCES users(id) ON DELETE SET NULL,
    created_at INTEGER NOT NULL
);
-- Users who may manage a registered app's storage (create databases, change tables), besides
-- admins, who always can.
CREATE TABLE app_owners (
    app_id   TEXT NOT NULL REFERENCES registered_apps(id) ON DELETE CASCADE,
    user_id  TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    added_at INTEGER NOT NULL,
    PRIMARY KEY (app_id, user_id)
);
"#,
];

pub fn now() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0)
}

/// 32 random bytes, hex-encoded.
pub fn random_token() -> String {
    let bytes: [u8; 32] = rand::random();
    hex::encode(bytes)
}

pub fn hash_token(token: &str) -> String {
    use sha2::{Digest, Sha256};
    hex::encode(Sha256::digest(token.as_bytes()))
}

#[derive(Debug, Clone, Serialize)]
pub struct User {
    pub id: Uuid,
    pub username: String,
    pub is_admin: bool,
    pub created_at: i64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum SignupMode {
    Open,
    Invite,
    Closed,
}

impl SignupMode {
    pub fn as_str(self) -> &'static str {
        match self {
            SignupMode::Open => "open",
            SignupMode::Invite => "invite",
            SignupMode::Closed => "closed",
        }
    }
    pub fn parse(s: &str) -> Option<Self> {
        match s {
            "open" => Some(SignupMode::Open),
            "invite" => Some(SignupMode::Invite),
            "closed" => Some(SignupMode::Closed),
            _ => None,
        }
    }
}

#[derive(Debug, Clone)]
pub struct PasskeyRow {
    pub id: i64,
    pub name: String,
    pub data: String,
    pub created_at: i64,
    pub last_used_at: Option<i64>,
}

#[derive(Debug, Clone)]
pub struct TokenRow {
    pub id: i64,
    pub name: String,
    pub scopes: String,
    pub created_at: i64,
    pub expires_at: Option<i64>,
    pub last_used_at: Option<i64>,
}

/// An app a user has signed in to: it owns the folder `apps/<id>` in their files.
#[derive(Debug, Clone)]
pub struct App {
    pub id: Uuid,
    pub name: String,
    /// `scheme://host[:port]` of the app that registered this id; only it may use the id.
    pub origin: String,
}

/// An app an admin registered, with storage of its own.
#[derive(Debug, Clone, Serialize)]
pub struct RegisteredApp {
    pub id: Uuid,
    pub name: String,
    /// `scheme://host[:port]`: the only origin that may sign in with this app's id.
    pub origin: String,
    pub created_at: i64,
}

/// A user who may manage a registered app's storage.
#[derive(Debug, Clone, Serialize)]
pub struct AppOwner {
    pub id: Uuid,
    pub username: String,
}

/// Who a bearer token belongs to, and what it may reach.
#[derive(Debug, Clone)]
pub struct TokenInfo {
    pub user: User,
    pub scopes: String,
    /// For tokens issued to an app through OAuth: the app's id.
    pub app: Option<Uuid>,
    /// For app tokens: the app's URL (`client_id`).
    pub client_id: Option<String>,
}

/// The apps (OAuth clients) a user has authorized, one row per app.
#[derive(Debug, Clone)]
pub struct AppRow {
    pub app_id: Uuid,
    pub name: String,
    pub client_id: String,
    pub scopes: String,
    pub tokens: i64,
    pub authorized_at: i64,
    pub last_used_at: Option<i64>,
}

/// An authorization code, as stored when it was issued.
#[derive(Debug, Clone)]
pub struct OAuthCode {
    pub user_id: Uuid,
    pub app_id: Uuid,
    pub client_id: String,
    pub redirect_uri: String,
    pub scopes: String,
    pub code_challenge: String,
}

#[derive(Debug, Clone)]
pub struct InviteRow {
    pub id: i64,
    pub note: String,
    pub grants_admin: bool,
    pub created_at: i64,
    pub expires_at: i64,
    pub used_at: Option<i64>,
    pub used_by: Option<String>,
}

#[derive(Debug, Clone)]
pub struct Invite {
    pub id: i64,
    pub grants_admin: bool,
}

/// Handle to system.db. All access goes through a single connection on a blocking thread.
#[derive(Clone)]
pub struct SystemDb {
    conn: Arc<Mutex<Connection>>,
}

fn user_from_row(r: &rusqlite::Row) -> rusqlite::Result<User> {
    let id: String = r.get(0)?;
    Ok(User {
        id: Uuid::parse_str(&id).unwrap_or_default(),
        username: r.get(1)?,
        is_admin: r.get(2)?,
        created_at: r.get(3)?,
    })
}

impl SystemDb {
    pub fn open(path: &Path) -> anyhow::Result<Self> {
        let conn = Connection::open(path)?;
        conn.pragma_update(None, "journal_mode", "WAL")?;
        conn.pragma_update(None, "foreign_keys", true)?;
        conn.busy_timeout(std::time::Duration::from_secs(5))?;
        let version: i64 = conn.pragma_query_value(None, "user_version", |r| r.get(0))?;
        for (i, m) in MIGRATIONS.iter().enumerate().skip(version as usize) {
            let tx = conn.unchecked_transaction()?;
            tx.execute_batch(m)?;
            tx.pragma_update(None, "user_version", (i + 1) as i64)?;
            tx.commit()?;
        }
        Ok(Self {
            conn: Arc::new(Mutex::new(conn)),
        })
    }

    /// Run `f` with the connection on a blocking thread.
    pub async fn call<T, F>(&self, f: F) -> AppResult<T>
    where
        T: Send + 'static,
        F: FnOnce(&mut Connection) -> AppResult<T> + Send + 'static,
    {
        let conn = self.conn.clone();
        tokio::task::spawn_blocking(move || {
            let mut guard = conn.lock().unwrap_or_else(|p| p.into_inner());
            f(&mut guard)
        })
        .await?
    }

    // ---- settings ----

    pub async fn signup_mode(&self) -> AppResult<SignupMode> {
        self.call(|c| {
            let v: Option<String> = c
                .query_row(
                    "SELECT value FROM settings WHERE key='signup_mode'",
                    [],
                    |r| r.get(0),
                )
                .optional()?;
            Ok(v.as_deref()
                .and_then(SignupMode::parse)
                .unwrap_or(SignupMode::Invite))
        })
        .await
    }

    pub async fn set_signup_mode(&self, mode: SignupMode) -> AppResult<()> {
        self.call(move |c| {
            c.execute(
                "INSERT INTO settings(key,value) VALUES('signup_mode',?1)
                 ON CONFLICT(key) DO UPDATE SET value=excluded.value",
                [mode.as_str()],
            )?;
            Ok(())
        })
        .await
    }

    // ---- users ----

    pub async fn user_count(&self) -> AppResult<i64> {
        self.call(|c| Ok(c.query_row("SELECT count(*) FROM users", [], |r| r.get(0))?))
            .await
    }

    pub async fn user_by_name(&self, username: String) -> AppResult<Option<User>> {
        self.call(move |c| {
            Ok(c.query_row(
                "SELECT id,username,is_admin,created_at FROM users WHERE username=?1",
                [username],
                user_from_row,
            )
            .optional()?)
        })
        .await
    }

    pub async fn user_by_id(&self, id: Uuid) -> AppResult<Option<User>> {
        self.call(move |c| {
            Ok(c.query_row(
                "SELECT id,username,is_admin,created_at FROM users WHERE id=?1",
                [id.to_string()],
                user_from_row,
            )
            .optional()?)
        })
        .await
    }

    pub async fn list_users(&self) -> AppResult<Vec<User>> {
        self.call(|c| {
            let mut st =
                c.prepare("SELECT id,username,is_admin,created_at FROM users ORDER BY created_at")?;
            let rows = st.query_map([], user_from_row)?;
            Ok(rows.collect::<Result<_, _>>()?)
        })
        .await
    }

    pub async fn set_admin(&self, user_id: Uuid, is_admin: bool) -> AppResult<()> {
        self.call(move |c| {
            c.execute(
                "UPDATE users SET is_admin=?2 WHERE id=?1",
                params![user_id.to_string(), is_admin],
            )?;
            Ok(())
        })
        .await
    }

    /// Create a user with their first passkey, consuming the invite (if any) atomically.
    pub async fn create_user(
        &self,
        id: Uuid,
        username: String,
        is_admin: bool,
        invite_id: Option<i64>,
        passkey_cred_id: String,
        passkey_json: String,
    ) -> AppResult<User> {
        self.call(move |c| {
            let tx = c.transaction()?;
            let now = now();
            if let Some(inv) = invite_id {
                let n = tx.execute(
                    "UPDATE invites SET used_at=?2, used_by=NULL
                     WHERE id=?1 AND used_at IS NULL AND expires_at > ?2",
                    params![inv, now],
                )?;
                if n == 0 {
                    return Err(AppError::forbidden("invite is no longer valid"));
                }
            }
            let inserted = tx.execute(
                "INSERT INTO users(id,username,is_admin,created_at) VALUES(?1,?2,?3,?4)
                 ON CONFLICT(username) DO NOTHING",
                params![id.to_string(), username, is_admin, now],
            )?;
            if inserted == 0 {
                return Err(AppError::Conflict("username is taken".into()));
            }
            if let Some(inv) = invite_id {
                tx.execute(
                    "UPDATE invites SET used_by=?2 WHERE id=?1",
                    params![inv, id.to_string()],
                )?;
            }
            tx.execute(
                "INSERT INTO passkeys(user_id,cred_id,name,data,created_at) VALUES(?1,?2,'Passkey',?3,?4)",
                params![id.to_string(), passkey_cred_id, passkey_json, now],
            )?;
            tx.commit()?;
            Ok(User {
                id,
                username,
                is_admin,
                created_at: now,
            })
        })
        .await
    }

    // ---- passkeys ----

    pub async fn passkeys(&self, user_id: Uuid) -> AppResult<Vec<PasskeyRow>> {
        self.call(move |c| {
            let mut st = c.prepare(
                "SELECT id,name,data,created_at,last_used_at FROM passkeys WHERE user_id=?1 ORDER BY id",
            )?;
            let rows = st.query_map([user_id.to_string()], |r| {
                Ok(PasskeyRow {
                    id: r.get(0)?,
                    name: r.get(1)?,
                    data: r.get(2)?,
                    created_at: r.get(3)?,
                    last_used_at: r.get(4)?,
                })
            })?;
            Ok(rows.collect::<Result<_, _>>()?)
        })
        .await
    }

    pub async fn add_passkey(
        &self,
        user_id: Uuid,
        name: String,
        cred_id: String,
        data: String,
    ) -> AppResult<()> {
        self.call(move |c| {
            c.execute(
                "INSERT INTO passkeys(user_id,cred_id,name,data,created_at) VALUES(?1,?2,?3,?4,?5)",
                params![user_id.to_string(), cred_id, name, data, now()],
            )
            .map_err(|e| match e {
                rusqlite::Error::SqliteFailure(f, _)
                    if f.code == rusqlite::ErrorCode::ConstraintViolation =>
                {
                    AppError::Conflict("passkey already registered".into())
                }
                e => e.into(),
            })?;
            Ok(())
        })
        .await
    }

    pub async fn update_passkey(&self, cred_id: String, data: String) -> AppResult<()> {
        self.call(move |c| {
            c.execute(
                "UPDATE passkeys SET data=?2, last_used_at=?3 WHERE cred_id=?1",
                params![cred_id, data, now()],
            )?;
            Ok(())
        })
        .await
    }

    /// Delete a passkey unless it is the user's last one.
    pub async fn delete_passkey(&self, user_id: Uuid, id: i64) -> AppResult<()> {
        self.call(move |c| {
            let tx = c.transaction()?;
            let count: i64 = tx.query_row(
                "SELECT count(*) FROM passkeys WHERE user_id=?1",
                [user_id.to_string()],
                |r| r.get(0),
            )?;
            if count <= 1 {
                return Err(AppError::Conflict("cannot delete your last passkey".into()));
            }
            tx.execute(
                "DELETE FROM passkeys WHERE id=?1 AND user_id=?2",
                params![id, user_id.to_string()],
            )?;
            tx.commit()?;
            Ok(())
        })
        .await
    }

    // ---- sessions ----

    pub async fn create_session(&self, user_id: Uuid, ttl_secs: i64) -> AppResult<String> {
        let token = random_token();
        let hash = hash_token(&token);
        self.call(move |c| {
            let now = now();
            c.execute("DELETE FROM sessions WHERE expires_at <= ?1", [now])?;
            c.execute(
                "INSERT INTO sessions(token_hash,user_id,created_at,expires_at) VALUES(?1,?2,?3,?4)",
                params![hash, user_id.to_string(), now, now + ttl_secs],
            )?;
            Ok(())
        })
        .await?;
        Ok(token)
    }

    pub async fn session_user(&self, token: &str) -> AppResult<Option<User>> {
        let hash = hash_token(token);
        self.call(move |c| {
            Ok(c.query_row(
                "SELECT u.id,u.username,u.is_admin,u.created_at FROM sessions s
                 JOIN users u ON u.id=s.user_id WHERE s.token_hash=?1 AND s.expires_at > ?2",
                params![hash, now()],
                user_from_row,
            )
            .optional()?)
        })
        .await
    }

    pub async fn delete_session(&self, token: &str) -> AppResult<()> {
        let hash = hash_token(token);
        self.call(move |c| {
            c.execute("DELETE FROM sessions WHERE token_hash=?1", [hash])?;
            Ok(())
        })
        .await
    }

    // ---- API tokens ----

    pub async fn create_api_token(
        &self,
        user_id: Uuid,
        name: String,
        scopes: String,
        expires_at: Option<i64>,
    ) -> AppResult<String> {
        self.insert_token(user_id, name, scopes, expires_at, None)
            .await
    }

    /// Issue a token to an app (OAuth client). It only reaches the app's own folder.
    pub async fn create_app_token(
        &self,
        user_id: Uuid,
        client_id: String,
        app_id: Uuid,
        scopes: String,
        expires_at: i64,
    ) -> AppResult<String> {
        self.insert_token(
            user_id,
            client_id.clone(),
            scopes,
            Some(expires_at),
            Some((client_id, app_id)),
        )
        .await
    }

    async fn insert_token(
        &self,
        user_id: Uuid,
        name: String,
        scopes: String,
        expires_at: Option<i64>,
        app: Option<(String, Uuid)>,
    ) -> AppResult<String> {
        let token = format!("wfs_{}", random_token());
        let hash = hash_token(&token);
        let (client_id, app_id) = app.map(|(c, a)| (c, a.to_string())).unzip();
        self.call(move |c| {
            c.execute(
                "INSERT INTO api_tokens(user_id,name,token_hash,scopes,created_at,expires_at,client_id,app_id)
                 VALUES(?1,?2,?3,?4,?5,?6,?7,?8)",
                params![user_id.to_string(), name, hash, scopes, now(), expires_at, client_id, app_id],
            )?;
            Ok(())
        })
        .await?;
        Ok(token)
    }

    /// Resolve a bearer token to its user, scope string and (for app tokens) the app it was
    /// issued to, recording last use.
    pub async fn api_token_user(&self, token: &str) -> AppResult<Option<TokenInfo>> {
        let hash = hash_token(token);
        self.call(move |c| {
            let now = now();
            let res = c
                .query_row(
                    "SELECT u.id,u.username,u.is_admin,u.created_at,t.scopes,t.id,t.client_id,t.app_id
                     FROM api_tokens t JOIN users u ON u.id=t.user_id
                     WHERE t.token_hash=?1 AND (t.expires_at IS NULL OR t.expires_at > ?2)",
                    params![hash, now],
                    |r| {
                        Ok((
                            user_from_row(r)?,
                            r.get::<_, String>(4)?,
                            r.get::<_, i64>(5)?,
                            r.get::<_, Option<String>>(6)?,
                            r.get::<_, Option<String>>(7)?,
                        ))
                    },
                )
                .optional()?;
            Ok(match res {
                // An app token without a valid app id would reach everything: refuse it.
                Some((_, _, _, Some(_), app))
                    if app.as_deref().and_then(|a| Uuid::parse_str(a).ok()).is_none() =>
                {
                    None
                }
                Some((user, scopes, id, client_id, app)) => {
                    // Only write when stale by a minute to avoid a write per request.
                    c.execute(
                        "UPDATE api_tokens SET last_used_at=?2
                         WHERE id=?1 AND (last_used_at IS NULL OR last_used_at < ?2 - 60)",
                        params![id, now],
                    )?;
                    let app = app.and_then(|a| Uuid::parse_str(&a).ok());
                    Some(TokenInfo {
                        user,
                        scopes,
                        app,
                        client_id,
                    })
                }
                None => None,
            })
        })
        .await
    }

    pub async fn api_tokens(&self, user_id: Uuid) -> AppResult<Vec<TokenRow>> {
        self.call(move |c| {
            let mut st = c.prepare(
                "SELECT id,name,scopes,created_at,expires_at,last_used_at FROM api_tokens
                 WHERE user_id=?1 AND client_id IS NULL ORDER BY id",
            )?;
            let rows = st.query_map([user_id.to_string()], |r| {
                Ok(TokenRow {
                    id: r.get(0)?,
                    name: r.get(1)?,
                    scopes: r.get(2)?,
                    created_at: r.get(3)?,
                    expires_at: r.get(4)?,
                    last_used_at: r.get(5)?,
                })
            })?;
            Ok(rows.collect::<Result<_, _>>()?)
        })
        .await
    }

    pub async fn delete_api_token(&self, user_id: Uuid, id: i64) -> AppResult<()> {
        self.call(move |c| {
            c.execute(
                "DELETE FROM api_tokens WHERE id=?1 AND user_id=?2",
                params![id, user_id.to_string()],
            )?;
            Ok(())
        })
        .await
    }

    /// Delete a token given its value (OAuth revocation). Unknown tokens are ignored.
    pub async fn revoke_token(&self, token: &str) -> AppResult<()> {
        let hash = hash_token(token);
        self.call(move |c| {
            c.execute("DELETE FROM api_tokens WHERE token_hash=?1", [hash])?;
            Ok(())
        })
        .await
    }

    // ---- OAuth ----

    /// Store a new authorization code and return it.
    #[allow(clippy::too_many_arguments)]
    pub async fn create_oauth_code(
        &self,
        user_id: Uuid,
        app_id: Uuid,
        client_id: String,
        redirect_uri: String,
        scopes: String,
        code_challenge: String,
        ttl_secs: i64,
    ) -> AppResult<String> {
        let code = random_token();
        let hash = hash_token(&code);
        self.call(move |c| {
            let now = now();
            c.execute("DELETE FROM oauth_codes WHERE expires_at <= ?1", [now])?;
            c.execute(
                "INSERT INTO oauth_codes(code_hash,user_id,client_id,redirect_uri,scopes,code_challenge,expires_at,app_id)
                 VALUES(?1,?2,?3,?4,?5,?6,?7,?8)",
                params![hash, user_id.to_string(), client_id, redirect_uri, scopes, code_challenge, now + ttl_secs, app_id.to_string()],
            )?;
            Ok(())
        })
        .await?;
        Ok(code)
    }

    /// Remove an authorization code and return it if it was still valid. Codes work once.
    pub async fn take_oauth_code(&self, code: &str) -> AppResult<Option<OAuthCode>> {
        let hash = hash_token(code);
        self.call(move |c| {
            Ok(c.query_row(
                "DELETE FROM oauth_codes WHERE code_hash=?1
                 RETURNING user_id,client_id,redirect_uri,scopes,code_challenge,expires_at,app_id",
                [hash],
                |r| {
                    let user_id: String = r.get(0)?;
                    let expires_at: i64 = r.get(5)?;
                    let app_id = r
                        .get::<_, Option<String>>(6)?
                        .and_then(|a| Uuid::parse_str(&a).ok());
                    Ok(app_id
                        .filter(|_| expires_at > now())
                        .map(|app_id| OAuthCode {
                            user_id: Uuid::parse_str(&user_id).unwrap_or_default(),
                            app_id,
                            client_id: r.get(1).unwrap_or_default(),
                            redirect_uri: r.get(2).unwrap_or_default(),
                            scopes: r.get(3).unwrap_or_default(),
                            code_challenge: r.get(4).unwrap_or_default(),
                        }))
                },
            )
            .optional()?
            .flatten())
        })
        .await
    }

    /// Apps the user has authorized and that still hold an unexpired token.
    pub async fn connected_apps(&self, user_id: Uuid) -> AppResult<Vec<AppRow>> {
        self.call(move |c| {
            let mut st = c.prepare(
                "SELECT t.app_id, a.name,
                        (SELECT client_id FROM api_tokens n WHERE n.user_id=t.user_id AND n.app_id=t.app_id
                         ORDER BY n.id DESC LIMIT 1),
                        (SELECT scopes FROM api_tokens n WHERE n.user_id=t.user_id AND n.app_id=t.app_id
                         ORDER BY n.id DESC LIMIT 1),
                        COUNT(*), MIN(t.created_at), MAX(t.last_used_at)
                 FROM api_tokens t JOIN apps a ON a.user_id=t.user_id AND a.id=t.app_id
                 WHERE t.user_id=?1 AND (t.expires_at IS NULL OR t.expires_at > ?2)
                 GROUP BY t.app_id ORDER BY MIN(t.created_at)",
            )?;
            let rows = st.query_map(params![user_id.to_string(), now()], |r| {
                Ok(AppRow {
                    app_id: Uuid::parse_str(&r.get::<_, String>(0)?).unwrap_or_default(),
                    name: r.get(1)?,
                    client_id: r.get(2)?,
                    scopes: r.get(3)?,
                    tokens: r.get(4)?,
                    authorized_at: r.get(5)?,
                    last_used_at: r.get(6)?,
                })
            })?;
            Ok(rows.collect::<Result<_, _>>()?)
        })
        .await
    }

    /// Revoke every token the user gave an app. Its folder and name stay.
    pub async fn disconnect_app(&self, user_id: Uuid, app_id: Uuid) -> AppResult<()> {
        self.call(move |c| {
            c.execute(
                "DELETE FROM api_tokens WHERE user_id=?1 AND app_id=?2",
                params![user_id.to_string(), app_id.to_string()],
            )?;
            Ok(())
        })
        .await
    }

    /// Every app the user has ever allowed, connected or not, so their folders can be labelled.
    pub async fn apps(&self, user_id: Uuid) -> AppResult<Vec<App>> {
        self.call(move |c| {
            let mut st =
                c.prepare("SELECT id,name,origin FROM apps WHERE user_id=?1 ORDER BY created_at")?;
            let rows = st.query_map([user_id.to_string()], |r| {
                Ok(App {
                    id: Uuid::parse_str(&r.get::<_, String>(0)?).unwrap_or_default(),
                    name: r.get(1)?,
                    origin: r.get(2)?,
                })
            })?;
            Ok(rows.collect::<Result<_, _>>()?)
        })
        .await
    }

    pub async fn app(&self, user_id: Uuid, app_id: Uuid) -> AppResult<Option<App>> {
        self.call(move |c| {
            Ok(c.query_row(
                "SELECT id,name,origin FROM apps WHERE user_id=?1 AND id=?2",
                params![user_id.to_string(), app_id.to_string()],
                |r| {
                    Ok(App {
                        id: Uuid::parse_str(&r.get::<_, String>(0)?).unwrap_or_default(),
                        name: r.get(1)?,
                        origin: r.get(2)?,
                    })
                },
            )
            .optional()?)
        })
        .await
    }

    /// Record (or rename) an app the user allowed. Fails if another origin already owns the id.
    pub async fn record_app(
        &self,
        user_id: Uuid,
        app_id: Uuid,
        name: String,
        origin: String,
    ) -> AppResult<()> {
        self.call(move |c| {
            let n = c.execute(
                "INSERT INTO apps(user_id,id,name,origin,created_at) VALUES(?1,?2,?3,?4,?5)
                 ON CONFLICT(user_id,id) DO UPDATE SET name=excluded.name WHERE origin=excluded.origin",
                params![user_id.to_string(), app_id.to_string(), name, origin, now()],
            )?;
            if n == 0 {
                return Err(AppError::Conflict(
                    "this app ID belongs to another app".into(),
                ));
            }
            Ok(())
        })
        .await
    }

    // ---- registered apps ----

    pub async fn registered_apps(&self) -> AppResult<Vec<RegisteredApp>> {
        self.call(|c| {
            let mut st = c.prepare(
                "SELECT id,name,origin,created_at FROM registered_apps ORDER BY created_at, name",
            )?;
            let rows = st.query_map([], registered_app_from_row)?;
            Ok(rows.collect::<Result<_, _>>()?)
        })
        .await
    }

    pub async fn registered_app(&self, id: Uuid) -> AppResult<Option<RegisteredApp>> {
        self.call(move |c| {
            Ok(c.query_row(
                "SELECT id,name,origin,created_at FROM registered_apps WHERE id=?1",
                [id.to_string()],
                registered_app_from_row,
            )
            .optional()?)
        })
        .await
    }

    /// Register an app (admins only; the caller checks). Fails if the id is taken.
    pub async fn create_registered_app(
        &self,
        admin: &User,
        id: Uuid,
        name: String,
        origin: String,
    ) -> AppResult<RegisteredApp> {
        let admin = admin.clone();
        self.call(move |c| {
            let tx = c.transaction()?;
            let at = now();
            let n = tx.execute(
                "INSERT INTO registered_apps(id,name,origin,created_by,created_at) VALUES(?1,?2,?3,?4,?5)
                 ON CONFLICT(id) DO NOTHING",
                params![id.to_string(), name, origin, admin.id.to_string(), at],
            )?;
            if n == 0 {
                return Err(AppError::Conflict("an app with this id is already registered".into()));
            }
            audit(
                &tx,
                Some(&admin),
                "register_app",
                "registered_apps",
                &id.to_string(),
                serde_json::json!({ "name": name, "origin": origin }),
            )?;
            tx.commit()?;
            Ok(RegisteredApp {
                id,
                name,
                origin,
                created_at: at,
            })
        })
        .await
    }

    /// Forget a registered app and its owners. Its storage is removed separately.
    pub async fn delete_registered_app(&self, admin: &User, id: Uuid) -> AppResult<()> {
        let admin = admin.clone();
        self.call(move |c| {
            let tx = c.transaction()?;
            let name: Option<String> = tx
                .query_row(
                    "DELETE FROM registered_apps WHERE id=?1 RETURNING name",
                    [id.to_string()],
                    |r| r.get(0),
                )
                .optional()?;
            let Some(name) = name else {
                return Err(AppError::not_found("no such app"));
            };
            audit(
                &tx,
                Some(&admin),
                "delete_app",
                "registered_apps",
                &id.to_string(),
                serde_json::json!({ "name": name }),
            )?;
            tx.commit()?;
            Ok(())
        })
        .await
    }

    pub async fn app_owners(&self, app_id: Uuid) -> AppResult<Vec<AppOwner>> {
        self.call(move |c| {
            let mut st = c.prepare(
                "SELECT u.id,u.username FROM app_owners o JOIN users u ON u.id=o.user_id
                 WHERE o.app_id=?1 ORDER BY u.username",
            )?;
            let rows = st.query_map([app_id.to_string()], |r| {
                Ok(AppOwner {
                    id: Uuid::parse_str(&r.get::<_, String>(0)?).unwrap_or_default(),
                    username: r.get(1)?,
                })
            })?;
            Ok(rows.collect::<Result<_, _>>()?)
        })
        .await
    }

    /// Whether `user` was made an owner of the app (admins aren't listed, but may manage any app).
    pub async fn is_app_owner(&self, app_id: Uuid, user_id: Uuid) -> AppResult<bool> {
        self.call(move |c| {
            Ok(c.query_row(
                "SELECT 1 FROM app_owners WHERE app_id=?1 AND user_id=?2",
                params![app_id.to_string(), user_id.to_string()],
                |_| Ok(()),
            )
            .optional()?
            .is_some())
        })
        .await
    }

    /// Registered apps the user owns, or has signed in to.
    pub async fn registered_apps_for(
        &self,
        user_id: Uuid,
    ) -> AppResult<Vec<(RegisteredApp, bool)>> {
        self.call(move |c| {
            let mut st = c.prepare(
                "SELECT r.id,r.name,r.origin,r.created_at,
                        EXISTS(SELECT 1 FROM app_owners o WHERE o.app_id=r.id AND o.user_id=?1)
                 FROM registered_apps r
                 WHERE EXISTS(SELECT 1 FROM app_owners o WHERE o.app_id=r.id AND o.user_id=?1)
                    OR EXISTS(SELECT 1 FROM apps a WHERE a.id=r.id AND a.user_id=?1)
                 ORDER BY r.name",
            )?;
            let rows = st.query_map([user_id.to_string()], |r| {
                Ok((registered_app_from_row(r)?, r.get(4)?))
            })?;
            Ok(rows.collect::<Result<_, _>>()?)
        })
        .await
    }

    /// Make `user` an owner of the app, or (`owner` false) stop them being one.
    pub async fn set_app_owner(
        &self,
        admin: &User,
        app_id: Uuid,
        user: &User,
        owner: bool,
    ) -> AppResult<()> {
        let (admin, user) = (admin.clone(), user.clone());
        self.call(move |c| {
            let tx = c.transaction()?;
            let exists = tx
                .query_row(
                    "SELECT 1 FROM registered_apps WHERE id=?1",
                    [app_id.to_string()],
                    |_| Ok(()),
                )
                .optional()?;
            if exists.is_none() {
                return Err(AppError::not_found("no such app"));
            }
            let n = if owner {
                tx.execute(
                    "INSERT INTO app_owners(app_id,user_id,added_at) VALUES(?1,?2,?3)
                     ON CONFLICT DO NOTHING",
                    params![app_id.to_string(), user.id.to_string(), now()],
                )?
            } else {
                tx.execute(
                    "DELETE FROM app_owners WHERE app_id=?1 AND user_id=?2",
                    params![app_id.to_string(), user.id.to_string()],
                )?
            };
            if n > 0 {
                audit(
                    &tx,
                    Some(&admin),
                    if owner {
                        "add_app_owner"
                    } else {
                        "remove_app_owner"
                    },
                    "app_owners",
                    &format!("{app_id}/{}", user.id),
                    serde_json::json!({ "username": user.username }),
                )?;
            }
            tx.commit()?;
            Ok(())
        })
        .await
    }

    // ---- invites ----

    pub async fn create_invite(
        &self,
        created_by: Option<Uuid>,
        grants_admin: bool,
        note: String,
        ttl_secs: i64,
    ) -> AppResult<String> {
        let token = random_token();
        let hash = hash_token(&token);
        self.call(move |c| {
            let now = now();
            c.execute(
                "INSERT INTO invites(token_hash,created_by,grants_admin,note,created_at,expires_at)
                 VALUES(?1,?2,?3,?4,?5,?6)",
                params![
                    hash,
                    created_by.map(|u| u.to_string()),
                    grants_admin,
                    note,
                    now,
                    now + ttl_secs
                ],
            )?;
            Ok(())
        })
        .await?;
        Ok(token)
    }

    /// Look up an unused, unexpired invite.
    pub async fn valid_invite(&self, token: &str) -> AppResult<Option<Invite>> {
        let hash = hash_token(token);
        self.call(move |c| {
            Ok(c.query_row(
                "SELECT id,grants_admin FROM invites
                 WHERE token_hash=?1 AND used_at IS NULL AND expires_at > ?2
                   AND recovers_user IS NULL",
                params![hash, now()],
                |r| {
                    Ok(Invite {
                        id: r.get(0)?,
                        grants_admin: r.get(1)?,
                    })
                },
            )
            .optional()?)
        })
        .await
    }

    pub async fn list_invites(&self) -> AppResult<Vec<InviteRow>> {
        self.call(|c| {
            let mut st = c.prepare(
                "SELECT i.id,i.note,i.grants_admin,i.created_at,i.expires_at,i.used_at,u.username
                 FROM invites i LEFT JOIN users u ON u.id=i.used_by ORDER BY i.id DESC LIMIT 100",
            )?;
            let rows = st.query_map([], |r| {
                Ok(InviteRow {
                    id: r.get(0)?,
                    note: r.get(1)?,
                    grants_admin: r.get(2)?,
                    created_at: r.get(3)?,
                    expires_at: r.get(4)?,
                    used_at: r.get(5)?,
                    used_by: r.get(6)?,
                })
            })?;
            Ok(rows.collect::<Result<_, _>>()?)
        })
        .await
    }

    // ---- account recovery and deletion ----

    /// Create a one-time link that lets `user` register a new passkey without logging in.
    /// `admin` is `None` when it's created from the command line.
    pub async fn create_recovery(
        &self,
        admin: Option<&User>,
        user: &User,
        ttl_secs: i64,
    ) -> AppResult<String> {
        let token = random_token();
        let hash = hash_token(&token);
        let (admin, user) = (admin.cloned(), user.clone());
        self.call(move |c| {
            let tx = c.transaction()?;
            let now = now();
            tx.execute(
                "INSERT INTO invites(token_hash,created_by,grants_admin,note,created_at,expires_at,recovers_user)
                 VALUES(?1,?2,0,?3,?4,?5,?6)",
                params![
                    hash,
                    admin.as_ref().map(|a| a.id.to_string()),
                    format!("Account recovery for {}", user.username),
                    now,
                    now + ttl_secs,
                    user.id.to_string()
                ],
            )?;
            audit(&tx, admin.as_ref(), "recovery_link", "users", &user.id.to_string(), serde_json::json!({
                "username": user.username,
            }))?;
            tx.commit()?;
            Ok(())
        })
        .await?;
        Ok(token)
    }

    /// Look up an unused, unexpired recovery link: its invite id and the user it recovers.
    pub async fn valid_recovery(&self, token: &str) -> AppResult<Option<(i64, User)>> {
        let hash = hash_token(token);
        self.call(move |c| {
            Ok(c.query_row(
                "SELECT i.id,u.id,u.username,u.is_admin,u.created_at
                 FROM invites i JOIN users u ON u.id=i.recovers_user
                 WHERE i.token_hash=?1 AND i.used_at IS NULL AND i.expires_at > ?2",
                params![hash, now()],
                |r| {
                    let id: String = r.get(1)?;
                    Ok((
                        r.get(0)?,
                        User {
                            id: Uuid::parse_str(&id).unwrap_or_default(),
                            username: r.get(2)?,
                            is_admin: r.get(3)?,
                            created_at: r.get(4)?,
                        },
                    ))
                },
            )
            .optional()?)
        })
        .await
    }

    /// Use a recovery link: consume it, add the new passkey and sign the user out everywhere
    /// else (the lost device may have a live session), all in one transaction.
    pub async fn recover_account(
        &self,
        invite_id: i64,
        user_id: Uuid,
        cred_id: String,
        passkey_json: String,
    ) -> AppResult<()> {
        self.call(move |c| {
            let tx = c.transaction()?;
            let now = now();
            let n = tx.execute(
                "UPDATE invites SET used_at=?3, used_by=?2
                 WHERE id=?1 AND recovers_user=?2 AND used_at IS NULL AND expires_at > ?3",
                params![invite_id, user_id.to_string(), now],
            )?;
            if n == 0 {
                return Err(AppError::forbidden("recovery link is no longer valid"));
            }
            tx.execute(
                "INSERT INTO passkeys(user_id,cred_id,name,data,created_at)
                 VALUES(?1,?2,'Passkey (recovered)',?3,?4)",
                params![user_id.to_string(), cred_id, passkey_json, now],
            )?;
            tx.execute(
                "DELETE FROM sessions WHERE user_id=?1",
                [user_id.to_string()],
            )?;
            tx.commit()?;
            Ok(())
        })
        .await
    }

    /// Delete a user and everything system.db holds for them (passkeys, sessions, tokens, apps
    /// and pending invites cascade). Their files are removed separately.
    pub async fn delete_user(&self, admin: &User, user: &User) -> AppResult<()> {
        let (admin, user) = (admin.clone(), user.clone());
        self.call(move |c| {
            let tx = c.transaction()?;
            let n = tx.execute("DELETE FROM users WHERE id=?1", [user.id.to_string()])?;
            if n == 0 {
                return Err(AppError::NotFound("user not found".into()));
            }
            audit(
                &tx,
                Some(&admin),
                "delete_user",
                "users",
                &user.id.to_string(),
                serde_json::json!({
                    "username": user.username,
                    "is_admin": user.is_admin,
                }),
            )?;
            tx.commit()?;
            Ok(())
        })
        .await
    }

    pub async fn delete_invite(&self, id: i64) -> AppResult<()> {
        self.call(move |c| {
            c.execute("DELETE FROM invites WHERE id=?1", [id])?;
            Ok(())
        })
        .await
    }
}

fn registered_app_from_row(r: &rusqlite::Row) -> rusqlite::Result<RegisteredApp> {
    Ok(RegisteredApp {
        id: Uuid::parse_str(&r.get::<_, String>(0)?).unwrap_or_default(),
        name: r.get(1)?,
        origin: r.get(2)?,
        created_at: r.get(3)?,
    })
}

/// Record an admin action in `audit_log` (`None`: from the command line).
fn audit(
    tx: &rusqlite::Transaction,
    admin: Option<&User>,
    action: &str,
    table: &str,
    row_key: &str,
    detail: serde_json::Value,
) -> rusqlite::Result<()> {
    tx.execute(
        "INSERT INTO audit_log(at, user_id, username, action, table_name, row_key, detail)
         VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)",
        params![
            now(),
            admin.map(|a| a.id.to_string()),
            admin.map_or("(command line)", |a| a.username.as_str()),
            action,
            table,
            row_key,
            detail.to_string()
        ],
    )?;
    Ok(())
}
