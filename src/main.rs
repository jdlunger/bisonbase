use axum::{
    Json, Router,
    extract::State,
    http::{HeaderMap, StatusCode, header},
    response::{Html, IntoResponse, Response},
    routing::{get, post},
};
use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD as B64};
use rusqlite::{Connection, OptionalExtension};
use serde::Deserialize;
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use std::{
    collections::HashMap,
    sync::{Arc, Mutex},
};
use uuid::Uuid;
use webauthn_rs::prelude::*;

const WORDS: &str = include_str!("../google-10000-english-usa-no-swears.txt");

struct App {
    webauthn: Webauthn,
    db: Mutex<Connection>,
    pending_reg: Mutex<HashMap<String, PasskeyRegistration>>,
    pending_auth: Mutex<HashMap<String, DiscoverableAuthentication>>,
    words: Vec<&'static str>,
}

type S = State<Arc<App>>;

#[tokio::main]
async fn main() {
    let origin = std::env::var("ORIGIN").unwrap_or("http://localhost:8080".into());
    let origin = Url::parse(&origin).expect("bad ORIGIN");
    let rp_id = origin.host_str().expect("ORIGIN needs a host").to_string();
    let webauthn = WebauthnBuilder::new(&rp_id, &origin).unwrap().build().unwrap();

    let db = Connection::open(std::env::var("DB").unwrap_or("users.db".into())).unwrap();
    db.execute_batch(
        "CREATE TABLE IF NOT EXISTS users (
            pubkey TEXT PRIMARY KEY,
            cred_id TEXT NOT NULL UNIQUE,
            passkey TEXT NOT NULL,
            created_at INTEGER NOT NULL DEFAULT (unixepoch())
        );
        CREATE TABLE IF NOT EXISTS sessions (
            token TEXT PRIMARY KEY,
            pubkey TEXT NOT NULL REFERENCES users(pubkey),
            created_at INTEGER NOT NULL DEFAULT (unixepoch())
        );",
    )
    .unwrap();

    let app = Arc::new(App {
        webauthn,
        db: Mutex::new(db),
        pending_reg: Default::default(),
        pending_auth: Default::default(),
        words: WORDS.lines().map(str::trim).filter(|w| !w.is_empty()).collect(),
    });

    let router = Router::new()
        .route("/", get(|| async { Html(include_str!("index.html")) }))
        .route("/api/users", get(users))
        .route("/api/me", get(me))
        .route("/api/register/start", post(register_start))
        .route("/api/register/finish", post(register_finish))
        .route("/api/login/start", post(login_start))
        .route("/api/login/finish", post(login_finish))
        .route("/api/logout", post(logout))
        .with_state(app);

    let port = std::env::var("PORT").unwrap_or("8080".into());
    let listener = tokio::net::TcpListener::bind(format!("0.0.0.0:{port}")).await.unwrap();
    println!("listening on {origin} (port {port})");
    axum::serve(listener, router).await.unwrap();
}

/// The user's ID: their public key, base64url-encoded.
fn pubkey_id(pk: &Passkey) -> String {
    let bytes = match &pk.get_public_key().key {
        COSEKeyType::EC_EC2(k) => [&[4u8][..], &k.x, &k.y].concat(), // SEC1 uncompressed point
        COSEKeyType::EC_OKP(k) => k.x.clone(),
        COSEKeyType::RSA(k) => [&k.n[..], &k.e[..]].concat(),
    };
    B64.encode(bytes)
}

/// Deterministic 4-word phrase from the public key.
fn phrase(app: &App, pubkey: &str) -> String {
    let h = Sha256::digest(pubkey.as_bytes());
    h.chunks(4)
        .take(4)
        .map(|c| app.words[u32::from_be_bytes(c.try_into().unwrap()) as usize % app.words.len()])
        .collect::<Vec<_>>()
        .join("_")
}

fn user_json(app: &App, pubkey: &str) -> Value {
    json!({ "pubkey": pubkey, "phrase": phrase(app, pubkey) })
}

fn session_token(headers: &HeaderMap) -> Option<&str> {
    let cookies = headers.get(header::COOKIE)?.to_str().ok()?;
    cookies.split(';').find_map(|c| c.trim().strip_prefix("session="))
}

fn session_pubkey(app: &App, headers: &HeaderMap) -> Option<String> {
    let token = session_token(headers)?;
    let db = app.db.lock().unwrap();
    db.query_row("SELECT pubkey FROM sessions WHERE token = ?1", [token], |r| r.get(0))
        .optional()
        .unwrap()
}

fn sign_in(app: &App, pubkey: &str) -> Response {
    let token = Uuid::new_v4().to_string();
    app.db
        .lock()
        .unwrap()
        .execute("INSERT INTO sessions (token, pubkey) VALUES (?1, ?2)", (&token, pubkey))
        .unwrap();
    let cookie = format!("session={token}; Path=/; HttpOnly; SameSite=Strict");
    ([(header::SET_COOKIE, cookie)], Json(user_json(app, pubkey))).into_response()
}

fn err(e: impl std::fmt::Display) -> Response {
    (StatusCode::BAD_REQUEST, e.to_string()).into_response()
}

async fn users(State(app): S) -> Json<Value> {
    let db = app.db.lock().unwrap();
    let mut stmt = db.prepare("SELECT pubkey FROM users ORDER BY created_at").unwrap();
    let keys: Vec<String> = stmt.query_map([], |r| r.get(0)).unwrap().flatten().collect();
    Json(keys.iter().map(|k| user_json(&app, k)).collect())
}

async fn me(State(app): S, headers: HeaderMap) -> Json<Value> {
    Json(session_pubkey(&app, &headers).map_or(Value::Null, |k| user_json(&app, &k)))
}

#[derive(Deserialize)]
struct Finish<T> {
    id: String,
    credential: T,
}

async fn register_start(State(app): S) -> Response {
    let user_id = Uuid::new_v4();
    let name = format!("user-{}", &user_id.to_string()[..8]);
    match app.webauthn.start_passkey_registration(user_id, &name, &name, None) {
        Ok((options, state)) => {
            let id = Uuid::new_v4().to_string();
            app.pending_reg.lock().unwrap().insert(id.clone(), state);
            Json(json!({ "id": id, "options": options })).into_response()
        }
        Err(e) => err(e),
    }
}

async fn register_finish(
    State(app): S,
    Json(req): Json<Finish<RegisterPublicKeyCredential>>,
) -> Response {
    let Some(state) = app.pending_reg.lock().unwrap().remove(&req.id) else {
        return err("unknown registration");
    };
    let pk = match app.webauthn.finish_passkey_registration(&req.credential, &state) {
        Ok(pk) => pk,
        Err(e) => return err(e),
    };
    let pubkey = pubkey_id(&pk);
    let res = app.db.lock().unwrap().execute(
        "INSERT INTO users (pubkey, cred_id, passkey) VALUES (?1, ?2, ?3)",
        (&pubkey, B64.encode(pk.cred_id()), serde_json::to_string(&pk).unwrap()),
    );
    match res {
        Ok(_) => sign_in(&app, &pubkey),
        Err(e) => err(e),
    }
}

async fn login_start(State(app): S) -> Response {
    match app.webauthn.start_discoverable_authentication() {
        Ok((options, state)) => {
            let id = Uuid::new_v4().to_string();
            app.pending_auth.lock().unwrap().insert(id.clone(), state);
            Json(json!({ "id": id, "options": options })).into_response()
        }
        Err(e) => err(e),
    }
}

async fn login_finish(State(app): S, Json(req): Json<Finish<PublicKeyCredential>>) -> Response {
    let Some(state) = app.pending_auth.lock().unwrap().remove(&req.id) else {
        return err("unknown login");
    };
    let cred_id = B64.encode(req.credential.get_credential_id());
    let db = app.db.lock().unwrap();
    let row: Option<(String, String)> = db
        .query_row(
            "SELECT pubkey, passkey FROM users WHERE cred_id = ?1",
            [&cred_id],
            |r| Ok((r.get(0)?, r.get(1)?)),
        )
        .optional()
        .unwrap();
    let Some((pubkey, passkey)) = row else {
        return err("unknown passkey");
    };
    let mut pk: Passkey = serde_json::from_str(&passkey).unwrap();
    let result = match app.webauthn.finish_discoverable_authentication_v2(&req.credential, state, &pk) {
        Ok(r) => r,
        Err(e) => return err(e),
    };
    if pk.update_credential(&result) == Some(true) {
        db.execute(
            "UPDATE users SET passkey = ?1 WHERE pubkey = ?2",
            (serde_json::to_string(&pk).unwrap(), &pubkey),
        )
        .unwrap();
    }
    drop(db);
    sign_in(&app, &pubkey)
}

async fn logout(State(app): S, headers: HeaderMap) -> StatusCode {
    if let Some(token) = session_token(&headers) {
        app.db.lock().unwrap().execute("DELETE FROM sessions WHERE token = ?1", [token]).unwrap();
    }
    StatusCode::NO_CONTENT
}
