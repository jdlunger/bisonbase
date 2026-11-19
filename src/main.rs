use axum::{
    Json, Router,
    extract::{Path, Query, State},
    http::StatusCode,
    response::{IntoResponse, Response},
    routing::get,
};
use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD as B64};
use ed25519_dalek::{Signature, VerifyingKey};
use fedcrdt::{NOTE_NAMESPACE, Pubkey, decode_id, encode_id, is_sshsig, phrase, verify_sshsig, write_payload};
use rusqlite::{Connection, OptionalExtension};
use serde::Deserialize;
use serde_json::{Value, json};
use std::{
    sync::{Arc, Mutex},
    time::{SystemTime, UNIX_EPOCH},
};
use tower_http::services::{ServeDir, ServeFile};

/// Bump to wipe the database when the schema changes incompatibly.
/// 3: no sessions; every note write is signed by its author and versioned.
const SCHEMA_VERSION: i64 = 3;

/// How far ahead of the server's clock a write's version may be.
const MAX_CLOCK_SKEW_MS: i64 = 10 * 60 * 1000;

struct App {
    db: Mutex<Connection>,
}

type S = State<Arc<App>>;

#[tokio::main]
async fn main() {
    let db_path = std::env::var("DB").unwrap_or("users.db".into());
    // `--drop-db` deletes the database and exits; it doesn't start the server, so that dev-mode
    // restarts (which re-run the same command) can't wipe it again. See `npm run dev:fresh`.
    if std::env::args().skip(1).any(|a| a == "--drop-db") {
        for f in [db_path.clone(), format!("{db_path}-wal"), format!("{db_path}-shm"), format!("{db_path}-journal")] {
            match std::fs::remove_file(&f) {
                Ok(()) => println!("deleted {f}"),
                Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
                Err(e) => panic!("couldn't delete {f}: {e}"),
            }
        }
        return;
    }
    let db = Connection::open(&db_path).unwrap();
    let version: i64 = db.query_row("PRAGMA user_version", [], |r| r.get(0)).unwrap();
    if version < SCHEMA_VERSION {
        db.execute_batch(&format!(
            "DROP TABLE IF EXISTS notes; DROP TABLE IF EXISTS sessions; DROP TABLE IF EXISTS users;
             PRAGMA user_version = {SCHEMA_VERSION};"
        ))
        .unwrap();
    }
    db.execute_batch(
        "-- Store raw bytes (keys, signatures), never their base58/base64 or phrases: those are only
        -- for input and output, at the API's edges.
        CREATE TABLE IF NOT EXISTS users (
            pubkey BLOB PRIMARY KEY, -- 32-byte Ed25519 public key: the user's ID
            created_at INTEGER NOT NULL DEFAULT (unixepoch())
        );
        -- One row per note, holding its latest signed write (last writer wins, by version).
        -- Deleted notes stay as tombstones so an older signed write can't resurrect them.
        CREATE TABLE IF NOT EXISTS notes (
            id TEXT PRIMARY KEY,
            author BLOB NOT NULL REFERENCES users(pubkey),
            version INTEGER NOT NULL,
            deleted INTEGER NOT NULL DEFAULT 0,
            body TEXT NOT NULL DEFAULT '',
            encrypted INTEGER NOT NULL DEFAULT 0,
            wrapped_key TEXT,
            sig BLOB NOT NULL,
            created_at INTEGER NOT NULL DEFAULT (unixepoch()),
            updated_at INTEGER NOT NULL DEFAULT (unixepoch())
        );",
    )
    .unwrap();

    let app = Arc::new(App { db: Mutex::new(db) });

    // The React app (web/), built with `npm run build`; unknown paths fall back to index.html.
    let web_dir = std::env::var("WEB_DIR").unwrap_or("web/dist".into());
    let spa = ServeDir::new(&web_dir).fallback(ServeFile::new(format!("{web_dir}/index.html")));

    let router = Router::new()
        .route("/api/users", get(users))
        .route("/api/users/{pubkey}", get(user))
        .route("/api/notes", get(list_notes))
        .route("/api/notes/{id}", axum::routing::put(put_note).delete(delete_note))
        .with_state(app)
        .fallback_service(spa);

    let port = std::env::var("PORT").unwrap_or("8080".into());
    let listener = tokio::net::TcpListener::bind(format!("0.0.0.0:{port}")).await.unwrap();
    println!("listening http://localhost:{port}");
    axum::serve(listener, router).await.unwrap();
}

/// Checks a signature by `pk` over `msg`. `sig` is either a bare Ed25519 signature (passkey-derived keys)
/// or an SSHSIG blob (ssh-ed25519 keys, see src/lib.rs).
fn verify(pk: &Pubkey, msg: &[u8], sig: &[u8]) -> Result<(), String> {
    if is_sshsig(sig) {
        return verify_sshsig(pk, NOTE_NAMESPACE, msg, sig);
    }
    let sig: [u8; 64] = sig.try_into().map_err(|_| "signature isn't 64 bytes, nor an SSH signature")?;
    let pk = VerifyingKey::from_bytes(pk).map_err(|e| e.to_string())?;
    pk.verify_strict(msg, &Signature::from_bytes(&sig)).map_err(|_| "signature doesn't match".to_string())
}

fn user_json(pk: &Pubkey) -> Value {
    json!({ "pubkey": encode_id(pk), "phrase": phrase(pk) })
}

/// Parses an ID from the API (base58).
fn parse_id(s: &str) -> Result<Pubkey, Response> {
    decode_id(s).ok_or_else(|| err(StatusCode::BAD_REQUEST, "ID isn't 32 bytes of base58"))
}

fn err(status: StatusCode, e: impl std::fmt::Display) -> Response {
    (status, e.to_string()).into_response()
}

async fn users(State(app): S) -> Json<Value> {
    let db = app.db.lock().unwrap();
    let mut stmt = db.prepare("SELECT pubkey FROM users ORDER BY created_at").unwrap();
    let keys: Vec<Pubkey> = stmt.query_map([], |r| r.get(0)).unwrap().flatten().collect();
    Json(keys.iter().map(user_json).collect())
}

/// Any public key's phrase, whether or not it has written anything yet.
async fn user(Path(pubkey): Path<String>) -> Response {
    match parse_id(&pubkey) {
        Ok(pk) => Json(user_json(&pk)).into_response(),
        Err(e) => e,
    }
}

// ---- notes: every write is a signed, versioned operation ----

#[derive(Deserialize)]
struct PutNote {
    /// base58 ID.
    author: String,
    /// Milliseconds since the epoch, by the author's clock; a write only lands if it's newer.
    version: i64,
    /// Plain text, or base64url(iv || AES-GCM ciphertext) under a random per-note key when `encrypted`.
    body: String,
    #[serde(default)]
    encrypted: bool,
    /// For encrypted notes: base64url(iv || per-note key encrypted under the author's note key).
    wrapped_key: Option<String>,
    /// base64url signature by `author` over write_payload(..): bare Ed25519, or SSHSIG (see verify).
    sig: String,
}

#[derive(Deserialize)]
struct DeleteNote {
    author: String,
    version: i64,
    sig: String,
}

fn valid_id(id: &str) -> bool {
    (1..=64).contains(&id.len()) && id.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_')
}

fn now_ms() -> i64 {
    SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_millis() as i64
}

/// Checks the signature, the author, and that the write is newer than what's stored.
/// Returns the author's ID and the signature, decoded.
fn check_write(
    app: &App,
    id: &str,
    author: &str,
    version: i64,
    payload: &str,
    sig: &str,
) -> Result<(Pubkey, Vec<u8>), Response> {
    if !valid_id(id) {
        return Err(err(StatusCode::BAD_REQUEST, "bad note id"));
    }
    if version > now_ms() + MAX_CLOCK_SKEW_MS {
        return Err(err(StatusCode::BAD_REQUEST, "version is too far in the future; check your clock"));
    }
    let author = parse_id(author)?;
    let sig = B64.decode(sig).map_err(|_| err(StatusCode::BAD_REQUEST, "signature isn't base64url"))?;
    verify(&author, payload.as_bytes(), &sig).map_err(|e| err(StatusCode::BAD_REQUEST, format!("bad signature: {e}")))?;
    let existing: Option<(Pubkey, i64)> = app
        .db
        .lock()
        .unwrap()
        .query_row("SELECT author, version FROM notes WHERE id = ?1", [id], |r| Ok((r.get(0)?, r.get(1)?)))
        .optional()
        .unwrap();
    match existing {
        Some((a, _)) if a != author => Err(err(StatusCode::FORBIDDEN, "that note belongs to someone else")),
        Some((_, v)) if v >= version => Err(err(StatusCode::CONFLICT, "a newer version of this note exists")),
        _ => Ok((author, sig)),
    }
}

#[derive(Deserialize)]
struct NotesQuery {
    /// Only this author's notes (base58 ID).
    author: Option<String>,
}

async fn list_notes(State(app): S, Query(q): Query<NotesQuery>) -> Response {
    let author = match q.author.as_deref().map(parse_id).transpose() {
        Ok(a) => a,
        Err(e) => return e,
    };
    let db = app.db.lock().unwrap();
    let mut stmt = db
        .prepare(
            "SELECT id, author, version, body, encrypted, wrapped_key, sig, created_at, updated_at
             FROM notes WHERE NOT deleted AND (?1 IS NULL OR author = ?1) ORDER BY created_at DESC, id",
        )
        .unwrap();
    let notes: Vec<Value> = stmt
        .query_map([author], |r| {
            Ok(json!({
                "id": r.get::<_, String>(0)?,
                "author": user_json(&r.get(1)?),
                "version": r.get::<_, i64>(2)?,
                "body": r.get::<_, String>(3)?,
                "encrypted": r.get::<_, bool>(4)?,
                "wrapped_key": r.get::<_, Option<String>>(5)?,
                "sig": B64.encode(r.get::<_, Vec<u8>>(6)?),
                "created_at": r.get::<_, i64>(7)?,
                "updated_at": r.get::<_, i64>(8)?,
            }))
        })
        .unwrap()
        .flatten()
        .collect();
    Json(Value::Array(notes)).into_response()
}

/// Creates or replaces a note.
async fn put_note(State(app): S, Path(id): Path<String>, Json(req): Json<PutNote>) -> Response {
    if req.body.is_empty() || req.body.trim() != req.body {
        return err(StatusCode::BAD_REQUEST, "note must be non-empty and trimmed");
    }
    if req.encrypted {
        // 12-byte IV + 32-byte key + 16-byte GCM tag.
        if !req.wrapped_key.as_deref().is_some_and(|k| B64.decode(k).is_ok_and(|b| b.len() == 60)) {
            return err(StatusCode::BAD_REQUEST, "encrypted note is missing its wrapped key");
        }
        // 12-byte IV + 16-byte GCM tag at minimum.
        if !B64.decode(&req.body).is_ok_and(|b| b.len() > 28) {
            return err(StatusCode::BAD_REQUEST, "encrypted note body isn't valid ciphertext");
        }
    } else if req.wrapped_key.is_some() {
        return err(StatusCode::BAD_REQUEST, "plain notes don't have a wrapped key");
    }
    let payload = write_payload(&id, req.version, Some((req.encrypted, req.wrapped_key.as_deref(), &req.body)));
    let (author, sig) = match check_write(&app, &id, &req.author, req.version, &payload, &req.sig) {
        Ok(v) => v,
        Err(e) => return e,
    };
    let db = app.db.lock().unwrap();
    db.execute("INSERT OR IGNORE INTO users (pubkey) VALUES (?1)", [author]).unwrap();
    db.execute(
        "INSERT INTO notes (id, author, version, body, encrypted, wrapped_key, sig)
         VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)
         ON CONFLICT (id) DO UPDATE SET version = ?3, deleted = 0, body = ?4, encrypted = ?5,
             wrapped_key = ?6, sig = ?7, updated_at = unixepoch()",
        (&id, author, req.version, &req.body, req.encrypted, &req.wrapped_key, sig),
    )
    .unwrap();
    StatusCode::NO_CONTENT.into_response()
}

/// Deletes a note, leaving a signed tombstone.
async fn delete_note(State(app): S, Path(id): Path<String>, Json(req): Json<DeleteNote>) -> Response {
    let payload = write_payload(&id, req.version, None);
    let (author, sig) = match check_write(&app, &id, &req.author, req.version, &payload, &req.sig) {
        Ok(v) => v,
        Err(e) => return e,
    };
    let db = app.db.lock().unwrap();
    db.execute("INSERT OR IGNORE INTO users (pubkey) VALUES (?1)", [author]).unwrap();
    db.execute(
        "INSERT INTO notes (id, author, version, deleted, sig) VALUES (?1, ?2, ?3, 1, ?4)
         ON CONFLICT (id) DO UPDATE SET version = ?3, deleted = 1, body = '', encrypted = 0,
             wrapped_key = NULL, sig = ?4, updated_at = unixepoch()",
        (&id, author, req.version, sig),
    )
    .unwrap();
    StatusCode::NO_CONTENT.into_response()
}
