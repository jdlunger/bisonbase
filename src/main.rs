use axum::{
    Json, Router,
    body::Bytes,
    extract::{Path, Query, State},
    http::{StatusCode, Uri, header},
    response::{IntoResponse, Redirect, Response},
    routing::get,
};
use fedcrdt::{Pubkey, Record, check_path, decode_id, encode_id, phrase};
use rusqlite::{Connection, OptionalExtension};
use serde::Deserialize;
use serde_json::{Value, json};
use std::{
    sync::{Arc, Mutex},
    time::{SystemTime, UNIX_EPOCH},
};

/// Bump to wipe the database when the schema changes incompatibly.
/// 4: notes became records (signed CBOR, see src/lib.rs).
const SCHEMA_VERSION: i64 = 4;

/// How far ahead of the server's clock a write's version may be.
const MAX_CLOCK_SKEW_MS: u64 = 10 * 60 * 1000;

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
            "DROP TABLE IF EXISTS records; DROP TABLE IF EXISTS notes; DROP TABLE IF EXISTS sessions; DROP TABLE IF EXISTS users;
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
        -- One row per (owner, path), holding the newest record written there, exactly as signed.
        -- Deletes stay as tombstone records so an older signed write can't resurrect what they deleted.
        -- The other columns are copies of the record's fields, for querying.
        CREATE TABLE IF NOT EXISTS records (
            owner BLOB NOT NULL,
            path TEXT NOT NULL,
            author BLOB NOT NULL,
            version INTEGER NOT NULL,
            type TEXT NOT NULL,
            record BLOB NOT NULL, -- the record's deterministic CBOR, signature included
            PRIMARY KEY (owner, path)
        );
        CREATE INDEX IF NOT EXISTS records_by_author ON records (author);",
    )
    .unwrap();

    let app = Arc::new(App { db: Mutex::new(db) });


    let router = Router::new()
        .route("/api/users", get(users))
        .route("/api/users/{pubkey}", get(user))
        .route("/api/records", get(list_records).post(put_record))
        .with_state(app)
        .fallback(|uri: Uri| async move {
            let path = uri.path_and_query().map_or("/", |p| p.as_str());
            Redirect::temporary(&format!("http://localhost:5173{path}"))
        });

    let port = std::env::var("PORT").unwrap_or("8080".into());
    let listener = tokio::net::TcpListener::bind(format!("0.0.0.0:{port}")).await.unwrap();
    println!("listening http://localhost:{port}");
    axum::serve(listener, router).await.unwrap();
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

// ---- records (see src/lib.rs): signed CBOR in, signed CBOR out ----

fn now_ms() -> u64 {
    SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_millis() as u64
}

#[derive(Deserialize)]
struct RecordsQuery {
    /// Only records in this space (base58 ID).
    owner: Option<String>,
    /// Only records by this author (base58 ID).
    author: Option<String>,
    /// Only records this user (base58 ID) owns or wrote.
    user: Option<String>,
    /// Only records of this type.
    #[serde(rename = "type")]
    kind: Option<String>,
    /// Only records at or under this path.
    prefix: Option<String>,
}

/// Live (non-tombstone) records matching the query, newest first, as a CBOR array of records.
async fn list_records(State(app): S, Query(q): Query<RecordsQuery>) -> Response {
    let parse = |s: Option<String>| s.as_deref().map(parse_id).transpose();
    let (owner, author, user) = match (parse(q.owner), parse(q.author), parse(q.user)) {
        (Ok(o), Ok(a), Ok(u)) => (o, a, u),
        (Err(e), _, _) | (_, Err(e), _) | (_, _, Err(e)) => return e,
    };
    let prefix = q.prefix.filter(|p| p != "/");
    if let Some(Err(e)) = prefix.as_deref().map(check_path) {
        return err(StatusCode::BAD_REQUEST, format!("bad prefix: {e}"));
    }
    let db = app.db.lock().unwrap();
    let mut stmt = db
        .prepare(
            "SELECT record FROM records
             WHERE type != 'tombstone' AND (?1 IS NULL OR owner = ?1) AND (?2 IS NULL OR author = ?2)
               AND (?3 IS NULL OR path = ?3 OR substr(path, 1, length(?3) + 1) = ?3 || '/')
               AND (?4 IS NULL OR owner = ?4 OR author = ?4) AND (?5 IS NULL OR type = ?5)
             ORDER BY version DESC",
        )
        .unwrap();
    let records: Vec<Vec<u8>> = stmt.query_map((owner, author, prefix, user, q.kind), |r| r.get(0)).unwrap().flatten().collect();
    // Each stored record is already deterministic CBOR, so the array can be assembled directly.
    let mut body = fedcrdt::cbor_head(4, records.len() as u64);
    records.iter().for_each(|r| body.extend(r));
    ([(header::CONTENT_TYPE, "application/cbor")], body).into_response()
}

/// Stores a record (CBOR body) if it's valid and newer than what's at its (owner, path).
async fn put_record(State(app): S, body: Bytes) -> Response {
    let rec = match Record::from_bytes(&body) {
        Ok(r) => r,
        Err(e) => return err(StatusCode::BAD_REQUEST, format!("bad record: {e}")),
    };
    if let Err(e) = rec.check() {
        return err(StatusCode::BAD_REQUEST, format!("bad record: {e}"));
    }
    if rec.version > now_ms() + MAX_CLOCK_SKEW_MS {
        return err(StatusCode::BAD_REQUEST, "version is too far in the future; check your clock");
    }
    let db = app.db.lock().unwrap();
    let stored: Option<i64> = db
        .query_row("SELECT version FROM records WHERE owner = ?1 AND path = ?2", (rec.owner, &rec.path), |r| r.get(0))
        .optional()
        .unwrap();
    if stored.is_some_and(|v| v as u64 >= rec.version) {
        return err(StatusCode::CONFLICT, "a newer version of this record exists");
    }
    for pk in [rec.author, rec.owner] {
        db.execute("INSERT OR IGNORE INTO users (pubkey) VALUES (?1)", [pk]).unwrap();
    }
    db.execute(
        "INSERT INTO records (owner, path, author, version, type, record) VALUES (?1, ?2, ?3, ?4, ?5, ?6)
         ON CONFLICT (owner, path) DO UPDATE SET author = ?3, version = ?4, type = ?5, record = ?6",
        (rec.owner, &rec.path, rec.author, rec.version as i64, &rec.kind, rec.to_bytes()),
    )
    .unwrap();
    StatusCode::NO_CONTENT.into_response()
}
