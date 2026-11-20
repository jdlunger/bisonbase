use axum::{
    Json, Router,
    body::Bytes,
    extract::{Path, Query, State},
    http::{HeaderMap, StatusCode, Uri, header},
    response::{IntoResponse, Redirect, Response},
    routing::{get, post},
};
use ed25519_dalek::{Signer, SigningKey};
use fedcrdt_core::{
    CBOR, FederateData, GrantData, Map, Pubkey, Record, check_path, claim_signed_bytes, decode_id,
    encode_id, federate_peer, grant_signed_bytes, path_within, phrase, server_phrase, verify_sig,
};
use rusqlite::{Connection, OptionalExtension};
use serde::Deserialize;
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use std::{
    collections::HashSet,
    sync::{Arc, Mutex},
    time::{Duration, SystemTime, UNIX_EPOCH},
};

/// Bump to wipe the database when the schema changes incompatibly.
/// 5: server keys and federation.
const SCHEMA_VERSION: i64 = 5;

/// How far ahead of the server's clock a write's version may be.
const MAX_CLOCK_SKEW_MS: u64 = 10 * 60 * 1000;

/// Records per push to a peer.
const PUSH_BATCH: i64 = 100;

struct App {
    db: Mutex<Connection>,
    /// This server's own key; its public half is `pk`.
    key: SigningKey,
    pk: Pubkey,
    /// Wakes the push task when a record is stored.
    push: tokio::sync::Notify,
    http: reqwest::Client,
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
    let port = std::env::var("PORT").unwrap_or("8080".into());
    // Where other servers reach this one, and where the SPA is served (for links).
    let public_url = std::env::var("PUBLIC_URL").unwrap_or(format!("http://localhost:{port}"));
    let origin = std::env::var("ORIGIN").unwrap_or("http://localhost:5173".into());

    let db = Connection::open(&db_path).unwrap();
    let version: i64 = db.query_row("PRAGMA user_version", [], |r| r.get(0)).unwrap();
    if version < SCHEMA_VERSION {
        db.execute_batch(&format!(
            "DROP TABLE IF EXISTS records; DROP TABLE IF EXISTS notes; DROP TABLE IF EXISTS sessions; DROP TABLE IF EXISTS users;
             DROP TABLE IF EXISTS server; DROP TABLE IF EXISTS claim_tokens; DROP TABLE IF EXISTS peer_cursors;
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
        -- owner, path, author, version and type are copies of the record's fields, for querying.
        CREATE TABLE IF NOT EXISTS records (
            owner BLOB NOT NULL,
            path TEXT NOT NULL,
            author BLOB NOT NULL,
            version INTEGER NOT NULL,
            type TEXT NOT NULL,
            record BLOB NOT NULL,  -- the record's deterministic CBOR, signature included
            seq INTEGER NOT NULL,  -- local order of arrival, renewed on every change: what peers are pushed by
            received_from BLOB,    -- the server that pushed it here, if one did; it isn't pushed back there
            PRIMARY KEY (owner, path)
        );
        CREATE INDEX IF NOT EXISTS records_by_author ON records (author);
        CREATE INDEX IF NOT EXISTS records_by_seq ON records (seq);
        -- This server's own key pair: exactly one row.
        CREATE TABLE IF NOT EXISTS server (
            pubkey BLOB PRIMARY KEY,
            secret BLOB NOT NULL -- 32-byte Ed25519 seed
        );
        -- SHA-256 of the token in the unused claim link, while the server has no owner.
        CREATE TABLE IF NOT EXISTS claim_tokens (hash BLOB PRIMARY KEY);
        -- How far each peer (by ID) has been pushed: every record with seq <= this one, under the
        -- federate record with this version (a new version starts over).
        CREATE TABLE IF NOT EXISTS peer_cursors (
            peer BLOB PRIMARY KEY,
            federate_version INTEGER NOT NULL,
            seq INTEGER NOT NULL
        );",
    )
    .unwrap();

    let key = server_key(&db);
    let pk = key.verifying_key().to_bytes();
    let app = Arc::new(App { db: Mutex::new(db), key, pk, push: Default::default(), http: reqwest::Client::new() });
    app.init(&public_url, &origin);
    tokio::spawn(push_loop(app.clone()));

    let router = Router::new()
        .route("/api/users", get(users))
        .route("/api/users/{pubkey}", get(user))
        .route("/api/records", get(list_records).post(put_record))
        .route("/api/server", get(server_info))
        .route("/api/servers", get(servers))
        .route("/api/claim", post(claim))
        .route("/receive", post(receive))
        .with_state(app)
        .fallback(move |uri: Uri| async move {
            let path = uri.path_and_query().map_or("/", |p| p.as_str());
            Redirect::temporary(&format!("{origin}{path}"))
        });

    let listener = tokio::net::TcpListener::bind(format!("0.0.0.0:{port}")).await.unwrap();
    println!("listening {public_url}");
    axum::serve(listener, router).await.unwrap();
}

fn random<const N: usize>() -> [u8; N] {
    let mut b = [0; N];
    getrandom::fill(&mut b).unwrap();
    b
}

/// This server's key, made on first run.
fn server_key(db: &Connection) -> SigningKey {
    let secret: Option<[u8; 32]> = db.query_row("SELECT secret FROM server", [], |r| r.get(0)).optional().unwrap();
    secret.map(|s| SigningKey::from_bytes(&s)).unwrap_or_else(|| {
        let key = SigningKey::from_bytes(&random());
        let pk = key.verifying_key().to_bytes();
        db.execute("INSERT INTO server (pubkey, secret) VALUES (?1, ?2)", (pk, key.to_bytes())).unwrap();
        db.execute("INSERT OR IGNORE INTO users (pubkey) VALUES (?1)", [pk]).unwrap();
        println!("new server key: {} ({})", encode_id(&pk), server_phrase(&pk));
        key
    })
}

fn now_ms() -> u64 {
    SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_millis() as u64
}

fn stored_record(db: &Connection, owner: &Pubkey, path: &str) -> Option<Record> {
    let b: Option<Vec<u8>> =
        db.query_row("SELECT record FROM records WHERE owner = ?1 AND path = ?2", (owner, path), |r| r.get(0)).optional().unwrap();
    b.map(|b| Record::from_bytes(&b).unwrap())
}

/// Stores `rec` if it's valid and wins against what's at its (owner, path): a newer version, or for the
/// same version, the greater bytes, so every server keeps the same one. Ok(false): it didn't win.
/// `from`: the server that pushed it here.
fn store(db: &Connection, rec: &Record, from: Option<Pubkey>) -> Result<bool, String> {
    rec.check()?;
    if rec.version > now_ms() + MAX_CLOCK_SKEW_MS {
        return Err("version is too far in the future; check your clock".into());
    }
    let bytes = rec.to_bytes();
    let stored: Option<(i64, Vec<u8>)> = db
        .query_row("SELECT version, record FROM records WHERE owner = ?1 AND path = ?2", (rec.owner, &rec.path), |r| {
            Ok((r.get(0)?, r.get(1)?))
        })
        .optional()
        .unwrap();
    if stored.is_some_and(|(v, b)| (v as u64, b.as_slice()) >= (rec.version, bytes.as_slice())) {
        return Ok(false);
    }
    for pk in [rec.author, rec.owner] {
        db.execute("INSERT OR IGNORE INTO users (pubkey) VALUES (?1)", [pk]).unwrap();
    }
    db.execute(
        "INSERT INTO records (owner, path, author, version, type, record, seq, received_from)
         VALUES (?1, ?2, ?3, ?4, ?5, ?6, (SELECT coalesce(max(seq), 0) + 1 FROM records), ?7)
         ON CONFLICT (owner, path) DO UPDATE SET author = ?3, version = ?4, type = ?5, record = ?6,
           seq = excluded.seq, received_from = ?7",
        (rec.owner, &rec.path, rec.author, rec.version as i64, &rec.kind, bytes, from),
    )
    .unwrap();
    Ok(true)
}

impl App {
    /// A record in this server's own space, signed by it, newer than what's there.
    fn sign(&self, db: &Connection, path: &str, kind: &str, data: CBOR) -> Record {
        let prev = stored_record(db, &self.pk, path).map_or(0, |r| r.version);
        let mut r = Record {
            author: self.pk,
            owner: self.pk,
            path: path.into(),
            version: now_ms().max(prev + 1),
            kind: kind.into(),
            data,
            authorization: None,
            signature: [0; 64],
            extra: Map::new(),
        };
        r.signature = self.key.sign(&r.signed_bytes()).to_bytes();
        r
    }

    /// Writes a record in this server's space.
    fn write(&self, db: &Connection, path: &str, kind: &str, data: CBOR) {
        let r = self.sign(db, path, kind, data);
        store(db, &r, None).unwrap();
        self.push.notify_one();
    }

    /// Keeps the /server record's URL current and, while there's no owner, prints a fresh claim link.
    fn init(&self, public_url: &str, origin: &str) {
        let db = self.db.lock().unwrap();
        let mut m = Map::new();
        m.insert("url", public_url);
        let data = CBOR::from(m);
        if stored_record(&db, &self.pk, "/server").is_none_or(|r| r.data != data) {
            self.write(&db, "/server", "server", data);
        }
        if self.owner(&db).is_none() {
            let token: [u8; 32] = random();
            db.execute("DELETE FROM claim_tokens", []).unwrap();
            db.execute("INSERT INTO claim_tokens (hash) VALUES (?1)", [Sha256::digest(token).as_slice()]).unwrap();
            println!("\nThis server has no owner yet. Open this one-time link to claim it:\n  {origin}/claim#{}\n", bs58::encode(token).into_string());
        }
    }

    /// Who claimed this server, from its /owner record.
    fn owner(&self, db: &Connection) -> Option<Pubkey> {
        stored_record(db, &self.pk, "/owner")?.owner_user()
    }
}

/// Whether `pk` has a server record (or is named by a federate record).
fn is_server(db: &Connection, pk: &Pubkey) -> bool {
    db.query_row(
        "SELECT 1 FROM records WHERE (owner = ?1 AND path = '/server' AND type = 'server') OR (type = 'federate' AND path = ?2)",
        (pk, format!("/federate/{}", encode_id(pk))),
        |_| Ok(()),
    )
    .optional()
    .unwrap()
    .is_some()
}

fn user_json(pk: &Pubkey, server: bool) -> Value {
    let phrase = if server { server_phrase(pk) } else { phrase(pk) };
    json!({ "pubkey": encode_id(pk), "phrase": phrase, "server": server })
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
    Json(keys.iter().map(|pk| user_json(pk, is_server(&db, pk))).collect())
}

/// Any public key's phrase, whether or not it has written anything yet.
async fn user(State(app): S, Path(pubkey): Path<String>) -> Response {
    match parse_id(&pubkey) {
        Ok(pk) => Json(user_json(&pk, is_server(&app.db.lock().unwrap(), &pk))).into_response(),
        Err(e) => e,
    }
}

// ---- records (see core/src/lib.rs): signed CBOR in, signed CBOR out ----

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
    ([(header::CONTENT_TYPE, "application/cbor")], cbor_array(&records)).into_response()
}

/// Stores a record (CBOR body) if it's valid and newer than what's at its (owner, path).
async fn put_record(State(app): S, body: Bytes) -> Response {
    let rec = match Record::from_bytes(&body) {
        Ok(r) => r,
        Err(e) => return err(StatusCode::BAD_REQUEST, format!("bad record: {e}")),
    };
    match store(&app.db.lock().unwrap(), &rec, None) {
        Ok(true) => {
            app.push.notify_one();
            StatusCode::NO_CONTENT.into_response()
        }
        Ok(false) => err(StatusCode::CONFLICT, "a newer version of this record exists"),
        Err(e) => err(StatusCode::BAD_REQUEST, format!("bad record: {e}")),
    }
}

// ---- this server, and claiming it ----

/// Who this server is, and who owns it. Readable from any origin, so a server's owner can look up a peer's ID.
async fn server_info(State(app): S) -> Response {
    let owner = app.owner(&app.db.lock().unwrap());
    let body = json!({ "pubkey": encode_id(&app.pk), "phrase": server_phrase(&app.pk), "owner": owner.map(|o| encode_id(&o)) });
    ([(header::ACCESS_CONTROL_ALLOW_ORIGIN, "*")], Json(body)).into_response()
}

/// IDs (base58) of every key known to be a server's: those with a server record, and peers named by federate records.
async fn servers(State(app): S) -> Json<Vec<String>> {
    let db = app.db.lock().unwrap();
    let mut stmt = db.prepare("SELECT owner FROM records WHERE path = '/server' AND type = 'server'").unwrap();
    let mut keys: HashSet<Pubkey> = stmt.query_map([], |r| r.get(0)).unwrap().flatten().collect();
    let mut stmt = db.prepare("SELECT path FROM records WHERE type = 'federate'").unwrap();
    keys.extend(stmt.query_map([], |r| r.get::<_, String>(0)).unwrap().flatten().filter_map(|p| federate_peer(&p)));
    Json(keys.iter().map(encode_id).collect())
}

/// A claim: the token from the one-time link, and the claiming user's ID and signature over
/// `claim_signed_bytes`, all base58.
#[derive(Deserialize)]
struct Claim {
    token: String,
    user: String,
    signature: String,
}

/// Makes the claiming user this server's owner: an /owner record, and a grant on /federate.
async fn claim(State(app): S, Json(c): Json<Claim>) -> Response {
    let user = match parse_id(&c.user) {
        Ok(u) => u,
        Err(e) => return e,
    };
    let (Ok(token), Some(sig)) = (
        bs58::decode(&c.token).into_vec(),
        bs58::decode(&c.signature).into_vec().ok().and_then(|s| <[u8; 64]>::try_from(s).ok()),
    ) else {
        return err(StatusCode::BAD_REQUEST, "malformed claim");
    };
    if let Err(e) = verify_sig(&user, &claim_signed_bytes(&app.pk, &token), &sig) {
        return err(StatusCode::BAD_REQUEST, format!("claim: {e}"));
    }
    let db = app.db.lock().unwrap();
    if db.execute("DELETE FROM claim_tokens WHERE hash = ?1", [Sha256::digest(&token).as_slice()]).unwrap() == 0 {
        return err(StatusCode::FORBIDDEN, "This claim link was already used, or isn't for this server.");
    }
    let mut m = Map::new();
    m.insert("user", CBOR::to_byte_string(user));
    app.write(&db, "/owner", "owner", m.into());
    let grant = GrantData { grantee: user, path: "/federate".into(), signature: app.key.sign(&grant_signed_bytes(&user, &app.pk, "/federate")).to_bytes() };
    let at = format!("/grants/{}", bs58::encode(random::<8>()).into_string());
    app.write(&db, &at, "grant", grant.to_cbor());
    println!("claimed by {} ({})", encode_id(&user), phrase(&user));
    Json(json!({ "server": encode_id(&app.pk) })).into_response()
}

/// A CBOR array of stored records (each already dCBOR).
fn cbor_array(records: &[Vec<u8>]) -> Vec<u8> {
    let items: Vec<CBOR> = records.iter().map(|r| CBOR::try_from_data(r).expect("stored records are dCBOR")).collect();
    CBOR::from(items).to_cbor_data()
}

// ---- federation: pushing records to peers, and receiving them ----

/// Stores records pushed by another server: a CBOR array of records, with the pusher's ID (base58) in
/// X-From. Answers, per record, "stored", "have" (this one or a newer one), or why it was refused.
async fn receive(State(app): S, headers: HeaderMap, body: Bytes) -> Response {
    let from = headers.get("x-from").and_then(|v| v.to_str().ok()).and_then(decode_id);
    let Some(items) = CBOR::try_from_data(&body).ok().and_then(CBOR::into_array) else {
        return err(StatusCode::BAD_REQUEST, "expected a CBOR array of records");
    };
    let db = app.db.lock().unwrap();
    let results: Vec<Value> = items
        .into_iter()
        .map(|v| match Record::from_cbor(&v).and_then(|r| store(&db, &r, from)) {
            Ok(true) => "stored".into(),
            Ok(false) => "have".into(),
            Err(e) => format!("bad record: {e}").into(),
        })
        .collect();
    if results.iter().any(|r| r == "stored") {
        app.push.notify_one();
    }
    Json(results).into_response()
}

/// Pushes new records to every peer whenever something is stored, and retries every 10s.
async fn push_loop(app: Arc<App>) {
    loop {
        for (peer, version, fed) in peers(&app) {
            if let Err(e) = push_to(&app, peer, version, &fed).await {
                eprintln!("push to {} at {}: {e}", server_phrase(&peer), fed.url);
            }
        }
        let _ = tokio::time::timeout(Duration::from_secs(10), app.push.notified()).await;
    }
}

/// Peers from this server's federate records: (ID, the record's version, what to push). Forgets how far
/// removed peers got.
fn peers(app: &App) -> Vec<(Pubkey, u64, FederateData)> {
    let db = app.db.lock().unwrap();
    let mut stmt = db.prepare("SELECT record FROM records WHERE owner = ?1 AND type = 'federate'").unwrap();
    let peers: Vec<_> = stmt
        .query_map([app.pk], |r| r.get::<_, Vec<u8>>(0))
        .unwrap()
        .flatten()
        .filter_map(|b| {
            let r = Record::from_bytes(&b).ok()?;
            Some((federate_peer(&r.path)?, r.version, FederateData::from_cbor(&r.data).ok()?))
        })
        .collect();
    let live: HashSet<Pubkey> = peers.iter().map(|p| p.0).collect();
    let mut stmt = db.prepare("SELECT peer FROM peer_cursors").unwrap();
    for gone in stmt.query_map([], |r| r.get::<_, Pubkey>(0)).unwrap().flatten().filter(|p| !live.contains(p)) {
        db.execute("DELETE FROM peer_cursors WHERE peer = ?1", [gone]).unwrap();
    }
    peers
}

/// Pushes everything `peer` hasn't been sent yet, in batches, moving its cursor after each one it accepts.
/// Leaves out this server's federate records, and records `peer` pushed here.
async fn push_to(app: &App, peer: Pubkey, version: u64, fed: &FederateData) -> Result<(), reqwest::Error> {
    loop {
        let (batch, last) = {
            let db = app.db.lock().unwrap();
            let cursor: i64 = db
                .query_row("SELECT seq FROM peer_cursors WHERE peer = ?1 AND federate_version = ?2", (peer, version as i64), |r| r.get(0))
                .optional()
                .unwrap()
                .unwrap_or(0);
            let mut stmt = db
                .prepare("SELECT seq, owner, path, type, received_from, record FROM records WHERE seq > ?1 ORDER BY seq LIMIT ?2")
                .unwrap();
            let rows: Vec<(i64, Pubkey, String, String, Option<Pubkey>, Vec<u8>)> = stmt
                .query_map((cursor, PUSH_BATCH), |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?, r.get(3)?, r.get(4)?, r.get(5)?)))
                .unwrap()
                .flatten()
                .collect();
            let Some(last) = rows.last().map(|r| r.0) else { return Ok(()) };
            let batch: Vec<Vec<u8>> = rows
                .into_iter()
                .filter(|(_, owner, path, kind, from, _)| {
                    *from != Some(peer)
                        && !(*owner == app.pk && path_within(path, "/federate"))
                        && fed.wants(owner, path, kind)
                })
                .map(|r| r.5)
                .collect();
            (batch, last)
        };
        if !batch.is_empty() {
            let body = cbor_array(&batch);
            app.http
                .post(format!("{}/receive", fed.url.trim_end_matches('/')))
                .header(header::CONTENT_TYPE, "application/cbor")
                .header("x-from", encode_id(&app.pk))
                .body(body)
                .timeout(Duration::from_secs(10))
                .send()
                .await?
                .error_for_status()?;
        }
        app.db
            .lock()
            .unwrap()
            .execute(
                "INSERT OR REPLACE INTO peer_cursors (peer, federate_version, seq) VALUES (?1, ?2, ?3)",
                (peer, version as i64, last),
            )
            .unwrap();
    }
}
