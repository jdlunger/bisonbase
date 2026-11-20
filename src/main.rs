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
    CBOR, FederateData, GrantData, Hash, Map, NODE_INFO_PATH, NODE_PATH, OWNER_PATH, Pubkey, Record, check_prefix,
    claim_signed_bytes, decode_id, encode_b58, encode_id, node_phrase, path_within, phrase, verify_sig,
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
/// 6: records identified by hash, nodes.
const SCHEMA_VERSION: i64 = 6;

/// How far ahead of the node's clock a write's version may be.
const MAX_CLOCK_SKEW_MS: u64 = 10 * 60 * 1000;

/// Records per push to a peer.
const PUSH_BATCH: i64 = 100;

struct App {
    db: Mutex<Connection>,
    /// This node's own key; its public half is `pk`.
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
    // `--drop-db` deletes the database and exits; it doesn't start the node, so that dev-mode
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
    // Where other nodes reach this one, and where the SPA is served (for links).
    let public_url = std::env::var("PUBLIC_URL").unwrap_or(format!("http://localhost:{port}"));
    let origin = std::env::var("ORIGIN").unwrap_or("http://localhost:5173".into());

    let db = Connection::open(&db_path).unwrap();
    let version: i64 = db.query_row("PRAGMA user_version", [], |r| r.get(0)).unwrap();
    if version < SCHEMA_VERSION {
        db.execute_batch(&format!(
            "DROP VIEW IF EXISTS heads; DROP TABLE IF EXISTS records; DROP TABLE IF EXISTS notes; DROP TABLE IF EXISTS sessions;
             DROP TABLE IF EXISTS users; DROP TABLE IF EXISTS server; DROP TABLE IF EXISTS node; DROP TABLE IF EXISTS claim_tokens;
             DROP TABLE IF EXISTS peer_cursors;
             PRAGMA user_version = {SCHEMA_VERSION};"
        ))
        .unwrap();
    }
    db.execute_batch(
        "-- Store raw bytes (keys, signatures, hashes), never their base58/base64 or phrases: those are only
        -- for input and output, at the API's edges.
        CREATE TABLE IF NOT EXISTS users (
            pubkey BLOB PRIMARY KEY, -- 32-byte Ed25519 public key: the user's ID
            created_at INTEGER NOT NULL DEFAULT (unixepoch())
        );
        -- Every record, exactly as signed, by hash. Records never change: edits and deletes (tombstones)
        -- are new records. author, path, version, type and edits are copies of the record's fields, for
        -- querying.
        CREATE TABLE IF NOT EXISTS records (
            hash BLOB PRIMARY KEY, -- SHA-256 of `record`
            author BLOB NOT NULL,
            path TEXT NOT NULL,
            version INTEGER NOT NULL,
            type TEXT NOT NULL,
            edits BLOB,            -- hash of the version it edits or deletes
            root BLOB NOT NULL,    -- its chain's first record: follows `edits` back as far as this node has
            record BLOB NOT NULL,  -- the record's deterministic CBOR, signature included
            seq INTEGER NOT NULL,  -- local order of arrival: what peers are pushed by
            received_from BLOB     -- the node that pushed it here, if one did; it isn't pushed back there
        );
        CREATE INDEX IF NOT EXISTS records_by_root ON records (root);
        CREATE INDEX IF NOT EXISTS records_by_path ON records (path);
        CREATE INDEX IF NOT EXISTS records_by_seq ON records (seq);
        -- Each live chain's current version: its newest (by version, then hash), unless any version is a tombstone.
        CREATE VIEW IF NOT EXISTS heads AS
            SELECT r.* FROM records r
            WHERE NOT EXISTS (SELECT 1 FROM records n WHERE n.root = r.root
                                AND (n.version > r.version OR (n.version = r.version AND n.hash > r.hash)))
              AND NOT EXISTS (SELECT 1 FROM records t WHERE t.root = r.root AND t.type = 'tombstone');
        -- This node's own key pair: exactly one row.
        CREATE TABLE IF NOT EXISTS node (
            pubkey BLOB PRIMARY KEY,
            secret BLOB NOT NULL -- 32-byte Ed25519 seed
        );
        -- SHA-256 of the token in the unused claim link, while the node has no owner.
        CREATE TABLE IF NOT EXISTS claim_tokens (hash BLOB PRIMARY KEY);
        -- How far each federate record (by hash) has been pushed: every record with seq <= this one.
        -- An edited federate record starts over.
        CREATE TABLE IF NOT EXISTS peer_cursors (
            federate BLOB PRIMARY KEY,
            seq INTEGER NOT NULL
        );",
    )
    .unwrap();

    let key = node_key(&db);
    let pk = key.verifying_key().to_bytes();
    let app = Arc::new(App { db: Mutex::new(db), key, pk, push: Default::default(), http: reqwest::Client::new() });
    app.init(&public_url, &origin);
    tokio::spawn(push_loop(app.clone()));

    let router = Router::new()
        .route("/api/users", get(users))
        .route("/api/users/{pubkey}", get(user))
        .route("/api/records", get(list_records).post(put_record))
        .route("/api/records/{hash}", get(chain))
        .route("/api/node", get(node_info))
        .route("/api/nodes", get(nodes))
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

/// This node's key, made on first run.
fn node_key(db: &Connection) -> SigningKey {
    let secret: Option<[u8; 32]> = db.query_row("SELECT secret FROM node", [], |r| r.get(0)).optional().unwrap();
    secret.map(|s| SigningKey::from_bytes(&s)).unwrap_or_else(|| {
        let key = SigningKey::from_bytes(&random());
        let pk = key.verifying_key().to_bytes();
        db.execute("INSERT INTO node (pubkey, secret) VALUES (?1, ?2)", (pk, key.to_bytes())).unwrap();
        db.execute("INSERT OR IGNORE INTO users (pubkey) VALUES (?1)", [pk]).unwrap();
        println!("new node key: {} ({})", encode_id(&pk), node_phrase(&pk));
        key
    })
}

fn now_ms() -> u64 {
    SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_millis() as u64
}

fn parse_record(b: Vec<u8>) -> Record {
    Record::from_bytes(&b).expect("stored records parse")
}

/// Current versions of live chains of type `kind`, with their chains' roots.
fn heads_of(db: &Connection, kind: &str) -> Vec<(Hash, Record)> {
    let mut stmt = db.prepare("SELECT root, record FROM heads WHERE type = ?1").unwrap();
    stmt.query_map([kind], |r| Ok((r.get(0)?, parse_record(r.get(1)?)))).unwrap().flatten().collect()
}

/// This node's owners, from its owner records.
fn owners(db: &Connection) -> Vec<Pubkey> {
    heads_of(db, "owner").iter().filter_map(|(_, r)| r.owner_user()).collect()
}

/// Whether `author` may write new records at `path`: they're an owner, or a grant covers it.
fn may_write(db: &Connection, author: &Pubkey, path: &str) -> bool {
    owners(db).contains(author)
        || heads_of(db, "grant").iter().any(|(_, r)| GrantData::from_cbor(&r.data).is_ok_and(|g| g.covers(author, path)))
}

/// Stores `rec` if it's valid and new here. Ok(false): this node already has it. `from`: the node that
/// pushed it here. Doesn't check who may write what: see `App::authorize`.
fn store(db: &Connection, rec: &Record, from: Option<Pubkey>) -> Result<bool, String> {
    rec.check()?;
    if rec.version > now_ms() + MAX_CLOCK_SKEW_MS {
        return Err("version is too far in the future; check your clock".into());
    }
    let hash = rec.hash();
    if db.query_row("SELECT 1 FROM records WHERE hash = ?1", [hash], |_| Ok(())).optional().unwrap().is_some() {
        return Ok(false);
    }
    // The chain's root: the edited record's, or if it hasn't arrived (yet), the edited record itself.
    let root: Hash = match rec.edits {
        Some(prev) => db.query_row("SELECT root FROM records WHERE hash = ?1", [prev], |r| r.get(0)).optional().unwrap().unwrap_or(prev),
        None => hash,
    };
    db.execute("INSERT OR IGNORE INTO users (pubkey) VALUES (?1)", [rec.author]).unwrap();
    db.execute(
        "INSERT INTO records (hash, author, path, version, type, edits, root, record, seq, received_from)
         VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, (SELECT coalesce(max(seq), 0) + 1 FROM records), ?9)",
        (hash, rec.author, &rec.path, rec.version as i64, &rec.kind, rec.edits, root, rec.to_bytes(), from),
    )
    .unwrap();
    // Edits of this record that arrived before it were filed under it as their root.
    if root != hash {
        db.execute("UPDATE records SET root = ?1 WHERE root = ?2", (root, hash)).unwrap();
    }
    Ok(true)
}

impl App {
    /// A record by this node, signed by it. `edits`: the version it replaces.
    fn sign(&self, db: &Connection, path: &str, kind: &str, data: CBOR, edits: Option<Hash>) -> Record {
        let prev: Option<i64> = edits.and_then(|h| db.query_row("SELECT version FROM records WHERE hash = ?1", [h], |r| r.get(0)).optional().unwrap());
        let mut r = Record {
            author: self.pk,
            path: path.into(),
            version: now_ms().max(prev.map_or(0, |v| v as u64 + 1)),
            kind: kind.into(),
            data,
            edits,
            signature: [0; 64],
            extra: Map::new(),
        };
        r.signature = self.key.sign(&r.signed_bytes()).to_bytes();
        r
    }

    /// Writes a record as this node.
    fn write(&self, db: &Connection, path: &str, kind: &str, data: CBOR, edits: Option<Hash>) {
        let r = self.sign(db, path, kind, data, edits);
        store(db, &r, None).unwrap();
        self.push.notify_one();
    }

    /// Keeps the node record's URL current and, while there's no owner, prints a fresh claim link.
    fn init(&self, public_url: &str, origin: &str) {
        let db = self.db.lock().unwrap();
        let mut m = Map::new();
        m.insert("url", public_url);
        let data = CBOR::from(m);
        let current: Option<(Hash, Vec<u8>)> = db
            .query_row("SELECT hash, record FROM heads WHERE type = 'node' AND author = ?1", [self.pk], |r| Ok((r.get(0)?, r.get(1)?)))
            .optional()
            .unwrap();
        if current.as_ref().is_none_or(|(_, r)| parse_record(r.clone()).data != data) {
            self.write(&db, NODE_INFO_PATH, "node", data, current.map(|c| c.0));
        }
        if owners(&db).is_empty() {
            let token: [u8; 32] = random();
            db.execute("DELETE FROM claim_tokens", []).unwrap();
            db.execute("INSERT INTO claim_tokens (hash) VALUES (?1)", [Sha256::digest(token).as_slice()]).unwrap();
            println!("\nThis node has no owner yet. Open this one-time link to claim it:\n  {origin}/claim#{}\n", bs58::encode(token).into_string());
        }
    }

    /// Whether `rec`'s author may write it here (see "nodes" in core/src/lib.rs). For records written
    /// to this node, not those pushed by peers.
    fn authorize(&self, db: &Connection, rec: &Record) -> Result<(), String> {
        if rec.author == self.pk {
            return Ok(());
        }
        if rec.kind == "node" {
            return Err("only the node itself writes its node record".into());
        }
        let owner = owners(db).contains(&rec.author);
        if rec.is_node_record() && !owner {
            return Err(format!("only this node's owners can write under {NODE_PATH}"));
        }
        let Some(prev_hash) = rec.edits else {
            return if may_write(db, &rec.author, &rec.path) { Ok(()) } else { Err(format!("writing at {} needs a grant", rec.path)) };
        };
        let (prev, root): (Record, Hash) = db
            .query_row("SELECT record, root FROM records WHERE hash = ?1", [prev_hash], |r| Ok((parse_record(r.get(0)?), r.get(1)?)))
            .optional()
            .unwrap()
            .ok_or("this node doesn't have the record it edits")?;
        if db.query_row("SELECT 1 FROM records WHERE root = ?1 AND type = 'tombstone'", [root], |_| Ok(())).optional().unwrap().is_some() {
            return Err("that record was deleted".into());
        }
        if prev.kind == "node" {
            return Err("only the node itself writes its node record".into());
        }
        if rec.kind != "tombstone" && rec.kind != prev.kind {
            return Err("an edit can't change a record's type".into());
        }
        if !owner {
            let original: Option<Pubkey> = db.query_row("SELECT author FROM records WHERE hash = ?1", [root], |r| r.get(0)).optional().unwrap();
            if original != Some(rec.author) {
                return Err("only its author or this node's owners can edit or delete it".into());
            }
            if rec.kind != "tombstone" && rec.path != prev.path && !may_write(db, &rec.author, &rec.path) {
                return Err(format!("moving it to {} needs a grant there", rec.path));
            }
        }
        if prev.kind == "owner" {
            let others = heads_of(db, "owner").iter().filter(|(r, _)| *r != root).count();
            if others == 0 && rec.kind == "tombstone" {
                return Err("a node needs at least one owner".into());
            }
        }
        Ok(())
    }

    /// Every node this one knows of: itself, and the peers its federate records name.
    fn nodes(&self, db: &Connection) -> HashSet<Pubkey> {
        let mut keys: HashSet<Pubkey> = peers(db).into_iter().map(|(_, f)| f.peer).collect();
        keys.insert(self.pk);
        keys
    }
}

fn user_json(pk: &Pubkey, node: bool) -> Value {
    let phrase = if node { node_phrase(pk) } else { phrase(pk) };
    json!({ "pubkey": encode_id(pk), "phrase": phrase, "node": node })
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
    let nodes = app.nodes(&db);
    let mut stmt = db.prepare("SELECT pubkey FROM users ORDER BY created_at").unwrap();
    let keys: Vec<Pubkey> = stmt.query_map([], |r| r.get(0)).unwrap().flatten().collect();
    Json(keys.iter().map(|pk| user_json(pk, nodes.contains(pk))).collect())
}

/// Any public key's phrase, whether or not it has written anything yet.
async fn user(State(app): S, Path(pubkey): Path<String>) -> Response {
    match parse_id(&pubkey) {
        Ok(pk) => Json(user_json(&pk, app.nodes(&app.db.lock().unwrap()).contains(&pk))).into_response(),
        Err(e) => e,
    }
}

// ---- records (see core/src/lib.rs): signed CBOR in, signed CBOR out ----

#[derive(Deserialize)]
struct RecordsQuery {
    /// Only records first written by this user (base58 ID).
    author: Option<String>,
    /// Only records of this type.
    #[serde(rename = "type")]
    kind: Option<String>,
    /// Only records at or under this path.
    prefix: Option<String>,
}

/// The current version of every live chain matching the query, newest first, as a CBOR array of
/// {record, root: its chain's hash, by: who wrote the chain's first record (if this node has it),
/// versions: how many versions the chain has}.
async fn list_records(State(app): S, Query(q): Query<RecordsQuery>) -> Response {
    let author = match q.author.as_deref().map(parse_id).transpose() {
        Ok(a) => a,
        Err(e) => return e,
    };
    let prefix = q.prefix.filter(|p| p != "/");
    if let Some(Err(e)) = prefix.as_deref().map(check_prefix) {
        return err(StatusCode::BAD_REQUEST, format!("bad prefix: {e}"));
    }
    let db = app.db.lock().unwrap();
    let mut stmt = db
        .prepare(
            "SELECT h.record, h.root, o.author, (SELECT count(*) FROM records v WHERE v.root = h.root)
             FROM heads h LEFT JOIN records o ON o.hash = h.root
             WHERE (?1 IS NULL OR o.author = ?1)
               AND (?2 IS NULL OR h.path = ?2 OR substr(h.path, 1, length(?2) + 1) = ?2 || '/')
               AND (?3 IS NULL OR h.type = ?3)
             ORDER BY h.version DESC",
        )
        .unwrap();
    let entries: Vec<CBOR> = stmt
        .query_map((author, prefix, q.kind), |r| {
            let mut m = Map::new();
            m.insert("record", CBOR::try_from_data(r.get::<_, Vec<u8>>(0)?).expect("stored records are dCBOR"));
            m.insert("root", CBOR::to_byte_string(r.get::<_, Hash>(1)?));
            if let Some(by) = r.get::<_, Option<Pubkey>>(2)? {
                m.insert("by", CBOR::to_byte_string(by));
            }
            m.insert("versions", r.get::<_, i64>(3)? as u64);
            Ok(CBOR::from(m))
        })
        .unwrap()
        .flatten()
        .collect();
    ([(header::CONTENT_TYPE, "application/cbor")], CBOR::from(entries).to_cbor_data()).into_response()
}

/// Every version of the chain the record with this hash (base58) is in, oldest first, as a CBOR array of records.
async fn chain(State(app): S, Path(hash): Path<String>) -> Response {
    let Some(hash) = bs58::decode(&hash).into_vec().ok().and_then(|h| Hash::try_from(h).ok()) else {
        return err(StatusCode::BAD_REQUEST, "hash isn't 32 bytes of base58");
    };
    let db = app.db.lock().unwrap();
    let Some(root): Option<Hash> = db.query_row("SELECT root FROM records WHERE hash = ?1", [hash], |r| r.get(0)).optional().unwrap() else {
        return err(StatusCode::NOT_FOUND, "no such record here");
    };
    let mut stmt = db.prepare("SELECT record FROM records WHERE root = ?1 ORDER BY version, hash").unwrap();
    let records: Vec<Vec<u8>> = stmt.query_map([root], |r| r.get(0)).unwrap().flatten().collect();
    ([(header::CONTENT_TYPE, "application/cbor")], cbor_array(&records)).into_response()
}

/// Stores a record (CBOR body) if it's valid, its author may write it here, and it's new.
async fn put_record(State(app): S, body: Bytes) -> Response {
    let rec = match Record::from_bytes(&body) {
        Ok(r) => r,
        Err(e) => return err(StatusCode::BAD_REQUEST, format!("bad record: {e}")),
    };
    let db = app.db.lock().unwrap();
    if let Err(e) = rec.check() {
        return err(StatusCode::BAD_REQUEST, format!("bad record: {e}"));
    }
    if let Err(e) = app.authorize(&db, &rec) {
        return err(StatusCode::FORBIDDEN, e);
    }
    match store(&db, &rec, None) {
        Ok(true) => {
            app.push.notify_one();
            Json(json!({ "hash": encode_b58(&rec.hash()) })).into_response()
        }
        Ok(false) => err(StatusCode::CONFLICT, "this record is already here"),
        Err(e) => err(StatusCode::BAD_REQUEST, format!("bad record: {e}")),
    }
}

// ---- this node, and claiming it ----

/// Who this node is, and who owns it. Readable from any origin, so a node's owner can look up a peer's ID.
async fn node_info(State(app): S) -> Response {
    let owners = owners(&app.db.lock().unwrap());
    let body = json!({
        "pubkey": encode_id(&app.pk),
        "phrase": node_phrase(&app.pk),
        "owners": owners.iter().map(encode_id).collect::<Vec<_>>(),
    });
    ([(header::ACCESS_CONTROL_ALLOW_ORIGIN, "*")], Json(body)).into_response()
}

/// IDs (base58) of every node this one knows of: itself, and the peers its federate records name.
async fn nodes(State(app): S) -> Json<Vec<String>> {
    Json(app.nodes(&app.db.lock().unwrap()).iter().map(encode_id).collect())
}

/// A claim: the token from the one-time link, and the claiming user's ID and signature over
/// `claim_signed_bytes`, all base58.
#[derive(Deserialize)]
struct Claim {
    token: String,
    user: String,
    signature: String,
}

/// Makes the claiming user this node's first owner, with an owner record signed by the node.
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
        return err(StatusCode::FORBIDDEN, "This claim link was already used, or isn't for this node.");
    }
    let mut m = Map::new();
    m.insert("user", CBOR::to_byte_string(user));
    app.write(&db, OWNER_PATH, "owner", m.into(), None);
    println!("claimed by {} ({})", encode_id(&user), phrase(&user));
    Json(json!({ "node": encode_id(&app.pk) })).into_response()
}

/// A CBOR array of stored records (each already dCBOR).
fn cbor_array(records: &[Vec<u8>]) -> Vec<u8> {
    let items: Vec<CBOR> = records.iter().map(|r| CBOR::try_from_data(r).expect("stored records are dCBOR")).collect();
    CBOR::from(items).to_cbor_data()
}

// ---- federation: pushing records to peers, and receiving them ----

/// Stores records pushed by another node: a CBOR array of records, with the pusher's ID (base58) in
/// X-From. Takes any valid record, except node records. Answers, per record, "stored", "have", or why
/// it was refused.
async fn receive(State(app): S, headers: HeaderMap, body: Bytes) -> Response {
    let from = headers.get("x-from").and_then(|v| v.to_str().ok()).and_then(decode_id);
    let Some(items) = CBOR::try_from_data(&body).ok().and_then(CBOR::into_array) else {
        return err(StatusCode::BAD_REQUEST, "expected a CBOR array of records");
    };
    let db = app.db.lock().unwrap();
    let results: Vec<Value> = items
        .into_iter()
        .map(|v| {
            let r = Record::from_cbor(&v)?;
            if r.is_node_record() {
                return Err(format!("{NODE_PATH} records aren't federated"));
            }
            store(&db, &r, from)
        })
        .map(|r| match r {
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
        let feds = {
            let db = app.db.lock().unwrap();
            let feds = peers(&db);
            // Forget how far removed (or edited) federate records got.
            let live: HashSet<Hash> = feds.iter().map(|f| f.0).collect();
            let mut stmt = db.prepare("SELECT federate FROM peer_cursors").unwrap();
            for gone in stmt.query_map([], |r| r.get::<_, Hash>(0)).unwrap().flatten().filter(|f| !live.contains(f)) {
                db.execute("DELETE FROM peer_cursors WHERE federate = ?1", [gone]).unwrap();
            }
            feds
        };
        for (hash, fed) in feds {
            if let Err(e) = push_to(&app, hash, &fed).await {
                eprintln!("push to {} at {}: {e}", node_phrase(&fed.peer), fed.url);
            }
        }
        let _ = tokio::time::timeout(Duration::from_secs(10), app.push.notified()).await;
    }
}

/// This node's live federate records: (hash of the current version, what to push where).
fn peers(db: &Connection) -> Vec<(Hash, FederateData)> {
    let mut stmt = db.prepare("SELECT hash, record FROM heads WHERE type = 'federate'").unwrap();
    stmt.query_map([], |r| Ok((r.get::<_, Hash>(0)?, r.get::<_, Vec<u8>>(1)?)))
        .unwrap()
        .flatten()
        .filter_map(|(h, b)| Some((h, FederateData::from_cbor(&parse_record(b).data).ok()?)))
        .collect()
}

/// Pushes everything the federate record `fed_hash` hasn't sent yet, in batches, moving its cursor
/// after each one the peer accepts. Leaves out node records, and records the peer pushed here.
async fn push_to(app: &App, fed_hash: Hash, fed: &FederateData) -> Result<(), reqwest::Error> {
    loop {
        let (batch, last) = {
            let db = app.db.lock().unwrap();
            let cursor: i64 =
                db.query_row("SELECT seq FROM peer_cursors WHERE federate = ?1", [fed_hash], |r| r.get(0)).optional().unwrap().unwrap_or(0);
            let mut stmt =
                db.prepare("SELECT seq, path, type, received_from, record FROM records WHERE seq > ?1 ORDER BY seq LIMIT ?2").unwrap();
            let rows: Vec<(i64, String, String, Option<Pubkey>, Vec<u8>)> = stmt
                .query_map((cursor, PUSH_BATCH), |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?, r.get(3)?, r.get(4)?)))
                .unwrap()
                .flatten()
                .collect();
            let Some(last) = rows.last().map(|r| r.0) else { return Ok(()) };
            let batch: Vec<Vec<u8>> = rows
                .into_iter()
                .filter(|(_, path, kind, from, _)| *from != Some(fed.peer) && !path_within(path, NODE_PATH) && fed.wants(path, kind))
                .map(|r| r.4)
                .collect();
            (batch, last)
        };
        if !batch.is_empty() {
            app.http
                .post(format!("{}/receive", fed.url.trim_end_matches('/')))
                .header(header::CONTENT_TYPE, "application/cbor")
                .header("x-from", encode_id(&app.pk))
                .body(cbor_array(&batch))
                .timeout(Duration::from_secs(10))
                .send()
                .await?
                .error_for_status()?;
        }
        app.db
            .lock()
            .unwrap()
            .execute("INSERT OR REPLACE INTO peer_cursors (federate, seq) VALUES (?1, ?2)", (fed_hash, last))
            .unwrap();
    }
}
