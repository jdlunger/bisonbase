use axum::{
    Json, Router,
    body::Bytes,
    extract::{
        Path, Query, State,
        ws::{CloseFrame, Message, WebSocket, WebSocketUpgrade},
    },
    http::{HeaderMap, StatusCode, Uri, header},
    response::{
        IntoResponse, Redirect, Response,
        sse::{Event, KeepAlive, Sse},
    },
    routing::{get, post},
};
use base64::{Engine, engine::general_purpose::STANDARD as BASE64};
use ed25519_dalek::{Signer, SigningKey};
use fedcrdt_core::{
    CBOR, CLAIM_PATH, ClaimData, DocData, DocUpdateData, GrantData, Hash, MAX_READ_TOKEN_MS, Map, NODE_INFO_PATH, NODE_PATH, OWNER_PATH, PeerData, Pubkey,
    Record, Who, check_prefix, claim_signed_bytes, decode_b58, decode_id, encode_b58, encode_id, node_phrase, path_within, phrase,
    live_signed_bytes, read_signed_bytes, verify_sig,
};
use rusqlite::{Connection, OptionalExtension};
use serde::Deserialize;
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use std::{
    collections::{HashMap, HashSet},
    convert::Infallible,
    sync::{
        Arc, Mutex,
        atomic::{AtomicU32, Ordering},
    },
    time::{Duration, SystemTime, UNIX_EPOCH},
};
use tokio::sync::{broadcast, mpsc};
use tokio_stream::wrappers::ReceiverStream;

/// Bump to wipe the database when the schema changes incompatibly.
/// 6: records identified by hash, nodes. 7: chains table, seq as rowid. 8: private records. 9: records.doc.
const SCHEMA_VERSION: i64 = 9;

/// How far ahead of the node's clock a write's version may be.
const MAX_CLOCK_SKEW_MS: u64 = 10 * 60 * 1000;

/// Records per push to a peer.
const PUSH_BATCH: i64 = 100;

/// The largest message a live room passes on.
const MAX_LIVE_MSG: usize = 64 * 1024;

struct App {
    db: Mutex<Connection>,
    /// This node's own key; its public half is `pk`.
    key: SigningKey,
    pk: Pubkey,
    /// Wakes the push task when a record is stored.
    push: tokio::sync::Notify,
    http: reqwest::Client,
    /// Every record as it's stored here, for streams (see `stream`).
    stored: broadcast::Sender<Stored>,
    /// Each doc's live room, while anyone's in it (see `live`).
    rooms: Mutex<HashMap<Hash, broadcast::Sender<LiveMsg>>>,
    /// Numbers connections to live rooms.
    next_conn: AtomicU32,
}

impl App {
    fn new(db: Connection, key: SigningKey) -> App {
        let pk = key.verifying_key().to_bytes();
        App {
            db: Mutex::new(db),
            key,
            pk,
            push: Default::default(),
            http: reqwest::Client::new(),
            stored: broadcast::channel(1024).0,
            rooms: Default::default(),
            next_conn: AtomicU32::new(0),
        }
    }
}

/// A record just stored here, as streams need it.
#[derive(Clone)]
struct Stored {
    seq: i64,
    root: Hash,
    doc: Option<Hash>,
    path: String,
    private: bool,
    bytes: Arc<Vec<u8>>,
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
    db.execute_batch("PRAGMA journal_mode = WAL; PRAGMA synchronous = NORMAL;").unwrap();
    create_schema(&db);

    let key = node_key(&db);
    let app = Arc::new(App::new(db, key));
    app.init(&public_url, &origin);
    tokio::spawn(push_loop(app.clone()));

    let router = Router::new()
        .route("/api/users", get(users))
        .route("/api/users/{pubkey}", get(user))
        .route("/api/records", get(list_records).post(put_record))
        .route("/api/records/{hash}", get(chain))
        .route("/api/stream", get(stream))
        .route("/api/docs/{hash}/live", get(live))
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
/// Creates the tables if they're missing, wiping them first if they're from an older schema.
fn create_schema(db: &Connection) {
    let version: i64 = db.query_row("PRAGMA user_version", [], |r| r.get(0)).unwrap();
    if version < SCHEMA_VERSION {
        db.execute_batch(&format!(
            "DROP VIEW IF EXISTS heads; DROP TABLE IF EXISTS chains; DROP TABLE IF EXISTS records; DROP TABLE IF EXISTS notes; DROP TABLE IF EXISTS sessions;
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
            seq INTEGER PRIMARY KEY, -- local order of arrival (the rowid): what peers are pushed by
            hash BLOB NOT NULL UNIQUE, -- SHA-256 of `record`
            author BLOB NOT NULL,
            path TEXT NOT NULL,
            version INTEGER NOT NULL,
            type TEXT NOT NULL,
            edits BLOB,            -- hash of the version it edits or deletes
            private INTEGER NOT NULL, -- 1: only this node's owners may read it, and it's never pushed
            root BLOB NOT NULL,    -- its chain's first record: follows `edits` back as far as this node has
            record BLOB NOT NULL,  -- the record's deterministic CBOR, signature included
            received_from BLOB,    -- the node that pushed it here, if one did; it isn't pushed back there
            doc BLOB               -- for a doc update: its doc (the doc chain's first record's hash)
        );
        CREATE INDEX IF NOT EXISTS records_by_root ON records (root, version, hash);
        CREATE INDEX IF NOT EXISTS records_by_doc ON records (doc, seq) WHERE doc IS NOT NULL;
        -- One row per chain (by root), kept up to date by `store`: its current version (newest by
        -- version, then hash) and a summary. path, type and version are the head's, for querying.
        CREATE TABLE IF NOT EXISTS chains (
            root BLOB PRIMARY KEY,
            head BLOB NOT NULL,     -- hash of the current version
            author BLOB,            -- who wrote the root record; NULL until it arrives here
            path TEXT NOT NULL,
            type TEXT NOT NULL,
            version INTEGER NOT NULL,
            versions INTEGER NOT NULL, -- how many versions this node has
            deleted INTEGER NOT NULL   -- 1 if any version is a tombstone
        );
        CREATE INDEX IF NOT EXISTS chains_by_type ON chains (type) WHERE NOT deleted;
        CREATE INDEX IF NOT EXISTS chains_by_path ON chains (path) WHERE NOT deleted;
        CREATE INDEX IF NOT EXISTS chains_by_author ON chains (author) WHERE NOT deleted;
        -- Each live chain's current version. `author` is the head's; `by` the root's. A chain is private
        -- if its head is.
        CREATE VIEW IF NOT EXISTS heads AS
            SELECT c.root, c.head AS hash, c.author AS by, c.path, c.type, c.version, c.versions, r.author, r.private, r.record
            FROM chains c JOIN records r ON r.hash = c.head
            WHERE NOT c.deleted;
        -- This node's own key pair: exactly one row.
        CREATE TABLE IF NOT EXISTS node (
            pubkey BLOB PRIMARY KEY,
            secret BLOB NOT NULL -- 32-byte Ed25519 seed
        );
        -- How far each peer record (by hash) has been pushed: every record with seq <= this one.
        -- An edited peer record starts over.
        CREATE TABLE IF NOT EXISTS peer_cursors (
            peer BLOB PRIMARY KEY,
            seq INTEGER NOT NULL
        );",
    )
    .unwrap();
}

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

/// The current version of the live claim chain `root`, and its data.
fn claim_head(db: &Connection, root: &Hash) -> Option<(Hash, ClaimData)> {
    let (hash, rec): (Hash, Vec<u8>) = db
        .query_row("SELECT hash, record FROM heads WHERE root = ?1 AND type = 'claim'", [root], |r| Ok((r.get(0)?, r.get(1)?)))
        .optional()
        .unwrap()?;
    Some((hash, parse_record(rec).claim()?))
}

/// Who claimed the claim chain `root`, if anyone has.
fn claimed_by(db: &Connection, root: &Hash) -> Option<Pubkey> {
    claim_head(db, root)?.1.user
}

/// The live doc whose chain starts with `root`: who started it, its current version, and that version's data.
fn doc_head(db: &Connection, root: &Hash) -> Result<(Pubkey, Record, DocData), String> {
    let (by, head): (Option<Pubkey>, Vec<u8>) = db
        .query_row("SELECT by, record FROM heads WHERE root = ?1 AND type = 'doc'", [root], |r| Ok((r.get(0)?, r.get(1)?)))
        .optional()
        .unwrap()
        .ok_or("this node has no live doc with that hash")?;
    let head = parse_record(head);
    match (by, head.doc()) {
        (Some(by), Some(doc)) => Ok((by, head, doc)),
        _ => Err("this node doesn't have that doc's first version".into()),
    }
}

/// This node's owners, from its owner records: users named directly, or who claimed a claim named.
fn owners(db: &Connection) -> Vec<Pubkey> {
    heads_of(db, "owner").iter().filter_map(|(_, r)| r.owner()?.resolve(|c| claimed_by(db, c))).collect()
}

/// Whether `author` may write new records at `path`: they're an owner, or a grant covers it.
fn may_write(db: &Connection, author: &Pubkey, path: &str) -> bool {
    owners(db).contains(author)
        || heads_of(db, "grant")
            .iter()
            .any(|(_, r)| GrantData::from_cbor(&r.data).is_ok_and(|g| g.covers(author, path, |c| claimed_by(db, c))))
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
    let tx = db.unchecked_transaction().unwrap();
    tx.execute("INSERT OR IGNORE INTO users (pubkey) VALUES (?1)", [rec.author]).unwrap();
    tx.execute(
        "INSERT INTO records (hash, author, path, version, type, edits, private, root, record, received_from, doc)
         VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11)",
        (hash, rec.author, &rec.path, rec.version as i64, &rec.kind, rec.edits, rec.private, root, rec.to_bytes(), from, rec.doc_update().map(|u| u.doc)),
    )
    .unwrap();
    // Edits of this record that arrived before it were filed under it as their root.
    if root != hash {
        tx.execute("UPDATE records SET root = ?1 WHERE root = ?2", (root, hash)).unwrap();
        tx.execute("DELETE FROM chains WHERE root = ?1", [hash]).unwrap();
    }
    tx.execute(
        "INSERT OR REPLACE INTO chains (root, head, author, path, type, version, versions, deleted)
         SELECT ?1, h.hash, (SELECT author FROM records WHERE hash = ?1), h.path, h.type, h.version,
                (SELECT count(*) FROM records WHERE root = ?1),
                EXISTS (SELECT 1 FROM records WHERE root = ?1 AND type = 'tombstone')
         FROM records h WHERE h.root = ?1 ORDER BY h.version DESC, h.hash DESC LIMIT 1",
        [root],
    )
    .unwrap();
    tx.commit().unwrap();
    Ok(true)
}

impl App {
    /// Stores `rec` (see `store`). If it's new here, passes it to streams and wakes the push task.
    fn store(&self, db: &Connection, rec: &Record, from: Option<Pubkey>) -> Result<bool, String> {
        let new = store(db, rec, from)?;
        if new {
            let (seq, root) =
                db.query_row("SELECT seq, root FROM records WHERE hash = ?1", [rec.hash()], |r| Ok((r.get(0)?, r.get(1)?))).unwrap();
            let doc = rec.doc_update().map(|u| u.doc);
            let _ = self.stored.send(Stored { seq, root, doc, path: rec.path.clone(), private: rec.private, bytes: Arc::new(rec.to_bytes()) });
            self.push.notify_one();
        }
        Ok(new)
    }

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
            private: false,
            signature: [0; 64],
            extra: Map::new(),
        };
        r.signature = self.key.sign(&r.signed_bytes()).to_bytes();
        r
    }

    /// Writes a record as this node. Returns its hash.
    fn write(&self, db: &Connection, path: &str, kind: &str, data: CBOR, edits: Option<Hash>) -> Hash {
        let r = self.sign(db, path, kind, data, edits);
        self.store(db, &r, None).unwrap();
        r.hash()
    }

    /// Writes (or with `edits`, renews) an unclaimed claim with a fresh token. Returns the claim's hash and its link.
    fn new_claim(&self, db: &Connection, origin: &str, edits: Option<Hash>) -> (Hash, String) {
        let token: [u8; 32] = random();
        let data = ClaimData { token_hash: Sha256::digest(token).into(), user: None };
        let hash = self.write(db, CLAIM_PATH, "claim", data.to_cbor(), edits);
        (hash, format!("{origin}/claim#{}", encode_b58(&token)))
    }

    /// Keeps the node record's URL current. On a fresh database, writes a claim and an owner record naming
    /// it, for whoever claims it first; while that's unclaimed, gives it a new token on each start and
    /// prints the link (the node only keeps the token's hash).
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
        let owner_records = heads_of(&db, "owner");
        let link = if owner_records.is_empty() {
            let (claim, link) = self.new_claim(&db, origin, None);
            self.write(&db, OWNER_PATH, "owner", Who::Claim(claim).to_cbor(), None);
            Some(link)
        } else {
            // The node's own unclaimed owner claim, if there is one.
            owner_records.iter().find_map(|(_, r)| {
                let Some(Who::Claim(root)) = r.owner() else { return None };
                let (head, data) = claim_head(&db, &root)?;
                let author: Pubkey = db.query_row("SELECT author FROM records WHERE hash = ?1", [head], |r| r.get(0)).unwrap();
                (data.user.is_none() && author == self.pk).then(|| self.new_claim(&db, origin, Some(head)).1)
            })
        };
        if let Some(link) = link {
            println!("\nThis node has no owner yet. Open this one-time link to claim it:\n  {link}\n");
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
        if rec.claim().is_some_and(|c| c.user.is_some()) {
            return Err("only the node fills in who claimed a claim".into());
        }
        let owner = owners(db).contains(&rec.author);
        if rec.is_node_record() && !owner {
            return Err(format!("only this node's owners can write under {NODE_PATH}"));
        }
        if let Some(u) = rec.doc_update() {
            return self.authorize_doc_update(db, rec, &u, owner);
        }
        let Some(prev_hash) = rec.edits else {
            return if may_write(db, &rec.author, &rec.path) { Ok(()) } else { Err(format!("writing at {} needs a grant", rec.path)) };
        };
        let (prev, root): (Record, Hash) = db
            .query_row("SELECT record, root FROM records WHERE hash = ?1", [prev_hash], |r| Ok((parse_record(r.get(0)?), r.get(1)?)))
            .optional()
            .unwrap()
            .ok_or("this node doesn't have the record it edits")?;
        if db.query_row("SELECT deleted FROM chains WHERE root = ?1", [root], |r| r.get(0)).optional().unwrap() == Some(true) {
            return Err("that record was deleted".into());
        }
        if prev.kind == "node" {
            return Err("only the node itself writes its node record".into());
        }
        if prev.kind == "doc_update" {
            return Err("doc updates are never edited or deleted; delete the doc instead".into());
        }
        if rec.kind != "tombstone" && rec.kind != prev.kind {
            return Err("an edit can't change a record's type".into());
        }
        if prev.claim().is_some_and(|c| c.user.is_some()) && rec.kind != "tombstone" {
            return Err("that claim was already claimed".into());
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

    /// Whether `rec`, an update to the doc `u.doc`, may be written here: the doc is live, the update is
    /// at its current path, and its author is the doc's author, one of its editors, or an owner.
    fn authorize_doc_update(&self, db: &Connection, rec: &Record, u: &DocUpdateData, owner: bool) -> Result<(), String> {
        let (by, head, doc) = doc_head(db, &u.doc)?;
        if rec.path != head.path {
            return Err(format!("this doc's updates go at its path, {}", head.path));
        }
        if !owner && !doc.may_edit(&by, &rec.author, |c| claimed_by(db, c)) {
            return Err("only the doc's author and editors can edit it".into());
        }
        Ok(())
    }

    /// Whether the request is from one of this node's owners, by its read token (see `read_signed_bytes`
    /// in core/src/lib.rs): `Authorization: Bisonbase <ID>.<expires>.<signature>`, base58 but for the
    /// expiry (ms since the epoch). Only owners may read private records. Err if the token isn't valid.
    fn owner_reading(&self, db: &Connection, headers: &HeaderMap) -> Result<bool, Response> {
        let Some(v) = headers.get(header::AUTHORIZATION) else { return Ok(false) };
        let bad = |e: &str| err(StatusCode::UNAUTHORIZED, format!("read token: {e}"));
        let mut parts = v.to_str().ok().and_then(|v| v.strip_prefix("Bisonbase ")).unwrap_or_default().split('.');
        let (Some(user), Some(expires), Some(sig), None) = (
            parts.next().and_then(decode_id),
            parts.next().and_then(|e| e.parse::<u64>().ok()),
            parts.next().and_then(decode_b58).and_then(|s| <[u8; 64]>::try_from(s).ok()),
            parts.next(),
        ) else {
            return Err(bad("expected \"Bisonbase <ID>.<expires>.<signature>\""));
        };
        let now = now_ms();
        if expires < now {
            return Err(bad("expired"));
        }
        if expires > now + MAX_READ_TOKEN_MS {
            return Err(bad("expires too far ahead; check your clock"));
        }
        verify_sig(&user, &read_signed_bytes(&self.pk, expires), &sig).map_err(|e| bad(&e))?;
        Ok(owners(db).contains(&user))
    }

    /// Every node this one knows of: itself, and the peers its peer records name.
    fn nodes(&self, db: &Connection) -> HashSet<Pubkey> {
        let mut keys: HashSet<Pubkey> = peers(db).into_iter().map(|(_, p)| p.node).collect();
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

/// SQL for "and `path` is at or under the prefix bound as `p`": one range ('0' sorts right after '/'),
/// narrowed to leave out siblings like `{p}-x` that sort between `{p}` and `{p}/`. As a range, it can
/// use an index.
fn under(p: &str) -> String {
    format!(" AND path >= {p} AND path < {p} || '0' AND (path = {p} OR path >= {p} || '/')")
}

/// The current version of every live chain matching the query (but doc updates, unless `type` asks for
/// them), newest first, as a CBOR array of
/// {record, root: its chain's hash, by: who wrote the chain's first record (if this node has it),
/// versions: how many versions the chain has}. Private ones only for this node's owners.
async fn list_records(State(app): S, headers: HeaderMap, Query(q): Query<RecordsQuery>) -> Response {
    let author = match q.author.as_deref().map(parse_id).transpose() {
        Ok(a) => a,
        Err(e) => return e,
    };
    let prefix = q.prefix.filter(|p| p != "/");
    if let Some(Err(e)) = prefix.as_deref().map(check_prefix) {
        return err(StatusCode::BAD_REQUEST, format!("bad prefix: {e}"));
    }
    let db = app.db.lock().unwrap();
    let owner = match app.owner_reading(&db, &headers) {
        Ok(o) => o,
        Err(e) => return e,
    };
    // Only the filters given, so the planner can pick an index for them (`?1 IS NULL OR …` defeats that).
    let mut sql = String::from("SELECT record, root, by, versions FROM heads WHERE 1");
    if !owner {
        sql += " AND NOT private";
    }
    let mut params: Vec<Box<dyn rusqlite::ToSql>> = vec![];
    let mut bind = |v: Box<dyn rusqlite::ToSql>| {
        params.push(v);
        format!("?{}", params.len())
    };
    if let Some(a) = author {
        sql += &format!(" AND by = {}", bind(Box::new(a)));
    }
    if let Some(p) = prefix {
        sql += &under(&bind(Box::new(p)));
    }
    match q.kind {
        Some(k) => sql += &format!(" AND type = {}", bind(Box::new(k))),
        // There are lots, and they only mean something together: see `doc_updates`.
        None => sql += " AND type != 'doc_update'",
    }
    sql += " ORDER BY version DESC";
    let mut stmt = db.prepare(&sql).unwrap();
    let entries: Vec<CBOR> = stmt
        .query_map(rusqlite::params_from_iter(params), |r| {
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

/// Every version of the chain the record with this hash (base58) is in, oldest first, as a CBOR array of
/// records. Private versions only for this node's owners: to anyone else, a private record isn't here.
async fn chain(State(app): S, headers: HeaderMap, Path(hash): Path<String>) -> Response {
    let Some(hash) = bs58::decode(&hash).into_vec().ok().and_then(|h| Hash::try_from(h).ok()) else {
        return err(StatusCode::BAD_REQUEST, "hash isn't 32 bytes of base58");
    };
    let db = app.db.lock().unwrap();
    let owner = match app.owner_reading(&db, &headers) {
        Ok(o) => o,
        Err(e) => return e,
    };
    let found: Option<(Hash, bool)> =
        db.query_row("SELECT root, private FROM records WHERE hash = ?1", [hash], |r| Ok((r.get(0)?, r.get(1)?))).optional().unwrap();
    let Some((root, _)) = found.filter(|(_, private)| owner || !private) else {
        return err(StatusCode::NOT_FOUND, "no such record here");
    };
    let mut stmt = db.prepare("SELECT record FROM records WHERE root = ?1 AND (?2 OR NOT private) ORDER BY version, hash").unwrap();
    let records: Vec<Vec<u8>> = stmt.query_map((root, owner), |r| r.get(0)).unwrap().flatten().collect();
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
    match app.store(&db, &rec, None) {
        Ok(true) => {
            Json(json!({ "hash": encode_b58(&rec.hash()) })).into_response()
        }
        Ok(false) => err(StatusCode::CONFLICT, "this record is already here"),
        Err(e) => err(StatusCode::BAD_REQUEST, format!("bad record: {e}")),
    }
}

// ---- streams: records as they arrive ----

#[derive(Deserialize)]
struct StreamQuery {
    /// Only a doc's records: its versions and its updates (the doc chain's first record's hash, base58).
    doc: Option<String>,
    /// Only records at or under this path.
    prefix: Option<String>,
    /// Start after this record (an event ID from an earlier stream), instead of at the beginning. A
    /// reconnecting EventSource's Last-Event-ID takes its place.
    after: Option<i64>,
}

/// Which records a stream passes on. Never private ones: the stream has no read token.
#[derive(Clone)]
struct StreamFilter {
    doc: Option<Hash>,
    prefix: Option<String>,
}

impl StreamFilter {
    fn matches(&self, s: &Stored) -> bool {
        !s.private && self.doc.is_none_or(|d| s.doc == Some(d) || s.root == d) && self.prefix.as_ref().is_none_or(|p| path_within(&s.path, p))
    }
}

/// The records matching `f` that arrived here after `after`, in order: (seq, record).
fn stored_after(db: &Connection, f: &StreamFilter, after: i64) -> Vec<(i64, Vec<u8>)> {
    let mut sql = String::from("SELECT seq, record FROM records WHERE seq > ?1 AND NOT private");
    let mut params: Vec<Box<dyn rusqlite::ToSql>> = vec![Box::new(after)];
    if let Some(d) = f.doc {
        params.push(Box::new(d));
        sql += &format!(" AND (doc = ?{0} OR root = ?{0})", params.len());
    }
    if let Some(p) = &f.prefix {
        params.push(Box::new(p.clone()));
        sql += &under(&format!("?{}", params.len()));
    }
    sql += " ORDER BY seq";
    let mut stmt = db.prepare(&sql).unwrap();
    stmt.query_map(rusqlite::params_from_iter(params), |r| Ok((r.get(0)?, r.get(1)?))).unwrap().flatten().collect()
}

/// Server-sent events: every record matching the query that's here (after `after`), then a "ready"
/// event (its data: the last record's seq), then each new one as it's stored. Each "record" event's data is the record (base64 CBOR), and
/// its ID is where to continue from. A stream that falls too far behind is ended; EventSource reconnects
/// and picks up where it left off.
async fn stream(State(app): S, headers: HeaderMap, Query(q): Query<StreamQuery>) -> Response {
    let doc = match q.doc.as_deref().map(|d| decode_b58(d).and_then(|h| Hash::try_from(h).ok())) {
        Some(None) => return err(StatusCode::BAD_REQUEST, "doc isn't 32 bytes of base58"),
        d => d.flatten(),
    };
    let prefix = q.prefix.filter(|p| p != "/");
    if let Some(Err(e)) = prefix.as_deref().map(check_prefix) {
        return err(StatusCode::BAD_REQUEST, format!("bad prefix: {e}"));
    }
    let f = StreamFilter { doc, prefix };
    let after = headers.get("last-event-id").and_then(|v| v.to_str().ok()?.parse().ok()).or(q.after).unwrap_or(0);
    // Subscribing with the database locked: anything stored before is in the backlog, anything after
    // comes through `live`. Some may be in both; seq tells.
    let (backlog, mut live) = {
        let db = app.db.lock().unwrap();
        (stored_after(&db, &f, after), app.stored.subscribe())
    };
    let (tx, rx) = mpsc::channel::<Result<Event, Infallible>>(64);
    let record = |seq: i64, bytes: &[u8]| Ok(Event::default().event("record").id(seq.to_string()).data(BASE64.encode(bytes)));
    tokio::spawn(async move {
        let mut last = after;
        for (seq, bytes) in backlog {
            if tx.send(record(seq, &bytes)).await.is_err() {
                return;
            }
            last = seq;
        }
        // With data: browsers drop events without any.
        if tx.send(Ok(Event::default().event("ready").id(last.to_string()).data(last.to_string()))).await.is_err() {
            return;
        }
        loop {
            tokio::select! {
                _ = tx.closed() => return,
                s = live.recv() => match s {
                    Ok(s) if s.seq > last && f.matches(&s) => {
                        last = s.seq;
                        if tx.send(record(s.seq, &s.bytes)).await.is_err() {
                            return;
                        }
                    }
                    Ok(_) => {}
                    Err(_) => return,
                },
            }
        }
    });
    Sse::new(ReceiverStream::new(rx)).keep_alive(KeepAlive::default()).into_response()
}

// ---- live rooms: presence in a doc ----
//
// A WebSocket per editor, per doc. The first message is a hello, signed by one of the doc's editors (see
// `live_signed_bytes` in core/src/lib.rs): JSON {user, expires, signature}, base58 but for the expiry.
// Then each binary message (a Yjs awareness update: cursors, selections) goes to everyone else in the
// room, as is. Nothing is stored or checked but its size.
//
// To the client, each message is a frame: a kind (LIVE_*), the sender's connection number (u32, big
// endian), the sender's ID (32 bytes), then for LIVE_UPDATE what they sent. The ID is the one their
// hello proved, so clients can name cursors by it rather than by what the update claims.

const LIVE_UPDATE: u8 = 0;
/// Someone joined: send them where you are.
const LIVE_JOINED: u8 = 1;
/// Someone left: forget their cursors.
const LIVE_LEFT: u8 = 2;

#[derive(Clone)]
struct LiveMsg {
    from: u32,
    frame: Arc<Vec<u8>>,
}

#[derive(Deserialize)]
struct Hello {
    user: String,
    expires: u64,
    signature: String,
}

impl App {
    /// Who a live room's hello is from, if it's valid and they may edit the doc.
    fn live_hello(&self, doc: &Hash, text: &str) -> Result<Pubkey, String> {
        let h: Hello = serde_json::from_str(text).map_err(|_| "expected a hello: {user, expires, signature}")?;
        let user = decode_id(&h.user).ok_or("the hello's user isn't an ID")?;
        let sig: [u8; 64] = decode_b58(&h.signature).and_then(|s| s.try_into().ok()).ok_or("the hello's signature isn't 64 bytes of base58")?;
        let now = now_ms();
        if h.expires < now || h.expires > now + MAX_READ_TOKEN_MS {
            return Err("the hello expired, or expires too far ahead; check your clock".into());
        }
        verify_sig(&user, &live_signed_bytes(&self.pk, doc, h.expires), &sig)?;
        let db = self.db.lock().unwrap();
        let (by, _, data) = doc_head(&db, doc)?;
        if !owners(&db).contains(&user) && !data.may_edit(&by, &user, |c| claimed_by(&db, c)) {
            return Err("only the doc's author and editors can join".into());
        }
        Ok(user)
    }
}

/// Joins the live room of the doc whose chain starts with the record with this hash (base58).
async fn live(State(app): S, Path(hash): Path<String>, ws: WebSocketUpgrade) -> Response {
    let Some(doc) = decode_b58(&hash).and_then(|h| Hash::try_from(h).ok()) else {
        return err(StatusCode::BAD_REQUEST, "hash isn't 32 bytes of base58");
    };
    ws.max_message_size(MAX_LIVE_MSG).on_upgrade(move |socket| live_conn(app, doc, socket))
}

async fn live_conn(app: Arc<App>, doc: Hash, mut ws: WebSocket) {
    let hello = match ws.recv().await {
        Some(Ok(Message::Text(t))) => app.live_hello(&doc, &t),
        _ => return,
    };
    let user = match hello {
        Ok(u) => u,
        Err(e) => {
            let _ = ws.send(Message::Close(Some(CloseFrame { code: 4003, reason: e.into() }))).await;
            return;
        }
    };
    let conn = app.next_conn.fetch_add(1, Ordering::Relaxed);
    let frame = |kind: u8, payload: &[u8]| LiveMsg { from: conn, frame: Arc::new([&[kind][..], &conn.to_be_bytes(), &user, payload].concat()) };
    // Subscribing with the rooms locked, so an emptied room can't be dropped between.
    let (tx, mut rx) = {
        let mut rooms = app.rooms.lock().unwrap();
        let tx = rooms.entry(doc).or_insert_with(|| broadcast::channel(256).0).clone();
        let rx = tx.subscribe();
        (tx, rx)
    };
    let _ = tx.send(frame(LIVE_JOINED, &[]));
    loop {
        tokio::select! {
            m = ws.recv() => match m {
                Some(Ok(Message::Binary(b))) => {
                    let _ = tx.send(frame(LIVE_UPDATE, &b));
                }
                Some(Ok(_)) => {}
                _ => break,
            },
            m = rx.recv() => match m {
                Ok(m) if m.from != conn => {
                    if ws.send(Message::Binary(m.frame.to_vec().into())).await.is_err() {
                        break;
                    }
                }
                Ok(_) => {}
                // Missed some: they're only cursors, and each client resends its own now and then.
                Err(broadcast::error::RecvError::Lagged(_)) => {}
                Err(broadcast::error::RecvError::Closed) => break,
            },
        }
    }
    let _ = tx.send(frame(LIVE_LEFT, &[]));
    drop(rx);
    let mut rooms = app.rooms.lock().unwrap();
    if tx.receiver_count() == 0 {
        rooms.remove(&doc);
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

/// IDs (base58) of every node this one knows of: itself, and the peers its peer records name.
async fn nodes(State(app): S) -> Json<Vec<String>> {
    Json(app.nodes(&app.db.lock().unwrap()).iter().map(encode_id).collect())
}

/// A claim: the token from a claim link, and the claiming user's ID and signature over
/// `claim_signed_bytes`, all base58.
#[derive(Deserialize)]
struct Claim {
    token: String,
    user: String,
    signature: String,
}

/// Claims the claim whose token this is, for the signing user: the node writes a new version of it
/// naming them. Answers with the claim's hash (base58: its chain's first record).
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
    let token_hash: Hash = Sha256::digest(&token).into();
    let db = app.db.lock().unwrap();
    let mut stmt = db.prepare("SELECT hash, root, record FROM heads WHERE type = 'claim'").unwrap();
    let found = stmt
        .query_map([], |r| Ok((r.get::<_, Hash>(0)?, r.get::<_, Hash>(1)?, r.get::<_, Vec<u8>>(2)?)))
        .unwrap()
        .flatten()
        .find_map(|(h, root, b)| {
            let r = parse_record(b);
            Some((h, root, r.claim().filter(|c| c.token_hash == token_hash)?, r.path))
        });
    let Some((head, root, data, path)) = found else {
        return err(StatusCode::NOT_FOUND, "This claim link isn't for this node, or its claim was deleted.");
    };
    if data.user.is_some() {
        return err(StatusCode::FORBIDDEN, "This claim link was already used.");
    }
    db.execute("INSERT OR IGNORE INTO users (pubkey) VALUES (?1)", [user]).unwrap();
    app.write(&db, &path, "claim", ClaimData { user: Some(user), ..data }.to_cbor(), Some(head));
    println!("claim {} claimed by {} ({})", encode_b58(&root), encode_id(&user), phrase(&user));
    Json(json!({ "claim": encode_b58(&root) })).into_response()
}

/// A CBOR array of stored records (each already dCBOR).
fn cbor_array(records: &[Vec<u8>]) -> Vec<u8> {
    let items: Vec<CBOR> = records.iter().map(|r| CBOR::try_from_data(r).expect("stored records are dCBOR")).collect();
    CBOR::from(items).to_cbor_data()
}

// ---- federation: pushing records to peers, and receiving them ----

/// Stores records pushed by another node: a CBOR array of records, with the pusher's ID (base58) in
/// X-From. Takes any valid record, except node records, claims and private ones. Answers, per record, "stored", "have", or why
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
            if r.private {
                return Err("private records aren't federated".into());
            }
            if r.kind == "claim" {
                return Err("claims aren't federated".into());
            }
            app.store(&db, &r, from)
        })
        .map(|r| match r {
            Ok(true) => "stored".into(),
            Ok(false) => "have".into(),
            Err(e) => format!("bad record: {e}").into(),
        })
        .collect();
    Json(results).into_response()
}

/// Pushes new records to every peer whenever something is stored, and retries every 10s.
async fn push_loop(app: Arc<App>) {
    loop {
        let peers = {
            let db = app.db.lock().unwrap();
            let peers = peers(&db);
            // Forget how far removed (or edited) peer records got.
            let live: HashSet<Hash> = peers.iter().map(|p| p.0).collect();
            let mut stmt = db.prepare("SELECT peer FROM peer_cursors").unwrap();
            for gone in stmt.query_map([], |r| r.get::<_, Hash>(0)).unwrap().flatten().filter(|p| !live.contains(p)) {
                db.execute("DELETE FROM peer_cursors WHERE peer = ?1", [gone]).unwrap();
            }
            peers
        };
        for (hash, peer) in peers {
            if let Err(e) = push_to(&app, hash, &peer).await {
                eprintln!("push to {} at {}: {e}", node_phrase(&peer.node), peer.url);
            }
        }
        let _ = tokio::time::timeout(Duration::from_secs(10), app.push.notified()).await;
    }
}

/// This node's live peer records: (hash of the current version, what to push where).
fn peers(db: &Connection) -> Vec<(Hash, PeerData)> {
    let mut stmt = db.prepare("SELECT hash, record FROM heads WHERE type = 'peer'").unwrap();
    stmt.query_map([], |r| Ok((r.get::<_, Hash>(0)?, r.get::<_, Vec<u8>>(1)?)))
        .unwrap()
        .flatten()
        .filter_map(|(h, b)| Some((h, PeerData::from_cbor(&parse_record(b).data).ok()?)))
        .collect()
}

/// Pushes everything the peer record `peer_hash` hasn't sent yet, in batches, moving its cursor
/// after each one the peer accepts. Leaves out node records, claims, private ones, and records the peer pushed here.
async fn push_to(app: &App, peer_hash: Hash, peer: &PeerData) -> Result<(), reqwest::Error> {
    loop {
        let (batch, last) = {
            let db = app.db.lock().unwrap();
            let cursor: i64 =
                db.query_row("SELECT seq FROM peer_cursors WHERE peer = ?1", [peer_hash], |r| r.get(0)).optional().unwrap().unwrap_or(0);
            let mut stmt =
                db.prepare("SELECT seq, path, type, received_from, private, record FROM records WHERE seq > ?1 ORDER BY seq LIMIT ?2").unwrap();
            let rows: Vec<(i64, String, String, Option<Pubkey>, bool, Vec<u8>)> = stmt
                .query_map((cursor, PUSH_BATCH), |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?, r.get(3)?, r.get(4)?, r.get(5)?)))
                .unwrap()
                .flatten()
                .collect();
            let Some(last) = rows.last().map(|r| r.0) else { return Ok(()) };
            let batch: Vec<Vec<u8>> = rows
                .into_iter()
                .filter(|(_, path, kind, from, private, _)| {
                    *from != Some(peer.node) && !private && kind != "claim" && !path_within(path, NODE_PATH) && peer.wants(path, kind)
                })
                .map(|r| r.5)
                .collect();
            (batch, last)
        };
        if !batch.is_empty() {
            app.http
                .post(format!("{}/receive", peer.url.trim_end_matches('/')))
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
            .execute("INSERT OR REPLACE INTO peer_cursors (peer, seq) VALUES (?1, ?2)", (peer_hash, last))
            .unwrap();
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use fedcrdt_core::{GRANT_PATH, Grantees};

    /// A fresh node on an in-memory database, started as `main` does: it has a node record, and an
    /// owner record naming an unclaimed claim.
    fn node() -> App {
        let db = Connection::open_in_memory().unwrap();
        create_schema(&db);
        let key = node_key(&db);
        let app = App::new(db, key);
        app.init("http://node.test", "http://web.test");
        app
    }

    fn key(n: u8) -> SigningKey {
        SigningKey::from_bytes(&[n; 32])
    }

    fn id(k: &SigningKey) -> Pubkey {
        k.verifying_key().to_bytes()
    }

    fn sign(key: &SigningKey, path: &str, kind: &str, data: CBOR, edits: Option<&Record>, version: u64) -> Record {
        let mut r = Record {
            author: id(key),
            path: path.into(),
            version,
            kind: kind.into(),
            data,
            edits: edits.map(Record::hash),
            private: false,
            signature: [0; 64],
            extra: Map::new(),
        };
        r.signature = key.sign(&r.signed_bytes()).to_bytes();
        r
    }

    /// A post only the node's owners may read.
    fn private_post(key: &SigningKey, path: &str, text: &str, edits: Option<&Record>, version: u64) -> Record {
        let mut r = post(key, path, text, edits, version);
        r.private = true;
        r.signature = key.sign(&r.signed_bytes()).to_bytes();
        r
    }

    /// Request headers with `key`'s read token for `app`, good until `expires`.
    fn reading_as(app: &App, key: &SigningKey, expires: u64) -> HeaderMap {
        let sig = key.sign(&read_signed_bytes(&app.pk, expires)).to_bytes();
        let mut h = HeaderMap::new();
        h.insert(header::AUTHORIZATION, format!("Bisonbase {}.{expires}.{}", encode_id(&id(key)), encode_b58(&sig)).parse().unwrap());
        h
    }

    async fn body(res: Response) -> Vec<u8> {
        axum::body::to_bytes(res.into_body(), usize::MAX).await.unwrap().to_vec()
    }

    /// The texts of the records in a CBOR array (as `chain` answers), or of the records in its entries (as `list_records` does).
    fn texts(bytes: &[u8]) -> Vec<String> {
        let items = CBOR::try_from_data(bytes).unwrap().into_array().unwrap();
        let mut t: Vec<String> = items
            .iter()
            .map(|v| v.as_map().and_then(|m| m.get::<_, CBOR>("record")).unwrap_or(v.clone()))
            .filter_map(|v| Record::from_cbor(&v).unwrap().data.as_text().map(Into::into))
            .collect();
        t.sort();
        t
    }

    fn post(key: &SigningKey, path: &str, text: &str, edits: Option<&Record>, version: u64) -> Record {
        sign(key, path, "post", text.into(), edits, version)
    }

    fn tombstone(key: &SigningKey, of: &Record, version: u64) -> Record {
        sign(key, &of.path, "tombstone", CBOR::null(), Some(of), version)
    }

    /// Writes `r` as `put_record` does: authorized, then stored.
    fn put(app: &App, r: &Record) -> Result<(), String> {
        let db = app.db.lock().unwrap();
        app.authorize(&db, r)?;
        assert!(store(&db, r, None)?, "already stored");
        Ok(())
    }

    /// Stores `r` as `receive` does for a record a peer pushed: unauthorized.
    fn pushed(app: &App, r: &Record) {
        assert!(store(&app.db.lock().unwrap(), r, Some([7; 32])).unwrap(), "already stored");
    }

    #[derive(Debug, PartialEq)]
    struct Chain {
        head: Hash,
        author: Option<Pubkey>,
        versions: i64,
        deleted: bool,
    }

    fn chain_of(app: &App, root: &Record) -> Option<Chain> {
        app.db
            .lock()
            .unwrap()
            .query_row("SELECT head, author, versions, deleted FROM chains WHERE root = ?1", [root.hash()], |r| {
                Ok(Chain { head: r.get(0)?, author: r.get(1)?, versions: r.get(2)?, deleted: r.get(3)? })
            })
            .optional()
            .unwrap()
    }

    /// Roots of the live chains of type `kind`.
    fn live(app: &App, kind: &str) -> Vec<Hash> {
        heads_of(&app.db.lock().unwrap(), kind).into_iter().map(|(root, _)| root).collect()
    }

    /// A node with an owner, alice, who lets anyone write under /post. Returns it, alice and bob.
    fn setup() -> (App, SigningKey, SigningKey) {
        let app = node();
        let (alice, bob) = (key(1), key(2));
        app.write(&app.db.lock().unwrap(), OWNER_PATH, "owner", Who::User(id(&alice)).to_cbor(), None);
        let grant = GrantData { path: "/post".into(), grantees: Grantees::Anyone };
        put(&app, &sign(&alice, GRANT_PATH, "grant", grant.to_cbor(), None, 1)).unwrap();
        (app, alice, bob)
    }

    #[test]
    fn edits_move_the_head() {
        let (app, _, bob) = setup();
        let v1 = post(&bob, "/post/a", "one", None, 1);
        put(&app, &v1).unwrap();
        assert_eq!(chain_of(&app, &v1), Some(Chain { head: v1.hash(), author: Some(id(&bob)), versions: 1, deleted: false }));

        let v2 = post(&bob, "/post/a", "two", Some(&v1), 2);
        put(&app, &v2).unwrap();
        assert_eq!(chain_of(&app, &v1), Some(Chain { head: v2.hash(), author: Some(id(&bob)), versions: 2, deleted: false }));

        // A concurrent edit at the same version: the higher hash wins, whichever arrives last.
        let v2b = post(&bob, "/post/a", "two, again", Some(&v1), 2);
        put(&app, &v2b).unwrap();
        let head = chain_of(&app, &v1).unwrap().head;
        assert_eq!(head, v2.hash().max(v2b.hash()));
        assert_eq!(live(&app, "post"), vec![v1.hash()]);

        // An older edit doesn't take over.
        put(&app, &post(&bob, "/post/a", "stale", Some(&v1), 1)).unwrap();
        assert_eq!(chain_of(&app, &v1).unwrap().head, head);
        assert_eq!(chain_of(&app, &v1).unwrap().versions, 4);
    }

    fn permutations(n: usize) -> Vec<Vec<usize>> {
        if n == 0 {
            return vec![vec![]];
        }
        permutations(n - 1)
            .into_iter()
            .flat_map(|p| (0..n).map(move |i| [&p[..i], &[n - 1], &p[i..]].concat()))
            .collect()
    }

    #[test]
    fn out_of_order_arrival_converges() {
        let bob = key(2);
        let mut chain = vec![post(&bob, "/post/a", "v1", None, 1)];
        for v in 2..=4 {
            let r = post(&bob, "/post/a", &format!("v{v}"), chain.last(), v);
            chain.push(r);
        }
        let (first, last) = (&chain[0], &chain[3]);
        let orders = permutations(chain.len());
        assert_eq!(orders.len(), 24);
        for order in orders {
            let app = node();
            for &i in &order {
                pushed(&app, &chain[i]);
            }
            let want = Chain { head: last.hash(), author: Some(id(&bob)), versions: 4, deleted: false };
            assert_eq!(chain_of(&app, first), Some(want), "order {order:?}");
            assert_eq!(live(&app, "post"), vec![first.hash()], "order {order:?}: one chain, no leftovers");
            let db = app.db.lock().unwrap();
            let roots: i64 = db.query_row("SELECT count(*) FROM records WHERE root = ?1", [first.hash()], |r| r.get(0)).unwrap();
            assert_eq!(roots, 4, "order {order:?}");
            let posts: i64 = db.query_row("SELECT count(*) FROM chains WHERE type = 'post'", [], |r| r.get(0)).unwrap();
            assert_eq!(posts, 1, "order {order:?}");
        }
    }

    #[test]
    fn missing_root_leaves_author_unknown() {
        let bob = key(2);
        let v1 = post(&bob, "/post/a", "v1", None, 1);
        let v2 = post(&bob, "/post/a", "v2", Some(&v1), 2);
        let app = node();
        pushed(&app, &v2);
        // Filed under v1 (its root as far as this node knows), with no author until v1 arrives.
        assert_eq!(chain_of(&app, &v1), Some(Chain { head: v2.hash(), author: None, versions: 1, deleted: false }));
        pushed(&app, &v1);
        assert_eq!(chain_of(&app, &v1), Some(Chain { head: v2.hash(), author: Some(id(&bob)), versions: 2, deleted: false }));
    }

    #[test]
    fn tombstones_delete_the_chain() {
        let (app, _, bob) = setup();
        let v1 = post(&bob, "/post/a", "one", None, 1);
        put(&app, &v1).unwrap();
        let t = tombstone(&bob, &v1, 2);
        put(&app, &t).unwrap();
        assert!(chain_of(&app, &v1).unwrap().deleted);
        assert!(live(&app, "post").is_empty());

        let err = put(&app, &post(&bob, "/post/a", "back", Some(&v1), 3)).unwrap_err();
        assert!(err.contains("deleted"), "{err}");
        assert!(put(&app, &tombstone(&bob, &t, 3)).unwrap_err().contains("deleted"));

        // Even an edit newer than the tombstone, pushed by a peer, doesn't bring it back.
        pushed(&app, &post(&bob, "/post/a", "late", Some(&v1), 5));
        assert!(chain_of(&app, &v1).unwrap().deleted);
        assert!(live(&app, "post").is_empty());
    }

    #[test]
    fn tombstone_before_its_record() {
        let bob = key(2);
        let v1 = post(&bob, "/post/a", "one", None, 1);
        let t = tombstone(&bob, &v1, 2);
        let app = node();
        pushed(&app, &t);
        pushed(&app, &v1);
        assert_eq!(chain_of(&app, &v1), Some(Chain { head: t.hash(), author: Some(id(&bob)), versions: 2, deleted: true }));
        assert!(live(&app, "post").is_empty());
    }

    #[test]
    fn who_may_write() {
        let (app, alice, bob) = setup();
        let carol = key(3);

        let err = put(&app, &post(&bob, "/notes/x", "hi", None, 1)).unwrap_err();
        assert!(err.contains("needs a grant"), "{err}");
        let grant = GrantData { path: "/notes".into(), grantees: Grantees::Anyone };
        let err = put(&app, &sign(&bob, GRANT_PATH, "grant", grant.to_cbor(), None, 1)).unwrap_err();
        assert!(err.contains("owners"), "{err}");

        let v1 = post(&bob, "/post/a", "bob's", None, 1);
        put(&app, &v1).unwrap();
        let err = put(&app, &post(&carol, "/post/a", "carol's now", Some(&v1), 2)).unwrap_err();
        assert!(err.contains("only its author"), "{err}");
        let err = put(&app, &post(&bob, "/notes/a", "moved", Some(&v1), 2)).unwrap_err();
        assert!(err.contains("needs a grant"), "{err}");
        put(&app, &post(&alice, "/post/a", "edited by an owner", Some(&v1), 2)).unwrap();
        assert_eq!(chain_of(&app, &v1).unwrap().author, Some(id(&bob)), "the chain is still bob's");

        // The node's owner records: the one naming the first-owner claim, and alice's.
        let owners: Vec<(Hash, Record)> = heads_of(&app.db.lock().unwrap(), "owner");
        assert_eq!(owners.len(), 2);
        let (claim_owner, alice_owner) = match owners[0].1.owner() {
            Some(Who::Claim(_)) => (&owners[0].1, &owners[1].1),
            _ => (&owners[1].1, &owners[0].1),
        };
        put(&app, &tombstone(&alice, claim_owner, now_ms())).unwrap();
        let err = put(&app, &tombstone(&alice, alice_owner, now_ms())).unwrap_err();
        assert!(err.contains("at least one owner"), "{err}");
    }

    #[tokio::test]
    async fn list_filters() {
        let (app, alice, bob) = setup();
        for path in ["/post", "/post/a", "/post/a/b", "/post-x", "/postx", "/posts/c", "/other"] {
            put(&app, &post(&alice, path, path, None, 1)).unwrap();
        }
        put(&app, &post(&bob, "/post/bob", "bob's", None, 2)).unwrap();
        let deleted = post(&alice, "/post/gone", "gone", None, 1);
        put(&app, &deleted).unwrap();
        put(&app, &tombstone(&alice, &deleted, 2)).unwrap();
        let app = Arc::new(app);

        let list = async |author: Option<&SigningKey>, kind: Option<&str>, prefix: Option<&str>| -> Vec<String> {
            let q = RecordsQuery { author: author.map(|k| encode_id(&id(k))), kind: kind.map(Into::into), prefix: prefix.map(Into::into) };
            let res = list_records(State(app.clone()), HeaderMap::new(), Query(q)).await;
            assert_eq!(res.status(), StatusCode::OK);
            let body = body(res).await;
            let mut paths: Vec<String> = CBOR::try_from_data(&body)
                .unwrap()
                .into_array()
                .unwrap()
                .iter()
                .map(|e| Record::from_cbor(&e.as_map().unwrap().get::<_, CBOR>("record").unwrap()).unwrap().path)
                .collect();
            paths.sort();
            paths
        };

        assert_eq!(list(None, Some("post"), Some("/post")).await, ["/post", "/post/a", "/post/a/b", "/post/bob"]);
        assert_eq!(list(None, None, Some("/post/a")).await, ["/post/a", "/post/a/b"]);
        assert_eq!(list(Some(&bob), None, None).await, ["/post/bob"]);
        assert_eq!(list(Some(&bob), Some("post"), Some("/posts")).await, Vec::<String>::new());
        assert_eq!(list(None, Some("post"), Some("/")).await.len(), 8, "everything but the deleted one");
        assert_eq!(list(None, Some("grant"), None).await, [GRANT_PATH]);
    }

    #[tokio::test]
    async fn private_records_are_for_owners() {
        let (app, alice, bob) = setup();
        put(&app, &post(&bob, "/post/a", "public", None, 1)).unwrap();
        let secret = private_post(&bob, "/post/b", "secret", None, 1);
        put(&app, &secret).unwrap();
        // A chain that went private: its public first version stays readable, the rest doesn't.
        let was_public = post(&bob, "/post/c", "was public", None, 1);
        put(&app, &was_public).unwrap();
        let now_private = private_post(&bob, "/post/c", "now private", Some(&was_public), 2);
        put(&app, &now_private).unwrap();
        let app = Arc::new(app);
        let expires = now_ms() + 60_000;

        let list = async |h: HeaderMap| {
            let res = list_records(State(app.clone()), h, Query(RecordsQuery { author: None, kind: Some("post".into()), prefix: None })).await;
            (res.status(), body(res).await)
        };
        let (status, b) = list(HeaderMap::new()).await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(texts(&b), ["public"]);
        assert_eq!(texts(&list(reading_as(&app, &bob, expires)).await.1), ["public"], "bob wrote it, but isn't an owner");
        assert_eq!(texts(&list(reading_as(&app, &alice, expires)).await.1), ["now private", "public", "secret"]);

        // Bad tokens are refused, not ignored.
        assert_eq!(list(reading_as(&app, &alice, now_ms() - 1)).await.0, StatusCode::UNAUTHORIZED, "expired");
        assert_eq!(list(reading_as(&app, &alice, now_ms() + MAX_READ_TOKEN_MS + 60_000)).await.0, StatusCode::UNAUTHORIZED);
        let mut forged = reading_as(&app, &alice, expires);
        let other = reading_as(&app, &alice, expires + 1);
        let sig = other[header::AUTHORIZATION].to_str().unwrap().rsplit('.').next().unwrap().to_string();
        let v = forged[header::AUTHORIZATION].to_str().unwrap().rsplit_once('.').unwrap().0.to_string();
        forged.insert(header::AUTHORIZATION, format!("{v}.{sig}").parse().unwrap());
        assert_eq!(list(forged).await.0, StatusCode::UNAUTHORIZED, "signature for another expiry");

        let chain = async |hash: &Record, h: HeaderMap| {
            let res = chain(State(app.clone()), h, Path(encode_b58(&hash.hash()))).await;
            (res.status(), body(res).await)
        };
        assert_eq!(chain(&secret, HeaderMap::new()).await.0, StatusCode::NOT_FOUND);
        assert_eq!(texts(&chain(&secret, reading_as(&app, &alice, expires)).await.1), ["secret"]);
        assert_eq!(chain(&now_private, HeaderMap::new()).await.0, StatusCode::NOT_FOUND);
        assert_eq!(texts(&chain(&was_public, HeaderMap::new()).await.1), ["was public"]);
        assert_eq!(texts(&chain(&was_public, reading_as(&app, &alice, expires)).await.1), ["now private", "was public"]);
    }

    #[tokio::test]
    async fn private_records_arent_received() {
        let app = Arc::new(node());
        let bob = key(2);
        let records = [post(&bob, "/post/a", "public", None, 1), private_post(&bob, "/post/b", "secret", None, 1)];
        let items: Vec<Vec<u8>> = records.iter().map(Record::to_bytes).collect();
        let res = receive(State(app.clone()), HeaderMap::new(), Bytes::from(cbor_array(&items))).await;
        let results: Vec<String> = serde_json::from_slice(&body(res).await).unwrap();
        assert_eq!(results[0], "stored");
        assert!(results[1].contains("private"), "{}", results[1]);
    }

    fn doc_update(key: &SigningKey, doc: &Record, path: &str, update: &[u8]) -> Record {
        sign(key, path, "doc_update", DocUpdateData { doc: doc.hash(), update: update.to_vec() }.to_cbor(), None, 1)
    }

    /// What a stream of `doc` starts with after `after`: its records' types (and for updates, what they
    /// say), and the last one's seq.
    fn streamed(app: &App, doc: &Record, after: i64) -> (Vec<String>, i64) {
        let f = StreamFilter { doc: Some(doc.hash()), prefix: None };
        let rows = stored_after(&app.db.lock().unwrap(), &f, after);
        let last = rows.last().map_or(after, |r| r.0);
        let said = rows
            .iter()
            .map(|(_, b)| {
                let r = parse_record(b.clone());
                r.doc_update().map_or(r.kind.clone(), |u| String::from_utf8(u.update).unwrap())
            })
            .collect();
        (said, last)
    }

    #[tokio::test]
    async fn docs() {
        use fedcrdt_core::DocData;
        let (app, alice, bob) = setup();
        let carol = key(3);
        let grant = GrantData { path: "/doc".into(), grantees: Grantees::Anyone };
        put(&app, &sign(&alice, GRANT_PATH, "grant", grant.to_cbor(), None, 1)).unwrap();

        let doc = sign(&bob, "/doc", "doc", DocData { title: "Plans".into(), editors: vec![] }.to_cbor(), None, 1);
        put(&app, &doc).unwrap();
        put(&app, &doc_update(&bob, &doc, "/doc", b"bob")).unwrap();
        put(&app, &doc_update(&alice, &doc, "/doc", b"alice")).expect("owners may edit anything");
        let err = put(&app, &doc_update(&carol, &doc, "/doc", b"carol")).unwrap_err();
        assert!(err.contains("author and editors"), "{err}");
        let err = put(&app, &doc_update(&bob, &doc, "/doc/x", b"elsewhere")).unwrap_err();
        assert!(err.contains("at its path"), "{err}");
        let not_a_doc = post(&bob, "/post/x", "hi", None, 1);
        put(&app, &not_a_doc).unwrap();
        let err = put(&app, &doc_update(&bob, &not_a_doc, "/post/x", b"x")).unwrap_err();
        assert!(err.contains("no live doc"), "{err}");

        // Bob invites whoever opens a claim link, which he makes next to the doc; carol opens it.
        let token = [42u8; 32];
        let claim_rec = sign(&bob, "/doc", "claim", ClaimData { token_hash: Sha256::digest(token).into(), user: None }.to_cbor(), None, 1);
        put(&app, &claim_rec).expect("claims go anywhere one may write");
        let v2 = sign(&bob, "/doc", "doc", DocData { title: "Plans".into(), editors: vec![Who::Claim(claim_rec.hash())] }.to_cbor(), Some(&doc), 2);
        put(&app, &v2).unwrap();
        let app = Arc::new(app);
        let sig = carol.sign(&claim_signed_bytes(&app.pk, &token)).to_bytes();
        let c = Claim { token: encode_b58(&token), user: encode_id(&id(&carol)), signature: encode_b58(&sig) };
        assert_eq!(claim(State(app.clone()), Json(c)).await.status(), StatusCode::OK);
        let claimed = claim_head(&app.db.lock().unwrap(), &claim_rec.hash()).unwrap();
        assert_eq!(claimed.1.user, Some(id(&carol)));
        let path: String = app.db.lock().unwrap().query_row("SELECT path FROM records WHERE hash = ?1", [claimed.0], |r| r.get(0)).unwrap();
        assert_eq!(path, "/doc", "the node's version stays where the claim was");
        let carols = doc_update(&carol, &doc, "/doc", b"carol");
        put(&app, &carols).unwrap();

        let err = put(&app, &tombstone(&bob, &carols, 2)).unwrap_err();
        assert!(err.contains("never edited or deleted"), "{err}");

        let (all, seq) = streamed(&app, &doc, 0);
        assert_eq!(all, ["doc", "bob", "alice", "doc", "carol"], "the doc's versions and updates, as they arrived");
        assert_eq!(streamed(&app, &doc, seq), (vec![], seq));
        let list = list_records(State(app.clone()), HeaderMap::new(), Query(RecordsQuery { author: None, kind: None, prefix: Some("/doc".into()) })).await;
        let kinds: Vec<String> = CBOR::try_from_data(body(list).await)
            .unwrap()
            .into_array()
            .unwrap()
            .iter()
            .map(|e| Record::from_cbor(&e.as_map().unwrap().get::<_, CBOR>("record").unwrap()).unwrap().kind)
            .collect();
        assert!(!kinds.contains(&"doc_update".into()), "listing leaves out doc updates: {kinds:?}");

        // Claims stay on their node.
        let mut h = HeaderMap::new();
        h.insert("x-from", encode_id(&[7; 32]).parse().unwrap());
        let other = sign(&bob, "/doc", "claim", ClaimData { token_hash: [1; 32], user: None }.to_cbor(), None, 3);
        let res = receive(State(app.clone()), h, cbor_array(&[other.to_bytes()]).into()).await;
        let results: Vec<String> = serde_json::from_slice(&body(res).await).unwrap();
        assert!(results[0].contains("claims aren't federated"), "{}", results[0]);

        // Deleting the doc ends it.
        put(&app, &tombstone(&bob, &v2, 3)).unwrap();
        let err = put(&app, &doc_update(&bob, &doc, "/doc", b"late")).unwrap_err();
        assert!(err.contains("no live doc"), "{err}");
        assert_eq!(streamed(&app, &doc, seq).0, ["tombstone"], "streams see it go");
    }

    #[tokio::test]
    async fn streams_and_live_rooms() {
        use fedcrdt_core::DocData;
        let (app, alice, bob) = setup();
        let carol = key(3);
        let grant = GrantData { path: "/doc".into(), grantees: Grantees::Anyone };
        put(&app, &sign(&alice, GRANT_PATH, "grant", grant.to_cbor(), None, 1)).unwrap();
        let doc = sign(&bob, "/doc", "doc", DocData { title: "".into(), editors: vec![Who::User(id(&carol))] }.to_cbor(), None, 1);
        put(&app, &doc).unwrap();

        // What a stream of the doc, and one of /post, would pass on as records are stored.
        let mut rx = app.stored.subscribe();
        let (of_doc, of_posts) = (StreamFilter { doc: Some(doc.hash()), prefix: None }, StreamFilter { doc: None, prefix: Some("/post".into()) });
        let db = app.db.lock().unwrap();
        for r in [doc_update(&carol, &doc, "/doc", b"hi"), post(&bob, "/post/a", "a", None, 1), private_post(&alice, "/post/b", "secret", None, 1)] {
            assert!(app.store(&db, &r, None).unwrap());
        }
        drop(db);
        let got: Vec<(bool, bool)> = (0..3).map(|_| rx.try_recv().unwrap()).map(|s| (of_doc.matches(&s), of_posts.matches(&s))).collect();
        assert_eq!(got, [(true, false), (false, true), (false, false)], "private records are never streamed");

        // Joining the doc's live room: a fresh hello signed by an editor (or an owner), for this doc on this node.
        let hello = |k: &SigningKey, doc: &Hash, expires: u64| {
            let sig = k.sign(&live_signed_bytes(&app.pk, doc, expires)).to_bytes();
            json!({ "user": encode_id(&id(k)), "expires": expires, "signature": encode_b58(&sig) }).to_string()
        };
        let soon = now_ms() + 60_000;
        assert_eq!(app.live_hello(&doc.hash(), &hello(&carol, &doc.hash(), soon)), Ok(id(&carol)));
        assert_eq!(app.live_hello(&doc.hash(), &hello(&bob, &doc.hash(), soon)), Ok(id(&bob)));
        assert_eq!(app.live_hello(&doc.hash(), &hello(&alice, &doc.hash(), soon)), Ok(id(&alice)));
        let err = app.live_hello(&doc.hash(), &hello(&key(4), &doc.hash(), soon)).unwrap_err();
        assert!(err.contains("author and editors"), "{err}");
        let err = app.live_hello(&doc.hash(), &hello(&carol, &[0; 32], soon)).unwrap_err();
        assert!(err.contains("doesn't match"), "signed for another doc: {err}");
        let err = app.live_hello(&doc.hash(), &hello(&carol, &doc.hash(), now_ms() - 1)).unwrap_err();
        assert!(err.contains("expired"), "{err}");
    }
}
