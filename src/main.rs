use axum::{
    Extension, Json, Router,
    body::Bytes,
    extract::{
        DefaultBodyLimit, Path, Query, Request, State,
        ws::{CloseFrame, Message, WebSocket, WebSocketUpgrade},
    },
    http::{HeaderMap, Method, StatusCode, Uri, header},
    middleware::{self, Next},
    response::{
        IntoResponse, Redirect, Response,
        sse::{Event, KeepAlive, Sse},
    },
    routing::{get, post},
};
use base64::{Engine, engine::general_purpose::STANDARD as BASE64};
use ed25519_dalek::{Signer, SigningKey};
use fedcrdt_core::{
    Acting, CBOR, CLAIM_PATH, ClaimData, DocData, GrantData, Hash, MAX_ACCESS_TOKEN_MS, MAX_READ_TOKEN_MS, MAX_RECORD_BYTES, Map, NODE_INFO_PATH,
    NODE_PATH, OWNER_PATH, PeerData, Pubkey, Record, Who, access_signed_bytes, check_prefix, claim_signed_bytes, decode_b58, decode_id,
    encode_b58, encode_id, live_signed_bytes, node_phrase, path_user, path_within, phrase, read_signed_bytes, verify_sig,
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
use tower_http::cors::CorsLayer;

/// Bump to wipe the database when the schema changes incompatibly.
/// 6: records identified by hash, nodes. 7: chains table, seq as rowid. 8: private records. 9: records.doc.
/// 10: records.principal, doc snapshots.
const SCHEMA_VERSION: i64 = 10;

/// How far ahead of the node's clock a write's version may be.
const MAX_CLOCK_SKEW_MS: u64 = 10 * 60 * 1000;

/// Records per push to a peer.
const PUSH_BATCH: i64 = 100;

/// The largest message a live room passes on.
const MAX_LIVE_MSG: usize = 64 * 1024;

/// How long a live room waits for a connection's hello.
const LIVE_HELLO_TIMEOUT: Duration = Duration::from_secs(10);

/// In private mode, how often open streams and live rooms check that whoever opened them still has access.
const ACCESS_RECHECK: Duration = Duration::from_secs(30);

/// The largest body `/api/auth` takes: an access token, and maybe a claim token.
const MAX_AUTH_BYTES: usize = 4 * 1024;

struct App {
    db: Mutex<Connection>,
    /// This node's own key; its public half is `pk`.
    key: SigningKey,
    pk: Pubkey,
    /// Where the web app is served: links to it, and what access tokens name.
    origin: String,
    /// Private mode (`--private`): only owners and those with access get in (see `gate`).
    private: bool,
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
    fn new(db: Connection, key: SigningKey, origin: String, private: bool) -> App {
        let pk = key.verifying_key().to_bytes();
        App {
            db: Mutex::new(db),
            key,
            pk,
            origin,
            private,
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
    // The database and certificates live next to the binary. `DB` names another database file (relative to the
    // binary), for running several nodes from one binary in dev and tests.
    let dir = std::env::current_exe().unwrap().parent().unwrap().to_path_buf();
    let db_path = dir.join(std::env::var("DB").unwrap_or("bb.db".into())).to_string_lossy().into_owned();
    // `--drop-db` deletes the database and exits; it doesn't start the node, so that dev-mode
    // restarts (which re-run the same command) can't wipe it again. See `npm run dev:fresh`.
    let args: Vec<String> = std::env::args().skip(1).collect();
    if let Some(a) = args.iter().find(|a| !["--drop-db", "--private"].contains(&a.as_str())) {
        panic!("unknown argument {a}: expected --drop-db or --private");
    }
    if args.iter().any(|a| a == "--drop-db") {
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
    // With a domain, the node serves HTTPS on it, with certificates from Let's Encrypt (see `serve_https`).
    let domain = std::env::var("DOMAIN").ok();
    // Where other nodes reach this one.
    let public_url = std::env::var("PUBLIC_URL").unwrap_or(match &domain {
        Some(d) => format!("https://{d}"),
        None => format!("http://localhost:{port}"),
    });
    // Where the web app is served (for links). By default the node serves it itself; in dev, Vite does.
    let origin = std::env::var("ORIGIN").unwrap_or(public_url.clone());
    let serve_web = origin == public_url;

    let db = Connection::open(&db_path).unwrap();
    db.execute_batch("PRAGMA journal_mode = WAL; PRAGMA synchronous = NORMAL;").unwrap();
    create_schema(&db);

    let key = node_key(&db);
    let private = args.iter().any(|a| a == "--private");
    let app = Arc::new(App::new(db, key, origin, private));
    app.init(&public_url);
    tokio::spawn(push_loop(app.clone()));
    let router = router(app, serve_web);

    println!("listening {public_url}{}", if private { " (private)" } else { "" });
    match domain {
        Some(domain) => serve_https(router, domain, dir.join("certs")).await,
        None => {
            let listener = tokio::net::TcpListener::bind(format!("0.0.0.0:{port}")).await.unwrap();
            axum::serve(listener, router).await.unwrap();
        }
    }
}

/// The API, and the web app if `serve_web` (else a redirect to it, at `app.origin`).
fn router(app: Arc<App>, serve_web: bool) -> Router {
    let origin = app.origin.clone();
    Router::new()
        .route("/api/users", get(users))
        .route("/api/users/{pubkey}", get(user))
        .route("/api/records", get(list_records).post(put_record))
        .route("/api/records/{hash}", get(chain))
        .route("/api/stream", get(stream))
        .route("/api/docs/{hash}/live", get(live))
        .route("/api/node", get(node_info))
        .route("/api/nodes", get(nodes))
        .route("/api/claim", post(claim))
        .route("/api/auth", post(auth).delete(sign_out).layer(DefaultBodyLimit::max(MAX_AUTH_BYTES)))
        .route("/receive", post(receive))
        .with_state(app.clone())
        // Records are signed and reads carry no cookies, so any web app, from any origin, may use the API.
        .layer(CorsLayer::permissive())
        .layer(DefaultBodyLimit::max(MAX_RECORD_BYTES * 4))
        .fallback(move |uri: Uri| async move {
            if serve_web {
                return web(uri.path());
            }
            let path = uri.path_and_query().map_or("/", |p| p.as_str());
            Redirect::temporary(&format!("{origin}{path}")).into_response()
        })
        // Outermost, so it sees every request, the fallback's too.
        .layer(middleware::from_fn_with_state(app.clone(), gate))
        .layer(middleware::from_fn_with_state(app, security_headers))
}

/// Headers for every response: never framed (so no clickjacking, e.g. of /connect), no content sniffing,
/// no referrers, and over HTTPS, HSTS.
async fn security_headers(State(app): S, req: Request, next: Next) -> Response {
    let mut res = next.run(req).await;
    let h = res.headers_mut();
    h.insert(header::X_FRAME_OPTIONS, header::HeaderValue::from_static("DENY"));
    h.insert(header::CONTENT_SECURITY_POLICY, header::HeaderValue::from_static("frame-ancestors 'none'"));
    h.insert(header::X_CONTENT_TYPE_OPTIONS, header::HeaderValue::from_static("nosniff"));
    h.insert(header::REFERRER_POLICY, header::HeaderValue::from_static("no-referrer"));
    if app.origin.starts_with("https:") {
        h.insert(header::STRICT_TRANSPORT_SECURITY, header::HeaderValue::from_static("max-age=31536000"));
    }
    res
}

/// Serves HTTPS for `domain` on port 443, getting and renewing its certificate from Let's Encrypt (through
/// TLS-ALPN-01, on that same port), and redirects port 80 to it. Certificates are kept in `certs`, so restarts
/// don't ask for new ones. `ACME_STAGING=1` uses Let's Encrypt's staging directory, whose certificates browsers
/// don't trust but whose rate limits are loose: for trying a setup out.
async fn serve_https(router: Router, domain: String, certs: std::path::PathBuf) {
    use tokio_stream::StreamExt;
    let mut acme = rustls_acme::AcmeConfig::new([domain.clone()])
        .cache(rustls_acme::caches::DirCache::new(certs))
        .directory_lets_encrypt(std::env::var("ACME_STAGING").is_err())
        .state();
    let acceptor = acme.axum_acceptor(acme.default_rustls_config());
    tokio::spawn(async move {
        while let Some(event) = acme.next().await {
            match event {
                Ok(ok) => println!("acme: {ok:?}"),
                Err(e) => eprintln!("acme: {e}"),
            }
        }
    });

    let to_https = Router::new().fallback(move |uri: Uri| async move {
        let path = uri.path_and_query().map_or("/", |p| p.as_str());
        Redirect::permanent(&format!("https://{domain}{path}"))
    });
    let http = bind(80).await;
    tokio::spawn(async move { axum::serve(http, to_https).await.unwrap() });

    axum_server::from_tcp(bind(443).await.into_std().unwrap()).unwrap().acceptor(acceptor).serve(router.into_make_service()).await.unwrap();
}

/// Listens on `port` on every address: IPv6 and IPv4 where the host has IPv6, else IPv4 only.
async fn bind(port: u16) -> tokio::net::TcpListener {
    match tokio::net::TcpListener::bind(("::", port)).await {
        Ok(l) => l,
        Err(_) => tokio::net::TcpListener::bind(("0.0.0.0", port)).await.unwrap(),
    }
}

/// The web app's built files (`npm run build`). Release builds compile them in; debug builds read them from
/// disk, so a missing `web/dist` only matters once a page is asked for.
#[derive(rust_embed::Embed)]
#[folder = "web/dist"]
#[allow_missing = true]
struct Web;

/// Serves the web app: the file at `path`, or else the app's page, as every route is the same SPA.
fn web(path: &str) -> Response {
    let path = path.trim_start_matches('/');
    let (path, file) = match Web::get(path) {
        Some(file) => (path, file),
        // A missing script or style is an error, not a route.
        None if path.starts_with("assets/") => return StatusCode::NOT_FOUND.into_response(),
        None => match Web::get("index.html") {
            Some(file) => ("index.html", file),
            None => return (StatusCode::NOT_FOUND, "web app not built: run `npm run build`").into_response(),
        },
    };
    // Vite names built assets by their content hash, so they never change; everything else might.
    let cache = if path.starts_with("assets/") { "public, max-age=31536000, immutable" } else { "no-cache" };
    ([(header::CONTENT_TYPE, file.metadata.mimetype()), (header::CACHE_CONTROL, cache)], file.data).into_response()
}

/// The sign-in page's own files (`web/gate.html` and what it loads), from Vite's manifest: all a private
/// node shows to those it doesn't let in.
static GATE_FILES: std::sync::LazyLock<HashSet<String>> = std::sync::LazyLock::new(|| {
    let mut files = HashSet::new();
    let Some(manifest) = Web::get(".vite/manifest.json").and_then(|f| serde_json::from_slice::<Value>(&f.data).ok()) else {
        return files;
    };
    let mut todo = vec!["gate.html".to_string()];
    let mut seen = HashSet::new();
    while let Some(key) = todo.pop() {
        if !seen.insert(key.clone()) {
            continue;
        }
        let Some(chunk) = manifest.get(&key) else { continue };
        let strings = |k: &str| chunk.get(k).and_then(Value::as_array).into_iter().flatten().filter_map(Value::as_str).map(String::from);
        files.extend(chunk.get("file").and_then(Value::as_str).map(String::from));
        files.extend(strings("css"));
        files.extend(strings("assets"));
        todo.extend(strings("imports"));
    }
    files.remove("gate.html");
    files
});

/// The sign-in page, as a private node answers page loads from those it doesn't let in. 401, so that the
/// service worker (web/public/sw.js) doesn't keep it as the app.
fn gate_page() -> Response {
    let no_store = [(header::CACHE_CONTROL, "no-store")];
    match Web::get("gate.html") {
        Some(f) => (StatusCode::UNAUTHORIZED, no_store, [(header::CONTENT_TYPE, "text/html; charset=utf-8")], f.data).into_response(),
        None => (StatusCode::UNAUTHORIZED, no_store, "web app not built: run `npm run build`").into_response(),
    }
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
            author BLOB NOT NULL,  -- who signed it
            principal BLOB NOT NULL, -- whose it is: the user its `as` names, or else its author
            path TEXT NOT NULL,
            version INTEGER NOT NULL,
            type TEXT NOT NULL,
            edits BLOB,            -- hash of the version it edits or deletes
            private INTEGER NOT NULL, -- 1: only this node's owners may read it, and it's never pushed
            root BLOB NOT NULL,    -- its chain's first record: follows `edits` back as far as this node has
            record BLOB NOT NULL,  -- the record's deterministic CBOR, signature included
            received_from BLOB,    -- the node that pushed it here, if one did; it isn't pushed back there
            doc BLOB               -- for a doc update or snapshot: its doc (the doc chain's first record's hash)
        );
        CREATE INDEX IF NOT EXISTS records_by_root ON records (root, version, hash);
        CREATE INDEX IF NOT EXISTS records_by_doc ON records (doc, seq) WHERE doc IS NOT NULL;
        -- One row per chain (by root), kept up to date by `store`: its current version (newest by
        -- version, then hash) and a summary. path, type and version are the head's, for querying.
        CREATE TABLE IF NOT EXISTS chains (
            root BLOB PRIMARY KEY,
            head BLOB NOT NULL,     -- hash of the current version
            author BLOB,            -- whose the root record is (its principal); NULL until it arrives here
            path TEXT NOT NULL,
            type TEXT NOT NULL,
            version INTEGER NOT NULL,
            versions INTEGER NOT NULL, -- how many versions this node has
            deleted INTEGER NOT NULL   -- 1 if any version is a tombstone
        );
        CREATE INDEX IF NOT EXISTS chains_by_type ON chains (type) WHERE NOT deleted;
        CREATE INDEX IF NOT EXISTS chains_by_path ON chains (path) WHERE NOT deleted;
        CREATE INDEX IF NOT EXISTS chains_by_author ON chains (author) WHERE NOT deleted;
        -- Each live chain's current version. `author` is the head's signer, `principal` whose it is; `by`
        -- whose the root is: who may edit the chain, besides the node's owners. A chain is private
        -- if its head is.
        CREATE VIEW IF NOT EXISTS heads AS
            SELECT c.root, c.head AS hash, c.author AS by, c.path, c.type, c.version, c.versions, r.author, r.principal, r.private, r.record
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

/// Whether `user` may get into this node in private mode: they're an owner, or an access record names them.
fn has_access(db: &Connection, user: &Pubkey) -> bool {
    owners(db).contains(user)
        || heads_of(db, "access").iter().any(|(_, r)| r.access().and_then(|w| w.resolve(|c| claimed_by(db, c))).as_ref() == Some(user))
}

/// Whether the delegation `a` names lets `key` sign a record of type `kind` at `path` for `a.user`, now:
/// it's a live "delegate" chain, its current version is by `a.user` for `key`, and it covers that.
fn delegated(db: &Connection, key: &Pubkey, a: &Acting, path: &str, kind: &str) -> Result<(), String> {
    let head: Option<Vec<u8>> =
        db.query_row("SELECT record FROM heads WHERE root = ?1 AND type = 'delegate'", [a.delegation], |r| r.get(0)).optional().unwrap();
    let head = parse_record(head.ok_or("this node doesn't have that delegation, or it was revoked")?);
    let d = head.delegate().filter(|_| head.author == a.user).ok_or("that delegation isn't the user's")?;
    if d.key != *key {
        return Err("that delegation is for another key".into());
    }
    if !d.covers(path, kind, now_ms()) {
        return Err(format!("the delegation doesn't cover a {kind} at {path}, or it expired"));
    }
    Ok(())
}

/// Whether `rec`, an update or snapshot of the doc `doc`, may be written here: the doc is live, `rec` is
/// at its current path, and its principal is the doc's author, one of its editors, or an owner.
fn authorize_doc_write(db: &Connection, rec: &Record, doc: &Hash, owner: bool) -> Result<(), String> {
    let (by, head, data) = doc_head(db, doc)?;
    if rec.path != head.path {
        return Err(format!("this doc's updates go at its path, {}", head.path));
    }
    if !owner && !data.may_edit(&by, &rec.principal(), |c| claimed_by(db, c)) {
        return Err("only the doc's author and editors can edit it".into());
    }
    Ok(())
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
    for pk in [rec.author, rec.principal()] {
        tx.execute("INSERT OR IGNORE INTO users (pubkey) VALUES (?1)", [pk]).unwrap();
    }
    tx.execute(
        "INSERT INTO records (hash, author, principal, path, version, type, edits, private, root, record, received_from, doc)
         VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12)",
        (hash, rec.author, rec.principal(), &rec.path, rec.version as i64, &rec.kind, rec.edits, rec.private, root, rec.to_bytes(), from, rec.doc_ref()),
    )
    .unwrap();
    // Edits of this record that arrived before it were filed under it as their root.
    if root != hash {
        tx.execute("UPDATE records SET root = ?1 WHERE root = ?2", (root, hash)).unwrap();
        tx.execute("DELETE FROM chains WHERE root = ?1", [hash]).unwrap();
    }
    tx.execute(
        "INSERT OR REPLACE INTO chains (root, head, author, path, type, version, versions, deleted)
         SELECT ?1, h.hash, (SELECT principal FROM records WHERE hash = ?1), h.path, h.type, h.version,
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
            let doc = rec.doc_ref();
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
            acting: None,
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
    fn init(&self, public_url: &str) {
        let origin = &self.origin;
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

    /// Whether `rec`'s author may write it here (see "nodes" and "user spaces" in core/src/lib.rs). For
    /// records written to this node, not those pushed by peers. Records signed under a delegation count as
    /// their principal's, if the delegation lets their author sign them.
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
        if let Some(a) = &rec.acting {
            delegated(db, &rec.author, a, &rec.path, &rec.kind)?;
        }
        let principal = rec.principal();
        let owner = owners(db).contains(&principal);
        if rec.is_node_record() && !owner {
            return Err(format!("only this node's owners can write under {NODE_PATH}"));
        }
        if let Some(u) = path_user(&rec.path)
            && u != principal
            && !owner
        {
            return Err(format!("{} is {}'s space: only they can write there", rec.path, phrase(&u)));
        }
        if let Some(doc) = rec.doc_ref() {
            return authorize_doc_write(db, rec, &doc, owner);
        }
        let Some(prev_hash) = rec.edits else {
            return if may_write(db, &principal, &rec.path) { Ok(()) } else { Err(format!("writing at {} needs a grant", rec.path)) };
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
        if prev.kind == "doc_update" || prev.kind == "doc_snapshot" {
            return Err("doc updates and snapshots are never edited or deleted; delete the doc instead".into());
        }
        if rec.kind != "tombstone" && rec.kind != prev.kind {
            return Err("an edit can't change a record's type".into());
        }
        if let (Some(new), Some(old)) = (rec.doc(), prev.doc())
            && (new.format != old.format || new.schema != old.schema || new.keys.is_some() != old.keys.is_some())
        {
            return Err("an edit can't change a doc's format, schema, or whether it's encrypted".into());
        }
        if prev.claim().is_some_and(|c| c.user.is_some()) && rec.kind != "tombstone" {
            return Err("that claim was already claimed".into());
        }
        if !owner {
            let original: Option<Pubkey> = db.query_row("SELECT principal FROM records WHERE hash = ?1", [root], |r| r.get(0)).optional().unwrap();
            if original != Some(principal) {
                return Err("only its author or this node's owners can edit or delete it".into());
            }
            if rec.kind != "tombstone" && rec.path != prev.path && !may_write(db, &principal, &rec.path) {
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

    /// Whether the request is from one of this node's owners, by its read token (see `read_signed_bytes`
    /// in core/src/lib.rs): `Authorization: Bisonbase <ID>.<expires>.<signature>`, base58 but for the
    /// expiry (ms since the epoch). Only owners may read private records. Err if the token isn't valid.
    fn owner_reading(&self, db: &Connection, headers: &HeaderMap) -> Result<bool, Response> {
        let Some(v) = headers.get(header::AUTHORIZATION) else { return Ok(false) };
        let bad = |e: &str| err(StatusCode::UNAUTHORIZED, format!("read token: {e}"));
        let Some((user, expires, sig)) = v.to_str().ok().and_then(|v| v.strip_prefix("Bisonbase ")).and_then(parse_token) else {
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

/// A signed token's parts, as read and access tokens write them: `<ID>.<expires>.<signature>`, base58 but
/// for the expiry (ms since the epoch).
fn parse_token(s: &str) -> Option<(Pubkey, u64, [u8; 64])> {
    let mut parts = s.split('.');
    let token = (
        parts.next().and_then(decode_id)?,
        parts.next()?.parse().ok()?,
        parts.next().and_then(decode_b58).and_then(|s| s.try_into().ok())?,
    );
    parts.next().is_none().then_some(token)
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

/// The current version of every live chain matching the query (but doc updates and snapshots, unless
/// `type` asks for them), newest first, as a CBOR array of
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
        // There are lots, and they only mean something together, in a doc's stream.
        None => sql += " AND type NOT IN ('doc_update', 'doc_snapshot')",
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
    /// For a doc's stream from the beginning: start from its newest snapshot (see `compact`).
    snapshot: Option<bool>,
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

/// A doc's records (as `stored_after` lists them) starting from its newest snapshot by someone who may edit
/// it: that snapshot, and the rest but other snapshots and the updates it covers. As they are if it has no
/// such snapshot. Readers who don't trust the snapshot can stream the doc without `snapshot`.
fn compact(db: &Connection, doc: &Hash, backlog: Vec<(i64, Vec<u8>)>) -> Vec<(i64, Vec<u8>)> {
    let Ok((by, _, data)) = doc_head(db, doc) else { return backlog };
    let owners = owners(db);
    let trusted = |r: &Record| {
        let p = r.principal();
        r.acting.as_ref().is_none_or(|a| delegated(db, &r.author, a, &r.path, &r.kind).is_ok())
            && (owners.contains(&p) || data.may_edit(&by, &p, |c| claimed_by(db, c)))
    };
    let hash = |b: &[u8]| -> Hash { Sha256::digest(b).into() };
    let best = backlog
        .iter()
        .filter_map(|(_, b)| {
            let r = parse_record(b.clone());
            let s = r.doc_snapshot().filter(|s| s.doc == *doc && trusted(&r))?;
            Some((r.version, hash(b), s.covers))
        })
        .max_by(|a, b| (a.0, a.1).cmp(&(b.0, b.1)));
    let Some((_, snapshot, covers)) = best else { return backlog };
    let covers: HashSet<Hash> = covers.into_iter().collect();
    backlog
        .into_iter()
        .filter(|(_, b)| {
            let h = hash(b);
            h == snapshot
                || match parse_record(b.clone()).kind.as_str() {
                    "doc_snapshot" => false,
                    "doc_update" => !covers.contains(&h),
                    _ => true,
                }
        })
        .collect()
}

/// Server-sent events: every record matching the query that's here (after `after`), then a "ready"
/// event (its data: the last record's seq), then each new one as it's stored. Each "record" event's data is the record (base64 CBOR), and
/// its ID is where to continue from. A stream that falls too far behind is ended; EventSource reconnects
/// and picks up where it left off.
async fn stream(State(app): S, access: Option<Extension<Access>>, headers: HeaderMap, Query(q): Query<StreamQuery>) -> Response {
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
        let mut backlog = stored_after(&db, &f, after);
        if let (Some(doc), 0, Some(true)) = (f.doc, after, q.snapshot) {
            backlog = compact(&db, &doc, backlog);
        }
        (backlog, app.stored.subscribe())
    };
    let (tx, rx) = mpsc::channel::<Result<Event, Infallible>>(64);
    let record = |seq: i64, bytes: &[u8]| Ok(Event::default().event("record").id(seq.to_string()).data(BASE64.encode(bytes)));
    let lapsed = lapsed(app.clone(), access.map(|a| a.0));
    tokio::spawn(async move {
        tokio::pin!(lapsed);
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
                _ = &mut lapsed => return,
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

/// `user` signs it. With `as` and `delegation` (base58), they sign for the user `as`, under that
/// delegation, which has to let them write the doc's updates.
#[derive(Deserialize)]
struct Hello {
    user: String,
    expires: u64,
    signature: String,
    #[serde(rename = "as")]
    acting: Option<String>,
    delegation: Option<String>,
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
        let (by, head, data) = doc_head(&db, doc)?;
        let user = match (h.acting, h.delegation) {
            (None, None) => user,
            (Some(u), Some(d)) => {
                let a = Acting {
                    user: decode_id(&u).ok_or("the hello's \"as\" isn't an ID")?,
                    delegation: decode_b58(&d).and_then(|d| d.try_into().ok()).ok_or("the hello's delegation isn't a hash")?,
                };
                delegated(&db, &user, &a, &head.path, "doc_update")?;
                a.user
            }
            _ => return Err("a hello with \"as\" needs a delegation too".into()),
        };
        if !owners(&db).contains(&user) && !data.may_edit(&by, &user, |c| claimed_by(&db, c)) {
            return Err("only the doc's author and editors can join".into());
        }
        Ok(user)
    }
}

/// Joins the live room of the doc whose chain starts with the record with this hash (base58).
async fn live(State(app): S, access: Option<Extension<Access>>, Path(hash): Path<String>, ws: WebSocketUpgrade) -> Response {
    let Some(doc) = decode_b58(&hash).and_then(|h| Hash::try_from(h).ok()) else {
        return err(StatusCode::BAD_REQUEST, "hash isn't 32 bytes of base58");
    };
    ws.max_message_size(MAX_LIVE_MSG).on_upgrade(move |socket| live_conn(app, access.map(|a| a.0), doc, socket))
}

async fn live_conn(app: Arc<App>, access: Option<Access>, doc: Hash, mut ws: WebSocket) {
    let hello = match tokio::time::timeout(LIVE_HELLO_TIMEOUT, ws.recv()).await {
        Ok(Some(Ok(Message::Text(t)))) => app.live_hello(&doc, &t),
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
    let lapsed = lapsed(app.clone(), access);
    tokio::pin!(lapsed);
    loop {
        tokio::select! {
            _ = &mut lapsed => break,
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
        "private": app.private,
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
    let db = app.db.lock().unwrap();
    let Some(found) = find_claim(&db, &token) else {
        return err(StatusCode::NOT_FOUND, "This claim link isn't for this node, or its claim was deleted.");
    };
    if found.data.user.is_some() {
        return err(StatusCode::FORBIDDEN, "This claim link was already used.");
    }
    let root = found.root;
    app.redeem(&db, found, &user);
    Json(json!({ "claim": encode_b58(&root) })).into_response()
}

/// A live claim, found by its token.
struct FoundClaim {
    head: Hash,
    root: Hash,
    path: String,
    data: ClaimData,
}

/// The live claim whose token this is, if this node has one.
fn find_claim(db: &Connection, token: &[u8]) -> Option<FoundClaim> {
    let token_hash: Hash = Sha256::digest(token).into();
    let mut stmt = db.prepare("SELECT hash, root, record FROM heads WHERE type = 'claim'").unwrap();
    stmt.query_map([], |r| Ok((r.get::<_, Hash>(0)?, r.get::<_, Hash>(1)?, r.get::<_, Vec<u8>>(2)?)))
        .unwrap()
        .flatten()
        .find_map(|(head, root, b)| {
            let r = parse_record(b);
            Some(FoundClaim { head, root, data: r.claim().filter(|c| c.token_hash == token_hash)?, path: r.path })
        })
}

impl App {
    /// Has `user` claim the unclaimed claim `c`: writes its new version naming them.
    fn redeem(&self, db: &Connection, c: FoundClaim, user: &Pubkey) {
        db.execute("INSERT OR IGNORE INTO users (pubkey) VALUES (?1)", [user]).unwrap();
        self.write(db, &c.path, "claim", ClaimData { user: Some(*user), ..c.data }.to_cbor(), Some(c.head));
        println!("claim {} claimed by {} ({})", encode_b58(&c.root), encode_id(user), phrase(user));
    }

    /// Who the request's access cookie (see `auth`) is from, if it's valid and they have access.
    fn let_in(&self, headers: &HeaderMap) -> Option<Access> {
        let (user, expires, sig) = cookie(headers, self.access_cookie()).and_then(parse_token)?;
        if expires > now_ms() + MAX_ACCESS_TOKEN_MS {
            return None;
        }
        verify_sig(&user, &access_signed_bytes(&self.origin, expires), &sig).ok()?;
        let access = Access { user, expires };
        self.still_in(&access).then_some(access)
    }

    /// Whether `a` still lets its user in: it hasn't expired, and they still have access.
    fn still_in(&self, a: &Access) -> bool {
        a.expires >= now_ms() && has_access(&self.db.lock().unwrap(), &a.user)
    }

    /// The access cookie's name. Over HTTPS, `__Host-`, so that no other (sub)domain can set it.
    fn access_cookie(&self) -> &'static str {
        if self.origin.starts_with("https:") { "__Host-bb_access" } else { "bb_access" }
    }
}

/// Who a private node let a request in for (see `gate`), and until when: a request extension.
#[derive(Clone, Copy)]
struct Access {
    user: Pubkey,
    expires: u64,
}

/// Resolves once `access` lapses (it expires, or its user's access is removed); never without one, as
/// outside private mode. Ends streams and live rooms that outlive someone's access.
async fn lapsed(app: Arc<App>, access: Option<Access>) {
    let Some(a) = access else { return std::future::pending().await };
    let mut tick = tokio::time::interval(ACCESS_RECHECK);
    loop {
        tick.tick().await;
        if !app.still_in(&a) {
            return;
        }
    }
}

// ---- private mode ----

/// The value of the cookie `name`, if the request has it.
fn cookie<'a>(headers: &'a HeaderMap, name: &str) -> Option<&'a str> {
    headers
        .get_all(header::COOKIE)
        .iter()
        .filter_map(|v| v.to_str().ok())
        .flat_map(|v| v.split(';'))
        .find_map(|c| c.trim().strip_prefix(name)?.strip_prefix('='))
}

/// In private mode, lets through only requests with a valid access cookie from someone with access. Others
/// get the sign-in page (`gate_page`) for page loads, its own files, and `/api/auth`; anything else is a
/// bare 404, so that they can't tell what this is.
async fn gate(State(app): S, mut req: Request, next: Next) -> Response {
    let path = req.uri().path();
    if !app.private || path == "/api/auth" || GATE_FILES.contains(path.trim_start_matches('/')) {
        return next.run(req).await;
    }
    if let Some(access) = app.let_in(req.headers()) {
        req.extensions_mut().insert(access);
        return next.run(req).await;
    }
    let page = req.method() == Method::GET
        && req.headers().get(header::ACCEPT).and_then(|v| v.to_str().ok()).is_some_and(|a| a.contains("text/html"));
    if page { gate_page() } else { StatusCode::NOT_FOUND.into_response() }
}

/// An access token, to sign in to a private node: the user's ID and signature over `access_signed_bytes`
/// (base58), and its expiry (ms since the epoch). With `claim`, the token from a claim link (base58): the
/// claim is claimed for the user first, if it'd let them in (or they already have access).
#[derive(Deserialize)]
struct Auth {
    user: String,
    expires: u64,
    signature: String,
    claim: Option<String>,
}

/// Signs in to a private node: if the token checks out and its user has access, sets it as the access
/// cookie, until it expires. Only on private nodes.
async fn auth(State(app): S, Json(a): Json<Auth>) -> Response {
    if !app.private {
        return StatusCode::NOT_FOUND.into_response();
    }
    let (Some(user), Some(sig)) = (decode_id(&a.user), decode_b58(&a.signature).and_then(|s| <[u8; 64]>::try_from(s).ok())) else {
        return err(StatusCode::BAD_REQUEST, "malformed access token");
    };
    let now = now_ms();
    if a.expires < now || a.expires > now + MAX_ACCESS_TOKEN_MS {
        return err(StatusCode::BAD_REQUEST, "access token expired, or expires too far ahead; check your clock");
    }
    if let Err(e) = verify_sig(&user, &access_signed_bytes(&app.origin, a.expires), &sig) {
        return err(StatusCode::BAD_REQUEST, format!("access token: {e}"));
    }
    let db = app.db.lock().unwrap();
    // A claim that'd let them in, or any claim if they're in already. Others stay unclaimed, for whoever
    // the link was meant for; a bad link just doesn't help.
    if let Some(found) = a.claim.as_deref().and_then(decode_b58).and_then(|t| find_claim(&db, &t))
        && found.data.user.is_none()
        && (has_access(&db, &user)
            || ["owner", "access"].iter().any(|k| heads_of(&db, k).iter().any(|(_, r)| matches!(r.owner().or(r.access()), Some(Who::Claim(c)) if c == found.root))))
    {
        app.redeem(&db, found, &user);
    }
    if !has_access(&db, &user) {
        return err(StatusCode::FORBIDDEN, "no access");
    }
    let token = format!("{}.{}.{}", encode_id(&user), a.expires, encode_b58(&sig));
    let max_age = (a.expires - now) / 1000;
    let secure = if app.origin.starts_with("https:") { "; Secure" } else { "" };
    let cookie = format!("{}={token}; Path=/; Max-Age={max_age}; HttpOnly; SameSite=Lax{secure}", app.access_cookie());
    (StatusCode::NO_CONTENT, [(header::SET_COOKIE, cookie)]).into_response()
}

/// Signs out of a private node: clears the access cookie.
async fn sign_out(State(app): S) -> Response {
    let secure = if app.origin.starts_with("https:") { "; Secure" } else { "" };
    let cookie = format!("{}=; Path=/; Max-Age=0; HttpOnly; SameSite=Lax{secure}", app.access_cookie());
    (StatusCode::NO_CONTENT, [(header::SET_COOKIE, cookie)]).into_response()
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
    use fedcrdt_core::{ACCESS_PATH, DelegateData, DocSnapshotData, DocUpdateData, EncKeyData, GRANT_PATH, Grantees, delegate_path, enckey_path, user_path};

    /// A fresh node on an in-memory database, started as `main` does: it has a node record, and an
    /// owner record naming an unclaimed claim.
    fn node() -> App {
        node_in_mode(false)
    }

    /// `node()`, in private mode or not.
    fn node_in_mode(private: bool) -> App {
        let db = Connection::open_in_memory().unwrap();
        create_schema(&db);
        let key = node_key(&db);
        let app = App::new(db, key, "http://web.test".into(), private);
        app.init("http://node.test");
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
            acting: None,
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

    fn doc_data(title: &str, editors: Vec<Who>) -> DocData {
        DocData { title: title.into(), editors, format: "yjs".into(), schema: "bisonbase.markdown".into(), keys: None }
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
        let (app, alice, bob) = setup();
        let carol = key(3);
        let grant = GrantData { path: "/doc".into(), grantees: Grantees::Anyone };
        put(&app, &sign(&alice, GRANT_PATH, "grant", grant.to_cbor(), None, 1)).unwrap();

        let doc = sign(&bob, "/doc", "doc", doc_data("Plans", vec![]).to_cbor(), None, 1);
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
        let v2 = sign(&bob, "/doc", "doc", doc_data("Plans", vec![Who::Claim(claim_rec.hash())]).to_cbor(), Some(&doc), 2);
        put(&app, &v2).unwrap();
        for changed in [
            DocData { schema: "bisonbase.list".into(), ..doc_data("Plans", vec![]) },
            DocData { format: "automerge".into(), ..doc_data("Plans", vec![]) },
            DocData { keys: Some(vec![]), ..doc_data("Plans", vec![]) },
        ] {
            let err = put(&app, &sign(&bob, "/doc", "doc", changed.to_cbor(), Some(&v2), 3)).unwrap_err();
            assert!(err.contains("format, schema"), "{err}");
        }
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
        let (app, alice, bob) = setup();
        let carol = key(3);
        let grant = GrantData { path: "/doc".into(), grantees: Grantees::Anyone };
        put(&app, &sign(&alice, GRANT_PATH, "grant", grant.to_cbor(), None, 1)).unwrap();
        let doc = sign(&bob, "/doc", "doc", doc_data("", vec![Who::User(id(&carol))]).to_cbor(), None, 1);
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

    /// `key`'s record `r`, re-signed for `user` under `delegation`.
    fn acting(key: &SigningKey, r: Record, user: &SigningKey, delegation: &Record) -> Record {
        let mut r = Record { acting: Some(Acting { user: id(user), delegation: delegation.hash() }), ..r };
        r.signature = key.sign(&r.signed_bytes()).to_bytes();
        r
    }

    fn grant_anyone(app: &App, owner: &SigningKey, path: &str) {
        put(app, &sign(owner, GRANT_PATH, "grant", GrantData { path: path.into(), grantees: Grantees::Anyone }.to_cbor(), None, 1)).unwrap();
    }

    #[test]
    fn app_types_and_user_spaces() {
        let (app, alice, bob) = setup();
        let carol = key(3);
        grant_anyone(&app, &alice, "/todo");
        grant_anyone(&app, &alice, "/u");

        let item = sign(&bob, "/todo/1", "todo.item", "milk".into(), None, 1);
        put(&app, &item).expect("any app type, given a grant");
        let err = put(&app, &sign(&carol, "/todo/1", "todo.item", "eggs".into(), Some(&item), 2)).unwrap_err();
        assert!(err.contains("only its author"), "{err}");
        put(&app, &sign(&bob, "/todo/1", "todo.item", "oat milk".into(), Some(&item), 2)).unwrap();
        let err = put(&app, &sign(&bob, "/todo/1", "todo.thing", "x".into(), Some(&item), 3)).unwrap_err();
        assert!(err.contains("type"), "{err}");
        assert!(put(&app, &sign(&bob, "/todo/2", "todo", "x".into(), None, 1)).unwrap_err().contains("unknown record type"));

        let space = user_path(&id(&bob));
        put(&app, &sign(&bob, &enckey_path(&id(&bob)), "enckey", EncKeyData { key: [5; 32] }.to_cbor(), None, 1)).unwrap();
        put(&app, &post(&bob, &format!("{space}/notes"), "mine", None, 1)).unwrap();
        let err = put(&app, &post(&carol, &format!("{space}/notes"), "in bob's space", None, 1)).unwrap_err();
        assert!(err.contains("space"), "{err}");
        put(&app, &post(&alice, &format!("{space}/notes"), "an owner's", None, 1)).expect("owners may write anywhere");

        // Still only with a grant: owners decide who stores what on their node.
        let other = node();
        let err = put(&other, &sign(&bob, &enckey_path(&id(&bob)), "enckey", EncKeyData { key: [5; 32] }.to_cbor(), None, 1)).unwrap_err();
        assert!(err.contains("needs a grant"), "{err}");
    }

    #[test]
    fn delegations() {
        let (app, alice, bob) = setup();
        let (carol, todo_app, other_key) = (key(3), key(9), key(10));
        grant_anyone(&app, &alice, "/todo");
        grant_anyone(&app, &alice, "/u");
        grant_anyone(&app, &alice, "/doc");
        let data = DelegateData {
            key: id(&todo_app),
            name: "Todo".into(),
            paths: Some(vec!["/todo".into(), "/doc".into()]),
            types: Some(vec!["todo.item".into(), "doc_update".into()]),
            expires: None,
        };
        let deleg = sign(&bob, &delegate_path(&id(&bob)), "delegate", data.to_cbor(), None, 1);
        put(&app, &deleg).unwrap();

        let item = acting(&todo_app, sign(&todo_app, "/todo/1", "todo.item", "milk".into(), None, 1), &bob, &deleg);
        put(&app, &item).expect("the app signs for bob");
        let by: Pubkey = app.db.lock().unwrap().query_row("SELECT author FROM chains WHERE root = ?1", [item.hash()], |r| r.get(0)).unwrap();
        assert_eq!(by, id(&bob), "it's bob's");
        put(&app, &sign(&bob, "/todo/1", "todo.item", "oat milk".into(), Some(&item), 2)).expect("so bob may edit it himself");

        let err = put(&app, &acting(&todo_app, post(&todo_app, "/todo/2", "hi", None, 1), &bob, &deleg)).unwrap_err();
        assert!(err.contains("doesn't cover"), "{err}");
        let err = put(&app, &acting(&todo_app, sign(&todo_app, "/elsewhere", "todo.item", "x".into(), None, 1), &bob, &deleg)).unwrap_err();
        assert!(err.contains("doesn't cover"), "{err}");
        let err = put(&app, &acting(&other_key, sign(&other_key, "/todo/3", "todo.item", "x".into(), None, 1), &bob, &deleg)).unwrap_err();
        assert!(err.contains("another key"), "{err}");
        let err = put(&app, &acting(&todo_app, sign(&todo_app, "/todo/4", "todo.item", "x".into(), None, 1), &carol, &deleg)).unwrap_err();
        assert!(err.contains("isn't the user's"), "{err}");
        let err = put(&app, &acting(&todo_app, post(&todo_app, &format!("{}/x", user_path(&id(&bob))), "x", None, 1), &bob, &deleg)).unwrap_err();
        assert!(err.contains("doesn't cover"), "{err}");

        // A doc of bob's, which the app edits for him.
        let doc = sign(&bob, "/doc", "doc", doc_data("", vec![]).to_cbor(), None, 1);
        put(&app, &doc).unwrap();
        put(&app, &acting(&todo_app, doc_update(&todo_app, &doc, "/doc", b"x"), &bob, &deleg)).expect("as bob, an editor");
        let hello = |doc: &Hash, user: Option<&SigningKey>, deleg: &Record| {
            let expires = now_ms() + 60_000;
            let sig = todo_app.sign(&live_signed_bytes(&app.pk, doc, expires)).to_bytes();
            let mut h = json!({ "user": encode_id(&id(&todo_app)), "expires": expires, "signature": encode_b58(&sig) });
            if let Some(u) = user {
                h["as"] = encode_id(&id(u)).into();
                h["delegation"] = encode_b58(&deleg.hash()).into();
            }
            h.to_string()
        };
        assert_eq!(app.live_hello(&doc.hash(), &hello(&doc.hash(), Some(&bob), &deleg)), Ok(id(&bob)), "joins as bob");
        assert!(app.live_hello(&doc.hash(), &hello(&doc.hash(), None, &deleg)).unwrap_err().contains("author and editors"));
        assert!(app.live_hello(&doc.hash(), &hello(&doc.hash(), Some(&carol), &deleg)).unwrap_err().contains("isn't the user's"));

        // Expired, then revoked.
        let expired = DelegateData { expires: Some(now_ms() - 1), ..data.clone() };
        let old = sign(&bob, &delegate_path(&id(&bob)), "delegate", expired.to_cbor(), None, 2);
        put(&app, &old).unwrap();
        let err = put(&app, &acting(&todo_app, sign(&todo_app, "/todo/5", "todo.item", "x".into(), None, 1), &bob, &old)).unwrap_err();
        assert!(err.contains("expired"), "{err}");
        put(&app, &tombstone(&bob, &deleg, 2)).unwrap();
        let err = put(&app, &acting(&todo_app, sign(&todo_app, "/todo/6", "todo.item", "x".into(), None, 1), &bob, &deleg)).unwrap_err();
        assert!(err.contains("revoked"), "{err}");
        assert!(app.live_hello(&doc.hash(), &hello(&doc.hash(), Some(&bob), &deleg)).unwrap_err().contains("revoked"));
    }

    #[test]
    fn snapshots() {
        let (app, alice, bob) = setup();
        let (carol, dave) = (key(3), key(4));
        grant_anyone(&app, &alice, "/doc");
        let doc = sign(&bob, "/doc", "doc", doc_data("", vec![Who::User(id(&carol))]).to_cbor(), None, 1);
        put(&app, &doc).unwrap();
        let u1 = doc_update(&bob, &doc, "/doc", b"u1");
        let u2 = doc_update(&carol, &doc, "/doc", b"u2");
        let u3 = doc_update(&bob, &doc, "/doc", b"u3");
        for u in [&u1, &u2, &u3] {
            put(&app, u).unwrap();
        }
        let snapshot = |k: &SigningKey, covers: &[&Record], version: u64| {
            let data = DocSnapshotData { doc: doc.hash(), state: b"state".to_vec(), covers: covers.iter().map(|r| r.hash()).collect() };
            sign(k, "/doc", "doc_snapshot", data.to_cbor(), None, version)
        };
        let s1 = snapshot(&carol, &[&u1, &u2], 5);
        put(&app, &s1).expect("an editor's snapshot");
        let older = snapshot(&bob, &[&u1], 4);
        put(&app, &older).unwrap();
        let err = put(&app, &snapshot(&dave, &[&u1], 9)).unwrap_err();
        assert!(err.contains("author and editors"), "{err}");
        // A non-editor's newer snapshot, pushed by a peer, is stored but never served in place of updates.
        let sneaky = snapshot(&dave, &[&u1, &u2, &u3], 9);
        pushed(&app, &sneaky);
        let u4 = doc_update(&bob, &doc, "/doc", b"u4");
        put(&app, &u4).unwrap();
        let err = put(&app, &tombstone(&carol, &s1, 6)).unwrap_err();
        assert!(err.contains("never edited or deleted"), "{err}");

        let db = app.db.lock().unwrap();
        let f = StreamFilter { doc: Some(doc.hash()), prefix: None };
        let hashes = |rows: Vec<(i64, Vec<u8>)>| -> Vec<Hash> { rows.iter().map(|(_, b)| Sha256::digest(b).into()).collect() };
        assert_eq!(hashes(stored_after(&db, &f, 0)).len(), 8, "everything, without compacting");
        assert_eq!(hashes(compact(&db, &doc.hash(), stored_after(&db, &f, 0))), [doc.hash(), u3.hash(), s1.hash(), u4.hash()]);
    }

    // ---- private mode ----

    /// A private node with an owner, alice, serving the web app; and alice, bob and carol.
    fn private_node() -> (Arc<App>, Router, SigningKey, SigningKey, SigningKey) {
        let app = Arc::new(node_in_mode(true));
        let alice = key(1);
        app.write(&app.db.lock().unwrap(), OWNER_PATH, "owner", Who::User(id(&alice)).to_cbor(), None);
        (app.clone(), router(app, true), alice, key(2), key(3))
    }

    /// Sends a request through the whole router, with these headers and (JSON) body.
    async fn send(router: &Router, method: Method, path: &str, headers: &[(header::HeaderName, &str)], json: Option<Value>) -> Response {
        use tower::ServiceExt;
        let mut req = axum::http::Request::builder().method(method).uri(path);
        for (k, v) in headers {
            req = req.header(k, *v);
        }
        let body = match json {
            Some(j) => {
                req = req.header(header::CONTENT_TYPE, "application/json");
                axum::body::Body::from(j.to_string())
            }
            None => axum::body::Body::empty(),
        };
        router.clone().oneshot(req.body(body).unwrap()).await.unwrap()
    }

    /// `key`'s access token for a node whose web app is at `origin`, good for an hour, as `/api/auth` takes it.
    fn access_token(key: &SigningKey, origin: &str, claim: Option<&str>) -> Value {
        let expires = now_ms() + 60 * 60 * 1000;
        let sig = key.sign(&access_signed_bytes(origin, expires)).to_bytes();
        json!({ "user": encode_id(&id(key)), "expires": expires, "signature": encode_b58(&sig), "claim": claim })
    }

    /// Signs in as `key`: the response, and the cookie header to send back, if it set one.
    async fn sign_in(router: &Router, key: &SigningKey, claim: Option<&str>) -> (StatusCode, Option<String>) {
        let res = send(router, Method::POST, "/api/auth", &[], Some(access_token(key, "http://web.test", claim))).await;
        let cookie = res.headers().get(header::SET_COOKIE).map(|c| c.to_str().unwrap().split(';').next().unwrap().to_string());
        (res.status(), cookie)
    }

    async fn status_with(router: &Router, path: &str, cookie: &str) -> StatusCode {
        send(router, Method::GET, path, &[(header::COOKIE, cookie)], None).await.status()
    }

    #[tokio::test]
    async fn private_mode_hides_everything_but_sign_in() {
        let (_, router, ..) = private_node();
        let page = send(&router, Method::GET, "/some/page", &[(header::ACCEPT, "text/html,*/*")], None).await;
        assert_eq!(page.status(), StatusCode::UNAUTHORIZED, "page loads get the sign-in page");
        assert_eq!(page.headers().get(header::CACHE_CONTROL).unwrap(), "no-store");
        for path in ["/", "/api/node", "/api/records", "/api/users", "/api/stream", "/sw.js", "/assets/index.js", "/nope"] {
            let res = send(&router, Method::GET, path, &[], None).await;
            assert_eq!(res.status(), StatusCode::NOT_FOUND, "{path}");
            assert!(body(res).await.is_empty(), "{path} says nothing");
        }
        for path in ["/api/records", "/api/claim", "/receive"] {
            assert_eq!(send(&router, Method::POST, path, &[], Some(json!({}))).await.status(), StatusCode::NOT_FOUND, "{path}");
        }
        assert_eq!(status_with(&router, "/api/node", "bb_access=junk").await, StatusCode::NOT_FOUND);
    }

    #[tokio::test]
    async fn owners_and_access_holders_get_in() {
        let (app, router, alice, bob, _) = private_node();
        let (status, cookie) = sign_in(&router, &bob, None).await;
        assert_eq!((status, cookie), (StatusCode::FORBIDDEN, None), "no access yet");

        let (status, alice_cookie) = sign_in(&router, &alice, None).await;
        assert_eq!(status, StatusCode::NO_CONTENT);
        let alice_cookie = alice_cookie.expect("an owner gets a cookie");
        assert_eq!(status_with(&router, "/api/node", &alice_cookie).await, StatusCode::OK);
        assert_eq!(status_with(&router, "/api/records", &alice_cookie).await, StatusCode::OK);

        let access = sign(&alice, ACCESS_PATH, "access", Who::User(id(&bob)).to_cbor(), None, 1);
        put(&app, &access).unwrap();
        let (status, bob_cookie) = sign_in(&router, &bob, None).await;
        assert_eq!(status, StatusCode::NO_CONTENT);
        let bob_cookie = bob_cookie.unwrap();
        assert_eq!(status_with(&router, "/api/node", &bob_cookie).await, StatusCode::OK);

        // Revoking access shuts the cookie out on the next request: there's no session to end.
        put(&app, &tombstone(&alice, &access, 2)).unwrap();
        assert_eq!(status_with(&router, "/api/node", &bob_cookie).await, StatusCode::NOT_FOUND);
        assert_eq!(status_with(&router, "/api/node", &alice_cookie).await, StatusCode::OK);

        // Only owners write access records.
        let err = put(&app, &sign(&bob, ACCESS_PATH, "access", Who::User(id(&bob)).to_cbor(), None, 3)).unwrap_err();
        assert!(err.contains("owners"), "{err}");
    }

    #[tokio::test]
    async fn access_tokens_are_checked() {
        let (_, router, alice, ..) = private_node();
        let auth = |token: Value| send(&router, Method::POST, "/api/auth", &[], Some(token));
        assert_eq!(auth(access_token(&alice, "http://elsewhere.test", None)).await.status(), StatusCode::BAD_REQUEST, "another origin's");
        let mut forged = access_token(&alice, "http://web.test", None);
        forged["expires"] = json!(forged["expires"].as_u64().unwrap() + 1);
        assert_eq!(auth(forged).await.status(), StatusCode::BAD_REQUEST, "signature doesn't match");
        let expires = now_ms() + MAX_ACCESS_TOKEN_MS + 60_000;
        let sig = alice.sign(&access_signed_bytes("http://web.test", expires)).to_bytes();
        let too_long = json!({ "user": encode_id(&id(&alice)), "expires": expires, "signature": encode_b58(&sig) });
        assert_eq!(auth(too_long).await.status(), StatusCode::BAD_REQUEST, "expires too far ahead");

        let (_, cookie) = sign_in(&router, &alice, None).await;
        let cookie = cookie.unwrap();
        assert_eq!(status_with(&router, "/api/node", &format!("other=1; {cookie}")).await, StatusCode::OK, "found among others");
        let res = send(&router, Method::DELETE, "/api/auth", &[], None).await;
        assert!(res.headers().get(header::SET_COOKIE).unwrap().to_str().unwrap().contains("Max-Age=0"), "signing out clears it");
    }

    #[tokio::test]
    async fn claim_links_let_in() {
        let (app, router, alice, bob, carol) = private_node();
        let (claim, link) = app.new_claim(&app.db.lock().unwrap(), "http://web.test", None);
        let token = link.split_once('#').unwrap().1.to_string();
        // A claim that doesn't give access stays unclaimed: it's for whoever it was meant for.
        let (status, _) = sign_in(&router, &bob, Some(&token)).await;
        assert_eq!(status, StatusCode::FORBIDDEN);
        assert_eq!(claimed_by(&app.db.lock().unwrap(), &claim), None);

        put(&app, &sign(&alice, ACCESS_PATH, "access", Who::Claim(claim).to_cbor(), None, 1)).unwrap();
        let (status, cookie) = sign_in(&router, &bob, Some(&token)).await;
        assert_eq!(status, StatusCode::NO_CONTENT);
        assert_eq!(claimed_by(&app.db.lock().unwrap(), &claim), Some(id(&bob)));
        assert_eq!(status_with(&router, "/api/node", &cookie.unwrap()).await, StatusCode::OK);
        // It works once.
        assert_eq!(sign_in(&router, &carol, Some(&token)).await.0, StatusCode::FORBIDDEN);
    }

    #[tokio::test]
    async fn first_owner_claims_a_private_node() {
        let app = Arc::new(node_in_mode(true));
        let router = router(app.clone(), true);
        let (_, link) = {
            let db = app.db.lock().unwrap();
            let (_, head) = heads_of(&db, "claim").pop().unwrap();
            app.new_claim(&db, "http://web.test", Some(head.hash()))
        };
        let token = link.split_once('#').unwrap().1;
        let alice = key(1);
        assert_eq!(sign_in(&router, &alice, Some(token)).await.0, StatusCode::NO_CONTENT);
        assert_eq!(owners(&app.db.lock().unwrap()), [id(&alice)]);
    }

    #[tokio::test]
    async fn hardening() {
        let (app, router, alice, bob, _) = private_node();
        let res = send(&router, Method::GET, "/nope", &[], None).await;
        assert_eq!(res.headers().get(header::X_FRAME_OPTIONS).unwrap(), "DENY", "even the gate's answers");
        assert_eq!(res.headers().get(header::X_CONTENT_TYPE_OPTIONS).unwrap(), "nosniff");

        let mut big = access_token(&alice, "http://web.test", None);
        big["claim"] = json!("x".repeat(MAX_AUTH_BYTES));
        assert_eq!(send(&router, Method::POST, "/api/auth", &[], Some(big)).await.status(), StatusCode::PAYLOAD_TOO_LARGE);

        // What streams and live rooms check: access that lapses, by removal or expiry.
        let access = sign(&alice, ACCESS_PATH, "access", Who::User(id(&bob)).to_cbor(), None, 1);
        put(&app, &access).unwrap();
        let bobs = Access { user: id(&bob), expires: now_ms() + 60_000 };
        assert!(app.still_in(&bobs));
        assert!(!app.still_in(&Access { expires: now_ms() - 1, ..bobs }), "expired");
        put(&app, &tombstone(&alice, &access, 2)).unwrap();
        assert!(!app.still_in(&bobs), "removed");
    }

    #[tokio::test]
    async fn public_mode_has_no_gate() {
        let app = Arc::new(node());
        let router = router(app, true);
        assert_eq!(send(&router, Method::GET, "/api/node", &[], None).await.status(), StatusCode::OK);
        assert_eq!(sign_in(&router, &key(1), None).await.0, StatusCode::NOT_FOUND);
    }
}
