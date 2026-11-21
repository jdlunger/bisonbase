//! Record format, IDs and checks, shared by the server (src/main.rs) and the web client (via wasm/).

use ed25519_dalek::{Signature, VerifyingKey};
use sha2::{Digest, Sha256};
use std::sync::LazyLock;

// ---- user IDs ----
//
// A user's ID is their raw 32-byte Ed25519 public key, and that's what gets stored. base58 (Bitcoin
// alphabet: letters and digits only, so a double-click selects it all) and the word phrase are only
// for showing, typing and passing it around.

pub type Pubkey = [u8; 32];

/// The ID as shown to people and used in URLs and the API.
pub fn encode_id(pk: &Pubkey) -> String {
    encode_b58(pk)
}

/// Any bytes in base58, e.g. random path segments.
pub fn encode_b58(b: &[u8]) -> String {
    bs58::encode(b).into_string()
}

/// Bytes from base58, e.g. a record's hash; None if it isn't base58.
pub fn decode_b58(s: &str) -> Option<Vec<u8>> {
    bs58::decode(s).into_vec().ok()
}

/// Parses a base58 ID; None unless it's exactly 32 bytes.
pub fn decode_id(s: &str) -> Option<Pubkey> {
    bs58::decode(s).into_vec().ok()?.try_into().ok()
}

static WORDS: LazyLock<Vec<&'static str>> = LazyLock::new(|| {
    include_str!("../../google-10000-english-usa-no-swears.txt")
        .lines()
        .map(str::trim)
        .filter(|w| !w.is_empty())
        .collect()
});

static EMOJI: LazyLock<Vec<&'static str>> = LazyLock::new(|| {
    include_str!("../../emoji.txt").lines().map(str::trim).filter(|e| !e.is_empty()).collect()
});

/// The u32 at byte `i` of SHA-256(`b`), mod `n`.
fn pick(b: &[u8], i: usize, n: usize) -> usize {
    let h = Sha256::digest(b);
    u32::from_be_bytes(h[i..i + 4].try_into().unwrap()) as usize % n
}

/// "two_words" from SHA-256 of `b`: its first two u32s pick the words. Also names passkeys, from their
/// user handle.
pub fn two_words(b: &[u8]) -> String {
    [0, 4].map(|i| WORDS[pick(b, i, WORDS.len())]).join("_")
}

/// A readable "🦬two_words" nickname for an ID, from SHA-256 of its raw bytes: two u32s pick the words, the
/// third the emoji. Not unique enough to identify anyone.
pub fn phrase(pk: &Pubkey) -> String {
    format!("{}{}", EMOJI[pick(pk, 8, EMOJI.len())], two_words(pk))
}

/// A node's nickname instead: "node_" and the phrase's first word.
pub fn node_phrase(pk: &Pubkey) -> String {
    format!("node_{}", WORDS[pick(pk, 0, WORDS.len())])
}

// ---- CBOR ----
//
// Records are passed around and stored as dCBOR (deterministic CBOR, see the `dcbor` crate), so the
// bytes a signature covers can always be rebuilt from the decoded value. Fields and values we don't
// recognize are ignored, not rejected.

pub use dcbor::{CBOR, CBORCase, Map, Simple};

fn bytes<const N: usize>(v: &CBOR) -> Option<[u8; N]> {
    v.as_byte_string()?.try_into().ok()
}

fn text(v: &CBOR) -> Option<String> {
    v.as_text().map(Into::into)
}

/// Field `k` of `m`, converted with `f`.
fn field<T>(m: &Map, k: &str, f: impl FnOnce(&CBOR) -> Option<T>) -> Result<T, String> {
    m.get::<_, CBOR>(k).as_ref().and_then(f).ok_or_else(|| format!("missing or malformed field {k:?}"))
}

fn opt_field<T>(m: &Map, k: &str, f: impl FnOnce(&CBOR) -> Option<T>) -> Result<Option<T>, String> {
    m.get::<_, CBOR>(k).map(|v| f(&v).ok_or_else(|| format!("malformed field {k:?}"))).transpose()
}

fn as_map<'a>(v: &'a CBOR, what: &str) -> Result<&'a Map, String> {
    v.as_map().ok_or_else(|| format!("{what} must be a map"))
}

// ---- records ----
//
// Everything users write is a record: a CBOR map, signed by its author.
//
//   author     bytes(32)  Ed25519 public key of whoever wrote and signed it
//   path       text       a category to find it by, e.g. "/post/dogs" (see `check_path`). Not unique:
//                         any number of records share a path
//   version    uint       ms since the epoch, by the author's clock
//   type       text       what `data` holds: "post" (data: text), "tombstone" (data: null, a delete),
//                         "claim" (see `ClaimData`), "doc" / "doc_update" / "doc_snapshot" (see
//                         "shared documents"), "delegate" / "enckey" (see "user spaces"), one of the
//                         node types below, or an app's own type (see "app types")
//   data       any        the content, per `type`
//   edits      bytes(32)? the hash of the version this one edits (or, for a tombstone, deletes): the
//                         newest one its author saw. Edits keep the type but may change the path
//   private    bool       if true, only the node's owners may read it, and it's never federated. Edits
//                         may change it; a chain is private if its current version is
//   as         map?       {user: bytes(32), delegation: bytes(32)}: the author signs for `user`, under
//                         the "delegate" chain (by its first record's hash) where `user` let the
//                         author's key do so (see "user spaces"). The record then counts as `user`'s:
//                         its principal. Without it, the author is the principal
//   signature  bytes(64)  author's Ed25519 signature over `RECORD_CONTEXT || CBOR(the record
//                         without this field)`
//
// Any other fields are kept (the signature covers them) but otherwise ignored. A record is at most
// MAX_RECORD_BYTES.
//
// A record is identified by its hash: SHA-256 of its CBOR, signature included. Records never change;
// an edit is a new record. A record and its edits form a chain, named by its first record's hash.
// The chain's current version is its newest (by version, then by hash), unless any version in it is
// a tombstone: then it's deleted.

/// Prefixed to the bytes of each kind of signature, so one can never pass for another.
pub const RECORD_CONTEXT: &[u8] = b"bisonbase-record-v2\n";

pub const MAX_PATH_BYTES: usize = 1024;

/// The largest record, as CBOR, signature included.
pub const MAX_RECORD_BYTES: usize = 1024 * 1024;

pub type Hash = [u8; 32];

#[derive(Clone, Debug, PartialEq)]
pub struct Record {
    pub author: Pubkey,
    pub path: String,
    pub version: u64,
    pub kind: String,
    pub data: CBOR,
    pub edits: Option<Hash>,
    pub private: bool,
    pub acting: Option<Acting>,
    pub signature: [u8; 64],
    /// Fields this version doesn't know about.
    pub extra: Map,
}

/// A record's `as`: its author signs for `user`, under `user`'s "delegate" chain `delegation`.
#[derive(Clone, Debug, PartialEq)]
pub struct Acting {
    pub user: Pubkey,
    pub delegation: Hash,
}

impl Acting {
    pub fn from_cbor(v: &CBOR) -> Result<Self, String> {
        let m = as_map(v, "as")?;
        Ok(Acting { user: field(m, "user", bytes)?, delegation: field(m, "delegation", bytes)? })
    }

    pub fn to_cbor(&self) -> CBOR {
        let mut m = Map::new();
        m.insert("user", CBOR::to_byte_string(self.user));
        m.insert("delegation", CBOR::to_byte_string(self.delegation));
        m.into()
    }
}

const RECORD_FIELDS: [&str; 9] = ["author", "path", "version", "type", "data", "edits", "private", "as", "signature"];

// ---- app types ----
//
// Apps write records of their own types, with any data: nodes check nothing about it but its size. An
// app type's name is namespaced: it has a "." (e.g. "todo.item", "com.example.board"), which no type
// nodes know ever has. Doc schemas (see "shared documents") are named the same way.

/// Names of app types, doc schemas and formats: 1 to MAX_NAME_BYTES of a-z, 0-9, ".", "-" and "_".
pub const MAX_NAME_BYTES: usize = 64;

pub fn check_name(name: &str, what: &str) -> Result<(), String> {
    if name.is_empty() || name.len() > MAX_NAME_BYTES {
        return Err(format!("{what} must be 1 to {MAX_NAME_BYTES} bytes"));
    }
    if !name.bytes().all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b"._-".contains(&b)) {
        return Err(format!("{what} may only have a-z, 0-9, \".\", \"-\" and \"_\""));
    }
    Ok(())
}

/// Whether `kind` is an app's type: namespaced, with a ".".
pub fn is_app_type(kind: &str) -> bool {
    kind.contains('.')
}

/// Checks a namespaced name: an app type or a doc schema.
pub fn check_app_name(name: &str, what: &str) -> Result<(), String> {
    check_name(name, what)?;
    if !is_app_type(name) || name.split('.').any(str::is_empty) {
        return Err(format!("{what} must be namespaced, with a \".\" between names (e.g. \"myapp.thing\")"));
    }
    Ok(())
}

// ---- user spaces ----
//
// Each user has a space, /u/<their ID>: only they (or the node's owners) may write there, given a grant
// covering it, as anywhere. Two of their records live at fixed paths in it, and they always sign those
// themselves, never under `as`:
//
//   /u/<ID>/delegate  type "delegate" (see `DelegateData`): lets another key, e.g. an app's, sign records
//                     for them, with `as`. A chain per key; deleting it revokes it. Readers then stop
//                     trusting anything that key signed for them, as it may have leaked
//   /u/<ID>/key       type "enckey" (see `EncKeyData`): their X25519 public key, for sealing encrypted
//                     docs' keys to them

pub const USER_SPACE: &str = "/u";

/// A user's space: /u/<their ID>.
pub fn user_path(pk: &Pubkey) -> String {
    format!("{USER_SPACE}/{}", encode_id(pk))
}

/// Whose space `path` is in, if it's in one.
pub fn path_user(path: &str) -> Option<Pubkey> {
    let rest = path.strip_prefix(USER_SPACE)?.strip_prefix('/')?;
    decode_id(rest.split('/').next()?)
}

pub fn delegate_path(pk: &Pubkey) -> String {
    format!("{}/delegate", user_path(pk))
}

pub fn enckey_path(pk: &Pubkey) -> String {
    format!("{}/key", user_path(pk))
}

/// A "delegate" record's data: lets `key` sign records for its author, at or under one of `paths`, of one
/// of `types` (either missing: any), until `expires` (ms since the epoch; missing: no end). `name` says
/// who `key` is, e.g. an app's name. Never for records under /node, nor for the user's own
/// delegate and enckey records.
#[derive(Clone, Debug, PartialEq)]
pub struct DelegateData {
    pub key: Pubkey,
    pub name: String,
    pub paths: Option<Vec<String>>,
    pub types: Option<Vec<String>>,
    pub expires: Option<u64>,
}

impl DelegateData {
    pub fn from_cbor(v: &CBOR) -> Result<Self, String> {
        let m = as_map(v, "a delegation's data")?;
        let d = DelegateData {
            key: field(m, "key", bytes)?,
            name: field(m, "name", text)?,
            paths: opt_field(m, "paths", text_list)?,
            types: opt_field(m, "types", text_list)?,
            expires: opt_field(m, "expires", |v| u64::try_from(v.clone()).ok())?,
        };
        if d.name.trim() != d.name || d.name.len() > 200 {
            return Err("a delegation's name must be trimmed, and at most 200 bytes".into());
        }
        for p in d.paths.iter().flatten() {
            check_prefix(p)?;
        }
        Ok(d)
    }

    pub fn to_cbor(&self) -> CBOR {
        let mut m = Map::new();
        m.insert("key", CBOR::to_byte_string(self.key));
        m.insert("name", self.name.as_str());
        if let Some(p) = &self.paths {
            m.insert("paths", p.clone());
        }
        if let Some(t) = &self.types {
            m.insert("types", t.clone());
        }
        if let Some(e) = self.expires {
            m.insert("expires", e);
        }
        m.into()
    }

    /// Whether this lets its key sign a record of type `kind` at `path`, at time `at` (ms since the epoch).
    /// Tombstones go wherever the key may write.
    pub fn covers(&self, path: &str, kind: &str, at: u64) -> bool {
        self.expires.is_none_or(|e| at <= e)
            && (kind == "tombstone" || self.types.as_ref().is_none_or(|t| t.iter().any(|t| t == kind)))
            && self.paths.as_ref().is_none_or(|p| p.iter().any(|p| path_within(path, p)))
    }
}

/// An "enckey" record's data: its author's X25519 public key.
#[derive(Clone, Debug, PartialEq)]
pub struct EncKeyData {
    pub key: [u8; 32],
}

impl EncKeyData {
    pub fn from_cbor(v: &CBOR) -> Result<Self, String> {
        Ok(EncKeyData { key: field(as_map(v, "an enckey's data")?, "key", bytes)? })
    }

    pub fn to_cbor(&self) -> CBOR {
        let mut m = Map::new();
        m.insert("key", CBOR::to_byte_string(self.key));
        m.into()
    }
}

// ---- nodes ----
//
// Each node has its own key. Its own records live under /node, and are never federated:
//
//   /node/info   type "node", data {url}: written by the node itself
//   /node/owner  type "owner", data a `Who`: one per owner
//   /node/grant  type "grant" (see `GrantData`): lets users write at or under a path
//   /node/peer   type "peer" (see `PeerData`): has the node push records to another node
//
// Owners write all of these (except /node/info) and may write anything, anywhere. Others need a grant
// covering the path, except to edit or delete their own records. A node checks all of that when a
// record is written to it, against its own /node records; records pushed by peers are taken as they are.
//
// Owner, grant and doc records name users directly, or name a claim: then they're for whoever claims
// it. A claim (type "claim", at any path: the node's own go under /node/claim) holds the SHA-256 of a
// random token; the token itself only travels in the claim link. Whoever opens the link signs
// `claim_signed_bytes` with it, and the node then writes a new version of the claim naming them. Claims
// are never federated: they only mean something on the node that holds the token's hash. On a fresh
// database the node writes a claim and an owner record naming it, and prints the link: that's how a
// node gets its first owner.

pub const NODE_PATH: &str = "/node";
pub const NODE_INFO_PATH: &str = "/node/info";
pub const OWNER_PATH: &str = "/node/owner";
pub const GRANT_PATH: &str = "/node/grant";
pub const PEER_PATH: &str = "/node/peer";
/// Where the node's own claims go, and owners' by default. Others' claims may go anywhere they may write.
pub const CLAIM_PATH: &str = "/node/claim";

pub const CLAIM_CONTEXT: &[u8] = b"bisonbase-claim-v2\n";

/// The bytes a user signs to claim a claim on `node`, with the token from its link.
pub fn claim_signed_bytes(node: &Pubkey, token: &[u8]) -> Vec<u8> {
    let mut m = Map::new();
    m.insert("node", CBOR::to_byte_string(node));
    m.insert("token", CBOR::to_byte_string(token));
    [CLAIM_CONTEXT, &CBOR::from(m).to_cbor_data()].concat()
}

// ---- reading private records ----
//
// The node has no sessions. To read private records, an owner sends a read token with their requests:
// their ID, an expiry, and their signature over `read_signed_bytes`. It's good on that node only, until
// it expires.

pub const READ_CONTEXT: &[u8] = b"bisonbase-read-v1\n";

/// How far ahead of the node's clock a read token's expiry may be.
pub const MAX_READ_TOKEN_MS: u64 = 60 * 60 * 1000;

/// The bytes a user signs to read `node`'s private records until `expires` (ms since the epoch).
pub fn read_signed_bytes(node: &Pubkey, expires: u64) -> Vec<u8> {
    let mut m = Map::new();
    m.insert("node", CBOR::to_byte_string(node));
    m.insert("expires", expires);
    [READ_CONTEXT, &CBOR::from(m).to_cbor_data()].concat()
}

// ---- live presence in a doc ----
//
// Editors of a doc can join its live room on a node, to see each other's cursors. Nothing said there is
// stored. To join, an editor signs `live_signed_bytes`: good for that doc, on that node, until it expires.

pub const LIVE_CONTEXT: &[u8] = b"bisonbase-live-v1\n";

/// The bytes a user signs to join the live room of `doc` (its chain's first record's hash) on `node`,
/// until `expires` (ms since the epoch; at most MAX_READ_TOKEN_MS ahead).
pub fn live_signed_bytes(node: &Pubkey, doc: &Hash, expires: u64) -> Vec<u8> {
    let mut m = Map::new();
    m.insert("node", CBOR::to_byte_string(node));
    m.insert("doc", CBOR::to_byte_string(doc));
    m.insert("expires", expires);
    [LIVE_CONTEXT, &CBOR::from(m).to_cbor_data()].concat()
}

/// A user, as owner and grant records name them: {user: their ID}, or {claim: the hash of a claim
/// chain's first record}, for whoever claims it.
#[derive(Clone, Debug, PartialEq)]
pub enum Who {
    User(Pubkey),
    Claim(Hash),
}

impl Who {
    pub fn from_cbor(v: &CBOR) -> Result<Self, String> {
        let m = as_map(v, "a user reference")?;
        match (opt_field(m, "user", bytes)?, opt_field(m, "claim", bytes)?) {
            (Some(u), None) => Ok(Who::User(u)),
            (None, Some(c)) => Ok(Who::Claim(c)),
            _ => Err("a user reference is {user: ID} or {claim: hash}".into()),
        }
    }

    pub fn to_cbor(&self) -> CBOR {
        let mut m = Map::new();
        match self {
            Who::User(u) => m.insert("user", CBOR::to_byte_string(u)),
            Who::Claim(c) => m.insert("claim", CBOR::to_byte_string(c)),
        }
        m.into()
    }

    /// The user this names, given who claimed what (claim hash → its user, if claimed).
    pub fn resolve(&self, claimed: impl Fn(&Hash) -> Option<Pubkey>) -> Option<Pubkey> {
        match self {
            Who::User(u) => Some(*u),
            Who::Claim(c) => claimed(c),
        }
    }
}

/// Who a grant lets write.
#[derive(Clone, Debug, PartialEq)]
pub enum Grantees {
    Anyone,
    Some(Vec<Who>),
}

/// A "grant" record's data: lets `grantees` write at or under `path` ("/" for everywhere).
#[derive(Clone, Debug, PartialEq)]
pub struct GrantData {
    pub path: String,
    pub grantees: Grantees,
}

impl GrantData {
    pub fn from_cbor(v: &CBOR) -> Result<Self, String> {
        let m = as_map(v, "a grant's data")?;
        let grantees = match m.get::<_, CBOR>("grantees") {
            Some(g) if g.as_text() == Some("anyone") => Grantees::Anyone,
            Some(g) => Grantees::Some(
                g.as_array()
                    .ok_or("grantees must be \"anyone\" or a list of user references")?
                    .iter()
                    .map(Who::from_cbor)
                    .collect::<Result<_, _>>()?,
            ),
            None => return Err("missing field \"grantees\"".into()),
        };
        let g = GrantData { path: field(m, "path", text)?, grantees };
        check_prefix(&g.path)?;
        Ok(g)
    }

    pub fn to_cbor(&self) -> CBOR {
        let mut m = Map::new();
        m.insert("path", self.path.as_str());
        match &self.grantees {
            Grantees::Anyone => m.insert("grantees", "anyone"),
            Grantees::Some(w) => m.insert("grantees", w.iter().map(Who::to_cbor).collect::<Vec<_>>()),
        }
        m.into()
    }

    /// Whether this lets `author` write at `path`, given who claimed what (see `Who::resolve`).
    pub fn covers(&self, author: &Pubkey, path: &str, claimed: impl Fn(&Hash) -> Option<Pubkey>) -> bool {
        path_within(path, &self.path)
            && match &self.grantees {
                Grantees::Anyone => true,
                Grantees::Some(w) => w.iter().any(|w| w.resolve(&claimed).as_ref() == Some(author)),
            }
    }
}

/// A "claim" record's data: the SHA-256 of its link's token, and once claimed (by the node only), who
/// claimed it.
#[derive(Clone, Debug, PartialEq)]
pub struct ClaimData {
    pub token_hash: Hash,
    pub user: Option<Pubkey>,
}

impl ClaimData {
    pub fn from_cbor(v: &CBOR) -> Result<Self, String> {
        let m = as_map(v, "a claim's data")?;
        Ok(ClaimData { token_hash: field(m, "token_hash", bytes)?, user: opt_field(m, "user", bytes)? })
    }

    pub fn to_cbor(&self) -> CBOR {
        let mut m = Map::new();
        m.insert("token_hash", CBOR::to_byte_string(self.token_hash));
        if let Some(u) = self.user {
            m.insert("user", CBOR::to_byte_string(u));
        }
        m.into()
    }
}

/// A "peer" record's data: push records to `node` at `url`, if their type is in `types` and they're
/// at or under one of `paths`. Either missing means all. Tombstones always pass the type filter, so
/// deletes follow what they delete.
#[derive(Clone, Debug, PartialEq)]
pub struct PeerData {
    pub node: Pubkey,
    pub url: String,
    pub types: Option<Vec<String>>,
    pub paths: Option<Vec<String>>,
}

fn check_url(url: &str) -> Result<(), String> {
    if !(url.starts_with("http://") || url.starts_with("https://")) || url.chars().any(char::is_whitespace) {
        return Err("url must be an http:// or https:// URL".into());
    }
    Ok(())
}

fn text_list(v: &CBOR) -> Option<Vec<String>> {
    v.as_array()?.iter().map(text).collect()
}

impl PeerData {
    pub fn from_cbor(v: &CBOR) -> Result<Self, String> {
        let m = as_map(v, "a peer record's data")?;
        let d = PeerData {
            node: field(m, "node", bytes)?,
            url: field(m, "url", text)?,
            types: opt_field(m, "types", text_list)?,
            paths: opt_field(m, "paths", text_list)?,
        };
        check_url(&d.url)?;
        for p in d.paths.iter().flatten() {
            check_prefix(p)?;
        }
        Ok(d)
    }

    pub fn to_cbor(&self) -> CBOR {
        let mut m = Map::new();
        m.insert("node", CBOR::to_byte_string(self.node));
        m.insert("url", self.url.as_str());
        if let Some(t) = &self.types {
            m.insert("types", t.clone());
        }
        if let Some(p) = &self.paths {
            m.insert("paths", p.clone());
        }
        m.into()
    }

    /// Whether a record of type `kind` at `path` goes to this peer.
    pub fn wants(&self, path: &str, kind: &str) -> bool {
        (kind == "tombstone" || self.types.as_ref().is_none_or(|t| t.iter().any(|t| t == kind)))
            && self.paths.as_ref().is_none_or(|p| p.iter().any(|p| path_within(path, p)))
    }
}

// ---- shared documents ----
//
// A document is a "doc" chain, named by its first record's hash. Its data holds the title, who may
// edit it besides its author, and what it holds: its `format`, the CRDT library its content is in (e.g.
// "yjs", "automerge"), and its `schema`, what an app keeps in that (namespaced, e.g. "bisonbase.markdown").
// Only the author (or the node's owners) edits the doc record, as with any chain, and never its format,
// schema, or whether it's encrypted. Nodes never look inside the content: it's built from "doc_update"
// records, each a signed batch of the format's updates naming its doc. Updates merge in any order and
// any number of times, so they arrive however federation brings them. They're never edited or deleted;
// deleting the doc deletes them all.
//
// A "doc_snapshot" is the doc's whole content as of some updates, which it names (`covers`): readers
// can start from it, then apply just the updates it doesn't cover. Snapshots are written like updates,
// and trusted like them: an editor's snapshot could leave out what others wrote, but an editor's update
// could delete it too. Nodes keep every update all the same.
//
// An encrypted doc has `keys`: its content key, sealed to each user who may read it (its author and
// editors), with their "enckey". Updates and snapshots then hold that key's ciphertext. The title isn't
// encrypted. See client/src/crypto.ts.
//
// A node takes updates and snapshots from the doc's author, its editors and the node's owners, for a live
// doc, at the doc's current path. Readers check the authors themselves (see `DocData::may_edit`), as peers
// pass along records without checking who may write them. None of them is ever private: encrypt instead.

/// A doc's content key, sealed to `user`.
#[derive(Clone, Debug, PartialEq)]
pub struct SealedKey {
    pub user: Pubkey,
    pub sealed: Vec<u8>,
}

/// A "doc" record's data: its title, who may edit it besides its author, its content's format and
/// schema, and if it's encrypted, its key sealed to each reader.
#[derive(Clone, Debug, PartialEq)]
pub struct DocData {
    pub title: String,
    pub editors: Vec<Who>,
    pub format: String,
    pub schema: String,
    pub keys: Option<Vec<SealedKey>>,
}

impl DocData {
    pub fn from_cbor(v: &CBOR) -> Result<Self, String> {
        let m = as_map(v, "a doc's data")?;
        let keys = opt_field(m, "keys", |v| Some(v.as_array()?.to_vec()))?
            .map(|a| {
                a.iter()
                    .map(|k| {
                        let k = as_map(k, "a sealed key")?;
                        Ok(SealedKey { user: field(k, "user", bytes)?, sealed: field(k, "sealed", |v| v.as_byte_string().map(<[u8]>::to_vec))? })
                    })
                    .collect::<Result<Vec<_>, String>>()
            })
            .transpose()?;
        let d = DocData {
            title: field(m, "title", text)?,
            editors: field(m, "editors", |v| Some(v.as_array()?.to_vec()))?.iter().map(Who::from_cbor).collect::<Result<_, _>>()?,
            format: field(m, "format", text)?,
            schema: field(m, "schema", text)?,
            keys,
        };
        if d.title.trim() != d.title {
            return Err("a doc's title must be trimmed".into());
        }
        check_name(&d.format, "a doc's format")?;
        check_app_name(&d.schema, "a doc's schema")?;
        Ok(d)
    }

    pub fn to_cbor(&self) -> CBOR {
        let mut m = Map::new();
        m.insert("title", self.title.as_str());
        m.insert("editors", self.editors.iter().map(Who::to_cbor).collect::<Vec<_>>());
        m.insert("format", self.format.as_str());
        m.insert("schema", self.schema.as_str());
        if let Some(k) = &self.keys {
            let k: Vec<CBOR> = k
                .iter()
                .map(|k| {
                    let mut m = Map::new();
                    m.insert("user", CBOR::to_byte_string(k.user));
                    m.insert("sealed", CBOR::to_byte_string(&k.sealed));
                    m.into()
                })
                .collect();
            m.insert("keys", k);
        }
        m.into()
    }

    /// Whether `user` may write updates to the doc, which `author` started, given who claimed what (see
    /// `Who::resolve`). The node's owners may too; that's up to the node.
    pub fn may_edit(&self, author: &Pubkey, user: &Pubkey, claimed: impl Fn(&Hash) -> Option<Pubkey>) -> bool {
        author == user || self.editors.iter().any(|w| w.resolve(&claimed).as_ref() == Some(user))
    }
}

/// A "doc_snapshot" record's data: the doc (its chain's first record's hash), its whole content
/// (`state`, in its format), and the updates that has in it (by hash).
#[derive(Clone, Debug, PartialEq)]
pub struct DocSnapshotData {
    pub doc: Hash,
    pub state: Vec<u8>,
    pub covers: Vec<Hash>,
}

impl DocSnapshotData {
    pub fn from_cbor(v: &CBOR) -> Result<Self, String> {
        let m = as_map(v, "a doc snapshot's data")?;
        let covers = field(m, "covers", |v| v.as_byte_string().map(<[u8]>::to_vec))?;
        if covers.len() % 32 != 0 {
            return Err("a snapshot's covers must be 32-byte hashes, one after another".into());
        }
        let d = DocSnapshotData {
            doc: field(m, "doc", bytes)?,
            state: field(m, "state", |v| v.as_byte_string().map(<[u8]>::to_vec))?,
            covers: covers.chunks(32).map(|c| c.try_into().unwrap()).collect(),
        };
        if d.state.is_empty() {
            return Err("a doc snapshot can't be empty".into());
        }
        Ok(d)
    }

    pub fn to_cbor(&self) -> CBOR {
        let mut m = Map::new();
        m.insert("doc", CBOR::to_byte_string(self.doc));
        m.insert("state", CBOR::to_byte_string(&self.state));
        m.insert("covers", CBOR::to_byte_string(self.covers.concat()));
        m.into()
    }
}

/// A "doc_update" record's data: the doc (its chain's first record's hash), and an update to its content.
#[derive(Clone, Debug, PartialEq)]
pub struct DocUpdateData {
    pub doc: Hash,
    pub update: Vec<u8>,
}

impl DocUpdateData {
    pub fn from_cbor(v: &CBOR) -> Result<Self, String> {
        let m = as_map(v, "a doc update's data")?;
        let d = DocUpdateData { doc: field(m, "doc", bytes)?, update: field(m, "update", |v| v.as_byte_string().map(<[u8]>::to_vec))? };
        if d.update.is_empty() {
            return Err("a doc update can't be empty".into());
        }
        Ok(d)
    }

    pub fn to_cbor(&self) -> CBOR {
        let mut m = Map::new();
        m.insert("doc", CBOR::to_byte_string(self.doc));
        m.insert("update", CBOR::to_byte_string(&self.update));
        m.into()
    }
}

/// Paths: "/" then one or more "/"-separated segments. Segments are non-empty, not "." or "..",
/// and free of control characters; the whole is at most MAX_PATH_BYTES. Case matters. (Paths in
/// records are Unicode NFC, as all dCBOR text is.)
pub fn check_path(path: &str) -> Result<(), String> {
    let Some(rest) = path.strip_prefix('/') else {
        return Err("path must start with /".into());
    };
    if path.len() > MAX_PATH_BYTES {
        return Err(format!("path is longer than {MAX_PATH_BYTES} bytes"));
    }
    for seg in rest.split('/') {
        if seg.is_empty() {
            return Err("path has an empty segment (// or a trailing /)".into());
        }
        if seg == "." || seg == ".." {
            return Err("path segments can't be . or ..".into());
        }
        if seg.chars().any(char::is_control) {
            return Err("path has a control character".into());
        }
    }
    Ok(())
}

/// A path to match records at or under: a path, or "/" for all of them.
pub fn check_prefix(prefix: &str) -> Result<(), String> {
    if prefix == "/" { Ok(()) } else { check_path(prefix) }
}

/// Whether `path` is `prefix` or below it, by whole segments ("/a/b" is under "/a", not under "/a/b2").
/// Everything is under "/".
pub fn path_within(path: &str, prefix: &str) -> bool {
    prefix == "/" || path.strip_prefix(prefix).is_some_and(|rest| rest.is_empty() || rest.starts_with('/'))
}

pub fn verify_sig(pk: &Pubkey, msg: &[u8], sig: &[u8; 64]) -> Result<(), String> {
    let pk = VerifyingKey::from_bytes(pk).map_err(|_| "not a valid Ed25519 public key")?;
    pk.verify_strict(msg, &Signature::from_bytes(sig)).map_err(|_| "signature doesn't match".into())
}

/// The path each node type belongs at.
fn node_type_path(kind: &str) -> Option<&'static str> {
    Some(match kind {
        "node" => NODE_INFO_PATH,
        "owner" => OWNER_PATH,
        "grant" => GRANT_PATH,
        "peer" => PEER_PATH,
        _ => return None,
    })
}

impl Record {
    fn unsigned_map(&self) -> Map {
        let mut m = self.extra.clone();
        m.insert("author", CBOR::to_byte_string(self.author));
        m.insert("path", self.path.as_str());
        m.insert("version", self.version);
        m.insert("type", self.kind.as_str());
        m.insert("data", self.data.clone());
        if let Some(e) = self.edits {
            m.insert("edits", CBOR::to_byte_string(e));
        }
        m.insert("private", self.private);
        if let Some(a) = &self.acting {
            m.insert("as", a.to_cbor());
        }
        m
    }

    /// Whose record it is: the user it's signed for (see `as`), or else its author.
    pub fn principal(&self) -> Pubkey {
        self.acting.as_ref().map_or(self.author, |a| a.user)
    }

    /// A node record's URL.
    pub fn node_url(&self) -> Option<String> {
        let m = self.data.as_map().filter(|_| self.kind == "node")?;
        field(m, "url", text).ok()
    }

    /// An owner record's user.
    pub fn owner(&self) -> Option<Who> {
        (self.kind == "owner").then(|| Who::from_cbor(&self.data).ok()).flatten()
    }

    /// A claim record's data.
    pub fn claim(&self) -> Option<ClaimData> {
        (self.kind == "claim").then(|| ClaimData::from_cbor(&self.data).ok()).flatten()
    }

    /// A doc record's data.
    pub fn doc(&self) -> Option<DocData> {
        (self.kind == "doc").then(|| DocData::from_cbor(&self.data).ok()).flatten()
    }

    /// A doc update's data.
    pub fn doc_update(&self) -> Option<DocUpdateData> {
        (self.kind == "doc_update").then(|| DocUpdateData::from_cbor(&self.data).ok()).flatten()
    }

    /// A doc snapshot's data.
    pub fn doc_snapshot(&self) -> Option<DocSnapshotData> {
        (self.kind == "doc_snapshot").then(|| DocSnapshotData::from_cbor(&self.data).ok()).flatten()
    }

    /// For a doc update or snapshot: its doc (the doc chain's first record's hash).
    pub fn doc_ref(&self) -> Option<Hash> {
        self.doc_update().map(|u| u.doc).or_else(|| self.doc_snapshot().map(|s| s.doc))
    }

    /// A delegation's data.
    pub fn delegate(&self) -> Option<DelegateData> {
        (self.kind == "delegate").then(|| DelegateData::from_cbor(&self.data).ok()).flatten()
    }

    /// An enckey record's data.
    pub fn enckey(&self) -> Option<EncKeyData> {
        (self.kind == "enckey").then(|| EncKeyData::from_cbor(&self.data).ok()).flatten()
    }

    /// Whether it's one of a node's own records, which are never federated.
    pub fn is_node_record(&self) -> bool {
        path_within(&self.path, NODE_PATH)
    }

    /// The bytes the author signs.
    pub fn signed_bytes(&self) -> Vec<u8> {
        [RECORD_CONTEXT, &CBOR::from(self.unsigned_map()).to_cbor_data()].concat()
    }

    pub fn to_cbor(&self) -> CBOR {
        let mut m = self.unsigned_map();
        m.insert("signature", CBOR::to_byte_string(self.signature));
        m.into()
    }

    pub fn to_bytes(&self) -> Vec<u8> {
        self.to_cbor().to_cbor_data()
    }

    /// What identifies it: SHA-256 of its bytes, signature included.
    pub fn hash(&self) -> Hash {
        Sha256::digest(self.to_bytes()).into()
    }

    /// Parses a record's structure. Doesn't check its contents or signature: see `check`.
    pub fn from_cbor(v: &CBOR) -> Result<Self, String> {
        let m = as_map(v, "a record")?;
        let mut extra = Map::new();
        for (k, v) in m.iter() {
            if !k.as_text().is_some_and(|k| RECORD_FIELDS.contains(&k)) {
                extra.insert(k.clone(), v.clone());
            }
        }
        Ok(Record {
            author: field(m, "author", bytes)?,
            path: field(m, "path", text)?,
            version: field(m, "version", |v| u64::try_from(v.clone()).ok())?,
            kind: field(m, "type", text)?,
            data: field(m, "data", |v| Some(v.clone()))?,
            edits: opt_field(m, "edits", bytes)?,
            private: field(m, "private", CBOR::as_bool)?,
            acting: m.get::<_, CBOR>("as").map(|v| Acting::from_cbor(&v)).transpose()?,
            signature: field(m, "signature", bytes)?,
            extra,
        })
    }

    pub fn from_bytes(b: &[u8]) -> Result<Self, String> {
        Self::from_cbor(&CBOR::try_from_data(b).map_err(|e| format!("CBOR: {e}"))?)
    }

    /// Checks everything that doesn't depend on other records: the path, that `data` fits `type`, and
    /// the author's signature. Who may write what is up to each node (see "nodes" above).
    pub fn check(&self) -> Result<(), String> {
        check_path(&self.path)?;
        let size = self.to_bytes().len();
        if size > MAX_RECORD_BYTES {
            return Err(format!("a record can be at most {MAX_RECORD_BYTES} bytes, not {size}"));
        }
        match node_type_path(&self.kind) {
            Some(p) if self.path != p => return Err(format!("a {} record belongs at {p}", self.kind)),
            None if !["tombstone", "claim"].contains(&self.kind.as_str()) && self.is_node_record() => {
                return Err(format!("{NODE_PATH} is for the node's own records, not {:?}", self.kind));
            }
            _ => {}
        }
        let principal = self.principal();
        if let Some(a) = &self.acting {
            if a.user == self.author {
                return Err("a record signed for its own author doesn't need \"as\"".into());
            }
            if self.is_node_record() || ["delegate", "enckey"].contains(&self.kind.as_str()) {
                return Err(format!("a {} record is never signed under a delegation", self.kind));
            }
            if [delegate_path(&a.user), enckey_path(&a.user)].iter().any(|p| path_within(&self.path, p)) {
                return Err("a user's delegations and enckey are only theirs to change".into());
            }
        }
        match self.kind.as_str() {
            "delegate" if self.path != delegate_path(&principal) => {
                return Err(format!("a delegation belongs at its author's {}", delegate_path(&principal)));
            }
            "enckey" if self.path != enckey_path(&principal) => {
                return Err(format!("an enckey belongs at its author's {}", enckey_path(&principal)));
            }
            "doc" | "doc_update" | "doc_snapshot" if self.private => return Err(format!("a {} can't be private", self.kind)),
            "doc_update" | "doc_snapshot" if self.edits.is_some() => return Err(format!("a {} is never edited", self.kind)),
            _ => {}
        }
        match self.kind.as_str() {
            "tombstone" if !self.data.is_null() => return Err("a tombstone's data must be null".into()),
            "tombstone" if self.edits.is_none() => return Err("a tombstone needs to say what it deletes (edits)".into()),
            "tombstone" => {}
            "post" => match self.data.as_text() {
                Some(t) if !t.is_empty() && t.trim() == t => {}
                _ => return Err("a post's data must be non-empty, trimmed text".into()),
            },
            "grant" => {
                GrantData::from_cbor(&self.data).map_err(|e| format!("grant: {e}"))?;
            }
            "node" => check_url(&field(as_map(&self.data, "a node record's data")?, "url", text)?)?,
            "owner" => {
                Who::from_cbor(&self.data).map_err(|e| format!("owner: {e}"))?;
            }
            "peer" => {
                PeerData::from_cbor(&self.data)?;
            }
            "claim" => {
                ClaimData::from_cbor(&self.data)?;
            }
            "doc" => {
                DocData::from_cbor(&self.data).map_err(|e| format!("doc: {e}"))?;
            }
            "doc_update" => {
                DocUpdateData::from_cbor(&self.data)?;
            }
            "doc_snapshot" => {
                DocSnapshotData::from_cbor(&self.data)?;
            }
            "delegate" => {
                DelegateData::from_cbor(&self.data).map_err(|e| format!("delegate: {e}"))?;
            }
            "enckey" => {
                EncKeyData::from_cbor(&self.data)?;
            }
            k if is_app_type(k) => check_app_name(k, "an app type")?,
            _ => return Err(format!("unknown record type {:?} (an app's own types have a \".\", e.g. \"myapp.thing\")", self.kind)),
        }
        verify_sig(&self.author, &self.signed_bytes(), &self.signature)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ed25519_dalek::{Signer, SigningKey};

    fn signed(key: &SigningKey, path: &str, kind: &str, data: CBOR, edits: Option<Hash>) -> Record {
        let mut r = Record {
            author: key.verifying_key().to_bytes(),
            path: path.into(),
            version: 1,
            kind: kind.into(),
            data,
            edits,
            private: false,
            acting: None,
            signature: [0; 64],
            extra: Map::new(),
        };
        r.signature = key.sign(&r.signed_bytes()).to_bytes();
        r
    }

    fn resign(key: &SigningKey, mut r: Record) -> Record {
        r.signature = key.sign(&r.signed_bytes()).to_bytes();
        r
    }

    #[test]
    fn paths() {
        assert!(check_path("/a/b c/ü").is_ok());
        for bad in ["", "/", "a", "/a/", "/a//b", "/a/../b", "/a/\n"] {
            assert!(check_path(bad).is_err(), "{bad:?}");
        }
        assert!(check_prefix("/").is_ok());
        assert!(path_within("/a/b", "/a") && path_within("/a", "/a") && !path_within("/ab", "/a") && path_within("/a", "/"));
    }

    #[test]
    fn records() {
        let key = SigningKey::from_bytes(&[1; 32]);
        let r = signed(&key, "/post/dogs", "post", "hi".into(), None);
        let back = Record::from_bytes(&r.to_bytes()).unwrap();
        assert_eq!(back, r);
        assert_eq!(back.hash(), r.hash());
        back.check().unwrap();

        // Unknown fields survive a round trip, and the signature covers them.
        let mut x = r.clone();
        x.extra.insert("future", 1);
        x.signature = key.sign(&x.signed_bytes()).to_bytes();
        let back = Record::from_bytes(&x.to_bytes()).unwrap();
        assert_eq!(back, x);
        back.check().unwrap();
        assert_ne!(x.hash(), r.hash());

        let mut p = r.clone();
        p.private = true;
        p.signature = key.sign(&p.signed_bytes()).to_bytes();
        let back = Record::from_bytes(&p.to_bytes()).unwrap();
        assert!(back.private);
        back.check().unwrap();
        let mut flipped = p.clone();
        flipped.private = false;
        assert!(flipped.check().is_err(), "the signature covers it");

        let edit = signed(&key, "/post/cats", "post", "hello".into(), Some(r.hash()));
        assert_eq!(Record::from_bytes(&edit.to_bytes()).unwrap(), edit);
        edit.check().unwrap();
        signed(&key, "/post/dogs", "tombstone", CBOR::null(), Some(r.hash())).check().unwrap();
        assert!(signed(&key, "/post/dogs", "tombstone", CBOR::null(), None).check().is_err());

        let mut bad = r.clone();
        bad.data = "changed".into();
        assert!(bad.check().is_err());
    }

    #[test]
    fn node_records() {
        let key = SigningKey::from_bytes(&[1; 32]);
        let none = |_: &Hash| None;
        let g = GrantData { path: "/post".into(), grantees: Grantees::Some(vec![Who::User([2; 32]), Who::Claim([9; 32])]) };
        assert_eq!(GrantData::from_cbor(&g.to_cbor()).unwrap(), g);
        assert!(g.covers(&[2; 32], "/post/dogs", none) && !g.covers(&[3; 32], "/post", none) && !g.covers(&[2; 32], "/postx", none));
        assert!(g.covers(&[3; 32], "/post", |c: &Hash| (*c == [9; 32]).then_some([3; 32])), "via a claim");
        let anyone = GrantData { path: "/".into(), grantees: Grantees::Anyone };
        assert_eq!(GrantData::from_cbor(&anyone.to_cbor()).unwrap(), anyone);
        assert!(anyone.covers(&[3; 32], "/x", none));
        signed(&key, GRANT_PATH, "grant", g.to_cbor(), None).check().unwrap();
        assert!(signed(&key, "/grant", "grant", g.to_cbor(), None).check().is_err());
        assert!(signed(&key, "/node/x", "post", "hi".into(), None).check().is_err());

        let o = signed(&key, OWNER_PATH, "owner", Who::User([2; 32]).to_cbor(), None);
        o.check().unwrap();
        assert_eq!(o.owner(), Some(Who::User([2; 32])));
        assert!(o.is_node_record());
        let o = signed(&key, OWNER_PATH, "owner", Who::Claim([9; 32]).to_cbor(), None);
        assert_eq!(o.owner(), Some(Who::Claim([9; 32])));
        let mut both = Map::new();
        both.insert("user", CBOR::to_byte_string([2u8; 32]));
        both.insert("claim", CBOR::to_byte_string([9u8; 32]));
        assert!(signed(&key, OWNER_PATH, "owner", both.into(), None).check().is_err());

        let c = ClaimData { token_hash: [5; 32], user: None };
        signed(&key, "/doc", "claim", c.to_cbor(), None).check().expect("claims go anywhere");
        assert_eq!(ClaimData::from_cbor(&c.to_cbor()).unwrap(), c);
        let claimed = ClaimData { user: Some([2; 32]), ..c.clone() };
        let r = signed(&key, CLAIM_PATH, "claim", claimed.to_cbor(), None);
        r.check().unwrap();
        assert_eq!(r.claim(), Some(claimed));
    }

    fn doc_data(editors: Vec<Who>) -> DocData {
        DocData { title: "Notes".into(), editors, format: "yjs".into(), schema: "bisonbase.list".into(), keys: None }
    }

    #[test]
    fn docs() {
        let key = SigningKey::from_bytes(&[1; 32]);
        let d = doc_data(vec![Who::User([2; 32]), Who::Claim([9; 32])]);
        assert_eq!(DocData::from_cbor(&d.to_cbor()).unwrap(), d);
        let r = signed(&key, "/doc", "doc", d.to_cbor(), None);
        r.check().unwrap();
        assert_eq!(r.doc(), Some(d.clone()));
        let author = key.verifying_key().to_bytes();
        let none = |_: &Hash| None;
        assert!(d.may_edit(&author, &author, none) && d.may_edit(&author, &[2; 32], none) && !d.may_edit(&author, &[3; 32], none));
        assert!(d.may_edit(&author, &[3; 32], |c: &Hash| (*c == [9; 32]).then_some([3; 32])), "via a claim");
        assert!(signed(&key, "/doc", "doc", DocData { title: " x".into(), ..d.clone() }.to_cbor(), None).check().is_err());
        assert!(DocData::from_cbor(&DocData { schema: "list".into(), ..d.clone() }.to_cbor()).is_err(), "schemas are namespaced");
        assert!(DocData::from_cbor(&DocData { format: "Y JS".into(), ..d.clone() }.to_cbor()).is_err());
        DocData::from_cbor(&DocData { format: "automerge".into(), schema: "com.example.board".into(), ..d.clone() }.to_cbor())
            .expect("any format, any schema");
        let enc = DocData { keys: Some(vec![SealedKey { user: author, sealed: vec![1, 2, 3] }]), ..d.clone() };
        assert_eq!(DocData::from_cbor(&enc.to_cbor()).unwrap(), enc);

        let u = DocUpdateData { doc: r.hash(), update: vec![1, 2, 3] };
        assert_eq!(DocUpdateData::from_cbor(&u.to_cbor()).unwrap(), u);
        let ur = signed(&key, "/doc", "doc_update", u.to_cbor(), None);
        ur.check().unwrap();
        assert_eq!(ur.doc_update(), Some(u.clone()));
        assert_eq!(ur.doc_ref(), Some(r.hash()));
        assert!(signed(&key, "/doc", "doc_update", DocUpdateData { update: vec![], ..u.clone() }.to_cbor(), None).check().is_err());
        assert!(signed(&key, "/doc", "doc_update", u.to_cbor(), Some(ur.hash())).check().is_err(), "never edited");
        let p = resign(&key, Record { private: true, ..ur.clone() });
        assert!(p.check().is_err(), "never private");

        let s = DocSnapshotData { doc: r.hash(), state: vec![7], covers: vec![ur.hash(), [5; 32]] };
        assert_eq!(DocSnapshotData::from_cbor(&s.to_cbor()).unwrap(), s);
        let sr = signed(&key, "/doc", "doc_snapshot", s.to_cbor(), None);
        sr.check().unwrap();
        assert_eq!(sr.doc_ref(), Some(r.hash()));
        assert!(signed(&key, "/doc", "doc_snapshot", s.to_cbor(), Some(sr.hash())).check().is_err(), "never edited");
        let mut m = s.to_cbor().as_map().unwrap().clone();
        m.insert("covers", CBOR::to_byte_string([1u8; 33]));
        assert!(DocSnapshotData::from_cbor(&m.into()).is_err(), "covers are whole hashes");
    }

    #[test]
    fn app_types() {
        let key = SigningKey::from_bytes(&[1; 32]);
        let mut m = Map::new();
        m.insert("title", "buy milk");
        m.insert("done", false);
        signed(&key, "/todo", "todo.item", m.clone().into(), None).check().expect("any data");
        signed(&key, "/todo", "com.example.todo-item_2", CBOR::null(), None).check().unwrap();
        for bad in ["todo", "Todo.Item", "todo item.x", ".", &format!("{}.x", "a".repeat(64))] {
            assert!(signed(&key, "/todo", bad, CBOR::null(), None).check().is_err(), "{bad:?}");
        }
        let big = signed(&key, "/todo", "todo.blob", CBOR::to_byte_string(vec![0u8; MAX_RECORD_BYTES]), None);
        assert!(big.check().unwrap_err().contains("at most"));
    }

    #[test]
    fn user_spaces_and_delegation() {
        let user = SigningKey::from_bytes(&[1; 32]);
        let app = SigningKey::from_bytes(&[2; 32]);
        let (u, a) = (user.verifying_key().to_bytes(), app.verifying_key().to_bytes());
        assert_eq!(path_user(&format!("{}/notes/x", user_path(&u))), Some(u));
        assert_eq!(path_user(&user_path(&u)), Some(u));
        assert_eq!(path_user("/u"), None);
        assert_eq!(path_user("/doc"), None);

        let d = DelegateData { key: a, name: "Todo app".into(), paths: Some(vec!["/todo".into()]), types: Some(vec!["todo.item".into()]), expires: Some(100) };
        assert_eq!(DelegateData::from_cbor(&d.to_cbor()).unwrap(), d);
        let dr = signed(&user, &delegate_path(&u), "delegate", d.to_cbor(), None);
        dr.check().unwrap();
        assert_eq!(dr.delegate(), Some(d.clone()));
        assert!(signed(&user, "/delegate", "delegate", d.to_cbor(), None).check().is_err(), "at its author's path");
        assert!(signed(&app, &delegate_path(&u), "delegate", d.to_cbor(), None).check().is_err(), "in someone else's space");
        assert!(d.covers("/todo/x", "todo.item", 100) && d.covers("/todo", "tombstone", 1));
        assert!(!d.covers("/todo/x", "todo.item", 101) && !d.covers("/other", "todo.item", 1) && !d.covers("/todo", "post", 1));
        let any = DelegateData { paths: None, types: None, expires: None, ..d.clone() };
        assert!(any.covers("/anything", "post", u64::MAX));

        let e = signed(&user, &enckey_path(&u), "enckey", EncKeyData { key: [3; 32] }.to_cbor(), None);
        e.check().unwrap();
        assert_eq!(e.enckey(), Some(EncKeyData { key: [3; 32] }));

        // The app signs for the user.
        let acting = Some(Acting { user: u, delegation: dr.hash() });
        let mut item = Map::new();
        item.insert("title", "x");
        let r = resign(&app, Record { acting: acting.clone(), ..signed(&app, "/todo/1", "todo.item", item.into(), None) });
        let back = Record::from_bytes(&r.to_bytes()).unwrap();
        assert_eq!(back, r);
        back.check().unwrap();
        assert_eq!(back.principal(), u);
        assert_eq!(signed(&app, "/x", "post", "hi".into(), None).principal(), a);
        // Never for its own author, node records, or the user's delegations and enckey.
        let own = resign(&user, Record { acting: acting.clone(), ..signed(&user, "/todo/1", "post", "hi".into(), None) });
        assert!(own.check().is_err());
        for (path, kind, data) in [
            (delegate_path(&u), "delegate", d.to_cbor()),
            (enckey_path(&u), "enckey", EncKeyData { key: [4; 32] }.to_cbor()),
            (GRANT_PATH.to_string(), "grant", GrantData { path: "/".into(), grantees: Grantees::Anyone }.to_cbor()),
        ] {
            let r = resign(&app, Record { acting: acting.clone(), ..signed(&app, &path, kind, data, None) });
            assert!(r.check().is_err(), "{kind}");
        }
        let revoke = resign(&app, Record { acting: acting.clone(), ..signed(&app, &delegate_path(&u), "tombstone", CBOR::null(), Some(dr.hash())) });
        assert!(revoke.check().is_err(), "an app can't touch its delegation");
    }

    #[test]
    fn peer_filters() {
        let all = PeerData { node: [1; 32], url: "http://x".into(), types: None, paths: None };
        assert_eq!(PeerData::from_cbor(&all.to_cbor()).unwrap(), all);
        assert!(all.wants("/anything", "post"));
        let some = PeerData {
            node: [1; 32],
            url: "http://x".into(),
            types: Some(vec!["post".into()]),
            paths: Some(vec!["/pub".into(), "/b".into()]),
        };
        assert_eq!(PeerData::from_cbor(&some.to_cbor()).unwrap(), some);
        assert!(some.wants("/pub/x", "post") && some.wants("/b", "post"));
        assert!(some.wants("/pub/x", "tombstone"), "deletes follow");
        assert!(!some.wants("/pubx", "post") && !some.wants("/pub/x", "grant"));
        assert!(PeerData::from_cbor(&PeerData { url: "ftp://x".into(), ..all.clone() }.to_cbor()).is_err());
        assert!(PeerData::from_cbor(&PeerData { paths: Some(vec!["nope".into()]), ..all }.to_cbor()).is_err());
    }
}
