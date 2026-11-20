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

pub use dcbor::{CBOR, CBORCase, Map};

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
//                         or one of the node types below
//   data       any        the content, per `type`
//   edits      bytes(32)? the hash of the version this one edits (or, for a tombstone, deletes): the
//                         newest one its author saw. Edits keep the type but may change the path
//   signature  bytes(64)  author's Ed25519 signature over `RECORD_CONTEXT || CBOR(the record
//                         without this field)`
//
// Any other fields are kept (the signature covers them) but otherwise ignored.
//
// A record is identified by its hash: SHA-256 of its CBOR, signature included. Records never change;
// an edit is a new record. A record and its edits form a chain, named by its first record's hash.
// The chain's current version is its newest (by version, then by hash), unless any version in it is
// a tombstone: then it's deleted.

/// Prefixed to the bytes of each kind of signature, so one can never pass for another.
pub const RECORD_CONTEXT: &[u8] = b"bisonbase-record-v2\n";

pub const MAX_PATH_BYTES: usize = 1024;

pub type Hash = [u8; 32];

#[derive(Clone, Debug, PartialEq)]
pub struct Record {
    pub author: Pubkey,
    pub path: String,
    pub version: u64,
    pub kind: String,
    pub data: CBOR,
    pub edits: Option<Hash>,
    pub signature: [u8; 64],
    /// Fields this version doesn't know about.
    pub extra: Map,
}

const RECORD_FIELDS: [&str; 7] = ["author", "path", "version", "type", "data", "edits", "signature"];

// ---- nodes ----
//
// Each node has its own key. Its own records live under /node, and are never federated:
//
//   /node/info   type "node", data {url}: written by the node itself
//   /node/owner  type "owner", data a `Who`: one per owner
//   /node/grant  type "grant" (see `GrantData`): lets users write at or under a path
//   /node/peer   type "peer" (see `PeerData`): has the node push records to another node
//   /node/claim  type "claim" (see `ClaimData`): a one-time link, for a user nobody knows yet
//
// Owners write all of these (except /node/info) and may write anything, anywhere. Others need a grant
// covering the path, except to edit or delete their own records. A node checks all of that when a
// record is written to it, against its own /node records; records pushed by peers are taken as they are.
//
// Owner and grant records name users directly, or name a claim: then they're for whoever claims it.
// A claim holds the SHA-256 of a random token; the token itself only travels in the claim link. Whoever
// opens the link signs `claim_signed_bytes` with it, and the node then writes a new version of the claim
// naming them. On a fresh database the node writes a claim and an owner record naming it, and prints the
// link: that's how a node gets its first owner.

pub const NODE_PATH: &str = "/node";
pub const NODE_INFO_PATH: &str = "/node/info";
pub const OWNER_PATH: &str = "/node/owner";
pub const GRANT_PATH: &str = "/node/grant";
pub const PEER_PATH: &str = "/node/peer";
pub const CLAIM_PATH: &str = "/node/claim";

pub const CLAIM_CONTEXT: &[u8] = b"bisonbase-claim-v2\n";

/// The bytes a user signs to claim a claim on `node`, with the token from its link.
pub fn claim_signed_bytes(node: &Pubkey, token: &[u8]) -> Vec<u8> {
    let mut m = Map::new();
    m.insert("node", CBOR::to_byte_string(node));
    m.insert("token", CBOR::to_byte_string(token));
    [CLAIM_CONTEXT, &CBOR::from(m).to_cbor_data()].concat()
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
        "claim" => CLAIM_PATH,
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
        m
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
        match node_type_path(&self.kind) {
            Some(p) if self.path != p => return Err(format!("a {} record belongs at {p}", self.kind)),
            None if self.kind != "tombstone" && self.is_node_record() => {
                return Err(format!("{NODE_PATH} is for the node's own records, not {:?}", self.kind));
            }
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
            _ => return Err(format!("unknown record type {:?}", self.kind)),
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
            signature: [0; 64],
            extra: Map::new(),
        };
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
        assert_eq!(ClaimData::from_cbor(&c.to_cbor()).unwrap(), c);
        let claimed = ClaimData { user: Some([2; 32]), ..c.clone() };
        let r = signed(&key, CLAIM_PATH, "claim", claimed.to_cbor(), None);
        r.check().unwrap();
        assert_eq!(r.claim(), Some(claimed));
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
