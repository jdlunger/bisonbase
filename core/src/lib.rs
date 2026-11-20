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

/// A server's nickname instead: "server_" and the phrase's first word.
pub fn server_phrase(pk: &Pubkey) -> String {
    format!("server_{}", WORDS[pick(pk, 0, WORDS.len())])
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
//   author         bytes(32)  Ed25519 public key of whoever wrote and signed it
//   owner          bytes(32)  whose space it lives in; may differ from the author (see `authorization`)
//   path           text       where in the owner's space, e.g. "/posts/hello" (see `check_path`);
//                             written bb://<owner, base58><path> at the edges
//   version        uint       ms since the epoch, by the author's clock; per (owner, path), the newest wins
//   type           text       what `data` holds: "post" (data: text), "tombstone" (data: null, a
//                             delete), "grant" (see `GrantData`), or one of the server types below
//   data           any        the content, per `type`
//   authorization  map?       required iff author != owner: {path, signature}, the owner's signature
//                             (see `grant_signed_bytes`) letting the author write at or under `path`;
//                             the owner also keeps it as a "grant" record, by default under /grants
//   signature      bytes(64)  author's Ed25519 signature over `RECORD_CONTEXT || CBOR(the record
//                             without this field)`
//
// Any other fields are kept (the signature covers them) but otherwise ignored. Records are
// identified by (owner, path).

/// Prefixed to the bytes of each kind of signature, so one can never pass for another.
pub const RECORD_CONTEXT: &[u8] = b"bisonbase-record-v1\n";
pub const GRANT_CONTEXT: &[u8] = b"bisonbase-grant-v1\n";

pub const MAX_PATH_BYTES: usize = 1024;

#[derive(Clone, Debug, PartialEq)]
pub struct Record {
    pub author: Pubkey,
    pub owner: Pubkey,
    pub path: String,
    pub version: u64,
    pub kind: String,
    pub data: CBOR,
    pub authorization: Option<Authorization>,
    pub signature: [u8; 64],
    /// Fields this version doesn't know about.
    pub extra: Map,
}

const RECORD_FIELDS: [&str; 8] = ["author", "owner", "path", "version", "type", "data", "authorization", "signature"];

/// The owner's permission for the record's author to write at or under `path`.
#[derive(Clone, Debug, PartialEq)]
pub struct Authorization {
    pub path: String,
    pub signature: [u8; 64],
}

/// A "grant" record's data: the owner (who must also be the record's author) lets `grantee` write
/// at or under `path` in their space. `signature` is what the grantee's records carry as their
/// `authorization`.
#[derive(Clone, Debug, PartialEq)]
pub struct GrantData {
    pub grantee: Pubkey,
    pub path: String,
    pub signature: [u8; 64],
}

impl GrantData {
    pub fn from_cbor(v: &CBOR) -> Result<Self, String> {
        let m = as_map(v, "a grant's data")?;
        Ok(GrantData { grantee: field(m, "grantee", bytes)?, path: field(m, "path", text)?, signature: field(m, "signature", bytes)? })
    }

    pub fn to_cbor(&self) -> CBOR {
        let mut m = Map::new();
        m.insert("grantee", CBOR::to_byte_string(self.grantee));
        m.insert("path", self.path.as_str());
        m.insert("signature", CBOR::to_byte_string(self.signature));
        m.into()
    }
}

/// The bytes an owner signs to let `author` write at or under `path` in their space.
pub fn grant_signed_bytes(author: &Pubkey, owner: &Pubkey, path: &str) -> Vec<u8> {
    let mut m = Map::new();
    m.insert("author", CBOR::to_byte_string(author));
    m.insert("owner", CBOR::to_byte_string(owner));
    m.insert("path", path);
    [GRANT_CONTEXT, &CBOR::from(m).to_cbor_data()].concat()
}

// ---- servers and federation ----
//
// Each server has its own key, and these records in its space:
//
//   /server          type "server", data {url}: self-signed; marks the key as a server's
//   /owner           type "owner", data {user: bytes(32)}: self-signed when someone claims the server
//                    with its one-time link (see `claim_signed_bytes`); the server also grants them /federate
//   /federate/<ID>   type "federate" (see `FederateData`): push records to the server with that ID.
//                    Written by the owner under that grant, and never pushed themselves

pub const CLAIM_CONTEXT: &[u8] = b"bisonbase-claim-v1\n";

/// The bytes a user signs to claim `server`, with the token from its one-time claim link.
pub fn claim_signed_bytes(server: &Pubkey, token: &[u8]) -> Vec<u8> {
    let mut m = Map::new();
    m.insert("server", CBOR::to_byte_string(server));
    m.insert("token", CBOR::to_byte_string(token));
    [CLAIM_CONTEXT, &CBOR::from(m).to_cbor_data()].concat()
}

/// The peer a federate record's path names: /federate/<ID>.
pub fn federate_peer(path: &str) -> Option<Pubkey> {
    decode_id(path.strip_prefix("/federate/")?)
}

/// Which records go to a peer: everything at or under `path` ("/" for all of it), in `owner`'s space, or
/// in every space if None. Written bb://<owner, base58 or *><path> at the edges.
#[derive(Clone, Debug, PartialEq)]
pub struct PathFilter {
    pub owner: Option<Pubkey>,
    pub path: String,
}

impl PathFilter {
    /// Parses bb://<ID or *><path>, where a bare "/" means the whole space.
    pub fn parse(s: &str) -> Result<Self, String> {
        let bad = || format!("{s} isn't bb://<ID or *>/<path>");
        let rest = s.strip_prefix("bb://").ok_or_else(bad)?;
        let (owner, path) = rest.split_at(rest.find('/').ok_or_else(bad)?);
        let owner = if owner == "*" { None } else { Some(decode_id(owner).ok_or_else(bad)?) };
        if path != "/" {
            check_path(path)?;
        }
        Ok(PathFilter { owner, path: path.into() })
    }

    pub fn matches(&self, owner: &Pubkey, path: &str) -> bool {
        self.owner.is_none_or(|o| &o == owner) && (self.path == "/" || path_within(path, &self.path))
    }
}

impl std::fmt::Display for PathFilter {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        let owner = self.owner.as_ref().map_or("*".into(), encode_id);
        write!(f, "bb://{owner}{}", self.path)
    }
}

/// A "federate" record's data: push records to the server at `url`, if their type is in `types` and
/// they match one of `paths`. Either missing means all. Tombstones always pass the type filter, so
/// deletes follow what they delete.
#[derive(Clone, Debug, PartialEq)]
pub struct FederateData {
    pub url: String,
    pub types: Option<Vec<String>>,
    pub paths: Option<Vec<PathFilter>>,
}

fn check_url(url: &str) -> Result<(), String> {
    if !(url.starts_with("http://") || url.starts_with("https://")) || url.chars().any(char::is_whitespace) {
        return Err("url must be an http:// or https:// URL".into());
    }
    Ok(())
}

impl FederateData {
    pub fn from_cbor(v: &CBOR) -> Result<Self, String> {
        let m = as_map(v, "a federate record's data")?;
        let list = |v: &CBOR| v.as_array().map(<[CBOR]>::to_vec);
        let types = opt_field(m, "types", list)?
            .map(|a| a.iter().map(|t| text(t).ok_or("types must be text")).collect::<Result<Vec<_>, _>>())
            .transpose()?;
        let paths = opt_field(m, "paths", list)?
            .map(|a| {
                a.iter()
                    .map(|p| {
                        let p = as_map(p, "paths")?;
                        let f = PathFilter { owner: opt_field(p, "owner", bytes)?, path: field(p, "path", text)? };
                        if f.path != "/" {
                            check_path(&f.path)?;
                        }
                        Ok(f)
                    })
                    .collect::<Result<Vec<_>, String>>()
            })
            .transpose()?;
        let d = FederateData { url: field(m, "url", text)?, types, paths };
        check_url(&d.url)?;
        Ok(d)
    }

    pub fn to_cbor(&self) -> CBOR {
        let mut m = Map::new();
        m.insert("url", self.url.as_str());
        if let Some(t) = &self.types {
            m.insert("types", t.clone());
        }
        if let Some(p) = &self.paths {
            let p: Vec<CBOR> = p
                .iter()
                .map(|f| {
                    let mut m = Map::new();
                    m.insert("path", f.path.as_str());
                    if let Some(o) = f.owner {
                        m.insert("owner", CBOR::to_byte_string(o));
                    }
                    m.into()
                })
                .collect();
            m.insert("paths", p);
        }
        m.into()
    }

    /// Whether a record of type `kind` at (`owner`, `path`) goes to this peer.
    pub fn wants(&self, owner: &Pubkey, path: &str, kind: &str) -> bool {
        (kind == "tombstone" || self.types.as_ref().is_none_or(|t| t.iter().any(|t| t == kind)))
            && self.paths.as_ref().is_none_or(|p| p.iter().any(|f| f.matches(owner, path)))
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

/// A record's address as shown at the edges: bb://<owner, base58><path>.
pub fn encode_uri(owner: &Pubkey, path: &str) -> String {
    format!("bb://{}{path}", encode_id(owner))
}

/// Parses a bb:// address into (owner, path).
pub fn decode_uri(uri: &str) -> Result<(Pubkey, String), String> {
    let rest = uri.strip_prefix("bb://").ok_or("an address starts with bb://")?;
    let (owner, path) = rest.split_at(rest.find('/').ok_or("an address needs a path after the owner")?);
    let owner = decode_id(owner).ok_or("an address's owner isn't an ID (32 bytes of base58)")?;
    check_path(path)?;
    Ok((owner, path.into()))
}

/// Whether `path` is `prefix` or below it, by whole segments ("/a/b" is under "/a", not under "/a/b2").
pub fn path_within(path: &str, prefix: &str) -> bool {
    path.strip_prefix(prefix).is_some_and(|rest| rest.is_empty() || rest.starts_with('/'))
}

pub fn verify_sig(pk: &Pubkey, msg: &[u8], sig: &[u8; 64]) -> Result<(), String> {
    let pk = VerifyingKey::from_bytes(pk).map_err(|_| "not a valid Ed25519 public key")?;
    pk.verify_strict(msg, &Signature::from_bytes(sig)).map_err(|_| "signature doesn't match".into())
}

impl Record {
    fn unsigned_map(&self) -> Map {
        let mut m = self.extra.clone();
        m.insert("author", CBOR::to_byte_string(self.author));
        m.insert("owner", CBOR::to_byte_string(self.owner));
        m.insert("path", self.path.as_str());
        m.insert("version", self.version);
        m.insert("type", self.kind.as_str());
        m.insert("data", self.data.clone());
        if let Some(a) = &self.authorization {
            let mut am = Map::new();
            am.insert("path", a.path.as_str());
            am.insert("signature", CBOR::to_byte_string(a.signature));
            m.insert("authorization", am);
        }
        m
    }

    /// A server record's URL.
    pub fn server_url(&self) -> Option<String> {
        let m = self.data.as_map().filter(|_| self.kind == "server")?;
        field(m, "url", text).ok()
    }

    /// An owner record's user: who claimed the server.
    pub fn owner_user(&self) -> Option<Pubkey> {
        let m = self.data.as_map().filter(|_| self.kind == "owner")?;
        field(m, "user", bytes).ok()
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

    /// Parses a record's structure. Doesn't check its contents or signatures: see `check`.
    pub fn from_cbor(v: &CBOR) -> Result<Self, String> {
        let m = as_map(v, "a record")?;
        let authorization = opt_field(m, "authorization", |v| {
            let a = v.as_map()?;
            Some(Authorization { path: field(a, "path", text).ok()?, signature: field(a, "signature", bytes).ok()? })
        })?;
        let mut extra = Map::new();
        for (k, v) in m.iter() {
            if !k.as_text().is_some_and(|k| RECORD_FIELDS.contains(&k)) {
                extra.insert(k.clone(), v.clone());
            }
        }
        Ok(Record {
            author: field(m, "author", bytes)?,
            owner: field(m, "owner", bytes)?,
            path: field(m, "path", text)?,
            version: field(m, "version", |v| u64::try_from(v.clone()).ok())?,
            kind: field(m, "type", text)?,
            data: field(m, "data", |v| Some(v.clone()))?,
            authorization,
            signature: field(m, "signature", bytes)?,
            extra,
        })
    }

    pub fn from_bytes(b: &[u8]) -> Result<Self, String> {
        Self::from_cbor(&CBOR::try_from_data(b).map_err(|e| format!("CBOR: {e}"))?)
    }

    /// Checks everything that doesn't depend on other records: the path, that `data` fits `type`,
    /// the authorization, and the author's signature.
    pub fn check(&self) -> Result<(), String> {
        check_path(&self.path)?;
        match self.kind.as_str() {
            "tombstone" if !self.data.is_null() => return Err("a tombstone's data must be null".into()),
            "tombstone" => {}
            "post" => match self.data.as_text() {
                Some(t) if !t.is_empty() && t.trim() == t => {}
                _ => return Err("a post's data must be non-empty, trimmed text".into()),
            },
            "grant" => {
                if self.author != self.owner {
                    return Err("only the owner can grant access to their space".into());
                }
                let g = GrantData::from_cbor(&self.data)?;
                check_path(&g.path).map_err(|e| format!("grant: {e}"))?;
                verify_sig(&self.owner, &grant_signed_bytes(&g.grantee, &self.owner, &g.path), &g.signature)
                    .map_err(|e| format!("grant: {e}"))?;
            }
            "server" | "owner" if self.author != self.owner => {
                return Err(format!("only a server can write its {} record", self.kind));
            }
            "server" => {
                if self.path != "/server" {
                    return Err("a server record belongs at /server".into());
                }
                check_url(&field(as_map(&self.data, "a server record's data")?, "url", text)?)?;
            }
            "owner" => {
                if self.path != "/owner" {
                    return Err("an owner record belongs at /owner".into());
                }
                field(as_map(&self.data, "an owner record's data")?, "user", bytes::<32>)?;
            }
            "federate" => {
                federate_peer(&self.path).ok_or("a federate record belongs at /federate/<server ID>")?;
                FederateData::from_cbor(&self.data)?;
            }
            _ => return Err(format!("unknown record type {:?}", self.kind)),
        }
        match (&self.authorization, self.author == self.owner) {
            (None, true) => {}
            (Some(_), true) => return Err("owners don't need an authorization in their own space".into()),
            (None, false) => return Err("writing in someone else's space needs their authorization".into()),
            (Some(a), false) => {
                check_path(&a.path).map_err(|e| format!("authorization: {e}"))?;
                if !path_within(&self.path, &a.path) {
                    return Err(format!("the authorization only covers {}", a.path));
                }
                verify_sig(&self.owner, &grant_signed_bytes(&self.author, &self.owner, &a.path), &a.signature)
                    .map_err(|e| format!("authorization: {e}"))?;
            }
        }
        verify_sig(&self.author, &self.signed_bytes(), &self.signature)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn paths() {
        assert!(check_path("/a/b c/ü").is_ok());
        for bad in ["", "/", "a", "/a/", "/a//b", "/a/../b", "/a/\n"] {
            assert!(check_path(bad).is_err(), "{bad:?}");
        }
        assert!(path_within("/a/b", "/a") && path_within("/a", "/a") && !path_within("/ab", "/a"));
    }

    #[test]
    fn record_signing_and_grants() {
        use ed25519_dalek::{Signer, SigningKey};
        let owner = SigningKey::from_bytes(&[1; 32]);
        let author = SigningKey::from_bytes(&[2; 32]);
        let (o, a) = (owner.verifying_key().to_bytes(), author.verifying_key().to_bytes());
        let grant_sig = owner.sign(&grant_signed_bytes(&a, &o, "/shared")).to_bytes();
        let mut r = Record {
            author: a,
            owner: o,
            path: "/shared/x".into(),
            version: 1,
            kind: "post".into(),
            data: "hi".into(),
            authorization: Some(Authorization { path: "/shared".into(), signature: grant_sig }),
            signature: [0; 64],
            extra: Map::new(),
        };
        r.signature = author.sign(&r.signed_bytes()).to_bytes();
        let back = Record::from_bytes(&r.to_bytes()).unwrap();
        assert_eq!(back, r);
        back.check().unwrap();

        // Unknown fields survive a round trip, and the signature covers them.
        let mut x = r.clone();
        x.extra.insert("future", 1);
        x.signature = author.sign(&x.signed_bytes()).to_bytes();
        let back = Record::from_bytes(&x.to_bytes()).unwrap();
        assert_eq!(back, x);
        back.check().unwrap();

        let mut g = Record {
            author: o,
            owner: o,
            path: "/grants/1".into(),
            version: 1,
            kind: "grant".into(),
            data: GrantData { grantee: a, path: "/shared".into(), signature: grant_sig }.to_cbor(),
            authorization: None,
            signature: [0; 64],
            extra: Map::new(),
        };
        g.signature = owner.sign(&g.signed_bytes()).to_bytes();
        g.check().unwrap();

        let mut outside = r.clone();
        outside.path = "/sharedx".into();
        outside.signature = author.sign(&outside.signed_bytes()).to_bytes();
        assert!(outside.check().is_err());
    }

    #[test]
    fn federate_filters() {
        let (a, b) = ([1; 32], [2; 32]);
        let all = FederateData { url: "http://x".into(), types: None, paths: None };
        assert_eq!(FederateData::from_cbor(&all.to_cbor()).unwrap(), all);
        assert!(all.wants(&a, "/anything", "post"));
        let some = FederateData {
            url: "http://x".into(),
            types: Some(vec!["post".into()]),
            paths: Some(vec![PathFilter { owner: None, path: "/pub".into() }, PathFilter { owner: Some(b), path: "/".into() }]),
        };
        assert_eq!(FederateData::from_cbor(&some.to_cbor()).unwrap(), some);
        assert!(some.wants(&a, "/pub/x", "post") && some.wants(&b, "/x", "post"));
        assert!(some.wants(&a, "/pub/x", "tombstone"), "deletes follow");
        assert!(!some.wants(&a, "/pubx", "post") && !some.wants(&a, "/pub/x", "grant"));
        assert!(FederateData::from_cbor(&FederateData { url: "ftp://x".into(), ..all }.to_cbor()).is_err());
        assert_eq!(federate_peer(&format!("/federate/{}", encode_id(&a))), Some(a));
        assert_eq!(federate_peer("/federate/x/y"), None);
        for f in ["bb://*/", "bb://*/pub", &format!("bb://{}/x/y", encode_id(&b))] {
            assert_eq!(PathFilter::parse(f).unwrap().to_string(), f);
        }
        assert!(PathFilter::parse("bb://nope/x").is_err() && PathFilter::parse("bb://*").is_err());
    }
}
