//! Record format, IDs and checks, used by the server.

use ed25519_dalek::{Signature, VerifyingKey};
use sha2::{Digest, Sha256};
use std::{collections::BTreeMap, sync::LazyLock};

// ---- user IDs ----
//
// A user's ID is their raw 32-byte Ed25519 public key, and that's what gets stored. base58 (Bitcoin
// alphabet: letters and digits only, so a double-click selects it all) and the word phrase are only
// for showing, typing and passing it around. Keep in sync with web/src/api.ts.

pub type Pubkey = [u8; 32];

/// The ID as shown to people and used in URLs and the API.
pub fn encode_id(pk: &Pubkey) -> String {
    bs58::encode(pk).into_string()
}

/// Parses a base58 ID; None unless it's exactly 32 bytes.
pub fn decode_id(s: &str) -> Option<Pubkey> {
    bs58::decode(s).into_vec().ok()?.try_into().ok()
}

static WORDS: LazyLock<Vec<&'static str>> = LazyLock::new(|| {
    include_str!("../google-10000-english-usa-no-swears.txt")
        .lines()
        .map(str::trim)
        .filter(|w| !w.is_empty())
        .collect()
});

static EMOJI: LazyLock<Vec<&'static str>> = LazyLock::new(|| {
    include_str!("../emoji.txt").lines().map(str::trim).filter(|e| !e.is_empty()).collect()
});

/// A readable "🦬two_words" nickname for an ID, from SHA-256 of its raw bytes: two u32s pick the words, the
/// third the emoji. Not unique enough to identify anyone.
pub fn phrase(pk: &Pubkey) -> String {
    let h = Sha256::digest(pk);
    let pick = |i: usize, n: usize| u32::from_be_bytes(h[i..i + 4].try_into().unwrap()) as usize % n;
    let words = [0, 4].map(|i| WORDS[pick(i, WORDS.len())]).join("_");
    format!("{}{words}", EMOJI[pick(8, EMOJI.len())])
}

// ---- deterministic CBOR (RFC 8949 §4.2.1 core deterministic encoding) ----
//
// Records are passed around and stored as CBOR in its one deterministic form, so the bytes a
// signature covers can always be rebuilt from the decoded value. Only a subset is supported:
// unsigned and negative integers, byte and text strings, arrays, maps with text keys, booleans and
// null; no floats, no tags, no indefinite lengths. The decoder rejects any non-deterministic
// encoding. Keep in sync with web/src/cbor.ts.

#[derive(Clone, Debug, PartialEq)]
pub enum Cbor {
    Uint(u64),
    /// -1 - n
    Neg(u64),
    Bytes(Vec<u8>),
    Text(String),
    Array(Vec<Cbor>),
    Map(BTreeMap<String, Cbor>),
    Bool(bool),
    Null,
}

fn put_head(out: &mut Vec<u8>, major: u8, n: u64) {
    let m = major << 5;
    match n {
        0..=23 => out.push(m | n as u8),
        24..=0xff => out.extend([m | 24, n as u8]),
        0x100..=0xffff => {
            out.push(m | 25);
            out.extend((n as u16).to_be_bytes())
        }
        0x1_0000..=0xffff_ffff => {
            out.push(m | 26);
            out.extend((n as u32).to_be_bytes())
        }
        _ => {
            out.push(m | 27);
            out.extend(n.to_be_bytes())
        }
    }
}

/// Deterministic map key order: by encoded bytes, which for text keys is by length, then bytewise.
fn key_order(a: &str, b: &str) -> std::cmp::Ordering {
    a.len().cmp(&b.len()).then(a.as_bytes().cmp(b.as_bytes()))
}

fn encode_into(v: &Cbor, out: &mut Vec<u8>) {
    match v {
        Cbor::Uint(n) => put_head(out, 0, *n),
        Cbor::Neg(n) => put_head(out, 1, *n),
        Cbor::Bytes(b) => {
            put_head(out, 2, b.len() as u64);
            out.extend(b)
        }
        Cbor::Text(s) => {
            put_head(out, 3, s.len() as u64);
            out.extend(s.as_bytes())
        }
        Cbor::Array(a) => {
            put_head(out, 4, a.len() as u64);
            a.iter().for_each(|v| encode_into(v, out))
        }
        Cbor::Map(m) => {
            put_head(out, 5, m.len() as u64);
            let mut keys: Vec<&String> = m.keys().collect();
            keys.sort_by(|a, b| key_order(a, b));
            for k in keys {
                encode_into(&Cbor::Text(k.clone()), out);
                encode_into(&m[k], out);
            }
        }
        Cbor::Bool(b) => out.push(if *b { 0xf5 } else { 0xf4 }),
        Cbor::Null => out.push(0xf6),
    }
}

/// Just the head of a CBOR item: its major type and argument (e.g. an array's length).
pub fn cbor_head(major: u8, n: u64) -> Vec<u8> {
    let mut out = Vec::new();
    put_head(&mut out, major, n);
    out
}

pub fn cbor_encode(v: &Cbor) -> Vec<u8> {
    let mut out = Vec::new();
    encode_into(v, &mut out);
    out
}

/// Decodes exactly one value, which must be deterministically encoded and fill all of `bytes`.
pub fn cbor_decode(bytes: &[u8]) -> Result<Cbor, String> {
    let mut b = bytes;
    let v = decode_value(&mut b, 0)?;
    if !b.is_empty() {
        return Err("CBOR: trailing bytes".into());
    }
    Ok(v)
}

fn take<'a>(b: &mut &'a [u8], n: u64) -> Result<&'a [u8], String> {
    if n > b.len() as u64 {
        return Err("CBOR: truncated".into());
    }
    let (head, rest) = b.split_at(n as usize);
    *b = rest;
    Ok(head)
}

/// The argument of a head with additional info `info`, which must be in its shortest form.
fn take_arg(b: &mut &[u8], info: u8) -> Result<u64, String> {
    let (n, min) = match info {
        0..=23 => return Ok(info as u64),
        24 => (take(b, 1)?[0] as u64, 24),
        25 => (u16::from_be_bytes(take(b, 2)?.try_into().unwrap()) as u64, 0x100),
        26 => (u32::from_be_bytes(take(b, 4)?.try_into().unwrap()) as u64, 0x1_0000),
        27 => (u64::from_be_bytes(take(b, 8)?.try_into().unwrap()), 0x1_0000_0000),
        _ => return Err("CBOR: indefinite lengths aren't allowed".into()),
    };
    if n < min {
        return Err("CBOR: not in shortest form".into());
    }
    Ok(n)
}

fn decode_value(b: &mut &[u8], depth: usize) -> Result<Cbor, String> {
    if depth > 32 {
        return Err("CBOR: nested too deeply".into());
    }
    let ib = take(b, 1)?[0];
    let (major, info) = (ib >> 5, ib & 0x1f);
    if major == 7 {
        return match info {
            20 => Ok(Cbor::Bool(false)),
            21 => Ok(Cbor::Bool(true)),
            22 => Ok(Cbor::Null),
            _ => Err("CBOR: only true, false and null simple values are allowed".into()),
        };
    }
    let n = take_arg(b, info)?;
    Ok(match major {
        0 => Cbor::Uint(n),
        1 => Cbor::Neg(n),
        2 => Cbor::Bytes(take(b, n)?.to_vec()),
        3 => Cbor::Text(String::from_utf8(take(b, n)?.to_vec()).map_err(|_| "CBOR: text isn't UTF-8")?),
        4 => Cbor::Array((0..n).map(|_| decode_value(b, depth + 1)).collect::<Result<_, _>>()?),
        5 => {
            let mut m = BTreeMap::new();
            let mut prev: Option<String> = None;
            for _ in 0..n {
                let Cbor::Text(k) = decode_value(b, depth + 1)? else {
                    return Err("CBOR: map keys must be text".into());
                };
                if prev.as_deref().is_some_and(|p| key_order(p, &k).is_ge()) {
                    return Err("CBOR: map keys out of order, or duplicated".into());
                }
                m.insert(k.clone(), decode_value(b, depth + 1)?);
                prev = Some(k);
            }
            Cbor::Map(m)
        }
        _ => return Err("CBOR: tags aren't allowed".into()),
    })
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
//                             delete), or "grant" (see `GrantData`)
//   data           any        the content, per `type`
//   authorization  map?       required iff author != owner: {path, signature}, the owner's signature
//                             (see `grant_signed_bytes`) letting the author write at or under `path`;
//                             the owner also keeps it as a "grant" record, by default under /grants
//   signature      bytes(64)  author's Ed25519 signature over `RECORD_CONTEXT || CBOR(the record
//                             without this field)`
//
// Records are identified by (owner, path). Keep in sync with web/src/api.ts.

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
    pub data: Cbor,
    pub authorization: Option<Authorization>,
    pub signature: [u8; 64],
}

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
    pub fn from_cbor(v: &Cbor) -> Result<Self, String> {
        let Cbor::Map(m) = v else { return Err("a grant's data must be a map".into()) };
        let mut m = m.clone();
        let g = GrantData {
            grantee: field(&mut m, "grantee", bytes)?,
            path: field(&mut m, "path", text)?,
            signature: field(&mut m, "signature", bytes)?,
        };
        no_more_fields(m)?;
        Ok(g)
    }

    pub fn to_cbor(&self) -> Cbor {
        Cbor::Map(BTreeMap::from([
            ("grantee".into(), Cbor::Bytes(self.grantee.to_vec())),
            ("path".into(), Cbor::Text(self.path.clone())),
            ("signature".into(), Cbor::Bytes(self.signature.to_vec())),
        ]))
    }
}

/// The bytes an owner signs to let `author` write at or under `path` in their space.
pub fn grant_signed_bytes(author: &Pubkey, owner: &Pubkey, path: &str) -> Vec<u8> {
    let m = BTreeMap::from([
        ("author".into(), Cbor::Bytes(author.to_vec())),
        ("owner".into(), Cbor::Bytes(owner.to_vec())),
        ("path".into(), Cbor::Text(path.into())),
    ]);
    [GRANT_CONTEXT, &cbor_encode(&Cbor::Map(m))].concat()
}

/// Paths: "/" then one or more "/"-separated segments. Segments are non-empty, not "." or "..",
/// and free of control characters; the whole is Unicode NFC and at most MAX_PATH_BYTES. Case matters.
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
    if !unicode_normalization::is_nfc(path) {
        return Err("path isn't Unicode NFC".into());
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

/// Takes field `k` out of `m`, converting it with `f`.
fn field<T>(m: &mut BTreeMap<String, Cbor>, k: &str, f: impl FnOnce(Cbor) -> Option<T>) -> Result<T, String> {
    m.remove(k).and_then(f).ok_or_else(|| format!("missing or malformed field {k:?}"))
}

fn opt_field<T>(m: &mut BTreeMap<String, Cbor>, k: &str, f: impl FnOnce(Cbor) -> Option<T>) -> Result<Option<T>, String> {
    m.remove(k).map(|v| f(v).ok_or_else(|| format!("malformed field {k:?}"))).transpose()
}

fn bytes<const N: usize>(v: Cbor) -> Option<[u8; N]> {
    match v {
        Cbor::Bytes(b) => b.try_into().ok(),
        _ => None,
    }
}

fn text(v: Cbor) -> Option<String> {
    match v {
        Cbor::Text(s) => Some(s),
        _ => None,
    }
}

fn no_more_fields(m: BTreeMap<String, Cbor>) -> Result<(), String> {
    match m.into_keys().next() {
        Some(k) => Err(format!("unknown field {k:?}")),
        None => Ok(()),
    }
}

impl Record {
    fn unsigned_map(&self) -> BTreeMap<String, Cbor> {
        let mut m = BTreeMap::from([
            ("author".into(), Cbor::Bytes(self.author.to_vec())),
            ("owner".into(), Cbor::Bytes(self.owner.to_vec())),
            ("path".into(), Cbor::Text(self.path.clone())),
            ("version".into(), Cbor::Uint(self.version)),
            ("type".into(), Cbor::Text(self.kind.clone())),
            ("data".into(), self.data.clone()),
        ]);
        if let Some(a) = &self.authorization {
            let a = BTreeMap::from([
                ("path".into(), Cbor::Text(a.path.clone())),
                ("signature".into(), Cbor::Bytes(a.signature.to_vec())),
            ]);
            m.insert("authorization".into(), Cbor::Map(a));
        }
        m
    }

    /// The bytes the author signs.
    pub fn signed_bytes(&self) -> Vec<u8> {
        [RECORD_CONTEXT, &cbor_encode(&Cbor::Map(self.unsigned_map()))].concat()
    }

    pub fn to_cbor(&self) -> Cbor {
        let mut m = self.unsigned_map();
        m.insert("signature".into(), Cbor::Bytes(self.signature.to_vec()));
        Cbor::Map(m)
    }

    pub fn to_bytes(&self) -> Vec<u8> {
        cbor_encode(&self.to_cbor())
    }

    /// Parses a record's structure. Doesn't check its contents or signatures: see `check`.
    pub fn from_cbor(v: Cbor) -> Result<Self, String> {
        let Cbor::Map(mut m) = v else { return Err("a record must be a map".into()) };
        let authorization = opt_field(&mut m, "authorization", |v| match v {
            Cbor::Map(mut a) => {
                let r = Authorization { path: field(&mut a, "path", text).ok()?, signature: field(&mut a, "signature", bytes).ok()? };
                a.is_empty().then_some(r)
            }
            _ => None,
        })?;
        let r = Record {
            author: field(&mut m, "author", bytes)?,
            owner: field(&mut m, "owner", bytes)?,
            path: field(&mut m, "path", text)?,
            version: field(&mut m, "version", |v| if let Cbor::Uint(n) = v { Some(n) } else { None })?,
            kind: field(&mut m, "type", text)?,
            data: field(&mut m, "data", Some)?,
            authorization,
            signature: field(&mut m, "signature", bytes)?,
        };
        no_more_fields(m)?;
        Ok(r)
    }

    pub fn from_bytes(b: &[u8]) -> Result<Self, String> {
        Self::from_cbor(cbor_decode(b)?)
    }

    /// Checks everything that doesn't depend on other records: the path, that `data` fits `type`,
    /// the authorization, and the author's signature.
    pub fn check(&self) -> Result<(), String> {
        check_path(&self.path)?;
        match (self.kind.as_str(), &self.data) {
            ("tombstone", Cbor::Null) => {}
            ("tombstone", _) => return Err("a tombstone's data must be null".into()),
            ("post", Cbor::Text(t)) if !t.is_empty() && t.trim() == t => {}
            ("post", _) => return Err("a post's data must be non-empty, trimmed text".into()),
            ("grant", d) => {
                if self.author != self.owner {
                    return Err("only the owner can grant access to their space".into());
                }
                let g = GrantData::from_cbor(d)?;
                check_path(&g.path).map_err(|e| format!("grant: {e}"))?;
                verify_sig(&self.owner, &grant_signed_bytes(&g.grantee, &self.owner, &g.path), &g.signature)
                    .map_err(|e| format!("grant: {e}"))?;
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
    fn cbor_round_trips_and_rejects_non_deterministic() {
        let v = Cbor::Map(BTreeMap::from([
            ("bb".into(), Cbor::Uint(1_700_000_000_000)),
            ("a".into(), Cbor::Array(vec![Cbor::Neg(0), Cbor::Bytes(vec![1, 2]), Cbor::Null, Cbor::Bool(true)])),
        ]));
        let b = cbor_encode(&v);
        assert_eq!(b[1], 0x61, "shorter key first");
        assert_eq!(cbor_decode(&b).unwrap(), v);
        assert!(cbor_decode(&[0x18, 0x05]).is_err(), "non-shortest int");
        assert!(cbor_decode(&[0xa2, 0x61, b'b', 0x00, 0x61, b'a', 0x00]).is_err(), "unsorted keys");
        assert!(cbor_decode(&[0x9f, 0xff]).is_err(), "indefinite length");
        assert!(cbor_decode(&[0x00, 0x00]).is_err(), "trailing bytes");
    }

    #[test]
    fn paths() {
        assert!(check_path("/a/b c/ü").is_ok());
        for bad in ["", "/", "a", "/a/", "/a//b", "/a/../b", "/a/\n", "/u\u{0308}"] {
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
            data: Cbor::Text("hi".into()),
            authorization: Some(Authorization { path: "/shared".into(), signature: grant_sig }),
            signature: [0; 64],
        };
        r.signature = author.sign(&r.signed_bytes()).to_bytes();
        let back = Record::from_bytes(&r.to_bytes()).unwrap();
        assert_eq!(back, r);
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
        };
        g.signature = owner.sign(&g.signed_bytes()).to_bytes();
        g.check().unwrap();

        let mut outside = r.clone();
        outside.path = "/sharedx".into();
        outside.signature = author.sign(&outside.signed_bytes()).to_bytes();
        assert!(outside.check().is_err());
    }
}
