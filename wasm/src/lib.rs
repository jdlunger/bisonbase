//! fedcrdt-core for the web client (web/src/api.ts): records, IDs and paths, as plain JS values.
//! Built into wasm/pkg by `npm run wasm`.

use fedcrdt_core::{
    Acting, CBOR, CBORCase, ClaimData, DelegateData, DocData, DocSnapshotData, DocUpdateData, EncKeyData, GrantData, Grantees, Map, PeerData, Record,
    SealedKey, Who, access_signed_bytes, check_path, check_prefix, claim_signed_bytes, decode_b58, decode_id, delegate_path, encode_b58, enckey_path, is_app_type,
    live_signed_bytes, node_phrase, path_user, path_within, phrase, read_signed_bytes, two_words, user_path,
};
use js_sys::{Array, BigInt, Object, Reflect, Uint8Array};
use serde::{Deserialize, Serialize};
use serde_bytes::ByteBuf;
use wasm_bindgen::prelude::*;

#[wasm_bindgen(typescript_custom_section)]
const TYPES: &str = r#"
/** A user, named directly by ID, or by the hash of a claim (its chain's first record), for whoever claims it. */
export type Who = { user: Uint8Array } | { claim: Uint8Array };

/** A grant's data: who may write at or under `path` ("/" for everywhere). */
export type GrantData = { path: string; grantees: "anyone" | Who[] };

/** A peer record's data: push to `node` at `url`. Missing `types` or `paths` means all. */
export type PeerData = { node: Uint8Array; url: string; types?: string[]; paths?: string[] };

/** A claim's data: SHA-256 of its link's token, and who claimed it, once someone has. */
export type ClaimData = { tokenHash: Uint8Array; user?: Uint8Array };

/** A doc's content key, sealed to `user` (see client/src/crypto.ts). */
export type SealedKey = { user: Uint8Array; sealed: Uint8Array };

/** A doc's data: its title, who may edit it besides its author, its content's format (CRDT library) and
 * schema (what an app keeps in it), and if it's encrypted, its key sealed to each reader. All but the
 * title and editors are fixed once it's made. */
export type DocData = { title: string; editors: Who[]; format: string; schema: string; keys?: SealedKey[] };

/** A doc update's data: the doc (its chain's first record's hash) and an update to its content. */
export type DocUpdateData = { doc: Uint8Array; update: Uint8Array };

/** A doc snapshot's data: the doc, its whole content, and the updates that has in it (by hash). */
export type DocSnapshotData = { doc: Uint8Array; state: Uint8Array; covers: Uint8Array[] };

/** A delegation's data: lets `key` sign records for its author, at or under `paths`, of `types` (missing:
 * any), until `expires` (ms since the epoch; missing: no end). `name`: who `key` is, e.g. an app. */
export type DelegateData = { key: Uint8Array; name: string; paths?: string[]; types?: string[]; expires?: number };

/** An enckey record's data: its author's X25519 public key. */
export type EncKeyData = { key: Uint8Array };

/** A record's `as`: its author signs for `user`, under `user`'s delegate chain `delegation` (its hash). */
export type Acting = { user: Uint8Array; delegation: Uint8Array };

/** A record, decoded and checked. Field by field, see core/src/lib.rs. */
export type Rec = {
  /** SHA-256 of its bytes: what identifies it. */
  hash: Uint8Array;
  author: Uint8Array;
  path: string;
  version: number;
  type: string;
  edits?: Uint8Array;
  /** Only the node's owners may read it, and it's never federated. */
  private: boolean;
  /** Signed for this user, under a delegation. */
  as?: Acting;
  /** Whose it is: `as.user`, or else `author`. */
  principal: Uint8Array;
  signature: Uint8Array;
  /** Whether it checks out: its path, data and signature. */
  verified: boolean;
  /** Why it doesn't, if it doesn't. */
  problem?: string;
  /** A post's text. */
  text?: string;
  grant?: GrantData;
  peer?: PeerData;
  claim?: ClaimData;
  /** A node record's URL. */
  nodeUrl?: string;
  /** An owner record's user. */
  owner?: Who;
  /** An access record's user. */
  access?: Who;
  doc?: DocData;
  docUpdate?: DocUpdateData;
  docSnapshot?: DocSnapshotData;
  delegate?: DelegateData;
  enckey?: EncKeyData;
  /** An app type's data, as plain JS: maps with text keys as objects, byte strings as Uint8Array,
   * integers past 2^53 as BigInt. */
  data?: unknown;
};

/** A chain's current version, as GET /api/records lists them: `root` is the chain's first record's
 * hash, `by` who wrote that (if the node has it), `versions` how many there are. */
export type Entry = { rec: Rec; root: Uint8Array; by?: Uint8Array; versions: number };

/** A record to sign and write. `data` is the text of a "post", null for a "tombstone", the data of one
 * of the types above (as `Rec` has it), or for an app type, any plain JS value (see `Rec.data`). */
export type Draft = {
  author: Uint8Array;
  path: string;
  version: number;
  type: string;
  edits?: Uint8Array;
  private: boolean;
  as?: Acting;
  data: unknown;
};
"#;

type Result<T> = std::result::Result<T, JsError>;

fn err(e: impl std::fmt::Display) -> JsError {
    JsError::new(&e.to_string())
}

fn fixed<const N: usize>(b: &[u8], what: &str) -> Result<[u8; N]> {
    b.try_into().map_err(|_| err(format!("{what} must be {N} bytes")))
}

fn buf(b: &[u8]) -> ByteBuf {
    ByteBuf::from(b.to_vec())
}

fn to_js(v: &impl Serialize) -> Result<JsValue> {
    v.serialize(&serde_wasm_bindgen::Serializer::new()).map_err(err)
}

// ---- reading ----

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct RecJs {
    hash: ByteBuf,
    author: ByteBuf,
    path: String,
    version: u64,
    #[serde(rename = "type")]
    kind: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    edits: Option<ByteBuf>,
    private: bool,
    #[serde(rename = "as", skip_serializing_if = "Option::is_none")]
    acting: Option<ActingJs>,
    principal: ByteBuf,
    signature: ByteBuf,
    verified: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    problem: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    text: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    grant: Option<GrantJs>,
    #[serde(skip_serializing_if = "Option::is_none")]
    peer: Option<PeerJs>,
    #[serde(skip_serializing_if = "Option::is_none")]
    claim: Option<ClaimJs>,
    #[serde(skip_serializing_if = "Option::is_none")]
    node_url: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    owner: Option<WhoJs>,
    #[serde(skip_serializing_if = "Option::is_none")]
    access: Option<WhoJs>,
    #[serde(skip_serializing_if = "Option::is_none")]
    doc: Option<DocJs>,
    #[serde(skip_serializing_if = "Option::is_none")]
    doc_update: Option<DocUpdateJs>,
    #[serde(skip_serializing_if = "Option::is_none")]
    doc_snapshot: Option<DocSnapshotJs>,
    #[serde(skip_serializing_if = "Option::is_none")]
    delegate: Option<DelegateJs>,
    #[serde(skip_serializing_if = "Option::is_none")]
    enckey: Option<EncKeyJs>,
}

#[derive(Serialize, Deserialize)]
struct ActingJs {
    user: ByteBuf,
    delegation: ByteBuf,
}

#[derive(Serialize, Deserialize)]
struct SealedKeyJs {
    user: ByteBuf,
    sealed: ByteBuf,
}

#[derive(Serialize, Deserialize)]
struct DocJs {
    title: String,
    editors: Vec<WhoJs>,
    format: String,
    schema: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    keys: Option<Vec<SealedKeyJs>>,
}

#[derive(Serialize, Deserialize)]
struct DocSnapshotJs {
    doc: ByteBuf,
    state: ByteBuf,
    covers: Vec<ByteBuf>,
}

#[derive(Serialize, Deserialize)]
struct DelegateJs {
    key: ByteBuf,
    name: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    paths: Option<Vec<String>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    types: Option<Vec<String>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    expires: Option<u64>,
}

#[derive(Serialize, Deserialize)]
struct EncKeyJs {
    key: ByteBuf,
}

#[derive(Serialize, Deserialize)]
struct DocUpdateJs {
    doc: ByteBuf,
    update: ByteBuf,
}

#[derive(Serialize, Deserialize)]
#[serde(untagged)]
enum WhoJs {
    User { user: ByteBuf },
    Claim { claim: ByteBuf },
}

impl WhoJs {
    fn from(w: &Who) -> Self {
        match w {
            Who::User(u) => WhoJs::User { user: buf(u) },
            Who::Claim(c) => WhoJs::Claim { claim: buf(c) },
        }
    }

    fn to(&self) -> Result<Who> {
        Ok(match self {
            WhoJs::User { user } => Who::User(fixed(user, "user")?),
            WhoJs::Claim { claim } => Who::Claim(fixed(claim, "claim")?),
        })
    }
}

#[derive(Serialize, Deserialize)]
#[serde(untagged)]
enum GranteesJs {
    Anyone(String),
    Some(Vec<WhoJs>),
}

#[derive(Serialize, Deserialize)]
struct GrantJs {
    path: String,
    grantees: GranteesJs,
}

#[derive(Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
struct ClaimJs {
    token_hash: ByteBuf,
    #[serde(skip_serializing_if = "Option::is_none")]
    user: Option<ByteBuf>,
}

#[derive(Serialize, Deserialize)]
struct PeerJs {
    node: ByteBuf,
    url: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    types: Option<Vec<String>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    paths: Option<Vec<String>>,
}

fn rec_js(r: &Record) -> RecJs {
    let problem = r.check().err();
    let grant = (r.kind == "grant").then(|| GrantData::from_cbor(&r.data).ok()).flatten();
    let peer = (r.kind == "peer").then(|| PeerData::from_cbor(&r.data).ok()).flatten();
    RecJs {
        hash: buf(&r.hash()),
        author: buf(&r.author),
        path: r.path.clone(),
        version: r.version,
        kind: r.kind.clone(),
        edits: r.edits.map(|e| buf(&e)),
        private: r.private,
        acting: r.acting.as_ref().map(|a| ActingJs { user: buf(&a.user), delegation: buf(&a.delegation) }),
        principal: buf(&r.principal()),
        signature: buf(&r.signature),
        verified: problem.is_none(),
        problem,
        text: (r.kind == "post").then(|| r.data.as_text().map(Into::into)).flatten(),
        grant: grant.map(|g| GrantJs {
            path: g.path,
            grantees: match g.grantees {
                Grantees::Anyone => GranteesJs::Anyone("anyone".into()),
                Grantees::Some(w) => GranteesJs::Some(w.iter().map(WhoJs::from).collect()),
            },
        }),
        peer: peer.map(|p| PeerJs { node: buf(&p.node), url: p.url, types: p.types, paths: p.paths }),
        claim: r.claim().map(|c| ClaimJs { token_hash: buf(&c.token_hash), user: c.user.map(|u| buf(&u)) }),
        node_url: r.node_url(),
        owner: r.owner().as_ref().map(WhoJs::from),
        access: r.access().as_ref().map(WhoJs::from),
        doc: r.doc().map(|d| DocJs {
            title: d.title,
            editors: d.editors.iter().map(WhoJs::from).collect(),
            format: d.format,
            schema: d.schema,
            keys: d.keys.map(|k| k.into_iter().map(|k| SealedKeyJs { user: buf(&k.user), sealed: ByteBuf::from(k.sealed) }).collect()),
        }),
        doc_update: r.doc_update().map(|u| DocUpdateJs { doc: buf(&u.doc), update: ByteBuf::from(u.update) }),
        doc_snapshot: r.doc_snapshot().map(|s| DocSnapshotJs { doc: buf(&s.doc), state: ByteBuf::from(s.state), covers: s.covers.iter().map(|c| buf(c)).collect() }),
        delegate: r.delegate().map(|d| DelegateJs { key: buf(&d.key), name: d.name, paths: d.paths, types: d.types, expires: d.expires }),
        enckey: r.enckey().map(|e| EncKeyJs { key: buf(&e.key) }),
    }
}

/// A record as JS, with an app type's data as plain JS.
fn rec_value(r: &Record) -> Result<JsValue> {
    let v = to_js(&rec_js(r))?;
    if is_app_type(&r.kind) {
        Reflect::set(&v, &"data".into(), &cbor_to_js(&r.data)).map_err(|_| err("couldn't set data"))?;
    }
    Ok(v)
}

// ---- any CBOR as plain JS, and back, for app types' data ----

/// The largest integer a JS number holds exactly.
const MAX_SAFE: u64 = (1 << 53) - 1;

fn cbor_to_js(c: &CBOR) -> JsValue {
    match c.as_case() {
        CBORCase::Unsigned(n) if *n <= MAX_SAFE => JsValue::from(*n as f64),
        CBORCase::Unsigned(n) => BigInt::from(*n).into(),
        CBORCase::Negative(n) if *n < MAX_SAFE => JsValue::from(-1.0 - *n as f64),
        CBORCase::Negative(n) => BigInt::from(-1i128 - *n as i128).into(),
        CBORCase::ByteString(b) => Uint8Array::from(b.data()).into(),
        CBORCase::Text(s) => JsValue::from(s.as_str()),
        CBORCase::Array(a) => a.iter().map(cbor_to_js).collect::<Array>().into(),
        CBORCase::Map(m) => {
            let o = Object::new();
            for (k, v) in m.iter() {
                // Only text keys can be object keys; others are shown as their CBOR diagnostic notation.
                let k = k.as_text().map(String::from).unwrap_or_else(|| k.diagnostic());
                let _ = Reflect::set(&o, &k.into(), &cbor_to_js(v));
            }
            o.into()
        }
        CBORCase::Tagged(t, v) => {
            let o = Object::new();
            let _ = Reflect::set(&o, &"tag".into(), &JsValue::from(t.value() as f64));
            let _ = Reflect::set(&o, &"value".into(), &cbor_to_js(v));
            o.into()
        }
        CBORCase::Simple(s) => match s {
            fedcrdt_core::Simple::True => JsValue::TRUE,
            fedcrdt_core::Simple::False => JsValue::FALSE,
            fedcrdt_core::Simple::Null => JsValue::NULL,
            fedcrdt_core::Simple::Float(f) => JsValue::from(*f),
        },
    }
}

fn js_to_cbor(v: &JsValue, depth: usize) -> Result<CBOR> {
    if depth > 64 {
        return Err(err("data is nested too deeply"));
    }
    if v.is_null() || v.is_undefined() {
        return Ok(CBOR::null());
    }
    if let Some(b) = v.as_bool() {
        return Ok(b.into());
    }
    if let Some(n) = v.as_f64() {
        return Ok(if n.fract() == 0.0 && n.abs() <= MAX_SAFE as f64 {
            if n >= 0.0 { CBOR::from(n as u64) } else { CBOR::from(n as i64) }
        } else {
            CBOR::from(n)
        });
    }
    if v.is_bigint() {
        let n: i128 = BigInt::from(v.clone()).to_string(10).ok().and_then(|s| String::from(s).parse().ok()).ok_or_else(|| err("BigInt out of range"))?;
        return match (u64::try_from(n), i64::try_from(n)) {
            (Ok(u), _) => Ok(u.into()),
            (_, Ok(i)) => Ok(i.into()),
            _ => Err(err("integers must fit in 64 bits")),
        };
    }
    if let Some(s) = v.as_string() {
        return Ok(s.into());
    }
    if let Some(b) = v.dyn_ref::<Uint8Array>() {
        return Ok(CBOR::to_byte_string(b.to_vec()));
    }
    if Array::is_array(v) {
        return Ok(Array::from(v).iter().map(|x| js_to_cbor(&x, depth + 1)).collect::<Result<Vec<_>>>()?.into());
    }
    if v.is_object() {
        let mut m = Map::new();
        for e in Object::entries(v.unchecked_ref()).iter() {
            let e = Array::from(&e);
            let k = e.get(0).as_string().ok_or_else(|| err("object keys must be text"))?;
            let x = e.get(1);
            if !x.is_undefined() {
                m.insert(k, js_to_cbor(&x, depth + 1)?);
            }
        }
        return Ok(m.into());
    }
    Err(err("data may only hold null, booleans, numbers, BigInts, text, Uint8Arrays, arrays and plain objects"))
}

#[derive(Serialize)]
struct EntryJs {
    root: ByteBuf,
    #[serde(skip_serializing_if = "Option::is_none")]
    by: Option<ByteBuf>,
    versions: u64,
}

fn entry_js(v: &CBOR) -> Option<Result<JsValue>> {
    let m = v.as_map()?;
    let rec = Record::from_cbor(&m.get::<_, CBOR>("record")?).ok()?;
    let bytes = |k: &str| m.get::<_, CBOR>(k).and_then(|v| v.as_byte_string().map(buf));
    let e = EntryJs { root: bytes("root")?, by: bytes("by"), versions: m.get::<_, CBOR>("versions").and_then(|v| u64::try_from(v).ok())? };
    Some((|| {
        let o = to_js(&e)?;
        Reflect::set(&o, &"rec".into(), &rec_value(&rec)?).map_err(|_| err("couldn't set rec"))?;
        Ok(o)
    })())
}

fn array(bytes: &[u8]) -> Result<Vec<CBOR>> {
    CBOR::try_from_data(bytes).map_err(err)?.into_array().ok_or_else(|| err("expected an array"))
}

/// Decodes and checks the entries GET /api/records returns. Leaves out any that aren't entries at all.
#[wasm_bindgen(js_name = decodeEntries, unchecked_return_type = "Entry[]")]
pub fn decode_entries(bytes: &[u8]) -> Result<JsValue> {
    array(bytes)?.iter().filter_map(entry_js).collect::<Result<Array>>().map(Into::into)
}

/// Decodes and checks a CBOR array of records, as GET /api/records/<hash> returns. Leaves out any
/// that aren't records at all.
#[wasm_bindgen(js_name = decodeRecords, unchecked_return_type = "Rec[]")]
pub fn decode_records(bytes: &[u8]) -> Result<JsValue> {
    array(bytes)?.iter().filter_map(|v| Record::from_cbor(v).ok()).map(|r| rec_value(&r)).collect::<Result<Array>>().map(Into::into)
}

/// Decodes and checks one record.
#[wasm_bindgen(js_name = decodeRecord, unchecked_return_type = "Rec")]
pub fn decode_record(bytes: &[u8]) -> Result<JsValue> {
    rec_value(&Record::from_bytes(bytes).map_err(err)?)
}

// ---- writing ----

#[derive(Deserialize)]
struct DraftJs {
    author: ByteBuf,
    path: String,
    version: u64,
    #[serde(rename = "type")]
    kind: String,
    edits: Option<ByteBuf>,
    private: bool,
    #[serde(rename = "as")]
    acting: Option<ActingJs>,
}

fn who_list(w: &[WhoJs]) -> Result<Vec<Who>> {
    w.iter().map(WhoJs::to).collect()
}

/// A draft's `data`, as its type has it.
fn data_cbor(kind: &str, data: JsValue) -> Result<CBOR> {
    fn de<T: for<'a> Deserialize<'a>>(v: JsValue) -> Result<T> {
        serde_wasm_bindgen::from_value(v).map_err(err)
    }
    Ok(match kind {
        "tombstone" => CBOR::null(),
        "post" => data.as_string().ok_or_else(|| err("a post's data is its text"))?.into(),
        "grant" => {
            let g: GrantJs = de(data)?;
            GrantData {
                path: g.path,
                grantees: match g.grantees {
                    GranteesJs::Anyone(s) if s == "anyone" => Grantees::Anyone,
                    GranteesJs::Anyone(s) => return Err(err(format!("grantees must be \"anyone\" or a list of IDs, not {s:?}"))),
                    GranteesJs::Some(w) => Grantees::Some(who_list(&w)?),
                },
            }
            .to_cbor()
        }
        "peer" => {
            let p: PeerJs = de(data)?;
            PeerData { node: fixed(&p.node, "node")?, url: p.url, types: p.types, paths: p.paths }.to_cbor()
        }
        "claim" => {
            let c: ClaimJs = de(data)?;
            ClaimData { token_hash: fixed(&c.token_hash, "tokenHash")?, user: c.user.map(|u| fixed(&u, "user")).transpose()? }.to_cbor()
        }
        "owner" | "access" => de::<WhoJs>(data)?.to()?.to_cbor(),
        "doc" => {
            let d: DocJs = de(data)?;
            let keys = d
                .keys
                .map(|k| k.iter().map(|k| Ok(SealedKey { user: fixed(&k.user, "user")?, sealed: k.sealed.to_vec() })).collect::<Result<Vec<_>>>())
                .transpose()?;
            DocData { title: d.title, editors: who_list(&d.editors)?, format: d.format, schema: d.schema, keys }.to_cbor()
        }
        "doc_update" => {
            let u: DocUpdateJs = de(data)?;
            DocUpdateData { doc: fixed(&u.doc, "doc")?, update: u.update.into_vec() }.to_cbor()
        }
        "doc_snapshot" => {
            let s: DocSnapshotJs = de(data)?;
            let covers = s.covers.iter().map(|c| fixed(c, "covers")).collect::<Result<Vec<_>>>()?;
            DocSnapshotData { doc: fixed(&s.doc, "doc")?, state: s.state.into_vec(), covers }.to_cbor()
        }
        "delegate" => {
            let d: DelegateJs = de(data)?;
            DelegateData { key: fixed(&d.key, "key")?, name: d.name, paths: d.paths, types: d.types, expires: d.expires }.to_cbor()
        }
        "enckey" => EncKeyData { key: fixed(&de::<EncKeyJs>(data)?.key, "key")? }.to_cbor(),
        // App types, and anything else (which `check` refuses).
        _ => js_to_cbor(&data, 0)?,
    })
}

fn record(draft: JsValue, signature: [u8; 64]) -> Result<Record> {
    let data = Reflect::get(&draft, &"data".into()).map_err(|_| err("a draft needs data"))?;
    let d: DraftJs = serde_wasm_bindgen::from_value(draft).map_err(err)?;
    Ok(Record {
        author: fixed(&d.author, "author")?,
        path: d.path,
        version: d.version,
        data: data_cbor(&d.kind, data)?,
        kind: d.kind,
        edits: d.edits.map(|e| fixed(&e, "edits")).transpose()?,
        private: d.private,
        acting: d.acting.map(|a| Ok::<_, JsError>(Acting { user: fixed(&a.user, "as.user")?, delegation: fixed(&a.delegation, "as.delegation")? })).transpose()?,
        signature,
        extra: Map::new(),
    })
}

/// The bytes the author signs for `draft`.
#[wasm_bindgen(js_name = signedBytes)]
pub fn signed_bytes(#[wasm_bindgen(unchecked_param_type = "Draft")] draft: JsValue) -> Result<Vec<u8>> {
    Ok(record(draft, [0; 64])?.signed_bytes())
}

/// `draft` with its author's `signature`, as CBOR to send to the node.
#[wasm_bindgen(js_name = encodeRecord)]
pub fn encode_record(#[wasm_bindgen(unchecked_param_type = "Draft")] draft: JsValue, signature: &[u8]) -> Result<Vec<u8>> {
    Ok(record(draft, fixed(signature, "signature")?)?.to_bytes())
}

/// The bytes a user signs to claim a claim on `node`, with the token from its link.
#[wasm_bindgen(js_name = claimSignedBytes)]
pub fn claim_signed_bytes_js(node: &[u8], token: &[u8]) -> Result<Vec<u8>> {
    Ok(claim_signed_bytes(&fixed(node, "node")?, token))
}

/// The bytes an owner signs for a token to read `node`'s private records until `expires` (ms since the epoch).
#[wasm_bindgen(js_name = readSignedBytes)]
pub fn read_signed_bytes_js(node: &[u8], expires: u64) -> Result<Vec<u8>> {
    Ok(read_signed_bytes(&fixed(node, "node")?, expires))
}

/// The bytes a user signs to be let into the private node whose web app is at `origin` until `expires`
/// (ms since the epoch).
#[wasm_bindgen(js_name = accessSignedBytes)]
pub fn access_signed_bytes_js(origin: &str, expires: u64) -> Vec<u8> {
    access_signed_bytes(origin, expires)
}

/// The bytes an editor signs to join the live room of `doc` on `node` until `expires` (ms since the epoch).
#[wasm_bindgen(js_name = liveSignedBytes)]
pub fn live_signed_bytes_js(node: &[u8], doc: &[u8], expires: u64) -> Result<Vec<u8>> {
    Ok(live_signed_bytes(&fixed(node, "node")?, &fixed(doc, "doc")?, expires))
}

// ---- IDs and paths ----

/// Any bytes in base58. For a 32-byte public key, that's its ID.
#[wasm_bindgen]
pub fn b58(bytes: &[u8]) -> String {
    encode_b58(bytes)
}

/// Bytes from base58; undefined if it isn't.
#[wasm_bindgen]
pub fn unb58(s: &str) -> Option<Vec<u8>> {
    decode_b58(s)
}

/// The public key for a base58 ID; undefined unless it's exactly 32 bytes.
#[wasm_bindgen(js_name = decodeId)]
pub fn decode_id_js(id: &str) -> Option<Vec<u8>> {
    decode_id(id).map(|pk| pk.to_vec())
}

/// An ID's "🦬two_words" nickname, or "node_word" for a node's.
#[wasm_bindgen(js_name = phrase)]
pub fn phrase_js(pk: &[u8], node: bool) -> Result<String> {
    let pk = fixed(pk, "an ID")?;
    Ok(if node { node_phrase(&pk) } else { phrase(&pk) })
}

/// "two_words" from SHA-256 of `bytes`, as a passkey's name is derived from its user handle.
#[wasm_bindgen(js_name = twoWords)]
pub fn two_words_js(bytes: &[u8]) -> String {
    two_words(bytes)
}

/// Throws unless `path` is a valid record path (see `check_path`).
#[wasm_bindgen(js_name = checkPath)]
pub fn check_path_js(path: &str) -> Result<()> {
    check_path(path).map_err(err)
}

/// Throws unless `prefix` is a valid path, or "/" for everything.
#[wasm_bindgen(js_name = checkPrefix)]
pub fn check_prefix_js(prefix: &str) -> Result<()> {
    check_prefix(prefix).map_err(err)
}

/// A user's space, /u/<their ID>.
#[wasm_bindgen(js_name = userPath)]
pub fn user_path_js(pk: &[u8]) -> Result<String> {
    Ok(user_path(&fixed(pk, "an ID")?))
}

/// Where a user's delegations go.
#[wasm_bindgen(js_name = delegatePath)]
pub fn delegate_path_js(pk: &[u8]) -> Result<String> {
    Ok(delegate_path(&fixed(pk, "an ID")?))
}

/// Where a user's enckey goes.
#[wasm_bindgen(js_name = enckeyPath)]
pub fn enckey_path_js(pk: &[u8]) -> Result<String> {
    Ok(enckey_path(&fixed(pk, "an ID")?))
}

/// Whose space `path` is in, if it's in one.
#[wasm_bindgen(js_name = pathUser)]
pub fn path_user_js(path: &str) -> Option<Vec<u8>> {
    path_user(path).map(|pk| pk.to_vec())
}

/// Whether `path` is `prefix` or below it, by whole segments.
#[wasm_bindgen(js_name = pathWithin)]
pub fn path_within_js(path: &str, prefix: &str) -> bool {
    path_within(path, prefix)
}
