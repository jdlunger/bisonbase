//! fedcrdt-core for the web client (web/src/api.ts): records, IDs and paths, as plain JS values.
//! Built into wasm/pkg by `npm run wasm`.

use fedcrdt_core::{
    CBOR, ClaimData, DocData, DocUpdateData, GrantData, Grantees, Map, PeerData, Record, Who, check_path, check_prefix, claim_signed_bytes, decode_b58,
    decode_id, encode_b58, node_phrase, path_within, phrase, read_signed_bytes, two_words,
};
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

/** A doc's data: its title, and who may edit its text besides its author. */
export type DocData = { title: string; editors: Who[] };

/** A doc update's data: the doc (its chain's first record's hash) and a Yjs update to its text. */
export type DocUpdateData = { doc: Uint8Array; update: Uint8Array };

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
  doc?: DocData;
  docUpdate?: DocUpdateData;
};

/** A chain's current version, as GET /api/records lists them: `root` is the chain's first record's
 * hash, `by` who wrote that (if the node has it), `versions` how many there are. */
export type Entry = { rec: Rec; root: Uint8Array; by?: Uint8Array; versions: number };

/** A record to sign and write. `data` is the text of a "post", null for a "tombstone", or a grant's,
 * peer record's, claim's, owner record's, doc's or doc update's data. */
export type Draft = {
  author: Uint8Array;
  path: string;
  version: number;
  type: string;
  edits?: Uint8Array;
  private: boolean;
  data: string | null | GrantData | PeerData | ClaimData | Who | DocData | DocUpdateData;
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
    doc: Option<DocJs>,
    #[serde(skip_serializing_if = "Option::is_none")]
    doc_update: Option<DocUpdateJs>,
}

#[derive(Serialize, Deserialize)]
struct DocJs {
    title: String,
    editors: Vec<WhoJs>,
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
        doc: r.doc().map(|d| DocJs { title: d.title, editors: d.editors.iter().map(WhoJs::from).collect() }),
        doc_update: r.doc_update().map(|u| DocUpdateJs { doc: buf(&u.doc), update: ByteBuf::from(u.update) }),
    }
}

#[derive(Serialize)]
struct EntryJs {
    rec: RecJs,
    root: ByteBuf,
    #[serde(skip_serializing_if = "Option::is_none")]
    by: Option<ByteBuf>,
    versions: u64,
}

fn entry_js(v: &CBOR) -> Option<EntryJs> {
    let m = v.as_map()?;
    let rec = Record::from_cbor(&m.get::<_, CBOR>("record")?).ok()?;
    let bytes = |k: &str| m.get::<_, CBOR>(k).and_then(|v| v.as_byte_string().map(buf));
    Some(EntryJs {
        rec: rec_js(&rec),
        root: bytes("root")?,
        by: bytes("by"),
        versions: m.get::<_, CBOR>("versions").and_then(|v| u64::try_from(v).ok())?,
    })
}

fn array(bytes: &[u8]) -> Result<Vec<CBOR>> {
    CBOR::try_from_data(bytes).map_err(err)?.into_array().ok_or_else(|| err("expected an array"))
}

/// Decodes and checks the entries GET /api/records returns. Leaves out any that aren't entries at all.
#[wasm_bindgen(js_name = decodeEntries, unchecked_return_type = "Entry[]")]
pub fn decode_entries(bytes: &[u8]) -> Result<JsValue> {
    to_js(&array(bytes)?.iter().filter_map(entry_js).collect::<Vec<_>>())
}

/// Decodes and checks a CBOR array of records, as GET /api/records/<hash> returns. Leaves out any
/// that aren't records at all.
#[wasm_bindgen(js_name = decodeRecords, unchecked_return_type = "Rec[]")]
pub fn decode_records(bytes: &[u8]) -> Result<JsValue> {
    to_js(&array(bytes)?.iter().filter_map(|v| Record::from_cbor(v).ok()).map(|r| rec_js(&r)).collect::<Vec<_>>())
}

/// Decodes and checks one record.
#[wasm_bindgen(js_name = decodeRecord, unchecked_return_type = "Rec")]
pub fn decode_record(bytes: &[u8]) -> Result<JsValue> {
    to_js(&rec_js(&Record::from_bytes(bytes).map_err(err)?))
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
    data: Option<DataJs>,
}

#[derive(Deserialize)]
#[serde(untagged)]
enum DataJs {
    Text(String),
    Grant(GrantJs),
    Peer(PeerJs),
    Claim(ClaimJs),
    Owner(WhoJs),
    Doc(DocJs),
    DocUpdate(DocUpdateJs),
}

fn record(draft: JsValue, signature: [u8; 64]) -> Result<Record> {
    let d: DraftJs = serde_wasm_bindgen::from_value(draft).map_err(err)?;
    let data = match d.data {
        None => CBOR::null(),
        Some(DataJs::Text(t)) => t.into(),
        Some(DataJs::Grant(g)) => GrantData {
            path: g.path,
            grantees: match g.grantees {
                GranteesJs::Anyone(s) if s == "anyone" => Grantees::Anyone,
                GranteesJs::Anyone(s) => return Err(err(format!("grantees must be \"anyone\" or a list of IDs, not {s:?}"))),
                GranteesJs::Some(w) => Grantees::Some(w.iter().map(WhoJs::to).collect::<Result<_>>()?),
            },
        }
        .to_cbor(),
        Some(DataJs::Peer(p)) => PeerData { node: fixed(&p.node, "node")?, url: p.url, types: p.types, paths: p.paths }.to_cbor(),
        Some(DataJs::Claim(c)) => {
            ClaimData { token_hash: fixed(&c.token_hash, "tokenHash")?, user: c.user.map(|u| fixed(&u, "user")).transpose()? }.to_cbor()
        }
        Some(DataJs::Owner(w)) => w.to()?.to_cbor(),
        Some(DataJs::Doc(d)) => DocData { title: d.title, editors: d.editors.iter().map(WhoJs::to).collect::<Result<_>>()? }.to_cbor(),
        Some(DataJs::DocUpdate(u)) => DocUpdateData { doc: fixed(&u.doc, "doc")?, update: u.update.into_vec() }.to_cbor(),
    };
    Ok(Record {
        author: fixed(&d.author, "author")?,
        path: d.path,
        version: d.version,
        kind: d.kind,
        data,
        edits: d.edits.map(|e| fixed(&e, "edits")).transpose()?,
        private: d.private,
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

/// Whether `path` is `prefix` or below it, by whole segments.
#[wasm_bindgen(js_name = pathWithin)]
pub fn path_within_js(path: &str, prefix: &str) -> bool {
    path_within(path, prefix)
}
