//! fedcrdt-core for the web client (web/src/api.ts): records, IDs and paths, as plain JS values.
//! Built into wasm/pkg by `npm run wasm`.

use fedcrdt_core::{
    Authorization, CBOR, FederateData, GrantData, Map, PathFilter, Record, check_path, claim_signed_bytes,
    decode_id, encode_b58, federate_peer, grant_signed_bytes, path_within, phrase, server_phrase, two_words,
};
use serde::{Deserialize, Serialize};
use serde_bytes::ByteBuf;
use wasm_bindgen::prelude::*;

#[wasm_bindgen(typescript_custom_section)]
const TYPES: &str = r#"
export type Authorization = { path: string; signature: Uint8Array };

/** A record, decoded and checked. Field by field, see core/src/lib.rs. */
export type Rec = {
  author: Uint8Array;
  owner: Uint8Array;
  path: string;
  version: number;
  type: string;
  authorization?: Authorization;
  signature: Uint8Array;
  /** Whether it checks out: its path, data, authorization and signature. */
  verified: boolean;
  /** Why it doesn't, if it doesn't. */
  problem?: string;
  /** A post's text. */
  text?: string;
  /** A grant record's data. */
  grant?: { grantee: Uint8Array; path: string; signature: Uint8Array };
  /** A federate record's peer and data; `paths` written bb://<ID or *><path>. Missing `types` or `paths` means all. */
  federate?: { peer: Uint8Array; url: string; types?: string[]; paths?: string[] };
  /** A server record's URL. */
  serverUrl?: string;
  /** An owner record's user: who claimed the server. */
  claimedBy?: Uint8Array;
};

/** A record to sign and write. `data` is the text of a "post", null for a "tombstone", or a grant's or
 * federate record's data (federate `paths` written bb://<ID or *><path>). */
export type Draft = {
  author: Uint8Array;
  owner: Uint8Array;
  path: string;
  version: number;
  type: string;
  authorization?: Authorization;
  data:
    | string
    | null
    | { grantee: Uint8Array; path: string; signature: Uint8Array }
    | { url: string; types?: string[]; paths?: string[] };
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

#[derive(Serialize, Deserialize)]
struct AuthorizationJs {
    path: String,
    signature: ByteBuf,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct RecJs {
    author: ByteBuf,
    owner: ByteBuf,
    path: String,
    version: u64,
    #[serde(rename = "type")]
    kind: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    authorization: Option<AuthorizationJs>,
    signature: ByteBuf,
    verified: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    problem: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    text: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    grant: Option<GrantJs>,
    #[serde(skip_serializing_if = "Option::is_none")]
    federate: Option<FederateJs>,
    #[serde(skip_serializing_if = "Option::is_none")]
    server_url: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    claimed_by: Option<ByteBuf>,
}

#[derive(Serialize, Deserialize)]
struct GrantJs {
    grantee: ByteBuf,
    path: String,
    signature: ByteBuf,
}

#[derive(Serialize)]
struct FederateJs {
    peer: ByteBuf,
    url: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    types: Option<Vec<String>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    paths: Option<Vec<String>>,
}

fn rec_js(r: &Record) -> RecJs {
    let problem = r.check().err();
    let grant = (r.kind == "grant").then(|| GrantData::from_cbor(&r.data).ok()).flatten();
    let federate = (r.kind == "federate")
        .then(|| Some((federate_peer(&r.path)?, FederateData::from_cbor(&r.data).ok()?)))
        .flatten();
    RecJs {
        author: buf(&r.author),
        owner: buf(&r.owner),
        path: r.path.clone(),
        version: r.version,
        kind: r.kind.clone(),
        authorization: r.authorization.as_ref().map(|a| AuthorizationJs { path: a.path.clone(), signature: buf(&a.signature) }),
        signature: buf(&r.signature),
        verified: problem.is_none(),
        problem,
        text: (r.kind == "post").then(|| r.data.as_text().map(Into::into)).flatten(),
        grant: grant.map(|g| GrantJs { grantee: buf(&g.grantee), path: g.path, signature: buf(&g.signature) }),
        federate: federate.map(|(peer, f)| FederateJs {
            peer: buf(&peer),
            url: f.url,
            types: f.types,
            paths: f.paths.map(|p| p.iter().map(PathFilter::to_string).collect()),
        }),
        server_url: r.server_url(),
        claimed_by: r.owner_user().map(|u| buf(&u)),
    }
}

/// Decodes and checks a CBOR array of records, as the server's GET /api/records returns. Leaves out
/// any that aren't records at all.
#[wasm_bindgen(js_name = decodeRecords, unchecked_return_type = "Rec[]")]
pub fn decode_records(bytes: &[u8]) -> Result<JsValue> {
    let items = CBOR::try_from_data(bytes).map_err(err)?.into_array().ok_or_else(|| err("expected an array of records"))?;
    to_js(&items.iter().filter_map(|v| Record::from_cbor(v).ok()).map(|r| rec_js(&r)).collect::<Vec<_>>())
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
    owner: ByteBuf,
    path: String,
    version: u64,
    #[serde(rename = "type")]
    kind: String,
    authorization: Option<AuthorizationJs>,
    data: Option<DataJs>,
}

#[derive(Deserialize)]
#[serde(untagged)]
enum DataJs {
    Text(String),
    Grant(GrantJs),
    Federate { url: String, types: Option<Vec<String>>, paths: Option<Vec<String>> },
}

fn record(draft: JsValue, signature: [u8; 64]) -> Result<Record> {
    let d: DraftJs = serde_wasm_bindgen::from_value(draft).map_err(err)?;
    let data = match d.data {
        None => CBOR::null(),
        Some(DataJs::Text(t)) => t.into(),
        Some(DataJs::Grant(g)) => GrantData {
            grantee: fixed(&g.grantee, "grantee")?,
            path: g.path,
            signature: fixed(&g.signature, "signature")?,
        }
        .to_cbor(),
        Some(DataJs::Federate { url, types, paths }) => FederateData {
            url,
            types,
            paths: paths.map(|p| p.iter().map(|s| PathFilter::parse(s)).collect::<std::result::Result<_, _>>()).transpose().map_err(err)?,
        }
        .to_cbor(),
    };
    let authorization = match d.authorization {
        Some(a) => Some(Authorization { path: a.path, signature: fixed(&a.signature, "authorization signature")? }),
        None => None,
    };
    Ok(Record {
        author: fixed(&d.author, "author")?,
        owner: fixed(&d.owner, "owner")?,
        path: d.path,
        version: d.version,
        kind: d.kind,
        data,
        authorization,
        signature,
        extra: Map::new(),
    })
}

/// The bytes the author signs for `draft`.
#[wasm_bindgen(js_name = signedBytes)]
pub fn signed_bytes(#[wasm_bindgen(unchecked_param_type = "Draft")] draft: JsValue) -> Result<Vec<u8>> {
    Ok(record(draft, [0; 64])?.signed_bytes())
}

/// `draft` with its author's `signature`, as CBOR to send to the server.
#[wasm_bindgen(js_name = encodeRecord)]
pub fn encode_record(#[wasm_bindgen(unchecked_param_type = "Draft")] draft: JsValue, signature: &[u8]) -> Result<Vec<u8>> {
    Ok(record(draft, fixed(signature, "signature")?)?.to_bytes())
}

/// The bytes an owner signs to let `author` write at or under `path` in their space.
#[wasm_bindgen(js_name = grantSignedBytes)]
pub fn grant_signed_bytes_js(author: &[u8], owner: &[u8], path: &str) -> Result<Vec<u8>> {
    Ok(grant_signed_bytes(&fixed(author, "author")?, &fixed(owner, "owner")?, path))
}

/// The bytes a user signs to claim `server`, with the token from its claim link.
#[wasm_bindgen(js_name = claimSignedBytes)]
pub fn claim_signed_bytes_js(server: &[u8], token: &[u8]) -> Result<Vec<u8>> {
    Ok(claim_signed_bytes(&fixed(server, "server")?, token))
}

// ---- IDs and paths ----

/// Any bytes in base58. For a 32-byte public key, that's its ID.
#[wasm_bindgen]
pub fn b58(bytes: &[u8]) -> String {
    encode_b58(bytes)
}

/// The public key for a base58 ID; undefined unless it's exactly 32 bytes.
#[wasm_bindgen(js_name = decodeId)]
pub fn decode_id_js(id: &str) -> Option<Vec<u8>> {
    decode_id(id).map(|pk| pk.to_vec())
}

/// An ID's "🦬two_words" nickname, or "server_word" for a server's.
#[wasm_bindgen(js_name = phrase)]
pub fn phrase_js(pk: &[u8], server: bool) -> Result<String> {
    let pk = fixed(pk, "an ID")?;
    Ok(if server { server_phrase(&pk) } else { phrase(&pk) })
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

/// Whether `path` is `prefix` or below it, by whole segments.
#[wasm_bindgen(js_name = pathWithin)]
pub fn path_within_js(path: &str, prefix: &str) -> bool {
    path_within(path, prefix)
}
