//! Posts a note (a "post" record, see src/lib.rs) to a bisonbase server, signed (and optionally
//! encrypted) with an ssh-ed25519 key from the local SSH agent. The author ID is the SSH public key
//! itself, so anyone can check it against e.g. https://github.com/<user>.keys.
//!
//!     note [--encrypt] [--key <file.pub | "ssh-ed25519 AAAA…">] [--path <path>] [--grant <bb://grant>] <text | -> <server URL>

use aes_gcm::{Aes256Gcm, KeyInit, aead::Aead};
use base64::{Engine, engine::general_purpose::STANDARD};
use fedcrdt::{Authorization, Cbor, GrantData, Record, cbor_decode, cbor_encode, check_path, ed25519_from_blob, put_string, take_string};
use hkdf::Hkdf;
use sha2::{Digest, Sha256};
use std::{
    io::{Read, Write},
    os::unix::net::UnixStream,
    process::exit,
    time::{SystemTime, UNIX_EPOCH},
};

const USAGE: &str = "usage: note [--encrypt] [--key <file.pub | \"ssh-ed25519 AAAA…\">] [--path <path>] [--grant <bb://grant>] <text | -> <server URL>

Signs a note with an ssh-ed25519 key from your SSH agent ($SSH_AUTH_SOCK) and posts it to the server.
Your author ID is that SSH public key. Text \"-\" reads the note from stdin.

  --encrypt   encrypt the note so only this SSH key can read it (the server and others see ciphertext)
  --key       which agent key to use (default: the agent's first ssh-ed25519 key)
  --path      where to put it, e.g. /posts/hello (default: /posts/<random>)
  --grant     write in someone else's space, under a grant they gave you: the grant record's
              bb:// address; --path must be within the grant's path";

/// The note encryption key is derived from this key's signature over this message, so nothing
/// else may ever ask the key to sign it: that signature *is* the secret. Its prefix differs from
/// every other bisonbase signature context.
const NOTEKEY_MESSAGE: &[u8] = b"bisonbase-notekey-v1\n";

fn main() {
    if let Err(e) = run() {
        eprintln!("note: {e}");
        exit(1);
    }
}

fn run() -> Result<(), String> {
    let (mut encrypt, mut key_arg, mut path, mut grant, mut pos) = (false, None, None, None, vec![]);
    let mut args = std::env::args().skip(1);
    while let Some(a) = args.next() {
        match a.as_str() {
            "--encrypt" | "-e" => encrypt = true,
            "--key" | "-k" => key_arg = Some(args.next().ok_or("--key needs a value")?),
            "--path" | "-p" => path = Some(args.next().ok_or("--path needs a value")?),
            "--grant" | "-g" => grant = Some(args.next().ok_or("--grant needs a value")?),
            "--help" | "-h" => {
                println!("{USAGE}");
                return Ok(());
            }
            "--" => pos.extend(args.by_ref()),
            _ if a.starts_with('-') && a != "-" => return Err(format!("unknown option {a}\n\n{USAGE}")),
            _ => pos.push(a),
        }
    }
    let [text, server] = <[String; 2]>::try_from(pos).map_err(|_| USAGE.to_string())?;
    let text = if text == "-" {
        let mut s = String::new();
        std::io::stdin().read_to_string(&mut s).map_err(|e| format!("reading stdin: {e}"))?;
        s
    } else {
        text
    };
    let text = text.trim();
    if text.is_empty() {
        return Err("the note is empty".into());
    }
    let server = server.trim_end_matches('/');
    let path = path.unwrap_or_else(|| format!("/posts/{}", bs58_random()));
    check_path(&path).map_err(|e| format!("bad --path: {e}"))?;

    let mut agent = Agent::connect()?;
    let pk = pick_key(&mut agent, key_arg.as_deref())?;

    let http = ureq::Agent::config_builder().http_status_as_error(false).build().new_agent();
    let grant = grant.map(|uri| fetch_grant(&http, server, &uri, &pk)).transpose()?;
    if let Some((_, g)) = &grant {
        if !fedcrdt::path_within(&path, &g.path) {
            return Err(format!("the grant only covers {}; pass a --path within it", g.path));
        }
    }

    let (data, wrapped_key) = if encrypt {
        let note_key = note_key(&mut agent, &pk)?;
        let raw = random::<32>();
        (Cbor::Bytes(seal(&raw, &cbor_encode(&Cbor::Text(text.into())))), Some(seal(&note_key, &raw)))
    } else {
        (Cbor::Text(text.into()), None)
    };
    let mut rec = Record {
        author: pk,
        owner: grant.as_ref().map_or(pk, |(owner, _)| *owner),
        path,
        version: SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_millis() as u64,
        kind: "post".into(),
        data,
        wrapped_key,
        authorization: grant.map(|(_, g)| Authorization { path: g.path, signature: g.signature }),
        signature: [0; 64],
    };
    rec.signature = agent.sign(&pk, &rec.signed_bytes())?;

    let mut res = http
        .post(format!("{server}/api/records"))
        .content_type("application/cbor")
        .send(&rec.to_bytes()[..])
        .map_err(|e| format!("couldn't reach {server}: {e}"))?;
    if !res.status().is_success() {
        let msg = res.body_mut().read_to_string().unwrap_or_default();
        return Err(format!("server refused the note ({}): {msg}", res.status()));
    }

    println!("posted {}note {}", if encrypt { "encrypted " } else { "" }, fedcrdt::encode_uri(&rec.owner, &rec.path));
    println!("author {} ({})", fedcrdt::phrase(&pk), fedcrdt::encode_id(&pk));
    println!("       ssh-ed25519 {}", STANDARD.encode(fedcrdt::ed25519_key_blob(&pk)));
    Ok(())
}

/// Fetches and checks the grant record at `uri`, which must grant `pk`. Returns its owner and data.
fn fetch_grant(http: &ureq::Agent, server: &str, uri: &str, pk: &[u8; 32]) -> Result<([u8; 32], GrantData), String> {
    let (owner, path) = fedcrdt::decode_uri(uri).map_err(|e| format!("bad --grant: {e}"))?;
    let mut res = http
        .get(format!("{server}/api/records"))
        .query("owner", fedcrdt::encode_id(&owner))
        .query("prefix", &path)
        .query("type", "grant")
        .call()
        .map_err(|e| format!("couldn't reach {server}: {e}"))?;
    let body = res.body_mut().read_to_vec().map_err(|e| format!("reading the grant: {e}"))?;
    if !res.status().is_success() {
        return Err(format!("couldn't fetch the grant ({}): {}", res.status(), String::from_utf8_lossy(&body)));
    }
    let Cbor::Array(recs) = cbor_decode(&body)? else { return Err("odd answer from the server".into()) };
    let rec = recs
        .into_iter()
        .map(Record::from_cbor)
        .collect::<Result<Vec<_>, _>>()?
        .into_iter()
        .find(|r| r.path == path)
        .ok_or_else(|| format!("there's no grant at {uri}"))?;
    rec.check().map_err(|e| format!("that grant doesn't check out: {e}"))?;
    let g = GrantData::from_cbor(&rec.data)?;
    if &g.grantee != pk {
        return Err(format!("that grant is for {}, not this key", fedcrdt::encode_id(&g.grantee)));
    }
    Ok((owner, g))
}

fn bs58_random() -> String {
    bs58::encode(random::<8>()).into_string()
}

/// The agent's ssh-ed25519 key to use: the one `key_arg` names, or else the first.
fn pick_key(agent: &mut Agent, key_arg: Option<&str>) -> Result<[u8; 32], String> {
    let ids = agent.identities()?;
    let ed: Vec<_> = ids.iter().filter_map(|(blob, comment)| Some((ed25519_from_blob(blob)?, comment))).collect();
    let Some(key_arg) = key_arg else {
        return ed.first().map(|(pk, _)| *pk).ok_or_else(|| {
            format!(
                "the SSH agent has no ssh-ed25519 keys ({} other keys); add one with ssh-add",
                ids.len()
            )
        });
    };
    let line = match std::fs::read_to_string(key_arg) {
        Ok(s) => s,
        Err(_) if key_arg.starts_with("ssh-") => key_arg.to_string(),
        Err(e) => return Err(format!("reading {key_arg}: {e}")),
    };
    let want = line
        .split_whitespace()
        .nth(1)
        .and_then(|b| STANDARD.decode(b).ok())
        .ok_or_else(|| format!("{key_arg} isn't an OpenSSH public key"))?;
    let want = ed25519_from_blob(&want).ok_or("only ssh-ed25519 keys are supported")?;
    ed.iter()
        .find(|(pk, _)| *pk == want)
        .map(|(pk, _)| *pk)
        .ok_or_else(|| "that key isn't in the SSH agent; add it with ssh-add".into())
}

/// The note encryption key: derived (as in web/src/api.ts deriveKeys) from a secret that only this
/// SSH key can produce, its signature over NOTEKEY_MESSAGE. Ed25519 signatures are deterministic.
fn note_key(agent: &mut Agent, pk: &[u8; 32]) -> Result<[u8; 32], String> {
    let secret = Sha256::digest(agent.sign(pk, NOTEKEY_MESSAGE)?);
    let mut key = [0; 32];
    Hkdf::<Sha256>::new(Some(&[]), &secret)
        .expand(b"bisonbase/notes/aes-gcm", &mut key)
        .unwrap();
    Ok(key)
}

/// AES-256-GCM: iv || ciphertext, as seal() in web/src/api.ts.
fn seal(key: &[u8; 32], data: &[u8]) -> Vec<u8> {
    let iv = random::<12>();
    let ct = Aes256Gcm::new_from_slice(key).unwrap().encrypt(&iv.into(), data).unwrap();
    [&iv[..], &ct].concat()
}

fn random<const N: usize>() -> [u8; N] {
    let mut b = [0; N];
    getrandom::fill(&mut b).expect("no randomness");
    b
}

/// A minimal ssh-agent client (draft-miller-ssh-agent): list keys, sign.
struct Agent(UnixStream);

const SSH_AGENT_FAILURE: u8 = 5;
const SSH_AGENTC_REQUEST_IDENTITIES: u8 = 11;
const SSH_AGENT_IDENTITIES_ANSWER: u8 = 12;
const SSH_AGENTC_SIGN_REQUEST: u8 = 13;
const SSH_AGENT_SIGN_RESPONSE: u8 = 14;

impl Agent {
    fn connect() -> Result<Self, String> {
        let path = std::env::var("SSH_AUTH_SOCK").map_err(|_| "no SSH agent: SSH_AUTH_SOCK isn't set")?;
        UnixStream::connect(&path).map(Agent).map_err(|e| format!("couldn't connect to the SSH agent at {path}: {e}"))
    }

    fn request(&mut self, msg: &[u8]) -> Result<Vec<u8>, String> {
        let io = |e: std::io::Error| format!("talking to the SSH agent: {e}");
        let mut framed = Vec::new();
        put_string(&mut framed, msg);
        self.0.write_all(&framed).map_err(io)?;
        let mut len = [0; 4];
        self.0.read_exact(&mut len).map_err(io)?;
        let mut res = vec![0; u32::from_be_bytes(len) as usize];
        self.0.read_exact(&mut res).map_err(io)?;
        Ok(res)
    }

    /// (public key blob, comment) for each key the agent holds.
    fn identities(&mut self) -> Result<Vec<(Vec<u8>, String)>, String> {
        let res = self.request(&[SSH_AGENTC_REQUEST_IDENTITIES])?;
        let bad = || "odd answer from the SSH agent".to_string();
        let (&kind, mut b) = res.split_first().ok_or_else(bad)?;
        if kind != SSH_AGENT_IDENTITIES_ANSWER {
            return Err("the SSH agent wouldn't list its keys".into());
        }
        let n = u32::from_be_bytes(b.get(..4).ok_or_else(bad)?.try_into().unwrap());
        b = &b[4..];
        (0..n)
            .map(|_| {
                let blob = take_string(&mut b).ok_or_else(bad)?.to_vec();
                let comment = String::from_utf8_lossy(take_string(&mut b).ok_or_else(bad)?).into_owned();
                Ok((blob, comment))
            })
            .collect()
    }

    /// A raw Ed25519 signature by `pk` over `data`. (For ssh-ed25519 the agent signs `data` itself,
    /// RFC 8709, then wraps the signature as string "ssh-ed25519", string sig.)
    fn sign(&mut self, pk: &[u8; 32], data: &[u8]) -> Result<[u8; 64], String> {
        let mut msg = vec![SSH_AGENTC_SIGN_REQUEST];
        put_string(&mut msg, &fedcrdt::ed25519_key_blob(pk));
        put_string(&mut msg, data);
        msg.extend_from_slice(&0u32.to_be_bytes()); // flags
        let res = self.request(&msg)?;
        let bad = || "odd signature from the SSH agent".to_string();
        match res.split_first() {
            Some((&SSH_AGENT_SIGN_RESPONSE, mut b)) => {
                let mut blob = take_string(&mut b).ok_or_else(bad)?;
                if take_string(&mut blob) != Some(b"ssh-ed25519") {
                    return Err(bad());
                }
                take_string(&mut blob).and_then(|s| s.try_into().ok()).ok_or_else(bad)
            }
            Some((&SSH_AGENT_FAILURE, _)) => Err("the SSH agent refused to sign (declined, or key locked?)".into()),
            _ => Err("odd answer from the SSH agent".into()),
        }
    }
}
