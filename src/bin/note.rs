//! Posts a note to a bisonbase server, signed (and optionally encrypted) with an ssh-ed25519 key
//! from the local SSH agent. The author ID is the SSH public key itself, so anyone can check it
//! against e.g. https://github.com/<user>.keys.
//!
//!     note [--encrypt] [--key <file.pub | "ssh-ed25519 AAAA…">] <text | -> <server URL>

use aes_gcm::{Aes256Gcm, KeyInit, aead::Aead};
use base64::{
    Engine,
    engine::general_purpose::{STANDARD, URL_SAFE_NO_PAD as B64},
};
use fedcrdt::{NOTE_NAMESPACE, ed25519_from_blob, put_string, sshsig_blob, sshsig_signed_data, take_string, write_payload};
use hkdf::Hkdf;
use serde_json::json;
use sha2::{Digest, Sha256};
use std::{
    io::{Read, Write},
    os::unix::net::UnixStream,
    process::exit,
    time::{SystemTime, UNIX_EPOCH},
};

const USAGE: &str = "usage: note [--encrypt] [--key <file.pub | \"ssh-ed25519 AAAA…\">] <text | -> <server URL>

Signs a note with an ssh-ed25519 key from your SSH agent ($SSH_AUTH_SOCK) and posts it to the server.
Your author ID is that SSH public key. Text \"-\" reads the note from stdin.

  --encrypt   encrypt the note so only this SSH key can read it (the server and others see ciphertext)
  --key       which agent key to use (default: the agent's first ssh-ed25519 key)";

/// Namespace for the signature the note encryption key is derived from. Nothing else may ever ask
/// the key to sign this: that signature *is* the secret.
const NOTEKEY_NAMESPACE: &str = "bisonbase-notekey";
const NOTEKEY_MESSAGE: &[u8] = b"bisonbase keys v1";

fn main() {
    if let Err(e) = run() {
        eprintln!("note: {e}");
        exit(1);
    }
}

fn run() -> Result<(), String> {
    let (mut encrypt, mut key_arg, mut pos) = (false, None, vec![]);
    let mut args = std::env::args().skip(1);
    while let Some(a) = args.next() {
        match a.as_str() {
            "--encrypt" | "-e" => encrypt = true,
            "--key" | "-k" => key_arg = Some(args.next().ok_or("--key needs a value")?),
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

    let mut agent = Agent::connect()?;
    let pk = pick_key(&mut agent, key_arg.as_deref())?;
    let author = fedcrdt::encode_id(&pk);

    let id = B64.encode(random::<16>());
    let version = SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_millis() as i64;
    let (body, wrapped_key) = if encrypt {
        let note_key = note_key(&mut agent, &pk)?;
        let raw = random::<32>();
        (seal(&raw, text.as_bytes()), Some(seal(&note_key, &raw)))
    } else {
        (text.to_string(), None)
    };

    let payload = write_payload(&id, version, Some((encrypt, wrapped_key.as_deref(), &body)));
    let sig = agent.sign(&pk, &sshsig_signed_data(NOTE_NAMESPACE, payload.as_bytes()))?;
    let sig = B64.encode(sshsig_blob(&pk, NOTE_NAMESPACE, &sig));

    let req = json!({ "author": author, "version": version, "body": body, "encrypted": encrypt,
                      "wrapped_key": wrapped_key, "sig": sig });
    let http = ureq::Agent::config_builder().http_status_as_error(false).build().new_agent();
    let mut res = http
        .put(format!("{server}/api/notes/{id}"))
        .send_json(&req)
        .map_err(|e| format!("couldn't reach {server}: {e}"))?;
    if !res.status().is_success() {
        let msg = res.body_mut().read_to_string().unwrap_or_default();
        return Err(format!("server refused the note ({}): {msg}", res.status()));
    }

    println!("posted {}note {id}", if encrypt { "encrypted " } else { "" });
    println!("author {} ({author})", fedcrdt::phrase(&pk));
    println!("       ssh-ed25519 {}", STANDARD.encode(fedcrdt::ed25519_key_blob(&pk)));
    Ok(())
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
/// SSH key can produce, its signature over a fixed message. Ed25519 signatures are deterministic.
fn note_key(agent: &mut Agent, pk: &[u8; 32]) -> Result<[u8; 32], String> {
    let sig = agent.sign(pk, &sshsig_signed_data(NOTEKEY_NAMESPACE, NOTEKEY_MESSAGE))?;
    let mut s = &sig[..];
    let raw = take_string(&mut s).and(take_string(&mut s)).ok_or("odd signature from the agent")?;
    let secret = Sha256::digest(raw);
    let mut key = [0; 32];
    Hkdf::<Sha256>::new(Some(&[]), &secret)
        .expand(b"bisonbase/notes/aes-gcm", &mut key)
        .unwrap();
    Ok(key)
}

/// AES-256-GCM: base64url(iv || ciphertext), as seal() in web/src/api.ts.
fn seal(key: &[u8; 32], data: &[u8]) -> String {
    let iv = random::<12>();
    let ct = Aes256Gcm::new_from_slice(key).unwrap().encrypt(&iv.into(), data).unwrap();
    B64.encode([&iv[..], &ct].concat())
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

    /// The agent's signature blob (string "ssh-ed25519", string sig) by `pk` over `data`.
    fn sign(&mut self, pk: &[u8; 32], data: &[u8]) -> Result<Vec<u8>, String> {
        let mut msg = vec![SSH_AGENTC_SIGN_REQUEST];
        put_string(&mut msg, &fedcrdt::ed25519_key_blob(pk));
        put_string(&mut msg, data);
        msg.extend_from_slice(&0u32.to_be_bytes()); // flags
        let res = self.request(&msg)?;
        match res.split_first() {
            Some((&SSH_AGENT_SIGN_RESPONSE, mut b)) => {
                take_string(&mut b).map(<[u8]>::to_vec).ok_or("odd signature from the SSH agent".into())
            }
            Some((&SSH_AGENT_FAILURE, _)) => Err("the SSH agent refused to sign (declined, or key locked?)".into()),
            _ => Err("odd answer from the SSH agent".into()),
        }
    }
}
