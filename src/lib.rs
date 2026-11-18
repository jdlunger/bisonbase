//! Code shared by the server and the `note` CLI.

use ed25519_dalek::{Signature, VerifyingKey};
use sha2::{Digest, Sha512};

/// The exact bytes a note write's signature covers. Keep in sync with writePayload in web/src/api.ts.
/// `put` is `(encrypted, wrapped_key, body)`; `None` is a delete.
pub fn write_payload(id: &str, version: i64, put: Option<(bool, Option<&str>, &str)>) -> String {
    let head = format!("bisonbase-note-v2\n{id}\n{version}");
    match put {
        None => format!("{head}\ndelete"),
        Some((encrypted, wrapped_key, body)) => format!(
            "{head}\nput\n{}\n{}\n{body}",
            if encrypted { "encrypted" } else { "plain" },
            wrapped_key.unwrap_or(""),
        ),
    }
}

// ---- SSH signatures (SSHSIG, as made by `ssh-keygen -Y sign`) ----
//
// Users with SSH keys sign note writes in OpenSSH's SSHSIG format, under this namespace, so their
// ID is their ssh-ed25519 public key (verifiable against e.g. github.com/<user>.keys), and so the
// signatures can't be mistaken for SSH logins, git commits, or anything else that key signs.
// See https://github.com/openssh/openssh-portable/blob/master/PROTOCOL.sshsig

/// Namespace for note write signatures.
pub const NOTE_NAMESPACE: &str = "bisonbase-note";

const SSHSIG_MAGIC: &[u8] = b"SSHSIG";

/// SSH wire format: a byte string with a u32 big-endian length prefix.
pub fn put_string(out: &mut Vec<u8>, s: &[u8]) {
    out.extend_from_slice(&(s.len() as u32).to_be_bytes());
    out.extend_from_slice(s);
}

/// Reads an SSH wire-format string from the front of `buf`.
pub fn take_string<'a>(buf: &mut &'a [u8]) -> Option<&'a [u8]> {
    let len = u32::from_be_bytes(buf.get(..4)?.try_into().ok()?) as usize;
    let s = buf.get(4..4 + len)?;
    *buf = &buf[4 + len..];
    Some(s)
}

/// An ssh-ed25519 public key blob (as in authorized_keys, base64-decoded) for a raw 32-byte key.
pub fn ed25519_key_blob(pk: &[u8; 32]) -> Vec<u8> {
    let mut b = Vec::new();
    put_string(&mut b, b"ssh-ed25519");
    put_string(&mut b, pk);
    b
}

/// The raw 32-byte key in an ssh-ed25519 public key blob; None for other key types.
pub fn ed25519_from_blob(mut blob: &[u8]) -> Option<[u8; 32]> {
    if take_string(&mut blob)? != b"ssh-ed25519" {
        return None;
    }
    let pk = take_string(&mut blob)?.try_into().ok()?;
    blob.is_empty().then_some(pk)
}

/// The bytes the key actually signs for an SSHSIG signature over `msg` (SHA-512 hashed).
pub fn sshsig_signed_data(namespace: &str, msg: &[u8]) -> Vec<u8> {
    let mut d = SSHSIG_MAGIC.to_vec();
    put_string(&mut d, namespace.as_bytes());
    put_string(&mut d, b""); // reserved
    put_string(&mut d, b"sha512");
    put_string(&mut d, &Sha512::digest(msg));
    d
}

/// The binary SSHSIG blob (what `ssh-keygen -Y sign` armors) for an ssh-ed25519 signature.
/// `sig_blob` is the signature as the agent returns it: string "ssh-ed25519", string sig.
pub fn sshsig_blob(pk: &[u8; 32], namespace: &str, sig_blob: &[u8]) -> Vec<u8> {
    let mut b = SSHSIG_MAGIC.to_vec();
    b.extend_from_slice(&1u32.to_be_bytes());
    put_string(&mut b, &ed25519_key_blob(pk));
    put_string(&mut b, namespace.as_bytes());
    put_string(&mut b, b"");
    put_string(&mut b, b"sha512");
    put_string(&mut b, sig_blob);
    b
}

/// Is this (decoded) signature an SSHSIG blob rather than a bare 64-byte Ed25519 signature?
pub fn is_sshsig(sig: &[u8]) -> bool {
    sig.starts_with(SSHSIG_MAGIC)
}

/// Checks an SSHSIG blob: signed by `pk` (ssh-ed25519), under `namespace`, over `msg`.
pub fn verify_sshsig(pk: &[u8; 32], namespace: &str, msg: &[u8], sig: &[u8]) -> Result<(), String> {
    let bad = || "malformed SSH signature".to_string();
    let mut b = sig.strip_prefix(SSHSIG_MAGIC).ok_or_else(bad)?;
    if b.get(..4) != Some(&1u32.to_be_bytes()[..]) {
        return Err("unsupported SSH signature version".into());
    }
    b = &b[4..];
    let key = take_string(&mut b).ok_or_else(bad)?;
    if ed25519_from_blob(key).as_ref() != Some(pk) {
        return Err("SSH signature is by a different key than the author".into());
    }
    if take_string(&mut b).ok_or_else(bad)? != namespace.as_bytes() {
        return Err(format!("SSH signature isn't for the {namespace:?} namespace"));
    }
    let reserved = take_string(&mut b).ok_or_else(bad)?;
    if take_string(&mut b).ok_or_else(bad)? != b"sha512" {
        return Err("only sha512 SSH signatures are supported".into());
    }
    let mut inner = take_string(&mut b).ok_or_else(bad)?;
    if !b.is_empty() || take_string(&mut inner).ok_or_else(bad)? != b"ssh-ed25519" {
        return Err(bad());
    }
    let raw: [u8; 64] = take_string(&mut inner).and_then(|s| s.try_into().ok()).ok_or_else(bad)?;
    if !inner.is_empty() {
        return Err(bad());
    }

    let mut data = SSHSIG_MAGIC.to_vec();
    put_string(&mut data, namespace.as_bytes());
    put_string(&mut data, reserved);
    put_string(&mut data, b"sha512");
    put_string(&mut data, &Sha512::digest(msg));
    let pk = VerifyingKey::from_bytes(pk).map_err(|e| e.to_string())?;
    pk.verify_strict(&data, &Signature::from_bytes(&raw)).map_err(|_| "signature doesn't match".to_string())
}
