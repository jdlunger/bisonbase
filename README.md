# federated crdt

Simple Rust web server that:
 - Serves a React + Tailwind SPA
 - Uses SQLite (users, notes); no sessions: every write is signed by its author
 - On main page, offers A) a list of all users (if any) and B) "Derive keys: [with new passkey] [with existing passkey]"; once derived, shows "Keys loaded (<word phrase>)" with the same buttons to derive different keys. If deriving fails, tells the user and suggests a new passkey
 - No sign-in: the passkey is only used, client-side, to derive the user's keys
 - Identifies users only by an Ed25519 public key derived from their passkey (via the WebAuthn PRF extension; nobody without the passkey can derive the private key). The passkey flow runs entirely client-side; the server never sees the passkey and has no sign-in flow
 - For human convenience, when listing users, displays both their derived public key (their main ID), along with a unique deterministic english phrase, built from the word list in this repo (thank you to https://github.com/first20hours/google-10000-english), e.g. "river_candle_oak_thirty".
 - Allows each user to record text notes, and view others'
 - Each note is always signed (every create / edit / delete is a signed, versioned write; the newest version wins, and deletes leave tombstones) and can optionally be e2e encrypted, using keys only derivable with the passkey - checkbox below note
 - Keys (signing + encryption, all derived from one PRF secret) live in memory; an opt-in "remember keys on this device" toggle stores the secret in localStorage so it survives reloads

## Run

```
cargo build
npm install
npm run dev
```

## Posting from the command line with an SSH key

`note` signs a note with an `ssh-ed25519` key from your SSH agent and posts it to a server:

```
cargo run --bin note -- "remember the milk" http://localhost:8080
echo "for my eyes only" | cargo run --bin note -- --encrypt - http://localhost:8080
cargo run --bin note -- --key ~/.ssh/work_ed25519.pub "hi" http://localhost:8080
```

- The author ID is the SSH public key itself (its 32 raw bytes, base64url), so anyone can match it against e.g. `https://github.com/<user>.keys`.
- Writes are signed in OpenSSH's SSHSIG format under the namespace `bisonbase-note`, so they can't be confused with SSH logins or git commit signatures. The server and the web app verify both these and the passkey users' bare Ed25519 signatures. To check one with OpenSSH alone, write the note's `sig` as an armored `-----BEGIN SSH SIGNATURE-----` block (standard base64) and run `ssh-keygen -Y verify -f allowed_signers -I <name> -n bisonbase-note -s note.sig < payload`, where `payload` is the signed text (see `write_payload` in `src/lib.rs`) and `allowed_signers` holds `<name> ssh-ed25519 AAAA…` lines from GitHub.
- `--encrypt` encrypts the note so only that SSH key can read it: the note key is derived from the key's (deterministic) signature over a fixed message under the namespace `bisonbase-notekey`, which nothing else should ever be asked to sign. The browser can't read these, since it has no access to your SSH agent.
- Only `ssh-ed25519` keys are supported (not RSA, ECDSA or hardware `sk-` keys).
