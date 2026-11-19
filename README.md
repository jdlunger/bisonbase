# federated crdt

Simple Rust web server that:
 - Serves a React + Tailwind SPA
 - Uses SQLite (users, notes); no sessions: every write is signed by its author
 - On main page, offers A) a list of all users (if any) and B) "Derive keys: [with new passkey] [with existing passkey]"; once derived, shows "Keys loaded (<word phrase>)" with the same buttons to derive different keys. If deriving fails, tells the user and suggests a new passkey
 - No sign-in: the passkey is only used, client-side, to derive the user's keys
 - Identifies users only by an Ed25519 public key derived from their passkey (via the WebAuthn PRF extension; nobody without the passkey can derive the private key). The passkey flow runs entirely client-side; the server never sees the passkey and has no sign-in flow
 - For human convenience, when listing users, displays both their derived public key (their main ID, in base58: letters and digits only, so a double-click selects it), along with a unique deterministic english phrase, built from the word list in this repo (thank you to https://github.com/first20hours/google-10000-english), e.g. "river_candle_oak_thirty".
 - Allows each user to record text notes, and view others'
 - Each note is always signed (every create / edit / delete is a signed, versioned write; the newest version wins, and deletes leave tombstones) and can optionally be e2e encrypted, using keys only derivable with the passkey - checkbox below note
 - Keys (signing + encryption, all derived from one PRF secret) live in memory; an opt-in "remember keys on this device" toggle stores the secret in localStorage so it survives reloads

## Run

```
cargo build
npm install
npm run dev
```

When modifying schema, to drop DB on each run:

```
npm run dev:fresh
```

### Post via CLI

```
eval "$(ssh-agent -s)"
ssh-add ~/.ssh/id_ed25519
cargo run --bin note -- --encrypt "remember the milk" http://localhost:8080
```
