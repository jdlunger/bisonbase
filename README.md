# federated crdt

Simple Rust web server that:
 - Serves a React + Tailwind SPA
 - Uses SQLite (users, records); no sessions: every write is signed by its author
 - On main page, offers A) a list of all users (if any) and B) "Derive keys: [with new passkey] [with existing passkey]"; once derived, shows "Keys loaded (<word phrase>)" with the same buttons to derive different keys. If deriving fails, tells the user and suggests a new passkey
 - No sign-in: the passkey is only used, client-side, to derive the user's keys
 - Identifies users only by an Ed25519 public key derived from their passkey (via the WebAuthn PRF extension; nobody without the passkey can derive the private key). The passkey flow runs entirely client-side; the server never sees the passkey and has no sign-in flow
 - For human convenience, when listing users, displays both their derived public key (their main ID, in base58: letters and digits only, so a double-click selects it), along with a unique deterministic english phrase, built from the word list in this repo (thank you to https://github.com/first20hours/google-10000-english), e.g. "river_candle_oak_thirty".
 - Everything users write is a **record**: a deterministic-CBOR map (RFC 8949 §4.2.1) with `author`, `owner`, `path`, `version`, `type`, `data`, optional `authorization`, and the author's Ed25519 `signature` over the rest (field details in `src/lib.rs`). Records are passed around and stored exactly as signed
 - Each user has a space, shown as one tree on their ID page (with what they wrote in others' spaces): a record lives at `bb://<owner ID><path>`, e.g. `bb://4E8C…/posts/hello`. Per (owner, path) the newest version wins; deletes are signed `tombstone` records
 - Types so far: `post` (text), `grant` and `tombstone`
 - Owners can sign a **grant** letting another user write at or under a path in their space, saved as a `grant` record (under `/grants`). The grantee picks it when posting, and their records carry its signature as their `authorization`. Grants can't be revoked yet
 - The signing key (derived from one PRF secret) lives in memory; an opt-in "remember keys on this device" toggle stores the secret in localStorage so it survives reloads

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
