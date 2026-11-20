# federated crdt

Simple Rust web server (a **node**) that:
 - Serves a React + Tailwind SPA
 - Shares one Rust core (`core/`: record format, signing, checks, IDs and phrases) between the node and the SPA, which loads it as wasm (`wasm/`)
 - Uses SQLite (users, records); no sessions: every write is signed by its author
 - On main page, offers A) a list of all users (if any) and B) "Derive keys: [with new passkey] [with existing passkey]"; once derived, shows "Keys loaded (<word phrase>)" with the same buttons to derive different keys. If deriving fails, tells the user and suggests a new passkey
 - No sign-in: the passkey is only used, client-side, to derive the user's keys
 - Identifies users only by an Ed25519 public key derived from their passkey (via the WebAuthn PRF extension; nobody without the passkey can derive the private key). The passkey flow runs entirely client-side; the node never sees the passkey and has no sign-in flow
 - For human convenience, when listing users, displays both their derived public key (their main ID, in base58: letters and digits only, so a double-click selects it), along with a unique deterministic english phrase, built from the word list in this repo (thank you to https://github.com/first20hours/google-10000-english), e.g. "🦬river_candle".
 - Everything users write is a **record**: a [dCBOR](https://datatracker.ietf.org/doc/draft-mcnally-deterministic-cbor/) (deterministic CBOR) map with `author`, `path`, `version`, `type`, `data`, optional `edits`, and the author's Ed25519 `signature` over the rest (field details in `core/src/lib.rs`). Records are passed around and stored exactly as signed
 - A record is identified by its hash (SHA-256 of its bytes), linked as `/r/<hash>`. Records never change: an edit or delete (`tombstone`) is a new record whose `edits` names the version it replaces. A record and its edits form a chain; the newest version wins, a tombstone anywhere deletes it, and every version stays viewable
 - Paths (e.g. `/posts/dogs`) are only categories: they're not unique and say nothing about ownership. `/posts/dogs` in the app lists everything at or under it
 - Types so far: `post` (text), `tombstone`, and the node types below
 - Each **node** has its own key and keeps its own records under `/node`, which are never federated: `/node/info` (its URL), `/node/owner` (one per owner), `/node/grants` and `/node/federate`. Whoever opens the one-time claim link the node prints becomes its first owner; owners can add and remove owners (not the last one), write anywhere, and edit or delete any record. A **grant** lets a list of users, or anyone, write at or under a path. Authors can edit and delete their own records. A node checks all of this for records written to it; records pushed by peers are taken as they are. Grants can't be revoked yet
 - A **federate** record has the node push new records to a peer node, optionally only some types and paths
 - The signing key (derived from one PRF secret) lives in memory; an opt-in "remember keys on this device" toggle stores the secret in localStorage so it survives reloads

## Run

Needs `rustup target add wasm32-unknown-unknown` and `cargo install wasm-pack` once.

```
cargo build
npm install
npm run dev
```

When modifying schema, to drop DB on each run:

```
npm run dev:fresh
```

## Future Ideas

 - Link share flow: "share" record signed by user with a random token (hidden, not federated), and when someone opens that token, the node signs a "claim" record
   - Prior to link usage, user can grant things to the future user
   - But, random token can't be public, so maybe a reference to that record
 - Blobs (images, files?)
 - Feed control: pick what users appear on your feed
 - Vouching: record stating another user is useful to listen to (is human, or at least doesn't spam, etc.)
 - Shared encryption (generate key, encrypt that key to share with other users, one record per user)
 - Applications to build
   - Social network - without API, just plain text & replies?
   - Shared documents