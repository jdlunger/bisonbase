# federated crdt

A full stack web app exploring ideas around identity, sharing, & federation.

## Run

Install [Node](https://github.com/nvm-sh/nvm#install--update-script) & [Rust](https://rust-lang.org/tools/install/).

```
cargo install wasm-pack
rustup target add wasm32-unknown-unknown
cargo build
npm install
npm run dev
npm run dev:fresh # drop db
```

## Deploy

```
cargo install cargo-zigbuild
rustup target add x86_64-unknown-linux-musl aarch64-unknown-linux-musl
npm run build:release
npm run build:linux-arm64
```

On the server, point the domain's DNS at it, open ports 80 and 443, and run:

```
DOMAIN=example.com ./fedcrdt
```

It serves HTTPS on 443 and redirects 80 to it. The first start prints the link to claim the node. The database
(`bb.db`) and certificates (`certs/`) are kept next to the binary. `ACME_STAGING=1` uses Let's Encrypt's staging
certificates (untrusted, but no rate limits) for trying a setup out. Binding 80 and 443 as a non-root user needs `AmbientCapabilities=CAP_NET_BIND_SERVICE` (systemd) or
`setcap cap_net_bind_service=+ep fedcrdt`. Back up the database: it holds the node's key, not only its records.

Without `DOMAIN`, it serves plain HTTP on `PORT` (default 8080), for running behind another proxy (set `PUBLIC_URL`).

## Building apps on it

Any app can keep its data on a node, as records of its own types (namespaced, e.g. `todo.item`) or as CRDT docs in any format and schema (e.g. Yjs, `myapp.board`), through the client library in `client/`. Apps on other origins sign with their own key, which the user lets sign for them at `/connect`. Docs can be encrypted, so that nodes only ever see ciphertext. See [client/README.md](client/README.md).

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
   - Add apps by dropping static html/assets into a folder next to server binary

## Model & logic (human written)

 - Each server instance is a node, which holds users & records.
 - Users and nodes have a public/private key pair, identified by their public key. In URLs and for copying and pasting, keys are base58 encoded. For users, the key is shown as an English_snake_case_phrase, generated from 10k word list:
   - Users (emoji prefix): 🦬two_words
   - Nodes: node_word
 - Each server has 1 or more owners: users identified by a node owner record.
 - Every record is signed by either a user or the node, and goes at a categorical path.
 - Every record is public or private (a signed `private` flag, chosen by its author; edits can change it). Private records can only be read by the node's owners, who prove who they are with a short-lived signed read token, and are never pushed to peers.
   - /node/owner contains all owner records.
   - /node/grant contains all user authorization grant records (e.g. anyone can create a record under /post)
   - /node/peer contains all node peer federation records (other server instances to push records to)
   - Claims, which can live anywhere, are one-time-use token records, which can be pointed to to grant permissions to an as-of-yet-unknown user. The tokens in these records are set by the author and never shared by the server, although the existence of them is known. On claim, they are edited to reference the claiming user.
   - /node/info has a "node" record listing info (just URL for now).
   - /node records are not federated / pushed to other servers.
   - Other paths will be usage & applicaton specific - for now, we have /post (use singular!) for random text posts.
 - Things can be shared & claimed via link with a "claim" record, which contains a random secret token to be shared. When someone opens the node with that token, the node creates & signs a new version of that claim record. The token is kept hidden, and claim records are never sent to peers.
   - This process enables a user to become the first owner: when a node first starts up / creates a fresh DB, it creates two records: a claim record, and an owner record pointing at that claim record. The node prints the claim link in the server logs for an administrator to claim and set their user as the owner.
