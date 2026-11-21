#!/usr/bin/env bash
# Starts a node on a fresh database, runs the client library's integration test against it, and stops it.
set -euo pipefail
cd "$(dirname "$0")/../.."
port=${PORT:-8099}
dir=$(mktemp -d)
log="$dir/node.log"
cargo build -q
DB="$dir/test.db" PORT=$port ORIGIN=http://web.test PUBLIC_URL=http://localhost:$port ./target/debug/fedcrdt >"$log" 2>&1 &
pid=$!
trap 'kill $pid 2>/dev/null; rm -rf "$dir"' EXIT
for _ in $(seq 50); do grep -q "claim#" "$log" && break; sleep 0.1; done
token=$(grep -o 'claim#[1-9A-HJ-NP-Za-km-z]*' "$log" | head -1 | cut -d'#' -f2)
NODE_URL=http://localhost:$port CLAIM_TOKEN=$token node --experimental-strip-types --experimental-eventsource --no-warnings client/test/integration.ts
