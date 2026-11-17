# federated crdt

Simple Rust web server that:
 - Serves a React + Tailwind SPA
 - Uses SQLite (users, sessions)
 - On main page, offers A) a list of all users (if any) and B) "create new passkey" and "sign in with existing passkey" buttons (or says already signed in); if sign-in fails, tells the user and suggests creating a new one
 - Allows users to sign in with passkey only
 - Identifies users only by their passkey's public key
 - For human convenience, when listing users, displays both their passkey's public key (their main ID), along with a unique deterministic english phrase, built from the word list in this repo (thank you to https://github.com/first20hours/google-10000-english), e.g. "river_candle_oak_thirty".
 - Allows each user to record text notes, and view others'

## Run

```
npm install
npm run dev
```