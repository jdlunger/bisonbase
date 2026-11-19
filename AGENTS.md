Never start claude/ branches.

We're in prototype phase - do not add any migration or legacy handling code. When DB schema updates, just mention I need to drop the DB.

Store raw bytes (public keys, signatures, …), never their text encodings. base58 (IDs), base64url and
word phrases are only for input and output, at the edges: API, URLs, UI, CLI.
