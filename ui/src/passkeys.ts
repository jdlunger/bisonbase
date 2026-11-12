// Passkey ceremonies: the server sends WebAuthn options as JSON (binary fields base64url),
// the browser's authenticator answers, and the answer goes back as JSON.

import { post } from './api.ts'

const b64uToBuf = (s: string): ArrayBuffer => {
  s = s.replace(/-/g, '+').replace(/_/g, '/')
  while (s.length % 4) s += '='
  return Uint8Array.from(atob(s), (c) => c.charCodeAt(0)).buffer
}

const bufToB64u = (buf: ArrayBuffer): string =>
  btoa(String.fromCharCode(...new Uint8Array(buf)))
    .replace(/\+/g, '-')
    .replace(/\//g, '_')
    .replace(/=+$/, '')

// The server's options, with base64url strings where the browser wants buffers.
type Json = any // eslint-disable-line @typescript-eslint/no-explicit-any

interface Started {
  ceremony: string
  options: { publicKey: Json }
}

function requireWebAuthn() {
  if (!window.PublicKeyCredential) {
    throw new Error('This browser does not support passkeys (or the page is not served over HTTPS/localhost).')
  }
}

async function create(opts: Started['options']): Promise<Json> {
  const pk = structuredClone(opts.publicKey)
  pk.challenge = b64uToBuf(pk.challenge)
  pk.user.id = b64uToBuf(pk.user.id)
  for (const c of pk.excludeCredentials ?? []) c.id = b64uToBuf(c.id)
  const cred = (await navigator.credentials.create({ publicKey: pk })) as PublicKeyCredential
  const r = cred.response as AuthenticatorAttestationResponse
  return {
    id: cred.id,
    rawId: bufToB64u(cred.rawId),
    type: cred.type,
    extensions: cred.getClientExtensionResults?.() ?? {},
    response: {
      attestationObject: bufToB64u(r.attestationObject),
      clientDataJSON: bufToB64u(r.clientDataJSON),
      transports: r.getTransports?.() ?? [],
    },
  }
}

async function assert(opts: Started['options']): Promise<Json> {
  const pk = structuredClone(opts.publicKey)
  pk.challenge = b64uToBuf(pk.challenge)
  for (const c of pk.allowCredentials ?? []) c.id = b64uToBuf(c.id)
  const cred = (await navigator.credentials.get({ publicKey: pk })) as PublicKeyCredential
  const r = cred.response as AuthenticatorAssertionResponse
  return {
    id: cred.id,
    rawId: bufToB64u(cred.rawId),
    type: cred.type,
    extensions: cred.getClientExtensionResults?.() ?? {},
    response: {
      authenticatorData: bufToB64u(r.authenticatorData),
      clientDataJSON: bufToB64u(r.clientDataJSON),
      signature: bufToB64u(r.signature),
      userHandle: r.userHandle ? bufToB64u(r.userHandle) : null,
    },
  }
}

interface Done {
  redirect?: string
}

/** Create an account with a new passkey. */
export async function signup(username: string, invite: string | null): Promise<Done> {
  requireWebAuthn()
  const start = await post<Started>('/auth/register/start', { username, invite })
  const credential = await create(start.options)
  return post<Done>('/auth/register/finish', { ceremony: start.ceremony, credential })
}

export async function login(username: string): Promise<void> {
  requireWebAuthn()
  const start = await post<Started>('/auth/login/start', { username })
  const credential = await assert(start.options)
  await post('/auth/login/finish', { ceremony: start.ceremony, credential })
}

/** Add another passkey to the logged-in account. */
export async function addPasskey(name: string): Promise<void> {
  requireWebAuthn()
  const start = await post<Started>('/auth/passkeys/add/start', { name })
  const credential = await create(start.options)
  await post('/auth/passkeys/add/finish', { ceremony: start.ceremony, credential })
}

/** Add a passkey with a recovery link's token. */
export async function recover(token: string): Promise<Done> {
  requireWebAuthn()
  const start = await post<Started>('/auth/recover/start', { token })
  const credential = await create(start.options)
  return post<Done>('/auth/recover/finish', { ceremony: start.ceremony, credential })
}

/** A ceremony's error, as shown to the user. */
export const ceremonyError = (e: Error) => (e.name === 'NotAllowedError' ? 'Cancelled or timed out.' : e.message)
