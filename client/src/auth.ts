// "Sign in with bisonbase": the OAuth 2.1 authorization code flow with PKCE, in the browser.

const base64url = (bytes: Uint8Array) =>
  btoa(String.fromCharCode(...bytes)).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '')
const randomString = () => base64url(crypto.getRandomValues(new Uint8Array(32)))
const sha256 = async (s: string) =>
  base64url(new Uint8Array(await crypto.subtle.digest('SHA-256', new TextEncoder().encode(s))))

/** A sign-in in progress, kept in sessionStorage across the redirect. */
interface Flow {
  state: string
  verifier: string
  server: string
  back: string // where to return to in the app afterwards
}

export interface AuthConfig {
  server: string
  appId: string
  appName: string
  scope: string
}

const FLOW_KEY = 'bisonbase:sign-in'
// An app is identified by its origin, and bisonbase sends the user back to the current page.
const clientId = () => location.origin
const redirectUri = () => location.origin + location.pathname

/** Send the browser to bisonbase to sign in. */
export async function startSignIn(cfg: AuthConfig): Promise<void> {
  const flow: Flow = {
    state: randomString(),
    verifier: randomString(),
    server: cfg.server,
    back: location.pathname + location.search + location.hash,
  }
  sessionStorage.setItem(FLOW_KEY, JSON.stringify(flow))
  const params = new URLSearchParams({
    response_type: 'code',
    client_id: clientId(),
    redirect_uri: redirectUri(),
    scope: cfg.scope,
    state: flow.state,
    code_challenge: await sha256(flow.verifier),
    code_challenge_method: 'S256',
    app_id: cfg.appId,
    app_name: cfg.appName,
  })
  location.assign(`${cfg.server}/oauth/authorize?${params}`)
}

/**
 * If bisonbase just sent the browser back here, take the response out of the address bar
 * (synchronously, before the app renders) and return a promise for the token.
 */
export function takeSignInResponse(server: string): Promise<string> | null {
  if (typeof location === 'undefined' || typeof sessionStorage === 'undefined') return null
  const params = new URLSearchParams(location.search)
  const saved = sessionStorage.getItem(FLOW_KEY)
  if (!saved || !params.has('state')) return null
  const flow: Flow = JSON.parse(saved)
  if (flow.server !== server || params.get('state') !== flow.state) return null
  sessionStorage.removeItem(FLOW_KEY)
  history.replaceState(history.state, '', flow.back) // drop ?code=... from the address bar
  return exchange(server, flow, params)
}

async function exchange(server: string, flow: Flow, params: URLSearchParams): Promise<string> {
  if (params.get('iss') !== server) throw new Error("Sign-in failed: the response didn't come from the expected server.")
  if (params.get('error') === 'access_denied') throw new Error('Sign-in was cancelled.')
  if (params.has('error')) throw new Error(`Sign-in failed: ${params.get('error_description') ?? params.get('error')}`)
  const res = await fetch(`${server}/oauth/token`, {
    method: 'POST',
    body: new URLSearchParams({
      grant_type: 'authorization_code',
      code: params.get('code') ?? '',
      client_id: clientId(),
      redirect_uri: redirectUri(),
      code_verifier: flow.verifier,
    }),
  })
  const json = await res.json().catch(() => ({}))
  if (!res.ok) throw new Error(`Sign-in failed: ${json.error_description ?? json.error ?? res.statusText}`)
  return json.access_token
}

/** Revoke a token on the server. Failures are ignored: the token is forgotten locally anyway. */
export async function revoke(server: string, token: string): Promise<void> {
  await fetch(`${server}/oauth/revoke`, { method: 'POST', body: new URLSearchParams({ token }) }).catch(() => {})
}
