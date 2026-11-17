export type User = { pubkey: string; phrase: string };

async function api<T>(path: string, body?: unknown): Promise<T> {
  const res = await fetch(
    path,
    body === undefined
      ? {}
      : { method: "POST", headers: { "content-type": "application/json" }, body: JSON.stringify(body) },
  );
  if (!res.ok) throw new Error(await res.text());
  return (res.status === 204 ? null : await res.json()) as T;
}

export const getMe = () => api<User | null>("/api/me");
export const getUsers = () => api<User[]>("/api/users");
export const logout = () => api<null>("/api/logout", {});

export async function register() {
  const { id, options } = await api<{ id: string; options: any }>("/api/register/start", {});
  const publicKey = options.publicKey;
  publicKey.authenticatorSelection = {
    ...publicKey.authenticatorSelection,
    residentKey: "required",
    requireResidentKey: true,
  };
  const cred = (await navigator.credentials.create({
    publicKey: PublicKeyCredential.parseCreationOptionsFromJSON(publicKey),
  })) as PublicKeyCredential;
  await api("/api/register/finish", { id, credential: cred.toJSON() });
}

export async function signIn() {
  try {
    const { id, options } = await api<{ id: string; options: any }>("/api/login/start", {});
    const cred = (await navigator.credentials.get({
      publicKey: PublicKeyCredential.parseRequestOptionsFromJSON(options.publicKey),
    })) as PublicKeyCredential;
    await api("/api/login/finish", { id, credential: cred.toJSON() });
  } catch (e) {
    throw new Error(
      `Couldn't sign in with an existing passkey (${(e as Error).message}). If you don't have one for this site yet, use "Create new passkey".`,
    );
  }
}
