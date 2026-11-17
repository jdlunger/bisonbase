export type User = { pubkey: string; phrase: string };
export type Note = { id: number; author: User; body: string; created_at: number; updated_at: number };

async function api<T>(path: string, body?: unknown, method = body === undefined ? "GET" : "POST"): Promise<T> {
  const res = await fetch(
    path,
    body === undefined
      ? { method }
      : { method, headers: { "content-type": "application/json" }, body: JSON.stringify(body) },
  );
  if (!res.ok) throw new Error((await res.text()) || res.statusText);
  return (res.status === 204 ? null : await res.json()) as T;
}

export const getMe = () => api<User | null>("/api/me");
export const getUsers = () => api<User[]>("/api/users");
export const logout = () => api<null>("/api/logout", {});

export const getNotes = () => api<Note[]>("/api/notes");
export const createNote = (body: string) => api<null>("/api/notes", { body });
export const updateNote = (id: number, body: string) => api<null>(`/api/notes/${id}`, { body }, "PUT");
export const deleteNote = (id: number) => api<null>(`/api/notes/${id}`, undefined, "DELETE");

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
