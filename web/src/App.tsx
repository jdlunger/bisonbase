import { useCallback, useEffect, useState } from "react";
import {
  type Note,
  type Passkey,
  type User,
  getNotes,
  getUsers,
  isRemembering,
  forgetKeys,
  forgetRecentPasskey,
  myPasskey,
  recentPasskeys,
  myPubkey,
  putNote,
  deriveFromNewPasskey,
  restoreKeys,
  setRemember,
  deriveFromExistingPasskey,
  userPhrase,
} from "./api.ts";
import Identity from "./Identity.tsx";
import { type Draft, NoteEditor, NoteList } from "./NoteList.tsx";
import { Link, idPath, usePath } from "./router.tsx";
import { type Run, link, primary, secondary } from "./ui.ts";

/** A forged note, added client-side to the bottom of the list to show what a bad signature looks like. */
const FORGED_NOTE: Note = {
  id: "forged-demo-note",
  author: { pubkey: "4zvwRjXUKGfvwnParsHAS3HuSVzV5cA4McphgmoCtajS", phrase: "forged_signature_demo_note" },
  version: 1,
  body: "This note was added client-side with a made-up signature, so it should show as a bad signature.",
  encrypted: false,
  wrapped_key: null,
  sig: "A".repeat(86),
  created_at: Math.floor(Date.now() / 1000),
  updated_at: Math.floor(Date.now() / 1000),
};

// The composer's Encrypt choice persists across visits.
const OPTS_KEY = "note-opts";
function loadEncrypt() {
  try {
    return !!JSON.parse(localStorage.getItem(OPTS_KEY) ?? "{}").encrypt;
  } catch {
    return false;
  }
}
function saveEncrypt(encrypt: boolean) {
  try {
    localStorage.setItem(OPTS_KEY, JSON.stringify({ encrypt }));
  } catch {}
}

/** Routes: "/" is Home, "/id/<pubkey>" an identity page. Remembered keys load first, for both. */
export default function App() {
  const path = usePath();
  /** undefined while loading remembered keys; then the error restoring them, if any. */
  const [restoreError, setRestoreError] = useState<string | null>();
  useEffect(() => {
    restoreKeys().then(
      () => setRestoreError(null),
      (e) => setRestoreError(`Couldn't restore remembered keys: ${e.message}`),
    );
  }, []);
  if (restoreError === undefined) return null;
  const id = path.match(/^\/id\/([^/]+)\/?$/);
  return id ? <Identity pubkey={decodeURIComponent(id[1])} /> : <Home initialError={restoreError} />;
}

function Home({ initialError }: { initialError: string | null }) {
  const [me, setMe] = useState<User | null>(null);
  const [users, setUsers] = useState<User[] | null>(null);
  const [notes, setNotes] = useState<Note[] | null>(null);
  const [error, setError] = useState(initialError ?? "");
  const [busy, setBusy] = useState(false);
  const [draft, setDraftState] = useState<Draft>(() => ({ body: "", encrypt: loadEncrypt() }));
  const setDraft = (d: Draft) => {
    setDraftState(d);
    saveEncrypt(d.encrypt);
  };
  const [remember, setRememberState] = useState(isRemembering);
  /** The passkey the loaded keys came from, and others used on this device recently (with their keys' phrases). */
  const [passkey, setPasskey] = useState<Passkey | null>(null);
  const [recent, setRecent] = useState<(Passkey & { phrase: string })[]>([]);

  const refresh = useCallback(async () => {
    const pubkey = myPubkey();
    const current = myPasskey();
    const others = recentPasskeys().filter((p) => p.credId !== current?.credId);
    const [m, u, n, phrases] = await Promise.all([
      pubkey ? userPhrase(pubkey).then((phrase) => ({ pubkey, phrase })) : null,
      getUsers(),
      getNotes(),
      Promise.all(others.map((p) => userPhrase(p.pubkey))),
    ]);
    setMe(m);
    setUsers(u);
    setNotes([...n, FORGED_NOTE]);
    setPasskey(current);
    setRecent(others.map((p, i) => ({ ...p, phrase: phrases[i] })));
    setRememberState(isRemembering());
  }, []);

  useEffect(() => {
    refresh().catch((e) => setError(e.message));
  }, [refresh]);

  const run: Run = (fn) => async () => {
    setError("");
    setBusy(true);
    try {
      await fn();
    } catch (e) {
      setError((e as Error).message);
    }
    await refresh().catch((e) => setError(e.message));
    setBusy(false);
  };

  return (
    <main className="mx-auto max-w-3xl px-4 py-10 font-sans text-gray-900">
      <h1 className="text-3xl font-bold tracking-tight">federated crdt</h1>

      <section className="mt-6 space-y-3">
        <div className="flex flex-wrap items-center gap-3">
          {me ? (
            <span>
              Keys loaded (
              <Link href={idPath(me.pubkey)} className={`font-semibold ${link}`} title={me.pubkey}>
                {me.phrase}
              </Link>
              {passkey && (
                <>
                  , from passkey <strong>{passkey.name ?? "(unnamed)"}</strong>
                </>
              )}
              ). Derive different keys:
            </span>
          ) : (
            <span>Derive keys:</span>
          )}
          <button className={me ? secondary : primary} disabled={busy} onClick={run(deriveFromNewPasskey)}>
            with new passkey
          </button>
          <button className={me ? secondary : primary} disabled={busy} onClick={run(deriveFromExistingPasskey)}>
            with existing passkey
          </button>
          {me && (
            <button className={secondary} disabled={busy} onClick={run(forgetKeys)}>
              Forget keys
            </button>
          )}
        </div>
        <p className="text-xs text-gray-500">
          Everything happens in your browser: your passkey derives a signing key (your ID) and an encryption key.
          A new passkey may ask for confirmation twice: once to create it, once to derive the keys.
        </p>
        {recent.length > 0 && (
          <div>
            <h3 className="text-sm font-semibold">{me ? "Other passkeys" : "Passkeys"} recently used on this device</h3>
            <ul className="mt-1 divide-y divide-gray-200 rounded-lg text-sm ring-1 ring-gray-200">
              {recent.map((p) => (
                <li key={p.credId} className="flex flex-wrap items-center justify-between gap-2 p-2">
                  <span>
                    <strong>{p.name ?? "(unnamed passkey)"}</strong>
                    <span className="ml-2 text-xs text-gray-500">
                      keys <span title={p.pubkey}>{p.phrase}</span> ·{" "}
                      last used{" "}
                      {new Date(p.lastUsed).toLocaleString()}
                    </span>
                  </span>
                  <span className="flex gap-2">
                    <button className={secondary} disabled={busy} onClick={run(() => deriveFromExistingPasskey(p.credId))}>
                      Use
                    </button>
                    <button className={secondary} disabled={busy} onClick={run(() => forgetRecentPasskey(p.credId))}>
                      Remove
                    </button>
                  </span>
                </li>
              ))}
            </ul>
          </div>
        )}
        {me && (
          <>
            <div className="space-y-1 text-sm">
              <label className="flex items-center gap-1.5">
                <input
                  type="checkbox"
                  checked={remember}
                  onChange={(e) => {
                    setRemember(e.target.checked);
                    setRememberState(isRemembering());
                  }}
                />
                🔑 Remember keys (save across reloads, no passkey flow needed, this device only)
              </label>
              {remember && (
                <p className="text-xs text-amber-800">
                  Your key secret is stored unencrypted in this browser's local storage. Anything that can read it
                  (other programs on this computer, browser extensions, malicious scripts on this site) could sign
                  and decrypt as you, forever. "Forget keys" removes it.
                </p>
              )}
            </div>
          </>
        )}
      </section>

      {error && (
        <p className="mt-4 rounded-md bg-red-50 p-3 text-sm text-red-700 ring-1 ring-red-200">{error}</p>
      )}

      <h2 className="mt-10 text-xl font-semibold">Notes</h2>
      {me ? (
        <div className="mt-3">
          <NoteEditor
            draft={draft}
            setDraft={setDraft}
            busy={busy}
            submitLabel="Add note"
            onSubmit={run(async () => {
              await putNote(draft.body, draft);
              setDraft({ ...draft, body: "" });
            })}
          />
        </div>
      ) : (
        <p className="mt-3 text-sm text-gray-500">Derive keys to write notes.</p>
      )}
      {notes === null ? (
        <p className="mt-3 text-gray-500">Loading…</p>
      ) : notes.length === 0 ? (
        <p className="mt-3 text-gray-500">No notes yet.</p>
      ) : (
        <NoteList notes={notes} me={me} busy={busy} run={run} />
      )}

      <h2 className="mt-10 text-xl font-semibold">Users</h2>
      {users === null ? (
        <p className="mt-3 text-gray-500">Loading…</p>
      ) : users.length === 0 ? (
        <p className="mt-3 text-gray-500">No users yet.</p>
      ) : (
        <ul className="mt-3 divide-y divide-gray-200 rounded-lg ring-1 ring-gray-200">
          {users.map((u) => (
            <li key={u.pubkey} className="p-3">
              <Link href={idPath(u.pubkey)} className={`font-semibold ${link}`}>
                {u.phrase}
                {u.pubkey === me?.pubkey && <span className="ml-1 font-normal text-gray-500">(you)</span>}
              </Link>
              <code className="block text-xs break-all text-gray-500">{u.pubkey}</code>
            </li>
          ))}
        </ul>
      )}
    </main>
  );
}
