import { useCallback, useEffect, useState } from "react";
import {
  type Note,
  type User,
  decryptNote,
  deleteNote,
  getNotes,
  getUser,
  getUsers,
  isRemembering,
  forgetKeys,
  myPubkey,
  putNote,
  deriveFromNewPasskey,
  restoreKeys,
  setRemember,
  deriveFromExistingPasskey,
  verifyNote,
} from "./api.ts";

const btn =
  "rounded-md px-3 py-1.5 text-sm font-medium shadow-sm transition disabled:opacity-50 cursor-pointer";
const primary = `${btn} bg-indigo-600 text-white hover:bg-indigo-500`;
const secondary = `${btn} bg-white text-gray-900 ring-1 ring-gray-300 ring-inset hover:bg-gray-50`;
const danger = `${btn} bg-white text-red-700 ring-1 ring-red-300 ring-inset hover:bg-red-50`;
const textarea =
  "block w-full rounded-md p-2 text-sm ring-1 ring-gray-300 ring-inset focus:ring-2 focus:ring-indigo-600 focus:outline-none";
const badge = "rounded-full px-2 py-0.5 text-xs font-medium ring-1 ring-inset";

const fmtTime = (t: number) => new Date(t * 1000).toLocaleString();

type Draft = { body: string; encrypt: boolean };

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

/** Note text plus an "Encrypt" checkbox. Notes are always signed. */
function NoteEditor(props: {
  draft: Draft;
  setDraft: (d: Draft) => void;
  busy: boolean;
  submitLabel: string;
  onSubmit: () => void;
  onCancel?: () => void;
}) {
  const { draft, setDraft, busy } = props;
  return (
    <div className="space-y-2">
      <textarea
        className={textarea}
        rows={3}
        placeholder="Write a note…"
        value={draft.body}
        onChange={(e) => setDraft({ ...draft, body: e.target.value })}
        autoFocus={!!props.onCancel}
      />
      <label className="flex items-center gap-1.5 text-sm" title="Only your passkey can decrypt it">
        <input type="checkbox" checked={draft.encrypt} onChange={(e) => setDraft({ ...draft, encrypt: e.target.checked })} />
        Encrypt (only you can read it)
      </label>
      <div className="flex gap-2">
        <button className={primary} disabled={busy || !draft.body.trim()} onClick={props.onSubmit}>
          {props.submitLabel}
        </button>
        {props.onCancel && (
          <button className={secondary} disabled={busy} onClick={props.onCancel}>
            Cancel
          </button>
        )}
      </div>
    </div>
  );
}

export default function App() {
  const [me, setMe] = useState<User | null>(null);
  const [users, setUsers] = useState<User[] | null>(null);
  const [notes, setNotes] = useState<Note[] | null>(null);
  const [error, setError] = useState("");
  const [busy, setBusy] = useState(false);
  const [draft, setDraftState] = useState<Draft>(() => ({ body: "", encrypt: loadEncrypt() }));
  const setDraft = (d: Draft) => {
    setDraftState(d);
    saveEncrypt(d.encrypt);
  };
  const [editing, setEditing] = useState<(Draft & { note: Note }) | null>(null);
  const [remember, setRememberState] = useState(isRemembering);
  /** Per note ID: decrypted text, and whether its signature checks out. */
  const [plain, setPlain] = useState<Record<string, string>>({});
  const [verified, setVerified] = useState<Record<string, boolean>>({});

  const refresh = useCallback(async () => {
    const pubkey = myPubkey();
    const [m, u, n] = await Promise.all([pubkey ? getUser(pubkey) : null, getUsers(), getNotes()]);
    setMe(m);
    setUsers(u);
    setNotes(n);
    setRememberState(isRemembering());
  }, []);

  useEffect(() => {
    // Remembered keys sign us back in silently.
    (async () => {
      await restoreKeys().catch((e) => setError(`Couldn't restore remembered keys: ${e.message}`));
      await refresh();
    })().catch((e) => setError(e.message));
  }, [refresh]);

  // Check signatures and decrypt what we can, entirely client-side.
  useEffect(() => {
    if (!notes) return;
    let cancelled = false;
    (async () => {
      const v: Record<string, boolean> = {};
      const p: Record<string, string> = {};
      for (const n of notes) {
        v[n.id] = await verifyNote(n);
        if (n.encrypted && n.author.pubkey === me?.pubkey) {
          p[n.id] = await decryptNote(n).catch(() => "(couldn't decrypt)");
        }
      }
      if (!cancelled) {
        setVerified(v);
        setPlain(p);
      }
    })();
    return () => {
      cancelled = true;
    };
  }, [notes, me]);

  const run = (fn: () => unknown) => async () => {
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
              Keys loaded (<strong title={me.pubkey}>{me.phrase}</strong>). Derive different keys:
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
                🔑 Remember my keys on this device (keep them loaded across reloads)
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
        <ul className="mt-4 divide-y divide-gray-200 rounded-lg ring-1 ring-gray-200">
          {notes.map((n) => {
            const mine = me?.pubkey === n.author.pubkey;
            const isEditing = editing?.note.id === n.id;
            const text = n.encrypted ? plain[n.id] : n.body;
            const v = verified[n.id];
            return (
              <li key={n.id} className="p-3">
                <div className="flex flex-wrap items-baseline justify-between gap-2 text-sm">
                  <span className="flex flex-wrap items-baseline gap-2">
                    <span className="font-semibold" title={n.author.pubkey}>
                      {n.author.phrase}
                      {mine && <span className="ml-1 font-normal text-gray-500">(you)</span>}
                    </span>
                    {v === true ? (
                      <span
                        className={`${badge} bg-green-50 text-green-700 ring-green-200`}
                        title="Signature verified in your browser against the author's public key"
                      >
                        ✓ signed
                      </span>
                    ) : v === false ? (
                      <span className={`${badge} bg-red-50 text-red-700 ring-red-200`}>✗ bad signature</span>
                    ) : (
                      <span className={`${badge} bg-gray-50 text-gray-600 ring-gray-200`}>checking…</span>
                    )}
                    {n.encrypted && (
                      <span className={`${badge} bg-amber-50 text-amber-800 ring-amber-200`}>🔒 encrypted</span>
                    )}
                  </span>
                  <span className="text-xs text-gray-500">
                    {fmtTime(n.created_at)}
                    {n.updated_at !== n.created_at && ` · edited ${fmtTime(n.updated_at)}`}
                  </span>
                </div>
                {isEditing ? (
                  <div className="mt-2">
                    <NoteEditor
                      draft={editing}
                      setDraft={(d) => setEditing({ ...d, note: n })}
                      busy={busy}
                      submitLabel="Save"
                      onSubmit={run(async () => {
                        await putNote(editing.body, editing, n);
                        setEditing(null);
                      })}
                      onCancel={() => setEditing(null)}
                    />
                  </div>
                ) : (
                  <>
                    {text !== undefined ? (
                      <p className="mt-1 whitespace-pre-wrap break-words">{text}</p>
                    ) : (
                      <p className="mt-1 text-sm text-gray-500 italic">
                        {mine ? "Decrypting…" : "Encrypted. Only the author can read this."}
                      </p>
                    )}
                    {mine && (
                      <div className="mt-2 flex gap-2">
                        <button
                          className={secondary}
                          disabled={busy || text === undefined}
                          onClick={() => setEditing({ note: n, body: text!, encrypt: n.encrypted })}
                        >
                          Edit
                        </button>
                        <button className={danger} disabled={busy} onClick={run(() => deleteNote(n))}>
                          Delete
                        </button>
                      </div>
                    )}
                  </>
                )}
              </li>
            );
          })}
        </ul>
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
              <div className="font-semibold">{u.phrase}</div>
              <code className="block text-xs break-all text-gray-500">{u.pubkey}</code>
            </li>
          ))}
        </ul>
      )}
    </main>
  );
}
