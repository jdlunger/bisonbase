import { useCallback, useEffect, useState } from "react";
import {
  type Note,
  type User,
  createNote,
  deleteNote,
  getMe,
  getNotes,
  getUsers,
  logout,
  register,
  signIn,
  updateNote,
} from "./api.ts";

const btn =
  "rounded-md px-3 py-1.5 text-sm font-medium shadow-sm transition disabled:opacity-50 cursor-pointer";
const primary = `${btn} bg-indigo-600 text-white hover:bg-indigo-500`;
const secondary = `${btn} bg-white text-gray-900 ring-1 ring-gray-300 ring-inset hover:bg-gray-50`;
const danger = `${btn} bg-white text-red-700 ring-1 ring-red-300 ring-inset hover:bg-red-50`;
const textarea =
  "block w-full rounded-md p-2 text-sm ring-1 ring-gray-300 ring-inset focus:ring-2 focus:ring-indigo-600 focus:outline-none";

const fmtTime = (t: number) => new Date(t * 1000).toLocaleString();

export default function App() {
  const [me, setMe] = useState<User | null>(null);
  const [users, setUsers] = useState<User[] | null>(null);
  const [notes, setNotes] = useState<Note[] | null>(null);
  const [error, setError] = useState("");
  const [busy, setBusy] = useState(false);
  const [draft, setDraft] = useState("");
  const [editing, setEditing] = useState<{ id: number; body: string } | null>(null);

  const refresh = useCallback(async () => {
    const [m, u, n] = await Promise.all([getMe(), getUsers(), getNotes()]);
    setMe(m);
    setUsers(u);
    setNotes(n);
  }, []);

  useEffect(() => {
    refresh().catch((e) => setError(e.message));
  }, [refresh]);

  const run = (fn: () => Promise<unknown>) => async () => {
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

      <section className="mt-6 flex flex-wrap items-center gap-3">
        {me ? (
          <>
            <span>
              Already signed in as <strong>{me.phrase}</strong>
            </span>
            <button className={secondary} disabled={busy} onClick={run(logout)}>
              Sign out
            </button>
          </>
        ) : (
          <>
            <button className={primary} disabled={busy} onClick={run(signIn)}>
              Sign in with existing passkey
            </button>
            <button className={secondary} disabled={busy} onClick={run(register)}>
              Create new passkey
            </button>
          </>
        )}
      </section>

      {error && (
        <p className="mt-4 rounded-md bg-red-50 p-3 text-sm text-red-700 ring-1 ring-red-200">{error}</p>
      )}

      <h2 className="mt-10 text-xl font-semibold">Notes</h2>
      {me ? (
        <form
          className="mt-3 space-y-2"
          onSubmit={(e) => {
            e.preventDefault();
            run(async () => {
              await createNote(draft);
              setDraft("");
            })();
          }}
        >
          <textarea
            className={textarea}
            rows={3}
            placeholder="Write a note…"
            value={draft}
            onChange={(e) => setDraft(e.target.value)}
          />
          <button className={primary} disabled={busy || !draft.trim()}>
            Add note
          </button>
        </form>
      ) : (
        <p className="mt-3 text-sm text-gray-500">Sign in to write notes.</p>
      )}
      {notes === null ? (
        <p className="mt-3 text-gray-500">Loading…</p>
      ) : notes.length === 0 ? (
        <p className="mt-3 text-gray-500">No notes yet.</p>
      ) : (
        <ul className="mt-4 divide-y divide-gray-200 rounded-lg ring-1 ring-gray-200">
          {notes.map((n) => {
            const mine = me?.pubkey === n.author.pubkey;
            const isEditing = editing?.id === n.id;
            return (
              <li key={n.id} className="p-3">
                <div className="flex flex-wrap items-baseline justify-between gap-2 text-sm">
                  <span className="font-semibold" title={n.author.pubkey}>
                    {n.author.phrase}
                    {mine && <span className="ml-1 font-normal text-gray-500">(you)</span>}
                  </span>
                  <span className="text-xs text-gray-500">
                    {fmtTime(n.created_at)}
                    {n.updated_at !== n.created_at && ` · edited ${fmtTime(n.updated_at)}`}
                  </span>
                </div>
                {isEditing ? (
                  <div className="mt-2 space-y-2">
                    <textarea
                      className={textarea}
                      rows={3}
                      value={editing.body}
                      onChange={(e) => setEditing({ id: n.id, body: e.target.value })}
                      autoFocus
                    />
                    <div className="flex gap-2">
                      <button
                        className={primary}
                        disabled={busy || !editing.body.trim()}
                        onClick={run(async () => {
                          await updateNote(n.id, editing.body);
                          setEditing(null);
                        })}
                      >
                        Save
                      </button>
                      <button className={secondary} disabled={busy} onClick={() => setEditing(null)}>
                        Cancel
                      </button>
                    </div>
                  </div>
                ) : (
                  <>
                    <p className="mt-1 whitespace-pre-wrap break-words">{n.body}</p>
                    {mine && (
                      <div className="mt-2 flex gap-2">
                        <button
                          className={secondary}
                          disabled={busy}
                          onClick={() => setEditing({ id: n.id, body: n.body })}
                        >
                          Edit
                        </button>
                        <button className={danger} disabled={busy} onClick={run(() => deleteNote(n.id))}>
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
