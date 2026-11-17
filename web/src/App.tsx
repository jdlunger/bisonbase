import { useCallback, useEffect, useState } from "react";
import { type User, getMe, getUsers, logout, register, signIn } from "./api.ts";

const btn =
  "rounded-md px-3 py-1.5 text-sm font-medium shadow-sm transition disabled:opacity-50 cursor-pointer";
const primary = `${btn} bg-indigo-600 text-white hover:bg-indigo-500`;
const secondary = `${btn} bg-white text-gray-900 ring-1 ring-gray-300 ring-inset hover:bg-gray-50`;

export default function App() {
  const [me, setMe] = useState<User | null>(null);
  const [users, setUsers] = useState<User[] | null>(null);
  const [error, setError] = useState("");
  const [busy, setBusy] = useState(false);

  const refresh = useCallback(async () => {
    const [m, u] = await Promise.all([getMe(), getUsers()]);
    setMe(m);
    setUsers(u);
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
