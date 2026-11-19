import { useCallback, useEffect, useRef, useState } from "react";
import {
  type Grant,
  type Passkey,
  type User,
  deriveFromExistingPasskey,
  deriveFromNewPasskey,
  forgetKeys,
  forgetRecentPasskey,
  isRemembering,
  myGrants,
  myPasskey,
  myPubkey,
  newPostPath,
  pathWithin,
  putPost,
  recentPasskeys,
  restoreKeys,
  setRemember,
  userPhrase,
} from "./api.ts";
import { Compose, type Draft, NoteEditor } from "./NoteList.tsx";
import Browse from "./Record.tsx";
import { Link, idPath, usePath } from "./router.tsx";
import { type Run, link, primary, secondary } from "./ui.ts";

/** A recently used passkey, with its keys' phrase. */
type Recent = Passkey & { phrase: string };

/** Routes: "/" is every space, "/bb/<pubkey><path>" a place in one space and what's under it ("/bb/<pubkey>/" is
 * that user's page). Remembered keys load first. */
export default function App() {
  /** undefined while loading remembered keys; then the error restoring them, if any. */
  const [restoreError, setRestoreError] = useState<string | null>();
  useEffect(() => {
    restoreKeys().then(
      () => setRestoreError(null),
      (e) => setRestoreError(`Couldn't restore remembered keys: ${e.message}`),
    );
  }, []);
  return restoreError === undefined ? null : <Shell initialError={restoreError} />;
}

/** The route as (owner, path): no owner for "/". */
function useRoute(): { owner?: string; path: string } {
  const m = usePath().match(/^\/bb\/([^/]+)(\/.*)?$/);
  if (!m) return { path: "/" };
  const path = (m[2] ?? "/").replace(/\/$/, "").split("/").map(decodeURIComponent).join("/") || "/";
  return { owner: decodeURIComponent(m[1]), path };
}

/** A fresh name for a new post in `dir` ("" for the root). */
const newPathIn = (dir: string) => `${dir}/${newPostPath().split("/").pop()}`;

function Shell({ initialError }: { initialError: string | null }) {
  const route = useRoute();
  const [me, setMe] = useState<User | null>(null);
  const [passkey, setPasskey] = useState<Passkey | null>(null);
  const [recent, setRecent] = useState<Recent[]>([]);
  const [grants, setGrants] = useState<Grant[]>([]);
  const [error, setError] = useState(initialError ?? "");
  const [busy, setBusy] = useState(false);
  /** Bumped after every action, so the page reloads its records. */
  const [tick, setTick] = useState(0);
  /** The new-post form, when open. */
  const [draft, setDraft] = useState<Draft | null>(null);

  const refresh = useCallback(async () => {
    const pubkey = myPubkey();
    const current = myPasskey();
    const others = recentPasskeys().filter((p) => p.credId !== current?.credId);
    const [m, g, phrases] = await Promise.all([
      pubkey ? userPhrase(pubkey).then((phrase) => ({ pubkey, phrase })) : null,
      myGrants(),
      Promise.all(others.map((p) => userPhrase(p.pubkey))),
    ]);
    setMe(m);
    setGrants(g);
    setPasskey(current);
    setRecent(others.map((p, i) => ({ ...p, phrase: phrases[i] })));
    if (!m) setDraft(null);
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
    setTick((t) => t + 1);
    setBusy(false);
  };

  const grantFor = (owner: string, dir: string) => grants.find((g) => g.owner.pubkey === owner && pathWithin(dir, g.path));
  const canWrite = (owner: string, dir: string) => !!me && (owner === me.pubkey || !!grantFor(owner, dir));
  const open = (owner: string, dir: string) => {
    setDraft({ body: "", path: newPathIn(dir), grant: owner === me?.pubkey ? undefined : grantFor(owner, dir) });
    window.scrollTo({ top: 0, behavior: "smooth" });
  };
  // "New post" goes where we're looking, if we may write there; else our own /posts.
  const here = route.owner && route.path !== "/" ? route.path : "";
  const newPost = () => (route.owner && canWrite(route.owner, here) ? open(route.owner, here) : open(me!.pubkey, "/posts"));

  return (
    <Compose.Provider value={{ canWrite, open }}>
      <main className="mx-auto max-w-3xl px-4 py-6 font-sans text-gray-900">
        <header className="flex items-center justify-between gap-3">
          <Link href="/" className="text-xl font-bold tracking-tight hover:text-indigo-600">
            federated crdt
          </Link>
          <div className="flex items-center gap-2">
            {me && !draft && (
              <button className={primary} disabled={busy} onClick={newPost}>
                + New post
              </button>
            )}
            <AuthMenu me={me} passkey={passkey} recent={recent} busy={busy} run={run} />
          </div>
        </header>

        {draft && (
          <section className="mt-4 rounded-lg p-3 ring-1 ring-gray-200">
            <NoteEditor
              draft={draft}
              setDraft={setDraft}
              grants={grants}
              busy={busy}
              submitLabel="Post"
              onSubmit={run(async () => {
                await putPost(draft.body, draft);
                setDraft(null);
              })}
              onCancel={() => setDraft(null)}
            />
          </section>
        )}

        {error && <p className="mt-4 rounded-md bg-red-50 p-3 text-sm text-red-700 ring-1 ring-red-200">{error}</p>}

        <div className="mt-6">
          <Browse owner={route.owner} path={route.path} me={me} busy={busy} run={run} tick={tick} />
        </div>
      </main>
    </Compose.Provider>
  );
}

/** "Sign in" (or our phrase), opening a menu of ways to get keys: a recent passkey, another existing one, or a new one. */
function AuthMenu({ me, passkey, recent, busy, run }: { me: User | null; passkey: Passkey | null; recent: Recent[]; busy: boolean; run: Run }) {
  const [openMenu, setOpenMenu] = useState(false);
  const [remember, setRememberState] = useState(isRemembering);
  const ref = useRef<HTMLDivElement>(null);
  useEffect(() => {
    if (!openMenu) return;
    const close = (e: MouseEvent) => ref.current?.contains(e.target as Node) || setOpenMenu(false);
    const esc = (e: KeyboardEvent) => e.key === "Escape" && setOpenMenu(false);
    document.addEventListener("mousedown", close);
    document.addEventListener("keydown", esc);
    return () => {
      document.removeEventListener("mousedown", close);
      document.removeEventListener("keydown", esc);
    };
  }, [openMenu]);
  // Runs `fn` like any action, then closes the menu.
  const act = (fn: () => unknown) => async () => {
    await run(fn)();
    setOpenMenu(false);
    setRememberState(isRemembering());
  };
  const item = "flex w-full cursor-pointer items-center justify-between gap-2 rounded-md px-2 py-1.5 text-left text-sm hover:bg-gray-100 disabled:opacity-50";

  return (
    <div ref={ref} className="relative">
      <button className={me ? secondary : primary} onClick={() => setOpenMenu(!openMenu)} aria-expanded={openMenu}>
        {me ? me.phrase : "Sign in"} <span className="text-xs">▾</span>
      </button>
      {openMenu && (
        <div className="absolute right-0 z-10 mt-2 w-80 max-w-[calc(100vw-2rem)] rounded-lg bg-white p-2 shadow-lg ring-1 ring-gray-200">
          {me && (
            <div className="border-b border-gray-200 px-2 pb-2">
              <Link href={idPath(me.pubkey)} className={`font-semibold ${link}`} title={me.pubkey} onClick={() => setOpenMenu(false)}>
                {me.phrase}
              </Link>
              {passkey && <div className="text-xs text-gray-500">passkey {passkey.name ?? "(unnamed)"}</div>}
              <label className="mt-2 flex items-center gap-1.5 text-sm">
                <input
                  type="checkbox"
                  checked={remember}
                  onChange={(e) => {
                    setRemember(e.target.checked);
                    setRememberState(isRemembering());
                  }}
                />
                Stay signed in on this device
              </label>
              {remember && (
                <p className="mt-1 text-xs text-amber-800">
                  Your key secret is stored unencrypted in this browser. Anything that can read it could sign as you,
                  forever. Signing out removes it.
                </p>
              )}
              <button className={`${secondary} mt-2 w-full`} disabled={busy} onClick={act(forgetKeys)}>
                Sign out
              </button>
            </div>
          )}
          {recent.length > 0 && (
            <ul className="border-b border-gray-200 py-1">
              {recent.map((p) => (
                <li key={p.credId} className="flex items-center gap-1">
                  <button className={item} disabled={busy} onClick={act(() => deriveFromExistingPasskey(p.credId))} title={p.pubkey}>
                    <span className="font-medium">{p.phrase}</span>
                    <span className="text-xs text-gray-500">{p.name ?? "(unnamed)"}</span>
                  </button>
                  <button
                    className="cursor-pointer rounded-md px-1.5 py-1 text-gray-400 hover:bg-gray-100 hover:text-red-600"
                    disabled={busy}
                    onClick={run(() => forgetRecentPasskey(p.credId))}
                    title="Remove from this list"
                    aria-label={`Remove ${p.phrase} from this list`}
                  >
                    ×
                  </button>
                </li>
              ))}
            </ul>
          )}
          <div className="pt-1">
            <button className={item} disabled={busy} onClick={act(() => deriveFromExistingPasskey())}>
              Other existing passkey…
            </button>
            <button className={item} disabled={busy} onClick={act(deriveFromNewPasskey)}>
              New passkey
            </button>
          </div>
        </div>
      )}
    </div>
  );
}
