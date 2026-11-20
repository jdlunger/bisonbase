import { useCallback, useEffect, useRef, useState } from "react";
import {
  type NodeInfo,
  type Passkey,
  type User,
  amOwner,
  claimNode,
  deriveFromExistingPasskey,
  deriveFromNewPasskey,
  forgetKeys,
  forgetRecentPasskey,
  isRemembering,
  loadNode,
  myGrants,
  myPasskey,
  myPubkey,
  pathWithin,
  putPost,
  recentPasskeys,
  restoreKeys,
  setRemember,
  userPhrase,
} from "./api.ts";
import { Compose, type Draft, NoteEditor } from "./NoteList.tsx";
import { PathPage, RecordPage, UserPage } from "./Record.tsx";
import { Link, idPath, navigate, recordPath, useRoute } from "./router.tsx";
import { type Run, link, hl, primary, secondary } from "./ui.ts";

/** A recently used passkey, with its keys' phrase. */
type Recent = Passkey & { phrase: string };

/** Loads remembered keys and this node's info first. */
export default function App() {
  /** undefined while loading; then the error, if any. */
  const [restoreError, setRestoreError] = useState<string | null>();
  useEffect(() => {
    Promise.all([restoreKeys(), loadNode()]).then(
      () => setRestoreError(null),
      (e) => setRestoreError(`Couldn't load: ${e.message}`),
    );
  }, []);
  return restoreError === undefined ? null : <Shell initialError={restoreError} />;
}

function Shell({ initialError }: { initialError: string | null }) {
  const route = useRoute();
  /** The node this page talks to. */
  const [node, setNode] = useState<NodeInfo | null>(null);
  const [me, setMe] = useState<User | null>(null);
  const [passkey, setPasskey] = useState<Passkey | null>(null);
  const [recent, setRecent] = useState<Recent[]>([]);
  /** Paths we hold grants at. */
  const [grants, setGrants] = useState<string[]>([]);
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
    const [g, n] = await Promise.all([myGrants(), loadNode()]);
    const m = pubkey ? { pubkey, phrase: userPhrase(pubkey), node: false } : null;
    setMe(m);
    setNode(n);
    setGrants(g);
    setPasskey(current);
    setRecent(others.map((p) => ({ ...p, phrase: userPhrase(p.pubkey) })));
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

  const owner = !!me && amOwner();
  const canWrite = (path: string) => !!me && (owner || grants.some((g) => pathWithin(path, g)));
  const open = (path: string) => {
    setDraft({ body: "", path });
    window.scrollTo({ top: 0, behavior: "smooth" });
  };
  // "New post" goes where we're looking, if we may write there; else the first place we may.
  const here = route.page === "path" && route.path !== "/" ? route.path : null;
  const newPost = () => open(here && canWrite(here) ? here : owner || !grants.length ? "/posts" : grants[0]);

  return (
    <Compose.Provider value={{ canWrite, open, writable: owner ? ["/"] : grants }}>
      <main className="mx-auto max-w-3xl px-4 py-6 font-sans text-gray-900">
        <header className="flex items-center justify-between gap-3">
          <div className="flex flex-wrap items-baseline gap-x-2">
            <Link href="/" className="text-xl font-bold tracking-tight hover:text-indigo-600">
              federated crdt
            </Link>
            {node && (
              <span className="text-sm text-gray-500">
                on{" "}
                <Link href={idPath(node.pubkey)} className={link} title={node.pubkey}>
                  <span className={hl(node.phrase)}>{node.phrase}</span>
                </Link>
              </span>
            )}
          </div>
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
              busy={busy}
              submitLabel="Post"
              onSubmit={run(async () => {
                const hash = await putPost(draft.body, draft.path);
                setDraft(null);
                navigate(recordPath(hash));
              })}
              onCancel={() => setDraft(null)}
            />
          </section>
        )}

        {error && <p className="mt-4 rounded-md bg-red-50 p-3 text-sm text-red-700 ring-1 ring-red-200">{error}</p>}

        <div className="mt-6">
          {route.page === "claim" ? (
            <Claim node={node} me={me} busy={busy} run={run} />
          ) : route.page === "user" ? (
            <UserPage pubkey={route.pubkey} node={node} me={me} busy={busy} run={run} tick={tick} />
          ) : route.page === "record" ? (
            <RecordPage hash={route.hash} me={me} busy={busy} run={run} tick={tick} />
          ) : (
            <PathPage path={route.path} me={me} busy={busy} run={run} tick={tick} />
          )}
        </div>
      </main>
    </Compose.Provider>
  );
}

/** /claim#<token>: the one-time link a new node prints, to make whoever signs in here its first owner. */
function Claim({ node, me, busy, run }: { node: NodeInfo | null; me: User | null; busy: boolean; run: Run }) {
  const token = location.hash.slice(1);
  if (!node) return <p className="text-gray-500">Loading…</p>;
  const name = <span className={hl(node.phrase)}>{node.phrase}</span>;
  return (
    <section className="space-y-3">
      <h1 className="text-2xl font-bold tracking-tight">Claim {name}</h1>
      {node.owners.length ? (
        <p>
          This node already has an owner:{" "}
          <Link href={idPath(node.pubkey)} className={link}>
            see its page
          </Link>
          .
        </p>
      ) : !token ? (
        <p>This link is missing its token. Use the whole link the node printed.</p>
      ) : (
        <>
          <p className="text-sm text-gray-600">
            A node's owners can write anywhere on it, let others write under paths, add owners, and federate it with
            other nodes. This link works once.
          </p>
          {me ? (
            <button
              className={secondary}
              disabled={busy}
              onClick={run(async () => {
                const id = await claimNode(token);
                history.replaceState(null, "", location.pathname); // the token is spent
                navigate(idPath(id));
              })}
            >
              Claim as <span className={hl(me.phrase)}>{me.phrase}</span>
            </button>
          ) : (
            <p>Sign in first (top right), with the keys that should own this node.</p>
          )}
        </>
      )}
    </section>
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
        {me ? <span className={hl(me.phrase)}>{me.phrase}</span> : "Sign in"} <span className="text-xs">▾</span>
      </button>
      {openMenu && (
        <div className="absolute right-0 z-10 mt-2 w-80 max-w-[calc(100vw-2rem)] rounded-lg bg-white p-2 shadow-lg ring-1 ring-gray-200">
          {me && (
            <div className="border-b border-gray-200 px-2 pb-2">
              <Link href={idPath(me.pubkey)} className={`font-semibold ${link}`} title={me.pubkey} onClick={() => setOpenMenu(false)}>
                <span className={hl(me.phrase)}>{me.phrase}</span>
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
                    <span className={`font-medium ${hl(p.phrase)}`}>{p.phrase}</span>
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
