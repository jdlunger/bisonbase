import { useCallback, useEffect, useState } from "react";
import { type Post, type User, getPosts, isPubkey, myPubkey, normalizePath, userPhrase } from "./api.ts";
import { Subtree } from "./NoteList.tsx";
import { Link, idPath, recordPath } from "./router.tsx";
import { type Run, link } from "./ui.ts";

/** /bb/<owner><path>: the record at `path` in `owner`'s space, if any, and everything under it. */
export default function RecordPage({ owner, path: rawPath }: { owner: string; path: string }) {
  let path = "/";
  let pathError = "";
  try {
    if (rawPath !== "/") path = normalizePath(rawPath);
  } catch (e) {
    pathError = (e as Error).message;
  }
  const valid = isPubkey(owner) && !pathError;
  const myId = myPubkey();
  const [phrase, setPhrase] = useState<string | null>(null);
  const [me, setMe] = useState<User | null>(null);
  const [posts, setPosts] = useState<Post[] | null>(null);
  const [error, setError] = useState("");
  const [busy, setBusy] = useState(false);

  const refresh = useCallback(async () => setPosts(await getPosts({ owner, prefix: path })), [owner, path]);

  useEffect(() => {
    if (myId) userPhrase(myId).then((phrase) => setMe({ pubkey: myId, phrase }));
  }, [myId]);

  useEffect(() => {
    if (!valid) return;
    setPhrase(null);
    setPosts(null);
    setError("");
    userPhrase(owner).then(setPhrase);
    refresh().catch((e) => setError(`Couldn't load records: ${e.message}`));
  }, [owner, valid, refresh]);

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

  const segs = path === "/" ? [] : path.slice(1).split("/");
  return (
    <main className="mx-auto max-w-3xl px-4 py-10 font-sans text-gray-900">
      <Link href="/" className={`text-sm text-gray-500 ${link}`}>
        ← federated crdt
      </Link>
      {!valid ? (
        <p className="mt-6 rounded-md bg-red-50 p-3 text-sm text-red-700 ring-1 ring-red-200">
          {pathError || (
            <>
              <code className="break-all">{owner}</code> isn't a valid ID (32 bytes of base58).
            </>
          )}
        </p>
      ) : (
        <>
          <h1 className="mt-2 font-mono text-xl break-all">
            bb://
            <Link href={idPath(owner)} className={link} title={owner}>
              {phrase ?? "…"}
            </Link>
            {segs.length === 0 && "/"}
            {segs.map((seg, i) => (
              <span key={i}>
                /
                {i === segs.length - 1 ? (
                  <span className="font-semibold">{seg}</span>
                ) : (
                  <Link href={recordPath(owner, "/" + segs.slice(0, i + 1).join("/"))} className={link}>
                    {seg}
                  </Link>
                )}
              </span>
            ))}
          </h1>
          {error && <p className="mt-4 rounded-md bg-red-50 p-3 text-sm text-red-700 ring-1 ring-red-200">{error}</p>}
          {posts === null ? (
            !error && <p className="mt-3 text-gray-500">Loading…</p>
          ) : posts.length === 0 ? (
            <p className="mt-3 text-gray-500">Nothing here.</p>
          ) : (
            <Subtree owner={owner} path={path} posts={posts} me={me} busy={busy} run={run} />
          )}
        </>
      )}
    </main>
  );
}
