import { useCallback, useEffect, useState } from "react";
import { type Post, type User, forgedPost, getPosts, isPubkey, normalizePath, userPhrase } from "./api.ts";
import { OwnerInfo } from "./Identity.tsx";
import { NewHere, PostTree, Subtree } from "./NoteList.tsx";
import { Link, idPath, recordPath } from "./router.tsx";
import { type Run, link, hl } from "./ui.ts";

type Loaded = {
  posts: Post[];
  /** At a space's root only: valid grants the owner gave or received, and what they wrote in others' spaces. */
  grants?: Post[];
  elsewhere?: Post[];
};

/** Everything at or under a place. No `owner`: every space ("/"). `owner` at "/": their page, with who they are
 * on top. Deeper: the record at `path`, if any, and everything under it. Reloads when `tick` changes. */
export default function Browse({
  owner,
  path: rawPath,
  me,
  busy,
  run,
  tick,
}: {
  owner?: string;
  path: string;
  me: User | null;
  busy: boolean;
  run: Run;
  tick: number;
}) {
  let path = "/";
  let pathError = "";
  try {
    if (rawPath !== "/") path = normalizePath(rawPath);
  } catch (e) {
    pathError = (e as Error).message;
  }
  const root = path === "/";
  const valid = (owner === undefined || isPubkey(owner)) && !pathError;
  const [phrase, setPhrase] = useState<string | null>(null);
  const [data, setData] = useState<Loaded | null>(null);
  const [error, setError] = useState("");

  const load = useCallback(async (): Promise<Loaded> => {
    if (owner === undefined) {
      const [posts, forged] = await Promise.all([getPosts(), forgedPost()]);
      return { posts: [...posts, forged] };
    }
    if (!root) return { posts: await getPosts({ owner, prefix: path }) };
    const [posts, g, written] = await Promise.all([getPosts({ owner }), getPosts({ type: "grant" }), getPosts({ author: owner })]);
    return {
      posts,
      grants: g.filter((p) => p.verified && p.grant && (p.owner.pubkey === owner || p.grant.grantee.pubkey === owner)),
      elsewhere: written.filter((p) => p.owner.pubkey !== owner),
    };
  }, [owner, path, root]);

  // A new place: start over.
  useEffect(() => {
    setPhrase(null);
    setData(null);
    if (valid && owner) setPhrase(userPhrase(owner));
  }, [owner, path, valid]);

  useEffect(() => {
    if (!valid) return;
    let live = true;
    setError("");
    load().then(
      (d) => live && setData(d),
      (e) => live && setError(`Couldn't load records: ${e.message}`),
    );
    return () => {
      live = false;
    };
  }, [load, valid, tick]);

  const items = { me, busy, run };
  if (!valid) {
    return (
      <p className="mt-6 rounded-md bg-red-50 p-3 text-sm text-red-700 ring-1 ring-red-200">
        {pathError || (
          <>
            <code className="break-all">{owner}</code> isn't a valid ID (32 bytes of base58).
          </>
        )}
      </p>
    );
  }

  const segs = root ? [] : path.slice(1).split("/");
  const records =
    data === null ? (
      !error && <p className="mt-3 text-gray-500">Loading…</p>
    ) : data.posts.length === 0 ? (
      <p className="mt-3 text-gray-500">Nothing here yet.</p>
    ) : owner === undefined ? (
      <PostTree posts={data.posts} first={me?.pubkey} {...items} />
    ) : (
      <Subtree owner={owner} path={path} posts={data.posts} {...items} />
    );
  return (
    <>
      {owner && root && (
        <OwnerInfo pubkey={owner} phrase={phrase} grants={data?.grants ?? null} me={me?.pubkey ?? null} busy={busy} run={run} />
      )}
      {owner && (
        <h2 className={`font-mono break-all ${root ? "mt-10 text-xl font-semibold" : "mt-2 text-xl"}`}>
          bb://
          {root ? (
            <span className={hl(phrase ?? "…")} title={owner}>{phrase ?? "…"}</span>
          ) : (
            <Link href={idPath(owner)} className={link} title={owner}>
              <span className={hl(phrase ?? "…")}>{phrase ?? "…"}</span>
            </Link>
          )}
          {root && "/"}
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
          <NewHere owner={owner} dir={root ? "" : path} />
        </h2>
      )}
      {error && <p className="mt-4 rounded-md bg-red-50 p-3 text-sm text-red-700 ring-1 ring-red-200">{error}</p>}
      {records}
      {data?.elsewhere && data.elsewhere.length > 0 && (
        <>
          <h2 className="mt-10 text-xl font-semibold">In others' spaces</h2>
          <p className="mt-1 text-sm text-gray-500">What {phrase ? <span className={hl(phrase)}>{phrase}</span> : "they"} wrote elsewhere, with grants.</p>
          <PostTree posts={data.elsewhere} {...items} />
        </>
      )}
    </>
  );
}
