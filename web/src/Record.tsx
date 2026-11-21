import {
  type Chain,
  type NodeInfo,
  type Post,
  type User,
  GRANT_PATH,
  forgedPost,
  getChain,
  getPosts,
  grantNames,
  isHash,
  isPubkey,
  normalizePath,
} from "./api.ts";
import { Identity, NodeAdmin } from "./Identity.tsx";
import { NewHere, PathLinks, PostItem, Subtree } from "./NoteList.tsx";
import { Link } from "./router.tsx";
import { type Run, link, useLoad } from "./ui.ts";

type PageProps = { me: User | null; busy: boolean; run: Run; tick: number };

const ErrorBox = ({ children }: { children: React.ReactNode }) => (
  <p className="mt-4 rounded-md bg-red-50 p-3 text-sm text-red-700 ring-1 ring-red-200">{children}</p>
);

/** Every record at or under `path` ("/" for all of them). */
export function PathPage({ path: rawPath, me, busy, run, tick }: { path: string } & PageProps) {
  let path = "/";
  let pathError = "";
  try {
    path = normalizePath(rawPath, true);
  } catch (e) {
    pathError = (e as Error).message;
  }
  const root = path === "/";
  const { data, error } = useLoad(
    pathError ? null : async () => (root ? [...(await getPosts()), forgedPost()] : getPosts({ prefix: path })),
    [path, pathError],
    tick,
  );
  if (pathError) return <ErrorBox>{pathError}</ErrorBox>;
  const items = { me, busy, run };
  return (
    <>
      {!root && (
        <h1 className="text-xl">
          <PathLinks path={path} />
          <NewHere path={path} />
        </h1>
      )}
      {error && <ErrorBox>Couldn't load records: {error}</ErrorBox>}
      {data === null ? (
        !error && <p className="mt-3 text-gray-500">Loading…</p>
      ) : data.length === 0 ? (
        <p className="mt-3 text-gray-500">Nothing here yet.</p>
      ) : (
        <Subtree path={path} posts={data} {...items} />
      )}
    </>
  );
}

/** One record, by any of its versions' hashes: its current version, then every version. */
export function RecordPage({ hash, me, busy, run, tick }: { hash: string } & PageProps) {
  const valid = isHash(hash);
  const { data, error } = useLoad<Chain>(valid ? () => getChain(hash) : null, [hash], tick);
  if (!valid) return <ErrorBox><code className="break-all">{hash}</code> isn't a record hash (32 bytes of base58).</ErrorBox>;
  if (error) return <ErrorBox>Couldn't load this record: {error}</ErrorBox>;
  if (!data) return <p className="text-gray-500">Loading…</p>;
  const items = { me, busy, run };
  const shown = data.current ?? data.versions[0];
  return (
    <>
      <h1 className="text-xl">
        <PathLinks path={shown.rec.path} />
      </h1>
      {data.deleted ? (
        <p className="mt-4 rounded-md bg-gray-50 p-3 text-sm text-gray-600 ring-1 ring-gray-200">
          Deleted by{" "}
          <Link href={`/u/${data.deleted.author.pubkey}`} className={link}>
            {data.deleted.author.phrase}
          </Link>
          . Its versions are below.
        </p>
      ) : (
        data.current && (
          <div className="mt-4 rounded-lg ring-1 ring-gray-200">
            <PostItem post={data.current} hidePath {...items} />
          </div>
        )
      )}
      <h2 className="mt-10 text-xl font-semibold">History</h2>
      <p className="mt-1 text-sm text-gray-500">Every version, oldest first. Each names the one it edits; the newest wins.</p>
      <ol className="mt-3 divide-y divide-gray-200 rounded-lg ring-1 ring-gray-200">
        {data.versions.map((p) => (
          <li key={p.hash} className={p.hash === hash ? "bg-indigo-50/50" : ""}>
            <PostItem post={p} history {...items} />
          </li>
        ))}
      </ol>
    </>
  );
}

type UserData = { grants: Post[]; written: Post[] };

/** A user's page: who they are, their grants, and what they wrote. For this node's key, also the node's owners, grants and peers. */
export function UserPage({ pubkey, node, me, busy, run, tick }: { pubkey: string; node: NodeInfo | null } & PageProps) {
  const valid = isPubkey(pubkey);
  const { data, error } = useLoad<UserData>(
    valid
      ? async () => {
          const [grants, written] = await Promise.all([getPosts({ type: "grant", prefix: GRANT_PATH }), getPosts({ author: pubkey })]);
          return { grants: grants.filter((g) => grantNames(g, pubkey, false)), written };
        }
      : null,
    [pubkey],
    tick,
  );
  if (!valid) return <ErrorBox><code className="break-all">{pubkey}</code> isn't a valid ID (32 bytes of base58).</ErrorBox>;
  const items = { me, busy, run };
  const isThisNode = node?.pubkey === pubkey;
  return (
    <>
      <Identity pubkey={pubkey} node={node} me={me} grants={data?.grants ?? null} busy={busy} run={run} />
      {isThisNode && <NodeAdmin node={node} me={me} busy={busy} run={run} tick={tick} />}
      <h2 className="mt-10 text-xl font-semibold">Written</h2>
      {error && <ErrorBox>Couldn't load records: {error}</ErrorBox>}
      {data === null ? (
        !error && <p className="mt-3 text-gray-500">Loading…</p>
      ) : data.written.length === 0 ? (
        <p className="mt-3 text-gray-500">Nothing yet.</p>
      ) : (
        <Subtree path="/" posts={data.written} {...items} />
      )}
    </>
  );
}
