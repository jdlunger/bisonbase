import { useEffect, useRef, useState } from "react";
import { type Grant, type Post, type User, canEdit, deletePost, newPostPath, putPost } from "./api.ts";
import { Link, idPath, recordPath } from "./router.tsx";
import { type Run, badge, danger, fmtTime, input, link, primary, secondary, textarea } from "./ui.ts";

/** `path` and `grant` are only for new posts: where it goes, and the grant to write in someone else's space. */
export type Draft = { body: string; path?: string; grant?: Grant };

/** Post text, and where it goes (for new posts). Posts are always signed. */
export function NoteEditor(props: {
  draft: Draft;
  setDraft: (d: Draft) => void;
  /** Grants we hold, offered as places to post besides our own space. */
  grants?: Grant[];
  busy: boolean;
  submitLabel: string;
  onSubmit: () => void;
  onCancel?: () => void;
}) {
  const { draft, setDraft, busy, grants = [] } = props;
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
      {draft.path !== undefined && (
        <div className="flex flex-wrap gap-2 text-sm">
          {grants.length > 0 && (
            <label className="flex items-center gap-1.5">
              In
              <select
                className={input}
                value={draft.grant?.uri ?? ""}
                onChange={(e) => {
                  const grant = grants.find((g) => g.uri === e.target.value);
                  const path = grant ? `${grant.path}/${newPostPath().split("/").pop()}` : newPostPath();
                  setDraft({ ...draft, grant, path });
                }}
              >
                <option value="">my space</option>
                {grants.map((g) => (
                  <option key={g.uri} value={g.uri}>
                    {g.owner.phrase}'s space, under {g.path}
                  </option>
                ))}
              </select>
            </label>
          )}
          <label className="flex min-w-48 flex-1 items-center gap-1.5">
            Path
            <input
              className={`${input} font-mono`}
              value={draft.path}
              onChange={(e) => setDraft({ ...draft, path: e.target.value })}
            />
          </label>
        </div>
      )}
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

/** Badge colors for record types; known types get fixed ones, any other type a stable pick by hash. */
const typeColors = [
  "bg-sky-50 text-sky-700 ring-sky-200",
  "bg-amber-50 text-amber-700 ring-amber-200",
  "bg-gray-100 text-gray-600 ring-gray-300",
  "bg-violet-50 text-violet-700 ring-violet-200",
  "bg-pink-50 text-pink-700 ring-pink-200",
  "bg-teal-50 text-teal-700 ring-teal-200",
  "bg-orange-50 text-orange-700 ring-orange-200",
  "bg-lime-50 text-lime-700 ring-lime-200",
];
const knownTypes: Record<string, number> = { post: 0, grant: 1, tombstone: 2 };

function typeColor(type: string) {
  if (type in knownTypes) return typeColors[knownTypes[type]];
  let h = 0;
  for (const c of type) h = (h * 31 + c.charCodeAt(0)) >>> 0;
  return typeColors[3 + (h % (typeColors.length - 3))];
}

/** A record's bb:// address with the owner as a phrase (`short`: just its first word). Clicking or
 * selecting any of it swaps in the real address, selected and copied to the clipboard, until it loses focus. */
function Uri({ post: n, short }: { post: Post; short: boolean }) {
  const [full, setFull] = useState(false);
  const [copied, setCopied] = useState(false);
  const ref = useRef<HTMLDivElement>(null);
  const href = recordPath(n.owner.pubkey, n.rec.path);
  useEffect(() => {
    if (!full || !ref.current) return;
    getSelection()?.selectAllChildren(ref.current);
    navigator.clipboard?.writeText(location.origin + href).then(
      () => setCopied(true),
      () => {},
    );
  }, [full]);
  useEffect(() => {
    if (!copied) return;
    const t = setTimeout(() => setCopied(false), 1200);
    return () => clearTimeout(t);
  }, [copied]);
  return (
    <div className="relative">
      {copied && (
        <span className="pointer-events-none absolute bottom-full left-0 mb-1 rounded bg-gray-900 px-2 py-0.5 text-xs text-white shadow select-none">
          Link copied
        </span>
      )}
      <div
        ref={ref}
        tabIndex={-1}
        onMouseUp={() => setFull(true)}
        onBlur={() => setFull(false)}
        className="font-mono text-sm break-all text-gray-500 outline-none"
      >
        {full ? (
          <Link href={href} className={link}>
            {location.origin}/bb/{n.owner.pubkey}
            <span className="font-semibold text-gray-900">{n.rec.path}</span>
          </Link>
        ) : (
          <>
            bb://
            <span title={n.owner.pubkey}>{short ? `${n.owner.phrase.split("_")[0]}_…` : n.owner.phrase}</span>
            <span className="font-semibold text-gray-900">{n.rec.path}</span>
          </>
        )}
      </div>
    </div>
  );
}

type ItemProps = { post: Post; me: User | null; busy: boolean; run: Run };

/** One record: author, badges, content, and Edit / Delete when we may. `name` replaces the bb:// address (in trees). */
function PostItem({ post: n, me, busy, run, name }: ItemProps & { name?: string }) {
  const [editing, setEditing] = useState<Draft | null>(null);
  const mine = me?.pubkey === n.author.pubkey;
  const text = n.text ?? undefined;
  const elsewhere = n.owner.pubkey !== n.author.pubkey;
  return (
    <div className="p-3">
      {name ? <div className="font-mono text-sm font-semibold">{name}</div> : <Uri post={n} short={!elsewhere} />}
      <div className="flex flex-wrap items-baseline justify-between gap-2 text-sm">
        <span className="flex flex-wrap items-baseline gap-2">
          <Link href={idPath(n.author.pubkey)} className={link} title={n.author.pubkey}>
            {n.author.phrase}
            {mine && <span className="ml-1 font-normal text-gray-500">(you)</span>}
          </Link>
          {n.verified ? (
            <span
              className="font-semibold text-green-600"
              title="Signature verified in your browser against the author's public key"
            >
              ✓
            </span>
          ) : (
            <span className={`${badge} bg-red-50 text-red-700 ring-red-200`}>✗ bad signature</span>
          )}
          <span className={`${badge} font-mono ${typeColor(n.rec.type)}`}>{n.rec.type}</span>
        </span>
        <span className="text-xs text-gray-500">{fmtTime(n.rec.version / 1000)}</span>
      </div>
      {editing ? (
        <div className="mt-2">
          <NoteEditor
            draft={editing}
            setDraft={setEditing}
            busy={busy}
            submitLabel="Save"
            onSubmit={run(async () => {
              await putPost(editing.body, {}, n);
              setEditing(null);
            })}
            onCancel={() => setEditing(null)}
          />
        </div>
      ) : (
        <>
          {n.grant ? (
            <p className="mt-1">
              🔑 Lets{" "}
              <Link href={idPath(n.grant.grantee.pubkey)} className={`font-semibold ${link}`} title={n.grant.grantee.pubkey}>
                {n.grant.grantee.phrase}
                {me?.pubkey === n.grant.grantee.pubkey && <span className="ml-1 font-normal text-gray-500">(you)</span>}
              </Link>{" "}
              write at or under <code className="font-mono text-sm">{n.grant.path}</code>
            </p>
          ) : text !== undefined ? (
            <p className="mt-1 whitespace-pre-wrap break-words">{text}</p>
          ) : (
            <p className="mt-1 text-sm text-gray-500 italic">(a {n.rec.type} record this page can't show)</p>
          )}
          {me && canEdit(n) && (
            <div className="mt-2 flex gap-2">
              {n.rec.type === "post" && (
                <button
                  className={secondary}
                  disabled={busy || text === undefined}
                  onClick={() => setEditing({ body: text! })}
                >
                  Edit
                </button>
              )}
              <button className={danger} disabled={busy} onClick={run(() => deletePost(n))}>
                Delete
              </button>
            </div>
          )}
        </>
      )}
    </div>
  );
}

/** Records as a flat list, newest first. Signatures were checked (in the browser) when they were fetched. */
export function NoteList({ posts, ...rest }: { posts: Post[] } & Omit<ItemProps, "post">) {
  return (
    <ul className="mt-4 divide-y divide-gray-200 rounded-lg ring-1 ring-gray-200">
      {posts.map((p) => (
        <li key={p.uri}>
          <PostItem post={p} {...rest} />
        </li>
      ))}
    </ul>
  );
}

// ---- the whole hierarchy: spaces, then folders (path segments), then records ----

type Node = { post?: Post; children: Map<string, Node> };
const newNode = (): Node => ({ children: new Map() });

/** Files each post under `root` by its path segments after `base` ("" or "/a/b"). */
function buildTree(posts: Post[], base = "", root = newNode()) {
  for (const p of posts) {
    let node = root;
    const rest = p.rec.path.slice(base.length);
    if (rest)
      for (const seg of rest.slice(1).split("/")) {
        let next = node.children.get(seg);
        if (!next) node.children.set(seg, (next = newNode()));
        node = next;
      }
    node.post = p;
  }
  return root;
}

/** `node`'s children: records by name, and subfolders (linking to their own page). `dir` is `node`'s path ("" for the root). */
function Folder({ node, owner, dir, ...rest }: { node: Node; owner: string; dir: string } & Omit<ItemProps, "post">) {
  return (
    <ul className="space-y-2">
      {[...node.children]
        .sort(([a], [b]) => a.localeCompare(b))
        .map(([seg, child]) => (
          <li key={seg}>
            {child.post && (
              <div className="rounded-lg ring-1 ring-gray-200">
                <PostItem post={child.post} name={seg} {...rest} />
              </div>
            )}
            {child.children.size > 0 && (
              <>
                <Link href={recordPath(owner, `${dir}/${seg}`)} className={`mt-1 block font-mono text-sm text-gray-700 ${link}`}>
                  📁 {seg}/
                </Link>
                <div className="mt-1 ml-2 border-l border-gray-200 pl-3">
                  <Folder node={child} owner={owner} dir={`${dir}/${seg}`} {...rest} />
                </div>
              </>
            )}
          </li>
        ))}
    </ul>
  );
}

/** Every record, grouped by space and nested by path. `first` (a base58 ID) puts that space first. */
export function PostTree({ posts, first, ...rest }: { posts: Post[]; first?: string } & Omit<ItemProps, "post">) {
  const spaces = new Map<string, { owner: User; posts: Post[] }>();
  for (const p of posts) {
    let space = spaces.get(p.owner.pubkey);
    if (!space) spaces.set(p.owner.pubkey, (space = { owner: p.owner, posts: [] }));
    space.posts.push(p);
  }
  const ordered = [...spaces.values()].sort(
    (a, b) => Number(b.owner.pubkey === first) - Number(a.owner.pubkey === first) || a.owner.phrase.localeCompare(b.owner.phrase),
  );
  return (
    <div className="mt-4 space-y-6">
      {ordered.map(({ owner, posts }) => (
        <section key={owner.pubkey}>
          <h3 className="font-mono text-sm break-all">
            bb://
            <Link href={idPath(owner.pubkey)} className={`font-semibold ${link}`} title={owner.pubkey}>
              {owner.phrase}
            </Link>
            /
          </h3>
          <div className="mt-2">
            <Folder node={buildTree(posts)} owner={owner.pubkey} dir="" {...rest} />
          </div>
        </section>
      ))}
    </div>
  );
}

/** One space at `path` ("/" for all of it): the record there, if any, then everything below it. `posts` are all at or under `path`. */
export function Subtree({
  owner,
  path,
  posts,
  ...rest
}: { owner: string; path: string; posts: Post[] } & Omit<ItemProps, "post">) {
  const dir = path === "/" ? "" : path;
  const root = buildTree(posts, dir);
  return (
    <div className="mt-4 space-y-4">
      {root.post && (
        <div className="rounded-lg ring-1 ring-gray-200">
          <PostItem post={root.post} {...rest} />
        </div>
      )}
      {root.children.size > 0 && <Folder node={root} owner={owner} dir={dir} {...rest} />}
    </div>
  );
}
