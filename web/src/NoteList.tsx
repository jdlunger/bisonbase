import { createContext, useContext, useState } from "react";
import { type Party, type Post, type User, b58, canEdit, deletePost, docLabel, pathWithin, putPost } from "./api.ts";
import { Link, docPath, idPath, pathPath, recordPath } from "./router.tsx";
import { type Run, badge, danger, fmtTime, input, link, hl, primary, secondary, textarea } from "./ui.ts";

/** Post text, the path to file it under, and whether only this node's owners may read it. */
export type Draft = { body: string; path: string; private: boolean };

/** Where we may post, and opening the new-post form there. Provided by the app. */
export const Compose = createContext<{ canWrite: (path: string) => boolean; open: (path: string) => void; writable: string[] }>({
  canWrite: () => false,
  open: () => {},
  writable: [],
});

/** Post text and its path. Posts are always signed. */
export function NoteEditor(props: {
  draft: Draft;
  setDraft: (d: Draft) => void;
  busy: boolean;
  submitLabel: string;
  onSubmit: () => void;
  onCancel?: () => void;
}) {
  const { draft, setDraft, busy } = props;
  const { writable } = useContext(Compose);
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
      <label className="flex items-center gap-1.5 text-sm">
        Path
        <input
          className={`${input} font-mono`}
          value={draft.path}
          list="writable-paths"
          onChange={(e) => setDraft({ ...draft, path: e.target.value })}
        />
        <datalist id="writable-paths">
          {writable.filter((p) => p !== "/").map((p) => (
            <option key={p} value={p} />
          ))}
        </datalist>
      </label>
      <label className="flex items-center gap-1.5 text-sm" title="Only this node's owners can see it, and it isn't sent to peers">
        <input type="checkbox" checked={draft.private} onChange={(e) => setDraft({ ...draft, private: e.target.checked })} />
        🔒 Private <span className="text-gray-500">(only this node's owners can see it)</span>
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
const knownTypes: Record<string, number> = {
  post: 0,
  grant: 1,
  tombstone: 2,
  node: 6,
  owner: 6,
  access: 6,
  peer: 6,
  claim: 6,
  delegate: 6,
  enckey: 6,
  doc: 5,
  doc_update: 5,
  doc_snapshot: 5,
};

function typeColor(type: string) {
  if (type in knownTypes) return typeColors[knownTypes[type]];
  let h = 0;
  for (const c of type) h = (h * 31 + c.charCodeAt(0)) >>> 0;
  return typeColors[3 + (h % (typeColors.length - 3))];
}

/** A user, linked to their page; "(you)" if it's us. */
export function UserLink({ user, me, className = "" }: { user: User; me: User | null; className?: string }) {
  return (
    <Link href={idPath(user.pubkey)} className={`${link} ${className}`} title={user.pubkey}>
      <span className={hl(user.phrase)}>{user.phrase}</span>
      {me?.pubkey === user.pubkey && <span className="ml-1 font-normal text-gray-500">(you)</span>}
    </Link>
  );
}

/** A path, each segment linking to its page. */
export function PathLinks({ path, className = "" }: { path: string; className?: string }) {
  const segs = path.slice(1).split("/");
  return (
    <span className={`font-mono break-all ${className}`}>
      {segs.map((seg, i) => (
        <span key={i}>
          /
          <Link href={pathPath("/" + segs.slice(0, i + 1).join("/"))} className={link}>
            {seg}
          </Link>
        </span>
      ))}
    </span>
  );
}

/** Who an owner or grant record names: a user, or a claim link (and who claimed it, once someone has). */
export function PartyLink({ party, me }: { party: Party; me: User | null }) {
  const user = party.user && <UserLink user={party.user} me={me} className="font-semibold" />;
  if (!party.claim) return user;
  const claim = (
    <Link href={recordPath(party.claim)} className={`font-mono text-sm ${link}`}>
      🎟 #{party.claim.slice(0, 8)}
    </Link>
  );
  return user ? (
    <>
      {user} <span className="text-sm text-gray-500">(via {claim})</span>
    </>
  ) : (
    <>
      <span className="italic">whoever claims</span> {claim}
    </>
  );
}

/** What a record holds, as shown. */
function Content({ post: n, me }: { post: Post; me: User | null }) {
  if (n.grant) {
    return (
      <p className="mt-1">
        🔑 Lets{" "}
        {n.grant.grantees === "anyone" ? (
          <b>anyone</b>
        ) : (
          n.grant.grantees.map((g, i) => (
            <span key={g.claim ?? g.user?.pubkey}>
              {i > 0 && ", "}
              <PartyLink party={g} me={me} />
            </span>
          ))
        )}{" "}
        write at or under <code className="font-mono text-sm">{n.grant.path}</code>
      </p>
    );
  }
  if (n.peer) {
    return (
      <p className="mt-1">
        ↔ Pushes to <UserLink user={n.peer.node} me={me} className="font-semibold" /> at{" "}
        <code className="font-mono text-sm">{n.peer.url}</code>
        <span className="block text-sm text-gray-600">
          Types: {n.peer.types?.join(", ") ?? "all"} · Paths: <code className="font-mono">{n.peer.paths?.join(" ") ?? "all"}</code>
        </span>
      </p>
    );
  }
  if (n.claim) {
    return (
      <p className="mt-1">
        🎟 A claim link:{" "}
        {n.claim.claimedBy ? (
          <>
            claimed by <UserLink user={n.claim.claimedBy} me={me} className="font-semibold" />
          </>
        ) : (
          <span className="italic">not claimed yet</span>
        )}
      </p>
    );
  }
  if (n.nodeUrl !== undefined) {
    return (
      <p className="mt-1">
        🖥 A node, at <code className="font-mono text-sm">{n.nodeUrl}</code>
      </p>
    );
  }
  if (n.owner) {
    return (
      <p className="mt-1">
        👑 Owned by <PartyLink party={n.owner} me={me} />
      </p>
    );
  }
  if (n.access) {
    return (
      <p className="mt-1">
        🚪 Lets in <PartyLink party={n.access} me={me} />
      </p>
    );
  }
  if (n.doc) {
    const editors = n.doc.editors.length;
    const { icon, noun } = docLabel(n.doc.schema);
    return (
      <p className="mt-1">
        {icon}{" "}
        <Link href={docPath(n.root)} className={`font-semibold ${link}`}>
          {n.doc.title || "Untitled"}
        </Link>
        <span className="text-sm text-gray-500">
          {" "}
          · a shared {n.doc.encrypted && "🔒 encrypted "}
          {noun}
          {editors > 0 && `, with ${editors} more editor${editors > 1 ? "s" : ""}`}
        </span>
      </p>
    );
  }
  const docRef = n.rec.docUpdate ?? n.rec.docSnapshot;
  if (docRef) {
    const doc = b58(docRef.doc);
    const size = n.rec.docUpdate?.update.length ?? n.rec.docSnapshot!.state.length;
    return (
      <p className="mt-1 text-sm">
        {n.rec.docUpdate ? "✏️ An edit to" : "📸 A snapshot of"} the doc{" "}
        <Link href={docPath(doc)} className={`font-mono ${link}`}>
          #{doc.slice(0, 8)}
        </Link>{" "}
        <span className="text-gray-500">
          ({size} bytes{n.rec.docSnapshot && `, with ${n.rec.docSnapshot.covers.length} updates in it`})
        </span>
      </p>
    );
  }
  if (n.delegate) {
    const d = n.delegate;
    return (
      <p className="mt-1">
        🔌 Lets <b>{d.name || "an app"}</b> (key <code className="font-mono text-sm">{d.key.slice(0, 8)}…</code>) sign records for{" "}
        <UserLink user={n.author} me={me} className="font-semibold" />
        <span className="block text-sm text-gray-600">
          Types: {d.types?.join(", ") ?? "all"} · Paths: <code className="font-mono">{d.paths?.join(" ") ?? "all"}</code>
          {d.expires && ` · until ${new Date(d.expires).toLocaleString()}`}
        </span>
      </p>
    );
  }
  if (n.rec.enckey) return <p className="mt-1 text-sm">🔐 An encryption key, for sealing encrypted docs' keys to its author</p>;
  if (n.rec.data !== undefined) {
    return (
      <pre className="mt-1 max-h-60 overflow-auto rounded-md bg-gray-50 p-2 text-xs whitespace-pre-wrap break-words">{showData(n.rec.data)}</pre>
    );
  }
  if (n.text !== null) return <p className="mt-1 whitespace-pre-wrap break-words">{n.text}</p>;
  if (n.rec.type === "tombstone") return <p className="mt-1 text-sm text-gray-500 italic">Deleted.</p>;
  return <p className="mt-1 text-sm text-gray-500 italic">(a {n.rec.type} record this page can't show)</p>;
}

/** An app type's data, as readable JSON: bytes as their length, BigInts as numbers. */
const showData = (data: unknown) =>
  JSON.stringify(data, (_, v) => (typeof v === "bigint" ? v.toString() : v instanceof Uint8Array ? `<${v.length} bytes>` : v), 2);

type ItemProps = { post: Post; me: User | null; busy: boolean; run: Run };

/** One record: where it is, who wrote it, badges, content, and Edit / Delete when we may. `hidePath`:
 * it's shown under its path already. `history`: one version in a record's history, without actions. */
export function PostItem({ post: n, me, busy, run, hidePath, history }: ItemProps & { hidePath?: boolean; history?: boolean }) {
  const [editing, setEditing] = useState<Draft | null>(null);
  const editedBy = n.by && n.by.pubkey !== n.author.pubkey ? n.author : null;
  return (
    <div className="p-3">
      {!hidePath && <PathLinks path={n.rec.path} className="text-sm font-semibold" />}
      <div className="flex flex-wrap items-baseline justify-between gap-2 text-sm">
        <span className="flex flex-wrap items-baseline gap-2">
          {editedBy && !history ? (
            <>
              <UserLink user={n.by!} me={me} />
              <span className="text-gray-500">edited by</span>
              <UserLink user={editedBy} me={me} />
            </>
          ) : (
            <UserLink user={n.author} me={me} />
          )}
          {n.signedBy && (
            <span className="text-gray-500" title={`Signed by the key ${n.signedBy.pubkey}, under ${n.author.phrase}'s delegation`}>
              via an app
            </span>
          )}
          {n.verified ? (
            <span className="font-semibold text-green-600" title="Signature verified in your browser against the author's public key">
              ✓
            </span>
          ) : (
            <span className={`${badge} bg-red-50 text-red-700 ring-red-200`} title={n.rec.problem}>
              ✗ bad signature
            </span>
          )}
          <span className={`${badge} font-mono ${typeColor(n.rec.type)}`}>{n.rec.type}</span>
          {n.rec.private && (
            <span className={`${badge} bg-gray-800 text-white ring-gray-800`} title="Only this node's owners can see it, and it isn't sent to peers">
              🔒 private
            </span>
          )}
        </span>
        <span className="flex items-baseline gap-2 text-xs text-gray-500">
          {!history && n.versions > 1 && (
            <Link href={recordPath(n.root)} className={link}>
              {n.versions} versions
            </Link>
          )}
          <Link href={recordPath(history ? n.hash : n.root)} className={`font-mono ${link}`} title={history ? n.hash : n.root}>
            #{(history ? n.hash : n.root).slice(0, 8)}
          </Link>
          <span>{fmtTime(n.rec.version / 1000)}</span>
        </span>
      </div>
      {editing ? (
        <div className="mt-2">
          <NoteEditor
            draft={editing}
            setDraft={setEditing}
            busy={busy}
            submitLabel="Save"
            onSubmit={run(async () => {
              await putPost(editing.body, editing.path, editing.private, n);
              setEditing(null);
            })}
            onCancel={() => setEditing(null)}
          />
        </div>
      ) : (
        <>
          <Content post={n} me={me} />
          {!history && me && canEdit(n) && (
            <div className="mt-2 flex gap-2">
              {n.rec.type === "post" && (
                <button className={secondary} disabled={busy || n.text === null} onClick={() => setEditing({ body: n.text!, path: n.rec.path, private: n.rec.private })}>
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

/** A (+) that opens the new-post form at `path`, if we may write there. */
export function NewHere({ path }: { path: string }) {
  const { canWrite, open } = useContext(Compose);
  if (path === "/" || pathWithin(path, "/node") || !canWrite(path)) return null;
  return (
    <button
      onClick={() => open(path)}
      title={`New post at ${path}`}
      aria-label="New post here"
      className="ml-1.5 inline-flex size-5 cursor-pointer items-center justify-center rounded-full align-middle font-sans text-sm leading-none text-gray-500 ring-1 ring-gray-300 hover:bg-indigo-50 hover:text-indigo-600 hover:ring-indigo-300"
    >
      +
    </button>
  );
}

// ---- the hierarchy: folders (path segments), each with the records filed at that path ----

type Node = { posts: Post[]; children: Map<string, Node> };
const newNode = (): Node => ({ posts: [], children: new Map() });

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
    node.posts.push(p);
  }
  return root;
}

function Posts({ posts, ...rest }: { posts: Post[] } & Omit<ItemProps, "post">) {
  return (
    <ul className="space-y-2">
      {posts.map((p) => (
        <li key={p.root} className="rounded-lg ring-1 ring-gray-200">
          <PostItem post={p} hidePath {...rest} />
        </li>
      ))}
    </ul>
  );
}

/** `node`'s subfolders, each linking to its own page, with its records and subfolders. `dir` is `node`'s path ("" for the root). */
function Folder({ node, dir, ...rest }: { node: Node; dir: string } & Omit<ItemProps, "post">) {
  return (
    <ul className="space-y-3">
      {[...node.children]
        .sort(([a], [b]) => a.localeCompare(b))
        .map(([seg, child]) => (
          <li key={seg}>
            <div className="font-mono text-sm text-gray-700">
              <Link href={pathPath(`${dir}/${seg}`)} className={link}>
                📁 {seg}/
              </Link>
              <NewHere path={`${dir}/${seg}`} />
            </div>
            <div className="mt-1 ml-2 space-y-2 border-l border-gray-200 pl-3">
              {child.posts.length > 0 && <Posts posts={child.posts} {...rest} />}
              {child.children.size > 0 && <Folder node={child} dir={`${dir}/${seg}`} {...rest} />}
            </div>
          </li>
        ))}
    </ul>
  );
}

/** Records at or under `path` ("/" for all): those at `path` itself, then its subfolders. */
export function Subtree({ path, posts, ...rest }: { path: string; posts: Post[] } & Omit<ItemProps, "post">) {
  const dir = path === "/" ? "" : path;
  const root = buildTree(posts, dir);
  return (
    <div className="mt-4 space-y-4">
      {root.posts.length > 0 && <Posts posts={root.posts} {...rest} />}
      {root.children.size > 0 && <Folder node={root} dir={dir} {...rest} />}
    </div>
  );
}
