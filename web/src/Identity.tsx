import { type MouseEvent, useEffect, useState } from "react";
import { encode } from "uqr";
import {
  type Choice,
  type NodeInfo,
  type Post,
  type User,
  type Written,
  addOwner,
  amOwner,
  getPosts,
  getUsers,
  isPubkey,
  makeGrant,
  putPeer,
  userPhrase,
} from "./api.ts";
import { PostItem, UserLink } from "./NoteList.tsx";
import { Link, idPath, recordPath } from "./router.tsx";
import { type Run, hl, input, link, primary, secondary, textarea, useLoad } from "./ui.ts";

/** A QR code as an SVG, encoded entirely client-side. */
function QrCode({ text, className }: { text: string; className?: string }) {
  const { data, size } = encode(text, { ecc: "M", border: 2 });
  let d = "";
  data.forEach((row, y) => row.forEach((dark, x) => dark && (d += `M${x} ${y}h1v1h-1z`)));
  return (
    <svg viewBox={`0 0 ${size} ${size}`} className={className} shapeRendering="crispEdges" role="img">
      <title>{text}</title>
      <rect width={size} height={size} fill="#fff" />
      <path d={d} fill="#000" />
    </svg>
  );
}

/** Copies `text`; reports whether it worked. */
async function copy(text: string) {
  try {
    await navigator.clipboard.writeText(text);
    return true;
  } catch {
    return false;
  }
}

/** A read-only text box that copies its value when clicked. */
function CopyBox({ label, value, id }: { label: string; value: string; id?: boolean }) {
  const [status, setStatus] = useState("");
  const onClick = async (e: MouseEvent<HTMLInputElement>) => {
    e.currentTarget.select(); // if copying fails, at least it's ready for Ctrl+C
    setStatus((await copy(value)) ? "Copied!" : "Press Ctrl+C to copy");
    setTimeout(() => setStatus(""), 1500);
  };
  return (
    <label className="block text-sm">
      <span className="flex justify-between font-medium">
        {label}
        <span className="font-normal text-green-700" aria-live="polite">
          {status}
        </span>
      </span>
      <input
        readOnly
        value={value}
        onClick={onClick}
        title="Click to copy"
        className={`mt-1 block w-full cursor-copy rounded-md ${id ? "bg-green-100 ring-green-300" : "bg-gray-50 ring-gray-300"} p-2 font-mono text-xs ring-1 ring-inset focus:ring-2 focus:ring-indigo-600 focus:outline-none`}
      />
    </label>
  );
}

/** A form's result: the record it wrote, linked, and the claim link it made, if any. */
function Saved({ saved, children }: { saved: Written | null; children?: React.ReactNode }) {
  if (!saved) return null;
  return (
    <div className="mt-2 space-y-2">
      <p className="text-sm text-gray-600">
        Saved as{" "}
        <Link href={recordPath(saved.hash)} className={`font-mono ${link}`}>
          #{saved.hash.slice(0, 8)}
        </Link>
        . {children}
      </p>
      {saved.link && <ClaimLink link={saved.link} />}
    </div>
  );
}

/** A new claim link, to pass on. It's only shown this once: the node keeps just its token's hash. */
export function ClaimLink({ link }: { link: string }) {
  return (
    <div className="flex flex-col gap-3 rounded-lg bg-amber-50 p-3 ring-1 ring-amber-200 sm:flex-row sm:items-start">
      <QrCode text={link} className="w-32 shrink-0 self-center rounded ring-1 ring-gray-200 sm:self-start" />
      <div className="min-w-0 flex-1 space-y-2">
        <CopyBox label="Claim link" value={link} />
        <p className="text-xs text-amber-900">
          Whoever opens this first and signs in gets what it grants. It works once, and it won't be shown again: copy it now.
          Deleting the claim record cancels it.
        </p>
      </div>
    </div>
  );
}

/** Picks who a record names: a known user or a typed ID, a new claim link, or (with `anyone`) anyone. */
function WhoPicker({ value, onChange, anyone }: { value: Choice; onChange: (c: Choice) => void; anyone?: boolean }) {
  const [users, setUsers] = useState<User[]>([]);
  useEffect(() => {
    getUsers().then((u) => setUsers(u.filter((u) => !u.node)), () => {});
  }, []);
  const [id, setId] = useState(value.kind === "user" ? value.id : "");
  const toggle = (kind: "claim" | "anyone") => (e: React.ChangeEvent<HTMLInputElement>) =>
    onChange(e.target.checked ? { kind } : { kind: "user", id });
  const known = value.kind === "user" && users.find((u) => u.pubkey === value.id.trim());
  return (
    <div className="space-y-1.5">
      <input
        className={`${input} font-mono disabled:opacity-50`}
        placeholder="A user's ID (pick a known one, or paste one)"
        list="known-users"
        disabled={value.kind !== "user"}
        value={id}
        onChange={(e) => {
          setId(e.target.value);
          onChange({ kind: "user", id: e.target.value });
        }}
      />
      <datalist id="known-users">
        {users.map((u) => (
          <option key={u.pubkey} value={u.pubkey} label={u.phrase} />
        ))}
      </datalist>
      {known && <span className={`text-xs ${hl(known.phrase)}`}>{known.phrase}</span>}
      <div className="flex flex-wrap gap-x-4">
        <label className="flex items-center gap-1.5">
          <input type="checkbox" checked={value.kind === "claim"} onChange={toggle("claim")} />
          Someone new: make a claim link
        </label>
        {anyone && (
          <label className="flex items-center gap-1.5">
            <input type="checkbox" checked={value.kind === "anyone"} onChange={toggle("anyone")} />
            Anyone
          </label>
        )}
      </div>
    </div>
  );
}

const ready = (c: Choice) => c.kind !== "user" || isPubkey(c.id.trim());

/** Lets an owner (us) let someone write at or under a path, saved as a grant record. `grantee`: an ID,
 * when it's for a given user. */
function GrantForm({ grantee, busy, run }: { grantee?: string; busy: boolean; run: Run }) {
  const [who, setWho] = useState<Choice>(grantee ? { kind: "user", id: grantee } : { kind: "anyone" });
  const [path, setPath] = useState("/post");
  const [saved, setSaved] = useState<Written | null>(null);
  return (
    <div className="mt-3 space-y-2 text-sm">
      {!grantee && <WhoPicker value={who} onChange={setWho} anyone />}
      <div className="flex flex-wrap items-center gap-2">
        <label className="flex min-w-48 flex-1 items-center gap-1.5 whitespace-nowrap">
          May write at or under
          <input className={`${input} font-mono`} value={path} onChange={(e) => setPath(e.target.value)} />
        </label>
        <button
          className={primary}
          disabled={busy || !ready(who)}
          onClick={run(async () => {
            setSaved(null);
            setSaved(await makeGrant(who, path));
          })}
        >
          Grant
        </button>
      </div>
      <Saved saved={saved}>It can't be revoked yet: deleting the record doesn't take back what was written under it.</Saved>
    </div>
  );
}

/** Lets an owner (us) have this node push records to another node, saved as a peer record. */
function PeerForm({ busy, run }: { busy: boolean; run: Run }) {
  const [url, setUrl] = useState("");
  const [types, setTypes] = useState("");
  const [paths, setPaths] = useState("");
  const [saved, setSaved] = useState<Written | null>(null);
  return (
    <div className="mt-3 space-y-2 text-sm">
      <label className="block">
        Its URL
        <input className={`${input} font-mono`} placeholder="http://localhost:8081" value={url} onChange={(e) => setUrl(e.target.value)} />
      </label>
      <label className="block">
        Types <span className="text-gray-500">(comma-separated; empty for all. Deletes always follow.)</span>
        <input className={`${input} font-mono`} placeholder="post" value={types} onChange={(e) => setTypes(e.target.value)} />
      </label>
      <label className="block">
        Paths <span className="text-gray-500">(one per line, each with what's under it; empty for all)</span>
        <textarea className={`${textarea} font-mono`} rows={2} placeholder={"/post"} value={paths} onChange={(e) => setPaths(e.target.value)} />
      </label>
      <button
        className={primary}
        disabled={busy || !url.trim()}
        onClick={run(async () => {
          setSaved(null);
          setSaved({ hash: await putPeer(url, types, paths) });
        })}
      >
        Add peer
      </button>
      <Saved saved={saved}>Delete that record to stop pushing there.</Saved>
    </div>
  );
}

/** Lets an owner (us) add an owner. */
function AddOwnerForm({ busy, run }: { busy: boolean; run: Run }) {
  const [who, setWho] = useState<Choice>({ kind: "user", id: "" });
  const [saved, setSaved] = useState<Written | null>(null);
  return (
    <div className="mt-3 space-y-2 text-sm">
      <WhoPicker value={who} onChange={setWho} />
      <button
        className={secondary}
        disabled={busy || !ready(who)}
        onClick={run(async () => {
          setSaved(null);
          setSaved(await addOwner(who));
        })}
      >
        Add owner
      </button>
      <Saved saved={saved} />
    </div>
  );
}

/** The top of a user's page: who they are, how to link to them, and the grants that name them. */
export function Identity({
  pubkey,
  node,
  me,
  grants,
  busy,
  run,
}: {
  pubkey: string;
  node: NodeInfo | null;
  me: User | null;
  /** Valid grants that name this user. */
  grants: Post[] | null;
  busy: boolean;
  run: Run;
}) {
  const url = `${location.origin}${idPath(pubkey)}`;
  const phrase = userPhrase(pubkey);
  const mine = me?.pubkey === pubkey;
  const isOwner = !!node?.owners.includes(pubkey);
  const owner = !!me && amOwner();
  return (
    <>
      <h1 className="mt-2 text-3xl font-bold tracking-tight break-words">
        <span className={hl(phrase)}>{phrase}</span>
        {mine && <span className="ml-2 text-lg font-normal text-gray-500">(you)</span>}
        {isOwner && <span className="ml-2 text-lg font-normal text-gray-500">👑 owns this node</span>}
      </h1>

      <section className="mt-6 flex flex-col gap-6 sm:flex-row sm:items-start">
        <QrCode text={url} className="w-48 shrink-0 self-center rounded-lg ring-1 ring-gray-200 sm:self-start" />
        <div className="min-w-0 flex-1 space-y-3">
          <CopyBox label="Public ID (key)" value={pubkey} id />
          <CopyBox label="Link to this page" value={url} />
          <p className="text-xs text-gray-500">
            The ID is an Ed25519 public key. Records below are checked against their authors' keys in your browser;
            the phrase is just a readable nickname derived from it.
          </p>
        </div>
      </section>

      {grants && grants.length > 0 && (
        <>
          <h2 className="mt-10 text-xl font-semibold">May write at</h2>
          <ul className="mt-3 divide-y divide-gray-200 rounded-lg ring-1 ring-gray-200">
            {grants.map((g) => (
              <li key={g.root} className="flex flex-wrap items-baseline justify-between gap-2 p-3 text-sm">
                <span>
                  🔑 <code className="font-mono">{g.grant!.path}</code> and under it, granted by <UserLink user={g.author} me={me} />
                </span>
                <Link href={recordPath(g.root)} className={`font-mono text-xs text-gray-500 ${link}`}>
                  #{g.root.slice(0, 8)}
                </Link>
              </li>
            ))}
          </ul>
        </>
      )}
      {owner && !mine && node?.pubkey !== pubkey && (
        <section className="mt-10">
          <h2 className="text-xl font-semibold">
            Let <span className={hl(phrase)}>{phrase}</span> write here
          </h2>
          <GrantForm grantee={pubkey} busy={busy} run={run} />
          {!isOwner && (
            <button className={`${secondary} mt-3`} disabled={busy} onClick={run(() => addOwner({ kind: "user", id: pubkey }))}>
              👑 Make <span className={hl(phrase)}>{phrase}</span> an owner
            </button>
          )}
        </section>
      )}
    </>
  );
}

/** On this node's page: its owners, grants, claims and peers (its /node records), and forms to add them if we own it. */
export function NodeAdmin({ me, busy, run, tick }: { me: User | null; busy: boolean; run: Run; tick: number }) {
  const { data } = useLoad(() => getPosts({ prefix: "/node" }), [], tick);
  const owner = !!me && amOwner();
  const items = { me, busy, run };
  const section = (title: string, type: string, form: React.ReactNode | null, note?: string) => {
    const posts = data?.filter((p) => p.rec.type === type) ?? [];
    return (
      <section className="mt-10">
        <h2 className="text-xl font-semibold">{title}</h2>
        {note && <p className="mt-1 text-sm text-gray-500">{note}</p>}
        {data === null ? (
          <p className="mt-3 text-gray-500">Loading…</p>
        ) : posts.length === 0 ? (
          <p className="mt-3 text-gray-500">None yet.</p>
        ) : (
          <ul className="mt-3 divide-y divide-gray-200 rounded-lg ring-1 ring-gray-200">
            {posts.map((p) => (
              <li key={p.root}>
                <PostItem post={p} hidePath {...items} />
              </li>
            ))}
          </ul>
        )}
        {owner && form}
      </section>
    );
  };
  return (
    <>
      {section("Owners", "owner", <AddOwnerForm busy={busy} run={run} />, "They can write anything, anywhere on this node, and edit or delete any record.")}
      {section("Grants", "grant", <GrantForm busy={busy} run={run} />, "Who else may write where.")}
      {section(
        "Claims",
        "claim",
        null,
        "One-time links, for owners and grants to name someone not known yet. Make one by checking \"claim link\" above.",
      )}
      {section(
        "Peers",
        "peer",
        <PeerForm busy={busy} run={run} />,
        "Nodes this one pushes new records to (and everything so far, to start). Each passes on only records new to it, so loops die out. Records under /node never leave.",
      )}
    </>
  );
}
