import { type MouseEvent, useContext, useState } from "react";
import { encode } from "uqr";
import { type Post, type User, makeGrant, putFederate } from "./api.ts";
import { Compose } from "./NoteList.tsx";
import { Link, idPath } from "./router.tsx";
import { type Run, fmtTime, idHl, input, link, hl, primary, textarea } from "./ui.ts";

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

/** Lets the owner (us) grant this page's user write access under a path in our space, saved as a grant record. */
function GrantForm({ grantee, phrase, busy, run }: { grantee: string; phrase: string; busy: boolean; run: Run }) {
  const [path, setPath] = useState("/shared");
  const [saved, setSaved] = useState("");
  return (
    <section className="mt-10">
      <h2 className="text-xl font-semibold">Let <span className={hl(phrase)}>{phrase}</span> write in your space</h2>
      <div className="mt-3 flex flex-wrap items-center gap-2 text-sm">
        <label className="flex min-w-48 flex-1 items-center gap-1.5 whitespace-nowrap">
          At or under
          <input className={`${input} font-mono`} value={path} onChange={(e) => setPath(e.target.value)} />
        </label>
        <button
          className={primary}
          disabled={busy}
          onClick={run(async () => {
            setSaved("");
            setSaved(await makeGrant(grantee, path));
          })}
        >
          Grant
        </button>
      </div>
      {saved && (
        <p className="mt-2 text-sm text-gray-600">
          Saved as <code className="font-mono text-xs break-all">{saved}</code>. <span className={hl(phrase)}>{phrase}</span> can now pick it when posting.
          It can't be revoked yet: deleting the record doesn't stop the grant from working.
        </p>
      )}
    </section>
  );
}

/** Lets this server's owner (us) have it push records to another server, saved as a federate record. */
function FederateForm({ server, busy, run }: { server: string; busy: boolean; run: Run }) {
  const [url, setUrl] = useState("");
  const [types, setTypes] = useState("");
  const [paths, setPaths] = useState("");
  const [saved, setSaved] = useState("");
  return (
    <section className="mt-10">
      <h2 className="text-xl font-semibold">Federate with another server</h2>
      <p className="mt-1 text-sm text-gray-500">
        New records here get pushed to it (and everything so far, to start). Each server passes on only records
        that are new to it, so loops die out.
      </p>
      <div className="mt-3 space-y-2 text-sm">
        <label className="block">
          Its URL
          <input className={`${input} font-mono`} placeholder="http://localhost:8081" value={url} onChange={(e) => setUrl(e.target.value)} />
        </label>
        <label className="block">
          Types <span className="text-gray-500">(comma-separated; empty for all. Deletes always follow.)</span>
          <input className={`${input} font-mono`} placeholder="post, grant" value={types} onChange={(e) => setTypes(e.target.value)} />
        </label>
        <label className="block">
          Paths <span className="text-gray-500">(one per line, bb://&lt;ID or *&gt;/&lt;path&gt;; empty for all)</span>
          <textarea
            className={`${textarea} font-mono`}
            rows={2}
            placeholder={"bb://*/posts\nbb://*/"}
            value={paths}
            onChange={(e) => setPaths(e.target.value)}
          />
        </label>
        <button
          className={primary}
          disabled={busy || !url.trim()}
          onClick={run(async () => {
            setSaved("");
            setSaved(await putFederate(server, url, types, paths));
          })}
        >
          Federate
        </button>
      </div>
      {saved && (
        <p className="mt-2 text-sm text-gray-600">
          Saved as <code className="font-mono text-xs break-all">{saved}</code>. Delete that record to stop pushing there.
        </p>
      )}
    </section>
  );
}

/** A user, linked to their page; "(you)" if it's us. */
function UserLink({ user, me }: { user: User; me: string | null }) {
  return (
    <Link href={idPath(user.pubkey)} className={`font-semibold ${link}`} title={user.pubkey}>
      <span className={hl(user.phrase)}>{user.phrase}</span>
      {user.pubkey === me && <span className="ml-1 font-normal text-gray-500">(you)</span>}
    </Link>
  );
}

/** Grants this user has given, and been given: who may write where. */
function Grants({ pubkey, grants, me }: { pubkey: string; grants: Post[]; me: string | null }) {
  const given = grants.filter((g) => g.owner.pubkey === pubkey);
  const received = grants.filter((g) => g.grant!.grantee.pubkey === pubkey);
  const row = (g: Post, who: User, dir: "given" | "received") => (
    <li key={g.uri} className="flex flex-wrap items-baseline justify-between gap-2 p-3 text-sm">
      <span>
        🔑 {dir === "given" ? "Lets " : "Can write in "}
        <UserLink user={who} me={me} />
        {dir === "given" ? " write at or under " : "'s space, at or under "}
        <code className="font-mono">{g.grant!.path}</code>
      </span>
      <span className="text-xs text-gray-500" title={g.uri}>
        {fmtTime(g.rec.version / 1000)}
      </span>
    </li>
  );
  return (
    <>
      <h2 className="mt-10 text-xl font-semibold">Grants</h2>
      {given.length + received.length === 0 ? (
        <p className="mt-3 text-gray-500">None yet.</p>
      ) : (
        <ul className="mt-3 divide-y divide-gray-200 rounded-lg ring-1 ring-gray-200">
          {received.map((g) => row(g, g.owner, "received"))}
          {given.map((g) => row(g, g.grant!.grantee, "given"))}
        </ul>
      )}
    </>
  );
}

/** The top of a user's page (their space's root): who they are, how to link to them, and their grants. */
export function OwnerInfo({
  pubkey,
  phrase,
  grants,
  me,
  busy,
  run,
}: {
  pubkey: string;
  phrase: string | null;
  /** Valid grants this user gave or received. */
  grants: Post[] | null;
  me: string | null;
  busy: boolean;
  run: Run;
}) {
  const url = `${location.origin}${idPath(pubkey)}`;
  const mine = me === pubkey;
  // Only a server's owner holds its /federate grant.
  const owns = useContext(Compose).canWrite(pubkey, "/federate");
  return (
    <>
      <h1 className="mt-2 text-3xl font-bold tracking-tight break-words">
        <span className={hl(phrase ?? "…")}>{phrase ?? "…"}</span>
        {mine && <span className="ml-2 text-lg font-normal text-gray-500">(you)</span>}
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

      {grants && <Grants pubkey={pubkey} grants={grants} me={me} />}
      {me && !mine && phrase && <GrantForm grantee={pubkey} phrase={phrase} busy={busy} run={run} />}
      {owns && <FederateForm server={pubkey} busy={busy} run={run} />}
    </>
  );
}
