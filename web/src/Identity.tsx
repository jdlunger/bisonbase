import { type MouseEvent, useCallback, useEffect, useState } from "react";
import { encode } from "uqr";
import { type Post, type User, getPosts, isPubkey, makeGrant, myPubkey, userPhrase } from "./api.ts";
import { PostTree } from "./NoteList.tsx";
import { Link, idPath } from "./router.tsx";
import { type Run, fmtTime, input, link, primary } from "./ui.ts";

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
function CopyBox({ label, value }: { label: string; value: string }) {
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
        className="mt-1 block w-full cursor-copy rounded-md bg-gray-50 p-2 font-mono text-xs ring-1 ring-gray-300 ring-inset focus:ring-2 focus:ring-indigo-600 focus:outline-none"
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
      <h2 className="text-xl font-semibold">Let {phrase} write in your space</h2>
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
          Saved as <code className="font-mono text-xs break-all">{saved}</code>. {phrase} can now pick it when posting.
          It can't be revoked yet: deleting the record doesn't stop the grant from working.
        </p>
      )}
    </section>
  );
}

/** A user, linked to their page; "(you)" if it's us. */
function UserLink({ user, me }: { user: User; me: string | null }) {
  return (
    <Link href={idPath(user.pubkey)} className={`font-semibold ${link}`} title={user.pubkey}>
      {user.phrase}
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

export default function Identity({ pubkey }: { pubkey: string }) {
  const valid = isPubkey(pubkey);
  const url = `${location.origin}${idPath(pubkey)}`;
  const myId = myPubkey();
  const mine = myId === pubkey;
  const [phrase, setPhrase] = useState<string | null>(null);
  const [myPhrase, setMyPhrase] = useState<string | null>(null);
  const [notes, setNotes] = useState<Post[] | null>(null);
  /** Valid grants this user gave or received. */
  const [grants, setGrants] = useState<Post[] | null>(null);
  const [error, setError] = useState("");
  const [busy, setBusy] = useState(false);
  const me: User | null = myId && myPhrase ? { pubkey: myId, phrase: myPhrase } : null;

  const refresh = useCallback(async () => {
    const [n, g] = await Promise.all([getPosts({ user: pubkey }), getPosts({ type: "grant" })]);
    setNotes(n);
    setGrants(g.filter((p) => p.verified && p.grant && (p.owner.pubkey === pubkey || p.grant.grantee.pubkey === pubkey)));
  }, [pubkey]);

  useEffect(() => {
    if (myId) userPhrase(myId).then(setMyPhrase);
  }, [myId]);

  useEffect(() => {
    if (!valid) return;
    setPhrase(null);
    setNotes(null);
    setGrants(null);
    setError("");
    userPhrase(pubkey).then(setPhrase);
    refresh().catch((e) => setError(`Couldn't load posts: ${e.message}`));
  }, [pubkey, valid, refresh]);
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

  return (
    <main className="mx-auto max-w-3xl px-4 py-10 font-sans text-gray-900">
      <Link href="/" className={`text-sm text-gray-500 ${link}`}>
        ← federated crdt
      </Link>
      {!valid ? (
        <p className="mt-6 rounded-md bg-red-50 p-3 text-sm text-red-700 ring-1 ring-red-200">
          <code className="break-all">{pubkey}</code> isn't a valid ID (32 bytes of base58).
        </p>
      ) : (
        <>
          <h1 className="mt-2 text-3xl font-bold tracking-tight break-words">
            {phrase ?? "…"}
            {mine && <span className="ml-2 text-lg font-normal text-gray-500">(you)</span>}
          </h1>

          <section className="mt-6 flex flex-col gap-6 sm:flex-row sm:items-start">
            <QrCode text={url} className="w-48 shrink-0 self-center rounded-lg ring-1 ring-gray-200 sm:self-start" />
            <div className="min-w-0 flex-1 space-y-3">
              <CopyBox label="Public ID (key)" value={pubkey} />
              <CopyBox label="Link to this page" value={url} />
              <p className="text-xs text-gray-500">
                The ID is an Ed25519 public key. Posts below are checked against their authors' keys in your
                browser; the phrase is just a readable nickname derived from it.
              </p>
            </div>
          </section>

          {error && (
            <p className="mt-4 rounded-md bg-red-50 p-3 text-sm text-red-700 ring-1 ring-red-200">{error}</p>
          )}

          {grants && <Grants pubkey={pubkey} grants={grants} me={myId} />}

          <h2 className="mt-10 text-xl font-semibold">Records</h2>
          <p className="mt-1 text-sm text-gray-500">Everything in their space, and everything they wrote in others'.</p>
          {notes === null ? (
            !error && <p className="mt-3 text-gray-500">Loading…</p>
          ) : notes.length === 0 ? (
            <p className="mt-3 text-gray-500">Nothing here yet.</p>
          ) : (
            <PostTree posts={notes} first={pubkey} me={me} busy={busy} run={run} />
          )}
          {mine && (
            <p className="mt-3 text-sm">
              <Link href="/" className={`text-indigo-600 ${link}`}>
                Write a post
              </Link>
            </p>
          )}
          {me && !mine && phrase && <GrantForm grantee={pubkey} phrase={phrase} busy={busy} run={run} />}
        </>
      )}
    </main>
  );
}
