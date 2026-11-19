import { type MouseEvent, useCallback, useEffect, useState } from "react";
import { encode } from "uqr";
import { type Note, type User, getNotes, isPubkey, myPubkey, userPhrase } from "./api.ts";
import { NoteList } from "./NoteList.tsx";
import { Link, idPath } from "./router.tsx";
import { type Run, link } from "./ui.ts";

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

export default function Identity({ pubkey }: { pubkey: string }) {
  const valid = isPubkey(pubkey);
  const url = `${location.origin}${idPath(pubkey)}`;
  const mine = myPubkey() === pubkey;
  const [phrase, setPhrase] = useState<string | null>(null);
  const [notes, setNotes] = useState<Note[] | null>(null);
  const [error, setError] = useState("");
  const [busy, setBusy] = useState(false);
  const me: User | null = mine && phrase ? { pubkey, phrase } : null;

  const refresh = useCallback(async () => {
    setNotes(await getNotes(pubkey));
  }, [pubkey]);

  useEffect(() => {
    if (!valid) return;
    setPhrase(null);
    setNotes(null);
    setError("");
    userPhrase(pubkey).then(setPhrase);
    refresh().catch((e) => setError(`Couldn't load notes: ${e.message}`));
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
                The ID is an Ed25519 public key. Notes below are checked against it in your browser; the
                phrase is just a readable nickname derived from it.
              </p>
            </div>
          </section>

          {error && (
            <p className="mt-4 rounded-md bg-red-50 p-3 text-sm text-red-700 ring-1 ring-red-200">{error}</p>
          )}

          <h2 className="mt-10 text-xl font-semibold">Notes</h2>
          {notes === null ? (
            !error && <p className="mt-3 text-gray-500">Loading…</p>
          ) : notes.length === 0 ? (
            <p className="mt-3 text-gray-500">No notes yet.</p>
          ) : (
            <NoteList notes={notes} me={me} busy={busy} run={run} />
          )}
          {mine && (
            <p className="mt-3 text-sm">
              <Link href="/" className={`text-indigo-600 ${link}`}>
                Write a note
              </Link>
            </p>
          )}
        </>
      )}
    </main>
  );
}
