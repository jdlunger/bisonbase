import { useEffect, useState } from "react";
import { type Note, type User, decryptNote, deleteNote, putNote, verifyNote } from "./api.ts";
import { Link, idPath } from "./router.tsx";
import { type Run, badge, danger, fmtTime, link, primary, secondary, textarea } from "./ui.ts";

export type Draft = { body: string; encrypt: boolean };

/** Note text plus an "Encrypt" checkbox. Notes are always signed. */
export function NoteEditor(props: {
  draft: Draft;
  setDraft: (d: Draft) => void;
  busy: boolean;
  submitLabel: string;
  onSubmit: () => void;
  onCancel?: () => void;
}) {
  const { draft, setDraft, busy } = props;
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
      <label className="flex items-center gap-1.5 text-sm" title="Only your passkey can decrypt it">
        <input type="checkbox" checked={draft.encrypt} onChange={(e) => setDraft({ ...draft, encrypt: e.target.checked })} />
        Encrypt (only you can read it)
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

/** Notes, with signatures checked and (our own) encrypted ones decrypted, entirely client-side. */
export function NoteList({ notes, me, busy, run }: { notes: Note[]; me: User | null; busy: boolean; run: Run }) {
  const [editing, setEditing] = useState<(Draft & { note: Note }) | null>(null);
  /** Per note ID: decrypted text, and whether its signature checks out. */
  const [plain, setPlain] = useState<Record<string, string>>({});
  const [verified, setVerified] = useState<Record<string, boolean>>({});

  useEffect(() => {
    let cancelled = false;
    (async () => {
      const v: Record<string, boolean> = {};
      const p: Record<string, string> = {};
      for (const n of notes) {
        v[n.id] = await verifyNote(n);
        if (n.encrypted && n.author.pubkey === me?.pubkey) {
          p[n.id] = await decryptNote(n).catch(() => "(couldn't decrypt)");
        }
      }
      if (!cancelled) {
        setVerified(v);
        setPlain(p);
      }
    })();
    return () => {
      cancelled = true;
    };
  }, [notes, me]);

  return (
    <ul className="mt-4 divide-y divide-gray-200 rounded-lg ring-1 ring-gray-200">
      {notes.map((n) => {
        const mine = me?.pubkey === n.author.pubkey;
        const isEditing = editing?.note.id === n.id;
        const text = n.encrypted ? plain[n.id] : n.body;
        const v = verified[n.id];
        return (
          <li key={n.id} className="p-3">
            <div className="flex flex-wrap items-baseline justify-between gap-2 text-sm">
              <span className="flex flex-wrap items-baseline gap-2">
                <Link href={idPath(n.author.pubkey)} className={`font-semibold ${link}`} title={n.author.pubkey}>
                  {n.author.phrase}
                  {mine && <span className="ml-1 font-normal text-gray-500">(you)</span>}
                </Link>
                {v === true ? (
                  <span
                    className={`${badge} bg-green-50 text-green-700 ring-green-200`}
                    title="Signature verified in your browser against the author's public key"
                  >
                    ✓ signed
                  </span>
                ) : v === false ? (
                  <span className={`${badge} bg-red-50 text-red-700 ring-red-200`}>✗ bad signature</span>
                ) : (
                  <span className={`${badge} bg-gray-50 text-gray-600 ring-gray-200`}>checking…</span>
                )}
                {n.encrypted && (
                  <span className={`${badge} bg-amber-50 text-amber-800 ring-amber-200`}>🔒 encrypted</span>
                )}
              </span>
              <span className="text-xs text-gray-500">
                {fmtTime(n.created_at)}
                {n.updated_at !== n.created_at && ` · edited ${fmtTime(n.updated_at)}`}
              </span>
            </div>
            {isEditing ? (
              <div className="mt-2">
                <NoteEditor
                  draft={editing}
                  setDraft={(d) => setEditing({ ...d, note: n })}
                  busy={busy}
                  submitLabel="Save"
                  onSubmit={run(async () => {
                    await putNote(editing.body, editing, n);
                    setEditing(null);
                  })}
                  onCancel={() => setEditing(null)}
                />
              </div>
            ) : (
              <>
                {text !== undefined ? (
                  <p className="mt-1 whitespace-pre-wrap break-words">{text}</p>
                ) : (
                  <p className="mt-1 text-sm text-gray-500 italic">
                    {mine ? "Decrypting…" : "Encrypted. Only the author can read this."}
                  </p>
                )}
                {mine && (
                  <div className="mt-2 flex gap-2">
                    <button
                      className={secondary}
                      disabled={busy || text === undefined}
                      onClick={() => setEditing({ note: n, body: text!, encrypt: n.encrypted })}
                    >
                      Edit
                    </button>
                    <button className={danger} disabled={busy} onClick={run(() => deleteNote(n))}>
                      Delete
                    </button>
                  </div>
                )}
              </>
            )}
          </li>
        );
      })}
    </ul>
  );
}
