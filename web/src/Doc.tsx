import { useEffect, useMemo, useRef, useState } from "react";
import * as Y from "yjs";
import { yCollab, yUndoManagerKeymap } from "y-codemirror.next";
import { Compartment, EditorState } from "@codemirror/state";
import { EditorView, drawSelection, keymap, placeholder } from "@codemirror/view";
import { defaultKeymap, indentWithTab } from "@codemirror/commands";
import { defaultHighlightStyle, syntaxHighlighting } from "@codemirror/language";
import { markdown } from "@codemirror/lang-markdown";
import { marked } from "marked";
import DOMPurify from "dompurify";
import {
  type Post,
  type Rec,
  type User,
  addDocEditor,
  amOwner,
  b58,
  docHasOpenClaims,
  getChain,
  getDocUpdates,
  inviteToDoc,
  isHash,
  loadClaims,
  mayEditDoc,
  putDocUpdate,
  removeDocEditor,
  renameDoc,
} from "./api.ts";
import { ClaimLink } from "./Identity.tsx";
import { PartyLink, PathLinks, UserLink } from "./NoteList.tsx";
import { Link, recordPath } from "./router.tsx";
import { type Run, input, link, secondary, useLoad } from "./ui.ts";

// A shared doc: its "doc" record (title, editors) and its text, a Yjs CRDT built from "doc_update"
// records (see the end of api.ts). We poll the node for new updates, apply those by the doc's author
// and editors, and write our own edits as updates: batched, so typing doesn't sign a record per key.

/** The origin we tag updates from the node with, so they aren't sent back. */
const REMOTE = Symbol("remote");
/** Send our edits once typing pauses this long, */
const FLUSH_IDLE_MS = 400;
/** or at the latest this long after the first unsent one. */
const FLUSH_MAX_MS = 2000;
const RETRY_MS = 3000;
const POLL_MS = 1000;
const POLL_HIDDEN_MS = 5000;

type Mode = "write" | "split" | "preview";

/** How our edits stand: all sent, waiting to send, sending, or failing to send (why). */
type SaveState = { unsent: boolean; sending: boolean; error: string };

/** The doc's text and how it syncs with the node: set up for one doc (its hash), torn down on leaving. */
function useDocSync(hash: string, onDocChange: (doc: Post | null, deleted: boolean) => void) {
  const [ytext, setYtext] = useState<Y.Text | null>(null);
  const [ready, setReady] = useState(false);
  const [save, setSave] = useState<SaveState>({ unsent: false, sending: false, error: "" });
  const [syncError, setSyncError] = useState("");
  /** Updates we got but aren't applying: their authors may not edit this doc (as far as we know). */
  const [ignored, setIgnored] = useState(0);
  const docRef = useRef<Post | null>(null);
  const reloadRef = useRef<() => Promise<void>>(async () => {});
  const onDocChangeRef = useRef(onDocChange);
  onDocChangeRef.current = onDocChange;

  useEffect(() => {
    if (!isHash(hash)) return;
    const ydoc = new Y.Doc();
    const text = ydoc.getText("md");
    let stopped = false;
    let seq = 0;
    let head = "";
    let pollTimer: ReturnType<typeof setTimeout> | undefined;
    let flushTimer: ReturnType<typeof setTimeout> | undefined;
    /** Updates from the node not applied yet, because we don't know their authors as editors (yet). */
    let pending: Rec[] = [];
    /** Our edits not sent yet, and when the first of them was made. */
    const outbox: Uint8Array[] = [];
    let firstUnsent = 0;
    let sending = false;
    docRef.current = null;
    setReady(false);
    setIgnored(0);
    setSyncError("");
    setSave({ unsent: false, sending: false, error: "" });

    const loadDoc = async () => {
      const chain = await getChain(hash);
      const current = chain.current?.rec.type === "doc" ? chain.current : null;
      if (stopped) return;
      docRef.current = chain.deleted ? null : current;
      onDocChangeRef.current(current, !!chain.deleted);
    };
    reloadRef.current = loadDoc;

    /** Applies the pending updates whose authors may edit the doc; keeps the rest for if that changes. */
    const apply = () => {
      const doc = docRef.current;
      if (!doc) return;
      pending = pending.filter((u) => {
        if (!u.verified || !u.docUpdate || b58(u.docUpdate.doc) !== hash) return false;
        if (!mayEditDoc(doc, b58(u.author))) return true;
        Y.applyUpdate(ydoc, u.docUpdate.update, REMOTE);
        return false;
      });
      setIgnored(pending.length);
    };

    const poll = async () => {
      try {
        const r = await getDocUpdates(hash, seq);
        if (stopped) return;
        if (!r) {
          // Deleted (or never a doc here): show why, and stop.
          await loadDoc();
          return;
        }
        seq = r.seq;
        pending.push(...r.updates);
        if (r.head !== head) {
          head = r.head;
          await loadDoc();
        }
        // Someone we don't know may have claimed an invite since we loaded who claimed what.
        const doc = docRef.current;
        if (r.updates.length && doc && docHasOpenClaims(doc) && pending.some((u) => !mayEditDoc(doc, b58(u.author)))) {
          await loadClaims();
          await loadDoc();
        }
        apply();
        setReady(true);
        setSyncError("");
      } catch (e) {
        setSyncError((e as Error).message);
      }
      if (!stopped) pollTimer = setTimeout(poll, document.hidden ? POLL_HIDDEN_MS : POLL_MS);
    };

    const schedule = (ms?: number) => {
      clearTimeout(flushTimer);
      flushTimer = setTimeout(flush, ms ?? Math.max(0, Math.min(FLUSH_IDLE_MS, firstUnsent + FLUSH_MAX_MS - Date.now())));
    };

    /** Sends our unsent edits as one update record. */
    const flush = async () => {
      const doc = docRef.current;
      if (sending || !outbox.length || !doc) return;
      sending = true;
      const merged = Y.mergeUpdates(outbox.splice(0));
      firstUnsent = 0;
      setSave((s) => ({ ...s, sending: true }));
      let error = "";
      try {
        await putDocUpdate(doc, merged);
      } catch (e) {
        error = `Couldn't save: ${(e as Error).message}`;
        outbox.unshift(merged);
      }
      sending = false;
      setSave({ unsent: outbox.length > 0, sending: false, error });
      if (outbox.length && !stopped) schedule(error ? RETRY_MS : undefined);
    };

    ydoc.on("update", (u: Uint8Array, origin: unknown) => {
      if (origin === REMOTE) return;
      outbox.push(u);
      if (!firstUnsent) firstUnsent = Date.now();
      setSave((s) => ({ ...s, unsent: true }));
      schedule();
    });

    const beforeUnload = (e: BeforeUnloadEvent) => {
      if (outbox.length || sending) e.preventDefault();
    };
    window.addEventListener("beforeunload", beforeUnload);

    setYtext(text);
    poll();

    return () => {
      stopped = true;
      clearTimeout(pollTimer);
      clearTimeout(flushTimer);
      window.removeEventListener("beforeunload", beforeUnload);
      // Leaving within the app: send what's left, best effort.
      if (outbox.length && docRef.current) putDocUpdate(docRef.current, Y.mergeUpdates(outbox)).catch(() => {});
      ydoc.destroy();
      setYtext(null);
    };
  }, [hash]);

  return { ytext, ready, save, syncError, ignored, reload: () => reloadRef.current() };
}

/** A CodeMirror markdown editor bound to `ytext`; read-only unless `editable`. */
function Editor({ ytext, editable }: { ytext: Y.Text; editable: boolean }) {
  const el = useRef<HTMLDivElement>(null);
  const view = useRef<EditorView | null>(null);
  const editability = useMemo(() => new Compartment(), []);
  const editableExt = (on: boolean) => [EditorView.editable.of(on), EditorState.readOnly.of(!on)];

  useEffect(() => {
    view.current = new EditorView({
      parent: el.current!,
      state: EditorState.create({
        doc: ytext.toString(),
        extensions: [
          keymap.of([...yUndoManagerKeymap, ...defaultKeymap, indentWithTab]),
          drawSelection(),
          syntaxHighlighting(defaultHighlightStyle, { fallback: true }),
          markdown(),
          EditorView.lineWrapping,
          placeholder("Write in markdown…"),
          yCollab(ytext, null),
          editability.of(editableExt(editable)),
          EditorView.theme({
            "&": { fontSize: "14px", height: "100%" },
            "&.cm-focused": { outline: "none" },
            ".cm-scroller": { minHeight: "60vh", fontFamily: "ui-monospace, SFMono-Regular, Menlo, monospace" },
            ".cm-content": { padding: "12px" },
          }),
        ],
      }),
    });
    return () => view.current?.destroy();
  }, [ytext]);

  useEffect(() => {
    view.current?.dispatch({ effects: editability.reconfigure(editableExt(editable)) });
  }, [editable]);

  return <div ref={el} className="h-full min-w-0 rounded-lg bg-white ring-1 ring-gray-200 focus-within:ring-2 focus-within:ring-indigo-600" />;
}

/** `ytext` as rendered markdown, sanitized: it's whatever the doc's editors wrote. */
function Preview({ ytext }: { ytext: Y.Text }) {
  const [text, setText] = useState(() => ytext.toString());
  useEffect(() => {
    const update = () => setText(ytext.toString());
    update();
    ytext.observe(update);
    return () => ytext.unobserve(update);
  }, [ytext]);
  const html = useMemo(() => DOMPurify.sanitize(marked.parse(text, { async: false })), [text]);
  return text.trim() ? (
    <div className="markdown min-w-0 rounded-lg p-4 ring-1 ring-gray-200" dangerouslySetInnerHTML={{ __html: html }} />
  ) : (
    <p className="rounded-lg p-4 text-sm text-gray-500 italic ring-1 ring-gray-200">Nothing written yet.</p>
  );
}

function Status({ save, syncError, ignored, editable }: { save: SaveState; syncError: string; ignored: number; editable: boolean }) {
  const parts: React.ReactNode[] = [];
  if (save.error) parts.push(<span className="text-red-700">{save.error} (retrying)</span>);
  else if (save.sending) parts.push("Saving…");
  else if (save.unsent) parts.push("Unsaved changes");
  else if (editable) parts.push("All changes saved");
  if (syncError) parts.push(<span className="text-red-700">Couldn't sync: {syncError}</span>);
  if (ignored) parts.push(<span title="Signed by people this doc doesn't name as editors">{ignored} update{ignored > 1 && "s"} by non-editors ignored</span>);
  return (
    <p className="text-xs text-gray-500">
      {parts.map((p, i) => (
        <span key={i}>
          {i > 0 && " · "}
          {p}
        </span>
      ))}
    </p>
  );
}

/** Who may edit `doc`, and (for its author and the node's owners) adding and removing editors. */
function Editors({ doc, me, manage, busy, run }: { doc: Post; me: User | null; manage: boolean; busy: boolean; run: Run }) {
  const [id, setId] = useState("");
  const [invite, setInvite] = useState<string | null>(null);
  const editors = doc.doc!.editors;
  return (
    <section className="space-y-2 rounded-lg p-3 text-sm ring-1 ring-gray-200">
      <h2 className="font-semibold">Editors</h2>
      <ul className="space-y-1">
        <li>
          {doc.by ? <UserLink user={doc.by} me={me} className="font-semibold" /> : <span className="italic">unknown</span>}{" "}
          <span className="text-gray-500">(started it)</span>
        </li>
        {editors.map((e, i) => (
          <li key={e.claim ?? e.user?.pubkey ?? i} className="flex items-baseline gap-2">
            <span>
              <PartyLink party={e} me={me} />
            </span>
            {manage && (
              <button
                className="cursor-pointer text-gray-400 hover:text-red-600"
                disabled={busy}
                onClick={run(() => removeDocEditor(doc, i))}
                title="Stop them editing it (what they wrote stays)"
                aria-label="Remove editor"
              >
                ×
              </button>
            )}
          </li>
        ))}
      </ul>
      {manage && (
        <>
          <form
            className="flex gap-2"
            onSubmit={(e) => {
              e.preventDefault();
              run(async () => {
                await addDocEditor(doc, id);
                setId("");
              })();
            }}
          >
            <input className={`${input} font-mono`} placeholder="Their ID" value={id} onChange={(e) => setId(e.target.value)} />
            <button className={secondary} disabled={busy || !id.trim()}>
              Add
            </button>
          </form>
          <button className={secondary} disabled={busy} onClick={run(async () => setInvite(await inviteToDoc(doc)))}>
            Make an invite link
          </button>
          {invite && <ClaimLink link={invite} />}
        </>
      )}
    </section>
  );
}

/** A doc's title: editable in place by whoever may change the doc record. */
function Title({ doc, manage, busy, run }: { doc: Post; manage: boolean; busy: boolean; run: Run }) {
  const title = doc.doc!.title;
  const [draft, setDraft] = useState(title);
  useEffect(() => setDraft(title), [title]);
  if (!manage) return <h1 className="text-2xl font-bold tracking-tight">{title || <span className="text-gray-400">Untitled</span>}</h1>;
  const commit = () => {
    if (draft.trim() !== title) run(() => renameDoc(doc, draft))();
  };
  return (
    <input
      className="w-full rounded-md px-1 text-2xl font-bold tracking-tight ring-gray-300 outline-none hover:ring-1 focus:ring-2 focus:ring-indigo-600"
      value={draft}
      placeholder="Untitled"
      disabled={busy}
      onChange={(e) => setDraft(e.target.value)}
      onBlur={commit}
      onKeyDown={(e) => e.key === "Enter" && (e.target as HTMLInputElement).blur()}
    />
  );
}

/** /d/<hash>: a shared doc, by its chain's hash. */
export function DocPage({ hash, me, busy, run, tick }: { hash: string; me: User | null; busy: boolean; run: Run; tick: number }) {
  const valid = isHash(hash);
  const [doc, setDoc] = useState<{ post: Post | null; deleted: boolean } | null>(null);
  const [mode, setMode] = useState<Mode>("split");
  useEffect(() => setDoc(null), [hash]);
  const { ytext, ready, save, syncError, ignored, reload } = useDocSync(hash, (post, deleted) => setDoc({ post, deleted }));
  // After our own actions (renaming, editors), see the new version now rather than on the next poll.
  const { error } = useLoad(valid && tick ? reload : null, [hash], tick);

  if (!valid) return <p className="text-red-700"><code className="break-all">{hash}</code> isn't a doc hash (32 bytes of base58).</p>;
  if (!doc) return <p className="text-gray-500">{syncError ? `Couldn't load this doc: ${syncError}` : "Loading…"}</p>;
  if (doc.deleted || !doc.post) {
    return (
      <p className="rounded-md bg-gray-50 p-3 text-sm text-gray-600 ring-1 ring-gray-200">
        {doc.deleted ? "This doc was deleted." : "That isn't a doc."}{" "}
        <Link href={recordPath(hash)} className={link}>
          See its record
        </Link>
        .
      </p>
    );
  }
  const post = doc.post;
  const editable = !!me && mayEditDoc(post, me.pubkey);
  const manage = !!me && (post.by?.pubkey === me.pubkey || amOwner());
  const tab = (m: Mode, label: string) => (
    <button
      className={`cursor-pointer px-2.5 py-1 ${mode === m ? "bg-gray-900 text-white" : "bg-white hover:bg-gray-50"}`}
      onClick={() => setMode(m)}
      aria-pressed={mode === m}
    >
      {label}
    </button>
  );

  return (
    <div className="space-y-4">
      <div className="space-y-1">
        <Title doc={post} manage={manage} busy={busy} run={run} />
        <p className="flex flex-wrap items-baseline gap-x-2 text-sm text-gray-500">
          <PathLinks path={post.rec.path} />
          <Link href={recordPath(post.root)} className={`font-mono ${link}`} title="The doc record and its versions">
            #{post.root.slice(0, 8)}
          </Link>
          {!editable && <span>{me ? "· You can read it, but not edit it." : "· Sign in to edit, if you're an editor."}</span>}
        </p>
      </div>
      {error && <p className="text-sm text-red-700">{error}</p>}

      <div className="flex items-center justify-between gap-2">
        <Status save={save} syncError={syncError} ignored={ignored} editable={editable} />
        <div className="flex overflow-hidden rounded-md text-xs font-medium ring-1 ring-gray-300">
          {tab("write", "Write")}
          {tab("split", "Split")}
          {tab("preview", "Preview")}
        </div>
      </div>

      {!ytext || !ready ? (
        <p className="text-gray-500">Loading its text…</p>
      ) : (
        <div className={`grid gap-4 ${mode === "split" ? "md:grid-cols-2" : ""}`}>
          {mode !== "preview" && <Editor ytext={ytext} editable={editable} />}
          {mode !== "write" && <Preview ytext={ytext} />}
        </div>
      )}

      <Editors doc={post} me={me} manage={manage} busy={busy} run={run} />
    </div>
  );
}
