import { useEffect, useMemo, useRef, useState } from "react";
import * as Y from "yjs";
import { Awareness, applyAwarenessUpdate, encodeAwarenessUpdate, removeAwarenessStates } from "y-protocols/awareness";
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
  inviteToDoc,
  isHash,
  joinLive,
  loadClaims,
  mayEditDoc,
  putDocUpdate,
  removeDocEditor,
  renameDoc,
  streamRecords,
  streamedRecord,
  userPhrase,
} from "./api.ts";
import { ClaimLink } from "./Identity.tsx";
import { ListView } from "./List.tsx";
import { PartyLink, PathLinks, UserLink } from "./NoteList.tsx";
import { Link, recordPath } from "./router.tsx";
import { kvDel, kvGet, kvSet } from "./store.ts";
import { type Run, input, link, secondary, useLoad } from "./ui.ts";

// A shared doc: its "doc" record (title, editors, kind) and its content, a Yjs CRDT built from
// "doc_update" records (see the end of api.ts): markdown text, or a list (see List.tsx). We stream the doc's records from the node, apply the updates by its
// author and editors, and write our own edits as updates: batched, so typing doesn't sign a record per
// key. Editors also join the doc's live room, to see each other's cursors (Yjs awareness), which
// nothing stores.

/** The origins we tag updates from the node, and from what this device kept, with: they aren't ours to send. */
const REMOTE = Symbol("remote");
const CACHED = Symbol("cached");
/** Keep the doc's content on this device once it's been still this long. */
const SAVE_STATE_MS = 500;
/** Send our edits once typing pauses this long, */
const FLUSH_IDLE_MS = 250;
/** or at the latest this long after the first unsent one. */
const FLUSH_MAX_MS = 1500;
const RETRY_MS = 3000;
const RECONNECT_MS = 2000;

/** Live room frames from the node (see `live` in src/main.rs): kind, connection (u32), sender's ID, payload. */
const LIVE_UPDATE = 0;
const LIVE_JOINED = 1;
const LIVE_LEFT = 2;

type Mode = "write" | "split" | "preview";

/** How our edits stand: all sent, waiting to send, sending, or failing to send (why). */
type SaveState = { unsent: boolean; sending: boolean; error: string };

/** How someone shows in the live room: their phrase, and a color from their ID. */
type Presence = { pubkey: string; name: string; color: string; colorLight: string };

function presence(pubkey: string): Presence {
  let h = 0;
  for (const c of pubkey) h = (h * 31 + c.charCodeAt(0)) >>> 0;
  const hue = h % 360;
  return { pubkey, name: userPhrase(pubkey), color: `hsl(${hue} 70% 42%)`, colorLight: `hsl(${hue} 70% 42% / 0.18)` };
}

/** The doc's awareness (cursors), and what the live room has proved about it: who's behind each
 * connection, and which connection each remote awareness client came from. */
type Live = { awareness: Awareness; users: Map<number, string>; clients: Map<number, number> };

/** A doc's content and how it syncs with the node: set up for one doc (its hash) and one of us (`me`, or
 * null signed out), torn down on leaving.
 *
 * This device keeps (see store.ts) the doc's last known content, shown before the node answers or when it
 * can't, and the edits we haven't sent, sent when it can: whether the node's unreachable, or we leave first. */
function useDocSync(hash: string, me: string | null, onDocChange: (doc: Post | null, deleted: boolean) => void) {
  const [sync, setSync] = useState<{ ydoc: Y.Doc; live: Live } | null>(null);
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
    const live: Live = { awareness: new Awareness(ydoc), users: new Map(), clients: new Map() };
    // Name remote cursors by who the live room says sent them, not by what they say. Registered
    // before the editor's own listener, so it sees the names already fixed.
    live.awareness.on("change", ({ added, updated }: { added: number[]; updated: number[] }, origin: unknown) => {
      const user = typeof origin === "number" ? live.users.get(origin) : undefined;
      if (!user) return;
      for (const id of [...added, ...updated]) {
        live.clients.set(id, origin as number);
        const state = live.awareness.states.get(id);
        if (state) state.user = presence(user);
      }
    });
    const stateKey = `doc:${hash}`;
    /** Unsent edits are ours alone: they're sent signed by us. */
    const outboxKey = me && `outbox:${hash}:${me}`;
    let stopped = false;
    let flushTimer: ReturnType<typeof setTimeout> | undefined;
    let stateTimer: ReturnType<typeof setTimeout> | undefined;
    /** Updates from the node not applied yet, because we don't know their authors as editors (yet). */
    let pending: Rec[] = [];
    /** Whether the doc record may have changed since we last loaded it; whether new updates came. */
    let docDirty = true;
    let fresh = false;
    let caughtUp = false;
    /** Our edits not sent yet, and when the first of them was made; and the ones being sent. */
    const outbox: Uint8Array[] = [];
    let firstUnsent = 0;
    let inflight: Uint8Array | null = null;
    docRef.current = null;
    setReady(false);
    setIgnored(0);
    setSyncError("");
    setSave({ unsent: false, sending: false, error: "" });

    /** Keeps what we haven't sent (for sure) on this device. */
    const keepOutbox = () => {
      if (!outboxKey) return;
      const all = inflight ? [inflight, ...outbox] : outbox;
      if (all.length) kvSet(outboxKey, Y.mergeUpdates(all));
      else kvDel(outboxKey);
    };
    const keepState = () => kvSet(stateKey, Y.encodeStateAsUpdate(ydoc));

    /** Loads what this device kept. Whether it had the doc's content. */
    const restore = async () => {
      const [state, unsent] = await Promise.all([kvGet<Uint8Array>(stateKey), outboxKey ? kvGet<Uint8Array>(outboxKey) : undefined]);
      if (stopped) return false;
      if (state) Y.applyUpdate(ydoc, state, CACHED);
      if (unsent) {
        Y.applyUpdate(ydoc, unsent, CACHED);
        outbox.push(unsent);
        firstUnsent ||= Date.now();
        setSave((s) => ({ ...s, unsent: true }));
        schedule();
      }
      return !!state;
    };

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

    /** Catches up with what the stream brought: the doc record if it changed, then the updates. One at a time. */
    let queue = Promise.resolve();
    const process = () =>
      (queue = queue.then(async () => {
        try {
          if (docDirty) {
            docDirty = false;
            await loadDoc();
          }
          // Someone we don't know may have claimed an invite since we loaded who claimed what.
          const doc = docRef.current;
          if (fresh && doc && docHasOpenClaims(doc) && pending.some((u) => !mayEditDoc(doc, b58(u.author)))) {
            await loadClaims();
            await loadDoc();
          }
          fresh = false;
          apply();
          if (outbox.length) schedule();
        } catch (e) {
          docDirty = true;
          setSyncError((e as Error).message);
        }
      }));

    // What this device kept is enough to show, until the stream catches up (or if it can't).
    Promise.all([restore(), process()]).then(([had]) => had && !stopped && docRef.current && setReady(true));

    const es = streamRecords({ doc: hash });
    es.addEventListener("record", (e) => {
      const rec = streamedRecord((e as MessageEvent<string>).data);
      if (rec.type === "doc_update") {
        pending.push(rec);
        fresh = true;
      } else docDirty = true; // a new version of the doc, or its deletion
      if (caughtUp) process();
    });
    es.addEventListener("ready", () => {
      caughtUp = true;
      process().then(() => !stopped && setReady(true));
    });
    es.onopen = () => setSyncError("");
    es.onerror = () => setSyncError("can't reach the node; reconnecting…");

    const schedule = (ms?: number) => {
      clearTimeout(flushTimer);
      flushTimer = setTimeout(flush, ms ?? Math.max(0, Math.min(FLUSH_IDLE_MS, firstUnsent + FLUSH_MAX_MS - Date.now())));
    };

    /** Sends our unsent edits as one update record. */
    const flush = async () => {
      const doc = docRef.current;
      if (inflight || !outbox.length || !doc) return;
      inflight = Y.mergeUpdates(outbox.splice(0));
      firstUnsent = 0;
      setSave((s) => ({ ...s, sending: true }));
      let error = "";
      try {
        await putDocUpdate(doc, inflight);
      } catch (e) {
        error = (e as Error).message;
        outbox.unshift(inflight);
      }
      inflight = null;
      keepOutbox();
      setSave({ unsent: outbox.length > 0, sending: false, error });
      if (outbox.length && !stopped) schedule(error ? RETRY_MS : undefined);
    };

    ydoc.on("update", (u: Uint8Array, origin: unknown) => {
      if (origin === CACHED) return;
      clearTimeout(stateTimer);
      stateTimer = setTimeout(keepState, SAVE_STATE_MS);
      if (origin === REMOTE) return;
      outbox.push(u);
      keepOutbox();
      if (!firstUnsent) firstUnsent = Date.now();
      setSave((s) => ({ ...s, unsent: true }));
      schedule();
    });

    setSync({ ydoc, live });

    return () => {
      stopped = true;
      es.close();
      clearTimeout(flushTimer);
      if (stateTimer) {
        clearTimeout(stateTimer);
        keepState();
      }
      // Leaving within the app: send what's left now, rather than next time. It's kept here until it's gone.
      const left = outbox.splice(0);
      if (left.length && docRef.current) {
        const merged = Y.mergeUpdates(left);
        putDocUpdate(docRef.current, merged).then(keepOutbox, () => {
          outbox.unshift(merged);
          keepOutbox();
        });
      }
      live.awareness.destroy();
      ydoc.destroy();
      setSync(null);
    };
  }, [hash, me]);

  return { sync, ready, save, syncError, ignored, reload: () => reloadRef.current() };
}

/** While `me` may edit the doc: its live room, passing our awareness (cursor) to the other editors there,
 * and theirs to us. Reconnects if the connection drops. */
function useLiveRoom(hash: string, live: Live | null, me: User | null, editable: boolean) {
  useEffect(() => {
    if (!live || !me || !editable) return;
    const { awareness, users, clients } = live;
    awareness.setLocalStateField("user", presence(me.pubkey));
    let stopped = false;
    let ws: WebSocket | null = null;
    let retry: ReturnType<typeof setTimeout> | undefined;

    const sendMine = () => {
      if (ws?.readyState === WebSocket.OPEN) ws.send(encodeAwarenessUpdate(awareness, [awareness.clientID]) as Uint8Array<ArrayBuffer>);
    };
    const onLocal = ({ added, updated, removed }: Record<string, number[]>, origin: unknown) => {
      if (origin === "local" && [...added, ...updated, ...removed].includes(awareness.clientID)) sendMine();
    };
    awareness.on("update", onLocal);

    /** Forgets the cursors that came through connection `conn` (all of them, if undefined). */
    const forget = (conn?: number) => {
      const ids = [...clients].filter(([, c]) => conn === undefined || c === conn).map(([id]) => id);
      ids.forEach((id) => clients.delete(id));
      removeAwarenessStates(awareness, ids, "left");
    };

    const connect = async () => {
      try {
        const live = await joinLive(hash);
        if (stopped) return live.ws.close();
        ws = live.ws;
        ws.onopen = () => {
          ws!.send(live.hello);
          sendMine();
        };
        ws.onmessage = (e) => {
          const b = new Uint8Array(e.data as ArrayBuffer);
          if (b.length < 37) return;
          const conn = new DataView(b.buffer).getUint32(1);
          users.set(conn, b58(b.subarray(5, 37)));
          if (b[0] === LIVE_UPDATE) applyAwarenessUpdate(awareness, b.subarray(37), conn);
          else if (b[0] === LIVE_JOINED) sendMine();
          else if (b[0] === LIVE_LEFT) {
            forget(conn);
            users.delete(conn);
          }
        };
        ws.onclose = (e) => {
          forget();
          if (e.code === 4003) console.warn(`Not joining this doc's live room: ${e.reason}`);
          else if (!stopped) retry = setTimeout(connect, RECONNECT_MS);
        };
      } catch (e) {
        console.warn("Couldn't join this doc's live room:", e);
      }
    };
    connect();

    return () => {
      stopped = true;
      clearTimeout(retry);
      awareness.off("update", onLocal);
      ws?.close();
      forget();
      awareness.setLocalState(null);
    };
  }, [hash, live, me?.pubkey, editable]);
}

/** Who else is in the live room right now. */
function useHere(live: Live | null) {
  const [here, setHere] = useState<Presence[]>([]);
  useEffect(() => {
    if (!live) return;
    const update = () => {
      const seen = new Map<string, Presence>();
      for (const [id, s] of live.awareness.getStates()) {
        const p = s.user as Presence | undefined;
        if (id !== live.awareness.clientID && live.clients.has(id) && p) seen.set(p.pubkey, p);
      }
      setHere([...seen.values()]);
    };
    update();
    live.awareness.on("change", update);
    return () => live.awareness.off("change", update);
  }, [live]);
  return here;
}

/** A CodeMirror markdown editor bound to `ytext`, showing the cursors in `awareness`; read-only unless `editable`. */
function Editor({ ytext, awareness, editable }: { ytext: Y.Text; awareness: Awareness; editable: boolean }) {
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
          yCollab(ytext, awareness),
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
  }, [ytext, awareness]);

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

function Status(props: { save: SaveState; syncError: string; ignored: number; editable: boolean; here: Presence[] }) {
  const { save, syncError, ignored, editable, here } = props;
  const parts: React.ReactNode[] = [];
  if (here.length) {
    parts.push(
      <span>
        Here now:{" "}
        {here.map((p, i) => (
          <span key={p.pubkey} style={{ color: p.color }} className="font-medium">
            {i > 0 && ", "}● {p.name}
          </span>
        ))}
      </span>,
    );
  }
  if (save.error) {
    parts.push(
      <span className="text-amber-700" title={save.error}>
        Not sent yet: kept on this device, and sent once the node takes it
      </span>,
    );
  } else if (save.sending) parts.push("Saving…");
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
  const { sync, ready, save, syncError, ignored, reload } = useDocSync(hash, me?.pubkey ?? null, (post, deleted) => setDoc({ post, deleted }));
  const post = doc?.post && !doc.deleted ? doc.post : null;
  const editable = !!me && !!post && mayEditDoc(post, me.pubkey);
  useLiveRoom(hash, sync?.live ?? null, me, editable);
  const here = useHere(sync?.live ?? null);
  // After our own actions (renaming, editors), see the new version now rather than on the next poll.
  const { error } = useLoad(valid && tick ? reload : null, [hash], tick);

  if (!valid) return <p className="text-red-700"><code className="break-all">{hash}</code> isn't a doc hash (32 bytes of base58).</p>;
  if (!doc) return <p className="text-gray-500">{syncError ? `Couldn't load this doc: ${syncError}` : "Loading…"}</p>;
  if (!post) {
    return (
      <p className="rounded-md bg-gray-50 p-3 text-sm text-gray-600 ring-1 ring-gray-200">
        {doc.deleted ? "This was deleted." : "That isn't a doc or a list."}{" "}
        <Link href={recordPath(hash)} className={link}>
          See its record
        </Link>
        .
      </p>
    );
  }
  const manage = !!me && (post.by?.pubkey === me.pubkey || amOwner());
  const list = post.doc!.kind === "list";
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
        <Status save={save} syncError={syncError} ignored={ignored} editable={editable} here={here} />
        {!list && (
          <div className="flex overflow-hidden rounded-md text-xs font-medium ring-1 ring-gray-300">
            {tab("write", "Write")}
            {tab("split", "Split")}
            {tab("preview", "Preview")}
          </div>
        )}
      </div>

      {!sync || !ready ? (
        <p className="text-gray-500">Loading…</p>
      ) : list ? (
        <ListView ydoc={sync.ydoc} editable={editable} />
      ) : (
        <div className={`grid gap-4 ${mode === "split" ? "md:grid-cols-2" : ""}`}>
          {mode !== "preview" && <Editor ytext={sync.ydoc.getText("md")} awareness={sync.live.awareness} editable={editable} />}
          {mode !== "write" && <Preview ytext={sync.ydoc.getText("md")} />}
        </div>
      )}

      <Editors doc={post} me={me} manage={manage} busy={busy} run={run} />
    </div>
  );
}
