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
  type User,
  SCHEMAS,
  addDocEditor,
  amOwner,
  b58,
  inviteToDoc,
  isHash,
  joinDocLive,
  mayEditDoc,
  myEncKeys,
  mySigner,
  node,
  removeDocEditor,
  renameDoc,
  sealForEditors,
  userPhrase,
  viewPost,
} from "./api.ts";
import { type DocStatus, type DocSync, type Store, decodeId, openDoc, unb58 } from "../../client/src/index.ts";
import { yjs } from "../../client/src/yjs.ts";
import { ClaimLink } from "./Identity.tsx";
import { ListView } from "./List.tsx";
import { PartyLink, PathLinks, UserLink } from "./NoteList.tsx";
import { Link, recordPath } from "./router.tsx";
import { kvDel, kvGet, kvSet } from "./store.ts";
import { type Run, input, link, secondary } from "./ui.ts";

// A shared doc: its "doc" record (title, editors, schema) and its content, a Yjs CRDT kept in sync with
// the node by `openDoc` (client/src/docs.ts), which also keeps it on this device, sends our edits, and
// decrypts and encrypts it if it's encrypted. What we show depends on its schema: markdown text, or a list
// (see List.tsx). Editors also join the doc's live room, to see each other's cursors (Yjs awareness),
// which nothing stores.

const RECONNECT_MS = 2000;

/** Live room frames from the node (see `live` in src/main.rs): kind, connection (u32), sender's ID, payload. */
const LIVE_UPDATE = 0;
const LIVE_JOINED = 1;
const LIVE_LEFT = 2;

type Mode = "write" | "split" | "preview";

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

/** This device's IndexedDB (store.ts), as `openDoc` keeps things in it. */
const store: Store = { get: kvGet, set: kvSet, del: kvDel };

/** A doc's content and how it syncs with the node: set up for one doc (its hash) and one of us (`me`, or
 * null signed out), torn down on leaving. */
function useDocSync(hash: string, me: string | null) {
  const [sync, setSync] = useState<{ doc: DocSync<Y.Doc>; live: Live } | null>(null);
  const [status, setStatus] = useState<DocStatus | null>(null);

  useEffect(() => {
    if (!isHash(hash)) return;
    const doc = openDoc({ node, hash, adapter: yjs, signer: mySigner(), encryption: myEncKeys(), store, onStatus: setStatus });
    const live: Live = { awareness: new Awareness(doc.content), users: new Map(), clients: new Map() };
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
    setSync({ doc, live });
    return () => {
      live.awareness.destroy();
      doc.close();
      setSync(null);
      setStatus(null);
    };
  }, [hash, me]);

  return { sync, status };
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
        const live = await joinDocLive(hash);
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

function Status({ status, here }: { status: DocStatus; here: Presence[] }) {
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
  if (status.saveError) {
    parts.push(
      <span className="text-amber-700" title={status.saveError}>
        Not sent yet: kept on this device, and sent once the node takes it
      </span>,
    );
  } else if (status.sending) parts.push("Saving…");
  else if (status.unsent) parts.push("Unsaved changes");
  else if (status.editable) parts.push("All changes saved");
  if (status.syncError) parts.push(<span className="text-red-700">Couldn't sync: {status.syncError}</span>);
  if (status.ignored) {
    parts.push(
      <span title="Signed by people this doc doesn't name as editors, or that couldn't be decrypted">
        {status.ignored} update{status.ignored > 1 && "s"} ignored
      </span>,
    );
  }
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
function Editors(props: { doc: Post; docKey: Uint8Array | null; me: User | null; manage: boolean; busy: boolean; run: Run }) {
  const { doc, docKey, me, manage, busy, run } = props;
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
                await addDocEditor(doc, id, docKey);
                setId("");
              })();
            }}
          >
            <input className={`${input} font-mono`} placeholder="Their ID" value={id} onChange={(e) => setId(e.target.value)} />
            <button className={secondary} disabled={busy || !id.trim()}>
              Add
            </button>
          </form>
          <button className={secondary} disabled={busy} onClick={run(async () => setInvite(await inviteToDoc(doc, docKey)))}>
            Make an invite link
          </button>
          {invite && <ClaimLink link={invite} />}
          {invite && doc.doc!.encrypted && (
            <p className="text-xs text-amber-800">This link carries the doc's key: whoever has it can read the doc.</p>
          )}
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
  const [mode, setMode] = useState<Mode>("split");
  const { sync, status } = useDocSync(hash, me?.pubkey ?? null);
  const info = status?.doc;
  const post = useMemo(
    () => info && viewPost(info.rec, { root: unb58(info.root)!, by: info.by ? decodeId(info.by) : undefined, versions: 1 }),
    [info],
  );
  const editable = !!status?.editable && !!me && !!post && mayEditDoc(post, me.pubkey);
  useLiveRoom(hash, sync?.live ?? null, me, editable);
  const here = useHere(sync?.live ?? null);
  // After our own actions (renaming, editors), see the new version now rather than when the stream says.
  useEffect(() => {
    if (tick) sync?.doc.reload();
  }, [tick]);
  const manage = !!me && !!post && (post.by?.pubkey === me.pubkey || amOwner());
  const docKey = sync?.doc.docKey() ?? null;
  // An encrypted doc's key goes to editors who don't have it yet, once they've published an encryption key.
  useEffect(() => {
    if (manage && post?.doc?.encrypted && docKey) {
      sealForEditors(post, docKey).then(
        (changed) => {
          if (changed) sync?.doc.reload();
        },
        (e) => console.warn("Couldn't share this doc's key with its editors:", e),
      );
    }
  }, [post?.hash, manage, !!docKey]);

  if (!valid) return <p className="text-red-700"><code className="break-all">{hash}</code> isn't a doc hash (32 bytes of base58).</p>;
  if (!status || (!status.doc && !status.deleted && !status.ready)) {
    return <p className="text-gray-500">{status?.syncError ? `Couldn't load this doc: ${status.syncError}` : "Loading…"}</p>;
  }
  if (!post) {
    return (
      <p className="rounded-md bg-gray-50 p-3 text-sm text-gray-600 ring-1 ring-gray-200">
        {status.deleted ? "This was deleted." : "That isn't a doc or a list."}{" "}
        <Link href={recordPath(hash)} className={link}>
          See its record
        </Link>
        .
      </p>
    );
  }
  const { schema, format } = post.doc!;
  const known = format === "yjs" && (schema === SCHEMAS.markdown || schema === SCHEMAS.list);
  const list = schema === SCHEMAS.list;
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
          {post.doc!.encrypted && <span title="Only its editors can read it. Its title isn't encrypted.">· 🔒 encrypted</span>}
          {!editable && !status.locked && <span>{me ? "· You can read it, but not edit it." : "· Sign in to edit, if you're an editor."}</span>}
        </p>
      </div>

      {status.locked ? (
        <p className="rounded-md bg-gray-50 p-3 text-sm text-gray-600 ring-1 ring-gray-200">
          🔒 This doc is encrypted, and its key hasn't been shared with {me ? "you" : "you (sign in, if you're an editor)"}.
        </p>
      ) : !known ? (
        <p className="rounded-md bg-gray-50 p-3 text-sm text-gray-600 ring-1 ring-gray-200">
          This doc holds <code className="font-mono">{schema}</code> ({format}), from an app this page doesn't know.
        </p>
      ) : (
        <>
          <div className="flex items-center justify-between gap-2">
            <Status status={{ ...status, editable }} here={here} />
            {!list && (
              <div className="flex overflow-hidden rounded-md text-xs font-medium ring-1 ring-gray-300">
                {tab("write", "Write")}
                {tab("split", "Split")}
                {tab("preview", "Preview")}
              </div>
            )}
          </div>
          {!sync || !status.ready ? (
            <p className="text-gray-500">Loading…</p>
          ) : list ? (
            <ListView ydoc={sync.doc.content} editable={editable} />
          ) : (
            <div className={`grid gap-4 ${mode === "split" ? "md:grid-cols-2" : ""}`}>
              {mode !== "preview" && <Editor ytext={sync.doc.content.getText("md")} awareness={sync.live.awareness} editable={editable} />}
              {mode !== "write" && <Preview ytext={sync.doc.content.getText("md")} />}
            </div>
          )}
        </>
      )}

      <Editors doc={post} docKey={docKey} me={me} manage={manage} busy={busy} run={run} />
    </div>
  );
}
