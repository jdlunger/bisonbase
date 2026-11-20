import { useEffect, useMemo, useRef, useState } from "react";
import * as Y from "yjs";
import { secondary } from "./ui.ts";

// A shared list (a doc of kind "list"), e.g. for shopping. Its Yjs doc holds a map "items": id → Y.Map
// {text, done, pos}. Items are a map, not an array, so moving one is changing its `pos`: Yjs arrays can
// only move by deleting and inserting, which duplicates an item two people move at once. Each field is
// last-writer-wins, which is what you'd expect of a checkbox or a short line of text.

type Item = { id: string; text: string; done: boolean; pos: string };

// ---- ordering: fractional indexes ----
//
// `pos` is a string of base-36 digits, compared as strings. There's always room between two (never
// ending in "0"), so moving an item only changes its own. Two people adding or moving items to the
// same spot at once can pick the same pos: then ids decide.

const DIGITS = "0123456789abcdefghijklmnopqrstuvwxyz";

/** A pos after `a` ("" for the very start) and before `b` (null for the very end). Needs a < b. */
export function between(a: string, b: string | null): string {
  const append = b === null;
  let out = "";
  for (let i = 0; ; i++) {
    const lo = i < a.length ? DIGITS.indexOf(a[i]) : 0;
    const hi = b !== null && i < b.length ? DIGITS.indexOf(b[i]) : DIGITS.length;
    // Halfway; or when appending, just past, which leaves room for 35 more appends per digit.
    if (hi - lo > 1) return out + DIGITS[append ? lo + 1 : (lo + hi) >> 1];
    out += DIGITS[lo];
    // Past here, we're below b whatever follows.
    if (hi - lo === 1) b = null;
  }
}

const cmp = (a: string, b: string) => (a < b ? -1 : a > b ? 1 : 0);

/** The items, in order. Skips anything that isn't an item: it's whatever editors wrote. */
function readItems(items: Y.Map<unknown>): Item[] {
  const out: Item[] = [];
  for (const [id, m] of items) {
    if (!(m instanceof Y.Map)) continue;
    const text = m.get("text");
    const pos = m.get("pos");
    out.push({ id, text: typeof text === "string" ? text : "", done: m.get("done") === true, pos: typeof pos === "string" ? pos : "" });
  }
  return out.sort((a, b) => cmp(a.pos, b.pos) || cmp(a.id, b.id));
}

const newId = () => Array.from(crypto.getRandomValues(new Uint8Array(8)), (b) => b.toString(16).padStart(2, "0")).join("");

/** A shared list: add, check off, edit, delete and drag items, if `editable`. Unchecked items first. */
export function ListView({ ydoc, editable }: { ydoc: Y.Doc; editable: boolean }) {
  const items = useMemo(() => ydoc.getMap<unknown>("items"), [ydoc]);
  const [, rerender] = useState(0);
  useEffect(() => {
    const f = () => rerender((v) => v + 1);
    items.observeDeep(f);
    return () => items.unobserveDeep(f);
  }, [items]);
  const [draft, setDraft] = useState("");

  const all = readItems(items);
  const todo = all.filter((i) => !i.done);
  const done = all.filter((i) => i.done);
  const field = (id: string, k: string, v: unknown) => {
    const m = items.get(id);
    if (m instanceof Y.Map) m.set(k, v);
  };

  const add = () => {
    const text = draft.trim();
    if (!text) return;
    ydoc.transact(() => {
      const m = new Y.Map<unknown>();
      m.set("text", text);
      m.set("done", false);
      m.set("pos", between(all.at(-1)?.pos ?? "", null));
      items.set(newId(), m);
    });
    setDraft("");
  };

  /** Moves `id` to be `index`th of `group` (which it's in). */
  const move = (group: Item[], id: string, index: number) => {
    const others = group.filter((i) => i.id !== id);
    const prev = others[index - 1]?.pos ?? "";
    // The next item with a pos above prev: others may share prev's.
    const next = others.slice(index).find((i) => i.pos > prev)?.pos ?? null;
    field(id, "pos", between(prev, next));
  };

  const clearChecked = () => ydoc.transact(() => done.forEach((i) => items.delete(i.id)));
  const rowProps = { editable, field, remove: (id: string) => items.delete(id) };

  return (
    <div className="space-y-4">
      {editable && (
        <form
          className="flex gap-2"
          onSubmit={(e) => {
            e.preventDefault();
            add();
          }}
        >
          <input
            className="block w-full rounded-md px-3 py-2 ring-1 ring-gray-300 ring-inset focus:ring-2 focus:ring-indigo-600 focus:outline-none"
            placeholder="Add an item…"
            value={draft}
            onChange={(e) => setDraft(e.target.value)}
            enterKeyHint="enter"
          />
          <button className={secondary} disabled={!draft.trim()}>
            Add
          </button>
        </form>
      )}
      {all.length === 0 && <p className="text-sm text-gray-500 italic">Nothing on the list yet.</p>}
      <Rows group={todo} move={move} {...rowProps} />
      {done.length > 0 && (
        <section className="space-y-2">
          <div className="flex items-center justify-between">
            <h3 className="text-sm font-semibold text-gray-500">Checked ({done.length})</h3>
            {editable && (
              <button className="cursor-pointer text-sm text-gray-500 hover:text-red-600" onClick={clearChecked}>
                Clear checked
              </button>
            )}
          </div>
          <Rows group={done} move={move} {...rowProps} />
        </section>
      )}
    </div>
  );
}

type RowsProps = {
  group: Item[];
  editable: boolean;
  field: (id: string, k: string, v: unknown) => void;
  remove: (id: string) => void;
  move: (group: Item[], id: string, index: number) => void;
};

/** A group of items, reorderable by dragging their handles (with a mouse, or a finger). */
function Rows({ group, editable, field, remove, move }: RowsProps) {
  const rows = useRef(new Map<string, HTMLLIElement>());
  /** The item being dragged, and where it'd land: its index among the others. */
  const [drag, setDrag] = useState<{ id: string; index: number } | null>(null);

  /** Where an item dropped at height `y` lands: how many of the others' middles are above it. */
  const landing = (id: string, y: number) =>
    group.filter((i) => i.id !== id).filter((i) => {
      const r = rows.current.get(i.id)?.getBoundingClientRect();
      return r && r.top + r.height / 2 < y;
    }).length;

  if (!group.length) return null;
  const others = drag ? group.filter((i) => i.id !== drag.id) : group;
  const marker = (i: number) => drag && drag.index === i && <li key={`marker-${i}`} aria-hidden className="h-0.5 rounded bg-indigo-500" />;

  return (
    <ul className="space-y-1">
      {group.map((item) => {
        const i = others.findIndex((o) => o.id === item.id);
        return [
          i >= 0 && marker(i),
          <li
            key={item.id}
            ref={(el) => {
              if (el) rows.current.set(item.id, el);
              else rows.current.delete(item.id);
            }}
            className={`flex items-center gap-2 rounded-md bg-white px-2 py-1.5 ring-1 ring-gray-200 ${drag?.id === item.id ? "opacity-40" : ""}`}
          >
            {editable && (
              <span
                className="cursor-grab touch-none px-1 text-gray-400 select-none hover:text-gray-700 active:cursor-grabbing"
                title="Drag to reorder"
                aria-label="Drag to reorder"
                onPointerDown={(e) => {
                  e.currentTarget.setPointerCapture(e.pointerId);
                  setDrag({ id: item.id, index: landing(item.id, e.clientY) });
                }}
                onPointerMove={(e) => drag?.id === item.id && setDrag({ id: item.id, index: landing(item.id, e.clientY) })}
                onPointerUp={() => {
                  if (drag?.id === item.id) move(group, item.id, drag.index);
                  setDrag(null);
                }}
                onPointerCancel={() => setDrag(null)}
              >
                ⠿
              </span>
            )}
            <input
              type="checkbox"
              className="size-5 shrink-0 cursor-pointer accent-indigo-600"
              checked={item.done}
              disabled={!editable}
              onChange={(e) => field(item.id, "done", e.target.checked)}
              aria-label={item.done ? "Uncheck" : "Check"}
            />
            <input
              className={`min-w-0 flex-1 rounded px-1 py-0.5 outline-none focus:ring-2 focus:ring-indigo-600 ${item.done ? "text-gray-400 line-through" : ""}`}
              value={item.text}
              readOnly={!editable}
              onChange={(e) => field(item.id, "text", e.target.value)}
              aria-label="Item"
            />
            {editable && (
              <button
                className="cursor-pointer px-1 text-gray-400 hover:text-red-600"
                onClick={() => remove(item.id)}
                title="Delete"
                aria-label="Delete item"
              >
                ×
              </button>
            )}
          </li>,
        ];
      })}
      {marker(others.length)}
    </ul>
  );
}
