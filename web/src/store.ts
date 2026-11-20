// A small key-value store in IndexedDB, for what this device keeps between visits: each doc's last known
// content, and edits not sent to the node yet. Failures are ignored: it's a cache, and private windows
// may not have it at all.

let db: Promise<IDBDatabase> | null = null;

function open() {
  db ??= new Promise((resolve, reject) => {
    const req = indexedDB.open("bisonbase", 1);
    req.onupgradeneeded = () => req.result.createObjectStore("kv");
    req.onsuccess = () => resolve(req.result);
    req.onerror = () => reject(req.error);
  });
  return db;
}

/** Runs `fn` on the store in a transaction. Transactions run in the order they're started. */
async function tx<T>(mode: IDBTransactionMode, fn: (s: IDBObjectStore) => IDBRequest<T>): Promise<T | undefined> {
  try {
    const s = (await open()).transaction("kv", mode).objectStore("kv");
    return await new Promise((resolve, reject) => {
      const req = fn(s);
      req.onsuccess = () => resolve(req.result);
      req.onerror = () => reject(req.error);
    });
  } catch (e) {
    console.warn("IndexedDB:", e);
    return undefined;
  }
}

export const kvGet = <T>(key: string) => tx<T>("readonly", (s) => s.get(key));
export const kvSet = (key: string, value: unknown) => tx("readwrite", (s) => s.put(value, key));
export const kvDel = (key: string) => tx("readwrite", (s) => s.delete(key));
