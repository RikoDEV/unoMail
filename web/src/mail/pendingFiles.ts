
import { t } from '../i18n';// Files attached without a connection wait in IndexedDB until their message is sent.
// They are referenced from drafts by a `pending:<uuid>` blob id, removed once the message
// has been handed to the server, and wiped on sign-out together with the mail cache.

const DATABASE = 'unomail-offline';
const STORE = 'attachments';
export const PENDING_PREFIX = 'pending:';

export const isPendingId = (blobId: string) => blobId.startsWith(PENDING_PREFIX);

export function pendingFilesAvailable(): boolean {
  return typeof indexedDB !== 'undefined';
}

function open(): Promise<IDBDatabase> {
  return new Promise((resolve, reject) => {
    const request = indexedDB.open(DATABASE, 1);
    request.onupgradeneeded = () => request.result.createObjectStore(STORE);
    request.onsuccess = () => resolve(request.result);
    request.onerror = () => reject(request.error ?? new Error(t('offline storage is unavailable')));
    request.onblocked = () => reject(new Error(t('offline storage is busy')));
  });
}

async function transact<T>(mode: IDBTransactionMode, work: (store: IDBObjectStore) => IDBRequest<T>): Promise<T> {
  const db = await open();
  try {
    return await new Promise<T>((resolve, reject) => {
      const tx = db.transaction(STORE, mode);
      const request = work(tx.objectStore(STORE));
      tx.oncomplete = () => resolve(request.result);
      tx.onerror = () => reject(tx.error ?? new Error(t('offline storage failed')));
      tx.onabort = () => reject(tx.error ?? new Error(t('offline storage is full')));
    });
  } finally {
    db.close();
  }
}

/** Stores a file and returns the blob id that stands in for it until it is uploaded. */
export async function storePendingFile(file: Blob): Promise<string> {
  const id = PENDING_PREFIX + crypto.randomUUID();
  // Stored as raw bytes: every browser can clone an ArrayBuffer into IndexedDB.
  const data = await file.arrayBuffer();
  await transact('readwrite', (store) => store.put(data, id));
  return id;
}

export async function loadPendingFile(id: string): Promise<ArrayBuffer | undefined> {
  const data = await transact<unknown>('readonly', (store) => store.get(id));
  // Not `instanceof`: the buffer may come from another realm.
  return Object.prototype.toString.call(data) === '[object ArrayBuffer]' ? (data as ArrayBuffer) : undefined;
}

export async function removePendingFiles(ids: string[]): Promise<void> {
  const pending = ids.filter(isPendingId);
  if (pending.length === 0 || !pendingFilesAvailable()) return;
  try {
    const db = await open();
    try {
      await new Promise<void>((resolve, reject) => {
        const tx = db.transaction(STORE, 'readwrite');
        pending.forEach((id) => tx.objectStore(STORE).delete(id));
        tx.oncomplete = () => resolve();
        tx.onerror = tx.onabort = () => reject(tx.error);
      });
    } finally {
      db.close();
    }
  } catch {
    /* leftovers are removed by the next sweep */
  }
}

/** Deletes stored files that no queued message refers to any more (e.g. after a closed tab). */
export async function sweepPendingFiles(referenced: string[]): Promise<void> {
  if (!pendingFilesAvailable()) return;
  try {
    const keys = await transact<IDBValidKey[]>('readonly', (store) => store.getAllKeys());
    const keep = new Set(referenced);
    await removePendingFiles(keys.filter((k): k is string => typeof k === 'string' && !keep.has(k)));
  } catch {
    /* nothing to sweep */
  }
}

/** Removes every stored file from this browser (called on sign-out). */
export function clearPendingFiles(): Promise<void> {
  if (!pendingFilesAvailable()) return Promise.resolve();
  return new Promise((resolve) => {
    const request = indexedDB.deleteDatabase(DATABASE);
    request.onsuccess = request.onerror = request.onblocked = () => resolve();
  });
}
