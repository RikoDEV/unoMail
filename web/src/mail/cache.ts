
import { readLocal, writeLocal } from '../storage';// Offline cache: the folder list, the first page of each folder and recently opened
// conversations are kept in the browser so the client opens instantly and stays readable
// without a connection. The cache is per account and is wiped on sign-out.

const PREFIX = 'unomail.cache.';
const MAX_THREADS = 30;
const MAX_LISTS = 20;

interface Stored {
  mailboxes?: unknown;
  lists: Record<string, { emails: unknown; total: number }>;
  threads: Record<string, unknown>;
  /** Insertion order, oldest first, for eviction. */
  threadOrder: string[];
  listOrder: string[];
}

let accountKey = '';
const memory = new Map<string, Stored>();
export const persistentCacheEnabled = () => readLocal('unomail.offlineCache') === 'true';
export function setPersistentCache(enabled: boolean) {
  writeLocal('unomail.offlineCache', enabled ? 'true' : null);
  if (!enabled) {
    memory.clear();
    removePersistedMail();
  }
}

function removePersistedMail() {
  try {
    for (const key of Object.keys(localStorage)) {
      if (key.startsWith(PREFIX) && !key.startsWith(`${PREFIX}outbox.`)) localStorage.removeItem(key);
    }
  } catch { /* storage may be disabled */ }
}

export function openCache(account: string) {
  if (!persistentCacheEnabled()) {
    // Remove old automatically-persisted mail, while leaving deliberate outbox work alone.
    removePersistedMail();
  }
  accountKey = PREFIX + account;
}

/** Stops caching: responses still arriving after sign-out must not write the cache back. */
export function closeCache() {
  accountKey = '';
}

function read(): Stored {
  if (!persistentCacheEnabled()) return memory.get(accountKey) ?? { lists: {}, threads: {}, threadOrder: [], listOrder: [] };
  try {
    const parsed = JSON.parse(localStorage.getItem(accountKey) ?? 'null');
    if (parsed && typeof parsed === 'object' && parsed.lists && parsed.threads) return parsed as Stored;
  } catch {
    // Corrupt or unavailable storage: start empty.
  }
  return { lists: {}, threads: {}, threadOrder: [], listOrder: [] };
}

function write(data: Stored) {
    if (!accountKey) return;
    if (!persistentCacheEnabled()) { memory.set(accountKey, data); return; }
  try {
    localStorage.setItem(accountKey, JSON.stringify(data));
  } catch {
    // Storage full or disabled: drop the bulky part and try once more, then give up silently.
    try {
      localStorage.setItem(accountKey, JSON.stringify({ ...data, threads: {}, threadOrder: [] }));
    } catch {
      /* the cache is an optimisation only */
    }
  }
}

function remember(order: string[], key: string, max: number, drop: (evicted: string) => void) {
  const next = order.filter((k) => k !== key);
  next.push(key);
  while (next.length > max) drop(next.shift()!);
  return next;
}

export function cachedMailboxes<T>(): T | undefined {
  return read().mailboxes as T | undefined;
}

export function cacheMailboxes(mailboxes: unknown) {
  write({ ...read(), mailboxes });
}

export function cachedList<T>(key: string): { emails: T; total: number } | undefined {
  return read().lists[key] as { emails: T; total: number } | undefined;
}

export function cacheList(key: string, emails: unknown, total: number) {
  const data = read();
  data.lists[key] = { emails, total };
  data.listOrder = remember(data.listOrder ?? [], key, MAX_LISTS, (evicted) => delete data.lists[evicted]);
  write(data);
}

export function cachedThread<T>(id: string): T | undefined {
  return read().threads[id] as T | undefined;
}

export function cacheThread(id: string, emails: unknown) {
  const data = read();
  data.threads[id] = emails;
  data.threadOrder = remember(data.threadOrder ?? [], id, MAX_THREADS, (evicted) => delete data.threads[evicted]);
  write(data);
}

/** Forgets what is stored on this device for one account (its cached mail and queued changes). */
export function clearAccountCache(account: string) {
  memory.delete(PREFIX + account);
  writeLocal(PREFIX + account, null);
  writeLocal(`${PREFIX}outbox.${account}`, null);
}

/** Removes every cached mailbox from this browser (called on sign-out). */
export function clearMailCache() {
  memory.clear();
  try {
    for (let i = localStorage.length - 1; i >= 0; i -= 1) {
      const key = localStorage.key(i);
      if (key?.startsWith(PREFIX)) localStorage.removeItem(key);
    }
  } catch {
    /* nothing to clear */
  }
}
