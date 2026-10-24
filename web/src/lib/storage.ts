// The browser's local storage, which may be missing or refuse writes (private windows, a full
// quota, blocked site data). Every value kept there is a convenience, so failures are quiet.

export function readLocal(key: string): string | null {
  try {
    return localStorage.getItem(key);
  } catch {
    return null;
  }
}

/** A stored JSON value, or `fallback` when there is none or it cannot be read. */
export function readLocalJson<T>(key: string, fallback: T): T {
  const raw = readLocal(key);
  if (raw === null) return fallback;
  try {
    return JSON.parse(raw) as T;
  } catch {
    return fallback;
  }
}

/** Stores a value (`null` removes it); returns whether that worked. */
export function writeLocal(key: string, value: string | null): boolean {
  try {
    if (value === null) localStorage.removeItem(key);
    else localStorage.setItem(key, value);
    return true;
  } catch {
    return false;
  }
}
