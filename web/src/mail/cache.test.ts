// @vitest-environment jsdom
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import { cachedList, cachedMailboxes, cachedThread, cacheList, cacheMailboxes, cacheThread, clearAccountCache, clearMailCache, closeCache, openCache, setPersistentCache } from './cache';
import { labelsOf, normalizeLabel } from './jmapClient';

describe('offline cache', () => {
  beforeEach(() => {
    localStorage.clear();
    localStorage.setItem('unomail.offlineCache', 'true');
    openCache('bob@example.org');
  });

  it('stores and returns folders, lists and conversations per account', () => {
    cacheMailboxes([{ id: 'b1' }]);
    cacheList('b1', [{ id: 'm1' }], 1);
    cacheThread('t1', [{ id: 'm1' }]);
    expect(cachedMailboxes()).toEqual([{ id: 'b1' }]);
    expect(cachedList('b1')).toEqual({ emails: [{ id: 'm1' }], total: 1 });
    expect(cachedThread('t1')).toEqual([{ id: 'm1' }]);

    // Another account on the same browser never sees this data.
    openCache('eve@example.org');
    expect(cachedMailboxes()).toBeUndefined();
    expect(cachedList('b1')).toBeUndefined();
    expect(cachedThread('t1')).toBeUndefined();
  });

  it('responses arriving after sign-out are not cached again', () => {
    cacheMailboxes([{ id: 'b1' }]);
    closeCache();
    clearMailCache();
    cacheList('b1', [{ id: 'late' }], 1);
    cacheThread('t1', [{ id: 'late' }]);
    expect(Object.keys(localStorage)).toEqual(['unomail.offlineCache']);
  });

  it("signing out of one account keeps the others' data", () => {
    cacheMailboxes([{ id: 'b1' }]);
    localStorage.setItem('unomail.cache.outbox.bob@example.org', '[]');
    openCache('eve@example.org');
    cacheMailboxes([{ id: 'b9' }]);
    clearAccountCache('bob@example.org');
    expect(cachedMailboxes()).toEqual([{ id: 'b9' }]);
    expect(localStorage.getItem('unomail.cache.outbox.bob@example.org')).toBeNull();
    openCache('bob@example.org');
    expect(cachedMailboxes()).toBeUndefined();
  });

  it('evicts the oldest conversations and is wiped on sign-out', () => {
    for (let i = 0; i < 40; i += 1) cacheThread(`t${i}`, [{ id: `m${i}` }]);
    expect(cachedThread('t0')).toBeUndefined();
    expect(cachedThread('t39')).toEqual([{ id: 'm39' }]);
    localStorage.setItem('unomail.mode', 'dark');
    clearMailCache();
    expect(cachedThread('t39')).toBeUndefined();
    expect(localStorage.getItem('unomail.mode')).toBe('dark');
  });

  it('survives corrupt storage', () => {
    localStorage.setItem('unomail.cache.bob@example.org', '{not json');
    expect(cachedMailboxes()).toBeUndefined();
    cacheMailboxes([1]);
    expect(cachedMailboxes()).toEqual([1]);
  });
  it('keeps cached mail in memory unless the device opts in', () => {
    setPersistentCache(false);
    openCache('bob@example.org');
    cacheThread('t1', [{ body: 'private mail' }]);
    expect(cachedThread('t1')).toEqual([{ body: 'private mail' }]);
    expect(localStorage.getItem('unomail.cache.bob@example.org')).toBeNull();
    clearMailCache();
    expect(cachedThread('t1')).toBeUndefined();
  });
});

describe('offline cache expiry', () => {
  const DAY = 24 * 60 * 60 * 1000;
  const key = 'unomail.cache.bob@example.org';
  const stored = (savedAt?: number, mailboxes: unknown = [{ id: 'old' }]) =>
    JSON.stringify({ mailboxes, lists: {}, threads: {}, threadOrder: [], listOrder: [], ...(savedAt === undefined ? {} : { savedAt }) });

  beforeEach(() => {
    vi.useFakeTimers();
    vi.setSystemTime(new Date('2026-11-08T12:00:00Z'));
    localStorage.clear();
    localStorage.setItem('unomail.offlineCache', 'true');
  });
  afterEach(() => vi.useRealTimers());

  it('stamps every write', () => {
    openCache('bob@example.org');
    cacheMailboxes([{ id: 'b1' }]);
    expect(JSON.parse(localStorage.getItem(key)!).savedAt).toBe(Date.now());
  });

  it('serves a copy younger than 30 days and removes an older one', () => {
    localStorage.setItem(key, stored(Date.now() - 29 * DAY));
    openCache('bob@example.org');
    expect(cachedMailboxes()).toEqual([{ id: 'old' }]);

    localStorage.setItem(key, stored(Date.now() - 31 * DAY));
    expect(cachedMailboxes()).toBeUndefined();
    expect(localStorage.getItem(key)).toBeNull();
  });

  it('treats a copy from before the stamp existed as expired', () => {
    localStorage.setItem(key, stored(undefined));
    openCache('bob@example.org');
    expect(cachedMailboxes()).toBeUndefined();
    expect(localStorage.getItem(key)).toBeNull();
  });

  it('refreshes the stamp when the cache is written again', () => {
    localStorage.setItem(key, stored(Date.now() - 20 * DAY));
    openCache('bob@example.org');
    cacheList('b1', [], 0);
    vi.setSystemTime(Date.now() + 20 * DAY);
    expect(cachedMailboxes()).toEqual([{ id: 'old' }]);
  });

  it('sweeps expired accounts that are never opened again, but not fresh ones or the outbox', () => {
    localStorage.setItem('unomail.cache.eve@example.org', stored(Date.now() - 40 * DAY));
    localStorage.setItem('unomail.cache.old@example.org', stored(undefined));
    localStorage.setItem('unomail.cache.corrupt@example.org', '{not json');
    localStorage.setItem('unomail.cache.carol@example.org', stored(Date.now() - DAY));
    localStorage.setItem('unomail.cache.outbox.eve@example.org', '[{"queued":true}]');
    localStorage.setItem('unomail.mode', 'dark');
    openCache('bob@example.org');
    expect(Object.keys(localStorage).sort()).toEqual([
      'unomail.cache.carol@example.org',
      'unomail.cache.outbox.eve@example.org',
      'unomail.mode',
      'unomail.offlineCache',
    ]);
  });

  it('keeps expiry and the sweep out of the memory-only mode', () => {
    setPersistentCache(false);
    localStorage.setItem(key, stored(undefined));
    openCache('bob@example.org');
    // Opening without the opt-in removes persisted mail altogether ...
    expect(localStorage.getItem(key)).toBeNull();
    // ... and what is cached afterwards never reaches storage, however much time passes.
    cacheMailboxes([{ id: 'm' }]);
    vi.setSystemTime(Date.now() + 90 * DAY);
    expect(cachedMailboxes()).toEqual([{ id: 'm' }]);
    expect(localStorage.getItem(key)).toBeNull();
  });

  it('turning the opt-in off wipes persisted mail but keeps the outbox', () => {
    openCache('bob@example.org');
    cacheMailboxes([{ id: 'b1' }]);
    localStorage.setItem('unomail.cache.outbox.bob@example.org', '[1]');
    setPersistentCache(false);
    expect(localStorage.getItem(key)).toBeNull();
    expect(localStorage.getItem('unomail.cache.outbox.bob@example.org')).toBe('[1]');
  });

  it('still stamps the reduced copy written when storage is full', () => {
    openCache('bob@example.org');
    const real = Storage.prototype.setItem;
    let first = true;
    const spy = vi.spyOn(Storage.prototype, 'setItem').mockImplementation(function (this: Storage, k: string, v: string) {
      if (k === key && first) { first = false; throw new DOMException('full', 'QuotaExceededError'); }
      real.call(this, k, v);
    });
    cacheThread('t1', [{ id: 'm1' }]);
    spy.mockRestore();
    const saved = JSON.parse(localStorage.getItem(key)!);
    expect(saved.savedAt).toBe(Date.now());
    expect(saved.threads).toEqual({});
  });
});

describe('labels', () => {
  it('normalises names to a safe alphabet', () => {
    expect(normalizeLabel(' Project X ')).toBe('project-x');
    expect(normalizeLabel('2026_taxes.final')).toBe('2026_taxes.final');
    for (const bad of ['', '$seen', 'a/b', 'x'.repeat(60), '(paren)', '"q"']) expect(normalizeLabel(bad)).toBeNull();
  });

  it('lists only user labels', () => {
    expect(labelsOf({ keywords: { $seen: true, work: true, alpha: true, old: false } })).toEqual(['alpha', 'work']);
  });
});
