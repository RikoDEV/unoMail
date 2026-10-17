import { beforeEach, describe, expect, it } from 'vitest';
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
