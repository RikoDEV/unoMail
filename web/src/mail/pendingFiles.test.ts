import 'fake-indexeddb/auto';
import { beforeEach, describe, expect, it } from 'vitest';
import { clearPendingFiles, isPendingId, loadPendingFile, removePendingFiles, storePendingFile, sweepPendingFiles } from './pendingFiles';

const bytes = (data: ArrayBuffer | undefined) => (data ? Array.from(new Uint8Array(data)) : undefined);

describe('files waiting for an offline message', () => {
  beforeEach(() => clearPendingFiles());

  it('keeps large binary files intact until they are removed', async () => {
    const big = new Uint8Array(5 * 1024 * 1024).map((_, i) => i % 251);
    const id = await storePendingFile(new Blob([big]));
    expect(isPendingId(id)).toBe(true);
    const loaded = new Uint8Array((await loadPendingFile(id))!);
    expect(loaded.length).toBe(big.length);
    expect(loaded.every((b, i) => b === big[i])).toBe(true);
    await removePendingFiles([id]);
    expect(await loadPendingFile(id)).toBeUndefined();
  });

  it('sweeps files nothing refers to and never touches server blob ids', async () => {
    const kept = await storePendingFile(new Blob(['kept']));
    const orphan = await storePendingFile(new Blob(['orphan']));
    await removePendingFiles(['G1234']);
    await sweepPendingFiles([kept]);
    expect(bytes(await loadPendingFile(kept))).toEqual([107, 101, 112, 116]);
    expect(await loadPendingFile(orphan)).toBeUndefined();
  });

  it('is wiped on sign-out', async () => {
    const id = await storePendingFile(new Blob(['secret']));
    await clearPendingFiles();
    expect(await loadPendingFile(id)).toBeUndefined();
  });
});
