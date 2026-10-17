import 'fake-indexeddb/auto';
import { beforeEach, describe, expect, it, vi } from 'vitest';

const calls: string[] = [];
let network = true;
let refuse = false;

function attempt(name: string) {
  if (!network) return Promise.reject(new TypeError('Failed to fetch'));
  if (refuse) return Promise.reject(new Error('forbidden to send'));
  calls.push(name);
  return Promise.resolve();
}

vi.mock('./jmapClient', () => ({
  setKeyword: (ids: string[], keyword: string, value: boolean) => attempt(`keyword ${ids.join(',')} ${keyword} ${value}`),
  moveEmails: (ids: string[], mailboxId: string) => attempt(`move ${ids.join(',')} ${mailboxId}`),
  destroyEmails: (ids: string[]) => attempt(`destroy ${ids.join(',')}`),
  sendEmail: (draft: { subject: string }) => attempt(`send ${draft.subject}`),
}));

import { flushOutbox, openOutbox, pendingCount, performOrQueue, queuedPendingFiles } from './outbox';
import { loadPendingFile, storePendingFile } from './pendingFiles';

const draft = { to: 'a@example.org', cc: '', bcc: '', subject: 'Hello', html: '<p>x</p>', attachments: [] };

describe('offline outbox', () => {
  beforeEach(() => {
    localStorage.clear();
    calls.length = 0;
    network = true;
    refuse = false;
    openOutbox('bob@example.org');
  });

  it('runs actions immediately while online', async () => {
    expect(await performOrQueue({ type: 'keyword', ids: ['m1'], keyword: '$flagged', value: true })).toBe(false);
    expect(calls).toEqual(['keyword m1 $flagged true']);
    expect(pendingCount()).toBe(0);
  });

  it('queues actions offline and replays them in order when the connection returns', async () => {
    network = false;
    expect(await performOrQueue({ type: 'move', ids: ['m1'], mailboxId: 'b5' })).toBe(true);
    expect(await performOrQueue({ type: 'send', draft, draftsId: 'b2', sentId: 'b3' })).toBe(true);
    expect(pendingCount()).toBe(2);
    expect(await flushOutbox()).toEqual({ done: 0, rejected: [], remaining: 2 });

    network = true;
    // A new action must not overtake the ones already waiting.
    expect(await performOrQueue({ type: 'destroy', ids: ['m9'] })).toBe(true);
    expect(await flushOutbox()).toEqual({ done: 3, rejected: [], remaining: 0 });
    expect(calls).toEqual(['move m1 b5', 'send Hello', 'destroy m9']);
  });

  it('survives a reload and is separate per account', async () => {
    network = false;
    await performOrQueue({ type: 'keyword', ids: ['m1'], keyword: 'work', value: true });
    openOutbox('eve@example.org');
    expect(pendingCount()).toBe(0);
    openOutbox('bob@example.org');
    expect(pendingCount()).toBe(1);
  });

  it('drops and reports actions the server refuses, and surfaces refusals when online', async () => {
    refuse = true;
    await expect(performOrQueue({ type: 'send', draft, draftsId: 'b2', sentId: 'b3' })).rejects.toThrow('forbidden to send');
    expect(pendingCount()).toBe(0);

    refuse = false;
    network = false;
    await performOrQueue({ type: 'send', draft, draftsId: 'b2', sentId: 'b3' });
    await performOrQueue({ type: 'destroy', ids: ['m2'] });
    network = true;
    refuse = true;
    const result = await flushOutbox();
    expect(result).toEqual({ done: 0, rejected: ['forbidden to send', 'forbidden to send'], remaining: 0 });
  });

  it('keeps the files of a queued message until it has been sent', async () => {
    const blobId = await storePendingFile(new Blob(['report']));
    const withFile = { ...draft, attachments: [{ blobId, name: 'report.txt', type: 'text/plain', size: 6 }] };
    network = false;
    await performOrQueue({ type: 'send', draft: withFile, draftsId: 'b2', sentId: 'b3' });
    expect(queuedPendingFiles()).toEqual([blobId]);
    await flushOutbox();
    expect(await loadPendingFile(blobId)).toBeDefined();

    network = true;
    expect((await flushOutbox()).done).toBe(1);
    expect(queuedPendingFiles()).toEqual([]);
    await vi.waitFor(async () => expect(await loadPendingFile(blobId)).toBeUndefined());
  });
});
