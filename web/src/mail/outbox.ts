// Offline outbox: changes and messages made without a connection are stored in the browser
// and replayed in order once the server is reachable again.

import { destroyEmails, type Draft, moveEmails, sendEmail, setKeyword } from './jmapClient';
import { isPendingId, removePendingFiles } from './pendingFiles';

import { t } from '../i18n';
import { errorText } from '../api';
import { readLocalJson, writeLocal } from '../storage';
export type OutboxAction =
  | { type: 'keyword'; ids: string[]; keyword: string; value: boolean }
  | { type: 'move'; ids: string[]; mailboxId: string }
  | { type: 'destroy'; ids: string[] }
  | { type: 'send'; draft: Draft; draftsId: string; sentId: string };

// Shares the cache prefix so that sign-out removes it together with cached mail.
const PREFIX = 'unomail.cache.outbox.';
const MAX_PENDING = 200;
let key = '';

export function openOutbox(account: string) {
  key = PREFIX + account;
}

function read(): OutboxAction[] {
  const parsed = readLocalJson<unknown>(key, []);
  return Array.isArray(parsed) ? (parsed as OutboxAction[]) : [];
}

// Storage unavailable: the action is lost, which the caller reports.
function write(actions: OutboxAction[]) {
  writeLocal(key, actions.length === 0 ? null : JSON.stringify(actions));
}

export function pendingCount(): number {
  return key ? read().length : 0;
}

function execute(action: OutboxAction): Promise<unknown> {
  switch (action.type) {
    case 'keyword':
      return setKeyword(action.ids, action.keyword, action.value);
    case 'move':
      return moveEmails(action.ids, action.mailboxId);
    case 'destroy':
      return destroyEmails(action.ids);
    case 'send':
      return sendEmail(action.draft, action.draftsId, action.sentId);
  }
}

/** Blob ids of files that queued messages (of any account in this browser) still need. */
export function queuedPendingFiles(): string[] {
  const ids: string[] = [];
  try {
    for (let i = 0; i < localStorage.length; i += 1) {
      const name = localStorage.key(i);
      if (!name?.startsWith(PREFIX)) continue;
      const actions = JSON.parse(localStorage.getItem(name) ?? '[]') as OutboxAction[];
      for (const action of Array.isArray(actions) ? actions : []) {
        if (action.type === 'send') ids.push(...action.draft.attachments.map((a) => a.blobId).filter(isPendingId));
      }
    }
  } catch {
    /* unreadable storage: nothing is referenced */
  }
  return ids;
}

/** Once a message is sent or refused for good, the files stored for it can go. */
function release(action: OutboxAction) {
  if (action.type === 'send') void removePendingFiles(action.draft.attachments.map((a) => a.blobId));
}

/** `fetch` rejects with a TypeError when the network is unreachable. */
export const isNetworkError = (err: unknown) => err instanceof TypeError;

/**
 * Runs an action now, or stores it for later when there is no connection.
 * Returns true when the action was queued. Server-side refusals are thrown.
 */
export async function performOrQueue(action: OutboxAction): Promise<boolean> {
  // Keep ordering: nothing may overtake changes that are already waiting.
  if (pendingCount() === 0) {
    try {
      await execute(action);
      release(action);
      return false;
    } catch (err) {
      if (!isNetworkError(err)) throw err;
    }
  }
  const pending = read();
  if (pending.length >= MAX_PENDING) throw new Error(t('Too many changes are waiting to be synchronised. Reconnect first.'));
  write([...pending, action]);
  return true;
}

export interface FlushResult {
  done: number;
  /** Actions the server refused; they are dropped and reported. */
  rejected: string[];
  remaining: number;
}

let flushing = false;

/** Replays queued actions in order. Stops at the first network failure. */
export async function flushOutbox(): Promise<FlushResult> {
  const result: FlushResult = { done: 0, rejected: [], remaining: pendingCount() };
  if (flushing || result.remaining === 0) return result;
  flushing = true;
  try {
    for (;;) {
      const pending = read();
      const next = pending[0];
      if (!next) break;
      try {
        await execute(next);
        result.done += 1;
      } catch (err) {
        if (isNetworkError(err)) break;
        result.rejected.push(errorText(err, t('A queued change was refused')));
      }
      write(read().slice(1));
      release(next);
    }
  } finally {
    flushing = false;
  }
  result.remaining = pendingCount();
  return result;
}
