// Per-user web client preferences, stored on the server so they follow the user between
// devices. Reads are synchronous from an in-memory copy; writes go to the server.

import { useSyncExternalStore } from 'react';
import { get, put } from './api';

export interface Prefs {
  /** Id of the selected skin. */
  skin?: string;
  /** Spell checking in the composer (on unless set to false). */
  spellcheck?: boolean;
  /** BCP 47 language the composer is checked in; empty follows the browser. */
  spell_lang?: string;
  /** Senders whose remote images are always shown. */
  image_senders?: string[];
  /** Encrypt and sign by default when every recipient has a key. */
  pgp_default?: boolean;
  /** Sort the inbox into category tabs (on unless set to false). */
  categories?: boolean;
  /** IANA time zone of the browser last used; the server reads zone-less calendar times in it. */
  timezone?: string;
  /** How the message list shows a conversation: one line, or several with attachments. */
  density?: 'condensed' | 'expanded';
  /** Seconds a sent message waits so that it can be called back (0: none; default 5). */
  undo_send_seconds?: number;
  /** What to do when a sender asks for a read receipt (default: ask). */
  receipts?: 'ask' | 'always' | 'never';
  /** Put the usual "-- " line above the signature, by which mail programs recognise it. */
  signature_separator?: boolean;
  /** In replies and forwards, put the signature below the quoted message instead of above it. */
  signature_below_quote?: boolean;
  /** Interface language (a code from i18n LANGUAGES); empty follows the browser. */
  language?: string;
}

let current: Prefs = {};
const listeners = new Set<() => void>();

function publish(next: Prefs) {
  current = next;
  listeners.forEach((listener) => listener());
}

/** Uses preferences fetched with other start-up data. */
export function primePrefs(prefs: Prefs) {
  publish(prefs && typeof prefs === 'object' ? prefs : {});
}

export async function loadPrefs(): Promise<Prefs> {
  try {
    publish(await get<Prefs>('/api/me/preferences'));
  } catch {
    // Preferences are a convenience; the client works with defaults when they cannot be read.
  }
  return current;
}

export async function updatePrefs(patch: Partial<Prefs>): Promise<void> {
  const next = { ...current, ...patch };
  publish(next);
  await put('/api/me/preferences', next);
}

export function resetPrefs() {
  publish({});
}

export function usePrefs(): Prefs {
  return useSyncExternalStore(
    (listener) => {
      listeners.add(listener);
      return () => listeners.delete(listener);
    },
    () => current,
  );
}
