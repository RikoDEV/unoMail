// New-mail notifications through Web Push: the browser subscribes with the server's VAPID
// key, the subscription is registered as a JMAP PushSubscription, and the service worker
// (public/sw.js) shows a notification when a message arrives, even with no tab open.
//
// Where Web Push is missing (the browser lacks it, or the server has no push key), an open
// unoMail tab shows the notifications itself while it is in the background.

import { get, jmap } from '../api';

import { t } from '../i18n';
import { readLocal, writeLocal } from '../storage';
/** Each signed-in account registers this browser on its own. */
const storageKey = (account: string) => `unomail.pushSubscription.${account}`;
/** Notifications from the open tab only, for an account without Web Push. */
const pageKey = (account: string) => `unomail.pageNotifications.${account}`;

/** Web Push: notifications also when unoMail is closed. */
function pushSupported(): boolean {
  return typeof window !== 'undefined' && 'serviceWorker' in navigator && 'PushManager' in window && typeof Notification !== 'undefined';
}

/** Any kind of notification: at least from an open tab. */
export function notificationsSupported(): boolean {
  return typeof window !== 'undefined' && typeof Notification !== 'undefined';
}

/** Whether the open tab is the one to show notifications for `account` (no Web Push). */
export function pageNotificationsOn(account: string): boolean {
  return notificationsSupported() && Notification.permission === 'granted' && readLocal(pageKey(account)) === '1';
}

const storedId = (account: string) => readLocal(storageKey(account));
// Private windows: the subscription simply is not remembered here.
const store = (account: string, id: string | null) => void writeLocal(storageKey(account), id || null);

/** Whether this browser currently receives new-mail notifications. */
export async function notificationsEnabled(account: string): Promise<boolean> {
  if (pageNotificationsOn(account)) return true;
  if (!pushSupported() || Notification.permission !== 'granted' || !storedId(account)) return false;
  const registration = await navigator.serviceWorker.getRegistration('/');
  return Boolean(await registration?.pushManager.getSubscription());
}

function keyBytes(base64url: string): Uint8Array<ArrayBuffer> {
  const base64 = base64url.replace(/-/g, '+').replace(/_/g, '/');
  const binary = atob(base64 + '='.repeat((4 - (base64.length % 4)) % 4));
  const out = new Uint8Array(new ArrayBuffer(binary.length));
  for (let i = 0; i < binary.length; i++) out[i] = binary.charCodeAt(i);
  return out;
}

/**
 * Asks for permission, subscribes this browser and registers it with the server. Returns
 * 'push', or 'page' when only an open tab can notify (no Web Push here or on the server).
 */
export async function enableNotifications(account: string): Promise<'push' | 'page'> {
  if (!notificationsSupported()) throw new Error(t('This browser cannot show notifications'));
  if ((await Notification.requestPermission()) !== 'granted') throw new Error(t('Notifications are blocked for this site in the browser settings'));
  const session = await get<{ capabilities: Record<string, { applicationServerKey?: string | null }> }>('/jmap/session');
  const key = session.capabilities['urn:ietf:params:jmap:webpush-vapid']?.applicationServerKey;
  if (!key || !pushSupported()) {
    writeLocal(pageKey(account), '1');
    return 'page';
  }
  writeLocal(pageKey(account), null);
  const registration = await navigator.serviceWorker.register('/sw.js', { scope: '/' });
  await navigator.serviceWorker.ready;
  const existing = await registration.pushManager.getSubscription();
  const subscription = existing ?? (await registration.pushManager.subscribe({ userVisibleOnly: true, applicationServerKey: keyBytes(key) }));
  const json = subscription.toJSON();
  // The verification code arrives through the push service, at the service worker.
  const verification = new Promise<{ id: string; code: string }>((resolve, reject) => {
    const timer = window.setTimeout(() => reject(new Error(t('The push service did not answer; try again later'))), 30_000);
    const listener = (event: MessageEvent) => {
      if (event.data?.type === 'push-verification') {
        window.clearTimeout(timer);
        navigator.serviceWorker.removeEventListener('message', listener);
        resolve(event.data);
      }
    };
    navigator.serviceWorker.addEventListener('message', listener);
  });
  const [[, created]] = await jmap([
    ['PushSubscription/set', { create: { web: { deviceClientId: `web:${navigator.userAgent.slice(0, 120)}`, url: json.endpoint, keys: json.keys, types: ['EmailDelivery'] } } }, '0'],
  ]);
  const id = created.created?.web?.id as string | undefined;
  if (!id) throw new Error(created.notCreated?.web?.description ?? t('The server refused the subscription'));
  const { code } = await verification;
  await jmap([['PushSubscription/set', { update: { [id]: { verificationCode: code } } }, '0']]);
  const previous = storedId(account);
  store(account, id);
  if (previous && previous !== id) await jmap([['PushSubscription/set', { destroy: [previous] }, '0']]).catch(() => {});
  return 'push';
}

export async function disableNotifications(account: string): Promise<void> {
  writeLocal(pageKey(account), null);
  if (!pushSupported()) return;
  const id = storedId(account);
  store(account, null);
  // The browser's subscription is shared by its accounts: kept while another one uses it.
  const othersUseIt = Object.keys(localStorage).some((key) => key.startsWith('unomail.pushSubscription.') && key !== storageKey(account));
  if (!othersUseIt) {
    const registration = await navigator.serviceWorker.getRegistration('/');
    await (await registration?.pushManager.getSubscription())?.unsubscribe();
  }
  if (id) await jmap([['PushSubscription/set', { destroy: [id] }, '0']]).catch(() => {});
}

export interface NewestUnread {
  account: string;
  unread: number;
  message: { from: string; subject: string; preview: string; threadId: string } | null;
}

/** The newest unread message in the inbox (also what the service worker asks for). */
const newestUnread = () => get<NewestUnread>('/api/me/newest-unread');

/**
 * Notifications shown by the open tab, for accounts without Web Push: after each change it
 * looks at the newest unread message, and announces it if it is new and nobody is looking.
 * Returns a function to call on every change the server reports.
 */
export function pageNotifier(account: string, open: (threadId: string) => void): () => void {
  let last: string | null | undefined;
  // What is unread now is not news; only what arrives from here on.
  void newestUnread().then((now) => (last = now.message?.threadId ?? null), () => (last = null));
  return () => {
    if (!pageNotificationsOn(account) || last === undefined) return;
    void newestUnread().then((now) => {
      const message = now.message;
      const known = last;
      last = message?.threadId ?? null;
      if (!message || message.threadId === known || document.visibilityState === 'visible') return;
      const notification = new Notification(message.from || t('New mail'), {
        body: [message.subject || t('(no subject)'), message.preview].filter(Boolean).join('\n'),
        tag: `unomail-${message.threadId}`,
        icon: '/favicon.svg',
      });
      notification.onclick = () => {
        window.focus();
        open(message.threadId);
        notification.close();
      };
    }, () => {});
  };
}
