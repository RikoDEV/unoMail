// Service worker of the web mail: keeps the application shell so the installed app starts
// offline, and shows a notification when the server pushes word of new mail (JMAP StateChange
// with EmailDelivery, delivered through the browser's push service).

const SHELL = 'unomail-shell-v1';
const ASSETS = 'unomail-assets-v1';
// Served by the server itself, never by the application shell; mail data is never cached here.
const SERVER_PATHS = /^\/(api|jmap|dav|lists|\.well-known)(\/|$)/;

self.addEventListener('install', (event) => {
  event.waitUntil(
    (async () => {
      const cache = await caches.open(SHELL);
      await Promise.all(['/', '/favicon.svg', '/manifest.webmanifest'].map((url) => cache.add(url).catch(() => {})));
      await self.skipWaiting();
    })(),
  );
});

self.addEventListener('activate', (event) =>
  event.waitUntil(
    (async () => {
      for (const name of await caches.keys()) if (name.startsWith('unomail-') && name !== SHELL && name !== ASSETS) await caches.delete(name);
      await self.clients.claim();
    })(),
  ),
);

self.addEventListener('fetch', (event) => {
  const request = event.request;
  if (request.method !== 'GET') return;
  const url = new URL(request.url);
  if (url.origin !== self.location.origin || SERVER_PATHS.test(url.pathname)) return;
  if (request.mode === 'navigate') event.respondWith(page(request));
  else if (url.pathname.startsWith('/assets/')) event.respondWith(asset(request));
});

/** Pages come from the network; offline, the last application shell starts instead. */
async function page(request) {
  const cache = await caches.open(SHELL);
  try {
    const response = await fetch(request);
    if (response.ok && (response.headers.get('content-type') || '').includes('text/html')) {
      const previous = await cache.match('/');
      const fresh = response.clone();
      const text = await fresh.clone().text();
      // A new build names new assets: the ones of the old build are no longer needed.
      if (previous && (await previous.text()) !== text) await caches.delete(ASSETS);
      await cache.put('/', fresh);
    }
    return response;
  } catch (error) {
    const shell = await cache.match('/');
    if (shell) return shell;
    throw error;
  }
}

/** Built assets carry a content hash in their name, so a cached copy is always right. */
async function asset(request) {
  const cache = await caches.open(ASSETS);
  const cached = await cache.match(request);
  if (cached) return cached;
  const response = await fetch(request);
  if (response.ok) cache.put(request, response.clone()).catch(() => {});
  return response;
}

self.addEventListener('push', (event) => {
  let data = {};
  try {
    data = event.data ? event.data.json() : {};
  } catch {
    return;
  }
  event.waitUntil(
    (async () => {
      const windows = await self.clients.matchAll({ type: 'window', includeUncontrolled: true });
      if (data['@type'] === 'PushVerification') {
        // The page that created the subscription confirms it with this code.
        for (const client of windows) client.postMessage({ type: 'push-verification', id: data.pushSubscriptionId, code: data.verificationCode });
        return;
      }
      if (data['@type'] !== 'StateChange') return;
      const delivered = Object.values(data.changed || {}).some((types) => types && types.EmailDelivery);
      if (!delivered) return;
      // Someone looking at the mail already sees it arrive.
      if (windows.some((client) => client.focused && client.visibilityState === 'visible')) return;
      await showNewest(Object.keys(data.changed || {}));
    })(),
  );
});

/**
 * Shows the newest unread message. The signed-in account is asked with its session cookie;
 * when the push is for another account of this browser (or the question fails), a plain
 * notice is shown instead of another account's mail.
 */
async function showNewest(accounts) {
  let newest = null;
  try {
    const response = await fetch('/api/me/newest-unread', { credentials: 'same-origin', headers: { Accept: 'application/json' } });
    if (response.ok) newest = await response.json();
  } catch {
    // Offline or signed out: the plain notice below.
  }
  if (newest && accounts.includes(newest.account)) {
    if (self.navigator.setAppBadge) self.navigator.setAppBadge(newest.unread).catch(() => {});
    const message = newest.message;
    if (!message) return;
    await self.registration.showNotification(message.from || 'New mail', {
      body: [message.subject || '(no subject)', message.preview].filter(Boolean).join('\n'),
      tag: `unomail-${message.threadId}`,
      icon: '/favicon.svg',
      data: { url: `/mail/inbox/${message.threadId}` },
    });
    return;
  }
  await self.registration.showNotification('New mail', {
    body: 'A new message has arrived.',
    tag: 'unomail-new-mail',
    renotify: true,
    icon: '/favicon.svg',
    data: { url: '/mail' },
  });
}

self.addEventListener('notificationclick', (event) => {
  event.notification.close();
  event.waitUntil(
    (async () => {
      const windows = await self.clients.matchAll({ type: 'window', includeUncontrolled: true });
      const url = (event.notification.data && event.notification.data.url) || '/mail';
      const open = windows.find((client) => new URL(client.url).pathname.startsWith('/mail'));
      if (open) {
        // The open tab shows the conversation itself (MailPage), without loading again.
        open.postMessage({ type: 'open', url });
        return open.focus();
      }
      return self.clients.openWindow(url);
    })(),
  );
});
