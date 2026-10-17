// Service worker of the web mail: shows a notification when the server pushes word of new
// mail (JMAP StateChange with EmailDelivery, delivered through the browser's push service).

self.addEventListener('install', () => self.skipWaiting());
self.addEventListener('activate', (event) => event.waitUntil(self.clients.claim()));

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
      await self.registration.showNotification('New mail', {
        body: 'A new message has arrived.',
        tag: 'unomail-new-mail',
        renotify: true,
        data: { url: '/mail' },
      });
    })(),
  );
});

self.addEventListener('notificationclick', (event) => {
  event.notification.close();
  event.waitUntil(
    (async () => {
      const windows = await self.clients.matchAll({ type: 'window', includeUncontrolled: true });
      const open = windows.find((client) => new URL(client.url).pathname.startsWith('/mail'));
      if (open) return open.focus();
      return self.clients.openWindow((event.notification.data && event.notification.data.url) || '/mail');
    })(),
  );
});
