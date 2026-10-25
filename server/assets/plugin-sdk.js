// unoMail plug-in SDK (API 2). Runs inside the plug-in's sandboxed frame, before the plug-in.
//
// The frame has no access to the page, the user's session or the server. Everything a plug-in
// does goes through `unomail`, which sends requests over a private channel to the web client;
// the client checks each one against the permissions in the plug-in's manifest.
(() => {
  'use strict';
  let port = null;
  let seq = 0;
  const pending = new Map();
  const listeners = Object.create(null);
  const actions = Object.create(null);

  const ready = new Promise((resolve) => {
    addEventListener('message', function connect(event) {
      if (event.source !== parent || !event.ports[0] || !event.data || event.data.type !== 'unomail:connect') return;
      removeEventListener('message', connect);
      port = event.ports[0];
      port.onmessage = ({ data }) => receive(data);
      resolve(Object.freeze(event.data.context));
    });
  });

  function receive(data) {
    if (!data || typeof data !== 'object') return;
    // The client checks now and then that the plug-in still responds.
    if (typeof data.ping === 'number') {
      port.postMessage({ pong: data.ping });
    } else if (typeof data.reply === 'number') {
      const call = pending.get(data.reply);
      if (!call) return;
      pending.delete(data.reply);
      if (data.error) call.reject(new Error(data.error));
      else call.resolve(data.result);
    } else if (typeof data.event === 'string') {
      for (const handler of listeners[data.event] || []) {
        try {
          handler(data.payload);
        } catch (err) {
          console.error(`unomail: handler for ${data.event} failed`, err);
        }
      }
    } else if (typeof data.action === 'string' && actions[data.action]) {
      Promise.resolve()
        .then(() => actions[data.action](data.payload))
        .catch((err) => console.error(`unomail: action ${data.action} failed`, err));
    }
  }

  function call(method, ...args) {
    return ready.then(
      () =>
        new Promise((resolve, reject) => {
          const id = ++seq;
          pending.set(id, { resolve, reject });
          port.postMessage({ id, method, args });
        }),
    );
  }

  function action(kind, { id, label, onClick }) {
    if (typeof onClick !== 'function') throw new TypeError('onClick must be a function');
    actions[`${kind}:${id}`] = onClick;
    return call(`ui.add${kind === 'message' ? 'Message' : 'Composer'}Action`, { id: String(id), label: String(label) });
  }

  const api = {
    version: 2,
    /**
     * Resolves with `{ id, account, view, redirectUri, locale, dir, dark }` once the client has connected.
     * `view` is null in the main frame, and the view's id in a frame drawing one (see `ui.mount`).
     */
    ready,
    ui: Object.freeze({
      addMessageAction: (options) => action('message', options),
      addComposerAction: (options) => action('composer', options),
      addSidebarLink: ({ id, label, href }) => call('ui.addSidebarLink', { id: String(id), label: String(label), href: String(href) }),
      /** A button, link or badge in a slot; a button's `onClick` runs here, in the main frame. */
      addItem({ slot, id, kind = 'button', label, icon, href, onClick }) {
        if (kind === 'button') {
          if (typeof onClick !== 'function') throw new TypeError('onClick must be a function');
          actions[`item:${id}`] = onClick;
        }
        return call('ui.addItem', { slot, id: String(id), kind, label: String(label ?? ''), icon, href });
      },
      removeItem: (id) => call('ui.removeItem', { id: String(id) }),
      /** Shows a view of this plug-in in a slot: another frame, whose `ready` names the view. */
      mount: ({ slot, id, title, height }) => call('ui.mount', { slot, id: String(id), title: String(title ?? ''), height }),
      unmount: (id) => call('ui.unmount', { id: String(id) }),
      /** Opens one of this plug-in's pages (mounted in `app.navigation`). */
      navigate: (view) => call('ui.navigate', { view: String(view) }),
      openPanel: ({ title } = {}) => call('ui.openPanel', { title: String(title ?? '') }),
      closePanel: () => call('ui.closePanel'),
    }),
    /** Built-in features this plug-in hides or replaces (needs `ui:replace`). */
    features: Object.freeze({
      hide: (feature) => call('features.hide', String(feature)),
      show: (feature) => call('features.show', String(feature)),
      replace: (feature, { id, title, height } = {}) => call('features.replace', String(feature), { id: String(id), title: String(title ?? ''), height }),
    }),
    message: Object.freeze({
      getCurrent: () => call('message.getCurrent'),
      /** The open message's attachments: `[{ id, name, type, size }]` (needs `attachments:read`). */
      getAttachments: () => call('message.getAttachments'),
      /** One attachment of a message the plug-in was shown, as a `File`. */
      getAttachment: (id) => call('message.getAttachment', String(id)),
    }),
    /** The composer opened or focused last. */
    composer: Object.freeze({
      getSubject: () => call('composer.getSubject'),
      setSubject: (subject) => call('composer.setSubject', String(subject)),
      getRecipients: () => call('composer.getRecipients'),
      insertHtml: (html) => call('composer.insertHtml', String(html)),
      /** Attaches a `File` or `Blob` (with `name` and `type` for a blob). */
      addAttachment: (file, { name, type } = {}) => call('composer.addAttachment', { file, name, type }),
      /** Inserts a link at the cursor: `{ href, text }`. */
      insertLink: ({ href, text } = {}) => call('composer.insertLink', { href: String(href ?? ''), text: String(text ?? '') }),
    }),
    /**
     * Signs the user in at a provider (OAuth): opens `url` in a window once the user confirms,
     * and resolves with the query parameters the provider sent back (`code`, `state`, …).
     * `url` must carry a `state` of at least 16 random characters; send the provider
     * `context.redirectUri` as the redirect address. Needs `auth` and `network:<provider host>`.
     */
    auth: Object.freeze({ start: ({ url }) => call('auth.start', { url: String(url) }) }),
    storage: Object.freeze({
      get: (key) => call('storage.get', String(key)),
      set: (key, value) => call('storage.set', String(key), value),
    }),
    settings: Object.freeze({
      /** The signed-in user's settings for this plug-in. */
      get: () => call('settings.get'),
      /** The administrator's settings, without secrets (those reach only the server module). */
      getAdmin: () => call('settings.getAdmin'),
    }),
    /** This plug-in's own server routes (`/api/x/<id>/<path>`, needs `server:routes`). */
    server: Object.freeze({ call: (path, body) => call('server.call', String(path), body ?? null) }),
    notify: (text) => call('notify', String(text)),
    on(event, handler) {
      if (typeof handler !== 'function') throw new TypeError('handler must be a function');
      (listeners[event] ||= []).push(handler);
    },
  };
  Object.defineProperty(globalThis, 'unomail', { value: Object.freeze(api), enumerable: true });
})();
