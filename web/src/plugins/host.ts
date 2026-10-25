// Host side of sandboxed plug-ins (API 2).
//
// Each plug-in the user opted in to runs in its own `<iframe sandbox="allow-scripts">`, served
// by the server with an opaque origin: it cannot touch this page, the session or the API.
// Besides that main frame, a plug-in may show views (widgets, pages, settings and admin
// sections): more frames of the same document, told which view to draw. Every frame talks to
// us over its own private MessageChannel; every request is checked here against the
// permissions the manifest declared, rate limited and size limited before anything happens.
// Only the main frame may change the interface.

import { useSyncExternalStore } from 'react';
import { get, post, put } from '../lib/api';
import { type ComposerHandle, type Feature, type Mount, type PluginMessage, REMOVABLE_FEATURES, registerHost, registrySnapshot, type Slot, SLOTS, type SlotItem, updateRegistry } from '../lib/plugins';

import { t } from '../i18n';

export interface PackageInfo {
  id: string;
  commit: string;
  name: string;
  permissions: string[];
  /** Started for an administrator's admin pages only, without the user's opt-in. */
  adminOnly?: boolean;
}

export interface FrameState {
  id: string;
  commit: string;
  name: string;
  panel: { open: boolean; title: string };
}

interface Running {
  info: PackageInfo;
  permissions: Set<string>;
  /** The view this frame draws; `null` for the main frame. */
  view: string | null;
  port: MessagePort | null;
  /** Times of recent calls, for the rate limit. */
  calls: number[];
  lastPong: number;
  ping: number;
}

const MAX_CALLS_PER_SECOND = 50;
const MAX_PAYLOAD = 256 * 1024;
const HEARTBEAT_MS = 5000;
const UNRESPONSIVE_MS = 15000;
const MAX_ITEMS = 20;
const MAX_MOUNTS = 10;
/** Files a plug-in may read from a message or attach to one. */
const MAX_FILE_BYTES = 100 * 1024 * 1024;
const AUTH_TIMEOUT_MS = 10 * 60 * 1000;

/** Icons plug-ins may give their items (Material icon names). */
export const ITEM_ICONS = ['extension', 'star', 'bolt', 'translate', 'note', 'link', 'label', 'info', 'chart', 'calendar', 'task', 'cloud'] as const;

/** Which permission a slot needs for a mounted frame. */
const MOUNT_PERMISSION: Record<Slot, string> = {
  'mail.toolbar': 'ui:widget',
  'mail.sidebar': 'ui:widget',
  'reader.header': 'ui:widget',
  'reader.footer': 'ui:widget',
  'composer.toolbar': 'ui:widget',
  'app.navigation': 'ui:page',
  'settings.section': 'ui:page',
  'admin.section': 'ui:admin',
};

let frames: FrameState[] = [];
const packages = new Map<string, PackageInfo>();
/** Frames by key: the plug-in's id for its main frame, `<id>#<view>` for a view. */
const running = new Map<string, Running>();
const listeners = new Set<() => void>();
let account = '';
let currentMessage: PluginMessage | null = null;
let currentComposer: ComposerHandle | null = null;
let notifier: (text: string) => void = () => {};
let heartbeat: ReturnType<typeof setInterval> | null = null;

const frameKey = (id: string, view: string | null) => (view ? `${id}#${view}` : id);

function changed(next: FrameState[]) {
  frames = next;
  listeners.forEach((listener) => listener());
}

function setPanel(id: string, panel: FrameState['panel']) {
  changed(frames.map((frame) => (frame.id === id ? { ...frame, panel } : frame)));
}

export function setPanelClosed(id: string) {
  setPanel(id, { open: false, title: '' });
  const plugin = running.get(id);
  if (plugin) send(plugin, { event: 'panel:close', payload: null });
}

export function setHostNotifier(show: (text: string) => void) {
  notifier = show;
}

/** The main frames to render; see `PluginFrames`. */
export function useFrames(): FrameState[] {
  return useSyncExternalStore(
    (listener) => {
      listeners.add(listener);
      return () => listeners.delete(listener);
    },
    () => frames,
  );
}

class Refused extends Error {}

/** What a call needs, by method. Methods missing here do not exist. */
const METHODS: Record<string, string | null> = {
  'ui.addMessageAction': null,
  'ui.addComposerAction': null,
  'ui.addSidebarLink': 'sidebar',
  'ui.addItem': null,
  'ui.removeItem': null,
  'ui.mount': null,
  'ui.unmount': null,
  'ui.openPanel': 'panel',
  'ui.closePanel': 'panel',
  'ui.navigate': null,
  'features.hide': 'ui:replace',
  'features.show': 'ui:replace',
  'features.replace': 'ui:replace',
  'message.getCurrent': 'message:read',
  'message.getAttachments': 'attachments:read',
  'message.getAttachment': 'attachments:read',
  'composer.addAttachment': 'composer:write',
  'composer.insertLink': 'composer:write',
  'auth.start': 'auth',
  'composer.getSubject': 'composer:read',
  'composer.getRecipients': 'composer:read',
  'composer.setSubject': 'composer:write',
  'composer.insertHtml': 'composer:write',
  'storage.get': 'storage',
  'storage.set': 'storage',
  'settings.get': null,
  'settings.getAdmin': null,
  'server.call': 'server:routes',
  notify: 'notify',
};

/** Calls that change the interface; views may not make them. */
const MAIN_ONLY = new Set(['ui.addMessageAction', 'ui.addComposerAction', 'ui.addSidebarLink', 'ui.addItem', 'ui.removeItem', 'ui.mount', 'ui.unmount', 'features.hide', 'features.show', 'features.replace']);

const text = (value: unknown, max: number) => String(value ?? '').slice(0, max);
const scoped = (id: string, name: unknown) => `${id}:${text(name, 60)}`;
const localId = (value: unknown) => {
  const id = text(value, 40);
  if (!/^[a-z0-9-]{1,40}$/.test(id)) throw new Refused(t('ids may contain lowercase letters, digits and -'));
  return id;
};

/** Download addresses of the attachments plug-ins were shown, by attachment id. */
const attachmentUrls = new Map<string, { url: string; name: string; type: string }>();

/** A message as plug-ins receive it: the attachments' addresses stay here. */
function forPlugin(message: PluginMessage): PluginMessage {
  for (const file of message.attachments ?? []) {
    if (file.url) attachmentUrls.set(file.id, { url: file.url, name: file.name, type: file.type });
  }
  while (attachmentUrls.size > 1000) attachmentUrls.delete(attachmentUrls.keys().next().value!);
  return { ...message, attachments: (message.attachments ?? []).map(({ id, name, type, size }) => ({ id, name, type, size })) };
}

const escapeHtml = (value: string) => value.replace(/[&<>"']/g, (c) => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' })[c]!);

function composer(): ComposerHandle {
  if (!currentComposer) throw new Refused(t('no message is being written'));
  return currentComposer;
}

function slotOf(value: unknown): Slot {
  if (!SLOTS.includes(value as Slot)) throw new Refused(t('unknown slot'));
  return value as Slot;
}

function featureOf(value: unknown): Feature {
  if (!REMOVABLE_FEATURES.includes(value as Feature)) throw new Refused(t('this feature cannot be removed'));
  return value as Feature;
}

function mount(plugin: Running, options: Record<string, unknown>, slot: Slot | `replace:${Feature}`) {
  const id = plugin.info.id;
  const permission = slot.startsWith('replace:') ? 'ui:replace' : MOUNT_PERMISSION[slot as Slot];
  if (!plugin.permissions.has(permission)) throw new Refused(t('the plug-in did not ask for the {{permission}} permission', { permission }));
  const view = localId(options.id);
  const registry = registrySnapshot();
  const others = registry.mounts.filter((m) => !(m.plugin === id && m.id === view));
  if (others.filter((m) => m.plugin === id).length >= MAX_MOUNTS) throw new Refused(t('too many views'));
  const height = Math.min(Math.max(Number(options.height) || 120, 32), 1200);
  const entry: Mount = { id: view, plugin: id, pluginName: plugin.info.name, commit: plugin.info.commit, slot: slot as Slot, title: text(options.title, 60) || plugin.info.name, height };
  updateRegistry({ mounts: [...others, entry] });
}

function setHidden(plugin: Running, feature: Feature, hidden: boolean) {
  const registry = registrySnapshot();
  const by = (registry.hidden[feature] ?? []).filter((p) => p !== plugin.info.id);
  updateRegistry({ hidden: { ...registry.hidden, [feature]: hidden ? [...by, plugin.info.id] : by } });
}

async function dispatch(plugin: Running, method: string, args: unknown[]): Promise<unknown> {
  const id = plugin.info.id;
  const enc = encodeURIComponent(id);
  const [first, second] = args;
  const options = (first && typeof first === 'object' ? first : {}) as Record<string, unknown>;
  // Clicks always go to the main frame, which registered them.
  const main = () => running.get(id) ?? (plugin.view === null ? plugin : undefined);
  switch (method) {
    case 'ui.addMessageAction':
    case 'ui.addComposerAction': {
      const kind = method === 'ui.addMessageAction' ? 'message' : 'composer';
      const actionId = text(options.id, 60);
      const action = { id: scoped(id, actionId), label: text(options.label, 40) || plugin.info.name };
      const registry = registrySnapshot();
      if (kind === 'message') {
        const onClick = (message: PluginMessage) => {
          const shown = forPlugin(message);
          const payload = plugin.permissions.has('message:read') ? shown : plugin.permissions.has('attachments:read') ? { id: shown.id, attachments: shown.attachments } : { id: shown.id };
          send(main(), { action: `message:${actionId}`, payload });
        };
        updateRegistry({ messageActions: [...registry.messageActions.filter((a) => a.id !== action.id), { ...action, onClick }] });
      } else {
        const onClick = (handle: ComposerHandle) => {
          currentComposer = handle;
          send(main(), { action: `composer:${actionId}`, payload: null });
        };
        updateRegistry({ composerActions: [...registry.composerActions.filter((a) => a.id !== action.id), { ...action, onClick }] });
      }
      return null;
    }
    case 'ui.addSidebarLink': {
      const href = text(options.href, 2000);
      // Links leave the application, so only real web addresses are accepted.
      if (!/^https?:\/\//i.test(href)) throw new Refused(t('sidebar links must be http(s) addresses'));
      const link = { id: scoped(id, options.id), label: text(options.label, 40), href };
      const registry = registrySnapshot();
      updateRegistry({ sidebarLinks: [...registry.sidebarLinks.filter((l) => l.id !== link.id), link] });
      return null;
    }
    case 'ui.addItem': {
      const slot = slotOf(options.slot);
      if (slot === 'app.navigation' || slot === 'settings.section' || slot === 'admin.section') throw new Refused(t('this slot shows views; use ui.mount'));
      const itemId = localId(options.id);
      const kind = options.kind === 'link' || options.kind === 'badge' ? options.kind : 'button';
      const item: SlotItem = { id: scoped(id, itemId), plugin: id, slot, kind, label: text(options.label, 40) || plugin.info.name };
      if (ITEM_ICONS.includes(options.icon as (typeof ITEM_ICONS)[number])) item.icon = options.icon as string;
      if (kind === 'link') {
        const href = text(options.href, 2000);
        if (!plugin.permissions.has('sidebar')) throw new Refused(t('the plug-in did not ask for the {{permission}} permission', { permission: 'sidebar' }));
        if (!/^https?:\/\//i.test(href)) throw new Refused(t('sidebar links must be http(s) addresses'));
        item.href = href;
      } else if (kind === 'button') {
        item.onClick = () => send(main(), { action: `item:${itemId}`, payload: null });
      }
      const registry = registrySnapshot();
      const others = registry.items.filter((i) => i.id !== item.id);
      if (others.filter((i) => i.plugin === id).length >= MAX_ITEMS) throw new Refused(t('too many items'));
      updateRegistry({ items: [...others, item] });
      return null;
    }
    case 'ui.removeItem': {
      const registry = registrySnapshot();
      updateRegistry({ items: registry.items.filter((i) => i.id !== scoped(id, options.id ?? first)) });
      return null;
    }
    case 'ui.mount':
      mount(plugin, options, slotOf(options.slot));
      return null;
    case 'ui.unmount': {
      const registry = registrySnapshot();
      const view = text(options.id ?? first, 40);
      updateRegistry({ mounts: registry.mounts.filter((m) => !(m.plugin === id && m.id === view)) });
      return null;
    }
    case 'ui.navigate': {
      // Only to this plug-in's own pages.
      const view = localId(options.view ?? first);
      if (!registrySnapshot().mounts.some((m) => m.plugin === id && m.id === view && m.slot === 'app.navigation')) throw new Refused(t('unknown view'));
      navigator(`/x/${enc}/${view}`);
      return null;
    }
    case 'features.hide':
      setHidden(plugin, featureOf(first), true);
      return null;
    case 'features.show':
      setHidden(plugin, featureOf(first), false);
      return null;
    case 'features.replace': {
      const feature = featureOf(first);
      mount(plugin, (second && typeof second === 'object' ? second : {}) as Record<string, unknown>, `replace:${feature}`);
      setHidden(plugin, feature, true);
      return null;
    }
    case 'ui.openPanel':
      setPanel(id, { open: true, title: text(options.title, 60) || plugin.info.name });
      return null;
    case 'ui.closePanel':
      setPanel(id, { open: false, title: '' });
      return null;
    case 'message.getCurrent':
      return currentMessage && forPlugin(currentMessage);
    case 'message.getAttachments':
      return currentMessage ? forPlugin(currentMessage).attachments : [];
    case 'message.getAttachment': {
      // Read by the client with the user's session; the plug-in gets the file, never the address.
      const file = attachmentUrls.get(text(first, 200));
      if (!file) throw new Refused(t('unknown attachment'));
      const response = await fetch(file.url, { credentials: 'same-origin' });
      if (!response.ok) throw new Refused(t('the attachment could not be read'));
      const blob = await response.blob();
      if (blob.size > MAX_FILE_BYTES) throw new Refused(t('the file is too large'));
      return new File([blob], file.name, { type: file.type || blob.type });
    }
    case 'composer.addAttachment': {
      const { file, name, type } = options as { file?: unknown; name?: unknown; type?: unknown };
      const data = file ?? first;
      if (!(data instanceof Blob)) throw new Refused(t('attachments must be files or blobs'));
      if (data.size > MAX_FILE_BYTES) throw new Refused(t('the file is too large'));
      const fileName = text(name ?? (data instanceof File ? data.name : ''), 200).replace(/[\\/\u0000-\u001f]/g, '_') || 'attachment';
      await composer().addFiles([new File([data], fileName, { type: text(type, 200) || data.type || 'application/octet-stream' })]);
      return null;
    }
    case 'composer.insertLink': {
      const href = text(options.href, 2000);
      if (!/^https?:\/\//i.test(href)) throw new Refused(t('links must be http(s) addresses'));
      const label = text(options.text, 500) || href;
      composer().insertHtml(`<a href="${escapeHtml(href)}">${escapeHtml(label)}</a>`);
      return null;
    }
    case 'auth.start':
      return startAuth(plugin, text(options.url, 4000));
    case 'composer.getSubject':
      return composer().getSubject();
    case 'composer.getRecipients':
      return composer().getRecipients();
    case 'composer.setSubject':
      composer().setSubject(text(first, 500));
      return null;
    case 'composer.insertHtml':
      // The composer sanitizes what it inserts, like everything else pasted into it.
      composer().insertHtml(text(first, MAX_PAYLOAD));
      return null;
    case 'storage.get':
      return (await get<Record<string, unknown>>(`/api/me/packages/${enc}/storage`))[text(first, 100)] ?? null;
    case 'storage.set':
      await put(`/api/me/packages/${enc}/storage`, { key: text(first, 100), value: second ?? null });
      return null;
    case 'settings.get':
      return get(`/api/me/packages/${enc}/settings`);
    case 'settings.getAdmin':
      return get(`/api/me/packages/${enc}/admin-settings`);
    case 'server.call': {
      // The plug-in's own server routes; the path cannot leave them.
      const path = text(first, 200).replace(/^\/+/, '');
      if (!/^[A-Za-z0-9._~\-/]*$/.test(path) || path.split('/').includes('..')) throw new Refused(t('invalid path'));
      return post(`/api/x/${enc}/${path}`, second ?? null);
    }
    case 'notify':
      notifier(`${plugin.info.name}: ${text(first, 300)}`);
      return null;
    default:
      throw new Refused(t('unknown method'));
  }
}

let navigator: (to: string) => void = (to) => window.location.assign(to);

/** Lets plug-ins open their own pages through the router. */
export function setHostNavigator(navigate: (to: string) => void) {
  navigator = navigate;
}

// --- Sign-in windows (OAuth) ----------------------------------------------------------------

export interface AuthRequest {
  plugin: string;
  pluginName: string;
  host: string;
  url: string;
  state: string;
}

let authRequest: AuthRequest | null = null;
const authListeners = new Set<() => void>();
const pendingAuth = new Map<string, { resolve: (value: unknown) => void; reject: (error: Error) => void; timer: ReturnType<typeof setTimeout> }>();
let authChannel: BroadcastChannel | null = null;

function setAuthRequest(next: AuthRequest | null) {
  authRequest = next;
  authListeners.forEach((listener) => listener());
}

/** The sign-in the user is asked to confirm; see `PluginFrames`. */
export function useAuthRequest(): AuthRequest | null {
  return useSyncExternalStore(
    (listener) => {
      authListeners.add(listener);
      return () => authListeners.delete(listener);
    },
    () => authRequest,
  );
}

/** Where providers send sign-in windows back to; give it to the provider as the redirect URI. */
export const AUTH_REDIRECT = '/plugin-auth/callback';

/**
 * A plug-in asks to sign the user in somewhere. The user confirms in a dialog (so the window
 * opens from their click and they see where it goes); the provider sends the window back to
 * our callback page, which reports the answer, matched to the plug-in by its `state`.
 */
function startAuth(plugin: Running, address: string): Promise<unknown> {
  let url: URL;
  try {
    url = new URL(address);
  } catch {
    throw new Refused(t('invalid address'));
  }
  if (url.protocol !== 'https:' || !plugin.permissions.has(`network:${url.hostname}`)) throw new Refused(t('the plug-in did not ask for the {{permission}} permission', { permission: `network:${url.hostname}` }));
  const state = url.searchParams.get('state') ?? '';
  if (state.length < 16 || state.length > 200) throw new Refused(t('the address needs a state of at least 16 characters'));
  if (authRequest || pendingAuth.has(state)) throw new Refused(t('another sign-in is in progress'));
  authChannel ??= new BroadcastChannel('unomail-plugin-auth');
  authChannel.onmessage = ({ data }) => {
    const params = Object.fromEntries(new URLSearchParams(String(data?.search ?? '')));
    const waiting = pendingAuth.get(params.state ?? '');
    if (!waiting) return;
    clearTimeout(waiting.timer);
    pendingAuth.delete(params.state);
    waiting.resolve(params);
  };
  return new Promise((resolve, reject) => {
    const timer = setTimeout(() => {
      pendingAuth.delete(state);
      if (authRequest?.state === state) setAuthRequest(null);
      reject(new Refused(t('the sign-in timed out')));
    }, AUTH_TIMEOUT_MS);
    pendingAuth.set(state, { resolve, reject, timer });
    setAuthRequest({ plugin: plugin.info.id, pluginName: plugin.info.name, host: url.hostname, url: url.toString(), state });
  });
}

/** The user's answer to the sign-in dialog. Opening happens in their click. */
export function answerAuth(open: boolean) {
  const request = authRequest;
  if (!request) return;
  setAuthRequest(null);
  if (open) {
    window.open(request.url, '_blank', 'popup,width=520,height=720');
    return;
  }
  const waiting = pendingAuth.get(request.state);
  if (waiting) {
    clearTimeout(waiting.timer);
    pendingAuth.delete(request.state);
    waiting.reject(new Refused(t('the sign-in was cancelled')));
  }
}

function send(plugin: Running | undefined, data: unknown) {
  try {
    plugin?.port?.postMessage(data);
  } catch (err) {
    console.error(`plug-in ${plugin?.info.id}: message not delivered`, err);
  }
}

function size(value: unknown): number {
  try {
    return JSON.stringify(value ?? null).length;
  } catch {
    return Infinity;
  }
}

/** Handles one request from a plug-in frame. Exported for tests. */
export async function handleCall(plugin: Running, data: unknown): Promise<{ reply: number; result?: unknown; error?: string } | null> {
  if (!data || typeof data !== 'object') return null;
  const { id, method, args } = data as { id?: unknown; method?: unknown; args?: unknown };
  if (typeof id !== 'number') {
    if (typeof (data as { pong?: unknown }).pong === 'number') plugin.lastPong = Date.now();
    return null;
  }
  const fail = (error: string) => ({ reply: id, error });
  const now = Date.now();
  plugin.calls = plugin.calls.filter((at) => now - at < 1000);
  if (plugin.calls.length >= MAX_CALLS_PER_SECOND) return fail(t('too many requests'));
  plugin.calls.push(now);
  if (typeof method !== 'string' || !Object.hasOwn(METHODS, method)) return fail(t('unknown method'));
  const needs = METHODS[method];
  if (needs && !plugin.permissions.has(needs)) return fail(t('the plug-in did not ask for the {{permission}} permission', { permission: needs }));
  if (plugin.view !== null && MAIN_ONLY.has(method)) return fail(t('views cannot change the interface'));
  // Started only for an administrator's admin pages: it may add those and nothing else.
  const adminSection = method === 'ui.mount' && (args as { slot?: unknown }[] | undefined)?.[0]?.slot === 'admin.section';
  if (plugin.info.adminOnly && MAIN_ONLY.has(method) && !adminSection && method !== 'ui.unmount') return fail(t('the user has not turned this plug-in on'));
  if (!Array.isArray(args) || size(args) > MAX_PAYLOAD) return fail(t('the request is too large'));
  try {
    const result = await dispatch(plugin, method, args);
    return { reply: id, result };
  } catch (err) {
    if (err instanceof Refused) return fail(err.message);
    console.error(`plug-in ${plugin.info.id}: ${method} failed`, err);
    return fail(t('the request failed'));
  }
}

export function createRunning(info: PackageInfo, view: string | null = null): Running {
  return { info, permissions: new Set(info.permissions), view, port: null, calls: [], lastPong: Date.now(), ping: 0 };
}

/** Called when a plug-in frame has loaded: hands it its end of a private channel. */
export function connectFrame(id: string, frame: HTMLIFrameElement, context: { locale: string; dir: string; dark: boolean }, view: string | null = null) {
  const info = packages.get(id);
  if (!info || !frame.contentWindow) return;
  const key = frameKey(id, view);
  const plugin = running.get(key) ?? createRunning(info, view);
  running.set(key, plugin);
  plugin.port?.close();
  const channel = new MessageChannel();
  plugin.port = channel.port1;
  plugin.lastPong = Date.now();
  channel.port1.onmessage = ({ data }) => {
    void handleCall(plugin, data).then((reply) => reply && send(plugin, reply));
  };
  // The frame's origin is opaque, so it cannot be named as the target; the port is the trust.
  const redirectUri = `${window.location.origin}${AUTH_REDIRECT}`;
  frame.contentWindow.postMessage({ type: 'unomail:connect', context: { id, account, view, redirectUri, ...context } }, '*', [channel.port2]);
}

/** A view's frame went away (its slot is no longer shown). */
export function disconnectView(id: string, view: string) {
  const key = frameKey(id, view);
  running.get(key)?.port?.close();
  running.delete(key);
}

/** Stops a plug-in: its frames, its registrations and its channels. */
export function stopPlugin(id: string, reason?: string) {
  const info = packages.get(id);
  if (!info) return;
  for (const [key, plugin] of running) {
    if (plugin.info.id !== id) continue;
    plugin.port?.close();
    running.delete(key);
  }
  packages.delete(id);
  const registry = registrySnapshot();
  const mine = (item: { id: string }) => !item.id.startsWith(`${id}:`);
  const hidden = Object.fromEntries(Object.entries(registry.hidden).map(([feature, by]) => [feature, (by ?? []).filter((p) => p !== id)]));
  updateRegistry({
    messageActions: registry.messageActions.filter(mine),
    composerActions: registry.composerActions.filter(mine),
    sidebarLinks: registry.sidebarLinks.filter(mine),
    items: registry.items.filter((i) => i.plugin !== id),
    mounts: registry.mounts.filter((m) => m.plugin !== id),
    hidden,
  });
  changed(frames.filter((frame) => frame.id !== id));
  if (reason) notifier(reason);
}

function checkHeartbeats() {
  const now = Date.now();
  for (const plugin of running.values()) {
    if (!plugin.port) continue;
    if (now - plugin.lastPong > UNRESPONSIVE_MS) {
      stopPlugin(plugin.info.id, t('{{name}} stopped responding and was turned off', { name: plugin.info.name }));
      continue;
    }
    send(plugin, { ping: ++plugin.ping });
  }
}

/** Events are passed on to every frame; those carrying mail content need `message:read`. */
function forward(event: string, payload: unknown) {
  if (event === 'message:open') currentMessage = payload as PluginMessage;
  const content = event === 'message:open' || event === 'message:sent';
  const shown = event === 'message:open' ? forPlugin(payload as PluginMessage) : payload;
  for (const plugin of running.values()) {
    if (content && !plugin.permissions.has('message:read')) continue;
    send(plugin, { event, payload: shown });
  }
}

/** Starts the sandboxed plug-ins the user opted in to. */
export async function startPackages(email: string, known?: PackageInfo[]) {
  account = email;
  let list = known;
  if (!list) {
    try {
      const startup = await get<{ packages?: PackageInfo[] }>('/api/me/startup');
      list = startup.packages ?? [];
    } catch {
      return;
    }
  }
  registerHost(forward);
  const added = list.filter((info) => !packages.has(info.id));
  for (const info of added) packages.set(info.id, info);
  changed([...frames, ...added.map((info) => ({ id: info.id, commit: info.commit, name: info.name, panel: { open: false, title: '' } }))]);
  heartbeat ??= setInterval(checkHeartbeats, HEARTBEAT_MS);
}

export function stopPackages() {
  for (const id of [...packages.keys()]) stopPlugin(id);
  if (heartbeat) clearInterval(heartbeat);
  heartbeat = null;
  currentMessage = null;
  currentComposer = null;
  attachmentUrls.clear();
  for (const waiting of pendingAuth.values()) clearTimeout(waiting.timer);
  pendingAuth.clear();
  setAuthRequest(null);
  changed([]);
}

/** Tells a running plug-in's frames that its settings changed. */
export function settingsChanged(id: string) {
  for (const plugin of running.values()) {
    if (plugin.info.id === id) send(plugin, { event: 'settings:change', payload: null });
  }
}

/** The composer plug-ins act on: the one opened or focused last. */
export function composerOpened(handle: ComposerHandle) {
  currentComposer = handle;
}

/** Forgets the composer once it closes, so plug-ins cannot write into a stale one. */
export function composerClosed(handle: ComposerHandle) {
  if (currentComposer === handle) currentComposer = null;
}

/** For tests: registers a package as started. */
export function registerPackage(info: PackageInfo) {
  packages.set(info.id, info);
}
