// Plug-in API of the web client.
//
// A plug-in is a JavaScript module installed by the server's operator under
// `<data>/plugins/<id>/plugin.js`. Its default export receives the API below and uses it to
// add actions to the reader and the composer, links to the sidebar, and to react to events.
// Plug-ins run with the page's privileges, which is why only the operator can install them.

import { useSyncExternalStore } from 'react';
import { get } from './api';

import { t } from './i18n';
export const PLUGIN_API_VERSION = 1;

export interface PluginMessage {
  id: string;
  subject: string;
  from: { name: string | null; email: string }[];
  to: { name: string | null; email: string }[];
  receivedAt: string;
  /** Sanitized HTML of the message body. */
  html: string;
}

export interface ComposerHandle {
  getSubject(): string;
  setSubject(subject: string): void;
  getRecipients(): string;
  /** Inserts sanitized HTML at the cursor. */
  insertHtml(html: string): void;
}

export interface MessageAction {
  id: string;
  label: string;
  onClick: (message: PluginMessage) => void;
}

export interface ComposerAction {
  id: string;
  label: string;
  onClick: (composer: ComposerHandle) => void;
}

export interface SidebarLink {
  id: string;
  label: string;
  /** Opened in a new tab; must be an http(s) address. */
  href: string;
}

export interface PluginEvents {
  'message:open': PluginMessage;
  'message:sent': { subject: string; recipients: string };
}

export interface PluginApi {
  version: number;
  /** Address of the signed-in user. */
  account: string;
  addMessageAction(action: MessageAction): void;
  addComposerAction(action: ComposerAction): void;
  addSidebarLink(link: SidebarLink): void;
  on<K extends keyof PluginEvents>(event: K, handler: (payload: PluginEvents[K]) => void): void;
  /** Shows a short notice to the user. */
  notify(text: string): void;
  log(...args: unknown[]): void;
}

interface Registry {
  messageActions: MessageAction[];
  composerActions: ComposerAction[];
  sidebarLinks: SidebarLink[];
  loaded: string[];
}

let registry: Registry = { messageActions: [], composerActions: [], sidebarLinks: [], loaded: [] };
const handlers: { [K in keyof PluginEvents]?: ((payload: PluginEvents[K]) => void)[] } = {};
const listeners = new Set<() => void>();
let notifier: (text: string) => void = () => {};

function update(change: Partial<Registry>) {
  registry = { ...registry, ...change };
  listeners.forEach((listener) => listener());
}

export function setPluginNotifier(show: (text: string) => void) {
  notifier = show;
}

/** Tells plug-ins that something happened. A failing plug-in never breaks the client. */
export function emit<K extends keyof PluginEvents>(event: K, payload: PluginEvents[K]) {
  for (const handler of handlers[event] ?? []) {
    try {
      handler(payload);
    } catch (err) {
      console.error(`plug-in handler for ${event} failed`, err);
    }
  }
}

export function createPluginApi(id: string, account: string): PluginApi {
  const scoped = (name: string) => `${id}:${name}`;
  return {
    version: PLUGIN_API_VERSION,
    account,
    addMessageAction: (action) => update({ messageActions: [...registry.messageActions.filter((a) => a.id !== scoped(action.id)), { ...action, id: scoped(action.id) }] }),
    addComposerAction: (action) => update({ composerActions: [...registry.composerActions.filter((a) => a.id !== scoped(action.id)), { ...action, id: scoped(action.id) }] }),
    addSidebarLink: (link) => {
      // Links leave the application, so only real web addresses are accepted.
      if (!/^https?:\/\//i.test(link.href)) throw new Error(t('sidebar links must be http(s) addresses'));
      update({ sidebarLinks: [...registry.sidebarLinks.filter((l) => l.id !== scoped(link.id)), { ...link, id: scoped(link.id) }] });
    },
    on: (event, handler) => {
      (handlers[event] ??= [] as never[]).push(handler as never);
    },
    notify: (text) => notifier(String(text).slice(0, 300)),
    log: (...args) => console.info(`[plug-in ${id}]`, ...args),
  };
}

export function resetPlugins() {
  for (const key of Object.keys(handlers) as (keyof PluginEvents)[]) delete handlers[key];
  update({ messageActions: [], composerActions: [], sidebarLinks: [], loaded: [] });
}

let loading: Promise<void> | null = null;

/** Loads every enabled plug-in once per session (`known`: the list, if already fetched). */
export function loadPlugins(account: string, known?: { id: string; enabled: boolean }[]): Promise<void> {
  loading ??= (async () => {
    let plugins: { id: string; enabled: boolean }[] = known ?? [];
    if (!known) {
      try {
        plugins = await get('/api/plugins');
      } catch {
        return;
      }
    }
    for (const plugin of plugins.filter((p) => p.enabled)) {
      try {
        const module = await import(/* @vite-ignore */ `/api/plugins/${encodeURIComponent(plugin.id)}/plugin.js`);
        if (typeof module.default === 'function') {
          await module.default(createPluginApi(plugin.id, account));
          update({ loaded: [...registry.loaded, plugin.id] });
        }
      } catch (err) {
        console.error(`plug-in ${plugin.id} failed to load`, err);
      }
    }
  })();
  return loading;
}

export function unloadPlugins() {
  loading = null;
  resetPlugins();
}

/** The current registrations (for code outside React components). */
export function registrySnapshot(): Registry {
  return registry;
}

export function usePlugins(): Registry {
  return useSyncExternalStore(
    (listener) => {
      listeners.add(listener);
      return () => listeners.delete(listener);
    },
    () => registry,
  );
}
