// Plug-in registry of the web client: what the sandboxed plug-ins (`../plugins/host`) added
// to the interface, and which built-in features they hid. The reader, the composer, the
// sidebar and the other slots read it; nothing here runs plug-in code.

import { useSyncExternalStore } from 'react';

export interface PluginMessage {
  id: string;
  subject: string;
  from: { name: string | null; email: string }[];
  to: { name: string | null; email: string }[];
  receivedAt: string;
  /** Sanitized HTML of the message body. */
  html: string;
  /** Files attached to the message (inline images excluded). `url` stays with the client. */
  attachments: { id: string; name: string; type: string; size: number; url?: string }[];
}

export interface ComposerHandle {
  getSubject(): string;
  setSubject(subject: string): void;
  getRecipients(): string;
  /** Inserts sanitized HTML at the cursor. */
  insertHtml(html: string): void;
  /** Attaches files, uploaded like ones the user picked. */
  addFiles(files: File[]): Promise<void>;
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

/** Places in the layout plug-ins can add to. */
export const SLOTS = ['mail.toolbar', 'mail.sidebar', 'reader.header', 'reader.footer', 'composer.toolbar', 'app.navigation', 'settings.section', 'admin.section'] as const;
export type Slot = (typeof SLOTS)[number];

/** A button, link or badge a plug-in placed in a slot. */
export interface SlotItem {
  id: string;
  plugin: string;
  slot: Slot;
  kind: 'button' | 'link' | 'badge';
  label: string;
  icon?: string;
  href?: string;
  onClick?: () => void;
}

/** A plug-in's own frame shown in a slot (a widget, a page, a settings or admin section). */
export interface Mount {
  id: string;
  plugin: string;
  pluginName: string;
  commit: string;
  /** A slot, or `replace:<feature>` for a view that takes a hidden feature's place. */
  slot: Slot | `replace:${Feature}`;
  title: string;
  height: number;
}

/** Built-in features plug-ins may hide or replace (with `ui:replace`). */
export const REMOVABLE_FEATURES = ['calendar', 'contacts', 'smart-reply', 'summary-cards', 'masked-email', 'templates', 'composer.emoji', 'composer.schedule'] as const;
export type Feature = (typeof REMOVABLE_FEATURES)[number];

export interface PluginEvents {
  'message:open': PluginMessage;
  'message:sent': { subject: string; recipients: string };
}

interface Registry {
  messageActions: MessageAction[];
  composerActions: ComposerAction[];
  sidebarLinks: SidebarLink[];
  items: SlotItem[];
  mounts: Mount[];
  /** Hidden features, with the plug-ins that hid them. */
  hidden: Partial<Record<Feature, string[]>>;
}

const EMPTY: Registry = { messageActions: [], composerActions: [], sidebarLinks: [], items: [], mounts: [], hidden: {} };
let registry: Registry = EMPTY;
const listeners = new Set<() => void>();

/** Changes the registry (for the sandbox host). */
export function updateRegistry(change: Partial<Registry>) {
  registry = { ...registry, ...change };
  listeners.forEach((listener) => listener());
}

let host: (event: string, payload: unknown) => void = () => {};

/** Lets the sandbox host receive every event. */
export function registerHost(forward: (event: string, payload: unknown) => void) {
  host = forward;
}

/** Tells plug-ins that something happened. */
export function emit<K extends keyof PluginEvents>(event: K, payload: PluginEvents[K]) {
  host(event, payload);
}

export function resetPlugins() {
  host = () => {};
  updateRegistry(EMPTY);
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

/** Whether a built-in feature is shown (no plug-in hid it). */
export function useFeature(feature: Feature): boolean {
  return !usePlugins().hidden[feature]?.length;
}
