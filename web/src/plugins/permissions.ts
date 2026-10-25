// What each permission of a plug-in means, in words administrators and users can judge.

import { t } from '../i18n';

export function describePermission(permission: string): string {
  const host = permission.startsWith('network:') ? permission.slice('network:'.length) : null;
  if (host) return t('Send data to {{host}}', { host });
  if (permission.startsWith('host:')) return t('Send data to the server you enter as “{{setting}}”', { setting: permission.slice('host:'.length) });
  switch (permission) {
    case 'message:read':
      return t('Read the message you open, including its content');
    case 'composer:read':
      return t('Read the subject and recipients of the message you write');
    case 'composer:write':
      return t('Change the message you write');
    case 'sidebar':
      return t('Add links to the sidebar');
    case 'panel':
      return t('Show its own panel');
    case 'storage':
      return t('Keep its own data with your account');
    case 'notify':
      return t('Show notices');
    case 'attachments:read':
      return t('Read the attachments of the message you open');
    case 'auth':
      return t('Ask you to sign in to another service');
    case 'ui:widget':
      return t('Add views to the mail, the reader and the composer');
    case 'ui:page':
      return t('Add its own pages and settings');
    case 'ui:admin':
      return t('Add pages to the administration');
    case 'ui:replace':
      return t('Hide or replace built-in features');
    case 'server:mail-incoming':
      return t('Reject, hold or change incoming mail on the server');
    case 'server:mail-outgoing':
      return t('Reject, hold or change mail users send');
    case 'server:mail-body':
      return t('Read the full content of that mail');
    case 'server:routes':
      return t('Answer requests at its own server address');
    case 'server:storage':
      return t('Keep its own data on the server');
    default:
      return permission;
  }
}

/** What the manifest lets the plug-in do, including connecting to servers an administrator enters. */
export function declaredPermissions(manifest: PackageManifest): string[] {
  const hostSettings = (manifest.settings ?? []).filter((s) => s.type === 'host').map((s) => `host:${s.label}`);
  return [...(manifest.permissions ?? []), ...hostSettings];
}

/** Permissions that let a plug-in see mail or send data elsewhere. */
export function isSensitive(permission: string): boolean {
  return permission === 'message:read' || permission === 'attachments:read' || permission === 'composer:read' || permission === 'ui:replace' || permission.startsWith('network:') || permission.startsWith('host:') || permission.startsWith('server:mail');
}

export interface PackageManifest {
  id: string;
  type: 'plugin' | 'theme';
  name: string;
  version: string;
  description?: string;
  author?: string;
  homepage?: string;
  license?: string;
  permissions?: string[];
  settings?: { key: string; type: 'string' | 'boolean' | 'select' | 'host'; label: string; secret?: boolean; options?: string[]; default?: string | boolean; scope?: 'user' | 'admin' }[];
  entry?: string;
  server?: { module: string; hooks: string[]; routes: boolean; schedule: { id: string; everyMinutes: number }[] };
  theme?: Record<string, unknown>;
}
