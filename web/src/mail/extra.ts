// Web mail data beyond the mailbox itself: sender identities, response templates, recipient
// suggestions, folder import/export and sharing.

import { del, get, post, postRaw, put } from '../api';

import { t } from '../i18n';
export interface IdentitySmtp {
  host: string;
  port: number;
  security: 'tls' | 'starttls' | 'none';
  username: string;
  has_password: boolean;
}

export interface Identity {
  masked?: boolean;
  available?: boolean;
  /** 0 for the account's own address before it was first saved. */
  id: number;
  name: string;
  email: string;
  reply_to: string;
  signature_html: string;
  is_default: boolean;
  smtp: IdentitySmtp | null;
}

export interface IdentityInput {
  name: string;
  email: string;
  reply_to: string;
  is_default: boolean;
  smtp: { host: string; port: number; security: string; username: string; password?: string } | null;
}

export const listIdentities = () => get<Identity[]>('/api/me/identities');
export const saveIdentity = (id: number, input: IdentityInput) => (id ? put<Identity>(`/api/me/identities/${id}`, input) : post<Identity>('/api/me/identities', input));
export const deleteIdentity = (id: number) => del(`/api/me/identities/${id}`);

export interface Signature {
  id: number;
  name: string;
  html: string;
}
/** The signatures a sender address uses; `null` for none. */
export interface SignatureChoice {
  new_signature_id: number | null;
  reply_signature_id: number | null;
}
export interface Signatures {
  signatures: Signature[];
  /** By identity address. */
  defaults: Record<string, SignatureChoice>;
}

export const listSignatures = () => get<Signatures>('/api/me/signatures');
export const saveSignature = (id: number, input: { name: string; html: string }) => (id ? put<Signature>(`/api/me/signatures/${id}`, input) : post<Signature>('/api/me/signatures', input));
export const deleteSignature = (id: number) => del(`/api/me/signatures/${id}`);
export const chooseSignatures = (email: string, choice: SignatureChoice) => put<SignatureChoice>('/api/me/signatures/defaults', { email, ...choice });

export interface Template {
  id: number;
  name: string;
  subject: string;
  html: string;
}

export const listTemplates = () => get<Template[]>('/api/me/templates');
export const saveTemplate = (id: number, input: Omit<Template, 'id'>) => (id ? put<Template>(`/api/me/templates/${id}`, input) : post<Template>('/api/me/templates', input));
export const deleteTemplate = (id: number) => del(`/api/me/templates/${id}`);

export interface Contact {
  id: number;
  name: string;
  email: string;
  phone: string;
  organization: string;
  notes: string;
  pgp_key: string;
}

export interface ContactGroup {
  id: number;
  name: string;
  members: number;
}

export type Suggestion =
  | { source: 'contact' | 'directory' | 'ldap'; name: string; email: string }
  | { source: 'group'; name: string; members: { name: string; email: string }[] };

export const suggestRecipients = (query: string) => get<Suggestion[]>(`/api/me/contacts/suggest?q=${encodeURIComponent(query)}`);

/** The text a suggestion contributes to a recipient field. */
export function suggestionText(suggestion: Suggestion): string {
  const one = (name: string, email: string) => (name ? `${name.replace(/[<>,;"]/g, ' ').trim()} <${email}>` : email);
  return suggestion.source === 'group' ? suggestion.members.map((m) => one(m.name, m.email)).join(', ') : one(suggestion.name, suggestion.email);
}

/** Splits a recipient field into what was already entered and the entry being typed. */
export function splitRecipients(value: string): { done: string; current: string } {
  const cut = Math.max(value.lastIndexOf(','), value.lastIndexOf(';'));
  return { done: value.slice(0, cut + 1), current: value.slice(cut + 1).trimStart() };
}

/** Replaces the entry being typed with a chosen suggestion, ready for the next one. */
export function applySuggestion(value: string, suggestion: Suggestion): string {
  const { done } = splitRecipients(value);
  return `${done}${done && !done.endsWith(' ') ? ' ' : ''}${suggestionText(suggestion)}, `;
}

export interface AclEntry {
  identifier: string;
  rights: string;
}

/** Sharing levels offered in the interface, as RFC 4314 rights. */
export const SHARE_LEVELS = [
  { id: 'read', label: t('Can read'), rights: 'lrs' },
  { id: 'write', label: t('Can read and file messages'), rights: 'lrswi' },
  { id: 'full', label: t('Can read, file and delete'), rights: 'lrswite' },
] as const;

export function shareLevel(rights: string): string {
  const has = (wanted: string) => wanted.split('').every((right) => rights.includes(right));
  if (has('te')) return 'full';
  if (has('i')) return 'write';
  return 'read';
}

export const mailboxNumber = (jmapId: string) => jmapId.replace(/^b/, '');
export const getAcl = (mailboxId: string) => get<AclEntry[]>(`/api/me/mailboxes/${mailboxNumber(mailboxId)}/acl`);
export const setAcl = (mailboxId: string, identifier: string, rights: string) => put<AclEntry[]>(`/api/me/mailboxes/${mailboxNumber(mailboxId)}/acl`, { identifier, rights });
export const exportUrl = (mailboxId: string) => `/api/me/mailboxes/${mailboxNumber(mailboxId)}/export`;
export const importMessages = (mailboxId: string, file: Blob) => postRaw<{ imported: number; skipped: number }>(`/api/me/mailboxes/${mailboxNumber(mailboxId)}/import`, file);

/** Address through which the server fetches a remote image on the reader's behalf. */
export const imageProxyUrl = (url: string) => `/api/me/image-proxy?url=${encodeURIComponent(url)}`;

// --- Blocked senders, labels and inbox categories ------------------------------------------

export interface SpamFilterState {
  enabled: boolean;
  spam: number;
  ham: number;
  needed: number;
  active: boolean;
}
export const spamFilterState = () => get<SpamFilterState>('/api/me/spam-filter');
export const resetSpamFilter = () => del('/api/me/spam-filter');
export const listBlockedSenders = () => get<string[]>('/api/me/blocked-senders');
export const blockSender = (sender: string) => post<{ sender: string }>('/api/me/blocked-senders', { sender });
export const unblockSender = (sender: string) => del(`/api/me/blocked-senders?sender=${encodeURIComponent(sender)}`);

export interface LabelDetail {
  name: string;
  /** `#rrggbb`, or empty for the default look. */
  color: string;
}

export const listLabelDetails = () => get<LabelDetail[]>('/api/me/label-details');
export const saveLabel = (name: string, color: string) => put<LabelDetail>('/api/me/label-details', { name, color });

/** Colours offered for labels. */
export const LABEL_COLORS = ['', '#d93025', '#e8710a', '#f9ab00', '#188038', '#129eaf', '#1a73e8', '#8430ce', '#d01884', '#5f6368'];

/** Black or white, whichever reads better on `background` (#rrggbb). */
export function readableOn(background: string): string {
  const [r, g, b] = [1, 3, 5].map((at) => parseInt(background.slice(at, at + 2), 16) / 255).map((c) => (c <= 0.03928 ? c / 12.92 : ((c + 0.055) / 1.055) ** 2.4));
  return 0.2126 * r + 0.7152 * g + 0.0722 * b > 0.4 ? '#000000' : '#ffffff';
}

/** Inbox categories, in tab order. `general` is everything without a category. */
export const CATEGORIES = [
  { id: 'general', label: t('General') },
  { id: 'offers', label: t('Offers') },
  { id: 'communities', label: t('Communities') },
  { id: 'notifications', label: t('Notifications') },
  { id: 'forums', label: t('Forums') },
] as const;
export type CategoryName = (typeof CATEGORIES)[number]['id'];

export const categoryCounts = () => get<Record<CategoryName, number>>('/api/me/categories');

/** What the inbox categories learned from the user moving messages between them. */
export interface CategoryLearning {
  learned: Record<CategoryName, number>;
  total: number;
  /** Senders whose mail goes where the user last put it. */
  senders: number;
  /** Corrected messages of a category before the content classifier uses it. */
  needed: number;
}
export const categoryLearning = () => get<CategoryLearning>('/api/me/categories/learning');
export const resetCategoryLearning = () => del('/api/me/categories/learning');
