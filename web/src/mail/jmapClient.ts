// Typed helpers over the JMAP API for the operations the web client needs.

import { downloadUrl, get, jmap, type MethodCall, type MethodResponse, post, uploadBlob } from '../api';
import { buildEncryptedMessage, type MimeAddress, type MimeAttachment } from './mime';
import { isPendingId, loadPendingFile } from './pendingFiles';
import { encryptEntity } from './pgp';

import { t } from '../i18n';
export interface Mailbox {
  id: string;
  name: string;
  role: string | null;
  sortOrder: number;
  totalEmails: number;
  unreadEmails: number;
  /** Address of the owner when the folder is shared by another user. */
  shareOwner?: string | null;
  /** Number of users the folder is shared with (own folders only). */
  sharedWith?: number;
  myRights?: { mayReadItems: boolean; mayAddItems: boolean; mayRemoveItems: boolean; maySetSeen: boolean; maySetKeywords: boolean; mayAdmin?: boolean };
}

export interface EmailAddress {
  name: string | null;
  email: string;
}

export interface EmailSummary {
  id: string;
  /** The whole message as a downloadable blob. */
  blobId?: string;
  threadId: string;
  mailboxIds: Record<string, boolean>;
  keywords: Record<string, boolean>;
  from: EmailAddress[] | null;
  to: EmailAddress[] | null;
  subject: string;
  preview: string;
  receivedAt: string;
  hasAttachment: boolean;
  size: number;
  /** The attached files (listed without loading the message). */
  attachments?: BodyPart[];
}

export interface BodyPart {
  partId: string;
  blobId: string;
  size: number;
  name?: string | null;
  type: string;
  disposition?: string;
  cid?: string | null;
}

export interface EmailFull extends EmailSummary {
  /** Trusted delivery-envelope provenance, never inferred from message headers. */
  maskedAddresses?: string[];
  ownedAddresses?: string[];
  cc: EmailAddress[] | null;
  bcc: EmailAddress[] | null;
  replyTo: EmailAddress[] | null;
  messageId: string[] | null;
  references: string[] | null;
  /** Ways of unsubscribing the sender offers (List-Unsubscribe), or null. */
  unsubscribe?: { oneClick: boolean; mailto: boolean; link: boolean } | null;
  /** What the server established on delivery: sender authentication, encryption, virus scan. */
  security?: import('./Sender').Security | null;
  /** Who asked for a read receipt (Disposition-Notification-To), if anyone. */
  receiptRequestedBy?: string | null;
  /** The receipt address is the sender's own return path: a receipt may go without asking. */
  receiptAutomaticAllowed?: boolean;
  /** S/MIME signature and encryption, if the message uses them. */
  smime?: import('./Smime').SmimeStatus | null;
  textBody: BodyPart[];
  htmlBody: BodyPart[];
  attachments: BodyPart[];
  bodyValues: Record<string, { value: string }>;
}

export interface DraftAttachment {
  blobId: string;
  name: string;
  type: string;
  size: number;
  cid?: string;
  /**
   * Base64 content of a file attached while offline, for browsers without IndexedDB. Normally
   * such a file waits in IndexedDB under its `pending:` blob id (see pendingFiles.ts).
   */
  pendingData?: string;
}

export interface Draft {
  /** User-chosen initial content should be saved without requiring another edit. */
  saveOnOpen?: boolean;
  to: string;
  cc: string;
  bcc: string;
  subject: string;
  html: string;
  attachments: DraftAttachment[];
  inReplyTo?: string[];
  references?: string[];
  /** A reply or forward: it gets the identity's signature for replies. */
  answer?: boolean;
  /** Addresses the message being answered was sent to; picks the matching identity. */
  fromHint?: string[];
  /** The sender identity; the account's own address when absent. */
  from?: EmailAddress;
  replyTo?: string;
  /** Ask for a read receipt, to this address (Disposition-Notification-To). */
  receiptTo?: string;
  /** Sign and/or encrypt with the user's S/MIME certificate (done by the server). */
  smime?: { sign: boolean; encrypt: boolean };
}

/** When a message leaves: after a delay that allows calling it back, or at a chosen time. */
export interface SendOptions {
  holdFor?: number;
  sendAt?: Date;
}

/** The result of sending: the stored message, and the submission while it can be undone. */
export interface Sent {
  emailId: string;
  submissionId?: string;
}

function submission(options: SendOptions | undefined, from: string | undefined): Record<string, unknown> {
  const parameters = options?.sendAt ? { HOLDUNTIL: options.sendAt.toISOString().replace(/\.\d{3}Z$/, 'Z') } : options?.holdFor ? { HOLDFOR: String(options.holdFor) } : null;
  return parameters ? { emailId: '#draft', envelope: { mailFrom: { email: from ?? '', parameters }, rcptTo: [] } } : { emailId: '#draft' };
}

/** Calls back a message that is still waiting to be sent; it stays in Drafts. */
export async function cancelSubmission(submissionId: string): Promise<void> {
  const id = await accountId();
  const [[, result]] = await jmap([['EmailSubmission/set', { accountId: id, update: { [submissionId]: { undoStatus: 'canceled' } } }, 'u']]);
  const failed = result.notUpdated?.[submissionId];
  if (failed) throw new Error(failed.type === 'cannotUnsend' ? t('The message has already been sent') : (failed.description ?? t('The message could not be called back')));
}

export interface Scheduled {
  id: string;
  emailId: string;
  sendAt: string;
}

/** Messages waiting to be sent at a later time. */
export async function listScheduled(): Promise<Scheduled[]> {
  const id = await accountId();
  const responses = await jmap([
    ['EmailSubmission/query', { accountId: id, filter: { undoStatus: 'pending' } }, 'q'],
    ['EmailSubmission/get', { accountId: id, '#ids': { resultOf: 'q', name: 'EmailSubmission/query', path: '/ids' } }, 'g'],
  ]);
  return responses[1][1].list;
}

/** Sends a read receipt for a message (or records that none will be sent). */
export async function answerReceipt(emailId: string, send: boolean, automatic = false): Promise<void> {
  const id = await accountId();
  if (!send) {
    await jmap([['Email/set', { accountId: id, update: { [emailId]: { 'keywords/$mdnsent': true } } }, 'k']]);
    return;
  }
  const [[, result]] = await jmap([
    ['MDN/send', { accountId: id, identityId: 'default', send: { r: { forEmailId: emailId, disposition: automatic ? { actionMode: 'automatic-action', sendingMode: 'mdn-sent-automatically', type: 'displayed' } : { actionMode: 'manual-action', sendingMode: 'mdn-sent-manually', type: 'displayed' } } } }, 'm'],
  ]);
  if (result.notSent?.r) throw new Error(result.notSent.r.description ?? t('The receipt could not be sent'));
}

/** Snoozes messages until a time; they return to their folder then, unread. */
export const snooze = (emailIds: string[], until: Date) => post('/api/me/snoozes', { email_ids: emailIds, until: Math.floor(until.getTime() / 1000) });

const SUMMARY_PROPERTIES = ['threadId', 'mailboxIds', 'keywords', 'from', 'to', 'subject', 'preview', 'receivedAt', 'hasAttachment', 'size', 'attachments'];

let accountIdPromise: Promise<string> | null = null;

export function accountId(): Promise<string> {
  accountIdPromise ??= get<{ primaryAccounts: Record<string, string> }>('/jmap/session').then((s) => s.primaryAccounts['urn:ietf:params:jmap:mail']);
  return accountIdPromise;
}

export function resetSession() {
  accountIdPromise = null;
}

export async function listMailboxes(): Promise<Mailbox[]> {
  const id = await accountId();
  const [[, result]] = await jmap([['Mailbox/get', { accountId: id }, 'm']]);
  return (result.list as Mailbox[]).sort((a, b) => a.sortOrder - b.sortOrder || a.name.localeCompare(b.name));
}

export interface QueryResult {
  emails: EmailSummary[];
  total: number;
}

export interface ListFilter {
  mailboxId?: string;
  /** "All mail": every message outside these folders (Trash and Junk); used without `mailboxId`. */
  otherThan?: string[];
  label?: string;
  text?: string;
  /** Inbox category; only meaningful together with the inbox as `mailboxId`. */
  category?: string;
  /** A complete JMAP filter for a search (see searchQuery.ts); takes the place of the others. */
  search?: Record<string, unknown>;
}

function jmapFilter(options: ListFilter): Record<string, unknown> {
  if (options.search) return options.search;
  const filter: Record<string, unknown> = {};
  // A search covers every folder; otherwise list the selected one.
  if (options.text) filter.text = options.text;
  else if (options.label) filter.hasKeyword = options.label;
  else if (options.mailboxId) {
    filter.inMailbox = options.mailboxId;
    if (options.category) filter.category = options.category;
  } else if (options.otherThan?.length) filter.inMailboxOtherThan = options.otherThan;
  return filter;
}

/** Ids of every message matching a filter (for "select all in this folder"), up to `max`. */
export async function queryAllIds(options: ListFilter, max = 5000): Promise<string[]> {
  const id = await accountId();
  const ids: string[] = [];
  while (ids.length < max) {
    const [[, result]] = await jmap([['Email/query', { accountId: id, filter: jmapFilter(options), collapseThreads: false, position: ids.length, limit: 500 }, 'q']]);
    const page = result.ids as string[];
    ids.push(...page);
    if (page.length < 500) break;
  }
  return ids.slice(0, max);
}

export async function queryEmails(options: ListFilter & { position: number; limit: number }): Promise<QueryResult> {
  const id = await accountId();
  const filter = jmapFilter(options);
  const responses = await jmap([
    ['Email/query', { accountId: id, filter, collapseThreads: !options.text && !options.search, calculateTotal: true, position: options.position, limit: options.limit }, 'q'],
    ['Email/get', { accountId: id, '#ids': { resultOf: 'q', name: 'Email/query', path: '/ids' }, properties: SUMMARY_PROPERTIES }, 'g'],
  ]);
  return { emails: responses[1][1].list, total: responses[0][1].total ?? 0 };
}

/** Labels are JMAP keywords; names are restricted to a safe, portable alphabet. */
export function normalizeLabel(name: string): string | null {
  const label = name.trim().toLowerCase().replace(/\s+/g, '-');
  return /^[a-z0-9][a-z0-9_.-]{0,48}$/.test(label) ? label : null;
}

/** The user-visible labels of an email (system keywords start with "$"). */
export function labelsOf(email: { keywords: Record<string, boolean> }): string[] {
  return Object.keys(email.keywords).filter((k) => !k.startsWith('$') && email.keywords[k]).sort();
}

export async function getThread(threadId: string): Promise<EmailFull[]> {
  const id = await accountId();
  const responses = await jmap([
    ['Thread/get', { accountId: id, ids: [threadId] }, 't'],
    ['Email/get', { accountId: id, '#ids': { resultOf: 't', name: 'Thread/get', path: '/list/*/emailIds' } }, 'g'],
  ]);
  return responses[1][1].list;
}

async function updateEmails(patches: Record<string, Record<string, unknown>>) {
  const entries = Object.entries(patches);
  if (entries.length === 0) return;
  const id = await accountId();
  // Large selections are sent in batches the server accepts in one request.
  for (let start = 0; start < entries.length; start += BATCH) {
    const [[, result]] = await jmap([['Email/set', { accountId: id, update: Object.fromEntries(entries.slice(start, start + BATCH)) }, 'u']]);
    // The server answers per message; a refusal (for example missing rights on a shared
    // folder) must not pass for success.
    const refused = Object.values(result.notUpdated ?? {})[0] as { description?: string } | undefined;
    if (refused) throw new Error(refused.description ?? t('The change was refused'));
  }
}

const BATCH = 200;
const CATEGORY_KEYWORDS = ['offers', 'communities', 'notifications', 'forums'].map((name) => `$cat_${name}`);

/** Moves messages to an inbox category (`general` clears the category). */
export function setCategory(ids: string[], category: string) {
  const patch = Object.fromEntries(CATEGORY_KEYWORDS.map((keyword) => [`keywords/${keyword}`, keyword === `$cat_${category}` ? true : null]));
  return updateEmails(Object.fromEntries(ids.map((id) => [id, patch])));
}

export function setKeyword(ids: string[], keyword: string, value: boolean) {
  return updateEmails(Object.fromEntries(ids.map((id) => [id, { [`keywords/${keyword}`]: value ? true : null }])));
}

export function moveEmails(ids: string[], mailboxId: string) {
  return updateEmails(Object.fromEntries(ids.map((id) => [id, { mailboxIds: { [mailboxId]: true } }])));
}

export async function destroyEmails(ids: string[]) {
  const id = await accountId();
  for (let start = 0; start < ids.length; start += BATCH) {
    const [[, result]] = await jmap([['Email/set', { accountId: id, destroy: ids.slice(start, start + BATCH) }, 'd']]);
    const refused = Object.values(result.notDestroyed ?? {}).find((error) => (error as { type?: string }).type !== 'notFound') as { description?: string } | undefined;
    if (refused) throw new Error(refused.description ?? t('The message could not be deleted'));
  }
}

export async function createMailbox(name: string) {
  const id = await accountId();
  const [[, result]] = await jmap([['Mailbox/set', { accountId: id, create: { n: { name } } }, 'c']]);
  if (result.notCreated?.n) throw new Error(result.notCreated.n.description ?? t('Could not create the folder'));
}

export async function destroyMailbox(mailboxId: string) {
  const id = await accountId();
  const [[, result]] = await jmap([['Mailbox/set', { accountId: id, destroy: [mailboxId], onDestroyRemoveEmails: true }, 'd']]);
  if (result.notDestroyed?.[mailboxId]) throw new Error(result.notDestroyed[mailboxId].description ?? t('Could not delete the folder'));
}

/** Splits a comma/semicolon separated recipient field into JMAP addresses. */
export function parseRecipients(field: string): EmailAddress[] {
  return field
    .split(/[,;]/)
    .map((entry) => entry.trim())
    .filter(Boolean)
    .map((entry) => {
      const match = entry.match(/^(.*)<([^<>]+)>$/);
      return match ? { name: match[1].trim().replace(/^"|"$/g, '') || null, email: match[2].trim() } : { name: null, email: entry };
    });
}

export function formatAddress(address: EmailAddress): string {
  return address.name ? `${address.name} <${address.email}>` : address.email;
}

export function htmlToText(html: string): string {
  const doc = new DOMParser().parseFromString(html, 'text/html');
  doc.querySelectorAll('br').forEach((br) => br.replaceWith('\n'));
  doc.querySelectorAll('p, div, li, blockquote').forEach((el) => el.append('\n'));
  return (doc.body.textContent ?? '').replace(/\n{3,}/g, '\n\n').trim();
}

/** Uploads attachments that were added while offline and returns the draft with real blob ids. */
async function withUploads(draft: Draft): Promise<Draft> {
  if (!draft.attachments.some((a) => a.pendingData || isPendingId(a.blobId))) return draft;
  const id = await accountId();
  const attachments: DraftAttachment[] = [];
  for (const attachment of draft.attachments) {
    let bytes: ArrayBuffer | Uint8Array<ArrayBuffer>;
    if (attachment.pendingData) {
      bytes = Uint8Array.from(atob(attachment.pendingData), (c) => c.charCodeAt(0));
    } else if (isPendingId(attachment.blobId)) {
      const stored = await loadPendingFile(attachment.blobId).catch(() => undefined);
      if (!stored) throw new Error(t('The attachment {{name}} is no longer stored in this browser', { name: attachment.name }));
      bytes = stored;
    } else {
      attachments.push(attachment);
      continue;
    }
    const blob = await uploadBlob(id, new Blob([bytes], { type: attachment.type }));
    attachments.push({ ...attachment, blobId: blob.blobId, pendingData: undefined });
  }
  return { ...draft, attachments };
}

function emailObject(draft: Draft, mailboxId: string, isDraft: boolean) {
  return {
    mailboxIds: { [mailboxId]: true },
    keywords: isDraft ? { $draft: true, $seen: true } : { $seen: true },
    from: draft.from ? [draft.from] : undefined,
    replyTo: draft.replyTo ? [{ name: null, email: draft.replyTo }] : undefined,
    to: parseRecipients(draft.to),
    cc: parseRecipients(draft.cc),
    bcc: parseRecipients(draft.bcc),
    subject: draft.subject,
    inReplyTo: draft.inReplyTo,
    references: draft.references,
    bodyValues: { text: { value: htmlToText(draft.html) }, html: { value: draft.html } },
    textBody: [{ partId: 'text', type: 'text/plain' }],
    htmlBody: [{ partId: 'html', type: 'text/html' }],
    attachments: draft.attachments.map((a) => ({ blobId: a.blobId, name: a.name, type: a.type, cid: a.cid, disposition: a.cid ? 'inline' : 'attachment' })),
    ...(draft.receiptTo ? { 'header:Disposition-Notification-To:asAddresses': [{ name: null, email: draft.receiptTo }] } : {}),
    ...(draft.smime && (draft.smime.sign || draft.smime.encrypt) ? { smime: draft.smime } : {}),
  };
}

/** Stores the draft, replacing the previously saved copy. Returns the new email id. */
export async function saveDraft(draft: Draft, draftsId: string, previousId?: string): Promise<string> {
  draft = await withUploads(draft);
  const id = await accountId();
  const [[, result]] = await jmap([
    ['Email/set', { accountId: id, create: { draft: emailObject(draft, draftsId, true) }, destroy: previousId ? [previousId] : [] }, 'c'],
  ]);
  if (result.notCreated?.draft) throw new Error(result.notCreated.draft.description ?? t('Could not save the draft'));
  return result.created.draft.id;
}

/** Submits the message created as `#draft` in the same request; once sent it moves to Sent. */
function submitCall(id: string, options: SendOptions | undefined, from: string | undefined, sentId: string): MethodCall {
  return [
    'EmailSubmission/set',
    { accountId: id, create: { send: submission(options, from) }, onSuccessUpdateEmail: { '#send': { mailboxIds: { [sentId]: true }, 'keywords/$draft': null } } },
    's',
  ];
}

/** The outcome of creating `draft` and submitting it as `send` in one request. */
async function sendResult(responses: MethodResponse[], previousDraftId?: string): Promise<Sent> {
  const createError = responses[0][1].notCreated?.draft;
  if (createError) throw new Error(createError.description ?? t('The message could not be created'));
  const sendError = responses[1][1].notCreated?.send;
  if (sendError) {
    // Do not leave the failed copy behind; the composer still holds the content.
    await destroyEmails([responses[0][1].created.draft.id]).catch(() => {});
    throw new Error(sendError.description ?? t('The message could not be sent'));
  }
  if (previousDraftId) await destroyEmails([previousDraftId]).catch(() => {});
  const created = responses[1][1].created?.send;
  return { emailId: responses[0][1].created.draft.id, submissionId: created?.undoStatus === 'pending' ? created.id : undefined };
}

export async function sendEmail(draft: Draft, draftsId: string, sentId: string, previousDraftId?: string, options?: SendOptions): Promise<Sent> {
  draft = await withUploads(draft);
  const id = await accountId();
  const calls: MethodCall[] = [
    ['Email/set', { accountId: id, create: { draft: emailObject(draft, draftsId, true) } }, 'c'],
    submitCall(id, options, draft.from?.email ?? draft.receiptTo, sentId),
  ];
  return sendResult(await jmap(calls), previousDraftId);
}

/** Every address a draft is going to. */
export function draftRecipients(draft: Draft): string[] {
  return [...new Set([draft.to, draft.cc, draft.bcc].flatMap(parseRecipients).map((a) => a.email.toLowerCase()))];
}

async function attachmentBytes(account: string, attachment: DraftAttachment): Promise<Uint8Array> {
  if (attachment.pendingData) return Uint8Array.from(atob(attachment.pendingData), (c) => c.charCodeAt(0));
  if (isPendingId(attachment.blobId)) {
    const stored = await loadPendingFile(attachment.blobId);
    if (!stored) throw new Error(t('The attachment {{name}} is no longer stored in this browser', { name: attachment.name }));
    return new Uint8Array(stored);
  }
  const response = await fetch(downloadUrl(account, attachment.blobId, attachment.name), { credentials: 'same-origin' });
  if (!response.ok) throw new Error(t('The attachment {{name}} could not be read', { name: attachment.name }));
  return new Uint8Array(await response.arrayBuffer());
}

/**
 * Sends a message end-to-end encrypted (PGP/MIME). Body and attachments are encrypted in the
 * browser to `publicKeys`; the server only ever stores and relays the ciphertext. The subject
 * and the addresses stay readable, as mail transport requires.
 */
export async function sendEncrypted(draft: Draft, sender: MimeAddress, publicKeys: string[], draftsId: string, sentId: string, previousDraftId?: string, options?: SendOptions): Promise<Sent> {
  const id = await accountId();
  const files: MimeAttachment[] = [];
  for (const attachment of draft.attachments) {
    files.push({ name: attachment.name, type: attachment.type, cid: attachment.cid, data: await attachmentBytes(id, attachment) });
  }
  const armored = await encryptEntity(htmlToText(draft.html), draft.html, files, publicKeys);
  const raw = buildEncryptedMessage(
    {
      from: sender,
      to: parseRecipients(draft.to),
      cc: parseRecipients(draft.cc),
      bcc: parseRecipients(draft.bcc),
      replyTo: draft.replyTo ? { email: draft.replyTo } : undefined,
      subject: draft.subject,
      inReplyTo: draft.inReplyTo,
      references: draft.references,
    },
    armored,
  );
  const blob = await uploadBlob(id, new Blob([raw], { type: 'message/rfc822' }));
  const responses = await jmap([
    ['Email/import', { accountId: id, emails: { draft: { blobId: blob.blobId, mailboxIds: { [draftsId]: true }, keywords: { $draft: true, $seen: true } } } }, 'c'],
    submitCall(id, options, sender.email, sentId),
  ]);
  return sendResult(responses, previousDraftId);
}

const DEFAULT_FOLDER_NAMES: Record<string, string> = { inbox: 'INBOX', sent: 'Sent', drafts: 'Drafts', junk: 'Junk', trash: 'Trash', archive: 'Archive' };

/** A folder's name for display: the standard folders under their translated names. */
export function folderName(mailbox: { name: string; role?: string | null }): string {
  if (mailbox.name === 'INBOX') return t('Inbox');
  const standard = mailbox.role ? DEFAULT_FOLDER_NAMES[mailbox.role] : undefined;
  // Only a standard folder still carrying its standard name; one the user renamed keeps it.
  return standard && standard === mailbox.name ? t(standard, { context: 'folder' }) : mailbox.name;
}
