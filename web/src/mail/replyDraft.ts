// The first draft of a reply or forward: recipients, subject and the quoted message.

import { t, uiLocale } from '../i18n';
import { type Draft, type EmailFull, formatAddress } from './jmapClient';
import { emailHtml, type ReaderAction } from './Reader';
import { escapeHtml, textToHtml } from './sanitize';

export const EMPTY_DRAFT: Draft = { to: '', cc: '', bcc: '', subject: '', html: '', attachments: [] };



function prefixed(subject: string, prefix: string): string {
  return subject.toLowerCase().startsWith(prefix.toLowerCase()) ? subject : `${prefix} ${subject}`;
}

/** Builds the initial draft for a reply or forward of `email`. */
export function draftFor(action: ReaderAction, email: EmailFull, ownAddress: string, accountId: string, suggestedText?: string): Draft {
  const sender = email.replyTo?.length ? email.replyTo : (email.from ?? []);
  // The translation is plain text from our own files; the values are escaped before they go in.
  const attribution = escapeHtml(t('On {{date}}, {{sender}} wrote:', { date: new Date(email.receivedAt).toLocaleString(uiLocale()), sender: (email.from ?? []).map(formatAddress).join(', ') }));
  const quoted = `<p><br></p><p>${attribution}</p><blockquote>${emailHtml(email, accountId)}</blockquote>`;
  const references = [...(email.references ?? []), ...(email.messageId ?? [])];
  if (action === 'forward') {
    return { ...EMPTY_DRAFT, subject: prefixed(email.subject, 'Fwd:'), html: quoted, answer: true };
  }
  const owned = new Set([ownAddress, ...(email.ownedAddresses ?? []), ...(email.maskedAddresses ?? [])].map((a) => a.toLowerCase()));
  const others = action === 'replyAll' ? [...(email.to ?? []), ...(email.cc ?? [])].filter((a) => !owned.has(a.email.toLowerCase())) : [];
  const mask = email.maskedAddresses?.[0];
  return {
    ...EMPTY_DRAFT,
    // Answer from the identity the message was addressed to, if the user has one for it.
    fromHint: mask ? [mask] : [...(email.to ?? []), ...(email.cc ?? [])].map((a) => a.email),
    from: mask ? { name: null, email: mask } : undefined,
    to: sender.map(formatAddress).join(', '),
    cc: others.map(formatAddress).join(', '),
    subject: prefixed(email.subject, 'Re:'),
    html: suggestedText ? `<div class="unomail-reply-text">${textToHtml(suggestedText)}</div>${quoted}` : quoted,
    saveOnOpen: Boolean(suggestedText),
    answer: true,
    inReplyTo: email.messageId ?? undefined,
    references: references.length ? references : undefined,
  };
}
