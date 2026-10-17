// mailto: links (RFC 6068) as a new message: from links in mail, and from other sites and
// programs once unoMail is the browser's handler for them.

import { escapeHtml } from './sanitize';

export interface MailtoDraft {
  to: string;
  cc: string;
  bcc: string;
  subject: string;
  /** The body as HTML for the composer (the link carries plain text). */
  html: string;
}

/** Long enough for any sensible link, short enough that a hostile one cannot flood the composer. */
const MAX_FIELD = 10_000;

function decode(value: string): string {
  try {
    // RFC 6068: "+" is a plus sign here, not a space.
    return decodeURIComponent(value).slice(0, MAX_FIELD);
  } catch {
    return value.slice(0, MAX_FIELD);
  }
}

// Addresses separated by commas, written ", " as the composer shows them.
const join = (...parts: string[]) => parts.flatMap((part) => part.split(',')).map((part) => part.trim()).filter(Boolean).join(', ');

/** The message a mailto: URL describes, or null when it is not one. Other header fields are ignored. */
export function parseMailto(url: string): MailtoDraft | null {
  const trimmed = url.trim();
  if (!/^mailto:/i.test(trimmed)) return null;
  const rest = trimmed.slice('mailto:'.length);
  const [path, query = ''] = rest.split(/\?(.*)/s, 2);
  const draft: MailtoDraft = { to: decode(path), cc: '', bcc: '', subject: '', html: '' };
  for (const pair of query.split('&')) {
    if (!pair) continue;
    const [rawName, rawValue = ''] = pair.split(/=(.*)/s, 2);
    const value = decode(rawValue);
    switch (decode(rawName).toLowerCase()) {
      case 'to':
        draft.to = join(draft.to, value);
        break;
      case 'cc':
        draft.cc = join(draft.cc, value);
        break;
      case 'bcc':
        draft.bcc = join(draft.bcc, value);
        break;
      case 'subject':
        draft.subject = value;
        break;
      case 'body':
        draft.html = value
          .split(/\r?\n/)
          .map((line) => `<p>${line ? escapeHtml(line) : '<br>'}</p>`)
          .join('');
        break;
    }
  }
  draft.to = join(draft.to);
  return draft;
}

/** Whether unoMail can be offered as the browser's handler for mailto: links. */
export function mailtoHandlerSupported(): boolean {
  return typeof navigator !== 'undefined' && typeof navigator.registerProtocolHandler === 'function' && window.isSecureContext;
}

/** Asks the browser to open mailto: links with unoMail (it confirms with the user). */
export function registerMailtoHandler(): void {
  navigator.registerProtocolHandler('mailto', `${window.location.origin}/mail/inbox?mailto=%s`);
}
