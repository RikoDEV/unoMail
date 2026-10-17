// Building RFC 5322 / MIME messages in the browser. Used for messages the server must store
// exactly as written, such as PGP/MIME, where the server never sees the plain content.

export interface MimeAttachment {
  name: string;
  type: string;
  data: Uint8Array;
  /** Content-ID of an inline image. */
  cid?: string;
}

export interface MimeAddress {
  name?: string | null;
  email: string;
}

const CRLF = '\r\n';

function randomId(): string {
  const bytes = crypto.getRandomValues(new Uint8Array(12));
  return Array.from(bytes, (b) => b.toString(16).padStart(2, '0')).join('');
}

export function bytesToBase64(bytes: Uint8Array): string {
  let binary = '';
  for (let i = 0; i < bytes.length; i += 0x8000) binary += String.fromCharCode(...bytes.subarray(i, i + 0x8000));
  return btoa(binary);
}

/** Base64 in lines of 76 characters, as MIME requires. */
export function base64Lines(bytes: Uint8Array): string {
  return (bytesToBase64(bytes).match(/.{1,76}/g) ?? []).join(CRLF);
}

/** Header values must never contain line breaks: that is how header injection works. */
function clean(value: string): string {
  return value.replace(/[\r\n\0]+/g, ' ').trim();
}

/** RFC 2047 encoded-words for header text that is not plain ASCII. */
export function encodeHeaderText(value: string): string {
  const text = clean(value);
  if (/^[\x20-\x7e]*$/.test(text)) return text;
  const bytes = new TextEncoder().encode(text);
  const words: string[] = [];
  // 45 bytes per word keeps every encoded-word under the 75 character limit; split on
  // character boundaries so a multi-byte character is never cut in half.
  let start = 0;
  while (start < bytes.length) {
    let end = Math.min(start + 45, bytes.length);
    while (end < bytes.length && (bytes[end] & 0xc0) === 0x80) end -= 1;
    words.push(`=?UTF-8?B?${bytesToBase64(bytes.subarray(start, end))}?=`);
    start = end;
  }
  return words.join(`${CRLF} `);
}

export function formatMimeAddress(address: MimeAddress): string {
  const email = clean(address.email).replace(/[<>\s]/g, '');
  const name = clean(address.name ?? '');
  if (!name) return email;
  const display = /^[\x20-\x7e]*$/.test(name) ? `"${name.replace(/(["\\])/g, '\\$1')}"` : encodeHeaderText(name);
  return `${display} <${email}>`;
}

function parameter(name: string, value: string): string {
  const text = clean(value);
  return /^[\x20-\x7e]*$/.test(text) ? `${name}="${text.replace(/(["\\])/g, '\\$1')}"` : `${name}="${encodeHeaderText(text).replace(/\r\n /g, '')}"`;
}

function textPart(type: string, content: string): string {
  return [`Content-Type: ${type}; charset=utf-8`, 'Content-Transfer-Encoding: base64', '', base64Lines(new TextEncoder().encode(content))].join(CRLF);
}

function multipart(subtype: string, parts: string[], extra = ''): string {
  const boundary = `=_${randomId()}`;
  const body = parts.map((part) => `--${boundary}${CRLF}${part}${CRLF}`).join('');
  return `Content-Type: multipart/${subtype}; boundary="${boundary}"${extra}${CRLF}${CRLF}${body}--${boundary}--${CRLF}`;
}

/** The body of a message as one MIME entity: text and HTML alternatives plus attachments. */
export function buildEntity(text: string, html: string, attachments: MimeAttachment[]): string {
  const alternative = multipart('alternative', [textPart('text/plain', text), textPart('text/html', html)]);
  if (attachments.length === 0) return alternative;
  const files = attachments.map((file) => {
    const type = /^[\w.+-]+\/[\w.+-]+$/.test(file.type) ? file.type : 'application/octet-stream';
    const headers = [`Content-Type: ${type}; ${parameter('name', file.name)}`, 'Content-Transfer-Encoding: base64'];
    if (file.cid) headers.push(`Content-ID: <${clean(file.cid).replace(/[<>\s]/g, '')}>`, `Content-Disposition: inline; ${parameter('filename', file.name)}`);
    else headers.push(`Content-Disposition: attachment; ${parameter('filename', file.name)}`);
    return [...headers, '', base64Lines(file.data)].join(CRLF);
  });
  return multipart('mixed', [alternative, ...files]);
}

export interface Envelope {
  from: MimeAddress;
  to: MimeAddress[];
  cc: MimeAddress[];
  bcc: MimeAddress[];
  replyTo?: MimeAddress;
  subject: string;
  inReplyTo?: string[];
  references?: string[];
}

function messageIds(ids: string[] | undefined): string {
  return (ids ?? []).map((id) => `<${clean(id).replace(/[<>\s]/g, '')}>`).join(' ');
}

/** The header block of a message, without the content headers of its body. */
export function buildHeaders(envelope: Envelope): string {
  const domain = clean(envelope.from.email).split('@')[1] ?? 'localhost';
  const lines = [`From: ${formatMimeAddress(envelope.from)}`];
  if (envelope.to.length) lines.push(`To: ${envelope.to.map(formatMimeAddress).join(`,${CRLF} `)}`);
  if (envelope.cc.length) lines.push(`Cc: ${envelope.cc.map(formatMimeAddress).join(`,${CRLF} `)}`);
  if (envelope.bcc.length) lines.push(`Bcc: ${envelope.bcc.map(formatMimeAddress).join(`,${CRLF} `)}`);
  if (envelope.replyTo) lines.push(`Reply-To: ${formatMimeAddress(envelope.replyTo)}`);
  lines.push(`Subject: ${encodeHeaderText(envelope.subject)}`, `Date: ${new Date().toUTCString().replace('GMT', '+0000')}`, `Message-ID: <${randomId()}@${domain}>`);
  if (envelope.inReplyTo?.length) lines.push(`In-Reply-To: ${messageIds(envelope.inReplyTo)}`);
  if (envelope.references?.length) lines.push(`References: ${messageIds(envelope.references)}`);
  lines.push('MIME-Version: 1.0');
  return lines.join(CRLF) + CRLF;
}

/** Wraps an armored OpenPGP message as PGP/MIME (RFC 3156). */
export function buildEncryptedMessage(envelope: Envelope, armored: string): string {
  const control = ['Content-Type: application/pgp-encrypted', 'Content-Description: PGP/MIME version identification', '', 'Version: 1'].join(CRLF);
  const payload = ['Content-Type: application/octet-stream; name="encrypted.asc"', 'Content-Description: OpenPGP encrypted message', 'Content-Disposition: inline; filename="encrypted.asc"', '', armored.replace(/\r?\n/g, CRLF).trim()].join(CRLF);
  return buildHeaders(envelope) + multipart('encrypted', [control, payload], '; protocol="application/pgp-encrypted"');
}
