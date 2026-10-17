// Rendering untrusted e-mail HTML safely.
//
// Defence in depth: (1) DOMPurify removes scripts, event handlers, forms and embedded content;
// (2) remote resources are stripped so opening a message does not notify the sender;
// (3) the result is displayed in a sandboxed iframe without script permission, under its own
// restrictive Content-Security-Policy.
//
// Remote images are shown only when the reader asks for them, and then through the server's
// image proxy: the browser never contacts the sender's host, so neither the reader's address
// nor any cookie is revealed.
//
// HTML that goes into the application page itself (the composer, with a quoted message in it)
// has no frame around it: there, style sheets (which would restyle the whole application) and
// positioning (which could lay a fake dialog or link over it) are removed as well.

import DOMPurify from 'dompurify';
import { linkWarning } from './risk';

import { t } from '../i18n';
const FORBIDDEN_TAGS = ['script', 'iframe', 'frame', 'object', 'embed', 'form', 'input', 'button', 'select', 'textarea', 'link', 'meta', 'base', 'svg', 'math', 'audio', 'video', 'source'];
const SAFE_LINK = /^(https?:|mailto:)/i;
const REMOTE_IMAGE = /^https?:\/\//i;

export interface SanitizeOptions {
  /** Maps a Content-ID to a blob/data URL for inline images. */
  resolveCid?: (cid: string) => string | undefined;
  /** When given, remote images are kept and loaded through this address mapping. */
  proxyImage?: (url: string) => string;
  /** The result goes into the application page, not the sandboxed reader frame. */
  forEditor?: boolean;
}

/** Properties that let content leave its place in the flow and cover other parts of the page. */
const POSITIONING = ['position', 'inset', 'top', 'right', 'bottom', 'left', 'z-index', 'transform', 'translate', 'rotate', 'scale'];

export interface Sanitized {
  html: string;
  /** Number of remote images that were blocked. */
  blockedImages: number;
}

/** Sanitizes HTML and reports how many remote images were held back. */
export function sanitizeEmail(html: string, options: SanitizeOptions = {}): Sanitized {
  const clean = DOMPurify.sanitize(html, {
    FORBID_TAGS: FORBIDDEN_TAGS,
    FORBID_ATTR: ['srcset', 'ping', 'formaction', 'action', 'background', 'poster'],
    ALLOW_DATA_ATTR: false,
    WHOLE_DOCUMENT: false,
    RETURN_DOM: true,
  }) as unknown as HTMLElement;

  clean.querySelectorAll('a').forEach((link) => {
    const href = link.getAttribute('href') ?? '';
    if (SAFE_LINK.test(href.trim())) {
      link.setAttribute('target', '_blank');
      link.setAttribute('rel', 'noopener noreferrer nofollow');
      // The real destination on hover, and a marked link when it is not what it claims to be.
      link.setAttribute('title', href.trim());
      const warning = linkWarning(href.trim(), link.textContent ?? '');
      if (warning) link.setAttribute('data-unomail-warning', warning);
    } else {
      link.removeAttribute('href');
    }
  });
  let blockedImages = 0;
  clean.querySelectorAll('img').forEach((img) => {
    const src = (img.getAttribute('src') ?? '').trim();
    if (src.toLowerCase().startsWith('cid:')) {
      const resolved = options.resolveCid?.(src.slice(4));
      if (resolved) img.setAttribute('src', resolved);
      else img.removeAttribute('src');
    } else if (REMOTE_IMAGE.test(src) && options.proxyImage) {
      img.setAttribute('src', options.proxyImage(src));
      img.setAttribute('referrerpolicy', 'no-referrer');
    } else if (!/^data:image\/(png|jpeg|gif|webp);/i.test(src)) {
      // Remote image: would reveal to the sender that (and from where) the message was read.
      if (REMOTE_IMAGE.test(src)) blockedImages += 1;
      img.removeAttribute('src');
      img.setAttribute('alt', img.getAttribute('alt') || t('[remote image blocked]'));
    }
  });
  // url(...) in inline styles is another way to load remote content. CSS escapes (`u\72l(`)
  // and comments (`u/**/rl(`) would hide it from a pattern, so styles using them go too; the
  // frame's CSP blocks such loads anyway, this is the second layer.
  const remoteCss = (css: string) => /url\s*\(|expression\s*\(|@import|image-set\s*\(|\\|\/\*/i.test(css);
  clean.querySelectorAll('[style]').forEach((el) => {
    if (remoteCss(el.getAttribute('style') ?? '')) el.removeAttribute('style');
  });
  clean.querySelectorAll('style').forEach((style) => {
    if (options.forEditor || remoteCss(style.textContent ?? '')) style.remove();
  });
  if (options.forEditor) {
    // Styles with escapes or comments are gone already (above), so every declaration the
    // browser sees starts after a ';' and names its property plainly.
    const positioning = (declaration: string) => {
      const name = declaration.split(':', 1)[0].trim().toLowerCase().replace(/^-[a-z]+-/, '');
      return POSITIONING.includes(name) || name.startsWith('inset-');
    };
    clean.querySelectorAll('[style]').forEach((el) => {
      const kept = (el.getAttribute('style') ?? '').split(';').filter((declaration) => declaration.trim() && !positioning(declaration));
      if (kept.length) el.setAttribute('style', kept.join(';'));
      else el.removeAttribute('style');
    });
  }
  return { html: clean.innerHTML, blockedImages };
}

/**
 * Returns sanitized HTML for the application page (the composer, signatures, quoted replies).
 * `resolveCid` maps a Content-ID to a blob/data URL for inline images.
 */
export function sanitizeEmailHtml(html: string, resolveCid: (cid: string) => string | undefined = () => undefined): string {
  return sanitizeEmail(html, { resolveCid, forEditor: true }).html;
}

/**
 * Wraps sanitized HTML in a standalone document for the sandboxed reader frame. With
 * `proxyOrigin` the frame may additionally load images from that origin (the image proxy).
 */
export function buildFrameDocument(sanitizedHtml: string, dark: boolean, proxyOrigin = ''): string {
  const csp = `default-src 'none'; img-src data: blob:${proxyOrigin ? ` ${proxyOrigin}` : ''}; style-src 'unsafe-inline'`;
  const colors = dark ? 'color:#e6e0e9;background:#1d1b20' : 'color:#1d1b20;background:#fffbfe';
  return `<!doctype html><html><head><meta charset="utf-8"><meta http-equiv="Content-Security-Policy" content="${csp}"><base target="_blank"><style>body{margin:0;padding:4px 0;font:14px/1.5 Roboto,system-ui,sans-serif;${colors};overflow-wrap:anywhere}img{max-width:100%;height:auto}blockquote{margin:0 0 0 .8em;padding-left:.8em;border-left:3px solid #8884}a{color:${dark ? '#d0bcff' : '#6750a4'}}pre{white-space:pre-wrap}</style></head><body>${sanitizedHtml}</body></html>`;
}

export function escapeHtml(text: string): string {
  return text.replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;').replace(/"/g, '&quot;');
}

/** Converts a plain-text body to HTML, preserving line breaks. */
export function textToHtml(text: string): string {
  return `<pre>${escapeHtml(text)}</pre>`;
}
