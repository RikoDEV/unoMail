
import { t } from '../i18n';// Recognising the usual tricks of phishing and malware mail: links that are not what they say,
// look-alike addresses, attachments that run code, and display names that pose as someone else.

/** File types that run code when opened (Windows, scripts, installers, shortcuts, macros). */
const EXECUTABLE = new Set([
  'exe', 'scr', 'com', 'pif', 'bat', 'cmd', 'cpl', 'msi', 'msp', 'msc', 'hta', 'jar', 'js', 'jse', 'vbs', 'vbe', 'wsf', 'wsh', 'ps1', 'psm1', 'lnk', 'reg', 'inf', 'gadget',
  'application', 'appx', 'msix', 'dll', 'sys', 'vb', 'ws', 'scf', 'iqy', 'slk', 'xll', 'sh', 'command', 'app', 'apk', 'dmg', 'pkg', 'deb', 'rpm', 'run', 'bin', 'elf',
]);
/** Documents that can carry macros, and pages that run scripts when opened from disk. */
const ACTIVE_DOCUMENT = new Set(['docm', 'dotm', 'xlsm', 'xltm', 'xlam', 'pptm', 'potm', 'ppam', 'ppsm', 'sldm', 'html', 'htm', 'xhtml', 'shtml', 'svg', 'mht', 'mhtml', 'one', 'iso', 'img', 'vhd', 'vhdx']);
/** Containers that may hide either of the above. */
const ARCHIVE = new Set(['zip', '7z', 'rar', 'tar', 'gz', 'tgz', 'bz2', 'xz', 'cab', 'arj', 'ace', 'lzh', 'z']);
/** Characters that change how a name is displayed (right-to-left override, invisible marks). */
const BIDI_CONTROLS = /[​-‏‪-‮⁦-⁩﻿]/;

export interface AttachmentRisk {
  level: 'danger' | 'caution';
  reason: string;
}

/** How risky opening an attachment is, judged by its name (never by what it claims to be). */
export function attachmentRisk(name: string): AttachmentRisk | null {
  if (BIDI_CONTROLS.test(name)) {
    return { level: 'danger', reason: t('Its name contains hidden characters that disguise its real type.') };
  }
  const parts = name.trim().toLowerCase().replace(/[.\s]+$/, '').split('.');
  if (parts.length < 2) return null;
  const extension = parts[parts.length - 1];
  const inner = parts.length > 2 ? parts[parts.length - 2] : '';
  if (EXECUTABLE.has(extension)) {
    // "invoice.pdf.exe": a harmless-looking type in front of the real one.
    if (inner && !EXECUTABLE.has(inner) && /^[a-z0-9]{2,5}$/.test(inner)) {
      return { level: 'danger', reason: t('It is a program (.{{extension}}) disguised as a .{{inner}} file: opening it runs code on your computer.', { extension, inner }) };
    }
    return { level: 'danger', reason: t('It is a program (.{{extension}}): opening it runs code on your computer.', { extension }) };
  }
  if (ACTIVE_DOCUMENT.has(extension)) {
    return { level: 'caution', reason: t('.{{extension}} files can run macros or scripts when opened.', { extension }) };
  }
  if (ARCHIVE.has(extension)) {
    return { level: 'caution', reason: t('Archives (.{{extension}}) can contain programs; check what is inside before opening anything.', { extension }) };
  }
  return null;
}

function hostOf(href: string): URL | null {
  try {
    return new URL(href);
  } catch {
    return null;
  }
}

/** A domain written in the text of a link ("paypal.com", "https://paypal.com/login"). */
function domainInText(text: string): string | null {
  const match = /(?:^|[\s(<"'])(?:https?:\/\/)?((?:[a-z0-9-]+\.)+[a-z]{2,})(?:[/:?#\s)>"']|$)/i.exec(` ${text.trim()} `);
  return match ? match[1].toLowerCase().replace(/^www\./, '') : null;
}

function sameSite(a: string, b: string): boolean {
  const x = a.replace(/^www\./, '');
  const y = b.replace(/^www\./, '');
  return x === y || x.endsWith(`.${y}`) || y.endsWith(`.${x}`);
}

/** `value` percent-decoded, or as it is when its encoding is broken (hostile links often are). */
function decodeOr(value: string): string {
  try {
    return decodeURIComponent(value);
  } catch {
    return value;
  }
}

/** Why a link deserves a second look before it is followed, or null. */
export function linkWarning(href: string, text: string): string | null {
  const url = hostOf(href);
  if (!url || url.protocol === 'mailto:') return null;
  const host = url.hostname.toLowerCase();
  if (url.username || url.password) {
    return t('The address hides its real destination: it goes to {{host}}, not to “{{shown}}”.', { host, shown: decodeOr(url.username) });
  }
  if (/^\d{1,3}(\.\d{1,3}){3}$/.test(host) || host.startsWith('[')) {
    return t('It goes to a bare numeric address ({{host}}) instead of a named website.', { host });
  }
  if (host.split('.').some((label) => label.startsWith('xn--'))) {
    return t('The domain {{host}} uses international characters, which can imitate the letters of a familiar name.', { host });
  }
  const shown = domainInText(text);
  if (shown && !sameSite(shown, host)) {
    return t('The link says {{shown}}, but it goes to {{host}}.', { shown, host });
  }
  return null;
}

/** Why a sender's display name may be misleading, or null. */
export function senderNameWarning(name: string | null | undefined, address: string): string | null {
  if (!name) return null;
  const actual = address.toLowerCase();
  const actualDomain = actual.split('@')[1] ?? '';
  const named = /[\w.+-]+@[\w-]+(?:\.[\w-]+)+/.exec(name)?.[0].toLowerCase();
  if (named && named !== actual) {
    return t('The name shows the address {{named}}, but the message comes from {{actual}}.', { named, actual });
  }
  const domain = domainInText(name);
  if (domain && actualDomain && !sameSite(domain, actualDomain)) {
    return t('The name mentions {{domain}}, but the message comes from {{actualDomain}}.', { domain, actualDomain });
  }
  if (BIDI_CONTROLS.test(name)) {
    return t('The name contains hidden characters that change how it reads.');
  }
  return null;
}
