// The search box understands Gmail's search operators. A query is parsed into a JMAP filter
// (RFC 8621 FilterOperator / FilterCondition) plus the folders it is meant to cover, and the
// advanced-search form is turned into such a query, so that both stay in step.

export type Filter = Record<string, unknown>;

/** Which folders a search covers: the default (all but Trash and Junk), all of them, or one. */
export type Scope = { kind: 'default' } | { kind: 'anywhere' } | { kind: 'folder'; name: string };

export interface Parsed {
  /** The conditions, without the folders (see `scope`). */
  filter: Filter;
  scope: Scope;
  /** Whether the query uses anything beyond plain words. */
  operators: boolean;
}

/** Gmail's names for the inbox categories, and unoMail's. */
const CATEGORIES: Record<string, string> = {
  primary: 'general', general: 'general', promotions: 'offers', offers: 'offers', social: 'communities', communities: 'communities',
  updates: 'notifications', notifications: 'notifications', forums: 'forums',
};

const DAY = 86_400_000;

/** Splits a query into terms; quoted text (also after `key:`) stays together. */
export function tokenize(query: string): string[] {
  const out: string[] = [];
  let current = '';
  let quoted = false;
  for (const c of query) {
    if (c === '"') {
      quoted = !quoted;
      current += c;
    } else if (/\s/.test(c) && !quoted) {
      if (current) out.push(current);
      current = '';
    } else {
      current += c;
    }
  }
  if (current) out.push(current);
  return out;
}

const unquote = (value: string) => value.replace(/^"(.*)"$/s, '$1').replace(/"/g, '');

/** `2026/10/13` or `2026-10-13`: local midnight of that day. */
function day(value: string): Date | null {
  const match = /^(\d{4})[/-](\d{1,2})[/-](\d{1,2})$/.exec(value);
  if (!match) return null;
  const date = new Date(Number(match[1]), Number(match[2]) - 1, Number(match[3]));
  return Number.isNaN(date.getTime()) ? null : date;
}

/** `3d`, `2w`, `6m`, `1y`: that long before `now`. */
function ago(value: string, now: Date): Date | null {
  const match = /^(\d{1,4})([dwmy])$/i.exec(value);
  if (!match) return null;
  const amount = Number(match[1]);
  const date = new Date(now);
  switch (match[2].toLowerCase()) {
    case 'd':
      date.setDate(date.getDate() - amount);
      break;
    case 'w':
      date.setDate(date.getDate() - 7 * amount);
      break;
    case 'm':
      date.setMonth(date.getMonth() - amount);
      break;
    default:
      date.setFullYear(date.getFullYear() - amount);
  }
  return date;
}

/** `10M`, `500K`, `2000`: a size in bytes. */
export function bytes(value: string): number | null {
  const match = /^(\d+(?:\.\d+)?)\s*([kmg]?)b?$/i.exec(value);
  if (!match) return null;
  const factor = { '': 1, k: 1024, m: 1024 ** 2, g: 1024 ** 3 }[match[2].toLowerCase() as '' | 'k' | 'm' | 'g'];
  return Math.round(Number(match[1]) * factor);
}

/** One term as a filter condition; `null` when it is a plain word (or not understood). */
function condition(key: string, value: string, now: Date): Filter | 'scope' | null {
  const text = unquote(value).trim();
  if (!text) return null;
  switch (key) {
    case 'from':
    case 'to':
    case 'cc':
    case 'bcc':
    case 'subject':
      return { [key]: text };
    case 'filename':
      return { attachmentName: text };
    case 'has':
      if (text === 'attachment' || text === 'attachments') return { hasAttachment: true };
      if (text === 'noattachment' || text === 'noattachments') return { hasAttachment: false };
      return null;
    case 'is':
      return { unread: { notKeyword: '$seen' }, read: { hasKeyword: '$seen' }, starred: { hasKeyword: '$flagged' }, unstarred: { notKeyword: '$flagged' }, answered: { hasKeyword: '$answered' } }[text.toLowerCase()] ?? null;
    case 'label':
      return { hasKeyword: text.toLowerCase().replace(/\s+/g, '-') };
    case 'category':
      return CATEGORIES[text.toLowerCase()] ? { category: CATEGORIES[text.toLowerCase()] } : null;
    case 'before':
    case 'after':
    case 'older':
    case 'newer': {
      const date = day(text);
      if (!date) return null;
      return key === 'before' || key === 'older' ? { before: date.toISOString() } : { after: date.toISOString() };
    }
    case 'older_than':
    case 'newer_than': {
      const date = ago(text, now);
      if (!date) return null;
      return key === 'older_than' ? { before: date.toISOString() } : { after: date.toISOString() };
    }
    case 'larger':
    case 'size': {
      const size = bytes(text);
      return size === null ? null : { minSize: size };
    }
    case 'smaller': {
      const size = bytes(text);
      return size === null ? null : { maxSize: size };
    }
    case 'in':
      return 'scope';
    default:
      return null;
  }
}

/** Parses a search query. `now` is a parameter for the sake of tests. */
export function parseQuery(query: string, now = new Date()): Parsed {
  const terms = tokenize(query.trim());
  const parts: Filter[] = [];
  let words: string[] = [];
  let scope: Scope = { kind: 'default' };
  let operators = false;
  let pendingOr = false;

  const push = (part: Filter) => {
    // "a OR b": the previous condition and this one, either of them.
    if (pendingOr && parts.length > 0) {
      const previous = parts.pop()!;
      const either = previous.operator === 'OR' ? (previous.conditions as Filter[]) : [previous];
      parts.push({ operator: 'OR', conditions: [...either, part] });
    } else {
      parts.push(part);
    }
    pendingOr = false;
  };
  const flushWords = () => {
    if (words.length) parts.push({ text: words.join(' ') });
    words = [];
  };

  for (const term of terms) {
    if (term === 'OR' || term === '|') {
      operators = true;
      flushWords();
      pendingOr = true;
      continue;
    }
    const negated = term.startsWith('-') && term.length > 1;
    const body = negated ? term.slice(1) : term;
    const colon = body.indexOf(':');
    const key = colon > 0 && !body.startsWith('"') ? body.slice(0, colon).toLowerCase() : '';
    const found = key ? condition(key, body.slice(colon + 1), now) : null;
    if (found === 'scope') {
      operators = true;
      const name = unquote(body.slice(colon + 1)).trim();
      scope = name.toLowerCase() === 'anywhere' || name.toLowerCase() === 'all' ? { kind: 'anywhere' } : { kind: 'folder', name };
      continue;
    }
    if (found) {
      operators = true;
      flushWords();
      push(negated ? { operator: 'NOT', conditions: [found] } : found);
      continue;
    }
    // A plain word (or something that only looks like an operator, "re:meeting").
    const word = unquote(body);
    if (!word) continue;
    if (negated) {
      operators = true;
      flushWords();
      push({ operator: 'NOT', conditions: [{ text: word }] });
    } else if (pendingOr) {
      push({ text: word });
    } else {
      if (body.startsWith('"')) operators = true;
      words.push(word);
    }
  }
  flushWords();
  const filter: Filter = parts.length === 0 ? {} : parts.length === 1 ? parts[0] : { operator: 'AND', conditions: parts };
  return { filter, scope, operators };
}

/** Combines the conditions of a search with the folders it covers. */
export function withScope(filter: Filter, folders: Filter | null): Filter {
  if (!folders) return filter;
  if (Object.keys(filter).length === 0) return folders;
  return { operator: 'AND', conditions: [folders, filter] };
}

// --- The advanced-search form ------------------------------------------------------------

export interface SearchForm {
  from: string;
  to: string;
  subject: string;
  /** Words the message must contain. */
  words: string;
  /** Words it must not contain. */
  without: string;
  sizeOp: 'larger' | 'smaller';
  /** Empty for no size condition. */
  size: string;
  sizeUnit: 'MB' | 'KB';
  /** How far from `date` the message may be: '' for no date condition, else `1d`, `1w`, ... */
  within: '' | '1d' | '3d' | '1w' | '2w' | '1m' | '2m' | '6m' | '1y';
  /** `YYYY-MM-DD`. */
  date: string;
  /** `default`, `anywhere`, or a folder name as `in:` takes it. */
  folder: string;
  attachment: boolean;
}

export const WITHIN_LABELS: Record<Exclude<SearchForm['within'], ''>, string> = { '1d': '1 day', '3d': '3 days', '1w': '1 week', '2w': '2 weeks', '1m': '1 month', '2m': '2 months', '6m': '6 months', '1y': '1 year' };

export function emptyForm(today = new Date()): SearchForm {
  const pad = (n: number) => String(n).padStart(2, '0');
  return { from: '', to: '', subject: '', words: '', without: '', sizeOp: 'larger', size: '', sizeUnit: 'MB', within: '', date: `${today.getFullYear()}-${pad(today.getMonth() + 1)}-${pad(today.getDate())}`, folder: 'default', attachment: false };
}

const quote = (value: string) => {
  const clean = value.trim().replace(/"/g, '');
  return /\s/.test(clean) ? `"${clean}"` : clean;
};

const slashed = (date: Date) => `${date.getFullYear()}/${date.getMonth() + 1}/${date.getDate()}`;

/** The query a filled-in form stands for. */
export function formToQuery(form: SearchForm): string {
  const out: string[] = [];
  if (form.from.trim()) out.push(`from:${quote(form.from)}`);
  if (form.to.trim()) out.push(`to:${quote(form.to)}`);
  if (form.subject.trim()) out.push(`subject:${quote(form.subject)}`);
  if (form.words.trim()) out.push(form.words.trim());
  for (const word of tokenize(form.without)) out.push(`-${word}`);
  const size = Number(form.size);
  if (form.size.trim() && Number.isFinite(size) && size > 0) out.push(`${form.sizeOp}:${size}${form.sizeUnit === 'MB' ? 'M' : 'K'}`);
  const center = day(form.date);
  if (form.within && center) {
    const [amount, unit] = [Number(form.within.slice(0, -1)), form.within.slice(-1)];
    const shifted = (sign: number) => {
      const date = new Date(center);
      if (unit === 'd') date.setDate(date.getDate() + sign * amount);
      else if (unit === 'w') date.setDate(date.getDate() + sign * 7 * amount);
      else if (unit === 'm') date.setMonth(date.getMonth() + sign * amount);
      else date.setFullYear(date.getFullYear() + sign * amount);
      return date;
    };
    out.push(`after:${slashed(shifted(-1))}`, `before:${slashed(new Date(shifted(1).getTime() + DAY))}`);
  }
  if (form.attachment) out.push('has:attachment');
  if (form.folder === 'anywhere') out.push('in:anywhere');
  else if (form.folder !== 'default' && form.folder) out.push(`in:${quote(form.folder)}`);
  return out.join(' ');
}

/** Fills the form from a query, as far as the form can express it (to open it where the user is). */
export function queryToForm(query: string, today = new Date()): SearchForm {
  const form = emptyForm(today);
  const words: string[] = [];
  const without: string[] = [];
  for (const term of tokenize(query)) {
    const negated = term.startsWith('-') && term.length > 1;
    const body = negated ? term.slice(1) : term;
    const colon = body.indexOf(':');
    const key = colon > 0 ? body.slice(0, colon).toLowerCase() : '';
    const value = unquote(body.slice(colon + 1));
    if (!negated && (key === 'from' || key === 'to' || key === 'subject')) form[key] = value;
    else if (!negated && key === 'has' && value === 'attachment') form.attachment = true;
    else if (!negated && key === 'in') form.folder = value.toLowerCase() === 'anywhere' ? 'anywhere' : value;
    else if (!negated && (key === 'larger' || key === 'smaller') && bytes(value) !== null) {
      form.sizeOp = key;
      const mega = /m/i.test(value);
      form.sizeUnit = mega ? 'MB' : 'KB';
      form.size = value.replace(/[^\d.]/g, '');
    } else if (negated && !key) without.push(body);
    else if (!key) words.push(term);
  }
  form.words = words.join(' ');
  form.without = without.join(' ');
  return form;
}
