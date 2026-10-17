// Filter rules edited visually and stored as an ordinary Sieve script.
//
// Each rule is written as a "# rule:" comment holding its description (JSON on one line),
// followed by the Sieve code made from it. Reading a script back takes the descriptions and
// regenerates the code: when that reproduces the script exactly, the rules can be edited
// visually; when it does not (the script was written or changed by hand), they cannot, and the
// script is left to the Sieve editor rather than being silently rewritten.

import { t } from '../i18n';

export type Field = 'from' | 'to' | 'cc' | 'tocc' | 'subject' | 'listid' | 'header' | 'body' | 'size';
export type Operator = 'contains' | 'notcontains' | 'is' | 'notis' | 'matches' | 'notmatches' | 'regex' | 'notregex' | 'exists' | 'notexists' | 'over' | 'under';
export type ActionType = 'move' | 'copy' | 'forward' | 'forwardcopy' | 'read' | 'star' | 'label' | 'keep' | 'discard';

export interface Condition {
  field: Field;
  /** The header's name, for `header`. */
  header?: string;
  op: Operator;
  /** Text to compare with; for size a number with an optional K or M. */
  value: string;
}

export interface Action {
  type: ActionType;
  /** Folder, address or label, for the actions that take one. */
  value: string;
}

export interface Rule {
  name: string;
  enabled: boolean;
  /** Every condition, any of them, or every message. */
  match: 'all' | 'any' | 'always';
  conditions: Condition[];
  actions: Action[];
  /** Later rules are not applied to a message this rule matched. */
  stop: boolean;
}

export const FIELDS: Field[] = ['from', 'to', 'cc', 'tocc', 'subject', 'listid', 'header', 'body', 'size'];
export const FIELD_LABELS: Record<Field, string> = {
  from: t('From'), to: t('To'), cc: t('Cc'), tocc: t('To or Cc'), subject: t('Subject'), listid: t('Mailing list (List-Id)'), header: t('Other header…'), body: t('Message text'), size: t('Size'),
};

export const OPERATOR_LABELS: Record<Operator, string> = {
  contains: t('contains'), notcontains: t('does not contain'), is: t('is'), notis: t('is not'), matches: t('matches (* and ?)'), notmatches: t('does not match (* and ?)'),
  regex: t('matches regular expression'), notregex: t('does not match regular expression'), exists: t('exists'), notexists: t('does not exist'), over: t('is larger than'), under: t('is smaller than'),
};

/** The comparisons that make sense for a field. */
export function operatorsFor(field: Field): Operator[] {
  if (field === 'size') return ['over', 'under'];
  const text: Operator[] = ['contains', 'notcontains', 'is', 'notis', 'matches', 'notmatches', 'regex', 'notregex'];
  return field === 'body' ? text : [...text, 'exists', 'notexists'];
}

export const ACTIONS: ActionType[] = ['move', 'copy', 'label', 'read', 'star', 'forward', 'forwardcopy', 'keep', 'discard'];
export const ACTION_LABELS: Record<ActionType, string> = {
  move: t('Move to folder'), copy: t('Copy to folder'), label: t('Add label'), read: t('Mark as read'), star: t('Star'), forward: t('Forward to'),
  forwardcopy: t('Forward a copy to'), keep: t('Keep in Inbox'), discard: t('Delete for good'),
};

/** What an action's value is, if it takes one. */
export function actionTarget(type: ActionType): 'folder' | 'address' | 'label' | null {
  if (type === 'move' || type === 'copy') return 'folder';
  if (type === 'forward' || type === 'forwardcopy') return 'address';
  if (type === 'label') return 'label';
  return null;
}

export const needsValue = (op: Operator) => op !== 'exists' && op !== 'notexists';

export function emptyRule(): Rule {
  return { name: '', enabled: true, match: 'all', conditions: [{ field: 'subject', op: 'contains', value: '' }], actions: [{ type: 'move', value: '' }], stop: false };
}

// --- Writing Sieve ------------------------------------------------------------------------

function quote(text: string): string {
  return `"${text.replace(/\\/g, '\\\\').replace(/"/g, '\\"')}"`;
}

const HEADER_NAMES: Partial<Record<Field, string[]>> = { from: ['from'], to: ['to'], cc: ['cc'], tocc: ['to', 'cc'], subject: ['subject'], listid: ['list-id'] };
const ADDRESS_FIELDS: Field[] = ['from', 'to', 'cc', 'tocc'];

function headerNames(condition: Condition): string[] {
  return condition.field === 'header' ? [condition.header?.trim() || 'x-unnamed'] : (HEADER_NAMES[condition.field] ?? []);
}

const list = (items: string[]) => (items.length === 1 ? quote(items[0]) : `[${items.map(quote).join(', ')}]`);

/** The Sieve test for a condition, and the extensions it needs. */
function test(condition: Condition, needs: Set<string>): string {
  const { field, op } = condition;
  if (field === 'size') {
    const limit = condition.value.trim().toUpperCase().replace(/\s+/g, '').replace(/B$/, '');
    return `size :${op === 'under' ? 'under' : 'over'} ${/^\d+[KMG]?$/.test(limit) ? limit : '0'}`;
  }
  const negated = op.startsWith('not');
  const base = (negated ? op.slice(3) : op) as 'contains' | 'is' | 'matches' | 'regex' | 'exists';
  let code: string;
  if (base === 'exists') {
    code = `exists ${list(headerNames(condition))}`;
  } else {
    if (base === 'regex') needs.add('regex');
    const key = quote(condition.value);
    if (field === 'body') {
      needs.add('body');
      code = `body :${base} ${key}`;
    } else if (ADDRESS_FIELDS.includes(field) && base !== 'contains') {
      // Exact, wildcard and pattern comparisons look at the address itself, not the name shown with it.
      code = `address :${base} ${list(headerNames(condition))} ${key}`;
    } else {
      code = `header :${base} ${list(headerNames(condition))} ${key}`;
    }
  }
  return negated ? `not ${code}` : code;
}

/** Flag changes come first: in Sieve they apply to the copies filed after them. */
const ORDER: Record<ActionType, number> = { read: 0, star: 0, label: 0, copy: 1, forwardcopy: 1, forward: 2, move: 2, keep: 2, discard: 3 };

function command(action: Action, needs: Set<string>): string {
  switch (action.type) {
    case 'move':
      needs.add('fileinto');
      return `fileinto ${quote(action.value)};`;
    case 'copy':
      needs.add('fileinto').add('copy');
      return `fileinto :copy ${quote(action.value)};`;
    case 'forward':
      return `redirect ${quote(action.value.trim())};`;
    case 'forwardcopy':
      needs.add('copy');
      return `redirect :copy ${quote(action.value.trim())};`;
    case 'read':
      needs.add('imap4flags');
      return `addflag ${quote('\\Seen')};`;
    case 'star':
      needs.add('imap4flags');
      return `addflag ${quote('\\Flagged')};`;
    case 'label':
      needs.add('imap4flags');
      return `addflag ${quote(action.value)};`;
    case 'keep':
      return 'keep;';
    case 'discard':
      return 'discard;';
  }
}

const HEADER = [
  '# Written by the unoMail filter editor (Settings, Filters, Rules).',
  '# Each "# rule:" line describes the rule below it. Changing the script by hand',
  '# turns the rules off in the visual editor.',
];

/** A rule with its fields in a fixed order, so that its description reads back identically. */
function canonical(rule: Rule): Rule {
  return {
    name: rule.name,
    enabled: rule.enabled,
    match: rule.match,
    conditions: rule.conditions.map((c) => ({ field: c.field, ...(c.field === 'header' ? { header: c.header ?? '' } : {}), op: c.op, value: c.value })),
    actions: rule.actions.map((a) => ({ type: a.type, value: a.value })),
    stop: rule.stop,
  };
}

/** The Sieve script for a list of rules; empty for none. */
export function generate(rules: Rule[]): string {
  if (rules.length === 0) return '';
  const needs = new Set<string>();
  const blocks = rules.map((rule) => {
    const description = `# rule: ${JSON.stringify(canonical(rule))}`;
    // A rule that is switched off keeps only its description.
    if (!rule.enabled) return description;
    const actions = [...rule.actions].sort((a, b) => ORDER[a.type] - ORDER[b.type]).map((action) => command(action, needs));
    if (rule.stop) actions.push('stop;');
    if (rule.match === 'always' || rule.conditions.length === 0) return [description, ...actions].join('\n');
    const tests = rule.conditions.map((condition) => test(condition, needs));
    const condition = tests.length === 1 ? tests[0] : `${rule.match === 'any' ? 'anyof' : 'allof'} (${tests.join(', ')})`;
    return [description, `if ${condition} {`, ...actions.map((line) => `    ${line}`), '}'].join('\n');
  });
  const order = ['fileinto', 'copy', 'imap4flags', 'body', 'regex'];
  const require = order.filter((extension) => needs.has(extension));
  return [...HEADER, ...(require.length ? [`require ${list(require)};`] : []), '', blocks.join('\n\n'), ''].join('\n');
}

// --- Reading it back ----------------------------------------------------------------------

const normalize = (script: string) => script.replace(/\r\n/g, '\n').replace(/[ \t]+$/gm, '').trim();

function asRule(value: unknown): Rule | null {
  if (!value || typeof value !== 'object') return null;
  const raw = value as Record<string, unknown>;
  const conditions = Array.isArray(raw.conditions) ? raw.conditions : null;
  const actions = Array.isArray(raw.actions) ? raw.actions : null;
  if (typeof raw.name !== 'string' || !conditions || !actions || !['all', 'any', 'always'].includes(raw.match as string)) return null;
  const okConditions = conditions.every((c) => c && FIELDS.includes(c.field) && Object.hasOwn(OPERATOR_LABELS, c.op) && typeof c.value === 'string');
  const okActions = actions.every((a) => a && ACTIONS.includes(a.type) && typeof a.value === 'string');
  if (!okConditions || !okActions) return null;
  return canonical({
    name: raw.name,
    enabled: raw.enabled !== false,
    match: raw.match as Rule['match'],
    conditions: conditions.map((c) => ({ field: c.field, header: String(c.header ?? ''), op: c.op, value: c.value })),
    actions: actions.map((a) => ({ type: a.type, value: a.value })),
    stop: raw.stop === true,
  });
}

/**
 * The rules a script was made from: `[]` for an empty script, `null` when it was not written by
 * this editor or was changed by hand since.
 */
export function parseRules(script: string): Rule[] | null {
  if (!script.trim()) return [];
  const rules: Rule[] = [];
  for (const line of script.replace(/\r\n/g, '\n').split('\n')) {
    const found = /^# rule: (.*)$/.exec(line);
    if (!found) continue;
    let rule: Rule | null = null;
    try {
      rule = asRule(JSON.parse(found[1]));
    } catch {
      return null;
    }
    if (!rule) return null;
    rules.push(rule);
  }
  if (rules.length === 0) return null;
  return normalize(generate(rules)) === normalize(script) ? rules : null;
}

// --- Checking and describing --------------------------------------------------------------

/** What is still missing before a rule can be saved; empty when it is complete. */
export function problems(rule: Rule): string[] {
  const found: string[] = [];
  if (!rule.name.trim()) found.push(t('Give the rule a name.'));
  if (rule.match !== 'always') {
    if (rule.conditions.length === 0) found.push(t('Add a condition, or apply the rule to every message.'));
    for (const condition of rule.conditions) {
      if (condition.field === 'header' && !/^[A-Za-z0-9-]+$/.test(condition.header?.trim() ?? '')) found.push(t('Enter the name of the header, like X-Priority.'));
      if (condition.field === 'size' && !/^\d+\s*[KMG]?B?$/i.test(condition.value.trim())) found.push(t('Enter a size, like 500K or 10M.'));
      else if (condition.field !== 'size' && needsValue(condition.op) && !condition.value) found.push(t('Enter what to compare {{field}} with.', { field: FIELD_LABELS[condition.field] }));
      if ((condition.op === 'regex' || condition.op === 'notregex') && condition.value) {
        try {
          new RegExp(condition.value);
        } catch {
          found.push(t('“{{value}}” is not a valid regular expression.', { value: condition.value }));
        }
      }
    }
  }
  if (rule.actions.length === 0) found.push(t('Add an action.'));
  for (const action of rule.actions) {
    const target = actionTarget(action.type);
    if (target === 'folder' && !action.value) found.push(t('Choose a folder.'));
    if (target === 'label' && !action.value.trim()) found.push(t('Enter a label.'));
    if (target === 'address' && !/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(action.value.trim())) found.push(t('Enter the address to forward to.'));
  }
  return [...new Set(found)];
}

/** A one-line description of a rule, for the list. */
export function summary(rule: Rule, folderLabel: (name: string) => string = (name) => name): string {
  const describe = (condition: Condition) => {
    const field = condition.field === 'header' ? condition.header || FIELD_LABELS.header : FIELD_LABELS[condition.field];
    return needsValue(condition.op) ? `${field} ${OPERATOR_LABELS[condition.op]} “${condition.value}”` : `${field} ${OPERATOR_LABELS[condition.op]}`;
  };
  const when =
    rule.match === 'always' || rule.conditions.length === 0
      ? t('Every message')
      : rule.conditions.map(describe).join(rule.match === 'any' ? t(' or ') : t(' and '));
  const what = rule.actions
    .map((action) => {
      const target = actionTarget(action.type);
      const value = target === 'folder' ? folderLabel(action.value) : action.value;
      return target ? `${ACTION_LABELS[action.type]} ${value}` : ACTION_LABELS[action.type];
    })
    .join(', ');
  return `${when} → ${what}${rule.stop ? t(', then stop') : ''}`;
}
