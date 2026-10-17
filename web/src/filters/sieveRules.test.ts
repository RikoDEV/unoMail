import { describe, expect, it } from 'vitest';
import { emptyRule, generate, parseRules, problems, type Rule, summary } from './sieveRules';

const receipts: Rule = {
  name: 'Receipts',
  enabled: true,
  match: 'any',
  conditions: [
    { field: 'subject', op: 'contains', value: 'receipt' },
    { field: 'from', op: 'is', value: 'shop@example.com' },
  ],
  actions: [
    { type: 'move', value: 'Receipts' },
    { type: 'read', value: '' },
  ],
  stop: true,
};

describe('filter rules', () => {
  it('writes Sieve with only the extensions it uses', () => {
    const script = generate([receipts]);
    expect(script).toContain('require ["fileinto", "imap4flags"];');
    // Flags first, so the filed copy carries them; names from From are compared as addresses.
    expect(script).toContain(
      ['if anyof (header :contains "subject" "receipt", address :is "from" "shop@example.com") {', '    addflag "\\\\Seen";', '    fileinto "Receipts";', '    stop;', '}'].join('\n'),
    );
    expect(generate([])).toBe('');
  });

  it('reads its own scripts back, and refuses ones changed by hand', () => {
    const script = generate([receipts]);
    expect(parseRules(script)).toEqual([receipts]);
    expect(parseRules(script.replace(/\n/g, '\r\n'))).toEqual([receipts]);
    expect(parseRules('')).toEqual([]);
    expect(parseRules(script.replace('fileinto "Receipts"', 'fileinto "Elsewhere"'))).toBeNull();
    expect(parseRules('require "fileinto";\nfileinto "x";\n')).toBeNull();
    expect(parseRules(script.replace('"name":"Receipts"', '"name":'))).toBeNull();
  });

  it('escapes what it quotes, and handles every kind of condition', () => {
    const rule: Rule = {
      ...emptyRule(),
      name: 'Odd "one"',
      match: 'all',
      conditions: [
        { field: 'subject', op: 'notcontains', value: 'say "hi" \\ there' },
        { field: 'tocc', op: 'matches', value: '*@lists.example' },
        { field: 'header', header: 'X-Priority', op: 'exists', value: '' },
        { field: 'listid', op: 'notexists', value: '' },
        { field: 'body', op: 'regex', value: 'invoice [0-9]+' },
        { field: 'size', op: 'over', value: '500 kb' },
      ],
      actions: [{ type: 'forwardcopy', value: ' boss@example.com ' }, { type: 'label', value: 'work' }],
    };
    const script = generate([rule]);
    expect(script).toContain('require ["copy", "imap4flags", "body", "regex"];');
    expect(script).toContain('not header :contains "subject" "say \\"hi\\" \\\\ there"');
    expect(script).toContain('address :matches ["to", "cc"] "*@lists.example"');
    expect(script).toContain('exists "X-Priority"');
    expect(script).toContain('not exists "list-id"');
    expect(script).toContain('body :regex "invoice [0-9]+"');
    expect(script).toContain('size :over 500K');
    expect(script).toContain('redirect :copy "boss@example.com";');
    expect(parseRules(script)).toEqual([rule]);
  });

  it('keeps rules that are switched off without running them', () => {
    const off = { ...receipts, enabled: false };
    const always: Rule = { ...emptyRule(), name: 'Everything', match: 'always', conditions: [], actions: [{ type: 'star', value: '' }] };
    const script = generate([off, always]);
    expect(script).not.toContain('fileinto');
    expect(script).toContain('\naddflag "\\\\Flagged";\n');
    expect(parseRules(script)).toEqual([off, always]);
  });

  it('says what is missing and describes rules', () => {
    expect(problems(receipts)).toEqual([]);
    expect(problems(emptyRule())).toEqual(['Give the rule a name.', 'Enter what to compare Subject with.', 'Choose a folder.']);
    expect(problems({ ...receipts, actions: [{ type: 'forward', value: 'nobody' }] })).toEqual(['Enter the address to forward to.']);
    expect(problems({ ...receipts, conditions: [{ field: 'body', op: 'regex', value: '(' }] })).toEqual(['“(” is not a valid regular expression.']);
    expect(summary(receipts)).toBe('Subject contains “receipt” or From is “shop@example.com” → Move to folder Receipts, Mark as read, then stop');
  });
});
