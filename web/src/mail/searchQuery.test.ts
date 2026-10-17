import { describe, expect, it } from 'vitest';
import { bytes, emptyForm, formToQuery, parseQuery, queryToForm, tokenize, withScope } from './searchQuery';

const now = new Date(2026, 9, 14, 12, 0);
const midnight = (y: number, m: number, d: number) => new Date(y, m - 1, d).toISOString();

describe('search queries', () => {
  it('keeps plain searches plain', () => {
    expect(parseQuery('quarterly report', now)).toEqual({ filter: { text: 'quarterly report' }, scope: { kind: 'default' }, operators: false });
    expect(parseQuery('   ', now).filter).toEqual({});
    expect(tokenize('from:"Anna Kowalska" "exact words" x')).toEqual(['from:"Anna Kowalska"', '"exact words"', 'x']);
  });

  it('understands Gmail operators', () => {
    expect(parseQuery('from:anna@partner.example', now).filter).toEqual({ from: 'anna@partner.example' });
    expect(parseQuery('from:"Anna Kowalska" report', now).filter).toEqual({ operator: 'AND', conditions: [{ from: 'Anna Kowalska' }, { text: 'report' }] });
    expect(parseQuery('to:bob cc:carol bcc:dan subject:invoice', now).filter).toEqual({ operator: 'AND', conditions: [{ to: 'bob' }, { cc: 'carol' }, { bcc: 'dan' }, { subject: 'invoice' }] });
    expect(parseQuery('has:attachment filename:pdf', now).filter).toEqual({ operator: 'AND', conditions: [{ hasAttachment: true }, { attachmentName: 'pdf' }] });
    expect(parseQuery('is:unread', now).filter).toEqual({ notKeyword: '$seen' });
    expect(parseQuery('is:starred', now).filter).toEqual({ hasKeyword: '$flagged' });
    expect(parseQuery('label:Work Stuff', now).filter).toEqual({ operator: 'AND', conditions: [{ hasKeyword: 'work' }, { text: 'Stuff' }] });
    expect(parseQuery('category:promotions', now).filter).toEqual({ category: 'offers' });
    expect(parseQuery('larger:10M', now).filter).toEqual({ minSize: 10 * 1024 * 1024 });
    expect(parseQuery('smaller:500K', now).filter).toEqual({ maxSize: 500 * 1024 });
    expect(parseQuery('before:2026/10/01 after:2026-09-01', now).filter).toEqual({ operator: 'AND', conditions: [{ before: midnight(2026, 10, 1) }, { after: midnight(2026, 9, 1) }] });
    expect(parseQuery('newer_than:2d', now).filter).toEqual({ after: new Date(2026, 9, 12, 12, 0).toISOString() });
    expect(parseQuery('older_than:1y', now).filter).toEqual({ before: new Date(2025, 9, 14, 12, 0).toISOString() });
    expect(parseQuery('a', now).operators).toBe(false);
    expect(parseQuery('from:a', now).operators).toBe(true);
  });

  it('negates, alternates and scopes', () => {
    expect(parseQuery('report -draft', now).filter).toEqual({ operator: 'AND', conditions: [{ text: 'report' }, { operator: 'NOT', conditions: [{ text: 'draft' }] }] });
    expect(parseQuery('-from:boss', now).filter).toEqual({ operator: 'NOT', conditions: [{ from: 'boss' }] });
    expect(parseQuery('from:anna OR from:jan OR subject:x', now).filter).toEqual({ operator: 'OR', conditions: [{ from: 'anna' }, { from: 'jan' }, { subject: 'x' }] });
    expect(parseQuery('lunch OR dinner', now).filter).toEqual({ operator: 'OR', conditions: [{ text: 'lunch' }, { text: 'dinner' }] });
    expect(parseQuery('in:anywhere x', now).scope).toEqual({ kind: 'anywhere' });
    expect(parseQuery('in:sent', now)).toEqual({ filter: {}, scope: { kind: 'folder', name: 'sent' }, operators: true });
    expect(parseQuery('in:"Project Apollo"', now).scope).toEqual({ kind: 'folder', name: 'Project Apollo' });
    // Things that only look like operators are words.
    expect(parseQuery('re:meeting before:soon', now).filter).toEqual({ text: 're:meeting before:soon' });
    expect(withScope({ text: 'x' }, { inMailbox: 'b1' })).toEqual({ operator: 'AND', conditions: [{ inMailbox: 'b1' }, { text: 'x' }] });
    expect(withScope({}, { inMailbox: 'b1' })).toEqual({ inMailbox: 'b1' });
    expect(withScope({ text: 'x' }, null)).toEqual({ text: 'x' });
  });

  it('reads sizes', () => {
    expect([bytes('2000'), bytes('1k'), bytes('1.5M'), bytes('1GB'), bytes('big')]).toEqual([2000, 1024, 1572864, 1073741824, null]);
  });

  it('turns the advanced form into a query and back', () => {
    const today = new Date(2026, 9, 14);
    const form = { ...emptyForm(today), from: 'Anna Kowalska', to: 'bob', subject: 'report', words: 'numbers quarter', without: 'draft old', size: '5', sizeOp: 'larger' as const, attachment: true, folder: 'anywhere' };
    const query = formToQuery(form);
    expect(query).toBe('from:"Anna Kowalska" to:bob subject:report numbers quarter -draft -old larger:5M has:attachment in:anywhere');
    expect(queryToForm(query, today)).toEqual({ ...form, sizeUnit: 'MB' });
    expect(formToQuery({ ...emptyForm(today), within: '1w', date: '2026-10-14' })).toBe('after:2026/10/7 before:2026/10/22');
    expect(formToQuery({ ...emptyForm(today), size: '200', sizeOp: 'smaller', sizeUnit: 'KB', folder: 'Project Apollo' })).toBe('smaller:200K in:"Project Apollo"');
    expect(formToQuery(emptyForm(today))).toBe('');
    // A query the form produced finds the same thing as the form says.
    const parsed = parseQuery(query, today).filter as { conditions: unknown[] };
    expect(parsed.conditions).toContainEqual({ from: 'Anna Kowalska' });
    expect(parsed.conditions).toContainEqual({ operator: 'NOT', conditions: [{ text: 'old' }] });
  });
});
