import { describe, expect, it } from 'vitest';
import { parseMailto } from './mailto';

describe('parseMailto', () => {
  it('reads recipients, subject and body', () => {
    expect(parseMailto('mailto:a@example.com,b@example.com?cc=c@example.com&bcc=d@example.com&subject=Hello%20there&body=Line%201%0D%0A%0D%0ALine%202')).toEqual({
      to: 'a@example.com, b@example.com',
      cc: 'c@example.com',
      bcc: 'd@example.com',
      subject: 'Hello there',
      html: '<p>Line 1</p><p><br></p><p>Line 2</p>',
    });
  });

  it('adds "to" fields to the address part, keeps "+" and decodes names', () => {
    const draft = parseMailto('MAILTO:?To=x%2Btag@example.com&SUBJECT=1+1')!;
    expect(draft.to).toBe('x+tag@example.com');
    expect(draft.subject).toBe('1+1');
    expect(parseMailto('mailto:%22Ann%20B%22%20%3Cann@example.com%3E')!.to).toBe('"Ann B" <ann@example.com>');
  });

  it('escapes the body and ignores other header fields', () => {
    const draft = parseMailto('mailto:a@example.com?body=%3Cimg%20src=x%20onerror=alert(1)%3E&from=boss@example.com&in-reply-to=x')!;
    expect(draft.html).toBe('<p>&lt;img src=x onerror=alert(1)&gt;</p>');
    expect(Object.keys(draft)).toEqual(['to', 'cc', 'bcc', 'subject', 'html']);
  });

  it('survives bad escapes and rejects other schemes', () => {
    expect(parseMailto('mailto:a@example.com?subject=100%')!.subject).toBe('100%');
    expect(parseMailto('https://example.com')).toBeNull();
  });
});
