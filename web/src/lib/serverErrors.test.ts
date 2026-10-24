import { describe, expect, it } from 'vitest';
import { presentServerMessage } from './serverErrors';

describe('server error messages', () => {
  it('are shown as sentences', () => {
    expect(presentServerMessage('this address belongs to another mailbox on this server')).toBe('This address belongs to another mailbox on this server');
    // Messages without a translation still start with a capital letter.
    expect(presentServerMessage('an unlisted problem')).toBe('An unlisted problem');
    expect(presentServerMessage('AI provider returned HTTP 401')).toBe('AI provider returned HTTP 401');
    expect(presentServerMessage('')).toBe('');
  });
});
