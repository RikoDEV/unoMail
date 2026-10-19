import { describe, expect, it } from 'vitest';
import { matchingRules } from './SpamFilter';

const rules = [
  { symbol: 'DMARC_NA', weight: 0, description: 'No DMARC record', group: 'policies' },
  { symbol: 'DMARC_NA_DNSFAIL', weight: 2, description: 'DMARC lookup failed', group: 'policies' },
  { symbol: 'OTHER_RULE', weight: 5, description: 'Mentions DMARC_NA for context', group: 'other' },
];

describe('spam-filter rule search', () => {
  it('returns only an exact symbol match when one exists', () => {
    expect(matchingRules(rules, 'dmarc_na').map((rule) => rule.symbol)).toEqual(['DMARC_NA']);
  });

  it('keeps broad matching for partial searches', () => {
    expect(matchingRules(rules, 'lookup').map((rule) => rule.symbol)).toEqual(['DMARC_NA_DNSFAIL']);
    expect(matchingRules(rules, 'policies').map((rule) => rule.symbol)).toEqual(['DMARC_NA_DNSFAIL', 'DMARC_NA']);
  });
});
