import { describe, expect, it } from 'vitest';
import { fitsQrFormat, thunderbirdPayload } from './thunderbirdQr';

const setup = { email: 'jane@example.org', display_name: 'Jane Doe', hostname: 'mail.example.org', imap_port: 993, smtp_port: 465 };

describe('Thunderbird QR code', () => {
  it('describes one IMAP account with its SMTP server in format version 1', () => {
    expect(JSON.parse(thunderbirdPayload(setup, 'abcd-efgh'))).toEqual([
      1,
      [1, 1],
      [0, 'mail.example.org', 993, 3, 1, 'jane@example.org', '', 'abcd-efgh'],
      [[[0, 'mail.example.org', 465, 3, 1, 'jane@example.org', 'abcd-efgh'], ['jane@example.org', 'Jane Doe']]],
    ]);
  });

  it('names the identity by its address when the account has no name', () => {
    expect(JSON.parse(thunderbirdPayload({ ...setup, display_name: '' }, 'x'))[3][0][1]).toEqual(['jane@example.org', 'jane@example.org']);
  });

  it('accepts ASCII addresses only', () => {
    expect(fitsQrFormat(setup)).toBe(true);
    expect(fitsQrFormat({ ...setup, email: 'zoë@example.org' })).toBe(false);
  });
});
