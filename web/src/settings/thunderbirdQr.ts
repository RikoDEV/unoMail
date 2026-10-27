/**
 * The payload of Thunderbird's "Export for Mobile" QR code (format version 1), which
 * Thunderbird for Android reads under "Import settings":
 * https://github.com/thunderbird/thunderbird-android/blob/main/feature/migration/qrcode/qr-code-format.md
 */

/** What the server tells a mail program, plus the password the code carries. */
export interface ClientSetup {
  email: string;
  display_name: string;
  hostname: string;
  imap_port: number;
  smtp_port: number;
}

const IMAP = 0;
const SMTP = 0;
const TLS = 3;
const PASSWORD_CLEARTEXT = 1;

/** The format allows only ASCII host names and addresses. */
export const fitsQrFormat = (setup: Pick<ClientSetup, 'email' | 'hostname'>) => /^[\x21-\x7e]+$/.test(setup.email) && /^[\x21-\x7e]+$/.test(setup.hostname);

/** One IMAP account with its SMTP server, both over TLS with the given password. */
export function thunderbirdPayload(setup: ClientSetup, password: string): string {
  const { email, hostname } = setup;
  return JSON.stringify([
    1,
    [1, 1],
    // An empty account name stands for the address of the first identity.
    [IMAP, hostname, setup.imap_port, TLS, PASSWORD_CLEARTEXT, email, '', password],
    [[[SMTP, hostname, setup.smtp_port, TLS, PASSWORD_CLEARTEXT, email, password], [email, setup.display_name || email]]],
  ]);
}
