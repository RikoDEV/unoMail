// Error messages the server sends, in English (the server keeps one language for logs and API
// clients). Those listed here are shown in the interface language; the translation test asks
// for every one. Any message is shown as a sentence, starting with a capital letter.

import { t } from '../i18n';

export const SERVER_ERRORS = [
  // Sender identities, signatures, templates, contacts and preferences (server/src/api/personal.rs).
  'invalid e-mail address',
  'invalid reply-to address',
  'invalid SMTP host name',
  'invalid SMTP port',
  'the password is too long',
  'this address does not belong to your account; add an SMTP server to send through its own provider',
  'this address belongs to another mailbox on this server',
  'the PGP key must be an armored public key',
  'a group needs a name',
  'a template needs a name',
  'the template is too long',
  'a signature needs a name',
  'the signature is too long',
  'not one of your sender identities',
  'unknown signature',
  'preferences must be an object',
  'preferences are too large',
  'the stored private key cannot be decrypted; save it again',
  'an armored public key is required',
  'the private key must be an armored, passphrase-protected key',
  'a contact with this address already exists',
  "the address of your primary identity is your account's own address",
  'your own address is always sent by this server',
  'your primary identity cannot be deleted',
];

/** A server message as the interface shows it: translated when known, always capitalised. */
export function presentServerMessage(message: string): string {
  const shown = SERVER_ERRORS.includes(message) ? t(message) : message;
  return shown.charAt(0).toLocaleUpperCase() + shown.slice(1);
}
