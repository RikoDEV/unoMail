// OpenPGP end-to-end encryption in the browser.
//
// Keys are generated and used here only. The server stores the public key (so colleagues can
// find it) and, if the user wants the key to follow them between devices, the private key in
// its passphrase-protected form. The passphrase and the unlocked key never leave the browser
// and are kept in memory only, until the tab is closed or the user signs out.

import type { Key, PrivateKey } from 'openpgp';
import { del, get, put } from '../lib/api';
import { buildEntity, type MimeAttachment } from './mime';

import { t } from '../i18n';
import { readLocal, writeLocal } from '../lib/storage';
export interface StoredKeys {
  public_key: string;
  private_key: string;
  updated_at: number;
}

export interface DecryptedAttachment {
  name: string;
  type: string;
  data: Uint8Array;
  cid?: string;
}

export interface Decrypted {
  html: string | null;
  text: string | null;
  attachments: DecryptedAttachment[];
  /** `valid` when signed by a known key of the sender, `unknown` when the key is not known. */
  signature: 'none' | 'valid' | 'invalid' | 'unknown';
}

const openpgp = () => import('openpgp');

let unlocked: PrivateKey | null = null;
let lockVersion = 0;

export const fetchKeys = () => get<StoredKeys | null>('/api/me/pgp');
export async function removeKeys(email: string): Promise<void> {
  await del('/api/me/pgp');
  writeLocal(localKey(email), null);
  lock();
}

export function isUnlocked(): boolean {
  return unlocked !== null;
}

export function lock() {
  lockVersion += 1;
  unlocked = null;
}

/** A short, human-comparable identifier of a key. */
export async function fingerprint(armoredPublicKey: string): Promise<string> {
  const { readKey } = await openpgp();
  const key = await readKey({ armoredKey: armoredPublicKey });
  return (key.getFingerprint().toUpperCase().match(/.{1,4}/g) ?? []).join(' ');
}

/** Creates a key pair for the user and stores it; `keepOnServer` decides about the private half. */
export async function generateKeys(name: string, email: string, passphrase: string, keepOnServer: boolean): Promise<StoredKeys> {
  if (passphrase.length < 10) throw new Error(t('Use a passphrase of at least 10 characters'));
  const { generateKey } = await openpgp();
  const { privateKey, publicKey } = await generateKey({ type: 'ecc', userIDs: [{ name: name || undefined, email }], passphrase, format: 'armored' });
  await put('/api/me/pgp', { public_key: publicKey, private_key: keepOnServer ? privateKey : '' });
  if (!keepOnServer) storeLocalPrivateKey(email, privateKey);
  return { public_key: publicKey, private_key: keepOnServer ? privateKey : '', updated_at: Math.floor(Date.now() / 1000) };
}

/** Imports an existing passphrase-protected private key. */
export async function importKeys(email: string, armoredPrivateKey: string, keepOnServer: boolean): Promise<void> {
  const { readPrivateKey } = await openpgp();
  const key = await readPrivateKey({ armoredKey: armoredPrivateKey.trim() });
  if (key.isDecrypted()) throw new Error(t('Protect the key with a passphrase before importing it'));
  await put('/api/me/pgp', { public_key: key.toPublic().armor(), private_key: keepOnServer ? key.armor() : '' });
  if (!keepOnServer) storeLocalPrivateKey(email, key.armor());
}

// Deliberately outside the `unomail.cache.` prefix: signing out wipes the mail cache, but must
// not destroy the only copy of a key.
const localKey = (email: string) => `unomail.pgp.${email}`;

// A private key the user chose not to store on the server lives in this browser only, still
// passphrase-protected, until the user removes it in the settings.
function storeLocalPrivateKey(email: string, armored: string) {
  if (!writeLocal(localKey(email), armored)) {
    throw new Error(t('This browser cannot store the private key; keep it on the server or export it now'));
  }
}

export function localPrivateKey(email: string): string {
  return readLocal(localKey(email)) ?? '';
}

/** Unlocks the private key with the passphrase for the rest of the session. */
export async function unlock(armoredPrivateKey: string, passphrase: string): Promise<void> {
  const version = lockVersion;
  const { readPrivateKey, decryptKey } = await openpgp();
  const key = await readPrivateKey({ armoredKey: armoredPrivateKey });
  try {
    const decrypted = await decryptKey({ privateKey: key, passphrase });
    if (version === lockVersion) unlocked = decrypted;
  } catch {
    throw new Error(t('Wrong passphrase'));
  }
}

/** Public keys the server knows for these addresses (contacts first, then local accounts). */
export async function lookupKeys(emails: string[]): Promise<Record<string, string>> {
  if (emails.length === 0) return {};
  return get<Record<string, string>>(`/api/me/pgp/lookup?emails=${encodeURIComponent(emails.join(','))}`);
}

async function readKeys(armored: string[]): Promise<Key[]> {
  const { readKey } = await openpgp();
  return Promise.all(armored.map((armoredKey) => readKey({ armoredKey })));
}

/**
 * Encrypts a message body (as one MIME entity) to the given public keys. The sender's own key
 * is expected to be among them, so the copy in the Sent folder stays readable. The message is
 * signed when the private key is unlocked.
 */
export async function encryptEntity(text: string, html: string, attachments: MimeAttachment[], recipientKeys: string[]): Promise<string> {
  const { createMessage, encrypt } = await openpgp();
  const message = await createMessage({ text: buildEntity(text, html, attachments) });
  const armored = await encrypt({ message, encryptionKeys: await readKeys(recipientKeys), signingKeys: unlocked ?? undefined, format: 'armored' });
  return armored as string;
}

/** True for armored OpenPGP messages, however they arrived. */
export function looksEncrypted(text: string): boolean {
  return text.trimStart().startsWith('-----BEGIN PGP MESSAGE-----');
}

/** Decrypts an armored message with the unlocked key and parses the MIME entity inside. */
export async function decryptArmored(armored: string, senderKeys: string[] = []): Promise<Decrypted> {
  if (!unlocked) throw new Error(t('Unlock your private key first'));
  const { readMessage, decrypt } = await openpgp();
  const message = await readMessage({ armoredMessage: armored.trim() });
  const verificationKeys = await readKeys(senderKeys).catch(() => []);
  const result = await decrypt({ message, decryptionKeys: unlocked, verificationKeys: verificationKeys.length ? verificationKeys : undefined, format: 'binary' });
  let signature: Decrypted['signature'] = 'none';
  if (result.signatures.length > 0) {
    if (verificationKeys.length === 0) signature = 'unknown';
    else signature = (await result.signatures[0].verified.then(() => true).catch(() => false)) ? 'valid' : 'invalid';
  }
  const data = result.data as Uint8Array;
  const head = new TextDecoder().decode(data.subarray(0, 2000));
  // Inline PGP carries plain text; PGP/MIME carries a complete MIME entity.
  if (!/^(content-type|mime-version):/im.test(head)) {
    return { html: null, text: new TextDecoder().decode(data), attachments: [], signature };
  }
  const { default: PostalMime } = await import('postal-mime');
  const parsed = await new PostalMime().parse(data);
  return {
    html: parsed.html ?? null,
    text: parsed.text ?? null,
    attachments: (parsed.attachments ?? []).map((file) => ({
      name: file.filename ?? 'attachment',
      type: file.mimeType || 'application/octet-stream',
      data: typeof file.content === 'string' ? new TextEncoder().encode(file.content) : new Uint8Array(file.content),
      cid: file.contentId?.replace(/^<|>$/g, '') || undefined,
    })),
    signature,
  };
}
