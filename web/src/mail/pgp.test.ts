// @vitest-environment node
import { beforeAll, describe, expect, it, vi } from 'vitest';

const saved: { public_key?: string; private_key?: string } = {};
vi.mock('../api', () => ({
  get: vi.fn(),
  del: vi.fn(),
  put: vi.fn(async (_path: string, body: { public_key: string; private_key: string }) => Object.assign(saved, body)),
}));

import { buildEncryptedMessage, buildEntity, buildHeaders, encodeHeaderText, formatMimeAddress } from './mime';
import { decryptArmored, encryptEntity, fingerprint, generateKeys, isUnlocked, lock, looksEncrypted, unlock } from './pgp';

const PASSPHRASE = 'correct horse battery';

describe('message building', () => {
  it('encodes non-ASCII header text and never lets values break out of their header', () => {
    expect(encodeHeaderText('Plain subject')).toBe('Plain subject');
    const encoded = encodeHeaderText('Zażółć gęślą jaźń — pchnąć w tę łódź jeża lub ośm skrzyń fig');
    expect(encoded.split('\r\n ').every((word) => /^=\?UTF-8\?B\?[A-Za-z0-9+/=]+\?=$/.test(word) && word.length <= 75)).toBe(true);
    const bytes = encoded.split('\r\n ').flatMap((word) => Array.from(atob(word.slice(10, -2)), (c) => c.charCodeAt(0)));
    const decoded = new TextDecoder().decode(new Uint8Array(bytes));
    expect(decoded).toBe('Zażółć gęślą jaźń — pchnąć w tę łódź jeża lub ośm skrzyń fig');

    const headers = buildHeaders({ from: { name: 'Bob', email: 'bob@example.org' }, to: [{ email: 'ann@remote.example' }], cc: [], bcc: [], subject: 'Hello\r\nBcc: evil@remote.example' });
    expect(headers).toContain('Subject: Hello Bcc: evil@remote.example\r\n');
    expect(headers.split('\r\n').filter((line) => /^bcc:/i.test(line))).toEqual([]);
    expect(formatMimeAddress({ name: 'Evil" <x@y.example>\r\nBcc: z@y.example', email: 'a@b.example' })).toBe('"Evil\\" <x@y.example> Bcc: z@y.example" <a@b.example>');
    expect(formatMimeAddress({ name: null, email: 'a@b.example>\r\nBcc: <c@d.example' })).toBe('a@b.exampleBcc:c@d.example');
  });

  it('wraps an armored message as PGP/MIME', () => {
    const message = buildEncryptedMessage({ from: { email: 'bob@example.org' }, to: [{ email: 'ann@remote.example' }], cc: [], bcc: [], subject: 'Secret', inReplyTo: ['a@b'], references: ['x@y', 'a@b'] }, '-----BEGIN PGP MESSAGE-----\n\nabc\n-----END PGP MESSAGE-----\n');
    expect(message).toMatch(/Content-Type: multipart\/encrypted; boundary="[^"]+"; protocol="application\/pgp-encrypted"/);
    expect(message).toContain('Content-Type: application/pgp-encrypted');
    expect(message).toContain('In-Reply-To: <a@b>\r\nReferences: <x@y> <a@b>\r\n');
    expect(message).toContain('-----BEGIN PGP MESSAGE-----\r\n\r\nabc\r\n-----END PGP MESSAGE-----');
    expect(message.includes('\n') && !/[^\r]\n/.test(message)).toBe(true);
  });
});

describe('OpenPGP', () => {
  beforeAll(async () => {
    await generateKeys('Bob Example', 'bob@example.org', PASSPHRASE, true);
  }, 60_000);

  it('generates a protected key pair and refuses weak passphrases', async () => {
    expect(saved.public_key).toContain('BEGIN PGP PUBLIC KEY BLOCK');
    expect(saved.private_key).toContain('BEGIN PGP PRIVATE KEY BLOCK');
    expect(await fingerprint(saved.public_key!)).toMatch(/^([0-9A-F]{4} ){9}[0-9A-F]{4}$/);
    await expect(generateKeys('x', 'x@example.org', 'short', true)).rejects.toThrow('at least 10 characters');
  });

  it('unlocks only with the right passphrase', async () => {
    lock();
    await expect(unlock(saved.private_key!, 'wrong passphrase!')).rejects.toThrow('Wrong passphrase');
    expect(isUnlocked()).toBe(false);
    await unlock(saved.private_key!, PASSPHRASE);
    expect(isUnlocked()).toBe(true);
  });

  it('encrypts, signs and decrypts a message with attachments', async () => {
    await unlock(saved.private_key!, PASSPHRASE);
    const attachment = { name: 'plan – ściśle tajne.txt', type: 'text/plain', data: new TextEncoder().encode('the secret plan') };
    const armored = await encryptEntity('Top secret text', '<p>Top <b>secret</b> text</p>', [attachment], [saved.public_key!]);
    expect(looksEncrypted(armored)).toBe(true);
    expect(armored).not.toContain('secret plan');

    const opened = await decryptArmored(armored, [saved.public_key!]);
    expect(opened.html).toContain('<b>secret</b>');
    expect(opened.text?.trim()).toBe('Top secret text');
    expect(opened.signature).toBe('valid');
    expect(opened.attachments).toHaveLength(1);
    expect(opened.attachments[0].name).toBe('plan – ściśle tajne.txt');
    expect(new TextDecoder().decode(opened.attachments[0].data)).toBe('the secret plan');

    // Without the sender's key the signature cannot be judged; a damaged message is refused.
    expect((await decryptArmored(armored)).signature).toBe('unknown');
    const lines = armored.split('\n');
    lines[4] = lines[4].split('').reverse().join('');
    await expect(decryptArmored(lines.join('\n'), [saved.public_key!])).rejects.toThrow();

    lock();
    await expect(decryptArmored(armored)).rejects.toThrow('Unlock your private key first');
  }, 60_000);

  it('reads inline PGP messages as plain text', async () => {
    const { createMessage, encrypt, readKey } = await import('openpgp');
    const armored = (await encrypt({ message: await createMessage({ text: 'just a note' }), encryptionKeys: await readKey({ armoredKey: saved.public_key! }) })) as string;
    await unlock(saved.private_key!, PASSPHRASE);
    expect(await decryptArmored(armored)).toEqual({ html: null, text: 'just a note', attachments: [], signature: 'none' });
    expect(buildEntity('a', '<p>a</p>', [])).toContain('multipart/alternative');
  }, 60_000);
});
