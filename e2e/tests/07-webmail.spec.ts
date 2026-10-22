import { expect, test, type Page } from '@playwright/test';
import crypto from 'node:crypto';
import fs from 'node:fs';
import http from 'node:http';
import type { AddressInfo } from 'node:net';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { ADMIN, DOMAIN, login, logout, openAdmin, PORTS, smtpDeliver, USER_PASSWORD } from './helpers';

const ALICE = `alice@${DOMAIN}`;
const BOB = `bob@${DOMAIN}`;
const dataDir = path.join(path.dirname(fileURLToPath(import.meta.url)), '..', '.data');
// A 1x1 transparent PNG.
const PNG = Buffer.from('iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAYAAAAfFcSJAAAADUlEQVR42mP8z8BQDwAEhQGAhKmMIQAAAABJRU5ErkJggg==', 'base64');

interface Recorded {
  url: string;
  headers: http.IncomingHttpHeaders;
  body: string;
}

/** Starts a local HTTP server standing in for a remote service; returns its port and requests. */
async function standIn(handler: (request: Recorded, response: http.ServerResponse) => void): Promise<{ port: number; requests: Recorded[]; close: () => void }> {
  const requests: Recorded[] = [];
  const server = http.createServer((req, res) => {
    let body = '';
    req.on('data', (chunk) => (body += chunk));
    req.on('end', () => {
      const recorded = { url: req.url ?? '', headers: req.headers, body };
      requests.push(recorded);
      handler(recorded, res);
    });
  });
  await new Promise<void>((resolve) => server.listen(0, '127.0.0.1', resolve));
  return { port: (server.address() as AddressInfo).port, requests, close: () => server.close() };
}

async function openSettings(page: Page, tab?: string) {
  await page.getByRole('button', { name: 'Account menu' }).click();
  await page.getByRole('menuitem', { name: 'Settings' }).click();
  await expect(page.getByRole('heading', { name: 'Settings', level: 1 })).toBeVisible();
  if (tab) await page.getByRole('navigation', { name: 'Settings sections' }).getByRole('button', { name: tab }).click();
}

const conversation = (page: Page) => page.getByRole('region', { name: 'Conversation' });
const body = (page: Page) => conversation(page).frameLocator('iframe[title="Message body"]');
const composer = (page: Page) => page.getByRole('dialog', { name: 'New message' });
const folders = (page: Page) => page.getByRole('navigation', { name: 'Folders' });

test.describe('web mail extras', () => {
  test('remote images are shown on request, through the server and never directly', async ({ page }) => {
    const images = await standIn((_request, response) => {
      response.writeHead(200, { 'content-type': 'image/png' });
      response.end(PNG);
    });
    const html = (subject: string) => `From: News <news@remote.test>\nTo: ${BOB}\nSubject: ${subject}\nMIME-Version: 1.0\nContent-Type: text/html; charset=utf-8\n\n<p>Our news</p><img src="http://127.0.0.1:${images.port}/banner.png" alt="Banner">\n`;
    await smtpDeliver('news@remote.test', BOB, html('Newsletter one'));
    await smtpDeliver('news@remote.test', BOB, html('Newsletter two'));

    await login(page, BOB, USER_PASSWORD);
    await page.getByTestId('email-row').filter({ hasText: 'Newsletter one' }).click();
    await expect(body(page).getByText('Our news')).toBeVisible();
    await expect(page.getByText('Remote images are hidden to protect your privacy.')).toBeVisible();
    expect(await body(page).locator('img').getAttribute('src')).toBeNull();
    expect(images.requests).toHaveLength(0);

    await page.getByRole('button', { name: 'Show images' }).click();
    await expect(body(page).locator('img')).toHaveAttribute('src', /^\/api\/me\/image-proxy\?url=http%3A%2F%2F127\.0\.0\.1/);
    await expect.poll(() => images.requests.length).toBe(1);
    // The sender learns nothing about the reader: no cookie, no referrer.
    expect(images.requests[0].headers.cookie).toBeUndefined();
    expect(images.requests[0].headers.referer).toBeUndefined();
    expect(images.requests[0].url).toBe('/banner.png');
    await expect(page.getByText('Remote images are hidden to protect your privacy.')).toBeHidden();

    // Trusting the sender applies to their other messages, also after a reload.
    await page.getByRole('button', { name: 'Back to list' }).click();
    await page.getByTestId('email-row').filter({ hasText: 'Newsletter two' }).click();
    await page.getByRole('button', { name: 'Always from this sender' }).click();
    await expect.poll(() => images.requests.length).toBe(2);
    await page.reload();
    await expect(body(page).locator('img')).toHaveAttribute('src', /image-proxy/);
    await expect(page.getByText('Remote images are hidden to protect your privacy.')).toBeHidden();
    await expect.poll(() => images.requests.length).toBe(3);
    images.close();
  });

  test('identities, signatures, templates, contacts and recipient suggestions', async ({ page }) => {
    await login(page, BOB, USER_PASSWORD);
    await openSettings(page, 'Identities');

    // An alias that delivers to Bob can become an identity; a stranger's address cannot.
    await page.getByRole('button', { name: 'Add identity' }).click();
    let dialog = page.getByRole('dialog');
    await dialog.getByLabel('Display name').fill('Team Example');
    await dialog.getByLabel('E-mail address').fill(`team@${DOMAIN}`);
    await dialog.getByRole('button', { name: 'Save identity' }).click();
    await expect(page.getByRole('table', { name: 'Identities' }).getByRole('row', { name: new RegExp(`team@${DOMAIN}`) })).toContainText('Team Example');
    await page.getByRole('button', { name: 'Add identity' }).click();
    dialog = page.getByRole('dialog');
    await dialog.getByLabel('E-mail address').fill('ceo@elsewhere.test');
    await dialog.getByRole('button', { name: 'Save identity' }).click();
    await expect(dialog.getByRole('alert')).toContainText('does not belong to your account');
    await dialog.getByRole('button', { name: 'Cancel' }).click();

    // A signature, used by the team address for new messages.
    await page.getByRole('navigation', { name: 'Settings sections' }).getByRole('button', { name: 'Signatures' }).click();
    await page.getByRole('button', { name: 'Add signature' }).click();
    dialog = page.getByRole('dialog');
    await dialog.getByLabel('Signature name').fill('Team');
    await dialog.getByRole('textbox', { name: 'Signature text' }).fill('Kind regards,\nThe whole team');
    await dialog.getByRole('button', { name: 'Save signature' }).click();
    await expect(page.getByRole('table', { name: 'Signatures' }).getByRole('row', { name: /Team/ })).toContainText('The whole team');
    await page.getByRole('combobox', { name: `For new messages from team@${DOMAIN}` }).click();
    await page.getByRole('option', { name: 'Team' }).click();
    await expect(page.getByRole('combobox', { name: `For new messages from team@${DOMAIN}` })).toHaveText('Team');

    await page.getByRole('navigation', { name: 'Settings sections' }).getByRole('button', { name: 'Templates' }).click();
    await page.getByRole('button', { name: 'Add template' }).click();
    dialog = page.getByRole('dialog');
    await dialog.getByLabel('Template name').fill('Thanks');
    await dialog.getByLabel('Template subject').fill('Thank you for writing');
    await dialog.getByLabel('Template text').fill('We received your message and will answer soon.');
    await dialog.getByRole('button', { name: 'Save template' }).click();
    await expect(page.getByRole('table', { name: 'Templates' }).getByRole('row', { name: /Thanks/ })).toBeVisible();

    // Address book: a contact, a group, and writing straight from the list.
    await page.goto('/contacts');
    await page.getByRole('button', { name: 'New contact' }).click();
    dialog = page.getByRole('dialog');
    await dialog.getByLabel('Name').fill('Carla Contact');
    await dialog.getByLabel('E-mail address').fill('Carla@Remote.test');
    await dialog.getByLabel('Organization').fill('Remote Ltd');
    await dialog.getByRole('button', { name: 'Save' }).click();
    await expect(page.getByRole('table', { name: 'Contacts' }).getByRole('row', { name: /carla@remote\.test/ })).toContainText('Remote Ltd');
    page.once('dialog', (prompt) => void prompt.accept('Friends'));
    await page.getByRole('button', { name: 'New group' }).click();
    await expect(page.getByRole('navigation', { name: 'Contact groups' }).getByText('Friends')).toBeVisible();
    await page.getByRole('button', { name: 'Edit carla@remote.test' }).click();
    dialog = page.getByRole('dialog');
    await dialog.getByLabel('Friends').check();
    await dialog.getByRole('button', { name: 'Save' }).click();
    await expect(page.getByRole('navigation', { name: 'Contact groups' }).getByText('1 member')).toBeVisible();
    await page.getByRole('navigation', { name: 'Contact groups' }).getByText('Friends').click();
    await expect(page.getByRole('table', { name: 'Contacts' }).getByRole('row')).toHaveCount(2);

    await page.getByRole('button', { name: 'Write to carla@remote.test' }).click();
    await expect(composer(page).getByLabel('To')).toHaveValue('Carla Contact <carla@remote.test>');
    await composer(page).getByRole('button', { name: 'Discard draft' }).click();

    // Composer: suggestions from the address book, its groups and the domain directory.
    await page.getByRole('button', { name: 'Compose' }).click();
    const to = composer(page).getByLabel('To');
    await to.pressSequentially('frie');
    await expect(page.getByRole('option', { name: /Friends \(1 person\)/ })).toBeVisible();
    await to.fill('');
    await to.pressSequentially('carl');
    await expect(page.getByRole('option', { name: /Carla Contact/ })).toBeVisible();
    await to.fill('');
    await to.pressSequentially('ali');
    await expect(page.getByRole('option', { name: /Alice Example/ })).toContainText('Colleague');
    await to.press('Enter');
    await expect(to).toHaveValue(`Alice Example <${ALICE}>, `);

    // Sending as the other identity brings its signature; a template fills in the rest.
    const editor = composer(page).getByRole('textbox', { name: 'Message body' });
    await composer(page).getByRole('combobox', { name: 'From' }).click();
    await page.getByRole('option', { name: new RegExp(`team@${DOMAIN}`) }).click();
    await expect(editor).toContainText('The whole team');
    // Another signature (or none) can be picked for this message.
    await composer(page).getByRole('button', { name: 'Signature' }).click();
    await page.getByRole('menuitem', { name: 'No signature' }).click();
    await expect(editor).not.toContainText('The whole team');
    await composer(page).getByRole('button', { name: 'Signature' }).click();
    await page.getByRole('menuitem', { name: 'Team' }).click();
    await expect(editor).toContainText('The whole team');
    await editor.click();
    await page.keyboard.press('Control+Home');
    await composer(page).getByRole('button', { name: 'Templates' }).click();
    await page.getByRole('menuitem', { name: /Thanks/ }).click();
    await expect(composer(page).getByLabel('Subject')).toHaveValue('Thank you for writing');
    await expect(editor).toContainText('We received your message and will answer soon.');
    await composer(page).getByRole('button', { name: 'Send' }).click();
    await expect(page.getByText('Message sent')).toBeVisible();
    await logout(page);

    await login(page, ALICE, USER_PASSWORD);
    const received = page.getByTestId('email-row').filter({ hasText: 'Thank you for writing' });
    // Sent mail leaves after the undo window, so the reply takes a moment.
    await expect(received).toContainText('Team Example', { timeout: 20_000 });
    await received.click();
    await expect(body(page).getByText('We received your message and will answer soon.')).toBeVisible();
    await expect(body(page).getByText('The whole team')).toBeVisible();
    // Replying to mail sent to the alias answers from the alias identity... for Bob, who owns it.
    await logout(page);
  });

  test('drag and drop, folder export and import, and sharing a folder', async ({ page }) => {
    await smtpDeliver('ann@remote.test', BOB, `From: ann@remote.test\nTo: ${BOB}\nSubject: Drag me to projects\n\nplan\n`);
    await smtpDeliver('ann@remote.test', BOB, `From: ann@remote.test\nTo: ${BOB}\nSubject: Label me by dropping\n\nx\n`);
    await login(page, BOB, USER_PASSWORD);
    await folders(page).getByText('New folder').click();
    await page.getByLabel('Folder name').fill('Projects');
    await page.getByRole('button', { name: 'Create' }).click();
    const projects = page.getByTestId('folder').filter({ has: page.getByText('Projects', { exact: true }) });
    await expect(projects).toBeVisible();

    // Dragging a conversation onto a folder moves it there.
    await page.getByTestId('email-row').filter({ hasText: 'Drag me to projects' }).dragTo(projects);
    await expect(page.getByText('Moved to Projects')).toBeVisible();
    await expect(page.getByTestId('email-row').filter({ hasText: 'Drag me to projects' })).toHaveCount(0);
    await projects.click();
    await expect(page.getByTestId('email-row').filter({ hasText: 'Drag me to projects' })).toHaveCount(1);

    // Dragging onto a label applies the label.
    await page.getByTestId('email-row').filter({ hasText: 'Drag me to projects' }).click();
    await page.getByRole('button', { name: 'Labels' }).click();
    await page.getByLabel('New label').fill('dropzone');
    await page.keyboard.press('Enter');
    const label = page.getByRole('list', { name: 'Labels' }).getByText('dropzone', { exact: true });
    await expect(label).toBeVisible();
    await folders(page).getByText('Inbox', { exact: true }).click();
    const loose = page.getByTestId('email-row').filter({ hasText: 'Label me by dropping' });
    await loose.dragTo(label);
    await expect(page.getByText('Labelled “dropzone”')).toBeVisible();
    await expect(loose.getByText('dropzone')).toBeVisible();

    // Export the folder as an mbox file, then import a message from an .eml file.
    await page.getByRole('button', { name: 'Folder actions Projects', exact: true }).click();
    const download = page.waitForEvent('download');
    await page.getByRole('menuitem', { name: 'Export as mbox' }).click();
    const exported = fs.readFileSync(await (await download).path(), 'utf8');
    expect(exported).toMatch(/^From ann@remote\.test /);
    expect(exported).toContain('Subject: Drag me to projects');

    await page.getByRole('button', { name: 'Folder actions Projects', exact: true }).click();
    const chooser = page.waitForEvent('filechooser');
    await page.getByRole('menuitem', { name: 'Import messages…' }).click();
    await (await chooser).setFiles({ name: 'old.eml', mimeType: 'message/rfc822', buffer: Buffer.from('From: archive@remote.test\r\nSubject: Imported from a file\r\nMessage-ID: <old-1@remote.test>\r\n\r\nold news\r\n') });
    await expect(page.getByText('1 message imported')).toBeVisible();
    await projects.click();
    await expect(page.getByTestId('email-row').filter({ hasText: 'Imported from a file' })).toHaveCount(1);

    // Share the folder with Alice, read-only.
    await page.getByRole('button', { name: 'Folder actions Projects', exact: true }).click();
    await page.getByRole('menuitem', { name: 'Share…' }).click();
    const share = page.getByRole('dialog');
    await share.getByLabel('Share with').fill('nobody@elsewhere.test');
    await share.getByRole('button', { name: 'Share', exact: true }).click();
    await expect(share.getByRole('alert')).toContainText('unknown user');
    await share.getByLabel('Share with').fill(ALICE);
    await share.getByRole('button', { name: 'Share', exact: true }).click();
    await expect(share.getByRole('table', { name: 'Shared with' }).getByRole('row', { name: new RegExp(ALICE) })).toBeVisible();
    await share.getByRole('button', { name: 'Done' }).click();
    await logout(page);

    await login(page, ALICE, USER_PASSWORD);
    const shared = page.getByRole('list', { name: 'Shared folders' }).getByRole('link', { name: /Projects/ }).first();
    await expect(shared).toContainText(BOB);
    await shared.click();
    await expect(page.getByTestId('email-row')).toHaveCount(2);
    await page.getByTestId('email-row').filter({ hasText: 'Drag me to projects' }).click();
    await expect(body(page).getByText('plan')).toBeVisible();
    // Read-only: deleting is refused by the server and the message stays.
    await conversation(page).getByRole('button', { name: 'Delete', exact: true }).click();
    await expect(page.getByText(/necessary rights|forbidden|not have/i)).toBeVisible();
    await logout(page);

    // Bob takes the access away again.
    await login(page, BOB, USER_PASSWORD);
    await page.getByRole('button', { name: 'Folder actions Projects', exact: true }).click();
    await page.getByRole('menuitem', { name: 'Share…' }).click();
    await page.getByRole('button', { name: `Stop sharing with ${ALICE}` }).click();
    await expect(page.getByText('This folder is not shared with anyone.')).toBeVisible();
    await page.getByRole('dialog').getByRole('button', { name: 'Done' }).click();
    await logout(page);
    await login(page, ALICE, USER_PASSWORD);
    await expect(page.getByRole('list', { name: 'Shared folders' })).toHaveCount(0);
  });

  test('end-to-end encrypted mail', async ({ page }) => {
    const passphrases: Record<string, string> = { [ALICE]: 'alice secret passphrase', [BOB]: 'bob secret passphrase' };
    for (const user of [ALICE, BOB]) {
      await login(page, user, USER_PASSWORD);
      await openSettings(page, 'Security');
      await page.getByRole('button', { name: 'Create a key' }).click();
      await page.getByLabel('New passphrase').fill(passphrases[user]);
      await page.getByLabel('Repeat passphrase').fill(passphrases[user]);
      await page.getByRole('button', { name: 'Create key', exact: true }).click();
      await expect(page.getByText('Your key was created')).toBeVisible({ timeout: 30_000 });
      await expect(page.getByTestId('pgp-fingerprint')).toHaveText(/^([0-9A-F]{4} ){9}[0-9A-F]{4}$/);
      if (user === ALICE) await logout(page);
    }

    // Bob writes to Alice, encrypted; a recipient without a key blocks sending.
    await page.goto('/mail');
    await page.getByRole('button', { name: 'Compose' }).click();
    await composer(page).getByLabel('To').fill(`${ALICE}, nokey@remote.test`);
    await composer(page).getByLabel('Subject').fill('Encrypted hello');
    await composer(page).getByRole('textbox', { name: 'Message body' }).click();
    await page.keyboard.type('The launch code is 0000.');
    await composer(page).getByLabel('Attachment files').setInputFiles({ name: 'secret.txt', mimeType: 'text/plain', buffer: Buffer.from('attached secret') });
    await expect(composer(page).getByText(/secret\.txt/)).toBeVisible();
    await composer(page).getByRole('button', { name: 'Encrypt message' }).click();
    await expect(composer(page).getByText('Body and attachments will be encrypted')).toBeVisible();
    await composer(page).getByRole('button', { name: 'Send' }).click();
    await expect(composer(page).getByRole('alert').filter({ hasText: 'No public key is known for nokey@remote.test' })).toBeVisible();
    await composer(page).getByLabel('To').fill(ALICE);
    await composer(page).getByRole('button', { name: 'Send' }).click();
    await expect(page.getByText('Message sent')).toBeVisible({ timeout: 30_000 });

    // What the server stores is ciphertext; Bob can still read his own copy with his key.
    await folders(page).getByText('Sent', { exact: true }).click();
    await page.getByTestId('email-row').filter({ hasText: 'Encrypted hello' }).click();
    await expect(page.getByText('This message is encrypted.')).toBeVisible();
    await conversation(page).getByRole('button', { name: 'More actions' }).click();
    const raw = await (await page.request.get((await page.getByRole('menuitem', { name: 'Download message' }).getAttribute('href'))!)).text();
    await page.keyboard.press('Escape');
    expect(raw).toContain('-----BEGIN PGP MESSAGE-----');
    expect(raw).toContain('multipart/encrypted');
    expect(raw).not.toContain('launch code');
    expect(raw).not.toContain('attached secret');
    await page.getByLabel('Key passphrase').fill('not the passphrase');
    await page.getByRole('button', { name: 'Unlock', exact: true }).click();
    await expect(page.getByText('Wrong passphrase')).toBeVisible();
    await page.getByLabel('Key passphrase').fill(passphrases[BOB]);
    await page.getByRole('button', { name: 'Unlock', exact: true }).click();
    await expect(body(page).getByText('The launch code is 0000.')).toBeVisible({ timeout: 30_000 });
    await logout(page);

    await login(page, ALICE, USER_PASSWORD);
    const row = page.getByTestId('email-row').filter({ hasText: 'Encrypted hello' });
    await expect(row).toHaveCount(1, { timeout: 20_000 });
    await expect(row).not.toContainText('launch code');
    await row.click();
    await page.getByLabel('Key passphrase').fill(passphrases[ALICE]);
    await page.getByRole('button', { name: 'Unlock', exact: true }).click();
    await expect(body(page).getByText('The launch code is 0000.')).toBeVisible({ timeout: 30_000 });
    await expect(conversation(page).getByText('Decrypted', { exact: true })).toBeVisible();
    const attachment = conversation(page).getByRole('link', { name: /secret\.txt/ });
    await expect(attachment).toBeVisible();
    const file = page.waitForEvent('download');
    await attachment.click();
    expect(fs.readFileSync(await (await file).path(), 'utf8')).toBe('attached secret');
  });

  test('integrations: skins, plug-ins, webhooks, single sign-on and international addresses', async ({ page }) => {
    // A plug-in installed on the server's disk by its operator.
    const plugin = path.join(dataDir, 'plugins', 'hello');
    fs.mkdirSync(plugin, { recursive: true });
    fs.writeFileSync(path.join(plugin, 'plugin.json'), JSON.stringify({ name: 'Hello plug-in', version: '1.0', description: 'Adds a button to every message' }));
    fs.writeFileSync(
      path.join(plugin, 'plugin.js'),
      `export default function (api) {
         api.addMessageAction({ id: 'shout', label: 'Shout subject', onClick: (message) => api.notify(message.subject.toUpperCase()) });
         api.addSidebarLink({ id: 'wiki', label: 'Team wiki', href: 'https://wiki.example.test/' });
       }`,
    );
    const hooks = await standIn((_request, response) => {
      response.writeHead(200);
      response.end('ok');
    });
    // A minimal identity provider that approves everybody as Bob.
    const provider = await standIn((request, response) => {
      const base = `http://127.0.0.1:${provider.port}`;
      const url = new URL(request.url, base);
      const json = (value: unknown) => {
        response.writeHead(200, { 'content-type': 'application/json' });
        response.end(JSON.stringify(value));
      };
      if (url.pathname === '/.well-known/openid-configuration') json({ issuer: base, authorization_endpoint: `${base}/authorize`, token_endpoint: `${base}/token`, userinfo_endpoint: `${base}/userinfo` });
      else if (url.pathname === '/authorize') {
        response.writeHead(302, { location: `${url.searchParams.get('redirect_uri')}?code=approved&state=${url.searchParams.get('state')}` });
        response.end();
      } else if (url.pathname === '/token') json({ access_token: 'access-token', token_type: 'Bearer' });
      else if (url.pathname === '/userinfo') json({ sub: 'u-1', email: BOB, email_verified: true });
      else {
        response.writeHead(404);
        response.end();
      }
    });

    await login(page, ADMIN.email, ADMIN.password);
    await openAdmin(page, 'Integrations');

    await page.getByRole('button', { name: 'Insert an example' }).click();
    await page.getByRole('button', { name: 'Save skins' }).click();
    await expect(page.getByText('Skins saved')).toBeVisible();
    await page.getByLabel('Skins (JSON)').fill('[{ "id": "evil", "name": "Evil", "css": "body { display: none }" }]');
    await page.getByRole('button', { name: 'Save skins' }).click();
    await expect(page.getByRole('alert').filter({ hasText: 'unknown skin property' })).toBeVisible();

    await expect(page.getByRole('table', { name: 'Plug-ins' }).getByRole('row', { name: /Hello plug-in/ })).toContainText('Adds a button to every message');

    await page.getByLabel('Webhook URL').fill(`http://127.0.0.1:${hooks.port}/hook`);
    await page.getByRole('button', { name: 'Add webhook' }).click();
    const secret = await page.getByTestId('webhook-secret').innerText();
    await page.getByRole('table', { name: 'Webhooks' }).getByRole('button', { name: 'Test' }).click();
    await expect(page.getByRole('table', { name: 'Webhooks' }).getByRole('row').nth(1)).toContainText('HTTP 200');
    const ping = hooks.requests.find((request) => request.headers['x-unomail-event'] === 'ping')!;
    expect(ping.headers['x-unomail-signature']).toBe(`sha256=${crypto.createHmac('sha256', secret).update(ping.body).digest('hex')}`);

    await page.getByLabel('Issuer URL').fill(`http://127.0.0.1:${provider.port}`);
    await page.getByLabel('Client ID').fill('unomail-e2e');
    await page.getByLabel('Client secret').fill('provider-secret');
    await page.getByLabel('Button label').fill('Company login');
    await page.getByLabel('Enable single sign-on').check();
    await page.getByRole('button', { name: 'Save single sign-on' }).click();
    await expect(page.getByText('Single sign-on settings saved')).toBeVisible();
    await expect(page.getByLabel('Redirect URI to register with the provider')).toHaveValue(`http://localhost:${PORTS.http}/api/auth/oauth/callback`);

    // A mailbox with an internationalized address.
    await openAdmin(page, 'Mailboxes');
    await page.getByRole('button', { name: 'Add mailbox' }).click();
    const dialog = page.getByRole('dialog');
    await dialog.getByLabel('E-mail address').fill(`józef.żółw@${DOMAIN}`);
    await dialog.getByLabel('Password', { exact: true }).fill(USER_PASSWORD);
    await dialog.getByRole('button', { name: 'Create' }).click();
    await expect(page.getByText('Mailbox created')).toBeVisible();
    await logout(page);

    // Single sign-on: the provider vouches for Bob, who lands in his mailbox without a password.
    await expect(page.getByRole('link', { name: 'Company login' })).toBeVisible();
    await page.getByRole('link', { name: 'Company login' }).click();
    await expect(folders(page)).toBeVisible();
    await page.getByRole('button', { name: 'Account menu' }).click();
    await expect(page.getByRole('menu').getByText(BOB)).toBeVisible();
    await page.keyboard.press('Escape');
    const tokenRequest = provider.requests.find((request) => request.url === '/token')!;
    expect(tokenRequest.body).toContain('client_secret=provider-secret');
    expect(tokenRequest.body).toContain('code_verifier=');

    // The plug-in is active for Bob: its action and its sidebar link.
    await expect(folders(page).getByRole('link', { name: 'Team wiki' })).toHaveAttribute('href', 'https://wiki.example.test/');
    await page.getByTestId('email-row').filter({ hasText: 'Newsletter one' }).click();
    await conversation(page).getByRole('button', { name: 'Shout subject' }).click();
    await expect(page.getByText('NEWSLETTER ONE', { exact: true })).toBeVisible();

    // Skins: the administrator's custom skin can be chosen and follows the account.
    await openSettings(page, 'General');
    await page.getByRole('radio', { name: /Ocean/ }).click();
    await expect(page.locator('body')).toHaveCSS('background-color', 'rgb(10, 25, 41)');
    await page.reload();
    await expect(page.locator('body')).toHaveCSS('background-color', 'rgb(10, 25, 41)');
    await expect(page.getByRole('radio', { name: /Ocean/ })).toHaveAttribute('aria-checked', 'true');
    await page.getByRole('radio', { name: /Material You/ }).click();
    await expect(page.locator('body')).not.toHaveCSS('background-color', 'rgb(10, 25, 41)');
    await logout(page);

    // The new mailbox signs in with its internationalized address.
    await login(page, `józef.żółw@${DOMAIN}`, USER_PASSWORD);
    await logout(page);

    // Leave the server as the other specs expect it.
    await login(page, ADMIN.email, ADMIN.password);
    await openAdmin(page, 'Integrations');
    await page.getByLabel('Enable single sign-on').uncheck();
    await page.getByRole('button', { name: 'Save single sign-on' }).click();
    await expect(page.getByText('Single sign-on settings saved')).toBeVisible();
    // The switch reflects the server's state, so it flips once the change has been saved.
    await page.getByLabel('Enable hello').click();
    await expect(page.getByText('Plug-in disabled')).toBeVisible();
    await expect(page.getByLabel('Enable hello')).not.toBeChecked();
    hooks.close();
    provider.close();
  });
});
