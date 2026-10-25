import { expect, test, type Page } from '@playwright/test';
import { execFileSync } from 'node:child_process';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { fileURLToPath, pathToFileURL } from 'node:url';
import { ADMIN, DOMAIN, login, logout, openAdmin, smtpDeliver, USER_PASSWORD } from './helpers';

const BOB = `bob@${DOMAIN}`;
const examples = path.join(path.dirname(fileURLToPath(import.meta.url)), '..', '..', 'docs', 'examples');

/** A git repository holding one of the examples (or the given files), tagged v1.0.0. */
function repository(example: string | Record<string, string>): string {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'unomail-package-'));
  if (typeof example === 'string') fs.cpSync(path.join(examples, example), dir, { recursive: true });
  else for (const [name, content] of Object.entries(example)) fs.writeFileSync(path.join(dir, name), content);
  const git = (...args: string[]) => execFileSync('git', ['-c', 'user.name=E2E', '-c', 'user.email=e2e@example.test', '-c', 'commit.gpgsign=false', '-c', 'tag.gpgsign=false', ...args], { cwd: dir });
  git('init', '--quiet', '--initial-branch=main');
  git('add', '--all');
  git('commit', '--quiet', '--message', 'v1.0.0');
  git('tag', 'v1.0.0');
  return pathToFileURL(dir).href;
}

async function install(page: Page, url: string, name: string) {
  await page.getByLabel('Git repository (https)').fill(url);
  await page.getByLabel('Tag, branch or commit').fill('v1.0.0');
  await page.getByRole('button', { name: 'Fetch' }).click();
  const dialog = page.getByRole('dialog', { name: `Install ${name}?` });
  await expect(dialog).toBeVisible();
  return dialog;
}

async function openSettings(page: Page) {
  await page.getByRole('button', { name: 'Account menu' }).click();
  await page.getByRole('menuitem', { name: 'Settings' }).click();
  await page.getByRole('navigation', { name: 'Settings sections' }).getByRole('button', { name: 'General' }).click();
}

test('plug-ins and themes install from git and plug-ins run sandboxed', async ({ page }) => {
  await smtpDeliver('news@remote.test', BOB, `From: news@remote.test\r\nTo: ${BOB}\r\nSubject: Package test\r\n\r\nHello`);
  const hello = repository('plugins/hello-world');
  const theme = repository('themes/solarized');

  await login(page, ADMIN.email, ADMIN.password);
  await openAdmin(page, 'Integrations');
  const dialog = await install(page, hello, 'Hello world');
  await expect(dialog.getByRole('list', { name: 'Permissions' })).toContainText('Read the message you open, including its content');
  await expect(dialog.getByRole('list', { name: 'Permissions' })).toContainText('Show notices');
  await dialog.getByRole('button', { name: 'Install' }).click();
  await expect(page.getByText('Package installed')).toBeVisible();
  await page.getByLabel('Make Hello world available').click();
  await expect(page.getByText('Available to users')).toBeVisible();

  await (await install(page, theme, 'Solarized')).getByRole('button', { name: 'Install' }).click();
  await expect(page.getByRole('table', { name: 'Installed packages' })).toContainText('Solarized');
  await logout(page);

  // Bob turns the plug-in on for himself; the theme is offered without asking.
  await login(page, BOB, USER_PASSWORD);
  await openSettings(page);
  await expect(page.getByRole('radio', { name: /Solarized/ })).toBeVisible();
  await page.getByLabel('Turn on Hello world').click();
  await expect(page.getByLabel('Turn on Hello world')).toBeChecked();

  await page.goto('/mail/inbox');
  await page.getByTestId('email-row').filter({ hasText: 'Package test' }).click();
  await page.getByRole('region', { name: 'Conversation' }).getByRole('button', { name: 'Say hello' }).click();
  await expect(page.getByText('Hello world: Hello! You are reading "Package test".')).toBeVisible();

  // The frame cannot reach the page, the session or the API.
  const frame = page.frames().find((f) => f.url().includes('/plugin-frame/hello-world/'))!;
  expect(frame).toBeTruthy();
  const reach = await frame.evaluate(async () => {
    const attempt = async (probe: () => unknown) => {
      try {
        return { ok: true, value: String(await probe()) };
      } catch {
        return { ok: false };
      }
    };
    return {
      parent: await attempt(() => window.parent.document.title),
      cookie: await attempt(() => document.cookie),
      api: await attempt(() => fetch('/api/me').then((r) => r.status)),
      storage: await attempt(() => localStorage.length),
    };
  });
  expect(reach.parent.ok).toBe(false);
  expect(reach.cookie.ok && reach.cookie.value !== '').toBe(false);
  expect(reach.api.ok).toBe(false);
  expect(reach.storage.ok).toBe(false);
  await logout(page);

  // Uninstalling removes both, leaving the server as the other specs expect it.
  await login(page, ADMIN.email, ADMIN.password);
  await openAdmin(page, 'Integrations');
  for (const name of ['Hello world', 'Solarized']) {
    await page.getByLabel(`Uninstall ${name}`).click();
    await page.getByRole('dialog').getByRole('button', { name: 'Uninstall' }).click();
    await expect(page.getByText('Package uninstalled')).toBeVisible();
  }
  await expect(page.getByRole('table', { name: 'Installed packages' })).toHaveCount(0);
});

test('plug-ins hide features, add pages and hook into the mail server; themes bring images', async ({ page }) => {
  const noCalendar = repository('plugins/no-calendar');
  const tagger = repository('plugins/subject-tagger');
  const theme = repository('themes/solarized');

  await login(page, ADMIN.email, ADMIN.password);
  await openAdmin(page, 'Integrations');
  const dialog = await install(page, noCalendar, 'Mail only');
  await expect(dialog.getByRole('list', { name: 'Permissions' })).toContainText('Hide or replace built-in features');
  await dialog.getByRole('button', { name: 'Install' }).click();
  await page.getByLabel('Make Mail only available').click();
  await expect(page.getByText('Available to users')).toBeVisible();

  const server = await install(page, tagger, 'Subject tagger');
  await expect(server.getByRole('list', { name: 'Permissions' })).toContainText('Reject, hold or change incoming mail on the server');
  await server.getByRole('button', { name: 'Install' }).click();
  await expect(page.getByText('Package installed')).toBeVisible();
  await page.getByLabel('Make Subject tagger available').click();
  await expect(page.getByLabel('Make Subject tagger available')).toBeChecked();
  await (await install(page, theme, 'Solarized')).getByRole('button', { name: 'Install' }).click();
  await expect(page.getByRole('table', { name: 'Installed packages' })).toContainText('Solarized');

  // The administrator's setting for the server plug-in, and the page it adds to the administration.
  await page.getByLabel('Settings of Subject tagger').click();
  await page.getByRole('dialog').getByLabel('Subject prefix').fill('[OUTSIDE]');
  await page.getByRole('dialog').getByRole('button', { name: 'Save' }).click();
  await expect(page.getByRole('dialog')).toHaveCount(0);
  await page.reload();
  await page.getByRole('navigation', { name: 'Administration menu' }).getByRole('link', { name: 'Subject tagger' }).click();
  await expect(page.frameLocator('iframe[src*="/plugin-frame/subject-tagger/"][src*="view=admin"]').getByText('[OUTSIDE]')).toBeVisible();
  await logout(page);

  // The server plug-in tags mail from outside, whether or not anyone turned it on.
  await smtpDeliver('partner@remote.test', BOB, `From: partner@remote.test\r\nTo: ${BOB}\r\nSubject: Contract draft\r\n\r\nHello`);

  await login(page, BOB, USER_PASSWORD);
  await expect(page.getByTestId('email-row').filter({ hasText: '[OUTSIDE] Contract draft' })).toBeVisible();
  const folders = page.getByRole('navigation', { name: 'Folders' });
  await expect(folders.getByRole('link', { name: 'Calendar' })).toBeVisible();

  await openSettings(page);
  await page.getByLabel('Turn on Mail only').click();
  await expect(page.getByLabel('Turn on Mail only')).toBeChecked();
  // The theme's background image comes from the installed package.
  await page.getByRole('radio', { name: /Solarized/ }).click();
  await expect(page.locator('body')).toHaveCSS('background-image', /\/package-asset\/solarized\/[0-9a-f]{40}\/background\.png/);
  // Nothing in front of it paints over the image.
  await expect(page.locator('.um-page').first()).toHaveCSS('background-color', 'rgba(0, 0, 0, 0)');
  await page.getByRole('radio', { name: /Material You/ }).click();

  // The calendar is gone, its address leads back to the mail, and the plug-in's page took its place.
  await page.goto('/mail/inbox');
  await expect(folders.getByRole('link', { name: 'Agenda' })).toBeVisible();
  await expect(folders.getByRole('link', { name: 'Calendar' })).toHaveCount(0);
  await page.goto('/calendar');
  await expect(page).toHaveURL(/\/mail/);
  await folders.getByRole('link', { name: 'Agenda' }).click();
  await expect(page.frameLocator('iframe[src*="/plugin-frame/no-calendar/"][src*="view=agenda"]').getByText('The calendar is turned off on this server.')).toBeVisible();
  await logout(page);

  await login(page, ADMIN.email, ADMIN.password);
  await openAdmin(page, 'Integrations');
  for (const name of ['Mail only', 'Subject tagger', 'Solarized']) {
    await page.getByLabel(`Uninstall ${name}`).click();
    await page.getByRole('dialog').getByRole('button', { name: 'Uninstall' }).click();
    await expect(page.getByText('Package uninstalled')).toBeVisible();
  }
});

test('plug-ins read attachments as files and attach files to new messages', async ({ page }) => {
  const relay = repository({
    'unomail.json': JSON.stringify({
      schema: 2, id: 'file-relay', type: 'plugin', name: 'File relay', version: '1.0.0', api: '^2', entry: 'index.js',
      permissions: ['attachments:read', 'composer:write', 'notify'],
    }),
    'index.js': `
      await unomail.ready;
      unomail.ui.addItem({ slot: 'reader.header', id: 'check', label: 'Check files', onClick: async () => {
        const [file] = await unomail.message.getAttachments();
        const data = await unomail.message.getAttachment(file.id);
        await unomail.notify(file.name + ': ' + (await data.text()));
      } });
      unomail.ui.addItem({ slot: 'composer.toolbar', id: 'attach', label: 'Attach note', onClick: () =>
        unomail.composer.addAttachment(new Blob(['from the plug-in'], { type: 'text/plain' }), { name: 'plugin-note.txt' }) });
    `,
  });
  const boundary = 'relay-boundary';
  await smtpDeliver('ann@remote.test', BOB, `From: ann@remote.test\r\nTo: ${BOB}\r\nSubject: Relay test\r\nMIME-Version: 1.0\r\nContent-Type: multipart/mixed; boundary="${boundary}"\r\n\r\n--${boundary}\r\nContent-Type: text/plain\r\n\r\nSee attached.\r\n--${boundary}\r\nContent-Type: text/plain; name="data.txt"\r\nContent-Disposition: attachment; filename="data.txt"\r\n\r\ncloud payload\r\n--${boundary}--\r\n`);

  await login(page, ADMIN.email, ADMIN.password);
  await openAdmin(page, 'Integrations');
  const dialog = await install(page, relay, 'File relay');
  await expect(dialog.getByRole('list', { name: 'Permissions' })).toContainText('Read the attachments of the message you open');
  await dialog.getByRole('button', { name: 'Install' }).click();
  await page.getByLabel('Make File relay available').click();
  await expect(page.getByLabel('Make File relay available')).toBeChecked();
  await logout(page);

  await login(page, BOB, USER_PASSWORD);
  await openSettings(page);
  await page.getByLabel('Turn on File relay').click();
  await expect(page.getByLabel('Turn on File relay')).toBeChecked();
  await page.goto('/mail/inbox');
  await page.getByTestId('email-row').filter({ hasText: 'Relay test' }).click();
  await page.getByRole('region', { name: 'Conversation' }).getByRole('button', { name: 'Check files' }).click();
  await expect(page.getByText('File relay: data.txt: cloud payload')).toBeVisible();

  await page.getByRole('button', { name: 'Compose' }).click();
  const composer = page.getByRole('dialog', { name: 'New message' });
  await composer.getByRole('button', { name: 'Attach note' }).click();
  await expect(composer.getByText('plugin-note.txt')).toBeVisible();
  await composer.getByRole('button', { name: 'Discard draft' }).click();
  await logout(page);

  await login(page, ADMIN.email, ADMIN.password);
  await openAdmin(page, 'Integrations');
  await page.getByLabel('Uninstall File relay').click();
  await page.getByRole('dialog').getByRole('button', { name: 'Uninstall' }).click();
  await expect(page.getByText('Package uninstalled')).toBeVisible();
});
