import { createHmac } from 'node:crypto';
import { expect, test, type Page } from '@playwright/test';
import { DOMAIN, login, logout, USER_PASSWORD } from './helpers';

// A mailbox of its own: turning on 2-step verification must not affect the other specs.
const JACK = `jack@${DOMAIN}`;
const ADMIN_EMAIL = 'admin@e2e.test';
const ADMIN_PASSWORD = 'e2e-admin-password-1';

function base32(text: string): Buffer {
  const alphabet = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567';
  let bits = '';
  for (const c of text.replace(/\s/g, '')) bits += alphabet.indexOf(c).toString(2).padStart(5, '0');
  const bytes: number[] = [];
  for (let i = 0; i + 8 <= bits.length; i += 8) bytes.push(parseInt(bits.slice(i, i + 8), 2));
  return Buffer.from(bytes);
}

/** The code an authenticator app shows, `steps` periods from now. */
function totp(secret: string, steps = 0): string {
  const counter = Buffer.alloc(8);
  counter.writeBigUInt64BE(BigInt(Math.floor(Date.now() / 30_000) + steps));
  const digest = createHmac('sha1', base32(secret)).update(counter).digest();
  const offset = digest[19] & 0xf;
  return String((digest.readUInt32BE(offset) & 0x7fffffff) % 1_000_000).padStart(6, '0');
}

async function security(page: Page) {
  await page.goto('/settings?tab=security');
  await expect(page.getByRole('heading', { name: '2-step verification' })).toBeVisible();
}

test.describe('2-step verification and app passwords', () => {
  test.use({ actionTimeout: 10_000 });

  test.beforeAll(async ({ browser }) => {
    const page = await browser.newPage();
    await login(page, ADMIN_EMAIL, ADMIN_PASSWORD);
    await page.goto('/admin/mailboxes');
    await page.getByRole('button', { name: 'Add mailbox' }).click();
    const dialog = page.getByRole('dialog');
    await dialog.getByLabel('E-mail address').fill(JACK);
    await dialog.getByLabel('Password', { exact: true }).fill(USER_PASSWORD);
    await dialog.getByRole('button', { name: 'Create' }).click();
    await expect(page.getByText('Mailbox created').or(dialog.getByRole('alert').filter({ hasText: 'already exists' }))).toBeVisible();
    await page.close();
  });

  test('an authenticator app is set up, asked for at sign-in, and reset by the administrator', async ({ page, browser }) => {
    await login(page, JACK, USER_PASSWORD);
    await security(page);
    await page.getByRole('button', { name: 'Set up' }).click();
    const setup = page.getByRole('dialog', { name: 'Set up an authenticator app' });
    await expect(setup.getByRole('img', { name: 'QR code for the authenticator app' })).toBeVisible();
    const secret = (await setup.getByTestId('totp-secret').textContent())!.replace(/\s/g, '');
    expect(secret).toMatch(/^[A-Z2-7]{32}$/);
    await setup.getByLabel('Code from the app').fill('000000');
    await setup.getByRole('button', { name: 'Turn on' }).click();
    await expect(setup.getByRole('alert')).toContainText('not correct');
    await setup.getByLabel('Code from the app').fill(totp(secret));
    await setup.getByRole('button', { name: 'Turn on' }).click();

    // The recovery codes, shown once.
    const codes = page.getByRole('dialog', { name: 'Recovery codes' });
    await expect(codes.getByRole('list', { name: 'Recovery codes' }).getByRole('listitem')).toHaveCount(10);
    const recovery = (await codes.getByRole('listitem').first().textContent())!;
    await codes.getByRole('button', { name: 'I have saved them' }).click();
    await expect(page.getByText('The authenticator app is on')).toBeVisible();

    // An app password for a mail program.
    await page.getByRole('button', { name: 'Create app password' }).click();
    const create = page.getByRole('dialog', { name: 'Create an app password' });
    await create.getByLabel('Program').fill('Phone');
    await create.getByLabel('Your password').fill(USER_PASSWORD);
    await create.getByRole('button', { name: 'Create' }).click();
    await expect(page.getByTestId('new-app-password')).toHaveText(/^[a-z]{4} [a-z]{4} [a-z]{4} [a-z]{4}$/);
    await page.getByRole('button', { name: 'Done' }).click();
    await expect(page.getByRole('table', { name: 'App passwords' })).toContainText('Phone');

    // Signing in now takes the second step.
    await logout(page);
    await page.getByLabel('E-mail address').fill(JACK);
    await page.getByLabel('Password').fill(USER_PASSWORD);
    await page.getByRole('button', { name: 'Sign in', exact: true }).click();
    await expect(page.getByRole('heading', { name: '2-step verification' })).toBeVisible();
    await page.getByLabel('Code', { exact: true }).fill('123456');
    await page.getByRole('button', { name: 'Verify' }).click();
    await expect(page.getByRole('alert')).toContainText('not correct');
    await page.getByLabel('Code', { exact: true }).fill(totp(secret, 1));
    await page.getByRole('button', { name: 'Verify' }).click();
    await expect(page.getByRole('navigation', { name: 'Folders' })).toBeVisible();

    // A recovery code works once.
    await logout(page);
    await page.getByLabel('E-mail address').fill(JACK);
    await page.getByLabel('Password').fill(USER_PASSWORD);
    await page.getByRole('button', { name: 'Sign in', exact: true }).click();
    await page.getByRole('button', { name: 'Use a recovery code' }).click();
    await page.getByLabel('Recovery code').fill(recovery);
    await page.getByRole('button', { name: 'Verify' }).click();
    await expect(page.getByRole('navigation', { name: 'Folders' })).toBeVisible();
    await security(page);
    await expect(page.getByText('9 unused')).toBeVisible();

    // The administrator resets it for an owner who lost the phone.
    const admin = await (await browser.newContext()).newPage();
    await login(admin, ADMIN_EMAIL, ADMIN_PASSWORD);
    await admin.goto('/admin/mailboxes');
    await admin.getByRole('row', { name: new RegExp(JACK) }).getByRole('button', { name: /Edit/ }).click();
    const dialog = admin.getByRole('dialog');
    await expect(dialog).toContainText('2-step verification is on (authenticator app).');
    await expect(dialog).toContainText('1 app password.');
    await dialog.getByRole('button', { name: 'Reset' }).click();
    await expect(dialog).toContainText('2-step verification was reset');
    await admin.context().close();

    await logout(page);
    await login(page, JACK, USER_PASSWORD);
  });
});
