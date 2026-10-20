import { expect, test } from '@playwright/test';
import { ADMIN, DOMAIN, login, logout, openAdmin, USER_PASSWORD } from './helpers';

test.describe('administration', () => {
  test.beforeEach(async ({ page }) => {
    await login(page, ADMIN.email, ADMIN.password);
  });

  test('dashboard shows the server overview', async ({ page }) => {
    await openAdmin(page, 'Dashboard');
    await expect(page.getByRole('heading', { name: 'Dashboard' })).toBeVisible();
    await expect(page.getByTestId('metric-Queue size')).toHaveText('0');
    await expect(page.getByTestId('metric-Mailboxes')).toBeVisible();
    await expect(page.getByText('self-signed certificate')).toBeVisible();
  });

  test('creating a domain generates DKIM and shows the DNS records to publish', async ({ page }) => {
    await openAdmin(page, 'Domains');
    await page.getByRole('button', { name: 'Add domain' }).click();
    const dialog = page.getByRole('dialog');

    // Inline validation keeps invalid names from being submitted.
    await dialog.getByLabel('Domain name').fill('not a domain');
    await expect(dialog.getByText('Enter a valid domain name')).toBeVisible();
    await expect(dialog.getByRole('button', { name: 'Create' })).toBeDisabled();

    await dialog.getByLabel('Domain name').fill(DOMAIN);
    await dialog.getByRole('button', { name: 'Create' }).click();
    await expect(page.getByText('Domain created')).toBeVisible();

    await page.getByRole('link', { name: DOMAIN }).click();
    await expect(page.getByRole('heading', { name: DOMAIN })).toBeVisible();

    // SPF, DKIM and DMARC records are generated for the administrator to publish.
    const dns = page.getByRole('list', { name: 'DNS records' });
    const dnsCheck = (name: string | RegExp) => dns.getByRole('listitem').filter({ has: page.getByRole('heading', { name }) });
    await expect(dnsCheck(/MX record/)).toContainText('10 mail.e2e.test.');
    await expect(dnsCheck(/SPF record/)).toContainText('v=spf1 a:mail.e2e.test -all');
    await expect(dnsCheck(/DMARC policy/)).toContainText(`_dmarc.${DOMAIN}`);
    await expect(dnsCheck(/DMARC policy/)).toContainText('v=DMARC1; p=quarantine');
    await expect(dnsCheck(/DKIM key/)).toContainText('v=DKIM1; k=rsa; p=');

    // Key rotation: add a second selector, retire the first.
    const keys = page.getByRole('table', { name: 'DKIM keys' });
    await expect(keys.getByRole('row')).toHaveCount(2);
    await page.getByLabel('New selector').fill('rotated');
    await page.getByRole('button', { name: 'Generate key' }).click();
    await expect(keys.getByRole('row', { name: /rotated/ })).toBeVisible();
    await expect(dnsCheck(/DKIM key \(rotated\)/)).toBeVisible();
    await keys.getByRole('row', { name: /rotated/ }).getByRole('button', { name: /Delete key/ }).click();
    await expect(keys.getByRole('row', { name: /rotated/ })).toHaveCount(0);

    // The private key never reaches the browser.
    const response = await page.request.get(`/api/domains`);
    const domainId = (await response.json()).find((d: { name: string }) => d.name === DOMAIN).id;
    const keyJson = await (await page.request.get(`/api/domains/${domainId}/dkim`)).text();
    expect(keyJson).not.toContain('PRIVATE');
  });

  test('creating mailboxes and an alias', async ({ page }) => {
    await openAdmin(page, 'Mailboxes');
    for (const [local, name] of [['alice', 'Alice Example'], ['bob', 'Bob Example']]) {
      await page.getByRole('button', { name: 'Add mailbox' }).click();
      const dialog = page.getByRole('dialog');
      const create = dialog.getByRole('button', { name: 'Create' });

      await dialog.getByLabel('E-mail address').fill('broken address');
      await dialog.getByLabel('Password', { exact: true }).fill('short');
      await expect(dialog.getByText('Enter a valid e-mail address')).toBeVisible();
      await expect(dialog.getByText('Use at least 10 characters')).toBeVisible();
      await expect(create).toBeDisabled();

      await dialog.getByLabel('E-mail address').fill(`${local}@${DOMAIN}`);
      await dialog.getByLabel('Display name').fill(name);
      await dialog.getByLabel('Password', { exact: true }).fill(USER_PASSWORD);
      await create.click();
      await expect(page.getByText('Mailbox created')).toBeVisible();
      await expect(page.getByRole('row', { name: new RegExp(`${local}@${DOMAIN}`) })).toContainText(name);
    }

    // A duplicate is reported by the server and shown in the form.
    await page.getByRole('button', { name: 'Add mailbox' }).click();
    const dialog = page.getByRole('dialog');
    await dialog.getByLabel('E-mail address').fill(`alice@${DOMAIN}`);
    await dialog.getByLabel('Password', { exact: true }).fill(USER_PASSWORD);
    await dialog.getByRole('button', { name: 'Create' }).click();
    // Under the field it is about, inside the dialog.
    await expect(dialog.getByLabel('E-mail address')).toHaveAccessibleDescription(/already exists/i);
    await dialog.getByRole('button', { name: 'Cancel' }).click();

    await openAdmin(page, 'Aliases');
    await page.getByRole('button', { name: 'Add alias' }).click();
    await page.getByLabel('Alias address').fill(`team@${DOMAIN}`);
    await page.getByLabel('Destinations').fill(`alice@${DOMAIN}, bob@${DOMAIN}`);
    await page.getByRole('button', { name: 'Save' }).click();
    await expect(page.getByText('Alias created')).toBeVisible();
    await expect(page.getByRole('row', { name: new RegExp(`team@${DOMAIN}`) })).toContainText(`alice@${DOMAIN}, bob@${DOMAIN}`);
  });

  test('administrative actions are recorded in the audit log', async ({ page }) => {
    await openAdmin(page, 'Logs');
    await page.getByRole('tab', { name: 'Security audit' }).click();
    const log = page.getByRole('table', { name: 'Audit log' });
    await expect(log.getByRole('row', { name: /domain\.created/ }).first()).toContainText(DOMAIN);
    await expect(log.getByRole('row', { name: /account\.created/ }).first()).toContainText(ADMIN.email);
    await page.getByLabel('Search').fill('alias.created');
    await expect(log.getByRole('row')).toHaveCount(2);
  });

  test('ordinary users cannot open the administration area', async ({ page }) => {
    await logout(page);
    await login(page, `alice@${DOMAIN}`, USER_PASSWORD);
    await page.goto('/admin/mailboxes');
    await expect(page).toHaveURL(/\/mail/);
    await page.getByRole('button', { name: 'Account menu' }).click();
    await expect(page.getByRole('menuitem', { name: 'Administration' })).toHaveCount(0);
    for (const path of ['/api/accounts', '/api/domains', '/api/tls', '/api/logs/audit', '/api/queue']) {
      expect((await page.request.get(path)).status(), path).toBe(403);
    }
  });
});
