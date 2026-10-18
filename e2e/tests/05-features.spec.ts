import { expect, test, type Page } from '@playwright/test';
import { ADMIN, DOMAIN, login, logout, openAdmin, PORTS, smtpDeliver, USER_PASSWORD } from './helpers';

const ALICE = `alice@${DOMAIN}`;
const BOB = `bob@${DOMAIN}`;

async function openSettings(page: Page, tab?: string) {
  await page.getByRole('button', { name: 'Account menu' }).click();
  await page.getByRole('menuitem', { name: 'Settings' }).click();
  await expect(page.getByRole('heading', { name: 'Settings', level: 1 })).toBeVisible();
  if (tab) await page.getByRole('navigation', { name: 'Settings sections' }).getByRole('button', { name: tab }).click();
}

test.describe('user features', () => {
  test('out-of-office replies are configured in settings and sent once', async ({ page }) => {
    await login(page, BOB, USER_PASSWORD);
    await openSettings(page, 'Out of office');
    await page.getByLabel('Send automatic replies').check();
    await page.getByLabel('Reply subject').fill('On holiday');
    await page.getByRole('button', { name: 'Save out-of-office settings' }).click();
    await expect(page.getByRole('alert').filter({ hasText: 'a message is required' })).toBeVisible();
    await page.getByLabel('Reply message').fill('I am away until Monday and will answer then.');
    await page.getByRole('button', { name: 'Save out-of-office settings' }).click();
    await expect(page.getByText('Out-of-office settings saved.')).toBeVisible();
    await logout(page);

    await login(page, ALICE, USER_PASSWORD);
    for (const subject of ['Are you around?', 'Second try']) {
      await page.getByRole('button', { name: 'Compose' }).click();
      const composer = page.getByRole('dialog', { name: 'New message' });
      await composer.getByLabel('To').fill(BOB);
      await composer.getByLabel('Subject').fill(subject);
      await composer.getByRole('textbox', { name: 'Message body' }).click();
      await page.keyboard.type('ping');
      await composer.getByRole('button', { name: 'Send' }).click();
      await expect(page.getByText('Message sent')).toBeVisible();
      await expect(page.getByText('Message sent')).toBeHidden({ timeout: 10_000 });
    }
    const replies = page.getByTestId('email-row').filter({ hasText: 'On holiday' });
    await expect(replies).toHaveCount(1);
    await replies.click();
    await expect(page.getByRole('region', { name: 'Conversation' }).frameLocator('iframe[title="Message body"]').getByText('I am away until Monday')).toBeVisible();
    await logout(page);

    // Switch it off again so later tests are not answered automatically.
    await login(page, BOB, USER_PASSWORD);
    await openSettings(page, 'Out of office');
    await page.getByLabel('Send automatic replies').uncheck();
    await page.getByRole('button', { name: 'Save out-of-office settings' }).click();
    await expect(page.getByText('Out-of-office settings saved.')).toBeVisible();
  });

  test('sieve filters are validated and applied to incoming mail', async ({ page }) => {
    await login(page, BOB, USER_PASSWORD);
    await openSettings(page, 'Filters');
    // A new account starts with the visual rules; this test writes Sieve itself.
    await page.getByRole('tab', { name: 'Sieve script' }).click();
    const script = page.getByLabel('Sieve script');
    await script.fill('require "fileinto";\nfileinto "Receipts"');
    await page.getByRole('button', { name: 'Save filters' }).click();
    await expect(page.getByRole('alert').filter({ hasText: "line 2: expected ';'" })).toBeVisible();

    await script.fill('require ["fileinto", "mailbox"];\nif header :contains "subject" "receipt" {\n  fileinto :create "Receipts";\n}\n');
    await page.getByLabel('Filters enabled').check();
    await page.getByRole('button', { name: 'Save filters' }).click();
    await expect(page.getByText('Filter script saved.')).toBeVisible();

    await smtpDeliver('shop@remote.test', BOB, `From: Shop <shop@remote.test>\nTo: ${BOB}\nSubject: Your receipt #1234\n\nThanks for your order.\n`);
    await page.goto('/mail');
    const folders = page.getByRole('navigation', { name: 'Folders' });
    await folders.getByText('Receipts', { exact: true }).click();
    await expect(page.getByTestId('email-row').filter({ hasText: 'Your receipt #1234' })).toHaveCount(1);
    await folders.getByText('Inbox', { exact: true }).click();
    await expect(page.getByRole('heading', { name: 'Inbox', level: 1 })).toBeVisible();
    await expect(page.getByTestId('email-row').filter({ hasText: 'Your receipt #1234' })).toHaveCount(0);
  });

  test('labels can be created, shown and used to browse mail', async ({ page }) => {
    await login(page, BOB, USER_PASSWORD);
    await page.getByTestId('email-row').filter({ hasText: 'Weekly digest' }).click();
    const reader = page.getByRole('region', { name: 'Conversation' });
    await reader.getByRole('button', { name: 'Labels' }).click();
    await page.getByLabel('New label').fill('bad label!');
    await expect(page.getByText('Letters, digits, - _ . only')).toBeVisible();
    await page.getByLabel('New label').fill('Reading List');
    await page.keyboard.press('Enter');
    await expect(reader.getByText('reading-list')).toBeVisible();

    const labels = page.getByRole('list', { name: 'Labels' });
    await expect(labels.getByText('reading-list')).toBeVisible();
    await page.getByRole('button', { name: 'Back to list' }).click();
    await labels.getByText('reading-list').click();
    await expect(page.getByRole('heading', { name: 'Label: reading-list' })).toBeVisible();
    await expect(page.getByTestId('email-row')).toHaveCount(1);
    await expect(page.getByTestId('email-row').first()).toContainText('Weekly digest');

    // Removing the label empties the view.
    await page.getByTestId('email-row').first().click();
    await reader.getByRole('button', { name: 'Labels' }).click();
    await page.getByRole('menuitem', { name: 'reading-list' }).click();
    await expect(reader.getByText('reading-list')).toBeHidden();
    await page.getByRole('button', { name: 'Back to list' }).click();
    await page.getByRole('button', { name: 'Refresh' }).click();
    await expect(page.getByText('Nothing here yet.')).toBeVisible();
  });

  test('rich text formatting and links survive sending', async ({ page }) => {
    await login(page, ALICE, USER_PASSWORD);
    await page.getByRole('button', { name: 'Compose' }).click();
    const composer = page.getByRole('dialog', { name: 'New message' });
    await composer.getByLabel('To').fill(BOB);
    await composer.getByLabel('Subject').fill('Formatted note');
    await composer.getByRole('textbox', { name: 'Message body' }).click();
    await composer.getByRole('button', { name: 'Bold' }).click();
    await page.keyboard.type('Important');
    await composer.getByRole('button', { name: 'Bold' }).click();
    await page.keyboard.type(' see the docs');
    await page.keyboard.press('Shift+Home');

    // Dangerous link schemes are refused, web links accepted.
    page.once('dialog', (dialog) => void dialog.accept('javascript:alert(1)'));
    await composer.getByRole('button', { name: 'Insert link' }).click();
    await expect(composer.getByRole('alert').filter({ hasText: 'Links must start with' })).toBeVisible();
    page.once('dialog', (dialog) => void dialog.accept('https://docs.example.test/guide'));
    await composer.getByRole('button', { name: 'Insert link' }).click();
    await composer.getByRole('button', { name: 'Send' }).click();
    await expect(page.getByText('Message sent')).toBeVisible();
    await logout(page);

    await login(page, BOB, USER_PASSWORD);
    await page.getByTestId('email-row').filter({ hasText: 'Formatted note' }).click();
    const body = page.getByRole('region', { name: 'Conversation' }).frameLocator('iframe[title="Message body"]');
    const link = body.locator('a[href="https://docs.example.test/guide"]');
    await expect(link).toBeVisible();
    await expect(link).toHaveAttribute('rel', /noopener/);
    await expect(body.locator('b, strong').first()).toContainText('Important');
  });

  test('previously loaded mail stays readable offline', async ({ page, context }) => {
    await login(page, BOB, USER_PASSWORD);
    const row = page.getByTestId('email-row').filter({ hasText: 'Formatted note' });
    await row.click();
    const reader = page.getByRole('region', { name: 'Conversation' });
    await expect(reader.getByRole('heading', { name: 'Formatted note' })).toBeVisible();
    await page.getByRole('button', { name: 'Back to list' }).click();

    await context.setOffline(true);
    await page.getByRole('button', { name: 'Refresh' }).click();
    await expect(page.getByText('You are offline. Showing the copy saved on this device.')).toBeVisible();
    await expect(row).toBeVisible();
    await row.click();
    await expect(reader.frameLocator('iframe[title="Message body"]').getByText('see the docs')).toBeVisible();

    await context.setOffline(false);
    await page.getByRole('button', { name: 'Back to list' }).click();
    await page.getByRole('button', { name: 'Refresh' }).click();
    await expect(page.getByText('You are offline.')).toBeHidden();

    // Signing out removes the cached mail from the browser.
    await logout(page);
    const cached = await page.evaluate(() => Object.keys(localStorage).filter((k) => k.startsWith('unomail.cache.')));
    expect(cached).toEqual([]);
  });
});

test.describe('administration features', () => {
  test.beforeEach(async ({ page }) => {
    await login(page, ADMIN.email, ADMIN.password);
  });

  test('server settings change behaviour immediately', async ({ page }) => {
    await openAdmin(page, 'Server settings');
    const recipients = page.getByRole('textbox', { name: 'Recipients per message' });
    await recipients.fill('0');
    await expect(page.getByText('Must be between 1 and 10000')).toBeVisible();
    await recipients.fill('25');
    await page.getByRole('row', { name: /Recipients per message/ }).getByRole('button', { name: 'Save' }).click();
    await expect(page.getByText('Setting saved')).toBeVisible();
    await expect(page.getByRole('row', { name: /Recipients per message/ }).getByText('changed')).toBeVisible();

    // Strict inbound TLS: plaintext delivery is refused the moment the switch is flipped.
    const message = `From: a@remote.test\nTo: ${BOB}\nSubject: Plaintext hop\n\nx\n`;
    await smtpDeliver('a@remote.test', BOB, message);
    // The switch reflects the saved server state, so it flips once the change is stored.
    const strictTls = page.getByRole('checkbox', { name: 'Require TLS from other servers' });
    await strictTls.click();
    await expect(strictTls).toBeChecked();
    await expect(smtpDeliver('a@remote.test', BOB, message)).rejects.toThrow(/530 5\.7\.0 Must issue a STARTTLS/);

    await page.getByRole('button', { name: 'Reset Require TLS from other servers' }).click();
    await expect(page.getByText('Reset to default')).toBeVisible();
    await smtpDeliver('a@remote.test', BOB, message);
    await page.getByRole('button', { name: 'Reset Recipients per message' }).click();
    await expect(page.getByRole('row', { name: /Recipients per message/ }).getByText('default')).toBeVisible();
  });

  test('DMARC reports are uploaded and summarised', async ({ page }) => {
    const now = Math.floor(Date.now() / 1000);
    const xml = `<?xml version="1.0"?><feedback>
      <report_metadata><org_name>bigmail.example</org_name><email>d@bigmail.example</email><report_id>e2e-1</report_id>
        <date_range><begin>${now - 86400}</begin><end>${now}</end></date_range></report_metadata>
      <policy_published><domain>${DOMAIN}</domain><p>quarantine</p></policy_published>
      <record><row><source_ip>203.0.113.10</source_ip><count>90</count><policy_evaluated><disposition>none</disposition><dkim>pass</dkim><spf>pass</spf></policy_evaluated></row>
        <identifiers><header_from>${DOMAIN}</header_from></identifiers><auth_results><spf><domain>${DOMAIN}</domain><result>pass</result></spf></auth_results></record>
      <record><row><source_ip>198.51.100.66</source_ip><count>10</count><policy_evaluated><disposition>quarantine</disposition><dkim>fail</dkim><spf>fail</spf></policy_evaluated></row>
        <identifiers><header_from>${DOMAIN}</header_from></identifiers><auth_results><spf><domain>x.example</domain><result>fail</result></spf></auth_results></record>
    </feedback>`;
    await openAdmin(page, 'DMARC reports');
    await expect(page.getByText('No reports received in this period yet.')).toBeVisible();
    await page.getByLabel('DMARC report file').setInputFiles({ name: 'report.xml', mimeType: 'text/xml', buffer: Buffer.from(xml) });
    await expect(page.getByText('Report imported')).toBeVisible();

    const card = page.getByTestId(`dmarc-${DOMAIN}`);
    await expect(card).toContainText('90%');
    await expect(card).toContainText('100 messages in 1 report');
    await expect(card).toContainText('10 quarantined');
    const sources = page.getByRole('table', { name: 'Sending sources' });
    await expect(sources.getByRole('row', { name: /198\.51\.100\.66/ })).toContainText('0%');
    await page.getByRole('table', { name: 'Reports' }).getByRole('row', { name: /bigmail\.example/ }).click();
    await expect(page.getByRole('table', { name: 'Report records' }).getByRole('row')).toHaveCount(3);
    await page.keyboard.press('Escape');

    // The same report again is recognised; garbage is refused.
    await page.getByLabel('DMARC report file').setInputFiles({ name: 'report.xml', mimeType: 'text/xml', buffer: Buffer.from(xml) });
    await expect(page.getByRole('alert').filter({ hasText: 'already imported' })).toBeVisible();
    await page.getByLabel('DMARC report file').setInputFiles({ name: 'x.xml', mimeType: 'text/xml', buffer: Buffer.from('<nope/>') });
    await expect(page.getByRole('alert').first()).toBeVisible();
  });

  test('diagnostics, API reference and system log viewer', async ({ page }) => {
    await openAdmin(page, 'Diagnostics');
    await expect(page.getByTestId('deliverability-score')).toHaveText(/^\d+ \/ 100$/, { timeout: 30_000 });
    const ports = page.getByRole('table', { name: 'Port health' });
    await expect(ports.getByRole('row')).toHaveCount(9);
    await expect(ports.getByRole('row', { name: /IMAPS/ })).toContainText(String(PORTS.imaps));
    await expect(ports.getByText('error')).toHaveCount(0);

    await openAdmin(page, 'API reference');
    await page.getByLabel('Filter').fill('/health');
    await page.getByText('Liveness probe').click();
    await page.getByRole('button', { name: 'Try it' }).click();
    await expect(page.getByText('HTTP 200')).toBeVisible();
    await expect(page.locator('pre')).toContainText('"status": "ok"');
    await page.getByLabel('Filter').fill('sieve');
    await expect(page.getByText('Validate and save the Sieve filter script')).toBeVisible();

    await openAdmin(page, 'Logs');
    await page.getByRole('tab', { name: 'System' }).click();
    await page.getByLabel('Search').fill('unoMail is ready');
    await expect(page.getByRole('table', { name: 'System log' }).getByRole('row', { name: /unoMail is ready/ })).toBeVisible();
    await page.getByLabel('Search').fill('');

    // Live tail: a delivery shows up without reloading or polling the page.
    await page.getByRole('tab', { name: 'Mail delivery' }).click();
    await expect(page.getByText('Live tail (connected)')).toBeVisible();
    await smtpDeliver('tail@remote.test', BOB, `From: tail@remote.test\nTo: ${BOB}\nSubject: live tail marker\n\nx\n`);
    await expect(page.getByRole('table', { name: 'Delivery log' }).getByRole('row', { name: /tail@remote\.test/ }).first()).toBeVisible();
  });

  test('a mailbox is imported from another server over IMAP', async ({ page }) => {
    await openAdmin(page, 'Mailboxes');
    await page.getByRole('button', { name: 'Add mailbox' }).click();
    const dialog = page.getByRole('dialog');
    await dialog.getByLabel('E-mail address').fill(`migrated@${DOMAIN}`);
    await dialog.getByLabel('Password', { exact: true }).fill(USER_PASSWORD);
    await dialog.getByRole('button', { name: 'Create' }).click();
    await expect(page.getByText('Mailbox created')).toBeVisible();

    await page.getByRole('button', { name: `Import into migrated@${DOMAIN}` }).click();
    const importer = page.getByRole('dialog');
    await expect(importer.getByRole('button', { name: 'Start import' })).toBeDisabled();
    await importer.getByLabel('IMAP host').fill('127.0.0.1');
    // The source only offers STARTTLS: choosing it switches to the standard port.
    await expect(importer.getByLabel('Port')).toHaveValue('993');
    await importer.getByLabel('Encryption').click();
    await page.getByRole('option', { name: 'STARTTLS' }).click();
    await expect(importer.getByLabel('Port')).toHaveValue('143');
    await importer.getByLabel('Port').fill(String(PORTS.imap));
    await importer.getByLabel('User name').fill(BOB);
    await importer.getByLabel('Remote password').fill(USER_PASSWORD);
    await importer.getByLabel('Accept an invalid or self-signed certificate').check();
    await importer.getByRole('button', { name: 'Start import' }).click();
    await expect(page.getByText('Import started')).toBeVisible();
    const job = importer.getByRole('table', { name: 'Import jobs' }).getByRole('row').nth(1);
    await expect(job).toContainText('ok', { timeout: 30_000 });
    await expect(job).toContainText(`${BOB}@127.0.0.1`);
    await expect(importer.getByLabel('Remote password')).toHaveValue('');
    await importer.getByRole('button', { name: 'Close' }).click();
    await logout(page);

    await login(page, `migrated@${DOMAIN}`, USER_PASSWORD);
    await expect(page.getByTestId('email-row').filter({ hasText: 'Formatted note' })).toHaveCount(1);
    await page.getByRole('navigation', { name: 'Folders' }).getByText('Receipts', { exact: true }).click();
    await expect(page.getByTestId('email-row').filter({ hasText: 'Your receipt #1234' })).toHaveCount(1);
  });
});
