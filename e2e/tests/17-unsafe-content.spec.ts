import { expect, test } from '@playwright/test';
import { DOMAIN, login, openAdmin, smtpDeliver, USER_PASSWORD } from './helpers';

// A mailbox of its own, so these messages do not show up in the other specs.
const ERIN = `erin@${DOMAIN}`;
const ADMIN_EMAIL = 'admin@e2e.test';
const ADMIN_PASSWORD = 'e2e-admin-password-1';

function phishing(subject: string, attachment: string) {
  return [
    `From: "support@paypal.com" <jane@evil.test>`,
    `To: ${ERIN}`,
    `Subject: ${subject}`,
    'MIME-Version: 1.0',
    'Content-Type: multipart/mixed; boundary="b1"',
    '',
    '--b1',
    'Content-Type: text/html; charset=utf-8',
    '',
    '<p>Your account is locked. <a href="https://evil.test/login">https://paypal.com/login</a></p><p><a href="https://example.org/help">Help</a></p>',
    '--b1',
    'Content-Type: application/octet-stream',
    `Content-Disposition: attachment; filename="${attachment}"`,
    'Content-Transfer-Encoding: base64',
    '',
    'UEsDBAoAAAAAAA==',
    '--b1--',
    '',
  ].join('\n');
}

test.describe('unsafe content', () => {
  test.beforeAll(async ({ browser }) => {
    const page = await browser.newPage();
    await login(page, ADMIN_EMAIL, ADMIN_PASSWORD);
    await page.goto('/admin/mailboxes');
    await page.getByRole('button', { name: 'Add mailbox' }).click();
    const dialog = page.getByRole('dialog');
    await dialog.getByLabel('E-mail address').fill(ERIN);
    await dialog.getByLabel('Password', { exact: true }).fill(USER_PASSWORD);
    await dialog.getByRole('button', { name: 'Create' }).click();
    await expect(page.getByText('Mailbox created').or(dialog.getByRole('alert').filter({ hasText: 'already exists' }))).toBeVisible();
    await page.close();
  });

  test('deceptive links, risky attachments and misleading names are flagged', async ({ page }) => {
    await smtpDeliver('jane@evil.test', ERIN, phishing('Account locked', 'budget.xlsm'));
    await login(page, ERIN, USER_PASSWORD);
    await page.getByTestId('email-row').filter({ hasText: 'Account locked' }).click();

    await expect(page.getByTestId('sender-name-warning')).toContainText('support@paypal.com');

    // The link names paypal.com but goes elsewhere: the reader asks first, Cancel is the default.
    const body = page.frameLocator('iframe[title="Message body"]');
    await body.getByRole('link', { name: 'https://paypal.com/login' }).click();
    const linkDialog = page.getByRole('dialog', { name: 'Careful with this link' });
    await expect(linkDialog).toContainText('The link says paypal.com, but it goes to evil.test.');
    await expect(linkDialog.getByRole('button', { name: 'Cancel' })).toBeFocused();
    const popups: string[] = [];
    page.context().on('page', (popup) => popups.push(popup.url()));
    await linkDialog.getByRole('button', { name: 'Cancel' }).click();
    await expect(linkDialog).toBeHidden();
    // An honest link shows its destination and opens without a question.
    await expect(body.getByRole('link', { name: 'Help' })).toHaveAttribute('title', 'https://example.org/help');

    // A macro-enabled document is marked and needs a confirmation before it is saved.
    const chip = page.locator('[data-risk="caution"]').filter({ hasText: 'budget.xlsm' });
    await expect(chip).toBeVisible();
    await chip.click();
    const fileDialog = page.getByRole('dialog', { name: 'Download budget.xlsm?' });
    await expect(fileDialog).toContainText('macros');
    const download = page.waitForEvent('download');
    await fileDialog.getByRole('button', { name: 'Download anyway' }).click();
    expect((await download).suggestedFilename()).toBe('budget.xlsm');
    expect(popups).toEqual([]);
  });

  test('programs are refused by the server, inbound and from the web client', async ({ page }) => {
    await expect(smtpDeliver('jane@evil.test', ERIN, phishing('Your invoice', 'Invoice.pdf.exe'))).rejects.toThrow(
      /552 5\.7\.0 Message refused: it contains an executable attachment \(Invoice\.pdf\.exe\)/,
    );
    await expect(smtpDeliver('jane@evil.test', ERIN, phishing('Zipped invoice', 'invoice.zip'))).resolves.toBeUndefined();

    await login(page, ERIN, USER_PASSWORD);
    await page.getByRole('button', { name: 'Compose' }).click();
    const composer = page.getByRole('dialog', { name: 'New message' });
    await composer.getByLabel('To').fill(ERIN);
    await composer.getByLabel('Subject').fill('Here is the tool');
    await composer.getByLabel('Attachment files').setInputFiles({ name: 'tool.scr', mimeType: 'application/octet-stream', buffer: Buffer.from('MZ') });
    await expect(composer.getByText(/tool\.scr/)).toBeVisible();
    await composer.getByRole('button', { name: 'Send' }).click();
    await expect(page.getByText(/executable attachment \(tool\.scr\)/)).toBeVisible({ timeout: 20_000 });
  });

  test('the administrator is told when mail is not scanned for viruses', async ({ page }) => {
    await login(page, ADMIN_EMAIL, ADMIN_PASSWORD);
    await page.goto('/admin');
    await expect(page.getByTestId('no-virus-scanner')).toContainText('not scanned for viruses');
    await openAdmin(page, 'Diagnostics');
    await expect(page.getByTestId('virus-scanner-status')).toContainText('not scanned for malware', { timeout: 30_000 });
    await openAdmin(page, 'Server settings');
    await expect(page.getByLabel('Refuse executable attachments')).toBeChecked();
  });
});
