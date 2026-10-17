import { expect, test, type Page } from '@playwright/test';
import { ADMIN, DOMAIN, login, logout, openAdmin, smtpDeliver, USER_PASSWORD } from './helpers';

// Mailboxes of their own, so that nothing here changes what other specs see.
const NINA = `nina@${DOMAIN}`;
const OMAR = `omar@${DOMAIN}`;

async function createMailbox(page: Page, email: string) {
  await page.goto('/admin/mailboxes');
  await page.getByRole('button', { name: 'Add mailbox' }).click();
  const dialog = page.getByRole('dialog');
  await dialog.getByLabel('E-mail address').fill(email);
  await dialog.getByLabel('Password', { exact: true }).fill(USER_PASSWORD);
  await dialog.getByRole('button', { name: 'Create' }).click();
  await expect(page.getByText('Mailbox created').or(dialog.getByText(/already exists/).first())).toBeVisible();
}

function composer(page: Page) {
  return page.getByRole('dialog', { name: 'New message' });
}

async function write(page: Page, to: string, subject: string) {
  await page.getByRole('button', { name: 'Compose' }).click();
  await composer(page).getByLabel('To').fill(to);
  await composer(page).getByLabel('Subject').fill(subject);
  await composer(page).getByRole('textbox', { name: 'Message body' }).click();
  await page.keyboard.type(`Body of ${subject}`);
}

test.describe('mail tools: undo send, scheduled send, snooze, read receipts', () => {
  test.use({ actionTimeout: 15_000 });

  test.beforeAll(async ({ browser }) => {
    const page = await browser.newPage();
    await login(page, ADMIN.email, ADMIN.password);
    await createMailbox(page, NINA);
    await createMailbox(page, OMAR);
    await page.close();
  });

  test('a sent message can be called back, and a scheduled one cancelled', async ({ page }) => {
    await login(page, NINA, USER_PASSWORD);
    await write(page, OMAR, 'Oops, not yet');
    await composer(page).getByRole('button', { name: 'Send', exact: true }).click();
    await expect(page.getByText('Message sent')).toBeVisible();
    await page.getByRole('button', { name: 'Undo' }).click();
    await expect(page.getByText('Sending undone')).toBeVisible();
    // Back in the composer, as it was.
    await expect(composer(page).getByLabel('Subject')).toHaveValue('Oops, not yet');
    await composer(page).getByRole('button', { name: 'Save and close' }).click();

    // Scheduled: waits under "Scheduled" until cancelled.
    await write(page, OMAR, 'See you Monday');
    await composer(page).getByRole('button', { name: 'More options' }).click();
    await page.getByRole('menuitem', { name: /Monday morning/ }).click();
    await expect(page.getByText(/Scheduled for/)).toBeVisible();
    const folders = page.getByRole('navigation', { name: 'Folders' });
    await folders.getByText('Scheduled', { exact: true }).click();
    const row = page.getByTestId('email-row').filter({ hasText: 'See you Monday' });
    await expect(row).toHaveCount(1);
    await row.click();
    const reader = page.getByRole('region', { name: 'Conversation' });
    await expect(reader.getByText('This message is waiting to be sent.')).toBeVisible();
    await reader.getByRole('button', { name: 'Cancel sending' }).click();
    await expect(page.getByText('Sending cancelled. The message is in Drafts')).toBeVisible();
    await logout(page);

    // Nothing arrived.
    await login(page, OMAR, USER_PASSWORD);
    await page.waitForTimeout(7_000);
    await page.reload();
    await expect(page.getByTestId('email-row').filter({ hasText: /Oops, not yet|See you Monday/ })).toHaveCount(0);
  });

  test('snoozed mail leaves the inbox for the Snoozed folder', async ({ page }) => {
    await smtpDeliver('reminder@remote.test', OMAR, `From: Reminder <reminder@remote.test>\nTo: ${OMAR}\nSubject: Renew the domain\n\nThe domain expires next month.\n`);
    await login(page, OMAR, USER_PASSWORD);
    const row = page.getByTestId('email-row').filter({ hasText: 'Renew the domain' });
    await row.click();
    const reader = page.getByRole('region', { name: 'Conversation' });
    await reader.getByRole('button', { name: 'Snooze' }).click();
    await page.getByRole('menuitem', { name: /Next week/ }).click();
    await expect(page.getByText(/Snoozed until/)).toBeVisible();
    await expect(page.getByTestId('email-row').filter({ hasText: 'Renew the domain' })).toHaveCount(0);
    await page.getByRole('navigation', { name: 'Folders' }).getByText('Snoozed', { exact: true }).click();
    await expect(page.getByTestId('email-row').filter({ hasText: 'Renew the domain' })).toHaveCount(1);
  });

  test('a read receipt is sent when the reader agrees', async ({ page }) => {
    await login(page, NINA, USER_PASSWORD);
    await write(page, OMAR, 'Please confirm');
    await composer(page).getByRole('button', { name: 'More options' }).click();
    await page.getByRole('menuitem', { name: 'Request a read receipt' }).click();
    await page.keyboard.press('Escape');
    await composer(page).getByRole('button', { name: 'Send', exact: true }).click();
    await expect(page.getByText('Message sent')).toBeVisible();
    await logout(page);

    await login(page, OMAR, USER_PASSWORD);
    const row = page.getByTestId('email-row').filter({ hasText: 'Please confirm' });
    await expect(row).toHaveCount(1, { timeout: 20_000 });
    await row.click();
    const reader = page.getByRole('region', { name: 'Conversation' });
    await expect(reader.getByText(`${NINA} asked to be told when you have read this message.`)).toBeVisible();
    await reader.getByRole('button', { name: 'Send receipt' }).click();
    await expect(reader.getByText('asked to be told')).toHaveCount(0);
    await logout(page);

    await login(page, NINA, USER_PASSWORD);
    await expect(page.getByTestId('email-row').filter({ hasText: 'Read: Please confirm' })).toHaveCount(1, { timeout: 20_000 });
  });

  test('settings offer sending options, notifications and S/MIME', async ({ page }) => {
    await login(page, NINA, USER_PASSWORD);
    await page.goto('/settings');
    await expect(page.getByLabel('Undo send')).toBeVisible();
    await expect(page.getByLabel('Read receipts')).toBeVisible();
    await expect(page.getByRole('heading', { name: 'Notifications' })).toBeVisible();
    await page.goto('/settings?tab=security');
    await expect(page.getByRole('heading', { name: 'S/MIME certificate' })).toBeVisible();
    await expect(page.getByRole('button', { name: 'Choose .p12 / .pfx file' })).toBeVisible();
  });
});

test.describe('administration: mailing lists, backups, TLS reports', () => {
  test('a mailing list is created and gets members', async ({ page }) => {
    await login(page, ADMIN.email, ADMIN.password);
    await openAdmin(page, 'Mailing lists');
    await page.getByRole('button', { name: 'New list' }).click();
    const dialog = page.getByRole('dialog', { name: 'New mailing list' });
    await dialog.getByLabel('List address').fill(`crew@${DOMAIN}`);
    await dialog.getByLabel('Name').fill('Crew');
    await dialog.getByRole('button', { name: 'Create' }).click();
    await expect(page.getByRole('heading', { name: `crew@${DOMAIN}` })).toBeVisible();
    await page.getByLabel('Add addresses').fill(`${NINA}\n${OMAR}`);
    await page.getByRole('button', { name: 'Add', exact: true }).click();
    await expect(page.getByRole('table', { name: 'Members' }).getByText(OMAR)).toBeVisible();
    await page.getByRole('button', { name: 'All lists' }).click();
    await expect(page.getByRole('table', { name: 'Mailing lists' }).getByText(`crew@${DOMAIN}`)).toBeVisible();

    // A post reaches every member.
    await smtpDeliver(NINA, `crew@${DOMAIN}`, `From: ${NINA}\nTo: crew@${DOMAIN}\nSubject: Crew lunch\n\nFriday?\n`);
    await logout(page);
    await login(page, OMAR, USER_PASSWORD);
    // Mailing-list mail is sorted into the Forums tab.
    await page.getByRole('tab', { name: /Forums/ }).click();
    await expect(page.getByTestId('email-row').filter({ hasText: 'Crew lunch' })).toHaveCount(1, { timeout: 20_000 });
  });

  test('a backup is taken on request and listed', async ({ page }) => {
    await login(page, ADMIN.email, ADMIN.password);
    await openAdmin(page, 'Backups');
    await page.getByRole('button', { name: 'Back up now' }).click();
    const runs = page.getByRole('table', { name: 'Backup runs' });
    await expect(runs.getByText('ok')).toBeVisible({ timeout: 30_000 });
    await expect(page.getByRole('table', { name: 'Snapshots' })).toBeVisible();
  });

  test('the TLS reports page shows its sections', async ({ page }) => {
    await login(page, ADMIN.email, ADMIN.password);
    await openAdmin(page, 'TLS reports');
    await expect(page.getByRole('heading', { name: 'Received reports' })).toBeVisible();
    await expect(page.getByRole('heading', { name: 'Outgoing sessions' })).toBeVisible();
  });
});
