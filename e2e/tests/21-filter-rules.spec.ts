import { expect, test, type Page } from '@playwright/test';
import { DOMAIN, login, smtpDeliver, USER_PASSWORD } from './helpers';

const BOB = `bob@${DOMAIN}`;

/** A select field by its label; its accessible name also carries the value chosen. */
const select = (container: ReturnType<Page['getByRole']>, field: string) => container.getByRole('combobox', { name: new RegExp(`^${field}( |$)`) });

/** Picks an option of a select field inside the given container. */
async function choose(page: Page, container: ReturnType<Page['getByRole']>, field: string, option: string) {
  await select(container, field).click();
  await page.getByRole('option', { name: option, exact: true }).click();
}

test.describe('visual filter rules', () => {
  test('rules are built without Sieve, kept in order and applied to incoming mail', async ({ page }) => {
    await login(page, BOB, USER_PASSWORD);
    await page.goto('/settings?tab=filters');
    page.once('dialog', (dialog) => void dialog.accept('visual'));
    await page.getByRole('button', { name: 'New script' }).click();
    await expect(page.getByText('No rules yet.', { exact: false })).toBeVisible();

    // Invoices go to Receipts, already read.
    await page.getByRole('button', { name: 'Add rule' }).click();
    let dialog = page.getByRole('dialog');
    await dialog.getByRole('button', { name: 'Save rule' }).click();
    await expect(dialog.getByRole('alert')).toContainText('Give the rule a name.');
    await dialog.getByLabel('Rule name').fill('Invoices');
    await dialog.getByTestId('condition').getByRole('textbox', { name: 'Value' }).fill('invoice');
    await choose(page, dialog.getByTestId('action'), 'Folder', 'Receipts');
    await dialog.getByRole('button', { name: 'Add action' }).click();
    await expect(select(dialog.getByTestId('action').nth(1), 'Action')).toHaveText('Mark as read');
    await dialog.getByRole('button', { name: 'Save rule' }).click();
    await expect(dialog).toBeHidden();

    // Mail from the boss is starred and labelled, and no later rule touches it.
    await page.getByRole('button', { name: 'Add rule' }).click();
    dialog = page.getByRole('dialog');
    await dialog.getByLabel('Rule name').fill('Boss');
    await choose(page, dialog.getByTestId('condition'), 'Field', 'From');
    await choose(page, dialog.getByTestId('condition'), 'Comparison', 'is');
    await dialog.getByTestId('condition').getByRole('textbox', { name: 'Value' }).fill('boss@remote.test');
    await choose(page, dialog.getByTestId('action'), 'Action', 'Add label');
    await dialog.getByTestId('action').getByRole('combobox', { name: 'Label', exact: true }).fill('VIP');
    await dialog.getByRole('button', { name: 'Add action' }).click();
    await choose(page, dialog.getByTestId('action').nth(1), 'Action', 'Star');
    await dialog.getByLabel('Stop here: later rules are not applied to matching messages').check();
    await dialog.getByRole('button', { name: 'Save rule' }).click();

    const rules = page.getByTestId('rule');
    await expect(rules).toHaveCount(2);
    await expect(rules.nth(0)).toContainText('Subject contains “invoice” → Move to folder Receipts, Mark as read');
    await expect(rules.nth(1)).toContainText('From is “boss@remote.test” → Add label vip, Star, then stop');
    await page.getByRole('button', { name: 'Move Boss up' }).click();
    await expect(rules.nth(0)).toContainText('Boss');

    await page.getByLabel('Filters enabled').check();
    await page.getByRole('button', { name: 'Save filters' }).click();
    await expect(page.getByText('Filter script saved.')).toBeVisible();

    // The rules come back from the server as they were saved.
    await page.reload();
    await page.getByLabel('Script', { exact: true }).click();
    await page.getByRole('option', { name: /^visual/ }).click();
    await expect(rules).toHaveCount(2);
    await expect(rules.nth(0)).toContainText('Boss');
    await page.getByRole('tab', { name: 'Sieve script' }).click();
    await expect(page.getByLabel('Sieve script')).toHaveValue(/fileinto "Receipts";/);
    // Once changed by hand, the script is no longer shown as rules.
    await page.getByLabel('Sieve script').press('End');
    await page.getByLabel('Sieve script').pressSequentially('# my own note\n');
    await page.getByRole('tab', { name: 'Rules' }).click();
    await expect(page.getByText('This script was written or changed by hand')).toBeVisible();

    await smtpDeliver('shop@remote.test', BOB, `From: Shop <shop@remote.test>\nTo: ${BOB}\nSubject: Your invoice 2026-17\n\nAmount due: 12 EUR\n`);
    await smtpDeliver('boss@remote.test', BOB, `From: The Boss <boss@remote.test>\nTo: ${BOB}\nSubject: Quick question about the invoice\n\nCall me.\n`);
    await page.goto('/mail');
    const folders = page.getByRole('navigation', { name: 'Folders' });
    // The boss's mail stayed in the Inbox (the stop kept it out of Receipts), labelled.
    const boss = page.getByTestId('email-row').filter({ hasText: 'Quick question about the invoice' });
    await expect(boss).toContainText('vip', { timeout: 20_000 });
    await folders.getByText('Receipts', { exact: true }).click();
    const invoice = page.getByTestId('email-row').filter({ hasText: 'Your invoice 2026-17' });
    await expect(invoice).toHaveCount(1);
    await expect(invoice).toHaveAttribute('data-unread', 'false');
    await expect(page.getByTestId('email-row').filter({ hasText: 'Quick question about the invoice' })).toHaveCount(0);

    // Leave the other specs' filters as they were.
    await page.goto('/settings?tab=filters');
    await page.getByLabel('Script', { exact: true }).click();
    await page.getByRole('option', { name: /^visual/ }).click();
    page.once('dialog', (dialog) => void dialog.accept());
    await page.getByRole('button', { name: 'Delete script' }).click();
    await expect(page.getByText('Script "visual" deleted.')).toBeVisible();
  });
});
