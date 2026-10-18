import { expect, test, type Page } from '@playwright/test';
import { DOMAIN, login, smtpDeliver, USER_PASSWORD } from './helpers';

// A mailbox of its own, so the counts here do not depend on the other specs.
const FIONA = `fiona@${DOMAIN}`;
const ADMIN_EMAIL = 'admin@e2e.test';
const ADMIN_PASSWORD = 'e2e-admin-password-1';

const rows = (page: Page) => page.getByTestId('email-row');
const folders = (page: Page) => page.getByRole('navigation', { name: 'Folders' });

async function openSettings(page: Page, tab: string) {
  await page.getByRole('button', { name: 'Account menu' }).click();
  await page.getByRole('menuitem', { name: 'Settings' }).click();
  await page.getByRole('tab', { name: tab }).click();
}

test.describe('spam reports and interface language', () => {
  test.beforeAll(async ({ browser }) => {
    const page = await browser.newPage();
    await login(page, ADMIN_EMAIL, ADMIN_PASSWORD);
    await page.goto('/admin/mailboxes');
    await page.getByRole('button', { name: 'Add mailbox' }).click();
    const dialog = page.getByRole('dialog');
    await dialog.getByLabel('E-mail address').fill(FIONA);
    await dialog.getByLabel('Password', { exact: true }).fill(USER_PASSWORD);
    await dialog.getByRole('button', { name: 'Create' }).click();
    await expect(page.getByText('Mailbox created').or(dialog.getByText(/already exists/).first())).toBeVisible();
    await page.close();
  });

  test('reporting spam and "Not spam" teach the personal filter', async ({ page }) => {
    await smtpDeliver('prizes@lottery.test', FIONA, `From: Prize Desk <prizes@lottery.test>\nTo: ${FIONA}\nSubject: You won a million\n\nClaim your prize now, winner!\n`);
    await login(page, FIONA, USER_PASSWORD);
    await rows(page).filter({ hasText: 'You won a million' }).click();
    await page.getByRole('region', { name: 'Conversation' }).getByRole('button', { name: 'Report spam' }).click();
    await expect(page.getByText('Reported as spam')).toBeVisible();

    await openSettings(page, 'Inbox');
    const filter = page.getByTestId('spam-filter');
    await expect(filter).toContainText('Still learning: 1 of 10 spam and 0 of 10 wanted messages seen.', { timeout: 10_000 });

    // In Junk the reader offers "Not spam" instead; it moves the message back and is learned.
    await page.goto('/mail');
    await folders(page).getByRole('button', { name: /^Junk/ }).click();
    await rows(page).filter({ hasText: 'You won a million' }).click();
    const reader = page.getByRole('region', { name: 'Conversation' });
    await expect(reader.getByRole('button', { name: 'Report spam' })).toHaveCount(0);
    await reader.getByRole('button', { name: 'Not spam' }).click();
    await expect(page.getByText('Marked as not spam and moved to the inbox')).toBeVisible();
    await openSettings(page, 'Inbox');
    await expect(filter).toContainText('Still learning: 0 of 10 spam and 1 of 10 wanted messages seen.', { timeout: 10_000 });

    // It can be told to forget.
    await filter.getByRole('button', { name: 'Forget what it learned' }).click();
    await page.getByRole('dialog', { name: 'Reset the spam filter?' }).getByRole('button', { name: 'Reset' }).click();
    await expect(filter).toContainText('Still learning: 0 of 10 spam and 0 of 10 wanted messages seen.');
    await expect(filter.getByRole('button', { name: 'Forget what it learned' })).toHaveCount(0);
  });

  test('the interface language is chosen in the header and follows the account', async ({ page, browser }) => {
    await login(page, FIONA, USER_PASSWORD);
    await openSettings(page, 'General');
    await page.getByRole('button', { name: 'Interface language' }).click();
    await page.getByRole('menuitem', { name: 'Polski' }).click();

    // The page reloads in Polish.
    await expect(page.getByRole('heading', { name: 'Ustawienia', level: 1 })).toBeVisible();
    await expect(page.locator('html')).toHaveAttribute('lang', 'pl');
    await page.goto('/mail');
    const foldery = page.getByRole('navigation', { name: 'Foldery' });
    await expect(foldery.getByRole('button', { name: /^Odebrane/ })).toBeVisible();
    await expect(foldery.getByRole('button', { name: /^Wysłane/ })).toBeVisible();
    await expect(page.getByRole('button', { name: 'Napisz' })).toBeVisible();

    // Another device (a fresh browser) picks the language up from the account after signing in.
    const other = await browser.newContext({ locale: 'en-US' });
    const second = await other.newPage();
    await second.goto('/login');
    await expect(second.getByRole('button', { name: 'Sign in', exact: true })).toBeVisible();
    await second.getByLabel('E-mail address').fill(FIONA);
    await second.getByLabel('Password').fill(USER_PASSWORD);
    await second.getByRole('button', { name: 'Sign in', exact: true }).click();
    await expect(second.getByRole('navigation', { name: 'Foldery' })).toBeVisible();
    await other.close();

    // Back to English, by the same button.
    await page.getByRole('button', { name: 'Menu konta' }).click();
    await page.getByRole('menuitem', { name: 'Ustawienia' }).click();
    await page.getByRole('button', { name: 'Język interfejsu' }).click();
    await page.getByRole('menuitem', { name: 'English' }).click();
    await expect(page.getByRole('heading', { name: 'Settings', level: 1 })).toBeVisible();
  });

  test('the sign-in page has its own language switch', async ({ page }) => {
    await page.goto('/login');
    await page.getByRole('combobox', { name: 'Language' }).click();
    await page.getByRole('option', { name: 'Polski' }).click();
    await expect(page.getByRole('button', { name: 'Zaloguj się', exact: true })).toBeVisible();
    await expect(page.getByLabel('Adres e-mail')).toBeVisible();
    await page.getByRole('combobox', { name: 'Język' }).click();
    await page.getByRole('option', { name: 'English' }).click();
    await expect(page.getByRole('button', { name: 'Sign in', exact: true })).toBeVisible();
  });
});
