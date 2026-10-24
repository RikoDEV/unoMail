import { expect, test, type Page } from '@playwright/test';
import { ADMIN, DOMAIN, smtpDeliver, USER_PASSWORD } from './helpers';

const BOB = `bob@${DOMAIN}`;

/** Signs in; on a phone the folder list waits in a closed drawer, so the menu button shows it worked. */
async function login(page: Page, email: string, password: string) {
  await page.goto('/login');
  await page.getByLabel('E-mail address').fill(email);
  await page.getByLabel('Password').fill(password);
  await page.getByRole('button', { name: 'Sign in', exact: true }).click();
  await expect(page.getByRole('button', { name: 'Toggle sidebar' })).toBeVisible();
}

test.describe('small screens', () => {
  test.use({ viewport: { width: 390, height: 844 } });

  test('on a phone the list gets the width and the folders slide in', async ({ page }) => {
    await smtpDeliver('dora@remote.test', BOB, `From: Dora <dora@remote.test>\nTo: ${BOB}\nSubject: Read me on the bus\n\nShort note.\n`);
    await login(page, BOB, USER_PASSWORD);
    // Nothing is wider than the screen.
    expect(await page.evaluate(() => document.documentElement.scrollWidth)).toBeLessThanOrEqual(390);

    const folders = page.getByRole('navigation', { name: 'Folders' });
    const row = page.getByTestId('email-row').filter({ hasText: 'Read me on the bus' }).first();
    await expect(row).toBeVisible();
    await expect(folders.getByText('Sent')).not.toBeInViewport();
    await page.getByRole('button', { name: 'Toggle sidebar' }).click();
    await expect(folders.getByText('Sent')).toBeInViewport();
    await folders.getByText('Sent').click();
    // Choosing a folder closes the drawer again.
    await expect(folders.getByText('Sent')).not.toBeInViewport();
    await expect(page).toHaveURL(/\/mail\/sent/);

    // The composer takes the whole screen, and the conversation replaces the list.
    await page.goto('/mail');
    await page.getByRole('button', { name: 'Compose' }).last().click();
    const composer = page.locator('[data-fullscreen]');
    await expect(composer).toHaveAttribute('data-fullscreen', 'true');
    await expect(page.getByRole('button', { name: 'Full screen' })).toHaveCount(0);
    await composer.getByRole('button', { name: 'Discard draft' }).click();
    await row.click();
    await expect(page.getByRole('heading', { name: 'Read me on the bus' })).toBeVisible();
    await expect(row).toBeHidden();

    // Reply, Reply all and Forward stay in one row, which scrolls sideways rather than wrapping.
    const actions = page.getByTestId('reply-actions');
    const tops = await actions.locator(':scope > *').evaluateAll((items) => items.filter((item) => item.getBoundingClientRect().width > 0).map((item) => Math.round(item.getBoundingClientRect().top)));
    expect(tops.length).toBeGreaterThanOrEqual(3);
    expect(new Set(tops).size).toBe(1);
    expect(await actions.evaluate((row) => getComputedStyle(row).overflowX)).toBe('auto');
    expect(await page.evaluate(() => document.documentElement.scrollWidth)).toBeLessThanOrEqual(390);
  });

  test('the calendar and the administration fold their menus away', async ({ page }) => {
    await login(page, ADMIN.email, ADMIN.password);
    await page.goto('/calendar');
    expect(await page.evaluate(() => document.documentElement.scrollWidth)).toBeLessThanOrEqual(390);
    await page.getByRole('button', { name: 'Calendars' }).click();
    await expect(page.getByRole('button', { name: 'New event' }).first()).toBeInViewport();
    await page.keyboard.press('Escape');

    await page.goto('/admin/mailboxes');
    const nav = page.getByRole('navigation', { name: 'Administration' });
    await expect(nav.getByText('Domains')).not.toBeInViewport();
    await page.getByRole('button', { name: 'Administration menu' }).click();
    await nav.getByText('Domains').click();
    await expect(page).toHaveURL(/\/admin\/domains/);
    await expect(nav.getByText('Domains')).not.toBeInViewport();
  });
});
