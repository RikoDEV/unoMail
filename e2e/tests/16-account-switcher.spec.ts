import { expect, test, type Page } from '@playwright/test';
import { DOMAIN, login, USER_PASSWORD } from './helpers';

const ALICE = `alice@${DOMAIN}`;
const BOB = `bob@${DOMAIN}`;

async function openMenu(page: Page) {
  await page.getByRole('button', { name: 'Account menu' }).click();
  return page.getByRole('menu');
}

async function currentAccount(page: Page) {
  const menu = await openMenu(page);
  const shown = (await menu.locator('p').nth(1).textContent()) ?? '';
  await page.keyboard.press('Escape');
  return shown;
}

test.describe('account switcher', () => {
  test('two accounts are signed in at once and switched between', async ({ page, context }) => {
    await login(page, ALICE, USER_PASSWORD);

    // Add Bob without signing Alice out.
    let menu = await openMenu(page);
    await menu.getByRole('menuitem', { name: 'Add another account' }).click();
    await expect(page.getByText('Add another account')).toBeVisible();
    await page.getByLabel('E-mail address').fill(BOB);
    await page.getByLabel('Password').fill(USER_PASSWORD);
    await page.getByRole('button', { name: 'Sign in', exact: true }).click();
    await expect(page.getByRole('navigation', { name: 'Folders' })).toBeVisible();
    expect(await currentAccount(page)).toBe(BOB);

    // A second tab follows the browser's current account.
    const other = await context.newPage();
    await other.goto('/mail');
    await expect(other.getByRole('navigation', { name: 'Folders' })).toBeVisible();

    // Alice is one click away.
    menu = await openMenu(page);
    await menu.getByRole('menuitem', { name: `Switch to ${ALICE}` }).click();
    await expect(page.getByRole('navigation', { name: 'Folders' })).toBeVisible();
    expect(await currentAccount(page)).toBe(ALICE);
    await other.waitForLoadState('load');
    await expect(other.getByRole('navigation', { name: 'Folders' })).toBeVisible();
    expect(await currentAccount(other)).toBe(ALICE);
    await other.close();

    // Signing out of Alice continues with Bob; then out of everything.
    menu = await openMenu(page);
    await menu.getByRole('menuitem', { name: `Sign out of ${ALICE}` }).click();
    await expect(page.getByRole('navigation', { name: 'Folders' })).toBeVisible();
    expect(await currentAccount(page)).toBe(BOB);
    menu = await openMenu(page);
    await expect(menu.getByRole('menuitem', { name: /Switch to/ })).toHaveCount(0);
    await menu.getByRole('menuitem', { name: 'Sign out' }).click();
    await expect(page.getByRole('button', { name: 'Sign in', exact: true })).toBeVisible();
  });

  test('every account can be signed out at once', async ({ page }) => {
    await login(page, ALICE, USER_PASSWORD);
    await page.goto('/login?add=1');
    await page.getByLabel('E-mail address').fill(BOB);
    await page.getByLabel('Password').fill(USER_PASSWORD);
    await page.getByRole('button', { name: 'Sign in', exact: true }).click();
    await expect(page.getByRole('navigation', { name: 'Folders' })).toBeVisible();
    const menu = await openMenu(page);
    await menu.getByRole('menuitem', { name: 'Sign out of all accounts' }).click();
    await expect(page.getByRole('button', { name: 'Sign in', exact: true })).toBeVisible();
    // Neither comes back.
    await page.goto('/mail');
    await expect(page.getByRole('button', { name: 'Sign in', exact: true })).toBeVisible();
  });
});
