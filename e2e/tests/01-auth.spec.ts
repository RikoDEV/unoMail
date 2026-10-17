import { expect, test } from '@playwright/test';
import { ADMIN, login, logout } from './helpers';

test.describe('authentication', () => {
  test('unauthenticated visitors are sent to the login page', async ({ page }) => {
    for (const path of ['/', '/mail', '/admin/dashboard', '/settings']) {
      await page.goto(path);
      await expect(page).toHaveURL(/\/login$/);
    }
    // The API itself refuses as well; the redirect is not the only protection.
    expect((await page.request.get('/api/dashboard')).status()).toBe(401);
    expect((await page.request.get('/jmap/session')).status()).toBe(401);
  });

  test('wrong credentials show a generic error', async ({ page }) => {
    await page.goto('/login');
    await page.getByLabel('E-mail address').fill(ADMIN.email);
    await page.getByLabel('Password').fill('not the password');
    await page.getByRole('button', { name: 'Sign in', exact: true }).click();
    await expect(page.getByRole('alert')).toHaveText('Incorrect e-mail address or password.');
    await expect(page).toHaveURL(/\/login$/);
  });

  test('login, session cookie hardening and logout', async ({ page, context }) => {
    await login(page, ADMIN.email, ADMIN.password);
    await expect(page).toHaveURL(/\/mail/);

    const cookies = await context.cookies();
    const session = cookies.find((c) => c.name === 'unomail');
    expect(session, 'session cookie').toBeDefined();
    expect(session!.httpOnly).toBe(true);
    expect(session!.sameSite).toBe('Strict');
    // The token is not reachable from scripts running in the page.
    expect(await page.evaluate(() => document.cookie)).not.toContain('unomail');

    await page.reload();
    await expect(page.getByRole('navigation', { name: 'Folders' })).toBeVisible();

    await logout(page);
    await page.goto('/mail');
    await expect(page).toHaveURL(/\/login$/);
    expect((await page.request.get('/api/auth/me')).status()).toBe(401);
  });

  test('responses carry the security headers', async ({ page }) => {
    const response = await page.goto('/login');
    const headers = response!.headers();
    expect(headers['content-security-policy']).toContain("default-src 'self'");
    expect(headers['content-security-policy']).toContain("frame-ancestors 'none'");
    expect(headers['x-content-type-options']).toBe('nosniff');
    expect(headers['x-frame-options']).toBe('DENY');
    expect(headers['referrer-policy']).toBe('no-referrer');
  });

  test('failed logout locks mail across reloads until server revocation succeeds', async ({ page }) => {
    await login(page, ADMIN.email, ADMIN.password);
    await page.evaluate(() => localStorage.setItem('unomail.cache.audit', JSON.stringify({ secret: 'mail' })));
    await page.route('**/api/auth/logout', (route) => route.abort());
    await page.getByRole('button', { name: 'Account menu' }).click();
    await page.getByRole('menuitem', { name: 'Sign out', exact: true }).click();
    await expect(page.getByRole('alert')).toContainText('server sign-out could not be confirmed');
    expect(await page.evaluate(() => localStorage.getItem('unomail.cache.audit'))).toBeNull();
    await page.reload();
    await expect(page.getByRole('button', { name: 'Retry sign-out' })).toBeVisible();
    await expect(page.getByRole('navigation', { name: 'Folders' })).toHaveCount(0);
    await page.unroute('**/api/auth/logout');
    await page.getByRole('button', { name: 'Retry sign-out' }).click();
    await expect(page.getByRole('button', { name: 'Sign in', exact: true })).toBeVisible();
    expect((await page.request.get('/api/auth/me')).status()).toBe(401);
  });

  test('expired sessions clear persisted mail on return to the login page', async ({ page }) => {
    await login(page, ADMIN.email, ADMIN.password);
    await page.evaluate(() => localStorage.setItem('unomail.cache.audit', 'sensitive mail'));
    const current = await (await page.request.get('/api/auth/me')).json();
    expect((await page.request.post('/api/auth/logout', { headers: { 'X-CSRF-Token': current.csrf_token }, data: { all: true } })).ok()).toBe(true);
    await page.reload();
    await expect(page.getByRole('button', { name: 'Sign in', exact: true })).toBeVisible();
    expect(await page.evaluate(() => localStorage.getItem('unomail.cache.audit'))).toBeNull();
  });
});
