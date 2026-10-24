import { expect, test } from '@playwright/test';
import { ADMIN, login } from './helpers';

test.describe('installable web app', () => {
  test('serves a manifest the page links to', async ({ page, request }) => {
    await page.goto('/login');
    await expect(page.locator('link[rel="manifest"]')).toHaveAttribute('href', '/manifest.webmanifest');
    const response = await request.get('/manifest.webmanifest');
    expect(response.ok()).toBe(true);
    const manifest = await response.json();
    expect(manifest).toMatchObject({ name: 'unoMail', start_url: '/mail', display: 'standalone' });
    for (const icon of manifest.icons) {
      const file = await request.get(icon.src);
      expect(file.ok()).toBe(true);
      expect(file.headers()['content-type']).toContain(icon.type);
    }
    // Install prompts and splash screens want raster icons, not only SVG.
    expect(manifest.icons).toContainEqual(expect.objectContaining({ sizes: '512x512', type: 'image/png', purpose: 'any' }));
    expect(manifest.icons).toContainEqual(expect.objectContaining({ sizes: '512x512', type: 'image/png', purpose: 'maskable' }));
  });

  test('starts offline from the cached shell', async ({ page, context }) => {
    await login(page, ADMIN.email, ADMIN.password);
    await page.evaluate(() => navigator.serviceWorker.ready);
    // The first load happened before the worker controlled the page; this one fills the cache.
    await page.reload();
    await expect.poll(() => page.evaluate(async () => (await caches.open('unomail-shell-v1')).match('/').then(Boolean))).toBe(true);
    await context.setOffline(true);
    await page.reload();
    await expect(page.locator('#root')).not.toBeEmpty();
    await context.setOffline(false);
  });
});
