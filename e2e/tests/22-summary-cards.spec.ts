import { expect, test, type Page } from '@playwright/test';
import http from 'node:http';
import type { AddressInfo } from 'node:net';
import { ADMIN, login, openAdmin, USER_PASSWORD } from './helpers';

async function auth(page: Page) {
  const session = await (await page.request.get('/api/auth/me')).json();
  return { 'x-csrf-token': session.csrf_token as string };
}
async function importMail(page: Page, subject: string, body: string, html = false, day = 1) {
  const headers = await auth(page);
  const session = await (await page.request.get('/jmap/session')).json();
  const accountId = session.primaryAccounts['urn:ietf:params:jmap:mail'];
  const raw = `From: Shop <orders@shop.test>\r\nSubject: ${subject}\r\nDate: ${day} Nov 2026 12:00:00 +0000\r\nContent-Type: text/${html ? 'html' : 'plain'}; charset=utf-8\r\n\r\n${body}`;
  const upload = await page.request.post(`/jmap/upload/${accountId}`, { headers: { ...headers, 'content-type': 'message/rfc822' }, data: Buffer.from(raw) });
  expect(upload.status()).toBe(201);
  const call = async (methodCalls: unknown[]) => (await (await page.request.post('/jmap/api', { headers, data: { using: [], methodCalls } })).json()).methodResponses;
  const boxes = await call([['Mailbox/get', { accountId }, 'boxes']]);
  const inbox = boxes[0][1].list.find((b: { role: string }) => b.role === 'inbox').id;
  const result = await call([['Email/import', { accountId, emails: { mail: { blobId: (await upload.json()).blobId, mailboxIds: { [inbox]: true } } } }, 'import']]);
  expect(result[0][1].created?.mail?.id, JSON.stringify(result)).toBeTruthy();
  return result[0][1].created.mail.id as string;
}
const markup = (data: unknown) => `<script type="application/ld+json">${JSON.stringify(data)}</script><p>Your purchase details are attached to this email.</p>`;
const cards = async (page: Page, id: string) => (await (await page.request.get(`/api/me/summary-cards?email_id=${id}`)).json());

test('structured purchase cards consolidate messages, retain dismissal and follow user settings', async ({ page, browser }) => {
  await login(page, ADMIN.email, ADMIN.password);
  const adminHeaders = await auth(page);
  const created = await page.request.post('/api/accounts', { headers: adminHeaders, data: { email: 'purchase-reader@e2e.test', password: USER_PASSWORD } });
  expect(created.ok(), await created.text()).toBe(true);
  const context = await browser.newContext();
  try {
    const user = await context.newPage();
    await login(user, 'purchase-reader@e2e.test', USER_PASSWORD);
    const order = await importMail(user, 'Purchase confirmation P42', markup({ '@type': 'Order', seller: { name: 'Book Shop' }, orderNumber: 'P42', orderedItem: { name: 'A very good book' }, totalPrice: '12.50', priceCurrency: 'EUR', url: 'https://shop.test/orders/P42' }), true);
    const shippingData = { '@type': 'ParcelDelivery', partOfOrder: { seller: { name: 'Book Shop' }, orderNumber: 'P42' }, carrier: { name: 'Parcel Service' }, trackingNumber: 'TRACK42', trackingUrl: 'https://carrier.test/track/42', expectedArrivalFrom: '2026-11-04', expectedArrivalUntil: '2026-11-05', deliveryStatus: { eventType: 'Shipped' } };
    await importMail(user, 'Purchase shipped P42', markup(shippingData), true, 2);
    await expect.poll(async () => (await cards(user, order)).cards[0]?.purchase.status).toBe('shipped');
    await user.reload();
    await user.getByTestId('email-row').filter({ hasText: 'Purchase confirmation P42' }).click();
    const card = user.getByRole('article', { name: 'Purchase from Book Shop', exact: true });
    await expect(card).toBeVisible();
    await expect(card).toContainText('A very good book');
    await expect(card).toContainText('12.50');
    await expect(card.getByRole('link', { name: 'View order', exact: true })).toHaveAttribute('href', 'https://shop.test/orders/P42');
    await expect(card.getByRole('link', { name: 'Track package', exact: true })).toHaveAttribute('href', 'https://carrier.test/track/42');
    await expect(card).toContainText('TRACK42');
    await card.getByRole('button', { name: 'Related messages', exact: true }).click();
    await expect(card.getByRole('link', { name: 'Purchase shipped P42', exact: true })).toBeVisible();
    await card.getByRole('button', { name: 'Dismiss', exact: true }).click();
    await expect(card).toHaveCount(0);
    await user.reload();
    await expect(user.getByRole('button', { name: 'Show summary card', exact: true })).toBeVisible();
    await user.getByRole('button', { name: 'Show summary card', exact: true }).click();
    await expect(card).toBeVisible();
    await importMail(user, 'Purchase delivered P42', markup({ ...shippingData, deliveryStatus: { eventType: 'Delivered' } }), true, 3);
    await expect.poll(async () => (await cards(user, order)).cards[0]?.purchase.status).toBe('delivered');
    await user.reload();
    await expect(card.getByText('Delivered', { exact: true }).first()).toBeVisible();
    const readerUrl = user.url();
    await user.goto('/settings?tab=inbox');
    await user.getByLabel('Show summary cards', { exact: true }).uncheck();
    await expect.poll(async () => (await (await user.request.get('/api/me/preferences')).json()).summary_cards).toBe(false);
    await user.goto(readerUrl);
    await expect(user.getByRole('region', { name: 'Summary cards', exact: true })).toHaveCount(0);
    expect((await page.request.get(`/api/me/summary-cards?email_id=${order}`)).status()).toBe(404);
    const id = (await cards(user, order)).cards[0]?.id;
    // Disabled users receive no stored card payload.
    expect(id).toBeUndefined();
  } finally { await context.close(); }
});

test('AI extraction is explicit or requires both automatic-processing switches', async ({ page, browser }) => {
  const requests: unknown[] = [];
  const provider = http.createServer((req, res) => {
    let raw = '';
    req.on('data', (chunk) => { raw += chunk; });
    req.on('end', () => {
      const body = JSON.parse(raw);
      requests.push(body);
      const source = body.messages[1].content as string;
      const number = source.match(/Shop order (AI\d+)/)?.[1] ?? 'UNKNOWN';
      const content = JSON.stringify({ purchases: [{ purchase: { merchant: 'Shop', order_number: number, status: 'shipped', order_url: 'https://invented.test/order', shipments: [{ tracking_number: 'TRACK-AI', tracking_url: 'https://carrier.test/ai', delivery_until: '2026-11-10', status: 'shipped' }] }, evidence: `Shop order ${number} ships on 2026-11-10.` }] });
      res.writeHead(200, { 'content-type': 'application/json' });
      res.end(JSON.stringify({ choices: [{ message: { content } }] }));
    });
  });
  await new Promise<void>((resolve) => provider.listen(0, '127.0.0.1', resolve));
  const context = await browser.newContext();
  let modelId = '';
  try {
    await login(page, ADMIN.email, ADMIN.password);
    const headers = await auth(page);
    const modelResponse = await page.request.post('/api/models', { headers, data: { name: 'Purchase extractor', provider: 'custom', model: 'extractor', base_url: `http://127.0.0.1:${(provider.address() as AddressInfo).port}/v1`, enabled: true } });
    expect(modelResponse.ok()).toBe(true);
    modelId = (await modelResponse.json()).id;
    await openAdmin(page, 'Models');
    const settings = page.getByRole('region', { name: 'Summary card extraction', exact: true });
    await settings.getByLabel('Extraction model', { exact: true }).click();
    await page.getByRole('option', { name: 'Purchase extractor', exact: true }).click();
    await settings.getByLabel('Allow automatic AI extraction', { exact: true }).check();
    await settings.getByRole('button', { name: 'Save extraction settings', exact: true }).click();
    await expect(settings.getByText('Extraction settings saved')).toBeVisible();
    expect((await page.request.post('/api/accounts', { headers, data: { email: 'purchase-ai@e2e.test', password: USER_PASSWORD } })).ok()).toBe(true);
    const user = await context.newPage();
    await login(user, 'purchase-ai@e2e.test', USER_PASSWORD);
    const userHeaders = await auth(user);
    const message = (number: string) => `Shop order ${number} ships on 2026-11-10.\nTracking number TRACK-AI\nhttps://carrier.test/ai`;
    const first = await importMail(user, 'Order AI42', message('AI42'));
    await expect.poll(async () => (await cards(user, first)).state).toBe('done');
    expect(requests).toHaveLength(0); // User has not opted in.
    await user.reload();
    await user.getByTestId('email-row').filter({ hasText: 'Order AI42' }).click();
    await user.getByRole('button', { name: 'Extract summary card with AI', exact: true }).click();
    const card = user.getByRole('article', { name: 'Purchase from Shop', exact: true });
    await expect(card).toBeVisible();
    expect(requests).toHaveLength(1);
    await expect(card.getByRole('link', { name: 'View order', exact: true })).toHaveCount(0); // Invented URL is rejected.
    await expect(card.getByRole('link', { name: 'Track package', exact: true })).toHaveAttribute('href', 'https://carrier.test/ai');
    await user.goto('/settings?tab=inbox');
    await user.getByLabel('Automatically extract summary cards with AI', { exact: true }).check();
    await expect.poll(async () => (await (await user.request.get('/api/me/preferences')).json()).summary_cards_ai).toBe(true);
    const second = await importMail(user, 'Order AI43', message('AI43'));
    await expect.poll(async () => (await cards(user, second)).cards.length).toBe(1);
    expect(requests).toHaveLength(2);
    const config = { model_id: modelId, automatic_ai: false };
    expect((await page.request.put('/api/models/summary-cards', { headers, data: config })).ok()).toBe(true);
    const third = await importMail(user, 'Order AI44', message('AI44'));
    await expect.poll(async () => (await cards(user, third)).state).toBe('done');
    expect(requests).toHaveLength(2); // Admin switch is off.
    const prefs = await (await user.request.get('/api/me/preferences')).json();
    expect((await user.request.put('/api/me/preferences', { headers: userHeaders, data: { ...prefs, summary_cards_ai: false } })).ok()).toBe(true);
    expect((await page.request.put('/api/models/summary-cards', { headers, data: { ...config, automatic_ai: true } })).ok()).toBe(true);
    const fourth = await importMail(user, 'Order AI45', message('AI45'));
    await expect.poll(async () => (await cards(user, fourth)).state).toBe('done');
    expect(requests).toHaveLength(2); // User switch is off again.
    const before = await user.request.get('/api/models/summary-cards');
    expect(before.status()).toBe(403);
  } finally {
    const headers = await auth(page);
    await page.request.put('/api/models/summary-cards', { headers, data: { model_id: '', automatic_ai: false } });
    if (modelId) await page.request.delete(`/api/models/${modelId}`, { headers });
    await context.close();
    provider.close();
  }
});
