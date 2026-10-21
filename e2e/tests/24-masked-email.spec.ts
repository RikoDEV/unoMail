import { expect, test, type Page } from '@playwright/test';
import { ADMIN, login, openAdmin, smtpDeliver, USER_PASSWORD } from './helpers';
async function auth(page: Page) { return { 'x-csrf-token': (await (await page.request.get('/api/auth/me')).json()).csrf_token as string }; }
async function account(page: Page, email: string) {
  const response = await page.request.post('/api/accounts', { headers: await auth(page), data: { email, password: USER_PASSWORD } });
  expect(response.ok(), await response.text()).toBe(true); return response.json();
}
const settings = (page: Page) => page.goto('/settings?tab=masked-addresses');

test('masked addresses receive Bcc mail, reply without the primary address, and stay blocked after deletion', async ({ page, browser }) => {
  await login(page, ADMIN.email, ADMIN.password);
  const owner = await account(page, 'mask-user@e2e.test');
  await account(page, 'mask-recipient@e2e.test');
  const context = await browser.newContext();
  const recipientContext = await browser.newContext();
  try {
    const user = await context.newPage();
    await login(user, owner.email, USER_PASSWORD);
    await settings(user);
    await user.getByRole('button', { name: 'Create masked address', exact: true }).click();
    const dialog = user.getByRole('dialog');
    await dialog.getByLabel('Description', { exact: true }).fill('Shopping');
    await dialog.getByLabel('Website', { exact: true }).fill('https://shop.example/signup');
    await dialog.getByLabel('Address prefix', { exact: true }).fill('shop');
    const created = user.waitForResponse((r) => r.url().endsWith('/api/me/masked-addresses') && r.request().method() === 'POST');
    await dialog.getByRole('button', { name: 'Save', exact: true }).click();
    const mask = await (await created).json();
    expect(mask.email).toMatch(/^shop_[a-z2-7]{26}@e2e\.test$/);
    await expect(dialog).toBeHidden();
    const row = user.getByRole('table', { name: 'Masked addresses', exact: true }).getByRole('row').filter({ hasText: mask.email });
    await expect(row).toContainText('shop.example');
    await expect(row).toContainText('Active');
    const second = await (await user.request.post('/api/me/masked-addresses', { headers: await auth(user), data: { description: 'Other website' } })).json();
    await smtpDeliver('sender@remote.test', mask.email, `From: Sender <sender@remote.test>\nReply-To: mask-recipient@e2e.test\nTo: undisclosed-recipients:;\nCc: ${owner.email}, ${second.email}, colleague@remote.test\nSubject: A private masked message\nDelivered-To: forged@remote.test\n\nPlease reply using the address I wrote to.\n`);
    await user.goto('/mail');
    await user.getByTestId('email-row').filter({ hasText: 'A private masked message' }).click();
    await expect(user.getByText(`Received via ${mask.email}`, { exact: true })).toBeVisible();
    const readerUrl = user.url();
    await user.getByRole('button', { name: 'Reply all', exact: true }).click();
    const composer = user.getByRole('dialog', { name: 'New message', exact: true });
    await expect(composer.getByRole('combobox', { name: 'From', exact: true })).toHaveText(mask.email);
    await expect(composer.getByLabel('To', { exact: true })).toHaveValue('mask-recipient@e2e.test');
    await expect(composer.getByLabel('Cc', { exact: true })).toHaveValue('colleague@remote.test');
    await composer.getByLabel('Cc', { exact: true }).fill('');
    await composer.getByRole('textbox', { name: 'Message body', exact: true }).fill('My masked reply.');
    await composer.getByRole('button', { name: 'Send', exact: true }).click();
    await expect(user.getByText('Message sent', { exact: true })).toBeVisible();
    const recipient = await recipientContext.newPage();
    await login(recipient, 'mask-recipient@e2e.test', USER_PASSWORD);
    const reply = recipient.getByTestId('email-row').filter({ hasText: 'Re: A private masked message' });
    await expect(reply).toBeVisible({ timeout: 20_000 });
    await reply.click();
    const session = await (await recipient.request.get('/jmap/session')).json();
    const accountId = session.primaryAccounts['urn:ietf:params:jmap:mail'];
    const messages = await (await recipient.request.post('/jmap/api', { headers: await auth(recipient), data: { using: [], methodCalls: [['Email/query', { accountId, filter: { subject: 'Re: A private masked message' } }, 'q'], ['Email/get', { accountId, '#ids': { resultOf: 'q', name: 'Email/query', path: '/ids' } }, 'get']] } })).json();
    const email = messages.methodResponses[1][1].list[0];
    const raw = await (await recipient.request.get(`/jmap/download/${accountId}/${email.blobId}/message.eml`)).text();
    expect(email.from[0].email).toBe(mask.email);
    expect(raw).toContain(`Return-Path: <${mask.email}>`);
    expect(raw).not.toContain(owner.email);
    await page.request.patch(`/api/domains/${owner.domain_id}`, { headers: await auth(page), data: { catch_all: owner.email } });
    await settings(user);
    await row.getByRole('button', { name: 'Disable', exact: true }).click();
    await expect(row).toContainText('Disabled');
    await expect(smtpDeliver('sender@remote.test', mask.email, 'Subject: blocked\n\nblocked')).rejects.toThrow(/550/);
    await row.getByRole('button', { name: 'Enable', exact: true }).click();
    await expect(row).toContainText('Active');
    await row.getByRole('button', { name: `Delete ${mask.email}`, exact: true }).click();
    await user.getByRole('dialog').getByRole('button', { name: 'Delete', exact: true }).click();
    await expect(row).toHaveCount(0);
    await expect(smtpDeliver('sender@remote.test', mask.email, 'Subject: blocked\n\nblocked')).rejects.toThrow(/550/);
    await user.goto(readerUrl);
    await user.getByRole('button', { name: 'Reply', exact: true }).click();
    await expect(composer.getByRole('combobox', { name: 'From', exact: true })).toHaveText(mask.email);
    await expect(composer.getByText('Selected sending address is unavailable. Choose another address.', { exact: true })).toBeVisible();
    await composer.getByRole('button', { name: 'Send', exact: true }).click();
    await expect(composer).toBeVisible();
    await composer.getByRole('button', { name: 'Discard draft', exact: true }).click();
  } finally {
    await page.request.patch(`/api/domains/${owner.domain_id}`, { headers: await auth(page), data: { catch_all: null } });
    await context.close(); await recipientContext.close();
  }
});

test('administrators set quotas and domains and integration tokens have mask-only JMAP access', async ({ page, browser }) => {
  await login(page, ADMIN.email, ADMIN.password);
  const owner = await account(page, 'mask-integration@e2e.test');
  const domain = await page.request.post('/api/domains', { headers: await auth(page), data: { name: 'mask-privacy.test' } });
  expect(domain.ok()).toBe(true);
  await openAdmin(page, 'Masked addresses');
  await page.getByLabel('Mailbox address', { exact: true }).fill(owner.email);
  await page.getByRole('button', { name: 'Load mailbox', exact: true }).click();
  await expect(page.getByRole('heading', { name: owner.email, exact: true })).toBeVisible();
  await page.getByLabel('Mask quota override', { exact: true }).fill('1');
  await page.getByLabel('Additional mask domains', { exact: true }).fill('mask-privacy.test');
  const policy = page.waitForResponse((r) => r.url().endsWith(`/api/accounts/${owner.id}/masked-policy`) && r.request().method() === 'PUT');
  await page.getByRole('button', { name: 'Save', exact: true }).last().click();
  expect((await policy).ok()).toBe(true);
  const context = await browser.newContext(); const integration = await browser.newContext();
  try {
    const user = await context.newPage(); await login(user, owner.email, USER_PASSWORD); await settings(user);
    await user.getByRole('button', { name: 'Create masked address', exact: true }).click();
    const dialog = user.getByRole('dialog');
    await dialog.getByRole('combobox', { name: /^Domain/ }).click();
    await user.getByRole('option', { name: 'mask-privacy.test', exact: true }).click();
    await dialog.getByRole('button', { name: 'Save', exact: true }).click();
    await expect(dialog).toBeHidden();
    await expect(user.getByRole('button', { name: 'Create masked address', exact: true })).toBeDisabled();
    await user.getByLabel('Integration name', { exact: true }).fill('Test Password Manager');
    await user.getByRole('button', { name: 'Create token', exact: true }).click();
    const tokenField = user.getByLabel('Integration token', { exact: true }); await expect(tokenField).toBeVisible();
    const token = await tokenField.inputValue(); const headers = { authorization: `Bearer ${token}` };
    const session = await (await integration.request.get('/api/masked-email/session', { headers })).json();
    expect(JSON.stringify(session)).not.toContain(owner.email);
    const accountId = Object.keys(session.accounts)[0];
    const list = await (await integration.request.post('/api/masked-email/jmap', { headers, data: { using: ['urn:unomail:params:jmap:masked-email'], methodCalls: [['MaskedEmail/get', { accountId }, 'get'], ['Email/query', { accountId }, 'deny']] } })).json();
    expect(list.methodResponses[0][1].list[0].email).toMatch(/@mask-privacy\.test$/);
    expect(list.methodResponses[1][1].type).toBe('forbidden');
    expect((await integration.request.get('/jmap/session', { headers })).status()).toBe(401);
    const masks = await (await user.request.get('/api/me/masked-addresses')).json();
    expect((await user.request.post('/api/me/masked-addresses', { headers: await auth(user), data: {} })).status()).toBe(409);
    await user.request.delete(`/api/me/masked-addresses/${masks.items[0].id}`, { headers: await auth(user) });
    const result = await (await integration.request.post('/api/masked-email/jmap', { headers, data: { using: [], methodCalls: [['MaskedEmail/set', { accountId, create: { pm: { description: 'Password-manager entry', forDomain: 'https://website.example', emailDomain: 'mask-privacy.test' } } }, 'create']] } })).json();
    expect(result.methodResponses[0][1].created.pm.createdBy).toBe('Test Password Manager');
    await user.getByRole('button', { name: 'Revoke', exact: true }).click();
    await expect.poll(async () => (await integration.request.get('/api/masked-email/session', { headers })).status()).toBe(401);
  } finally { await context.close(); await integration.close(); }
});
