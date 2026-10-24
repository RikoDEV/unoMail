import { expect, test, type Page } from '@playwright/test';
import http from 'node:http';
import type { AddressInfo } from 'node:net';
import { ADMIN, login, USER_PASSWORD } from './helpers';

async function auth(page: Page) {
  const session = await (await page.request.get('/api/auth/me')).json();
  return { 'x-csrf-token': session.csrf_token as string };
}
async function importMail(page: Page, raw: string) {
  const headers = await auth(page);
  const session = await (await page.request.get('/jmap/session')).json();
  const accountId = session.primaryAccounts['urn:ietf:params:jmap:mail'];
  const upload = await page.request.post(`/jmap/upload/${accountId}`, { headers: { ...headers, 'content-type': 'message/rfc822' }, data: Buffer.from(raw) });
  expect(upload.status()).toBe(201);
  const call = async (methodCalls: unknown[]) => (await (await page.request.post('/jmap/api', { headers, data: { using: [], methodCalls } })).json()).methodResponses;
  const boxes = await call([['Mailbox/get', { accountId }, 'boxes']]);
  const inbox = boxes[0][1].list.find((b: { role: string }) => b.role === 'inbox').id;
  const result = await call([['Email/import', { accountId, emails: { mail: { blobId: (await upload.json()).blobId, mailboxIds: { [inbox]: true } } } }, 'import']]);
  expect(result[0][1].created?.mail?.id, JSON.stringify(result)).toBeTruthy();
  return result[0][1].created.mail.id as string;
}

test('smart replies use owned context and open editable, safe, auto-saved replies', async ({ page, browser }) => {
  const requests: any[] = [];
  let mode: 'normal' | 'empty' | 'invalid' | 'error' = 'normal';
  const provider = http.createServer((req, res) => {
    let raw = '';
    req.on('data', (chunk) => { raw += chunk; });
    req.on('end', () => {
      const body = JSON.parse(raw);
      requests.push(body);
      res.setHeader('content-type', 'application/json');
      if (mode === 'error') { res.writeHead(401); res.end(JSON.stringify({ error: { message: 'PRIVATE-PROVIDER-KEY' } })); return; }
      const content = mode === 'invalid' ? 'not valid JSON' : JSON.stringify({ replies: mode === 'empty' ? [] : [
        { label: 'Accept the invitation', text: 'Yes, Friday at 14:00 works for me.' },
        { label: 'Decline politely', text: 'Sorry, I cannot make it on Friday.' },
        { label: 'Quote safely', text: '<img src=x onerror=window.__smartReplyXss=1>\nThanks.' },
      ] });
      res.end(JSON.stringify({ choices: [{ message: { content } }] }));
    });
  });
  await new Promise<void>((resolve) => provider.listen(0, '127.0.0.1', resolve));
  const context = await browser.newContext();
  let modelId = '';
  try {
    await login(page, ADMIN.email, ADMIN.password);
    const adminHeaders = await auth(page);
    const created = await page.request.post('/api/models', { headers: adminHeaders, data: { name: 'Reply assistant', provider: 'custom', model: 'reply-model', base_url: `http://127.0.0.1:${(provider.address() as AddressInfo).port}/v1`, enabled: true } });
    expect(created.ok()).toBe(true);
    modelId = (await created.json()).id;
    expect((await page.request.post('/api/accounts', { headers: adminHeaders, data: { email: 'smart-reader@e2e.test', password: USER_PASSWORD } })).ok()).toBe(true);
    const adminMail = await importMail(page, 'From: private@remote.test\r\nSubject: Private\r\n\r\nPRIVATE-ADMIN-CONTENT');
    const user = await context.newPage();
    await login(user, 'smart-reader@e2e.test', USER_PASSWORD);
    const userHeaders = await auth(user);
    const signature = await user.request.post('/api/me/signatures', { headers: userHeaders, data: { name: 'Reply sign-off', html: '<p>Regards, Smart Reader</p>' } });
    expect(signature.ok()).toBe(true);
    expect((await user.request.put('/api/me/signatures/defaults', { headers: userHeaders, data: { email: 'smart-reader@e2e.test', new_signature_id: null, reply_signature_id: (await signature.json()).id } })).ok()).toBe(true);

    await importMail(user, 'From: Earlier Sender <earlier@remote.test>\r\nTo: smart-reader@e2e.test\r\nSubject: Smart reply meeting\r\nMessage-ID: <root@smart.test>\r\n\r\nProject ORCHID is the topic of our meeting.');
    await importMail(user, 'From: unrelated@remote.test\r\nSubject: Other conversation\r\n\r\nUNRELATED-SECRET');
    const selectedId = await importMail(user, 'From: Meeting Organizer <organizer@remote.test>\r\nReply-To: replies@remote.test\r\nTo: smart-reader@e2e.test\r\nCc: colleague@e2e.test\r\nSubject: Smart reply meeting\r\nMessage-ID: <selected@smart.test>\r\nReferences: <root@smart.test>\r\n\r\nCan you attend Friday at 14:00?');
    await importMail(user, 'From: Future Sender <future@remote.test>\r\nTo: smart-reader@e2e.test\r\nSubject: Smart reply meeting\r\nMessage-ID: <future@smart.test>\r\nReferences: <root@smart.test> <selected@smart.test>\r\n\r\nFUTURE-SECRET');
    const payload = { email_id: selectedId, model_id: modelId, language: 'auto' };
    expect((await user.request.post('/api/me/ai/replies', { headers: userHeaders, data: { ...payload, email_id: adminMail } })).status()).toBe(404);
    expect(requests).toHaveLength(0);
    await user.reload();
    await user.getByTestId('email-row').filter({ hasText: 'Smart reply meeting' }).click();
    const message = user.getByTestId('message').filter({ hasText: 'Meeting Organizer' });
    await message.locator('[data-collapsible]').click();
    // Suggest replies sits beside Reply; the suggestions appear above those buttons once asked for.
    const smart = message.getByRole('region', { name: 'Smart replies', exact: true });
    await expect(message.getByRole('button', { name: 'Suggest replies', exact: true })).toBeVisible();
    expect(requests).toHaveLength(0); // Reading mail makes no provider request.
    await message.getByRole('button', { name: 'Suggest replies', exact: true }).click();
    await expect(smart.getByRole('button', { name: 'Accept the invitation', exact: true })).toBeVisible();
    expect(requests).toHaveLength(1);
    const content = requests[0].messages[1].content as string;
    expect(content).toContain('Project ORCHID');
    expect(content).toContain('Can you attend Friday at 14:00?');
    for (const secret of ['PRIVATE-ADMIN-CONTENT', 'UNRELATED-SECRET', 'FUTURE-SECRET']) expect(content).not.toContain(secret);
    expect(requests[0].messages[0].content).toContain('in the language of the latest email');
    await message.getByRole('button', { name: 'Reply language', exact: true }).click();
    await user.getByRole('menuitem', { name: 'Polski', exact: true }).click();
    await message.getByRole('button', { name: 'Suggest replies', exact: true }).click();
    await expect(smart.getByRole('button', { name: 'Accept the invitation', exact: true })).toBeVisible();
    expect(requests[1].messages[0].content).toContain('in pl');

    const submissions: unknown[] = [];
    const saved: any[] = [];
    user.on('request', (request) => {
      if (!request.url().endsWith('/jmap/api') || request.method() !== 'POST') return;
      for (const [method, args] of request.postDataJSON()?.methodCalls ?? []) {
        if (method === 'EmailSubmission/set') submissions.push(args);
        if (method === 'Email/set' && args.create) saved.push(...Object.values(args.create));
      }
    });
    await smart.getByRole('button', { name: 'Accept the invitation', exact: true }).click();
    const composer = user.getByRole('dialog', { name: 'New message', exact: true });
    const editor = composer.getByRole('textbox', { name: 'Message body', exact: true });
    await expect(composer.getByLabel('To', { exact: true })).toHaveValue(/replies@remote\.test/);
    await expect(composer.getByLabel('Subject', { exact: true })).toHaveValue('Re: Smart reply meeting');
    await expect(editor).toContainText('Yes, Friday at 14:00 works for me.');
    await expect(editor).toContainText('Regards, Smart Reader');
    const text = await editor.innerText();
    expect(text.indexOf('Yes, Friday')).toBeLessThan(text.indexOf('Regards, Smart Reader'));
    expect(text.indexOf('Regards, Smart Reader')).toBeLessThan(text.indexOf('Can you attend'));
    await expect(composer.getByText('Draft saved', { exact: true })).toBeVisible({ timeout: 10_000 });
    expect(saved.at(-1).inReplyTo).toEqual(['selected@smart.test']);
    expect(saved.at(-1).references).toContain('root@smart.test');
    expect(saved.at(-1).bodyValues.html.value).toContain('Yes, Friday');
    expect(submissions).toHaveLength(0);
    await composer.getByRole('button', { name: 'Discard draft', exact: true }).click();
    await user.reload();
    await message.locator('[data-collapsible]').click();
    await message.getByRole('button', { name: 'Suggest replies', exact: true }).click();
    await expect(smart.getByRole('button', { name: 'Quote safely', exact: true })).toBeVisible();
    await smart.getByLabel('Reply all', { exact: true }).check();
    await smart.getByRole('button', { name: 'Quote safely', exact: true }).click();
    await expect(composer.getByLabel('Cc', { exact: true })).toHaveValue(/colleague@e2e\.test/);
    await expect(editor.locator('.unomail-reply-text')).toContainText('<img src=x onerror=window.__smartReplyXss=1>');
    await expect(editor.locator('.unomail-reply-text img')).toHaveCount(0);
    expect(await user.evaluate(() => (window as Window & { __smartReplyXss?: number }).__smartReplyXss)).toBeUndefined();
    // A second choice must not overwrite a reply the user already started editing.
    await editor.locator('.unomail-reply-text').fill('My own edited answer.');
    await composer.getByRole('button', { name: 'Minimize', exact: true }).click();
    await smart.getByRole('button', { name: 'Decline politely', exact: true }).click();
    await expect(user.getByText('Close the current draft before choosing a suggested reply.')).toBeVisible();
    await composer.getByRole('button', { name: 'Minimize', exact: true }).click();
    await expect(editor).toContainText('My own edited answer.');
    await composer.getByRole('button', { name: 'Discard draft', exact: true }).click();
    expect(submissions).toHaveLength(0);

    mode = 'empty';
    await message.getByRole('button', { name: 'Suggest again', exact: true }).click();
    await expect(smart.getByText('No reply suggestions for this message.')).toBeVisible();
    mode = 'invalid';
    await message.getByRole('button', { name: 'Suggest again', exact: true }).click();
    await expect(smart.getByRole('alert')).toContainText('invalid reply suggestions');
    mode = 'error';
    await message.getByRole('button', { name: 'Suggest again', exact: true }).click();
    await expect(smart.getByRole('alert')).toContainText('HTTP 401');
    await expect(smart).not.toContainText('PRIVATE-PROVIDER-KEY');
    const encrypted = await importMail(user, 'From: encrypted@remote.test\r\nSubject: Encrypted\r\n\r\n-----BEGIN PGP MESSAGE-----\r\nciphertext\r\n-----END PGP MESSAGE-----');
    const count = requests.length;
    expect((await user.request.post('/api/me/ai/replies', { headers: userHeaders, data: { ...payload, email_id: encrypted } })).status()).toBe(400);
    expect(requests).toHaveLength(count);
    const readerUrl = user.url();
    await user.goto('/settings?tab=inbox');
    await user.getByLabel('Offer AI reply suggestions', { exact: true }).uncheck();
    await expect.poll(async () => (await (await user.request.get('/api/me/preferences')).json()).smart_reply).toBe(false);
    expect((await user.request.post('/api/me/ai/replies', { headers: userHeaders, data: payload })).status()).toBe(400);
    expect(requests).toHaveLength(count);
    await user.goto(readerUrl);
    await expect(user.getByRole('region', { name: 'Smart replies', exact: true })).toHaveCount(0);
  } finally {
    if (modelId) await page.request.delete(`/api/models/${modelId}`, { headers: await auth(page) });
    await context.close();
    provider.close();
  }
});
