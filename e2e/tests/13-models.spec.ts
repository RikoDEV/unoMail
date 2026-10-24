import { expect, test, type Page } from '@playwright/test';
import http from 'node:http';
import type { AddressInfo } from 'node:net';
import { ADMIN, login, openAdmin, USER_PASSWORD } from './helpers';

async function headers(page: Page) {
  const session = await (await page.request.get('/api/auth/me')).json();
  return { 'x-csrf-token': session.csrf_token as string };
}

async function importMail(page: Page, subject: string, body: string) {
  const session = await (await page.request.get('/jmap/session')).json();
  const accountId = session.primaryAccounts['urn:ietf:params:jmap:mail'];
  const auth = await headers(page);
  const upload = await page.request.post(`/jmap/upload/${accountId}`, {
    headers: { ...auth, 'content-type': 'message/rfc822' },
    data: Buffer.from(`From: sender@remote.test\r\nTo: reader@e2e.test\r\nSubject: ${subject}\r\nContent-Type: text/plain; charset=utf-8\r\n\r\n${body}`),
  });
  expect(upload.status()).toBe(201);
  const call = async (methodCalls: unknown[]) => (await (await page.request.post('/jmap/api', { headers: auth, data: { using: [], methodCalls } })).json()).methodResponses;
  const boxes = await call([['Mailbox/get', { accountId }, 'boxes']]);
  const inbox = boxes[0][1].list.find((b: { role: string }) => b.role === 'inbox').id;
  const imported = await call([['Email/import', { accountId, emails: { mail: { blobId: (await upload.json()).blobId, mailboxIds: { [inbox]: true } } } }, 'import']]);
  expect(imported[0][1].created?.mail?.id, JSON.stringify(imported)).toBeTruthy();
  return imported[0][1].created.mail.id as string;
}

interface Recorded { url: string; headers: http.IncomingHttpHeaders; body: any }
async function provider() {
  const requests: Recorded[] = [];
  let fail = false;
  const server = http.createServer((req, res) => {
    let raw = '';
    req.on('data', (chunk) => { raw += chunk; });
    req.on('end', () => {
      const body = JSON.parse(raw);
      requests.push({ url: req.url!, headers: req.headers, body });
      res.setHeader('content-type', 'application/json');
      if (fail) { res.writeHead(401); res.end(JSON.stringify({ error: { message: 'DO-NOT-LEAK-provider-key' } })); return; }
      const instruction = body.messages?.[0]?.content ?? '';
      const content = instruction.startsWith('Translate') ? 'Réunion vendredi à 14 heures.' : 'Meeting on Friday at 14:00. Bring the report.';
      if (req.url?.endsWith('/messages')) res.end(JSON.stringify({ content: [{ type: 'text', text: content }] }));
      else if (req.url?.includes(':generateContent')) res.end(JSON.stringify({ candidates: [{ content: { parts: [{ text: content }] } }] }));
      else if (req.url === '/api/chat') res.end(JSON.stringify({ message: { content } }));
      else res.end(JSON.stringify({ choices: [{ message: { content } }] }));
    });
  });
  await new Promise<void>((resolve) => server.listen(0, '127.0.0.1', resolve));
  return { url: `http://127.0.0.1:${(server.address() as AddressInfo).port}`, requests, fail: (on = true) => { fail = on; }, close: () => server.close() };
}

test('models can be configured and used for summaries and translation of owned mail', async ({ page, browser }) => {
  const remote = await provider();
  const userContext = await browser.newContext();
  try {
    await login(page, ADMIN.email, ADMIN.password);
    const adminHeaders = await headers(page);
    const adminMessage = await importMail(page, 'Private administrator mail', 'Do not expose this message.');
    const createdAccount = await page.request.post('/api/accounts', { headers: adminHeaders, data: { email: 'ai-reader@e2e.test', password: USER_PASSWORD } });
    expect(createdAccount.ok(), await createdAccount.text()).toBe(true);

    await openAdmin(page, 'Models');
    await page.getByRole('button', { name: 'Add model' }).click();
    let dialog = page.getByRole('dialog');
    await dialog.getByLabel('Display name').fill('Mail assistant');
    await dialog.getByLabel('Provider', { exact: true }).click();
    await page.getByRole('option', { name: 'OpenAI-compatible', exact: true }).click();
    await dialog.getByLabel('Model ID').fill('test-model');
    await dialog.getByLabel('Base URL').fill(`${remote.url}/v1`);
    await dialog.getByLabel('API key', { exact: true }).fill('secret-provider-key');
    // Saving tests the settings first: a failing provider keeps the dialog open with the reason.
    remote.fail();
    await dialog.getByRole('button', { name: 'Save', exact: true }).click();
    await expect(dialog.getByRole('alert')).toContainText('HTTP 401');
    await expect(dialog).not.toContainText('DO-NOT-LEAK');
    await expect(dialog.getByRole('button', { name: 'Save anyway', exact: true })).toBeVisible();
    expect((await (await page.request.get('/api/models')).json()).some((m: { name: string }) => m.name === 'Mail assistant')).toBe(false);
    remote.fail(false);
    await dialog.getByRole('button', { name: 'Test connection', exact: true }).click();
    await expect(dialog.getByRole('status')).toContainText('Model connection successful');
    await dialog.getByRole('button', { name: 'Save', exact: true }).click();
    await expect(dialog).toBeHidden();
    expect(remote.requests).toHaveLength(2); // A passed test is not repeated when saving.
    const configured = await (await page.request.get('/api/models')).json();
    const model = configured.find((m: { name: string }) => m.name === 'Mail assistant');
    expect(model.has_api_key).toBe(true);
    expect(JSON.stringify(configured)).not.toContain('secret-provider-key');
    expect(model.api_key).toBeUndefined();

    await page.getByRole('button', { name: 'Test connection', exact: true }).click();
    await expect(page.getByText('Model connection successful')).toBeVisible();
    expect(remote.requests[2].headers.authorization).toBe('Bearer secret-provider-key');
    expect(remote.requests[2].url).toBe('/v1/chat/completions');
    // Renaming preserves the sealed API key without disclosing it to the form.
    await page.getByRole('button', { name: 'Edit Mail assistant', exact: true }).click();
    dialog = page.getByRole('dialog');
    await expect(dialog.getByLabel('API key', { exact: true })).toHaveValue('');
    await dialog.getByLabel('Display name').fill('Mail helper');
    await dialog.getByRole('button', { name: 'Save', exact: true }).click();
    await expect(dialog).toBeHidden();
    expect(remote.requests).toHaveLength(3); // A rename does not test the connection again.

    const user = await userContext.newPage();
    await login(user, 'ai-reader@e2e.test', USER_PASSWORD);
    const userHeaders = await headers(user);
    expect((await user.request.get('/api/models')).status()).toBe(403);
    expect((await user.request.post('/api/models', { headers: userHeaders, data: {} })).ok()).toBe(false);
    expect((await user.request.delete(`/api/models/${model.id}`, { headers: userHeaders })).status()).toBe(403);
    const available = await (await user.request.get('/api/me/ai/models')).json();
    expect(available).toContainEqual({ id: model.id, name: 'Mail helper', provider: 'custom' });
    expect(JSON.stringify(available)).not.toContain(remote.url);
    const forbidden = await user.request.post('/api/me/ai/assist', { headers: userHeaders, data: { model_id: model.id, email_id: adminMessage, language: 'en', task: 'summary' } });
    expect(forbidden.status()).toBe(404);
    expect(remote.requests).toHaveLength(3);

    const emailId = await importMail(user, 'AI meeting notes', 'Meeting Friday at 14:00. Please bring the report.');
    await user.reload();
    await user.getByTestId('email-row').filter({ hasText: 'AI meeting notes' }).click();
    const assistant = user.getByRole('region', { name: 'AI assistance', exact: true });
    await expect(assistant).toBeVisible();
    expect(remote.requests).toHaveLength(3); // Opening mail never sends it to a provider.
    await assistant.getByRole('button', { name: 'Summarize', exact: true }).click();
    await expect(assistant.getByText('Meeting on Friday at 14:00. Bring the report.', { exact: true })).toBeVisible();
    await expect(assistant.getByRole('button', { name: /^Translate to / })).toHaveCount(0);
    await expect(assistant.getByLabel('Target language')).toHaveCount(0);
    expect(remote.requests[3].headers.authorization).toBe('Bearer secret-provider-key');
    expect(remote.requests[3].body.messages[1].content).toContain('Meeting Friday at 14:00');
    await importMail(user, 'Notes de réunion', 'Bonjour, notre réunion aura lieu vendredi à quatorze heures. Merci de préparer le rapport et de confirmer votre présence.');
    await user.goto('/mail');
    await user.getByTestId('email-row').filter({ hasText: 'Notes de réunion' }).click();
    await expect(assistant.getByRole('button', { name: 'Translate to English', exact: true })).toBeVisible();
    expect(remote.requests).toHaveLength(4); // Language detection is local.
    await assistant.getByLabel('Target language').click();
    await user.getByRole('option', { name: 'Français', exact: true }).click();
    await assistant.getByRole('button', { name: 'Translate to Français', exact: true }).click();
    await expect(assistant.getByText('Réunion vendredi à 14 heures.', { exact: true })).toBeVisible();
    expect(remote.requests[4].body.messages[0].content).toContain('into fr');

    await user.getByRole('button', { name: 'Back to list', exact: true }).click();
    await user.getByTestId('email-row').filter({ hasText: 'AI meeting notes' }).click();
    await expect(assistant.getByRole('button', { name: 'Summarize', exact: true })).toBeVisible();
    await expect(assistant.getByRole('button', { name: /^Translate to / })).toHaveCount(0);

    const encryptedId = await importMail(user, 'Encrypted email', '-----BEGIN PGP MESSAGE-----\r\nEncrypted payload\r\n-----END PGP MESSAGE-----');
    const encrypted = await user.request.post('/api/me/ai/assist', { headers: userHeaders, data: { model_id: model.id, email_id: encryptedId, language: 'en', task: 'summary' } });
    expect(encrypted.status()).toBe(400);
    expect(await encrypted.text()).toContain('encrypted messages');
    const longId = await importMail(user, 'Long email', 'a'.repeat(60_001));
    const long = await user.request.post('/api/me/ai/assist', { headers: userHeaders, data: { model_id: model.id, email_id: longId, language: 'en', task: 'translate' } });
    expect(long.status()).toBe(400);
    expect(await long.text()).toContain('too long');
    expect(remote.requests).toHaveLength(5);

    // Provider failures are actionable, without forwarding the provider's secret-bearing body.
    remote.fail();
    await assistant.getByRole('button', { name: 'Summarize', exact: true }).click();
    await expect(assistant.getByRole('alert')).toContainText('HTTP 401');
    await expect(assistant).not.toContainText('DO-NOT-LEAK');

    const disabled = await page.request.put(`/api/models/${model.id}`, { headers: adminHeaders, data: { ...model, name: 'Mail helper', enabled: false } });
    expect(disabled.ok()).toBe(true);
    expect((await (await user.request.get('/api/me/ai/models')).json()).some((m: { id: string }) => m.id === model.id)).toBe(false);
    expect((await user.request.post('/api/me/ai/assist', { headers: userHeaders, data: { model_id: model.id, email_id: emailId, language: 'en', task: 'summary' } })).status()).toBe(400);
    await user.reload();
    await expect(user.getByRole('region', { name: 'AI assistance', exact: true })).toHaveCount(0);
    await page.reload();
    await page.getByRole('button', { name: 'Delete Mail helper', exact: true }).click();
    await page.getByRole('dialog').getByRole('button', { name: 'Delete', exact: true }).click();
    await expect(page.getByText('No AI models configured. Add a model to enable summaries and translations in webmail.')).toBeVisible();
  } finally {
    await userContext.close();
    remote.close();
  }
});

test('provider adapters use native endpoints and authentication', async ({ page }) => {
  const remote = await provider();
  try {
    await login(page, ADMIN.email, ADMIN.password);
    const auth = await headers(page);
    for (const provider of ['anthropic', 'gemini', 'ollama', 'openai']) {
      const response = await page.request.post('/api/models', { headers: auth, data: { name: provider, provider, model: 'test-model', base_url: provider === 'ollama' ? remote.url : `${remote.url}/v1`, api_key: 'adapter-key', enabled: true } });
      expect(response.ok(), await response.text()).toBe(true);
      const model = await response.json();
      const tested = await page.request.post(`/api/models/${model.id}/test`, { headers: auth });
      expect(tested.ok(), await tested.text()).toBe(true);
      const recorded = remote.requests.at(-1)!;
      if (provider === 'anthropic') {
        expect(recorded.url).toBe('/v1/messages');
        expect(recorded.headers['x-api-key']).toBe('adapter-key');
        expect(recorded.headers['anthropic-version']).toBe('2023-06-01');
        expect(recorded.body.system).toContain('Reply with');
      } else if (provider === 'gemini') {
        expect(recorded.url).toBe('/v1/models/test-model:generateContent');
        expect(recorded.headers['x-goog-api-key']).toBe('adapter-key');
        expect(recorded.body.systemInstruction.parts[0].text).toContain('Reply with');
      } else if (provider === 'ollama') {
        expect(recorded.url).toBe('/api/chat');
        expect(recorded.body.stream).toBe(false);
      } else {
        expect(recorded.url).toBe('/v1/chat/completions');
        expect(recorded.headers.authorization).toBe('Bearer adapter-key');
      }
      expect(recorded.headers.cookie).toBeUndefined();
      if (provider === 'openai') {
        // Unsaved settings are tested with the saved key, but never send it to a new address.
        const draft = await page.request.post('/api/models/test', { headers: auth, data: { ...model, id: model.id } });
        expect(draft.ok(), await draft.text()).toBe(true);
        expect(remote.requests.at(-1)!.headers.authorization).toBe('Bearer adapter-key');
        const moved = await page.request.post('/api/models/test', { headers: auth, data: { ...model, id: model.id, base_url: `${remote.url}/another-provider` } });
        expect(moved.status()).toBe(400);
        expect(await moved.text()).toContain('API key is required');
        const changed = await page.request.put(`/api/models/${model.id}`, { headers: auth, data: { ...model, base_url: `${remote.url}/another-provider` } });
        expect(changed.status()).toBe(400);
        expect(await changed.text()).toContain('API key is required');
      }
      expect((await page.request.delete(`/api/models/${model.id}`, { headers: auth })).ok()).toBe(true);
    }
  } finally { remote.close(); }
});
