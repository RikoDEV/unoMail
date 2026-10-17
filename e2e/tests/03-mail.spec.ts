import { expect, test } from '@playwright/test';
import { DOMAIN, login, logout, smtpDeliver, USER_PASSWORD } from './helpers';

const ALICE = `alice@${DOMAIN}`;
const BOB = `bob@${DOMAIN}`;

test.describe('web mail', () => {
  test('composing, sending, receiving and replying', async ({ page }) => {
    await login(page, ALICE, USER_PASSWORD);
    await page.getByRole('button', { name: 'Compose' }).click();
    const composer = page.getByRole('dialog', { name: 'New message' });
    await composer.getByLabel('To').fill(BOB);
    await composer.getByLabel('Subject').fill('Lunch on Friday?');
    await composer.getByRole('textbox', { name: 'Message body' }).click();
    await page.keyboard.type('Hi Bob, are you free for lunch on Friday?');

    // The draft is saved automatically while typing.
    await expect(composer.getByText('Draft saved')).toBeVisible({ timeout: 10_000 });
    await composer.getByRole('button', { name: 'Send' }).click();
    await expect(page.getByText('Message sent')).toBeVisible();

    const folders = page.getByRole('navigation', { name: 'Folders' });
    await folders.getByText('Sent', { exact: true }).click();
    await expect(page.getByTestId('email-row').filter({ hasText: 'Lunch on Friday?' })).toHaveCount(1);
    await folders.getByText('Drafts', { exact: true }).click();
    await expect(page.getByText('Nothing here yet.')).toBeVisible();
    await logout(page);

    await login(page, BOB, USER_PASSWORD);
    const row = page.getByTestId('email-row').filter({ hasText: 'Lunch on Friday?' });
    // Sent mail leaves after the undo window (5 seconds by default).
    await expect(row).toContainText('Alice Example', { timeout: 20_000 });
    await row.click();
    const reader = page.getByRole('region', { name: 'Conversation' });
    await expect(reader.getByRole('heading', { name: 'Lunch on Friday?' })).toBeVisible();
    await expect(reader.frameLocator('iframe[title="Message body"]').getByText('are you free for lunch on Friday?')).toBeVisible();

    // Reply with the keyboard shortcut.
    await page.keyboard.press('r');
    const reply = page.getByRole('dialog', { name: 'New message' });
    await expect(reply.getByLabel('To')).toHaveValue(/alice@example\.test/);
    await expect(reply.getByLabel('Subject')).toHaveValue('Re: Lunch on Friday?');
    await reply.getByRole('textbox', { name: 'Message body' }).click();
    await page.keyboard.press('Control+Home');
    await page.keyboard.type('Friday works for me!');
    await reply.getByRole('button', { name: 'Send' }).click();
    await expect(page.getByText('Message sent')).toBeVisible();
    await logout(page);

    // Alice sees the reply threaded with her original message.
    await login(page, ALICE, USER_PASSWORD);
    const replyRow = page.getByTestId('email-row').filter({ hasText: 'Re: Lunch on Friday?' });
    await expect(replyRow).toHaveCount(1, { timeout: 20_000 });
    await replyRow.click();
    await expect(page.getByTestId('message')).toHaveCount(2);
  });

  test('keyboard navigation, starring, archiving and search', async ({ page }) => {
    await smtpDeliver('news@remote.test', BOB, `From: Newsletter <news@remote.test>\nTo: ${BOB}\nSubject: Weekly digest\n\nThis week: zebra migration patterns.\n`);
    await smtpDeliver('boss@remote.test', BOB, `From: The Boss <boss@remote.test>\nTo: ${BOB}\nSubject: Quarterly numbers\n\nPlease review the attached numbers.\n`);
    await login(page, BOB, USER_PASSWORD);
    const rows = page.getByTestId('email-row');
    await expect(rows.filter({ hasText: 'Quarterly numbers' })).toHaveCount(1);
    await expect(rows.first()).toContainText('Quarterly numbers');

    // New mail arrives without reloading the page.
    await smtpDeliver('late@remote.test', BOB, `From: late@remote.test\nTo: ${BOB}\nSubject: Pushed to the client\n\nlive update\n`);
    await expect(rows.first()).toContainText('Pushed to the client');

    // j/k move the selection, Enter opens, u returns to the list.
    await page.keyboard.press('j');
    await page.keyboard.press('Enter');
    await expect(page.getByRole('region', { name: 'Conversation' }).getByRole('heading', { name: 'Quarterly numbers' })).toBeVisible();
    await page.keyboard.press('u');
    await expect(page.getByRole('region', { name: 'Conversation' })).toHaveCount(0);

    // s stars, e archives the selected conversation.
    await page.keyboard.press('s');
    await expect(rows.filter({ hasText: 'Quarterly numbers' }).getByRole('button', { name: 'Remove star' })).toBeVisible();
    await page.keyboard.press('e');
    await expect(page.getByText('Conversation archived')).toBeVisible();
    await expect(rows.filter({ hasText: 'Quarterly numbers' })).toHaveCount(0);
    await page.getByRole('navigation', { name: 'Folders' }).getByText('Archive', { exact: true }).click();
    await expect(rows.filter({ hasText: 'Quarterly numbers' })).toHaveCount(1);

    // "/" focuses the search box; results come from every folder.
    await page.keyboard.press('/');
    await expect(page.getByLabel('Search mail')).toBeFocused();
    await page.keyboard.type('zebra');
    await expect(rows).toHaveCount(1);
    await expect(rows.first()).toContainText('Weekly digest');
    await page.getByLabel('Search mail').fill('no such message anywhere');
    await expect(page.getByText('No messages match your search.')).toBeVisible();
  });

  test('hostile HTML mail cannot run scripts or load remote content', async ({ page }) => {
    const html = [
      '<html><body>',
      '<p id="greeting">Totally harmless newsletter</p>',
      '<script>parent.window.__xss = "script"; window.top.document.title = "pwned";</script>',
      '<img src="x" onerror="parent.window.__xss = \'onerror\'">',
      '<img src="https://tracker.remote.test/pixel.gif?u=bob" width="1" height="1">',
      '<a id="js" href="javascript:parent.window.__xss=\'href\'">click me</a>',
      '<form action="https://phish.remote.test/login"><input name="password"><button>Sign in</button></form>',
      '<iframe src="https://evil.remote.test/"></iframe>',
      '<svg onload="parent.window.__xss = \'svg\'"></svg>',
      '<div style="background:url(https://tracker.remote.test/bg.png)">styled</div>',
      '</body></html>',
    ].join('\n');
    await smtpDeliver('evil@remote.test', BOB, `From: Evil <evil@remote.test>\nTo: ${BOB}\nSubject: <img src=x onerror=window.__xss=1> Important\nMIME-Version: 1.0\nContent-Type: text/html; charset=utf-8\n\n${html}\n`);

    const external: string[] = [];
    page.on('request', (request) => {
      if (!request.url().startsWith('http://localhost') && !request.url().startsWith('blob:') && !request.url().startsWith('data:')) external.push(request.url());
    });
    let dialogs = 0;
    page.on('dialog', (dialog) => {
      dialogs += 1;
      void dialog.dismiss();
    });

    await login(page, BOB, USER_PASSWORD);
    const row = page.getByTestId('email-row').filter({ hasText: 'Important' });
    // The subject is rendered as text, not markup.
    await expect(row).toContainText('<img src=x onerror=window.__xss=1> Important');
    await row.click();

    const frame = page.getByRole('region', { name: 'Conversation' }).frameLocator('iframe[title="Message body"]');
    await expect(frame.locator('#greeting')).toHaveText('Totally harmless newsletter');
    await expect(frame.locator('script, form, input, iframe, svg')).toHaveCount(0);
    await expect(frame.locator('#js')).not.toHaveAttribute('href', /javascript/);
    await expect(frame.locator('[onerror], [onload]')).toHaveCount(0);
    await frame.locator('#js').click({ force: true });
    await page.waitForTimeout(500);

    expect(await page.evaluate(() => (window as unknown as { __xss?: string }).__xss)).toBeUndefined();
    expect(await page.title()).toBe('unoMail');
    expect(dialogs).toBe(0);
    expect(external, 'no request may leave for remote hosts').toEqual([]);

    // The frame cannot execute scripts even if markup slipped through.
    const sandbox = await page.locator('iframe[title="Message body"]').getAttribute('sandbox');
    expect(sandbox).not.toContain('allow-scripts');
  });

  test('users only ever see their own mail', async ({ page }) => {
    await login(page, ALICE, USER_PASSWORD);
    await expect(page.getByTestId('email-row').filter({ hasText: 'Weekly digest' })).toHaveCount(0);
    await page.getByLabel('Search mail').fill('zebra');
    await expect(page.getByText('No messages match your search.')).toBeVisible();

    // Guessing another account's identifiers through the API yields nothing.
    const session = await (await page.request.get('/jmap/session')).json();
    const own = session.primaryAccounts['urn:ietf:params:jmap:mail'] as string;
    const csrf = (await (await page.request.get('/api/auth/me')).json()).csrf_token as string;
    const other = `a${Number(own.slice(1)) + 1}`;
    const response = await page.request.post('/jmap/api', {
      headers: { 'x-csrf-token': csrf },
      data: { using: [], methodCalls: [['Email/query', { accountId: other }, '0'], ['Mailbox/get', { accountId: other }, '1']] },
    });
    const body = await response.json();
    expect(body.methodResponses.map((r: [string, { type: string }]) => r[1].type)).toEqual(['accountNotFound', 'accountNotFound']);
  });
});
