import { expect, test, type Page } from '@playwright/test';
import { DOMAIN, login, smtpDeliver, USER_PASSWORD } from './helpers';

// A mailbox of its own, so the counts here do not depend on the other specs.
const HANK = `hank@${DOMAIN}`;
const ADMIN_EMAIL = 'admin@e2e.test';
const ADMIN_PASSWORD = 'e2e-admin-password-1';

const rows = (page: Page) => page.getByTestId('email-row');
const row = (page: Page, text: string) => rows(page).filter({ hasText: text });
const folders = (page: Page) => page.getByRole('navigation', { name: 'Folders' });

const HOSTNAME = 'mail.e2e.test';

/** Puts a raw message into the signed-in user's inbox, as an import would. */
async function importMessage(page: Page, raw: string) {
  const session = await (await page.request.get('/jmap/session')).json();
  const account = session.primaryAccounts['urn:ietf:params:jmap:mail'] as string;
  const csrf = (await (await page.request.get('/api/auth/me')).json()).csrf_token as string;
  const headers = { 'x-csrf-token': csrf };
  const upload = await page.request.post(`/jmap/upload/${account}`, { headers: { ...headers, 'content-type': 'message/rfc822' }, data: Buffer.from(raw) });
  expect(upload.status()).toBe(201);
  const call = async (methodCalls: unknown[]) => (await (await page.request.post('/jmap/api', { headers, data: { using: [], methodCalls } })).json()).methodResponses;
  const mailboxes = await call([['Mailbox/get', { accountId: account }, 'm']]);
  const inbox = mailboxes[0][1].list.find((mailbox: { role: string | null }) => mailbox.role === 'inbox').id as string;
  const imported = await call([['Email/import', { accountId: account, emails: { e: { blobId: (await upload.json()).blobId, mailboxIds: { [inbox]: true } } } }, 'i']]);
  expect(imported[0][1].created?.e?.id, JSON.stringify(imported)).toBeTruthy();
}

test.describe('sender details, warnings and navigation', () => {
  test.beforeAll(async ({ browser }) => {
    const page = await browser.newPage();
    await login(page, ADMIN_EMAIL, ADMIN_PASSWORD);
    await page.goto('/admin/mailboxes');
    await page.getByRole('button', { name: 'Add mailbox' }).click();
    const dialog = page.getByRole('dialog');
    await dialog.getByLabel('E-mail address').fill(HANK);
    await dialog.getByLabel('Password', { exact: true }).fill(USER_PASSWORD);
    await dialog.getByRole('button', { name: 'Create' }).click();
    await expect(page.getByText('Mailbox created').or(dialog.getByText(/already exists/).first())).toBeVisible();
    await page.close();
  });

  test('hovering the sender shows the details; doubtful senders and malware get a warning', async ({ page }) => {
    await login(page, HANK, USER_PASSWORD);
    // As the server would have stored them after checking the sender (the test server sees
    // every connection coming from this machine and checks none, so they are put in place).
    const found = (results: string) => `Received: from out.remote.test ([203.0.113.9])\r\n\tby ${HOSTNAME} with ESMTP id abc; Tue, 13 Oct 2026 10:00:00 +0000\r\nAuthentication-Results: ${HOSTNAME}; ${results}\r\n`;
    const body = (subject: string) => `From: Ann Example <ann@remote.test>\r\nTo: Hank <${HANK}>\r\nCc: team@remote.test\r\nSubject: ${subject}\r\n\r\nPlease pay.\r\n`;
    await importMessage(page, found('dkim=none; spf=none smtp.mailfrom=bounce@mailer.remote.test; dmarc=none header.from=remote.test') + body('Wire transfer today'));
    await importMessage(page, 'X-Virus-Status: Infected (Eicar-Signature)\r\n' + found('dkim=fail header.d=remote.test; spf=softfail smtp.mailfrom=ann@remote.test; dmarc=fail header.from=remote.test') + body('Invoice attached'));
    await importMessage(page, found('dkim=pass header.d=remote.test header.s=s1; spf=pass smtp.mailfrom=bounce@mailer.remote.test; dmarc=pass header.from=remote.test').replace('with ESMTP id', 'with ESMTPS id') + body('All in order'));
    await page.reload();

    await row(page, 'Wire transfer today').click();
    const message = page.getByTestId('message');
    const warning = message.getByTestId('sender-warning');
    await expect(warning).toContainText('It could not be confirmed that this message is from ann@remote.test');
    await expect(warning).toContainText('Be careful with links');
    for (const chip of ['SPF: none', 'DKIM: none', 'DMARC: none']) await expect(warning).toContainText(chip);
    // Nobody vouches for this sender: the initial, no picture.
    await expect(message.locator('[data-avatar-source]')).toHaveAttribute('data-avatar-source', 'initial');

    const details = page.getByRole('table', { name: 'Message details' });
    await expect(details).toHaveCount(0);
    await message.getByTestId('sender-name').hover();
    await expect(details).toBeVisible();
    const line = (label: string) => details.getByRole('row').filter({ has: page.getByRole('rowheader', { name: `${label}:`, exact: true }) });
    await expect(line('from')).toContainText('Ann Example <ann@remote.test>');
    await expect(line('to')).toContainText(HANK);
    await expect(line('cc')).toContainText('team@remote.test');
    await expect(line('subject')).toContainText('Wire transfer today');
    await expect(line('date')).toContainText(String(new Date().getFullYear()));
    await expect(line('mailed-by')).toContainText('mailer.remote.test');
    await expect(line('security')).toContainText('Not encrypted on the way to this server');
    await expect(line('sender')).toContainText('Sender not verified');
    await expect(line('sender')).toContainText('SPF none · DKIM none · DMARC none');
    await expect(line('signed-by')).toHaveCount(0);
    // Looking at the details does not collapse the message.
    await details.click();
    await expect(warning).toBeVisible();
    // The keyboard reaches the same details.
    await page.mouse.move(0, 0);
    await expect(details).toHaveCount(0);
    await message.getByTestId('sender-name').focus();
    await page.keyboard.press('Shift+Tab');
    await page.keyboard.press('Tab');
    await expect(message.getByTestId('sender-name')).toBeFocused();
    await expect(details).toBeVisible();

    // Failed checks are named one by one, and malware comes first.
    await page.goto('/mail');
    await row(page, 'Invoice attached').click();
    const alerts = page.getByTestId('message').getByRole('alert');
    await expect(alerts.first()).toContainText('The virus scanner found malware in this message: Eicar-Signature');
    await expect(alerts.first()).toContainText('Do not open its attachments');
    const failed = page.getByTestId('sender-warning');
    await expect(failed).toContainText('This message may not really be from ann@remote.test');
    await expect(failed.getByRole('listitem')).toHaveCount(3);
    await expect(failed).toContainText('DMARC: the message does not come from where remote.test says its mail comes from');
    for (const chip of ['SPF: softfail', 'DKIM: fail', 'DMARC: fail']) await expect(failed).toContainText(chip);

    // A message that passed everything: no warning, and the details say who signed it.
    await page.getByRole('banner').getByRole('link', { name: 'unoMail' }).click();
    await row(page, 'All in order').click();
    await expect(page.getByTestId('message')).toBeVisible();
    await expect(page.getByTestId('sender-warning')).toHaveCount(0);
    await expect(page.getByTestId('message').getByRole('alert')).toHaveCount(0);
    await page.getByTestId('message').getByTestId('sender-name').hover();
    await expect(line('signed-by')).toContainText('remote.test');
    await expect(line('sender')).toContainText('Sender verified');
    await expect(line('security')).toContainText('Standard encryption (TLS)');

    // What arrived without being checked at all says so, without alarm.
    await smtpDeliver('bea@remote.test', HANK, `From: bea@remote.test\nTo: ${HANK}\nSubject: Unchecked delivery\n\nHi\n`);
    await page.getByRole('banner').getByRole('link', { name: 'unoMail' }).click();
    await page.reload();
    await row(page, 'Unchecked delivery').click();
    await expect(page.getByTestId('message')).toBeVisible();
    await expect(page.getByTestId('sender-warning')).toHaveCount(0);
    await page.getByTestId('message').getByTestId('sender-name').hover();
    await expect(line('sender')).toContainText('Not checked');
  });

  test('mail from a signed-in colleague carries no warning', async ({ page }) => {
    await login(page, HANK, USER_PASSWORD);
    await page.getByRole('button', { name: 'Compose' }).click();
    const composer = page.getByRole('dialog', { name: 'New message' });
    await composer.getByLabel('To').fill(HANK);
    await composer.getByLabel('Subject').fill('Note to self');
    await composer.getByRole('textbox', { name: 'Message body' }).click();
    await page.keyboard.type('Remember the milk.');
    await composer.getByRole('button', { name: 'Send' }).click();
    await expect(page.getByText('Message sent')).toBeVisible();
    await expect(async () => {
      await page.reload();
      await expect(row(page, 'Note to self')).toBeVisible({ timeout: 2000 });
    }).toPass({ timeout: 30_000 });
    await row(page, 'Note to self').click();
    const message = page.getByTestId('message').last();
    await expect(message.getByText('Remember the milk.').or(message.locator('iframe'))).toBeVisible();
    await expect(page.getByTestId('sender-warning')).toHaveCount(0);
    await message.getByTestId('sender-name').hover();
    const details = page.getByRole('table', { name: 'Message details' });
    await expect(details).toContainText('Sent from within this mail server');
    await expect(details).toContainText('From a signed-in user of this server');
  });

  test('the name in the header leads back to the inbox', async ({ page }) => {
    await login(page, HANK, USER_PASSWORD);
    const home = page.getByRole('banner').getByRole('link', { name: 'unoMail' });
    await folders(page).getByText('Sent', { exact: true }).click();
    await expect(page.getByRole('heading', { name: 'Sent', level: 1 })).toBeVisible();
    await page.getByPlaceholder('Search mail').fill('milk');
    await home.click();
    await expect(page.getByRole('heading', { name: 'Inbox', level: 1 })).toBeVisible();
    await expect(page.getByPlaceholder('Search mail')).toHaveValue('');

    // From an open conversation, and from the other pages.
    await row(page, 'Wire transfer today').click();
    await expect(page.getByTestId('message')).toBeVisible();
    await home.click();
    await expect(page.getByTestId('message')).toHaveCount(0);
    await expect(page).toHaveURL(/\/mail$/);
    for (const path of ['/calendar', '/contacts', '/settings']) {
      await page.goto(path);
      await page.getByRole('banner').getByRole('link').first().click();
      await expect(folders(page)).toBeVisible();
      await expect(page.getByRole('heading', { name: 'Inbox', level: 1 })).toBeVisible();
    }
  });

  test('the sidebar switch shrinks the sidebar to icons instead of hiding it', async ({ page }) => {
    await login(page, HANK, USER_PASSWORD);
    const nav = folders(page);
    const toggle = page.getByRole('button', { name: 'Toggle sidebar' });
    const wide = (await nav.boundingBox())!.width;
    expect(wide).toBeGreaterThan(200);
    await expect(nav.getByText('Sent', { exact: true })).toBeVisible();
    await expect(toggle).toHaveAttribute('aria-expanded', 'true');

    await toggle.click();
    await expect(toggle).toHaveAttribute('aria-expanded', 'false');
    await expect(nav).toBeVisible();
    await expect(nav).toHaveAttribute('data-mini', 'true');
    await expect.poll(async () => (await nav.boundingBox())!.width).toBeLessThan(90);
    // Texts and the less used entries are gone; the folders stay, as icons with their names.
    await expect(nav.getByText('Sent', { exact: true })).toBeHidden();
    await expect(nav.getByText('New folder')).toBeHidden();
    await expect(nav.getByText('Labels')).toBeHidden();
    await expect(nav.getByRole('button', { name: 'Compose' })).toBeVisible();
    for (const name of ['Inbox', 'Drafts', 'Sent', 'Archive', 'Junk', 'Trash', 'Calendar', 'Contacts']) await expect(nav.getByRole('button', { name, exact: true })).toBeVisible();
    await expect(nav.getByRole('button', { name: 'Sent', exact: true })).toHaveAttribute('title', 'Sent');
    // Nothing spills out of the strip.
    for (const name of ['Inbox', 'Calendar']) {
      const [strip, box] = [(await nav.boundingBox())!, (await nav.getByRole('button', { name, exact: true }).boundingBox())!];
      expect(box.x).toBeGreaterThanOrEqual(strip.x);
      expect(box.x + box.width).toBeLessThanOrEqual(strip.x + strip.width + 1);
    }
    // The message list got the room.
    await expect(rows(page).first()).toBeVisible();
    expect((await page.getByRole('list', { name: 'Messages' }).boundingBox())!.x).toBeLessThan(120);

    // It works as before, and stays that way after a reload.
    await nav.getByRole('button', { name: 'Sent', exact: true }).click();
    await expect(page.getByRole('heading', { name: 'Sent', level: 1 })).toBeVisible();
    await nav.getByRole('button', { name: 'Compose' }).click();
    await expect(page.getByRole('dialog', { name: 'New message' })).toBeVisible();
    await page.keyboard.press('Escape');
    await page.reload();
    await expect(folders(page)).toHaveAttribute('data-mini', 'true');

    await page.getByRole('button', { name: 'Toggle sidebar' }).click();
    await expect(folders(page)).toHaveAttribute('data-mini', 'false');
    await expect(folders(page).getByText('New folder')).toBeVisible();
    await expect.poll(async () => (await folders(page).boundingBox())!.width).toBeGreaterThan(200);
  });
});
