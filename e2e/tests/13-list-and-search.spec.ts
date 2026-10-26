import { expect, test, type Page } from '@playwright/test';
import { DOMAIN, login, smtpDeliver, USER_PASSWORD } from './helpers';

// A mailbox of its own, so the counts here do not depend on the other specs.
const IVY = `ivy@${DOMAIN}`;
const ADMIN_EMAIL = 'admin@e2e.test';
const ADMIN_PASSWORD = 'e2e-admin-password-1';

const rows = (page: Page) => page.getByTestId('email-row');
const row = (page: Page, text: string) => rows(page).filter({ hasText: text });
const searchBox = (page: Page) => page.getByRole('textbox', { name: 'Search mail' });

const withFiles = (subject: string) =>
  [
    'From: Anna Kowalska <anna@partner.test>', `To: ${IVY}`, `Subject: ${subject}`, 'MIME-Version: 1.0', 'Content-Type: multipart/mixed; boundary="b1"', '',
    '--b1', 'Content-Type: text/plain', '', 'The figures are attached. Codeword: marmalade.', '',
    '--b1', 'Content-Type: text/plain; name="notes.txt"', 'Content-Disposition: attachment; filename="notes.txt"', '', 'Agenda for Thursday', '',
    '--b1', 'Content-Type: application/pdf; name="report-q3.pdf"', 'Content-Disposition: attachment; filename="report-q3.pdf"', 'Content-Transfer-Encoding: base64', '', 'JVBERi0xLjQK', '--b1--', '',
  ].join('\n');

async function setDensity(page: Page, density: 'Condensed' | 'Expanded') {
  await page.goto('/settings?tab=general');
  await page.getByRole('radiogroup', { name: 'Message list density' }).getByRole('radio', { name: new RegExp(`^${density}`) }).click();
  await expect(page.getByRole('radio', { name: new RegExp(`^${density}`) })).toHaveAttribute('aria-checked', 'true');
  await page.goto('/mail');
}

test.describe('message list, reader and search', () => {
  // A step that cannot happen should fail with its own line, not run into the test's time limit.
  test.use({ actionTimeout: 10_000 });
  test.beforeAll(async ({ browser }) => {
    const page = await browser.newPage();
    await login(page, ADMIN_EMAIL, ADMIN_PASSWORD);
    await page.goto('/admin/mailboxes');
    await page.getByRole('button', { name: 'Add mailbox' }).click();
    const dialog = page.getByRole('dialog');
    await dialog.getByLabel('E-mail address').fill(IVY);
    await dialog.getByLabel('Password', { exact: true }).fill(USER_PASSWORD);
    await dialog.getByRole('button', { name: 'Create' }).click();
    const exists = dialog.getByText(/already exists/).first();
    await expect(page.getByText('Mailbox created').or(exists)).toBeVisible();
    // A failed test starts this hook over; the mail then is there already.
    if (!(await exists.isVisible())) {
      await smtpDeliver('anna@partner.test', IVY, withFiles('Quarterly figures'));
      await smtpDeliver('jan@remote.test', IVY, `From: Jan Nowak <jan@remote.test>\nTo: ${IVY}\nSubject: Lunch plans\nMessage-ID: <lunch-1@remote.test>\n\nShall we meet at the canteen?\n`);
      await smtpDeliver('ivy@remote.test', IVY, `From: Ivy Other <other@remote.test>\nTo: ${IVY}\nSubject: Re: Lunch plans\nIn-Reply-To: <lunch-1@remote.test>\nReferences: <lunch-1@remote.test>\n\nYes, at noon.\n`);
      await smtpDeliver('news@shop.test', IVY, `From: Shop <news@shop.test>\nTo: ${IVY}\nSubject: Autumn sale\n\nEverything must go.\n`);
    }
    await page.close();
  });

  test('the list is condensed or expanded, the same with a conversation open', async ({ page }) => {
    await login(page, IVY, USER_PASSWORD);
    await setDensity(page, 'Condensed');
    const figures = row(page, 'Quarterly figures');
    await expect(figures).toHaveAttribute('data-density', 'condensed');
    expect((await figures.boundingBox())!.height).toBeLessThan(52);
    // Every row has the sender's picture (the initial, for senders without one).
    await expect(figures.locator('.MuiAvatar-root')).toHaveCount(1);
    await expect(figures.locator('.MuiAvatar-root')).toHaveText('A');
    await expect(figures.getByRole('list', { name: /^Attachments of/ })).toHaveCount(0);

    // Beside an open conversation the rows keep their style: still one line each.
    await row(page, 'Autumn sale').click();
    await expect(page.getByRole('region', { name: 'Conversation' })).toBeVisible();
    await expect(figures).toHaveAttribute('data-density', 'condensed');
    expect((await figures.boundingBox())!.height).toBeLessThan(52);
    const [sender, subject] = await Promise.all([figures.getByText('Anna Kowalska').boundingBox(), figures.getByText('Quarterly figures').boundingBox()]);
    expect(Math.abs(sender!.y - subject!.y)).toBeLessThan(6);

    await setDensity(page, 'Expanded');
    await expect(figures).toHaveAttribute('data-density', 'expanded');
    expect((await figures.boundingBox())!.height).toBeGreaterThan(70);
    await expect(figures.locator('.MuiAvatar-root')).toHaveCount(1);
    // The attached files, as Gmail lists them.
    const files = figures.getByRole('list', { name: 'Attachments of Quarterly figures' });
    await expect(files.getByRole('listitem')).toHaveCount(2);
    await expect(files).toContainText('notes.txt');
    await expect(files).toContainText('report-q3.pdf');
    await expect(row(page, 'Autumn sale').getByRole('list', { name: /^Attachments of/ })).toHaveCount(0);
    // A file opens in the preview, without opening the conversation.
    await files.getByText('notes.txt').click();
    const preview = page.getByRole('dialog');
    await expect(preview).toContainText('Agenda for Thursday');
    await expect(page.getByRole('region', { name: 'Conversation' })).toHaveCount(0);
    await page.keyboard.press('Escape');

    // With a conversation open the list stays expanded too.
    await row(page, 'Autumn sale').click();
    await expect(page.getByRole('region', { name: 'Conversation' })).toBeVisible();
    await expect(figures).toHaveAttribute('data-density', 'expanded');
    await expect(files.getByRole('listitem')).toHaveCount(2);
    await setDensity(page, 'Condensed');
  });

  test('a lone message stays open; the sender can be clicked without folding it', async ({ page }) => {
    await login(page, IVY, USER_PASSWORD);
    await row(page, 'Autumn sale').click();
    const message = page.getByTestId('message');
    const body = message.frameLocator('iframe[title="Message body"]').getByText('Everything must go.');
    await expect(body).toBeVisible();
    await expect(message.locator('[data-collapsible]')).toHaveAttribute('data-collapsible', 'false');
    // Clicking anywhere on the header of a conversation's only message folds nothing.
    await message.locator('[data-collapsible]').click({ position: { x: 400, y: 20 } });
    await expect(body).toBeVisible();

    // The download moved into the menu.
    await expect(message.getByRole('link', { name: 'Download' })).toHaveCount(0);
    await message.getByRole('button', { name: 'More actions' }).click();
    const download = page.getByRole('menuitem', { name: 'Download message' });
    await expect(download).toHaveAttribute('href', /\/jmap\/download\//);
    await expect(download).toHaveAttribute('download', 'Autumn sale.eml');
    const raw = await (await page.request.get((await download.getAttribute('href'))!)).text();
    expect(raw).toContain('Subject: Autumn sale');
    await page.keyboard.press('Escape');

    // In a conversation of two, the header folds a message, but its sender does not.
    await page.goto('/mail');
    await row(page, 'Lunch plans').click();
    const messages = page.getByTestId('message');
    await expect(messages).toHaveCount(2);
    const latest = messages.last();
    const reply = latest.frameLocator('iframe[title="Message body"]').getByText('Yes, at noon.');
    await expect(reply).toBeVisible();
    // (The name last: hovering it opens the card about the sender, which then covers the lines below.)
    for (const part of [latest.locator('.MuiAvatar-root'), latest.getByTestId('sender-block').getByText(/^to /), latest.getByTestId('sender-name')]) {
      await part.click();
      await expect(reply).toBeVisible();
    }
    await page.mouse.move(0, 0);
    // The date is part of the header, not of the sender.
    await latest.locator('[data-collapsible]').getByText(/\d:\d\d/).click();
    await expect(reply).toHaveCount(0);
    // A folded message opens again from its sender's name too.
    await latest.getByTestId('sender-name').click();
    await expect(reply).toBeVisible();
  });

  test('advanced search builds a query, and the query finds what it says', async ({ page }) => {
    await login(page, IVY, USER_PASSWORD);
    await expect(rows(page)).toHaveCount(3);

    await page.getByRole('button', { name: 'Show search options' }).click();
    const form = page.getByRole('search', { name: 'Advanced search' });
    await form.getByLabel('From', { exact: true }).fill('Anna Kowalska');
    await form.getByLabel('Has the words', { exact: true }).fill('marmalade');
    await form.getByLabel('Has attachment').check();
    await expect(form).toContainText('from:"Anna Kowalska" marmalade has:attachment');
    await form.getByRole('button', { name: 'Search' }).click();
    await expect(form).toHaveCount(0);
    await expect(searchBox(page)).toHaveValue('from:"Anna Kowalska" marmalade has:attachment');
    await expect(rows(page)).toHaveCount(1);
    await expect(rows(page)).toContainText('Quarterly figures');

    // Typed operators work the same; the form opens on what is in the box.
    const search = async (query: string) => {
      await searchBox(page).fill(query);
      await searchBox(page).press('Enter');
    };
    await search('has:attachment');
    await expect(rows(page)).toHaveCount(1);
    await search('lunch -noon');
    await expect(rows(page)).toHaveCount(1);
    await expect(rows(page)).toContainText('Shall we meet');
    await search('from:shop OR from:jan');
    await expect(rows(page)).toHaveCount(2);
    await search('filename:notes');
    await expect(rows(page)).toHaveCount(1);
    await expect(rows(page)).toContainText('Quarterly figures');
    await search('canteen');
    await expect(rows(page)).toHaveCount(1);
    await expect(rows(page)).toContainText('Lunch plans');
    await search('subject:canteen');
    await expect(page.getByText('No messages match your search.')).toBeVisible();
    await search('larger:5M');
    await expect(page.getByText('No messages match your search.')).toBeVisible();
    await search('in:sent sale');
    await expect(page.getByText('No messages match your search.')).toBeVisible();
    await search('newer_than:1d sale');
    await expect(rows(page)).toHaveCount(1);

    await search('from:jan lunch');
    await page.getByRole('button', { name: 'Show search options' }).click();
    await expect(form.getByLabel('From', { exact: true })).toHaveValue('jan');
    await expect(form.getByLabel('Has the words', { exact: true })).toHaveValue('lunch');
    await form.getByLabel("Doesn't have", { exact: true }).fill('noon');
    await form.getByRole('button', { name: 'Search' }).click();
    await expect(searchBox(page)).toHaveValue('from:jan lunch -noon');
    await expect(rows(page)).toHaveCount(1);
  });

  test('settings are grouped in sections and use the whole width', async ({ page }) => {
    await login(page, IVY, USER_PASSWORD);
    await page.getByRole('button', { name: 'Account menu' }).click();
    await page.getByRole('menuitem', { name: 'Settings' }).click();
    const sections = page.getByRole('navigation', { name: 'Settings sections' });
    await expect(sections.getByRole('button')).toHaveText(['General', 'Inbox', 'Identities', 'Masked addresses', 'Signatures', 'Templates', 'Filters', 'Out of office', 'Security']);
    await expect(page.getByRole('heading', { name: 'General', level: 2 })).toBeVisible();
    await expect(page.getByRole('radiogroup', { name: 'Message list density' })).toBeVisible();
    await expect(page.getByLabel('Sieve script')).toHaveCount(0);
    const main = (await page.getByRole('main').boundingBox())!;
    // Everything beside the section list.
    expect(main.width).toBeGreaterThan(page.viewportSize()!.width * 0.75);

    await sections.getByRole('button', { name: 'Security' }).click();
    await expect(page).toHaveURL(/\?tab=security$/);
    await expect(page.getByRole('heading', { name: 'Change password' })).toBeVisible();
    await expect(page.getByRole('table', { name: 'Sessions' })).toBeVisible();
    // A section can be linked to.
    await page.goto('/settings?tab=filters');
    await expect(page.getByRole('tab', { name: 'Rules' })).toBeVisible();
    await expect(sections.getByRole('button', { name: 'Filters' })).toHaveAttribute('aria-current', 'page');
    await page.goto('/settings?tab=nonsense');
    await expect(page.getByRole('heading', { name: 'General', level: 2 })).toBeVisible();
  });
});
