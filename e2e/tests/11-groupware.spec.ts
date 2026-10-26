import { expect, test, type Browser, type Page } from '@playwright/test';
import { DOMAIN, login, smtpDeliver, USER_PASSWORD } from './helpers';

// Mailboxes of their own, so nothing here depends on what the other specs left behind.
const FRANK = `frank@${DOMAIN}`;
const GRACE = `grace@${DOMAIN}`;
const ADMIN_EMAIL = 'admin@e2e.test';
const ADMIN_PASSWORD = 'e2e-admin-password-1';

const pad = (n: number) => String(n).padStart(2, '0');
const now = new Date();
const today = `${now.getFullYear()}-${pad(now.getMonth() + 1)}-${pad(now.getDate())}`;
const local = (date: Date) => `${date.getFullYear()}-${pad(date.getMonth() + 1)}-${pad(date.getDate())}T${pad(date.getHours())}:${pad(date.getMinutes())}`;

const rows = (page: Page) => page.getByTestId('email-row');
const row = (page: Page, text: string) => rows(page).filter({ hasText: text });
const chips = (page: Page, summary: string) => page.getByRole('button', { name: new RegExp(`^${summary},`) });

async function createMailboxes(browser: Browser, addresses: string[]) {
  const page = await browser.newPage();
  await login(page, ADMIN_EMAIL, ADMIN_PASSWORD);
  await page.goto('/admin/mailboxes');
  for (const address of addresses) {
    await page.getByRole('button', { name: 'Add mailbox' }).click();
    const dialog = page.getByRole('dialog');
    await dialog.getByLabel('E-mail address').fill(address);
    await dialog.getByLabel('Password', { exact: true }).fill(USER_PASSWORD);
    await dialog.getByRole('button', { name: 'Create' }).click();
    // After a failed test the worker (and this hook) starts over; the mailbox may exist already.
    const exists = dialog.getByText(/already exists/).first();
    await expect(page.getByText('Mailbox created').or(exists)).toBeVisible();
    if (await exists.isVisible()) await dialog.getByRole('button', { name: 'Cancel' }).click();
    await expect(dialog).toHaveCount(0);
  }
  await page.close();
}

async function openCalendar(page: Page, user: string) {
  await login(page, user, USER_PASSWORD);
  await page.getByRole('button', { name: 'Account menu' }).click();
  await page.getByRole('menuitem', { name: 'Calendar' }).click();
  await expect(page.getByRole('navigation', { name: 'Calendars' })).toContainText('Personal');
}

async function newEvent(page: Page, title: string, fill?: (dialog: ReturnType<Page['getByRole']>) => Promise<void>) {
  await page.getByRole('button', { name: 'New event' }).click();
  const dialog = page.getByRole('dialog', { name: 'New event' });
  await dialog.getByLabel('Title').fill(title);
  await dialog.getByLabel('Starts').fill(`${today}T12:00`);
  if (fill) await fill(dialog);
  await dialog.getByRole('button', { name: 'Save' }).click();
  await expect(page.getByText('Event saved')).toBeVisible();
}

test.describe('groupware', () => {
  test.beforeAll(async ({ browser }) => {
    await createMailboxes(browser, [FRANK, GRACE]);
  });

  test('conversations offer quick actions when the pointer is on them', async ({ page }) => {
    for (const subject of ['Hover to archive', 'Hover to delete', 'Hover to read']) await smtpDeliver('ann@remote.test', FRANK, `From: Ann <ann@remote.test>\nTo: ${FRANK}\nSubject: ${subject}\n\nBody\n`);
    await login(page, FRANK, USER_PASSWORD);
    await expect(rows(page)).toHaveCount(3);

    const target = row(page, 'Hover to read');
    const actions = target.getByRole('group', { name: 'Quick actions for Hover to read' });
    await expect(actions).toBeHidden();
    await target.hover();
    await expect(actions).toBeVisible();
    // The actions take the place of the date, on the right edge of the row.
    const [rowBox, actionsBox] = [(await target.boundingBox())!, (await actions.boundingBox())!];
    expect(actionsBox.x + actionsBox.width).toBeGreaterThan(rowBox.x + rowBox.width - 16);
    expect(actionsBox.y).toBeGreaterThanOrEqual(rowBox.y - 1);
    expect(actionsBox.y + actionsBox.height).toBeLessThanOrEqual(rowBox.y + rowBox.height + 1);

    // Read and unread, without opening the conversation.
    await actions.getByRole('button', { name: 'Mark as read' }).click();
    await expect(target).toHaveAttribute('data-unread', 'false');
    await expect(page).toHaveURL(/\/mail(\/inbox)?$/);
    await target.hover();
    await actions.getByRole('button', { name: 'Mark as unread' }).click();
    await expect(target).toHaveAttribute('data-unread', 'true');

    await row(page, 'Hover to archive').hover();
    await row(page, 'Hover to archive').getByRole('button', { name: 'Archive', exact: true }).click();
    await expect(page.getByText('1 conversation archived')).toBeVisible();
    await expect(row(page, 'Hover to archive')).toHaveCount(0);
    await row(page, 'Hover to delete').hover();
    await row(page, 'Hover to delete').getByRole('button', { name: 'Delete', exact: true }).click();
    await expect(page.getByText('1 conversation deleted')).toBeVisible();
    await expect(rows(page)).toHaveCount(1);

    // The archived conversation is in the archive, where archiving is not offered again.
    await page.getByRole('navigation', { name: 'Folders' }).getByText('Archive', { exact: true }).click();
    await expect(row(page, 'Hover to archive')).toHaveCount(1);
    await row(page, 'Hover to archive').hover();
    await expect(row(page, 'Hover to archive').getByRole('button', { name: 'Delete', exact: true })).toBeVisible();
    await expect(row(page, 'Hover to archive').getByRole('button', { name: 'Archive', exact: true })).toHaveCount(0);
  });

  test('a colleague is invited, answers from the message, and the organizer sees the answer', async ({ page, browser }) => {
    await openCalendar(page, FRANK);
    await newEvent(page, 'Planning poker', async (dialog) => {
      await dialog.getByLabel('Guests').fill(GRACE);
      await dialog.getByLabel('Guests').press('Enter');
      await expect(dialog.getByRole('button', { name: GRACE })).toBeVisible();
      await dialog.getByLabel('Location').fill('Room 4');
    });
    await chips(page, 'Planning poker').click();
    await expect(page.getByRole('list', { name: 'Guests' })).toContainText(`${GRACE} no answer yet`);
    await page.getByRole('dialog').getByRole('button', { name: 'Close' }).click();

    // Grace finds the invitation in her mail and accepts it there.
    const context = await browser.newContext();
    const hers = await context.newPage();
    await login(hers, GRACE, USER_PASSWORD);
    await expect(async () => {
      await hers.reload();
      await expect(row(hers, 'Invitation: Planning poker')).toBeVisible({ timeout: 2000 });
    }).toPass({ timeout: 45_000 });
    await row(hers, 'Invitation: Planning poker').click();
    const card = hers.getByRole('region', { name: 'Invitation: Planning poker' });
    await expect(card).toContainText('Room 4');
    await expect(card).toContainText(`Organizer: ${FRANK}`);
    await card.getByRole('button', { name: 'Accept' }).click();
    await expect(card.getByRole('status')).toHaveText('Added to your calendar and the organizer was told');
    await expect(card.getByRole('button', { name: 'Accept' })).toHaveAttribute('aria-pressed', 'true');
    await hers.getByRole('button', { name: 'Account menu' }).click();
    await hers.getByRole('menuitem', { name: 'Calendar' }).click();
    await expect(chips(hers, 'Planning poker')).toHaveCount(1);
    // It is Frank's event: she can change her copy's reminder, not the guest list.
    await chips(hers, 'Planning poker').click();
    await hers.getByRole('dialog').getByRole('button', { name: 'Edit' }).click();
    await expect(hers.getByRole('dialog', { name: 'Edit event' })).toContainText('its guest list belongs to the organizer');
    await expect(hers.getByRole('dialog', { name: 'Edit event' }).getByLabel('Guests')).toHaveCount(0);
    await context.close();

    // Frank's event shows her answer once her reply has arrived; the reply explains itself too.
    await expect(async () => {
      await page.reload();
      await chips(page, 'Planning poker').click({ timeout: 2000 });
      await expect(page.getByRole('list', { name: 'Guests' })).toContainText(`${GRACE} accepted`, { timeout: 2000 });
    }).toPass({ timeout: 45_000 });
    await page.goto('/mail/inbox');
    await row(page, 'Accepted: Planning poker').click();
    await expect(page.getByRole('region', { name: 'Answer to your invitation: Planning poker' })).toContainText('accepted');
  });

  test('a calendar is shared with a colleague for reading', async ({ page, browser }) => {
    await openCalendar(page, FRANK);
    await page.getByRole('navigation', { name: 'Calendars' }).getByText('New calendar').click();
    await page.getByRole('dialog', { name: 'New calendar' }).getByLabel('Name').fill('Team');
    await page.getByRole('dialog', { name: 'New calendar' }).getByRole('button', { name: 'Save' }).click();
    await expect(page.getByRole('navigation', { name: 'Calendars' })).toContainText('Team');
    await newEvent(page, 'Team offsite', async (dialog) => {
      await dialog.getByLabel('Calendar', { exact: true }).click();
      await page.getByRole('option', { name: 'Team' }).click();
    });

    await page.getByRole('button', { name: 'Options for Team' }).click();
    await page.getByRole('menuitem', { name: 'Share with colleagues' }).click();
    const share = page.getByRole('dialog', { name: 'Share “Team”' });
    await expect(share).toContainText('Not shared with anybody');
    await share.getByLabel('Colleague’s address').fill('someone@elsewhere.example');
    await share.getByRole('button', { name: 'Add' }).click();
    await share.getByRole('button', { name: 'Save' }).click();
    await expect(share.getByRole('alert')).toContainText('not a mailbox of your domain');
    await share.getByRole('button', { name: 'Stop sharing with someone@elsewhere.example' }).click();
    await share.getByLabel('Colleague’s address').fill(GRACE);
    await share.getByLabel('Colleague’s address').press('Enter');
    await expect(share.getByTestId('calendar-share')).toContainText(GRACE);
    await share.getByRole('button', { name: 'Save' }).click();
    await expect(page.getByText('Sharing saved')).toBeVisible();

    const context = await browser.newContext();
    const hers = await context.newPage();
    await openCalendar(hers, GRACE);
    const list = hers.getByRole('navigation', { name: 'Calendars' });
    await expect(list).toContainText('Team');
    await expect(list).toContainText(`${FRANK} · read only`);
    await chips(hers, 'Team offsite').click();
    const details = hers.getByRole('dialog');
    await expect(details).toContainText('read only');
    await expect(details.getByRole('button', { name: 'Edit' })).toHaveCount(0);
    await expect(details.getByRole('button', { name: 'Delete' })).toHaveCount(0);
    await details.getByRole('button', { name: 'Close' }).click();
    // She can take it off her list; Frank's calendar is untouched.
    hers.on('dialog', (prompt) => void prompt.accept());
    await hers.getByRole('button', { name: 'Options for Team' }).click();
    await expect(hers.getByRole('menuitem', { name: 'Share with colleagues' })).toHaveCount(0);
    await hers.getByRole('menuitem', { name: 'Remove from my list' }).click();
    await expect(hers.getByText('Calendar removed from your list')).toBeVisible();
    await expect(chips(hers, 'Team offsite')).toHaveCount(0);
    await context.close();
    await page.reload();
    await expect(chips(page, 'Team offsite')).toHaveCount(1);
  });

  test('one occurrence of a repeating event is changed on its own', async ({ page }) => {
    await openCalendar(page, GRACE);
    await newEvent(page, 'Daily sync', async (dialog) => {
      await dialog.getByLabel('Repeat', { exact: true }).click();
      await page.getByRole('option', { name: 'Every day' }).click();
    });
    const total = await chips(page, 'Daily sync').count();
    expect(total).toBeGreaterThan(1);

    await chips(page, 'Daily sync').first().click();
    await page.getByRole('dialog').getByRole('button', { name: 'Edit' }).click();
    await page.getByRole('menuitem', { name: 'Only this occurrence' }).click();
    const editor = page.getByRole('dialog', { name: 'Edit this occurrence' });
    await expect(editor.getByLabel('Starts')).toHaveValue(`${today}T12:00`);
    await expect(editor.getByLabel('Repeat', { exact: true })).toHaveCount(0);
    await editor.getByLabel('Title').fill('Daily sync moved');
    await editor.getByLabel('Starts').fill(`${today}T15:00`);
    await editor.getByRole('button', { name: 'Save' }).click();
    await expect(page.getByText('Event saved')).toBeVisible();
    await expect(chips(page, 'Daily sync moved')).toHaveCount(1);
    await expect(chips(page, 'Daily sync')).toHaveCount(total - 1);

    // Editing the series afterwards renames the others and leaves the changed one alone.
    await chips(page, 'Daily sync').first().click();
    await page.getByRole('dialog').getByRole('button', { name: 'Edit' }).click();
    await page.getByRole('menuitem', { name: 'All occurrences' }).click();
    const series = page.getByRole('dialog', { name: 'Edit event' });
    await series.getByLabel('Title').fill('Daily check-in');
    await series.getByRole('button', { name: 'Save' }).click();
    await expect(chips(page, 'Daily check-in')).toHaveCount(total - 1);
    await expect(chips(page, 'Daily sync moved')).toHaveCount(1);
  });

  test('tasks are kept, completed and deleted', async ({ page }) => {
    await openCalendar(page, GRACE);
    await page.getByRole('group', { name: 'View' }).getByRole('button', { name: 'Tasks', exact: true }).click();
    await expect(page.getByText('No tasks.')).toBeVisible();
    await page.getByLabel('New task').fill('Book the flights');
    await page.getByLabel('Due', { exact: true }).fill('2020-01-15');
    await page.getByRole('button', { name: 'Add', exact: true }).click();
    await page.getByLabel('New task').fill('Water the plants');
    await page.getByLabel('New task').press('Enter');
    const tasks = page.getByTestId('task');
    await expect(tasks).toHaveCount(2);
    // The dated task comes first and is overdue.
    await expect(tasks.nth(0)).toContainText('Book the flights');
    await expect(tasks.nth(0)).toContainText('overdue');

    await page.getByLabel('Complete Book the flights').check();
    await expect(tasks.nth(1)).toContainText('Book the flights');
    await expect(tasks.nth(1)).toHaveAttribute('data-completed', 'true');
    await expect(tasks.nth(1)).not.toContainText('overdue');
    await page.reload();
    await expect(page.getByLabel('Reopen Book the flights')).toBeChecked();
    await page.getByRole('button', { name: 'Delete Book the flights' }).click();
    await expect(tasks).toHaveCount(1);
    await expect(tasks).toContainText('Water the plants');
  });

  test('a reminder is announced while the web client is open', async ({ page }) => {
    await openCalendar(page, GRACE);
    // An event five minutes from now with a reminder five minutes ahead: due at once.
    const start = new Date(Date.now() + 5 * 60_000);
    test.skip(start.getDate() !== now.getDate(), 'too close to midnight to place the event today');
    await page.getByRole('button', { name: 'New event' }).click();
    const dialog = page.getByRole('dialog', { name: 'New event' });
    await dialog.getByLabel('Title').fill('Call the bank');
    await dialog.getByLabel('Starts').fill(local(start));
    await dialog.getByLabel('Reminder').click();
    await page.getByRole('option', { name: '5 minutes before', exact: true }).click();
    await dialog.getByRole('button', { name: 'Save' }).click();
    await expect(page.getByText('Event saved')).toBeVisible();

    // Reminders are picked up when the page comes to the front; a reload does the same.
    await page.goto('/mail/inbox');
    const alert = page.getByRole('alert').filter({ hasText: 'Call the bank' });
    await expect(alert).toBeVisible({ timeout: 15_000 });
    await expect(alert).toContainText(/Starts (in \d minutes?|now)/);
    await alert.getByRole('button', { name: 'Close' }).click();
    await expect(alert).toHaveCount(0);
    // Shown once: not again after another reload.
    await page.reload();
    await expect(page.getByRole('navigation', { name: 'Folders' })).toBeVisible();
    await page.waitForTimeout(1500);
    await expect(alert).toHaveCount(0);
  });

  test('the address book tells how to synchronise it', async ({ page, request }) => {
    await login(page, GRACE, USER_PASSWORD);
    await page.getByRole('navigation', { name: 'Folders' }).getByText('Contacts', { exact: true }).click();
    await page.getByRole('button', { name: 'Sync with phone' }).click();
    const dialog = page.getByRole('dialog', { name: 'Use these contacts on a phone or in a mail program' });
    await expect(dialog.getByLabel('Server address')).toHaveValue(/\/dav\/$/);
    await expect(dialog.getByLabel('User name')).toHaveValue(GRACE);
    const book = await dialog.getByLabel('Address book (if the program asks for it)').inputValue();
    expect(book).toMatch(new RegExp(`/dav/addressbooks/${GRACE}/contacts/$`));
    await dialog.getByRole('button', { name: 'Close' }).click();

    // A card stored the way a phone does it shows up in the list.
    const authorization = `Basic ${Buffer.from(`${GRACE}:${USER_PASSWORD}`).toString('base64')}`;
    const card = 'BEGIN:VCARD\r\nVERSION:3.0\r\nUID:e2e-card\r\nFN:Phone Friend\r\nTEL:+48 600 100 200\r\nEND:VCARD\r\n';
    const stored = await request.fetch(`${new URL(book).pathname}e2e-card.vcf`, { method: 'PUT', headers: { Authorization: authorization, 'Content-Type': 'text/vcard' }, data: card });
    expect(stored.status()).toBe(201);
    await page.reload();
    await expect(page.getByRole('cell', { name: 'Phone Friend' })).toBeVisible();
  });
});
