import { expect, test, type Page } from '@playwright/test';
import { DOMAIN, login, smtpDeliver, USER_PASSWORD } from './helpers';

// A mailbox of its own, so the calendar starts empty whatever the other specs did.
const DAVE = `dave@${DOMAIN}`;
const ADMIN_EMAIL = 'admin@e2e.test';
const ADMIN_PASSWORD = 'e2e-admin-password-1';
const BASIC = `Basic ${Buffer.from(`${DAVE}:${USER_PASSWORD}`).toString('base64')}`;
const HOME = `/dav/calendars/${DAVE}/`;

const pad = (n: number) => String(n).padStart(2, '0');
const now = new Date();
const today = `${now.getFullYear()}-${pad(now.getMonth() + 1)}-${pad(now.getDate())}`;
const todayCompact = today.replaceAll('-', '');

const chips = (page: Page, summary: string) => page.getByRole('button', { name: new RegExp(`^${summary},`) });

async function openCalendar(page: Page) {
  await login(page, DAVE, USER_PASSWORD);
  await page.getByRole('navigation', { name: 'Folders' }).getByText('Calendar', { exact: true }).click();
  await expect(page.getByRole('navigation', { name: 'Calendars' })).toContainText('Personal');
}

test.describe('calendar', () => {
  test.beforeAll(async ({ browser }) => {
    const page = await browser.newPage();
    await login(page, ADMIN_EMAIL, ADMIN_PASSWORD);
    await page.goto('/admin/mailboxes');
    await page.getByRole('button', { name: 'Add mailbox' }).click();
    const dialog = page.getByRole('dialog');
    await dialog.getByLabel('E-mail address').fill(DAVE);
    await dialog.getByLabel('Password', { exact: true }).fill(USER_PASSWORD);
    await dialog.getByRole('button', { name: 'Create' }).click();
    await expect(page.getByText('Mailbox created').or(dialog.getByRole('alert').filter({ hasText: 'already exists' }))).toBeVisible();
    await page.close();
  });

  test('events are created, repeated, edited and deleted', async ({ page }) => {
    await openCalendar(page);
    await expect(page.getByRole('grid', { name: 'Month' })).toBeVisible();

    await page.getByRole('button', { name: 'New event' }).click();
    const dialog = page.getByRole('dialog');
    await expect(dialog.getByRole('button', { name: 'Save' })).toBeDisabled();
    await dialog.getByLabel('Title').fill('Team lunch');
    await dialog.getByLabel('Starts').fill(`${today}T12:00`);
    // The end follows the start, keeping the length of one hour.
    await expect(dialog.getByLabel('Ends')).toHaveValue(`${today}T13:00`);
    await dialog.getByLabel('Location').fill('Canteen');
    await dialog.getByRole('button', { name: 'Save' }).click();
    await expect(page.getByText('Event saved')).toBeVisible();
    await expect(chips(page, 'Team lunch')).toHaveCount(1);

    // Details, then editing: a new title and a daily repetition.
    await chips(page, 'Team lunch').click();
    await expect(page.getByRole('dialog')).toContainText('Canteen');
    await page.getByRole('dialog').getByRole('button', { name: 'Edit' }).click();
    const editor = page.getByRole('dialog', { name: 'Edit event' });
    await expect(editor.getByLabel('Starts')).toHaveValue(`${today}T12:00`);
    await editor.getByLabel('Title').fill('Daily lunch');
    await editor.getByLabel('Repeat', { exact: true }).click();
    await page.getByRole('option', { name: 'Every day' }).click();
    await editor.getByRole('button', { name: 'Save' }).click();
    await expect(chips(page, 'Team lunch')).toHaveCount(0);
    const repeated = await chips(page, 'Daily lunch').count();
    expect(repeated).toBeGreaterThan(1);

    // The same series in the other views.
    await page.getByRole('group', { name: 'View' }).getByRole('button', { name: 'Day', exact: true }).click();
    await expect(chips(page, 'Daily lunch')).toHaveCount(1);
    await page.getByRole('button', { name: 'Next' }).click();
    await expect(chips(page, 'Daily lunch')).toHaveCount(1);
    await page.getByRole('button', { name: 'Today' }).click();
    await page.getByRole('group', { name: 'View' }).getByRole('button', { name: 'Agenda', exact: true }).click();
    await expect(chips(page, 'Daily lunch')).toHaveCount(30);
    await page.getByRole('group', { name: 'View' }).getByRole('button', { name: 'Month', exact: true }).click();
    await expect(chips(page, 'Daily lunch')).toHaveCount(repeated);

    // One occurrence goes, the others stay; then the whole series.
    await chips(page, 'Daily lunch').first().click();
    await page.getByRole('dialog').getByRole('button', { name: 'Delete' }).click();
    await page.getByRole('menuitem', { name: 'Only this occurrence' }).click();
    await expect(page.getByText('Occurrence deleted')).toBeVisible();
    await expect(chips(page, 'Daily lunch')).toHaveCount(repeated - 1);
    await chips(page, 'Daily lunch').first().click();
    await page.getByRole('dialog').getByRole('button', { name: 'Delete' }).click();
    await page.getByRole('menuitem', { name: 'All occurrences' }).click();
    await expect(page.getByText('Event deleted')).toBeVisible();
    await expect(chips(page, 'Daily lunch')).toHaveCount(0);
  });

  test('calendar programs see the same calendars over CalDAV', async ({ page, request }) => {
    // What a phone would do: find the calendars, then store an event.
    expect((await request.fetch('/dav/', { method: 'PROPFIND' })).status()).toBe(401);
    const home = await request.fetch(HOME, { method: 'PROPFIND', headers: { Authorization: BASIC, Depth: '1' } });
    expect(home.status()).toBe(207);
    expect(await home.text()).toContain(`${HOME}personal/`);
    const ics = `BEGIN:VCALENDAR\r\nVERSION:2.0\r\nPRODID:-//E2E//EN\r\nBEGIN:VEVENT\r\nUID:phone-1@e2e\r\nDTSTAMP:20260101T000000Z\r\nDTSTART;VALUE=DATE:${todayCompact}\r\nSUMMARY:From the phone\r\nEND:VEVENT\r\nEND:VCALENDAR\r\n`;
    const stored = await request.fetch(`${HOME}personal/phone-1.ics`, { method: 'PUT', headers: { Authorization: BASIC, 'Content-Type': 'text/calendar' }, data: ics });
    expect(stored.status()).toBe(201);

    await openCalendar(page);
    await expect(chips(page, 'From the phone')).toHaveCount(1);

    // A second calendar made in the browser, and an event moved into it.
    await page.getByRole('navigation', { name: 'Calendars' }).getByText('New calendar').click();
    const dialog = page.getByRole('dialog', { name: 'New calendar' });
    await dialog.getByLabel('Name').fill('Work');
    await dialog.getByRole('radio', { name: 'Colour #d93025' }).click();
    await dialog.getByRole('button', { name: 'Save' }).click();
    await expect(page.getByRole('navigation', { name: 'Calendars' })).toContainText('Work');
    await chips(page, 'From the phone').click();
    await page.getByRole('dialog').getByRole('button', { name: 'Edit' }).click();
    const editor = page.getByRole('dialog', { name: 'Edit event' });
    await expect(editor.getByLabel('All day')).toBeChecked();
    await editor.getByLabel('Calendar', { exact: true }).click();
    await page.getByRole('option', { name: 'Work' }).click();
    await editor.getByRole('button', { name: 'Save' }).click();
    await expect(page.getByText('Event saved')).toBeVisible();

    // The phone finds it in the new calendar, with the identity it gave the event.
    const moved = await request.fetch(`${HOME}work/phone-1.ics`, { headers: { Authorization: BASIC } });
    expect(moved.status()).toBe(200);
    expect(await moved.text()).toContain('UID:phone-1@e2e');
    expect((await request.fetch(`${HOME}personal/phone-1.ics`, { headers: { Authorization: BASIC } })).status()).toBe(404);

    // Hiding a calendar hides its events; the choice survives a reload.
    await page.getByLabel('Show Work').uncheck();
    await expect(chips(page, 'From the phone')).toHaveCount(0);
    await page.reload();
    await expect(page.getByLabel('Show Work')).not.toBeChecked();
    await expect(chips(page, 'From the phone')).toHaveCount(0);
    await page.getByLabel('Show Work').check();
    await expect(chips(page, 'From the phone')).toHaveCount(1);

    // The addresses a calendar program needs.
    await page.getByText('Sync with other apps').click();
    const connect = page.getByRole('dialog', { name: 'Use these calendars in another app' });
    await expect(connect.getByRole('textbox', { name: 'Server address' })).toHaveValue(/\/dav\/$/);
    await expect(connect.getByRole('textbox', { name: 'User name' })).toHaveValue(DAVE);
    await expect(connect.getByRole('textbox', { name: 'Work', exact: true })).toHaveValue(new RegExp(`/dav/calendars/${DAVE}/work/$`));
    await connect.getByRole('button', { name: 'Close' }).click();

    // Deleting the calendar removes it for the phone too.
    page.on('dialog', (prompt) => void prompt.accept());
    await page.getByRole('button', { name: 'Options for Work' }).click();
    await page.getByRole('menuitem', { name: 'Delete' }).click();
    await expect(page.getByText('Calendar deleted')).toBeVisible();
    expect((await request.fetch(`${HOME}work/`, { method: 'PROPFIND', headers: { Authorization: BASIC, Depth: '0' } })).status()).toBe(404);
  });

  test('an invitation attached to a message can be added to the calendar', async ({ page }) => {
    const ics = `BEGIN:VCALENDAR\nVERSION:2.0\nPRODID:-//E2E//EN\nMETHOD:REQUEST\nBEGIN:VEVENT\nUID:invite-1@e2e\nDTSTAMP:20260101T000000Z\nDTSTART;VALUE=DATE:${todayCompact}\nSUMMARY:Release party\nEND:VEVENT\nEND:VCALENDAR\n`;
    const message = [
      'From: Ann <ann@remote.test>', `To: ${DAVE}`, 'Subject: You are invited', 'MIME-Version: 1.0', 'Content-Type: multipart/mixed; boundary="b1"', '',
      '--b1', 'Content-Type: text/plain', '', 'Please come.', '--b1', 'Content-Type: text/calendar; name="invite.ics"', 'Content-Disposition: attachment; filename="invite.ics"', '', ics, '--b1--', '',
    ].join('\n');
    await smtpDeliver('ann@remote.test', DAVE, message);
    await login(page, DAVE, USER_PASSWORD);
    await page.getByTestId('email-row').filter({ hasText: 'You are invited' }).click();
    await page.getByRole('button', { name: 'Add invite.ics to calendar' }).click();
    await expect(page.getByRole('status').filter({ hasText: 'Added to Personal' })).toBeVisible();

    await page.getByRole('button', { name: 'Account menu' }).click();
    await page.getByRole('menuitem', { name: 'Calendar' }).click();
    await expect(chips(page, 'Release party')).toHaveCount(1);
  });
});
