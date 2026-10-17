import { expect, test, type Page } from '@playwright/test';
import { DOMAIN, login, smtpDeliver, USER_PASSWORD } from './helpers';

// A mailbox of its own, so the counts in these tests do not depend on the other specs.
const CAROL = `carol@${DOMAIN}`;
const ADMIN_EMAIL = 'admin@e2e.test';
const ADMIN_PASSWORD = 'e2e-admin-password-1';

const rows = (page: Page) => page.getByTestId('email-row');
const row = (page: Page, text: string) => rows(page).filter({ hasText: text });
const conversation = (page: Page) => page.getByRole('region', { name: 'Conversation' });
const mail = (from: string, subject: string, headers = '') => `From: ${from}\nTo: ${CAROL}\nSubject: ${subject}\n${headers}\nBody of ${subject}\n`;

async function openSettings(page: Page, tab?: string) {
  await page.getByRole('button', { name: 'Account menu' }).click();
  await page.getByRole('menuitem', { name: 'Settings' }).click();
  await expect(page.getByRole('heading', { name: 'Settings', level: 1 })).toBeVisible();
  if (tab) await page.getByRole('tab', { name: tab }).click();
}

test.describe('inbox tools', () => {
  test.beforeAll(async ({ browser }) => {
    const page = await browser.newPage();
    await login(page, ADMIN_EMAIL, ADMIN_PASSWORD);
    await page.goto('/admin/mailboxes');
    await page.getByRole('button', { name: 'Add mailbox' }).click();
    const dialog = page.getByRole('dialog');
    await dialog.getByLabel('E-mail address').fill(CAROL);
    await dialog.getByLabel('Password', { exact: true }).fill(USER_PASSWORD);
    await dialog.getByRole('button', { name: 'Create' }).click();
    // After a failed test the worker (and this hook) starts over; the mailbox may exist already.
    await expect(page.getByText('Mailbox created').or(dialog.getByRole('alert').filter({ hasText: 'already exists' }))).toBeVisible();
    await page.close();
  });

  test('conversations are listed one per line and can be selected for bulk actions', async ({ page }) => {
    for (const subject of ['First to select', 'Second to select', 'Third stays unread']) await smtpDeliver('ann@remote.test', CAROL, mail('Ann <ann@remote.test>', subject));
    await login(page, CAROL, USER_PASSWORD);
    await expect(rows(page)).toHaveCount(3);

    // One compact line: sender, subject and the start of the text side by side.
    const first = row(page, 'First to select');
    const box = (await first.boundingBox())!;
    expect(box.height).toBeLessThan(52);
    const [sender, subject, preview] = await Promise.all([first.getByText('Ann', { exact: true }).boundingBox(), first.getByText('First to select', { exact: true }).boundingBox(), first.getByText(/Body of First to select/).boundingBox()]);
    expect(Math.abs(sender!.y - subject!.y)).toBeLessThan(6);
    expect(Math.abs(subject!.y - preview!.y)).toBeLessThan(6);
    expect(sender!.x).toBeLessThan(subject!.x);

    // Select two, mark them as read.
    await page.getByLabel('Select First to select').check();
    await page.getByLabel('Select Second to select').check();
    const toolbar = page.getByRole('toolbar', { name: 'Actions for the selection' });
    await expect(toolbar).toContainText('2 selected');
    await expect(page.getByLabel('Select all conversations')).toHaveAttribute('data-indeterminate', 'true');
    await toolbar.getByRole('button', { name: 'Mark selected as read' }).click();
    await expect(page.getByText('2 conversations marked as read')).toBeVisible();
    await expect(row(page, 'First to select')).toHaveAttribute('data-unread', 'false');
    await expect(row(page, 'Third stays unread')).toHaveAttribute('data-unread', 'true');
    await expect(toolbar).toHaveCount(0);

    // Label through the selection toolbar, with a coloured label created in the sidebar.
    await page.getByRole('navigation', { name: 'Folders' }).getByText('New label').click();
    const dialog = page.getByRole('dialog');
    await dialog.getByLabel('Label name').fill('Important Clients');
    await dialog.getByRole('radio', { name: 'Colour #d93025' }).click();
    await dialog.getByRole('button', { name: 'Save label' }).click();
    await expect(page.getByText('Label “important-clients” created')).toBeVisible();
    await expect(page.getByRole('list', { name: 'Labels' }).getByText('important-clients')).toBeVisible();
    await page.getByLabel('Select Third stays unread').check();
    await page.getByRole('button', { name: 'Label selected' }).click();
    await page.getByRole('menuitem', { name: 'important-clients' }).click();
    const chip = row(page, 'Third stays unread').getByText('important-clients');
    await expect(chip).toBeVisible();
    await expect(chip.locator('..')).toHaveCSS('background-color', 'rgb(217, 48, 37)');
    // The colour can be changed later.
    await page.getByRole('button', { name: 'Colour of label important-clients', exact: true }).click();
    await page.getByRole('dialog').getByRole('radio', { name: 'Colour #188038' }).click();
    await page.getByRole('dialog').getByRole('button', { name: 'Save label' }).click();
    await expect(chip.locator('..')).toHaveCSS('background-color', 'rgb(24, 128, 56)');

    // Keyboard: x selects the highlighted conversation.
    await page.keyboard.press('x');
    await expect(page.getByRole('toolbar', { name: 'Actions for the selection' })).toContainText('1 selected');
    await page.keyboard.press('x');

    // Select everything and archive it.
    await page.getByLabel('Select all conversations').check();
    await expect(page.getByRole('toolbar', { name: 'Actions for the selection' })).toContainText('3 selected');
    await page.getByRole('button', { name: 'Archive selected' }).click();
    await expect(page.getByText('3 conversations archived')).toBeVisible();
    await expect(rows(page)).toHaveCount(0);
    await page.getByRole('navigation', { name: 'Folders' }).getByText('Archive', { exact: true }).click();
    await expect(rows(page)).toHaveCount(3);

    // Move two of them back with "Move to".
    await page.getByLabel('Select First to select').check();
    await page.getByLabel('Select Second to select').check();
    await page.getByRole('button', { name: 'Move selected to a folder' }).click();
    await page.getByRole('menuitem', { name: 'Inbox' }).click();
    await expect(page.getByText('2 conversations moved')).toBeVisible();
    await expect(rows(page)).toHaveCount(1);
  });

  test('the inbox is sorted into categories', async ({ page }) => {
    await smtpDeliver('news@shop.test', CAROL, mail('Shop <news@shop.test>', 'Autumn sale: 30% off', 'List-Unsubscribe: <mailto:leave@shop.test?subject=unsubscribe>\n'));
    await smtpDeliver('no-reply@bank.test', CAROL, mail('Bank <no-reply@bank.test>', 'Your statement is ready'));
    await smtpDeliver('dev@lists.test', CAROL, mail('Dev list <dev@lists.test>', '[dev] Release plan', 'List-Id: <dev.lists.test>\nList-Post: <mailto:dev@lists.test>\n'));
    await login(page, CAROL, USER_PASSWORD);
    const tabs = page.getByRole('tablist', { name: 'Inbox categories' });
    await expect(tabs.getByRole('tab')).toHaveText([/General/, /Offers/, /Communities/, /Notifications/, /Forums/]);

    // General holds personal mail only; each other tab shows its own, with an unread count.
    await expect(rows(page)).toHaveCount(2);
    await expect(row(page, 'Autumn sale')).toHaveCount(0);
    await expect(tabs.getByRole('tab', { name: /Offers/ })).toContainText('1');
    await tabs.getByRole('tab', { name: /Offers/ }).click();
    await expect(rows(page)).toHaveCount(1);
    await expect(row(page, 'Autumn sale: 30% off')).toBeVisible();
    await tabs.getByRole('tab', { name: /Notifications/ }).click();
    await expect(row(page, 'Your statement is ready')).toBeVisible();
    await tabs.getByRole('tab', { name: /Forums/ }).click();
    await expect(row(page, '[dev] Release plan')).toBeVisible();
    await tabs.getByRole('tab', { name: /Communities/ }).click();
    await expect(page.getByText('Nothing here yet.')).toBeVisible();

    // A wrongly sorted message is moved by its menu, or by dropping it on a tab.
    await tabs.getByRole('tab', { name: /Notifications/ }).click();
    await row(page, 'Your statement is ready').click();
    await conversation(page).getByRole('button', { name: 'More actions' }).click();
    await page.getByRole('menuitem', { name: 'General', exact: true }).click();
    await expect(page.getByText('Moved to General.')).toBeVisible();
    await page.getByRole('button', { name: 'Back to list' }).click();
    await expect(page.getByText('Nothing here yet.')).toBeVisible();
    await tabs.getByRole('tab', { name: /General/ }).click();
    await expect(row(page, 'Your statement is ready')).toBeVisible();
    await row(page, 'Your statement is ready').dragTo(tabs.getByRole('tab', { name: /Notifications/ }));
    await expect(page.getByText('Moved to Notifications')).toBeVisible();
    await expect(row(page, 'Your statement is ready')).toHaveCount(0);

    // Categories can be switched off: one undivided inbox.
    await openSettings(page, 'Inbox');
    await page.getByLabel(/Sort the inbox into categories/).uncheck();
    await page.goto('/mail');
    await expect(page.getByRole('tablist', { name: 'Inbox categories' })).toHaveCount(0);
    await expect(rows(page)).toHaveCount(5);
    await openSettings(page, 'Inbox');
    await page.getByLabel(/Sort the inbox into categories/).check();
  });

  test('unsubscribe, show original and block sender', async ({ page }) => {
    await smtpDeliver('pest@pushy.test', CAROL, mail('Pushy Sales <pest@pushy.test>', 'You will love this', 'X-Trace: original-header-marker\n'));
    await login(page, CAROL, USER_PASSWORD);

    // Unsubscribe: the newsletter offers a mail address, so a request is sent on Carol's behalf.
    await page.getByRole('tab', { name: /Offers/ }).click();
    await row(page, 'Autumn sale: 30% off').click();
    page.once('dialog', (dialog) => {
      expect(dialog.message()).toBe('Unsubscribe from Shop?');
      void dialog.accept();
    });
    await conversation(page).getByRole('button', { name: 'Unsubscribe' }).click();
    await expect(page.getByText('An unsubscribe request was sent to leave@shop.test.')).toBeVisible();
    await page.getByRole('button', { name: 'Back to list' }).click();

    // Personal mail has no unsubscribe button.
    await page.getByRole('tab', { name: /General/ }).click();
    await row(page, 'You will love this').click();
    await expect(conversation(page).getByRole('button', { name: 'Unsubscribe' })).toHaveCount(0);

    // Show original: the message exactly as it arrived, as text.
    await conversation(page).getByRole('button', { name: 'More actions' }).click();
    await page.getByRole('menuitem', { name: 'Show original' }).click();
    const original = page.getByRole('dialog', { name: 'Original message' });
    await expect(original.getByRole('table', { name: 'Message summary' })).toContainText('You will love this');
    await expect(original.getByTestId('original-source')).toContainText('X-Trace: original-header-marker');
    await expect(original.getByTestId('original-source')).toContainText('Received: from sender.remote.test');
    await expect(original.getByRole('link', { name: 'Download' })).toHaveAttribute('download', /\.eml$/);
    await original.getByRole('button', { name: 'Close' }).click();

    // Block the sender: later mail from them goes to Junk, silently.
    await conversation(page).getByRole('button', { name: 'More actions' }).click();
    await page.getByRole('menuitem', { name: 'Block pest@pushy.test' }).click();
    await expect(page.getByText('pest@pushy.test is blocked. New mail from this sender goes to Junk.')).toBeVisible();
    await smtpDeliver('pest@pushy.test', CAROL, mail('Pushy Sales <pest@pushy.test>', 'Did you see my last mail?'));
    await smtpDeliver('ann@remote.test', CAROL, mail('Ann <ann@remote.test>', 'Not blocked'));
    await page.getByRole('button', { name: 'Back to list' }).click();
    await expect(row(page, 'Not blocked')).toBeVisible();
    await expect(row(page, 'Did you see my last mail?')).toHaveCount(0);
    await page.getByRole('navigation', { name: 'Folders' }).getByText('Junk', { exact: true }).click();
    await expect(row(page, 'Did you see my last mail?')).toBeVisible();

    // The menu now offers to unblock; the list is managed in Settings too.
    await row(page, 'Did you see my last mail?').click();
    await conversation(page).getByRole('button', { name: 'More actions' }).click();
    await expect(page.getByRole('menuitem', { name: 'Unblock pest@pushy.test' })).toBeVisible();
    await page.keyboard.press('Escape');
    await openSettings(page, 'Inbox');
    const blocked = page.getByRole('list', { name: 'Blocked senders' });
    await expect(blocked.getByText('pest@pushy.test')).toBeVisible();
    await page.getByLabel('Sender to block').fill('@Spam-Domain.test');
    await page.getByRole('button', { name: 'Block', exact: true }).click();
    await expect(blocked.getByText('@spam-domain.test')).toBeVisible();
    await page.getByLabel('Sender to block').fill('not an address');
    await page.getByRole('button', { name: 'Block', exact: true }).click();
    await expect(page.getByRole('alert').filter({ hasText: 'enter an e-mail address' })).toBeVisible();
    await blocked.getByRole('listitem').filter({ hasText: 'pest@pushy.test' }).getByTestId('CancelIcon').click();
    await expect(blocked.getByText('pest@pushy.test')).toHaveCount(0);
    await smtpDeliver('pest@pushy.test', CAROL, mail('Pushy Sales <pest@pushy.test>', 'Welcome back'));
    await page.goto('/mail');
    await expect(row(page, 'Welcome back')).toBeVisible();
  });

  test('accent colours stay readable on the dark theme', async ({ page }) => {
    await login(page, CAROL, USER_PASSWORD);
    // Light and dark are in the account menu; the accent colour in the settings.
    await page.getByRole('button', { name: 'Account menu' }).click();
    await expect(page.getByRole('button', { name: /^Accent colour / })).toHaveCount(0);
    await page.getByRole('button', { name: 'Dark' }).click();
    await page.keyboard.press('Escape');
    await page.goto('/settings?tab=general');
    await expect(page.getByRole('button', { name: /^Accent colour / })).toHaveCount(9);
    const luminance = (color: string) => {
      const [r, g, b] = (color.match(/[\d.]+/g) ?? []).slice(0, 3).map((v) => Number(v) / 255).map((c) => (c <= 0.03928 ? c / 12.92 : ((c + 0.055) / 1.055) ** 2.4));
      return 0.2126 * r + 0.7152 * g + 0.0722 * b;
    };
    for (const accent of ['#6750a4', '#455a64', '#b25e00']) {
      await page.getByRole('button', { name: `Accent colour ${accent}` }).click();
      // The brand colour as used for text (the page title) against the page background.
      const title = page.locator('header').getByText('unoMail', { exact: true });
      const [text, background] = await Promise.all([title.evaluate((el) => getComputedStyle(el).color), page.locator('body').evaluate((el) => getComputedStyle(el).backgroundColor)]);
      const [light, dark] = [luminance(text), luminance(background)].sort((a, b) => b - a);
      expect((light + 0.05) / (dark + 0.05), `${accent} on dark`).toBeGreaterThan(4.5);
    }
    await page.getByRole('button', { name: 'Accent colour #6750a4' }).click();
    // Skins with colours of their own offer no accent colour.
    await page.getByRole('radio', { name: /Midnight/ }).click();
    await expect(page.getByRole('button', { name: /^Accent colour / })).toHaveCount(0);
    await page.getByRole('radio', { name: /Material You/ }).click();
    await page.getByRole('button', { name: 'Account menu' }).click();
    await page.getByRole('button', { name: 'System' }).click();
  });
});
