import { expect, test, type Page } from '@playwright/test';
import { DOMAIN, login, logout, smtpDeliver, USER_PASSWORD } from './helpers';

const ALICE = `alice@${DOMAIN}`;
const BOB = `bob@${DOMAIN}`;

async function openSettings(page: Page, tab?: string) {
  await page.getByRole('button', { name: 'Account menu' }).click();
  await page.getByRole('menuitem', { name: 'Settings' }).click();
  await expect(page.getByRole('heading', { name: 'Settings', level: 1 })).toBeVisible();
  if (tab) await page.getByRole('navigation', { name: 'Settings sections' }).getByRole('button', { name: tab }).click();
}

test.describe('offline changes, label management and filter scripts', () => {
  test('changes and messages made offline are synchronised on reconnect', async ({ page, context }) => {
    await smtpDeliver('note@remote.test', BOB, `From: note@remote.test\nTo: ${BOB}\nSubject: Offline candidate\n\nstar me later\n`);
    await login(page, BOB, USER_PASSWORD);
    const row = page.getByTestId('email-row').filter({ hasText: 'Offline candidate' });
    await expect(row).toBeVisible();

    await context.setOffline(true);
    await row.getByRole('button', { name: 'Add star' }).click();
    await expect(page.getByText('Saved on this device; it will be synchronised when you are back online')).toBeVisible();
    await expect(row.getByRole('button', { name: 'Remove star' })).toBeVisible();

    await page.getByRole('button', { name: 'Compose' }).click();
    const composer = page.getByRole('dialog', { name: 'New message' });
    await composer.getByLabel('To').fill(ALICE);
    await composer.getByLabel('Subject').fill('Written on the train');
    await composer.getByRole('textbox', { name: 'Message body' }).click();
    await page.keyboard.type('No signal here.');
    // Files can be attached without a connection too; they travel with the queued message.
    await composer.getByLabel('Attachment files').setInputFiles({ name: 'notes.txt', mimeType: 'text/plain', buffer: Buffer.from('attached while offline') });
    await expect(composer.getByText(/notes\.txt/)).toBeVisible();
    // Large files too: they wait in IndexedDB rather than in the queued message itself.
    const scan = Buffer.alloc(3 * 1024 * 1024, 7);
    await composer.getByLabel('Attachment files').setInputFiles({ name: 'scan.bin', mimeType: 'application/octet-stream', buffer: scan });
    await expect(composer.getByText(/scan\.bin/)).toBeVisible();
    await composer.getByRole('button', { name: 'Send' }).click();
    await expect(page.getByText('You are offline. The message will be sent when the connection returns')).toBeVisible();
    await expect(page.getByText('2 changes waiting to be synchronised.')).toBeVisible();

    // The queue survives a closed tab: it lives in the browser's storage.
    const stored = await page.evaluate(() => Object.keys(localStorage).filter((k) => k.includes('outbox')).length);
    expect(stored).toBe(1);

    // Reconnecting is enough: the browser's "online" event starts the synchronisation.
    // Signing out now would discard the queue, so the user is asked first.
    page.once('dialog', (dialog) => {
      expect(dialog.message()).toContain('2 changes made offline have not been synchronised yet');
      void dialog.dismiss();
    });
    await page.getByRole('button', { name: 'Account menu' }).click();
    await page.getByRole('menuitem', { name: 'Sign out' }).click();
    await expect(page.getByRole('navigation', { name: 'Folders' })).toBeVisible();

    await context.setOffline(false);
    await expect(page.getByText('2 offline changes synchronised')).toBeVisible();
    await expect(page.getByText('You are offline.')).toBeHidden();
    await page.reload();
    await expect(page.getByTestId('email-row').filter({ hasText: 'Offline candidate' }).getByRole('button', { name: 'Remove star' })).toBeVisible();
    await logout(page);

    await login(page, ALICE, USER_PASSWORD);
    const delivered = page.getByTestId('email-row').filter({ hasText: 'Written on the train' });
    await expect(delivered).toHaveCount(1);
    await delivered.click();
    await expect(page.getByRole('region', { name: 'Conversation' }).frameLocator('iframe[title="Message body"]').getByText('No signal here.')).toBeVisible();
    const attachment = page.getByRole('region', { name: 'Conversation' }).getByRole('link', { name: /notes\.txt/ });
    await expect(attachment).toBeVisible();
    const file = await page.request.get((await attachment.getAttribute('href'))!);
    expect(await file.text()).toBe('attached while offline');
    const large = page.getByRole('region', { name: 'Conversation' }).getByRole('link', { name: /scan\.bin/ });
    const received = await (await page.request.get((await large.getAttribute('href'))!)).body();
    expect(received.length).toBe(3 * 1024 * 1024);
    expect(received.every((byte) => byte === 7)).toBe(true);
    // Nothing is left behind in the browser once the message has gone out.
    const leftovers = await page.evaluate(
      () =>
        new Promise<number>((resolve) => {
          const open = indexedDB.open('unomail-offline');
          open.onsuccess = () => {
            const db = open.result;
            if (!db.objectStoreNames.contains('attachments')) return resolve(0);
            const count = db.transaction('attachments').objectStore('attachments').count();
            count.onsuccess = () => resolve(count.result);
          };
          open.onerror = () => resolve(-1);
        }),
    );
    expect(leftovers).toBe(0);
  });

  test('labels can be renamed and deleted', async ({ page }) => {
    await login(page, BOB, USER_PASSWORD);
    await page.getByTestId('email-row').filter({ hasText: 'Offline candidate' }).click();
    const reader = page.getByRole('region', { name: 'Conversation' });
    await reader.getByRole('button', { name: 'Labels' }).click();
    await page.getByLabel('New label').fill('todo');
    await page.keyboard.press('Enter');
    await expect(reader.getByText('todo')).toBeVisible();
    const labels = page.getByRole('list', { name: 'Labels' });
    await expect(labels.getByText('todo', { exact: true })).toBeVisible();

    page.once('dialog', (dialog) => void dialog.accept('Follow Up'));
    await page.getByRole('button', { name: 'Rename label todo', exact: true }).click();
    await expect(labels.getByText('follow-up', { exact: true })).toBeVisible();
    await expect(labels.getByText('todo', { exact: true })).toHaveCount(0);
    await labels.getByText('follow-up', { exact: true }).click();
    await expect(page.getByRole('heading', { name: 'Label: follow-up' })).toBeVisible();
    await expect(page.getByTestId('email-row').filter({ hasText: 'Offline candidate' })).toHaveCount(1);

    page.once('dialog', (dialog) => void dialog.accept());
    await page.getByRole('button', { name: 'Delete label follow-up', exact: true }).click();
    await expect(page.getByRole('list', { name: 'Labels' }).getByText('follow-up', { exact: true })).toHaveCount(0);
    // The message itself is still there, just without the label.
    await expect(page.getByRole('heading', { name: 'Inbox', level: 1 })).toBeVisible();
    await expect(page.getByTestId('email-row').filter({ hasText: 'Offline candidate' })).toHaveCount(1);
  });

  test('several filter scripts with include, variables and a vacation reply', async ({ page }) => {
    await login(page, BOB, USER_PASSWORD);
    await openSettings(page, 'Filters');
    const script = page.getByLabel('Sieve script');

    // A library script that names folders from the subject.
    page.once('dialog', (dialog) => void dialog.accept('projects'));
    await page.getByRole('button', { name: 'New script' }).click();
    await page.getByRole('tab', { name: 'Sieve script' }).click();
    await page.getByLabel('Filters enabled').uncheck();
    await script.fill('require ["fileinto", "mailbox", "variables", "regex"];\nif header :regex "subject" "^\\\\[([a-z]+)\\\\]" {\n  set :upperfirst "name" "${1}";\n  fileinto :create "Projects/${name}";\n  stop;\n}\n');
    await page.getByRole('button', { name: 'Save filters' }).click();
    await expect(page.getByText('Filter script saved.')).toBeVisible();

    // The main script includes it and answers everything else automatically.
    await page.getByLabel('Script', { exact: true }).click();
    await page.getByRole('option', { name: /^main/ }).click();
    await script.fill('require ["include", "vacation"];\ninclude "missing";\n');
    await page.getByLabel('Filters enabled').check();
    await page.getByRole('button', { name: 'Save filters' }).click();
    await expect(page.getByRole('alert').filter({ hasText: 'included script "missing" does not exist' })).toBeVisible();
    await script.fill('require ["include", "vacation"];\ninclude "projects";\nvacation :days 1 :subject "Filter says hello" "This reply was sent by a Sieve rule.";\n');
    await page.getByRole('button', { name: 'Save filters' }).click();
    await expect(page.getByText('Filter script saved.')).toBeVisible();
    await page.getByLabel('Script', { exact: true }).click();
    await expect(page.getByRole('option', { name: 'main (active)' })).toBeVisible();
    await expect(page.getByRole('option', { name: 'projects', exact: true })).toBeVisible();
    await page.keyboard.press('Escape');

    await smtpDeliver('pm@remote.test', BOB, `From: pm@remote.test\nTo: ${BOB}\nSubject: [apollo] Launch checklist\n\nx\n`);
    await logout(page);

    // A local sender gets the vacation reply from the rule.
    await login(page, ALICE, USER_PASSWORD);
    await page.getByRole('button', { name: 'Compose' }).click();
    const composer = page.getByRole('dialog', { name: 'New message' });
    await composer.getByLabel('To').fill(BOB);
    await composer.getByLabel('Subject').fill('Quick question');
    await composer.getByRole('textbox', { name: 'Message body' }).click();
    await page.keyboard.type('Are you there?');
    await composer.getByRole('button', { name: 'Send' }).click();
    await expect(page.getByText('Message sent')).toBeVisible();
    // Sent mail leaves after the undo window (5 seconds by default), so the answer takes a moment.
    await expect(page.getByTestId('email-row').filter({ hasText: 'Filter says hello' })).toHaveCount(1, { timeout: 20_000 });
    await logout(page);

    await login(page, BOB, USER_PASSWORD);
    await page.getByRole('navigation', { name: 'Folders' }).getByText('Projects/Apollo', { exact: true }).click();
    await expect(page.getByTestId('email-row').filter({ hasText: '[apollo] Launch checklist' })).toHaveCount(1);

    // Clean up: remove the library script and switch filtering off.
    await openSettings(page, 'Filters');
    await page.getByLabel('Filters enabled').uncheck();
    await script.fill('keep;');
    await page.getByRole('button', { name: 'Save filters' }).click();
    await expect(page.getByText('Filter script saved.')).toBeVisible();
    await page.getByLabel('Script', { exact: true }).click();
    await page.getByRole('option', { name: 'projects', exact: true }).click();
    page.once('dialog', (dialog) => void dialog.accept());
    await page.getByRole('button', { name: 'Delete script' }).click();
    await expect(page.getByText('Script "projects" deleted.')).toBeVisible();
  });
});

test.describe('global filter scripts', () => {
  test('an administrator publishes a script that users include', async ({ page }) => {
    await login(page, 'admin@e2e.test', 'e2e-admin-password-1');
    await page.goto('/admin/settings');
    await expect(page.getByRole('heading', { name: 'Global filter scripts' })).toBeVisible();
    await page.getByLabel('Global script name').fill('house-rules');
    await page.getByLabel('Global script', { exact: true }).fill('fileinto "Nope"');
    await page.getByRole('button', { name: 'Save global script' }).click();
    await expect(page.getByRole('alert').filter({ hasText: 'fileinto needs: require "fileinto";' })).toBeVisible();
    await page.getByLabel('Global script', { exact: true }).fill('require ["fileinto", "mailbox"];\nif header :contains "subject" "[bulletin]" { fileinto :create "Bulletins"; stop; }\n');
    await page.getByRole('button', { name: 'Save global script' }).click();
    await expect(page.getByText('Global script saved')).toBeVisible();
    await expect(page.getByRole('button', { name: 'house-rules' })).toBeVisible();
    await logout(page);

    await login(page, BOB, USER_PASSWORD);
    await openSettings(page, 'Filters');
    await page.getByLabel('Sieve script').fill('require "include";\ninclude :global "house-rules";\n');
    await page.getByLabel('Filters enabled').check();
    await page.getByRole('button', { name: 'Save filters' }).click();
    await expect(page.getByText('Filter script saved.')).toBeVisible();
    await smtpDeliver('office@remote.test', BOB, `From: office@remote.test\nTo: ${BOB}\nSubject: [bulletin] Fire drill\n\nx\n`);
    await page.goto('/mail');
    await page.getByRole('navigation', { name: 'Folders' }).getByText('Bulletins', { exact: true }).click();
    await expect(page.getByTestId('email-row').filter({ hasText: '[bulletin] Fire drill' })).toHaveCount(1);
  });
});
