import { expect, test } from '@playwright/test';
import { ADMIN, DOMAIN, login, openAdmin, smtpDeliver, USER_PASSWORD } from './helpers';

const BOB = `bob@${DOMAIN}`;

test.describe('operations', () => {
  test('the composer can be used full screen', async ({ page }) => {
    await login(page, BOB, USER_PASSWORD);
    await page.getByRole('button', { name: 'Compose' }).click();
    const composer = page.getByRole('dialog', { name: 'New message' });
    const viewport = page.viewportSize()!;
    const small = (await composer.boundingBox())!;
    expect(small.width).toBeLessThan(viewport.width);

    await composer.getByRole('button', { name: 'Full screen', exact: true }).click();
    await expect(composer).toHaveAttribute('data-fullscreen', 'true');
    const full = (await composer.boundingBox())!;
    expect([Math.round(full.x), Math.round(full.y), Math.round(full.width), Math.round(full.height)]).toEqual([0, 0, viewport.width, viewport.height]);
    // What was typed survives switching back and forth.
    await composer.getByLabel('Subject').fill('Written with room to think');
    await composer.getByRole('textbox', { name: 'Message body' }).click();
    await page.keyboard.type('A long message.');
    await page.keyboard.press('Escape');
    await expect(composer).toHaveAttribute('data-fullscreen', 'false');
    await expect(composer.getByLabel('Subject')).toHaveValue('Written with room to think');
    await expect(composer.getByRole('textbox', { name: 'Message body' })).toContainText('A long message.');
    await composer.getByRole('button', { name: 'Full screen', exact: true }).click();
    await composer.getByRole('button', { name: 'Exit full screen' }).click();
    await expect(composer).toHaveAttribute('data-fullscreen', 'false');
    await composer.getByRole('button', { name: 'Discard draft' }).click();
  });

  test('dashboard shows remote addresses and the last SMTP replies', async ({ page }) => {
    await smtpDeliver('ann@remote.test', BOB, `From: ann@remote.test\nTo: ${BOB}\nSubject: For the dashboard\n\nx\n`);
    await smtpDeliver('ann@remote.test', `nobody@${DOMAIN}`, 'Subject: x\n\nx\n').catch(() => {});
    await login(page, ADMIN.email, ADMIN.password);
    await openAdmin(page, 'Dashboard');

    const ips = page.getByRole('table', { name: 'Remote IPs' });
    await expect(ips.getByRole('row', { name: /127\.0\.0\.1/ })).toBeVisible();
    await expect(ips.getByLabel('Country unknown').first()).toBeVisible();

    const replies = page.getByRole('table', { name: 'Last messages' });
    await expect(replies.getByRole('row', { name: /User unknown/ }).first()).toContainText('550');
    await expect(replies.getByRole('row', { name: /closing connection\. Have a jolly good day\./ }).first()).toContainText('221');
    await expect(replies.getByRole('row', { name: /Ok: queued as/ }).first()).toContainText('250');

    // Domain names in the domain table use the theme's link colour, in light and dark mode.
    await openAdmin(page, 'Domains');
    const link = page.getByRole('table', { name: 'Domains' }).getByRole('link', { name: DOMAIN });
    await expect(link).not.toHaveCSS('color', 'rgb(0, 0, 238)');
    const light = await link.evaluate((el) => getComputedStyle(el).color);
    await page.getByRole('button', { name: 'Account menu' }).click();
    await page.getByRole('button', { name: 'Dark' }).click();
    await page.keyboard.press('Escape');
    await expect(link).not.toHaveCSS('color', light);
    await expect(link).not.toHaveCSS('color', 'rgb(0, 0, 238)');
    await page.getByRole('button', { name: 'Account menu' }).click();
    await page.getByRole('button', { name: 'System' }).click();
    await page.keyboard.press('Escape');
  });

  test('SMTP blacklist, whitelist and karma records', async ({ page }) => {
    await login(page, ADMIN.email, ADMIN.password);
    await openAdmin(page, 'SMTP blacklist');
    await expect(page.getByText('No rules yet.')).toBeVisible();

    // Add, validate, edit.
    await page.getByRole('button', { name: 'Add rule' }).click();
    let dialog = page.getByRole('dialog');
    await dialog.getByLabel('IP address or network').fill('not-an-address');
    await dialog.getByRole('button', { name: 'Save rule' }).click();
    await expect(dialog.getByLabel('IP address or network')).toHaveAccessibleDescription(/enter an IP address or a network/i);
    await dialog.getByLabel('IP address or network').fill('203.0.113.77/24');
    await dialog.getByLabel('Description (optional)').fill('Partner network');
    await dialog.getByLabel('List').click();
    await page.getByRole('option', { name: /Whitelist/ }).click();
    await dialog.getByRole('button', { name: 'Save rule' }).click();
    const rules = page.getByRole('table', { name: 'User defined rules' });
    const partner = rules.getByRole('row', { name: /203\.0\.113\.0\/24/ });
    await expect(partner).toContainText('Whitelist');
    await expect(partner).toContainText('Partner network');
    await expect(partner).toContainText('Never');
    await page.getByRole('button', { name: 'Edit rule 203.0.113.0/24' }).click();
    dialog = page.getByRole('dialog');
    await dialog.getByLabel('Priority').fill('50');
    await dialog.getByRole('button', { name: 'Save rule' }).click();
    await expect(partner.getByRole('cell', { name: '50', exact: true })).toBeVisible();

    // Blacklisting the address the test mail comes from stops it at the door, at once.
    await page.getByRole('button', { name: 'Add rule' }).click();
    dialog = page.getByRole('dialog');
    await dialog.getByLabel('IP address or network').fill('127.0.0.1');
    await dialog.getByLabel('Description (optional)').fill('Blocked for the test');
    await dialog.getByRole('button', { name: 'Save rule' }).click();
    await expect(rules.getByRole('row', { name: /127\.0\.0\.1/ })).toContainText('Blacklist');
    await expect(smtpDeliver('ann@remote.test', BOB, 'Subject: blocked\n\nx\n')).rejects.toThrow(/554 5\.7\.1 .*is blocked/);
    await page.reload();
    await expect(rules.getByRole('row', { name: /127\.0\.0\.1/ }).getByRole('cell', { name: '1', exact: true })).toBeVisible();
    await page.getByRole('button', { name: 'Delete rule 127.0.0.1' }).click();
    await expect(page.getByText('Rule deleted')).toBeVisible();
    await smtpDeliver('ann@remote.test', BOB, `From: ann@remote.test\nTo: ${BOB}\nSubject: Allowed again\n\nx\n`);
    await page.getByRole('button', { name: 'Delete rule 203.0.113.0/24' }).click();
    await expect(page.getByText('No rules yet.')).toBeVisible();

    await page.getByRole('tab', { name: 'Automatically generated' }).click();
    await expect(page.getByText('Nothing has been blocked automatically.')).toBeVisible();

    // Karma: the test sender has a record; it can be turned into a rule or forgotten.
    await page.getByRole('tab', { name: 'Karma records' }).click();
    const karma = page.getByRole('table', { name: 'Karma records' });
    const record = karma.getByRole('row', { name: /127\.0\.0\.1/ });
    await expect(record).toContainText('message accepted');
    await page.getByRole('button', { name: 'Whitelist 127.0.0.1' }).click();
    await expect(page.getByText('Address whitelisted')).toBeVisible();
    await page.getByRole('tab', { name: 'User defined' }).click();
    await expect(rules.getByRole('row', { name: /127\.0\.0\.1/ })).toContainText('From karma record');
    await page.getByRole('button', { name: 'Delete rule 127.0.0.1' }).click();
    await expect(page.getByText('No rules yet.')).toBeVisible();
    await page.getByRole('tab', { name: 'Karma records' }).click();
    await page.getByRole('button', { name: 'Forget 127.0.0.1' }).click();
    await expect(page.getByText('No remote server has been scored yet.')).toBeVisible();
  });

  test('the spam filter page explains when no filter is connected', async ({ page }) => {
    await login(page, ADMIN.email, ADMIN.password);
    await openAdmin(page, 'Spam filter');
    await expect(page.getByText('No spam filter is connected to this server.')).toBeVisible();
    await expect(page.getByRole('button', { name: 'Save thresholds' })).toHaveCount(0);
  });
});

/** A minimal one-page PDF with correct cross-reference offsets. */
function tinyPdf(text: string): Buffer {
  const stream = `BT /F1 24 Tf 40 100 Td (${text}) Tj ET`;
  const objects = [
    '<< /Type /Catalog /Pages 2 0 R >>',
    '<< /Type /Pages /Kids [3 0 R] /Count 1 >>',
    '<< /Type /Page /Parent 2 0 R /MediaBox [0 0 300 200] /Contents 4 0 R /Resources << /Font << /F1 5 0 R >> >> >>',
    `<< /Length ${stream.length} >>\nstream\n${stream}\nendstream`,
    '<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica >>',
  ];
  let body = '%PDF-1.4\n';
  const offsets: number[] = [];
  objects.forEach((object, index) => {
    offsets.push(body.length);
    body += `${index + 1} 0 obj\n${object}\nendobj\n`;
  });
  const xref = body.length;
  body += `xref\n0 ${objects.length + 1}\n0000000000 65535 f \n${offsets.map((offset) => `${String(offset).padStart(10, '0')} 00000 n \n`).join('')}`;
  body += `trailer\n<< /Size ${objects.length + 1} /Root 1 0 R >>\nstartxref\n${xref}\n%%EOF\n`;
  return Buffer.from(body, 'latin1');
}

test.describe('previews and capacity', () => {
  test('text and PDF attachments are previewed in the browser', async ({ page }) => {
    const boundary = 'preview-boundary';
    const part = (name: string, type: string, data: Buffer) => `--${boundary}\nContent-Type: ${type}; name="${name}"\nContent-Disposition: attachment; filename="${name}"\nContent-Transfer-Encoding: base64\n\n${data.toString('base64').replace(/.{76}/g, '$&\n')}\n`;
    const message =
      `From: ann@remote.test\nTo: ${BOB}\nSubject: Files to look at\nMIME-Version: 1.0\nContent-Type: multipart/mixed; boundary="${boundary}"\n\n` +
      `--${boundary}\nContent-Type: text/plain\n\nSee attached.\n` +
      part('notes.txt', 'text/plain', Buffer.from('First line\nZażółć gęślą jaźń\n<script>alert(1)</script>\n')) +
      part('page.html', 'application/octet-stream', Buffer.from('<h1 id="evil">Rendered?</h1><img src=x onerror="document.title=\'pwned\'">')) +
      part('report.pdf', 'application/pdf', tinyPdf('Quarterly report')) +
      part('archive.zip', 'application/zip', Buffer.from('PK\u0003\u0004not really')) +
      `--${boundary}--\n`;
    await smtpDeliver('ann@remote.test', BOB, message);
    await login(page, BOB, USER_PASSWORD);
    await page.getByTestId('email-row').filter({ hasText: 'Files to look at' }).click();
    const conversation = page.getByRole('region', { name: 'Conversation' });

    // Every attachment is still a download; only the kinds a browser can show get a preview.
    await expect(conversation.getByRole('link', { name: /archive\.zip/ })).toBeVisible();
    await expect(conversation.getByRole('button', { name: 'Preview archive.zip' })).toHaveCount(0);

    await conversation.getByRole('button', { name: 'Preview notes.txt' }).click();
    let dialog = page.getByRole('dialog', { name: /^notes\.txt/ });
    await expect(dialog.getByTestId('text-preview')).toHaveText('First line\nZażółć gęślą jaźń\n<script>alert(1)</script>\n');
    await expect(dialog.getByRole('link', { name: 'Download' })).toHaveAttribute('download', 'notes.txt');
    await dialog.getByRole('button', { name: 'Close' }).click();

    // HTML is shown as its source, never rendered or executed.
    await conversation.getByRole('button', { name: 'Preview page.html' }).click();
    dialog = page.getByRole('dialog', { name: /^page\.html/ });
    await expect(dialog.getByTestId('text-preview')).toContainText('<h1 id="evil">Rendered?</h1>');
    await expect(page.locator('#evil')).toHaveCount(0);
    expect(await page.title()).not.toBe('pwned');
    await dialog.getByRole('button', { name: 'Close' }).click();

    await conversation.getByRole('button', { name: 'Preview report.pdf' }).click();
    dialog = page.getByRole('dialog', { name: /^report\.pdf/ });
    await expect(dialog.getByTestId('pdf-pages')).toHaveAttribute('data-pages-rendered', '1', { timeout: 30_000 });
    const canvas = dialog.getByRole('img', { name: 'Page 1' });
    await expect(canvas).toBeVisible();
    // The page was really drawn: it is not a blank canvas.
    const inked = await canvas.evaluate((element) => {
      const canvas = element as HTMLCanvasElement;
      const pixels = canvas.getContext('2d')!.getImageData(0, 0, canvas.width, canvas.height).data;
      let dark = 0;
      for (let i = 0; i < pixels.length; i += 4) if (pixels[i] < 128 && pixels[i + 3] > 0) dark += 1;
      return dark;
    });
    expect(inked).toBeGreaterThan(50);
    await dialog.getByRole('button', { name: 'Close' }).click();
  });

  test('the dashboard charts free disk space and memory', async ({ page }) => {
    await login(page, ADMIN.email, ADMIN.password);
    await openAdmin(page, 'Dashboard');
    await expect(page.getByRole('heading', { name: 'Capacity' })).toBeVisible();
    await expect(page.getByTestId('chart-headline-Free disk space')).toHaveText(/^[\d.]+ (B|KB|MB|GB|TB) free$/);
    await expect(page.getByTestId('chart-headline-Memory in use')).toHaveText(/^[\d.]+ (MB|GB|TB) used$/);
    await expect(page.getByText(/of [\d.]+ (GB|TB) on the data volume/)).toBeVisible();
    await expect(page.getByText(/^\d+% of [\d.]+ (MB|GB|TB)$/)).toBeVisible();

    // Memory is split by service, each named in the legend.
    const capacity = page.getByTestId('capacity');
    const legend = capacity.getByRole('list', { name: 'Legend' });
    for (const name of ['unoMail', 'Rspamd', 'ClamAV', 'Redis', 'Other']) {
      await expect(legend.getByText(name, { exact: true })).toBeVisible();
    }

    // The same numbers are available as a table, and the period can be changed.
    await capacity.getByRole('button', { name: 'Show as a table' }).first().click();
    const table = page.getByRole('table', { name: 'Free disk space, data' });
    await expect(table.getByRole('row').nth(1)).toContainText(/(B|KB|MB|GB|TB)$/);
    await capacity.getByRole('button', { name: '7 days' }).click();
    await expect(capacity.getByRole('button', { name: '7 days' })).toHaveAttribute('aria-pressed', 'true');
    await expect(page.getByTestId('chart-headline-Free disk space')).toBeVisible();
  });

  test('the dashboard shows connections and mail per day', async ({ page }) => {
    await login(page, ADMIN.email, ADMIN.password);
    await openAdmin(page, 'Dashboard');
    const daily = page.getByTestId('daily-stats');
    await expect(daily.getByRole('heading', { name: 'Daily stats' })).toBeVisible();
    // Earlier specs connected over SMTP and delivered mail today.
    const legend = daily.getByRole('list', { name: 'Series' });
    for (const name of ['Valid connections', 'Invalid connections', 'Delivered emails', 'Bounced emails', 'Quarantined emails', 'Discarded']) {
      await expect(legend.getByRole('button', { name: new RegExp(`^${name}`) })).toHaveAttribute('aria-pressed', 'true');
    }
    await expect(legend.getByRole('button', { name: /^Valid connections [1-9]/ })).toBeVisible();
    await expect(legend.getByText(/^\d[\d,]* – blocked$/)).toBeVisible();
    await expect(legend.getByText(/^\d[\d,]* – local$/)).toBeVisible();

    // A line can be hidden, the period changed, and the numbers read as a table.
    await legend.getByRole('button', { name: /^Discarded/ }).click();
    await expect(legend.getByRole('button', { name: /^Discarded/ })).toHaveAttribute('aria-pressed', 'false');
    await daily.getByRole('button', { name: '7 days' }).click();
    await daily.getByRole('button', { name: 'Show as a table' }).click();
    const table = daily.getByRole('table', { name: 'Daily stats, data' });
    await expect(table.getByRole('row')).toHaveCount(8);
    await expect(table.getByRole('columnheader', { name: 'remote' })).toBeVisible();
  });
});
