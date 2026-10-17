import { expect, test } from '@playwright/test';
import { generate } from 'selfsigned';
import { ADMIN, login, openAdmin, PORTS, servedCertificate } from './helpers';

async function makeCertificate(commonName: string) {
  const pems = await generate([{ name: 'commonName', value: commonName }], {
    keySize: 2048,
    algorithm: 'sha256',
    extensions: [{ name: 'subjectAltName', altNames: [{ type: 2, value: commonName }] }],
  });
  return { cert: pems.cert, key: pems.private };
}

test.describe('certificate management', () => {
  test('switching between self-signed, custom and automated certificates', async ({ page }) => {
    const matching = await makeCertificate('mail.e2e.test');
    const other = await makeCertificate('other.e2e.test');
    const initial = await servedCertificate(PORTS.https);

    await login(page, ADMIN.email, ADMIN.password);
    await openAdmin(page, 'Certificates');
    const mode = page.getByTestId('tls-mode');
    await expect(mode).toHaveText('Self-signed');
    await expect(page.getByLabel('Time until expiry')).toHaveText(/^\d+d \d\d:\d\d:\d\d$/);

    // Custom certificate: a key that does not belong to the certificate is rejected.
    await page.getByRole('tab', { name: 'Custom certificate' }).click();
    await page.getByLabel('Certificate chain (PEM)').fill(matching.cert);
    await page.getByLabel('Private key (PEM)').fill(other.key);
    await page.getByRole('button', { name: 'Validate' }).click();
    await expect(page.getByRole('alert').filter({ hasText: 'private key does not match the certificate' })).toBeVisible();
    await page.getByRole('button', { name: 'Install certificate' }).click();
    await expect(page.getByRole('alert').filter({ hasText: 'private key does not match the certificate' }).first()).toBeVisible();
    await expect(mode).toHaveText('Self-signed');
    expect((await servedCertificate(PORTS.https)).fingerprint, 'a rejected upload changes nothing').toBe(initial.fingerprint);

    // A valid pair is validated (with warnings), installed, and served immediately.
    await page.getByLabel('Private key (PEM)').fill(matching.key);
    await page.getByRole('button', { name: 'Validate' }).click();
    await expect(page.getByRole('alert').filter({ hasText: 'Valid for mail.e2e.test' })).toContainText('not publicly trusted');
    await page.getByRole('button', { name: 'Install certificate' }).click();
    await expect(page.getByText('Certificate installed and active on all services')).toBeVisible();
    await expect(mode).toHaveText('Custom certificate');
    await expect(page.getByLabel('Private key (PEM)')).toHaveValue('');

    // Hot reload: HTTPS and implicit-TLS SMTP present the new certificate without a restart.
    const afterUpload = await servedCertificate(PORTS.https);
    expect(afterUpload.fingerprint).not.toBe(initial.fingerprint);
    expect(afterUpload.subject).toBe('mail.e2e.test');
    expect((await servedCertificate(PORTS.smtps)).fingerprint).toBe(afterUpload.fingerprint);

    // The private key cannot be read back through the API.
    const status = await (await page.request.get('/api/tls')).text();
    expect(status).not.toContain('PRIVATE KEY');

    // Automated mode: the CA is unreachable in this environment, so the request fails, is
    // reported, and the working certificate stays in place.
    await page.getByRole('tab', { name: "Automated (Let's Encrypt)" }).click();
    await page.getByLabel('Domain names').fill('*.e2e.test');
    await page.getByLabel('Contact e-mail').fill(ADMIN.email);
    await page.getByRole('button', { name: 'Save and request certificate' }).click();
    await expect(page.getByRole('alert').filter({ hasText: 'wildcard certificates require the DNS-01 challenge' })).toBeVisible();

    await page.getByLabel('Domain names').fill('mail.e2e.test');
    await page.getByRole('button', { name: 'Save and request certificate' }).click();
    await expect(page.getByRole('alert').filter({ hasText: 'The certificate could not be issued' })).toBeVisible({ timeout: 30_000 });
    await expect(mode).toHaveText("Let's Encrypt (automatic)");
    await expect(page.getByRole('button', { name: 'Renew now' })).toBeVisible();
    expect((await servedCertificate(PORTS.https)).fingerprint, 'a failed request keeps the current certificate').toBe(afterUpload.fingerprint);

    // Back to self-signed.
    await page.getByRole('button', { name: 'Revert to a self-signed certificate' }).click();
    await page.getByRole('dialog').getByRole('button', { name: 'Revert' }).click();
    await expect(mode).toHaveText('Self-signed');
    const reverted = await servedCertificate(PORTS.https);
    expect(reverted.fingerprint).not.toBe(afterUpload.fingerprint);

    await openAdmin(page, 'Logs');
    await page.getByRole('tab', { name: 'Security audit' }).click();
    await page.getByLabel('Search').fill('tls.');
    const log = page.getByRole('table', { name: 'Audit log' });
    for (const action of ['tls.custom_installed', 'tls.acme_configured', 'tls.acme_failed', 'tls.self_signed']) {
      await expect(log.getByRole('cell', { name: action, exact: true }).first()).toBeVisible();
    }
  });
});
