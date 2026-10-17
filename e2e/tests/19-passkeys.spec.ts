import { expect, test, type Browser, type Page } from '@playwright/test';
import { DOMAIN, login, USER_PASSWORD } from './helpers';

// A mailbox of its own, so the passkey set up here affects no other spec.
const GINA = `gina@${DOMAIN}`;
const ADMIN_EMAIL = 'admin@e2e.test';
const ADMIN_PASSWORD = 'e2e-admin-password-1';

type Credential = { credentialId: string; isResidentCredential: boolean; rpId?: string; privateKey: string; userHandle?: string; signCount: number };

/**
 * A platform authenticator (like Touch ID or Windows Hello) that always verifies the user.
 * Virtual authenticators also answer the address field's autofill request at once, where a
 * person would pick the passkey from the suggestions.
 */
async function virtualAuthenticator(page: Page, existing: Credential[] = []) {
  const cdp = await page.context().newCDPSession(page);
  await cdp.send('WebAuthn.enable');
  const { authenticatorId } = await cdp.send('WebAuthn.addVirtualAuthenticator', {
    options: { protocol: 'ctap2', transport: 'internal', hasResidentKey: true, hasUserVerification: true, isUserVerified: true, automaticPresenceSimulation: true },
  });
  for (const credential of existing) await cdp.send('WebAuthn.addCredential', { authenticatorId, credential });
  return { credentials: async () => (await cdp.send('WebAuthn.getCredentials', { authenticatorId })).credentials as Credential[] };
}

/** A browser without passkeys in the autofill, where the button is the way in. */
async function pageWithoutAutofill(browser: Browser) {
  const context = await browser.newContext();
  await context.addInitScript(() => {
    if (typeof PublicKeyCredential !== 'undefined') Object.defineProperty(PublicKeyCredential, 'isConditionalMediationAvailable', { value: async () => false });
  });
  return context.newPage();
}

async function signOut(page: Page) {
  await page.getByRole('button', { name: 'Account menu' }).click();
  await page.getByRole('menuitem', { name: 'Sign out', exact: true }).click();
}

async function openSecurity(page: Page) {
  await page.getByRole('button', { name: 'Account menu' }).click();
  await page.getByRole('menuitem', { name: 'Settings' }).click();
  await page.getByRole('tab', { name: 'Security' }).click();
}

async function signedInAs(page: Page, email: string) {
  await expect(page.getByRole('navigation', { name: 'Folders' })).toBeVisible();
  await page.getByRole('button', { name: 'Account menu' }).click();
  await expect(page.getByRole('menu')).toContainText(email);
  await page.keyboard.press('Escape');
}

test.describe('passkeys', () => {
  test.beforeAll(async ({ browser }) => {
    const page = await browser.newPage();
    await login(page, ADMIN_EMAIL, ADMIN_PASSWORD);
    await page.goto('/admin/mailboxes');
    await page.getByRole('button', { name: 'Add mailbox' }).click();
    const dialog = page.getByRole('dialog');
    await dialog.getByLabel('E-mail address').fill(GINA);
    await dialog.getByLabel('Password', { exact: true }).fill(USER_PASSWORD);
    await dialog.getByRole('button', { name: 'Create' }).click();
    await expect(page.getByText('Mailbox created').or(dialog.getByRole('alert').filter({ hasText: 'already exists' }))).toBeVisible();
    await page.close();
  });

  test('a passkey signs in without an address or password', async ({ page, browser }) => {
    const device = await virtualAuthenticator(page);
    await login(page, GINA, USER_PASSWORD);

    // Add one in the settings.
    await openSecurity(page);
    page.once('dialog', (dialog) => void dialog.accept('Work laptop'));
    await page.getByRole('button', { name: 'Add a passkey' }).click();
    // A passkey is a new way in: the password is asked for first.
    const confirmAdd = page.getByRole('dialog', { name: 'Add a passkey' });
    await confirmAdd.getByLabel('Your password').fill(USER_PASSWORD);
    await confirmAdd.getByRole('button', { name: 'Continue' }).click();
    await expect(page.getByText('Passkey added')).toBeVisible();
    // The first factor brings recovery codes.
    await page.getByRole('button', { name: 'I have saved them' }).click();
    const list = page.getByRole('table', { name: 'Passkeys' });
    await expect(list).toContainText('Work laptop');
    await expect(list).toContainText('Signs in without a password');
    const stored = await device.credentials();
    expect(stored).toHaveLength(1);
    expect(stored[0].isResidentCredential).toBe(true);

    // Signed out, the address field's autofill offers the passkey, and picking it signs in.
    await signOut(page);
    await signedInAs(page, GINA);

    // Elsewhere (a browser without the autofill), the button does the same.
    const other = await pageWithoutAutofill(browser);
    const copy = await virtualAuthenticator(other, stored);
    await other.goto('/login');
    await expect(other.getByLabel('E-mail address')).toHaveAttribute('autocomplete', 'username webauthn');
    await other.getByRole('button', { name: 'Sign in with a passkey' }).click();
    await signedInAs(other, GINA);

    // After a password, the same passkey is the second step.
    await signOut(other);
    await other.getByLabel('E-mail address').fill(GINA);
    await other.getByLabel('Password').fill(USER_PASSWORD);
    await other.getByRole('button', { name: 'Sign in', exact: true }).click();
    await expect(other.getByRole('heading', { name: '2-step verification' })).toBeVisible();
    await other.getByRole('button', { name: 'Use a passkey' }).click();
    await signedInAs(other, GINA);

    // Renamed, then removed: it no longer signs in.
    await openSecurity(other);
    const otherList = other.getByRole('table', { name: 'Passkeys' });
    other.once('dialog', (dialog) => void dialog.accept('Old laptop'));
    await other.getByRole('button', { name: 'Rename Work laptop' }).click();
    await expect(otherList).toContainText('Old laptop');
    await other.getByRole('button', { name: 'Remove Old laptop' }).click();
    const confirm = other.getByRole('dialog');
    await confirm.getByLabel('Password').fill(USER_PASSWORD);
    await confirm.getByRole('button', { name: 'Remove' }).click();
    await expect(other.getByText('Passkey removed')).toBeVisible();
    await signOut(other);
    await expect(other.getByRole('button', { name: 'Sign in', exact: true })).toBeVisible();
    await other.getByRole('button', { name: 'Sign in with a passkey' }).click();
    // The device may still offer it (then the server refuses it and says so) or have dropped it
    // already on the browser's signal; either way she stays on the sign-in page.
    if ((await copy.credentials()).length > 0) await expect(other.getByRole('alert')).toContainText('not registered here any more');
    await expect(other.getByRole('button', { name: 'Sign in', exact: true })).toBeVisible();
    await other.context().close();
  });
});
