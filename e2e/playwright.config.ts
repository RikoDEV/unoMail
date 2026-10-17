import { defineConfig } from '@playwright/test';
import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const here = path.dirname(fileURLToPath(import.meta.url));
const dataDir = path.join(here, '.data');

const defaultPorts = { http: 18080, https: 18443, smtp: 12525, submission: 12587, smtps: 12465, imaps: 12993, imap: 12143, pop3s: 12995, sieve: 14190 };
// Windows/Hyper-V can reserve the default range; shift all listeners together.
const portOffset = Number(process.env.UNOMAIL_E2E_PORT_OFFSET ?? 0);
export const PORTS = Object.fromEntries(Object.entries(defaultPorts).map(([name, port]) => [name, port + portOffset])) as typeof defaultPorts;
export const ADMIN = { email: 'admin@e2e.test', password: 'e2e-admin-password-1' };

// Every run starts from an empty server. Only the main process may wipe the directory;
// workers evaluate this file too, while the server is already running.
if (!process.env.TEST_WORKER_INDEX && !process.env.UNOMAIL_E2E_KEEP_DATA) {
  fs.rmSync(dataDir, { recursive: true, force: true });
}

export default defineConfig({
  testDir: './tests',
  // The specs share one server and build on each other's state.
  fullyParallel: false,
  workers: 1,
  retries: 0,
  timeout: 60_000,
  reporter: [['list']],
  use: {
    // A host name, not an address: passkeys (WebAuthn) are only offered to named sites.
    baseURL: `http://localhost:${PORTS.http}`,
    // The interface follows the browser language; the tests read English.
    locale: 'en-US',
    trace: 'retain-on-failure',
    screenshot: 'only-on-failure',
  },
  webServer: {
    command: 'cargo run --quiet',
    cwd: path.join(here, '..', 'server'),
    url: `http://127.0.0.1:${PORTS.http}/health`,
    timeout: 600_000,
    reuseExistingServer: false,
    stdout: 'ignore',
    stderr: 'pipe',
    env: {
      UNOMAIL_DATA_DIR: dataDir,
      UNOMAIL_HOSTNAME: 'mail.e2e.test',
      UNOMAIL_BIND: '127.0.0.1',
      UNOMAIL_HTTP_PORT: String(PORTS.http),
      UNOMAIL_HTTPS_PORT: String(PORTS.https),
      UNOMAIL_SMTP_PORT: String(PORTS.smtp),
      UNOMAIL_SUBMISSION_PORT: String(PORTS.submission),
      UNOMAIL_SMTPS_PORT: String(PORTS.smtps),
      UNOMAIL_IMAPS_PORT: String(PORTS.imaps),
      UNOMAIL_IMAP_PORT: String(PORTS.imap),
      UNOMAIL_POP3S_PORT: String(PORTS.pop3s),
      UNOMAIL_SIEVE_PORT: String(PORTS.sieve),
      UNOMAIL_BACKUP_DIR: path.join(dataDir, 'backups'),
      UNOMAIL_WEB_DIR: path.join(here, '..', 'web', 'dist'),
      // The suite talks plain HTTP to the loopback interface.
      UNOMAIL_COOKIE_SECURE: 'false',
      UNOMAIL_HTTP_REDIRECT: 'false',
      UNOMAIL_ADMIN_EMAIL: ADMIN.email,
      UNOMAIL_ADMIN_PASSWORD: ADMIN.password,
      UNOMAIL_GREYLIST: 'false',
      // The suite runs its own stand-ins for remote services on the loopback interface.
      UNOMAIL_ALLOW_PRIVATE_DESTINATIONS: 'true',
      UNOMAIL_PUBLIC_URL: `http://localhost:${PORTS.http}`,
      // No requests to third parties from the tests.
      UNOMAIL_GRAVATAR: 'off',
      // An unreachable CA: certificate requests must fail quickly and gracefully.
      UNOMAIL_ACME_DIRECTORY: 'https://127.0.0.1:9/directory',
      // Info level, so the system log viewer has the start-up messages to show on every platform.
      UNOMAIL_LOG: 'info',
    },
  },
});
