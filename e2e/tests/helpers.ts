import { expect, type Page } from '@playwright/test';
import net from 'node:net';
import tls from 'node:tls';
import { ADMIN, PORTS } from '../playwright.config';

export { ADMIN, PORTS };
export const USER_PASSWORD = 'e2e-user-password-1';
export const DOMAIN = 'example.test';

export async function login(page: Page, email: string, password: string) {
  await page.goto('/login');
  await page.getByLabel('E-mail address').fill(email);
  await page.getByLabel('Password').fill(password);
  await page.getByRole('button', { name: 'Sign in', exact: true }).click();
  await expect(page.getByRole('navigation', { name: 'Folders' })).toBeVisible();
}

export async function logout(page: Page) {
  await page.getByRole('button', { name: 'Account menu' }).click();
  await page.getByRole('menuitem', { name: 'Sign out' }).click();
  await expect(page.getByRole('button', { name: 'Sign in', exact: true })).toBeVisible();
}

export async function openAdmin(page: Page, section: string) {
  await page.goto('/admin');
  await page.getByRole('navigation', { name: 'Administration' }).getByRole('link', { name: section }).click();
  await expect(page.getByRole('heading', { level: 1 })).toBeVisible();
}

/** Delivers a raw message through the MX port, as a remote mail server would. */
export function smtpDeliver(from: string, to: string, message: string): Promise<void> {
  return new Promise((resolve, reject) => {
    const socket = net.connect(PORTS.smtp, '127.0.0.1');
    const body = message.replace(/\r?\n/g, '\r\n').replace(/^\./gm, '..');
    const steps = [`EHLO sender.remote.test`, `MAIL FROM:<${from}>`, `RCPT TO:<${to}>`, 'DATA', `${body}\r\n.`, 'QUIT'];
    let buffer = '';
    let step = -1;
    socket.setEncoding('utf8');
    socket.on('data', (chunk: string) => {
      buffer += chunk;
      // A reply is complete when its last line has a space after the status code.
      const lines = buffer.split('\r\n').filter(Boolean);
      const last = lines[lines.length - 1];
      if (!buffer.endsWith('\r\n') || !last || last[3] !== ' ') return;
      const code = Number(last.slice(0, 3));
      buffer = '';
      if (code >= 400) {
        socket.destroy();
        reject(new Error(`SMTP step ${step} failed: ${last}`));
        return;
      }
      step += 1;
      if (step < steps.length) socket.write(`${steps[step]}\r\n`);
      else socket.end();
    });
    socket.on('close', () => resolve());
    socket.on('error', reject);
  });
}

/** SHA-256 fingerprint of the certificate currently presented on a TLS port. */
export function servedCertificate(port: number): Promise<{ fingerprint: string; subject: string }> {
  return new Promise((resolve, reject) => {
    const socket = tls.connect({ host: '127.0.0.1', port, rejectUnauthorized: false, servername: 'mail.e2e.test' }, () => {
      const cert = socket.getPeerCertificate();
      socket.end();
      resolve({ fingerprint: cert.fingerprint256, subject: String(cert.subject?.CN ?? '') });
    });
    socket.on('error', reject);
  });
}
