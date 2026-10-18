import { describe, expect, it } from 'vitest';
import { attachmentRisk, linkWarning, senderNameWarning } from './risk';

describe('attachment risks', () => {
  it('flags programs, disguised programs and hidden characters', () => {
    expect(attachmentRisk('setup.exe')?.level).toBe('danger');
    expect(attachmentRisk('Invoice.PDF.exe')?.reason).toContain('disguised as a .pdf file');
    expect(attachmentRisk('report.js')?.level).toBe('danger');
    expect(attachmentRisk('shortcut.lnk')?.level).toBe('danger');
    expect(attachmentRisk('invoice‮fdp.exe')?.reason).toContain('hidden characters');
    expect(attachmentRisk('setup.exe. ')?.level).toBe('danger');
  });

  it('cautions about macros, pages and archives, and lets ordinary files be', () => {
    expect(attachmentRisk('budget.xlsm')?.level).toBe('caution');
    expect(attachmentRisk('page.html')?.level).toBe('caution');
    expect(attachmentRisk('logo.svg')?.level).toBe('caution');
    expect(attachmentRisk('photos.zip')?.level).toBe('caution');
    for (const ordinary of ['report.pdf', 'photo.jpg', 'notes.txt', 'budget.xlsx', 'README', 'archive.tar.pdf']) {
      expect(attachmentRisk(ordinary)).toBeNull();
    }
  });
});

describe('link warnings', () => {
  it('spots links whose text names another site', () => {
    expect(linkWarning('https://evil.example/login', 'https://paypal.com/login')).toBe('The link says paypal.com, but it goes to evil.example.');
    // A broken percent-encoding in the hidden user name is reported, not thrown.
    expect(linkWarning('http://%E0%A4%A@example.com', 'click')).toContain('example.com');
    expect(linkWarning('https://evil.example/', 'Log in at www.paypal.com')).toContain('paypal.com');
    expect(linkWarning('https://www.paypal.com/x', 'paypal.com')).toBeNull();
    expect(linkWarning('https://login.paypal.com/x', 'https://paypal.com')).toBeNull();
    expect(linkWarning('https://example.org/a', 'Read more')).toBeNull();
  });

  it('spots hidden destinations, numeric hosts and look-alike domains', () => {
    expect(linkWarning('https://paypal.com@evil.example/', 'click')).toContain('goes to evil.example');
    expect(linkWarning('http://203.0.113.9/login', 'Sign in')).toContain('numeric address');
    expect(linkWarning('https://раypal.com/', 'Sign in')).toContain('international characters');
    expect(linkWarning('mailto:a@b.example', 'write to c.example')).toBeNull();
    expect(linkWarning('not a url', 'x')).toBeNull();
  });
});

describe('sender name warnings', () => {
  it('spots names that show another address or domain', () => {
    expect(senderNameWarning('support@paypal.com', 'x@evil.example')).toContain('shows the address support@paypal.com');
    expect(senderNameWarning('PayPal.com Security', 'x@evil.example')).toContain('mentions paypal.com');
    expect(senderNameWarning('Alice Example', 'alice@example.org')).toBeNull();
    expect(senderNameWarning('alice@example.org', 'alice@example.org')).toBeNull();
    expect(senderNameWarning('Example.org team', 'news@mail.example.org')).toBeNull();
    expect(senderNameWarning(null, 'a@b.example')).toBeNull();
  });
});
