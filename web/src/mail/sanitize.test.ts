import { describe, expect, it } from 'vitest';
import { formatAddress, htmlToText, parseRecipients } from './jmapClient';
import { buildFrameDocument, escapeHtml, sanitizeEmail, sanitizeEmailHtml, textToHtml } from './sanitize';

describe('sanitizeEmailHtml', () => {
  it('removes scripts and event handlers', () => {
    const out = sanitizeEmailHtml('<p onclick="steal()">hi</p><script>alert(1)</script><img src=x onerror=alert(1)>');
    expect(out).not.toMatch(/script|onclick|onerror|alert/i);
    expect(out).toContain('<p>hi</p>');
  });

  it('removes forms, frames and embedded content used for phishing', () => {
    const out = sanitizeEmailHtml('<form action="https://evil.example"><input name="password"><button>Go</button></form><iframe src="https://evil.example"></iframe><object data="x"></object><svg><script>1</script></svg>');
    expect(out).not.toMatch(/<form|<input|<button|<iframe|<object|<svg/i);
  });

  it('neutralises dangerous link schemes and hardens safe links', () => {
    const out = sanitizeEmailHtml('<a href="javascript:alert(1)">a</a><a href="data:text/html,x">b</a><a href="https://example.org/x">c</a><a href="mailto:a@b.example">d</a>');
    expect(out).not.toMatch(/javascript:|data:text/i);
    expect(out).toContain('<a href="https://example.org/x" target="_blank" rel="noopener noreferrer nofollow" title="https://example.org/x">c</a>');
    expect(out).toContain('href="mailto:a@b.example"');
  });

  it('blocks remote images and tracking pixels but keeps inline ones', () => {
    const out = sanitizeEmailHtml(
      '<img src="https://tracker.example/pixel.gif"><img src="cid:logo@x" alt="Logo"><img src="cid:missing"><img src="data:image/png;base64,AAAA"><img src="data:text/html;base64,AAAA">',
      (cid) => (cid === 'logo@x' ? 'blob:local-logo' : undefined),
    );
    expect(out).not.toContain('tracker.example');
    expect(out).toContain('[remote image blocked]');
    expect(out).toContain('src="blob:local-logo"');
    expect(out).toContain('src="data:image/png;base64,AAAA"');
    expect(out).not.toContain('data:text/html');
  });

  it('removes remote resources referenced from CSS', () => {
    const out = sanitizeEmailHtml('<div style="background:url(https://tracker.example/a.png)">x</div><p style="color:red">y</p><style>@import "https://evil.example/x.css";</style>');
    expect(out).not.toContain('tracker.example');
    expect(out).not.toContain('@import');
    expect(out).toContain('style="color:red"');
  });

  it('marks links that are not what they claim, and shows every destination', () => {
    const out = sanitizeEmailHtml('<a href="https://evil.example/login">https://paypal.com/login</a> <a href="https://example.org/a">Read more</a>');
    expect(out).toContain('data-unomail-warning="The link says paypal.com, but it goes to evil.example."');
    expect(out).toContain('title="https://example.org/a"');
    expect(out.match(/data-unomail-warning/g)).toHaveLength(1);
  });

  it('removes CSS that hides remote loads behind escapes or comments', () => {
    const out = sanitizeEmailHtml(
      '<div style="background:u\\72l(https://tracker.example/1.png)">a</div><div style="background:u/**/rl(https://tracker.example/2.png)">b</div>' +
        '<div style="background-image:image-set(\'https://tracker.example/3.png\' 1x)">c</div><style>.x{background:\\75rl(https://tracker.example/4.png)}</style>',
    );
    expect(out).not.toContain('tracker.example');
  });

  it('keeps quoted mail from restyling or covering the application', () => {
    const hostile =
      '<p>Hello</p><style>body * { display: none }</style>' +
      '<a href="https://evil.example/login" style="POSITION: fixed; inset:0; z-index:99999; -webkit-transform: scale(9); inset-block-start: 0; color: red">Your session expired</a>' +
      '<div style="top:-500px;left:0;position:absolute">x</div>';
    const out = sanitizeEmailHtml(hostile);
    expect(out).not.toContain('<style');
    expect(out).not.toMatch(/position|inset|z-index|transform|top|left/i);
    expect(out).toContain('style=" color: red"');
    expect(out).toContain('<div>x</div>');
    // The reader's sandboxed frame keeps the sender's layout: nothing there reaches the app.
    const framed = sanitizeEmail(hostile).html;
    expect(framed).toContain('<style>');
    expect(framed).toContain('position:absolute');
  });

  it('drops meta refresh, base and link tags', () => {
    const out = sanitizeEmailHtml('<meta http-equiv="refresh" content="0;url=https://evil.example"><base href="https://evil.example/"><link rel="stylesheet" href="https://evil.example/x.css"><p>ok</p>');
    expect(out).toBe('<p>ok</p>');
  });
});

describe('frame document', () => {
  it('embeds a restrictive content security policy', () => {
    const doc = buildFrameDocument('<p>x</p>', false);
    expect(doc).toContain("default-src 'none'");
    expect(doc).not.toMatch(/script-src/);
    expect(doc).toContain('<p>x</p>');
  });
});

describe('text helpers', () => {
  it('escapes plain text bodies', () => {
    expect(escapeHtml('<b>"a" & b</b>')).toBe('&lt;b&gt;&quot;a&quot; &amp; b&lt;/b&gt;');
    expect(textToHtml('<script>x</script>')).toBe('<pre>&lt;script&gt;x&lt;/script&gt;</pre>');
  });

  it('parses recipient fields', () => {
    expect(parseRecipients('a@example.org, "Bob B" <bob@example.org>; Carol <carol@example.org>,')).toEqual([
      { name: null, email: 'a@example.org' },
      { name: 'Bob B', email: 'bob@example.org' },
      { name: 'Carol', email: 'carol@example.org' },
    ]);
    expect(parseRecipients('  ')).toEqual([]);
    expect(formatAddress({ name: 'Bob', email: 'bob@example.org' })).toBe('Bob <bob@example.org>');
    expect(formatAddress({ name: null, email: 'bob@example.org' })).toBe('bob@example.org');
  });

  it('derives a text alternative from HTML', () => {
    expect(htmlToText('<p>Hello <b>world</b></p><p>Second<br>line</p>')).toBe('Hello world\nSecond\nline');
  });
});
