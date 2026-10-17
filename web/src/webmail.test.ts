import { beforeEach, describe, expect, it, vi } from 'vitest';

vi.mock('./api', () => ({ get: vi.fn(async () => []), put: vi.fn(async () => ({})), post: vi.fn(), del: vi.fn(), postRaw: vi.fn() }));

import { applySuggestion, imageProxyUrl, shareLevel, splitRecipients, suggestionText } from './mail/extra';
import { buildFrameDocument, sanitizeEmail } from './mail/sanitize';
import { createPluginApi, emit, registrySnapshot, resetPlugins, setPluginNotifier } from './plugins';
import { BUILT_IN_SKINS, buildTheme, sanitizeSkin, skinIsDark } from './skins';

describe('remote images', () => {
  const html = '<p>Hi</p><img src="https://tracker.example/pixel.gif?id=42"><img src="http://cdn.example/logo.png" alt="Logo"><img src="data:image/png;base64,AAAA"><img src="javascript:alert(1)">';

  it('are blocked and counted by default', () => {
    const result = sanitizeEmail(html);
    expect(result.blockedImages).toBe(2);
    expect(result.html).not.toContain('tracker.example');
    expect(result.html).toContain('[remote image blocked]');
    expect(result.html).toContain('data:image/png;base64,AAAA');
    expect(result.html).not.toContain('javascript:');
  });

  it('are loaded through the proxy only when the reader asks, never directly', () => {
    const result = sanitizeEmail(html, { proxyImage: imageProxyUrl });
    expect(result.blockedImages).toBe(0);
    expect(result.html).toContain('src="/api/me/image-proxy?url=https%3A%2F%2Ftracker.example%2Fpixel.gif%3Fid%3D42"');
    expect(result.html).toContain('src="/api/me/image-proxy?url=http%3A%2F%2Fcdn.example%2Flogo.png"');
    expect(result.html).not.toMatch(/src="https?:\/\//);
    expect(result.html).not.toContain('javascript:');
    // Other ways of loading remote content stay closed.
    const sneaky = sanitizeEmail('<div style="background:url(https://tracker.example/x)">x</div><img srcset="https://tracker.example/y 2x">', { proxyImage: imageProxyUrl });
    expect(sneaky.html).not.toContain('tracker.example');
  });

  it('opens the frame policy for the proxy origin only when it is used', () => {
    expect(buildFrameDocument('<p>x</p>', false)).toContain("img-src data: blob:; style-src");
    const allowed = buildFrameDocument('<p>x</p>', false, 'https://mail.example.org');
    expect(allowed).toContain("img-src data: blob: https://mail.example.org; style-src");
    expect(allowed).toContain("default-src 'none'");
  });
});

describe('recipient suggestions', () => {
  it('replace only the entry being typed', () => {
    expect(splitRecipients('ann@example.org, bo')).toEqual({ done: 'ann@example.org,', current: 'bo' });
    expect(splitRecipients('bo')).toEqual({ done: '', current: 'bo' });
    const contact = { source: 'contact' as const, name: 'Bob <evil>, "Jr"', email: 'bob@example.org' };
    expect(suggestionText(contact)).toBe('Bob  evil    Jr <bob@example.org>');
    expect(applySuggestion('ann@example.org, bo', contact)).toBe('ann@example.org, Bob  evil    Jr <bob@example.org>, ');
    const group = { source: 'group' as const, name: 'Team', members: [{ name: '', email: 'a@example.org' }, { name: 'B', email: 'b@example.org' }] };
    expect(applySuggestion('te', group)).toBe('a@example.org, B <b@example.org>, ');
  });

  it('maps access rights to sharing levels', () => {
    expect(shareLevel('lrs')).toBe('read');
    expect(shareLevel('lrswi')).toBe('write');
    expect(shareLevel('lrswite')).toBe('full');
    expect(shareLevel('lr')).toBe('read');
  });
});

describe('skins', () => {
  it('accept only well-formed design tokens', () => {
    expect(sanitizeSkin({ id: 'ocean', name: 'Ocean', mode: 'dark', primary: '#0061A4', radius: 8, density: 'compact', font: 'system' })).toEqual({
      id: 'ocean', name: 'Ocean', mode: 'dark', primary: '#0061A4', radius: 8, density: 'compact', font: 'system',
    });
    // Anything that is not a known token is dropped rather than applied.
    expect(sanitizeSkin({ id: 'x', name: 'X', primary: 'url(https://evil.example)', background: 'red', radius: 500, font: 'Comic Sans', css: 'body{}' })).toEqual({ id: 'x', name: 'X' });
    for (const bad of [null, 'ocean', {}, { id: 'Bad Id', name: 'x' }, { id: 'ok' }]) expect(sanitizeSkin(bad)).toBeNull();
  });

  it('build a theme for every built-in skin', () => {
    for (const skin of BUILT_IN_SKINS) {
      const theme = buildTheme(skin, '#6750a4', false);
      expect(theme.palette.mode).toBe(skinIsDark(skin, false) ? 'dark' : 'light');
      // Skins with their own primary keep it; otherwise the accent, lightened on dark themes.
      if (skin.primary) expect(theme.palette.primary.main).toBe(skin.primary);
      else if (!skinIsDark(skin, false)) expect(theme.palette.primary.main).toBe('#6750a4');
    }
    const dark = buildTheme(BUILT_IN_SKINS[0], '#006e1c', true);
    expect(dark.palette.mode).toBe('dark');
    expect(dark.palette.primary.main).not.toBe('#006e1c');
    expect(contrast(dark.palette.primary.main, dark.palette.background.paper)).toBeGreaterThan(4.5);
    for (const seed of ['#6750a4', '#0061a4', '#006e1c', '#b3261e', '#7d5260', '#006874', '#c2185b', '#b25e00', '#455a64']) {
      const theme = buildTheme(BUILT_IN_SKINS[0], seed, true);
      expect(contrast(theme.palette.primary.main, theme.palette.background.paper), seed).toBeGreaterThan(4.5);
      expect(contrast(buildTheme(BUILT_IN_SKINS[0], seed, false).palette.primary.main, '#fffbfe'), seed).toBeGreaterThan(4.5);
    }
    expect(buildTheme({ id: 'p', name: 'P', mode: 'light' }, '#006e1c', true).palette.mode).toBe('light');
  });
});

describe('plug-in API', () => {
  beforeEach(() => resetPlugins());

  it('registers scoped actions, validates links and isolates failing handlers', () => {
    const api = createPluginApi('demo', 'bob@example.org');
    expect(api.account).toBe('bob@example.org');
    api.addMessageAction({ id: 'translate', label: 'Translate', onClick: () => {} });
    api.addMessageAction({ id: 'translate', label: 'Translate again', onClick: () => {} });
    api.addComposerAction({ id: 'greet', label: 'Greeting', onClick: (composer) => composer.insertHtml('<p>Hello</p>') });
    api.addSidebarLink({ id: 'wiki', label: 'Wiki', href: 'https://wiki.example.org' });
    expect(() => api.addSidebarLink({ id: 'bad', label: 'Bad', href: 'javascript:alert(1)' })).toThrow();

    const registry = registrySnapshot();
    expect(registry.messageActions.map((a) => `${a.id}=${a.label}`)).toEqual(['demo:translate=Translate again']);
    expect(registry.composerActions[0].id).toBe('demo:greet');
    expect(registry.sidebarLinks).toEqual([{ id: 'demo:wiki', label: 'Wiki', href: 'https://wiki.example.org' }]);

    const seen: string[] = [];
    api.on('message:sent', () => {
      throw new Error('broken plug-in');
    });
    api.on('message:sent', (payload) => seen.push(payload.subject));
    const errors = vi.spyOn(console, 'error').mockImplementation(() => {});
    emit('message:sent', { subject: 'Hello', recipients: 'ann@example.org' });
    expect(seen).toEqual(['Hello']);
    expect(errors).toHaveBeenCalledOnce();
    errors.mockRestore();

    const notices: string[] = [];
    setPluginNotifier((text) => notices.push(text));
    api.notify('x'.repeat(1000));
    expect(notices[0]).toHaveLength(300);
  });
});

/** WCAG contrast ratio of two colours given as #rrggbb or rgb(). */
function contrast(a: string, b: string): number {
  const channels = (color: string) => {
    const hex = color.match(/^#([0-9a-f]{6})$/i);
    const values = hex ? [0, 2, 4].map((at) => parseInt(hex[1].slice(at, at + 2), 16)) : (color.match(/[\d.]+/g) ?? []).slice(0, 3).map(Number);
    return values.map((value) => value / 255).map((c) => (c <= 0.03928 ? c / 12.92 : ((c + 0.055) / 1.055) ** 2.4));
  };
  const luminance = (color: string) => {
    const [r, g, b] = channels(color);
    return 0.2126 * r + 0.7152 * g + 0.0722 * b;
  };
  const [light, dark] = [luminance(a), luminance(b)].sort((x, y) => y - x);
  return (light + 0.05) / (dark + 0.05);
}
