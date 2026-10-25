import { describe, expect, it } from 'vitest';
import { createTheme } from '@mui/material';
import { isGradient, partStyles, readableColor, sanitizeImages, sanitizeParts } from './skinParts';
import { sanitizeSkin } from './skins';

describe('skin parts', () => {
  it('accept plain gradients only', () => {
    expect(isGradient('linear-gradient(135deg, #102030, #405060 80%)')).toBe(true);
    expect(isGradient('linear-gradient(135deg, #102030)')).toBe(false);
    expect(isGradient('linear-gradient(135deg, #102030, url(x))')).toBe(false);
    expect(isGradient('linear-gradient(400deg, #102030, #405060)')).toBe(false);
    expect(isGradient('radial-gradient(#102030, #405060)')).toBe(false);
  });

  it('keep known parts and bounded values', () => {
    expect(sanitizeParts({ sidebar: { background: '#112233', blur: 99, display: 'none' }, warning: { color: '#000000' } })).toEqual({ sidebar: { background: '#112233' } });
    expect(sanitizeParts({ sidebar: { background: 'url(https://evil.example/x)' } })).toBeUndefined();
  });

  it('take images only from installed packages', () => {
    const own = `/package-asset/ocean/${'a'.repeat(40)}/bg.webp`;
    expect(sanitizeImages({ page: own, login: 'https://evil.example/x.png', sidebar: '/api/me' })).toEqual({ page: own });
    expect(sanitizeSkin({ id: 'x', name: 'X', images: { page: own } })?.images).toEqual({ page: own });
  });

  it('fall back to readable text when a part has too little contrast', () => {
    expect(readableColor({ color: '#777777', background: '#7a7a7a' }, '#000000', '#ffffff')).toBe('#000000');
    expect(readableColor({ color: '#ffffff', background: 'linear-gradient(90deg, #000000, #202020)' }, '#000000', '#ffffff')).toBe('#ffffff');
    // A gradient with one light stop fails the check for white text.
    expect(readableColor({ color: '#ffffff', background: 'linear-gradient(90deg, #000000, #f0f0f0)' }, '#111111', '#ffffff')).toBe('#111111');
  });

  it('style the named containers and set the page image', () => {
    const theme = createTheme();
    const css = partStyles(theme, { sidebar: { background: '#102030', opacity: 0.8, blur: 12 } }, { page: `/package-asset/ocean/${'a'.repeat(40)}/bg.webp` });
    expect(css['.um-part-sidebar']).toMatchObject({ background: 'rgba(16, 32, 48, 0.8)', backdropFilter: 'blur(12px)' });
    expect(css.body).toMatchObject({ backgroundAttachment: 'fixed' });
    expect(css['body .um-page']).toEqual({ backgroundColor: 'transparent' });
  });
});
