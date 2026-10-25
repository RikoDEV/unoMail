// Per-part styles and background images of a skin. Like the rest of a skin they are data:
// each part takes a fixed set of bounded properties, turned here into styles for that part's
// class (`um-part-<name>`) or Material UI component. Nothing can hide, move or overlay
// anything, and text that would become hard to read falls back to the scheme's colour.

import type { Theme } from '@mui/material';

export const PARTS = ['appBar', 'sidebar', 'messageList', 'messageRow', 'reader', 'composer', 'card', 'dialog', 'button', 'input', 'chip'] as const;
export type Part = (typeof PARTS)[number];

export interface PartStyle {
  background?: string;
  color?: string;
  borderColor?: string;
  borderWidth?: number;
  radius?: number;
  shadow?: 'none' | 'low' | 'medium' | 'high';
  opacity?: number;
  blur?: number;
  fontWeight?: number;
  fontSize?: number;
  textTransform?: 'none' | 'uppercase';
}

export type ImagePlace = 'page' | 'sidebar' | 'login';
export type Images = Partial<Record<ImagePlace, string>>;

const COLOR = /^#[0-9a-f]{6}$/i;
const GRADIENT = /^linear-gradient\((\d{1,3})deg((?:\s*,\s*#[0-9a-f]{6}(?:\s+\d{1,3}%)?){2,4})\)$/i;
/** Theme images are files of an installed package, served by this server. */
const IMAGE_URL = /^\/package-asset\/[a-z0-9-]{1,40}\/[0-9a-f]{40}\/[A-Za-z0-9._/-]{1,100}$/;

/** Selectors of each part: the layout's named containers and the toolkit's components. */
const SELECTORS: Record<Part, string> = {
  appBar: '.um-part-appBar',
  sidebar: '.um-part-sidebar',
  messageList: '.um-part-messageList',
  messageRow: '.um-part-messageRow',
  reader: '.um-part-reader',
  composer: '.um-part-composer',
  card: '.MuiCard-root',
  dialog: '.MuiDialog-paper',
  button: '.MuiButton-root',
  input: '.MuiOutlinedInput-root, .MuiFilledInput-root',
  chip: '.MuiChip-root',
};

export function isGradient(value: string): boolean {
  const match = GRADIENT.exec(value);
  return Boolean(match) && Number(match![1]) <= 360 && [...match![2].matchAll(/(\d{1,3})%/g)].every((m) => Number(m[1]) <= 100);
}

const within = (value: unknown, min: number, max: number) => typeof value === 'number' && value >= min && value <= max;

/** Keeps only the well-formed styles of known parts. */
export function sanitizeParts(input: unknown): Partial<Record<Part, PartStyle>> | undefined {
  if (!input || typeof input !== 'object') return undefined;
  const out: Partial<Record<Part, PartStyle>> = {};
  for (const part of PARTS) {
    const raw = (input as Record<string, unknown>)[part] as Record<string, unknown> | undefined;
    if (!raw || typeof raw !== 'object') continue;
    const style: PartStyle = {};
    if (typeof raw.background === 'string' && (COLOR.test(raw.background) || isGradient(raw.background))) style.background = raw.background;
    if (typeof raw.color === 'string' && COLOR.test(raw.color)) style.color = raw.color;
    if (typeof raw.borderColor === 'string' && COLOR.test(raw.borderColor)) style.borderColor = raw.borderColor;
    if (within(raw.borderWidth, 0, 4)) style.borderWidth = raw.borderWidth as number;
    if (within(raw.radius, 0, 32)) style.radius = raw.radius as number;
    if (raw.shadow === 'none' || raw.shadow === 'low' || raw.shadow === 'medium' || raw.shadow === 'high') style.shadow = raw.shadow;
    if (within(raw.opacity, 0.6, 1)) style.opacity = raw.opacity as number;
    if (within(raw.blur, 0, 24)) style.blur = raw.blur as number;
    if (within(raw.fontWeight, 400, 800) && (raw.fontWeight as number) % 100 === 0) style.fontWeight = raw.fontWeight as number;
    if (within(raw.fontSize, 0.8, 1.3)) style.fontSize = raw.fontSize as number;
    if (raw.textTransform === 'none' || raw.textTransform === 'uppercase') style.textTransform = raw.textTransform;
    if (Object.keys(style).length) out[part] = style;
  }
  return Object.keys(out).length ? out : undefined;
}

export function sanitizeImages(input: unknown): Images | undefined {
  if (!input || typeof input !== 'object') return undefined;
  const out: Images = {};
  for (const place of ['page', 'sidebar', 'login'] as const) {
    const url = (input as Record<string, unknown>)[place];
    if (typeof url === 'string' && IMAGE_URL.test(url)) out[place] = url;
  }
  return Object.keys(out).length ? out : undefined;
}

function channels(hex: string): [number, number, number] {
  return [1, 3, 5].map((at) => parseInt(hex.slice(at, at + 2), 16)) as [number, number, number];
}

/** WCAG contrast ratio of two #rrggbb colours. */
export function contrast(a: string, b: string): number {
  const luminance = (hex: string) => {
    const [r, g, bl] = channels(hex).map((v) => v / 255).map((c) => (c <= 0.03928 ? c / 12.92 : ((c + 0.055) / 1.055) ** 2.4));
    return 0.2126 * r + 0.7152 * g + 0.0722 * bl;
  };
  const [light, dark] = [luminance(a), luminance(b)].sort((x, y) => y - x);
  return (light + 0.05) / (dark + 0.05);
}

/** The colours a background shows, for the contrast check (every stop of a gradient). */
function backgroundColors(background: string): string[] {
  return background.match(/#[0-9a-f]{6}/gi) ?? [];
}

const SHADOWS = { none: 'none', low: '0 1px 3px rgba(0,0,0,.2)', medium: '0 4px 12px rgba(0,0,0,.25)', high: '0 12px 32px rgba(0,0,0,.35)' };

function translucent(background: string, opacity: number): string {
  if (opacity >= 1) return background;
  const tint = (hex: string) => `rgba(${channels(hex).join(', ')}, ${opacity})`;
  return background.replace(/#[0-9a-f]{6}/gi, tint);
}

/** A text colour readable on the part's background, or the scheme's own when it is not. */
export function readableColor(style: PartStyle, fallbackText: string, fallbackBackground: string): string {
  const text = style.color ?? fallbackText;
  const backgrounds = style.background ? backgroundColors(style.background) : [fallbackBackground];
  if (!COLOR.test(text) || backgrounds.some((bg) => !COLOR.test(bg))) return text;
  return backgrounds.every((bg) => contrast(text, bg) >= 3) ? text : fallbackText;
}

const imageCss = (url: string, fit: 'cover' | 'contain' | 'tile' = 'cover') =>
  fit === 'tile' ? { backgroundImage: `url("${url}")`, backgroundRepeat: 'repeat' } : { backgroundImage: `url("${url}")`, backgroundSize: fit, backgroundPosition: 'center', backgroundRepeat: 'no-repeat' };

/** Global styles for a skin's parts and images. */
export function partStyles(theme: Theme, parts: Partial<Record<Part, PartStyle>> = {}, images: Images = {}, fit?: 'cover' | 'contain' | 'tile'): Record<string, object> {
  const css: Record<string, object> = {};
  const scheme = { text: theme.palette.text.primary, background: theme.palette.background.paper };
  for (const part of PARTS) {
    const style = parts[part];
    if (!style) continue;
    const rule: Record<string, string | number> = {};
    if (style.background) rule.background = translucent(style.background, style.opacity ?? 1);
    else if (style.opacity !== undefined && COLOR.test(scheme.background)) rule.background = translucent(scheme.background, style.opacity);
    if (style.color || style.background) {
      const fallbackText = COLOR.test(scheme.text) ? scheme.text : '#000000';
      rule.color = readableColor(style, fallbackText, COLOR.test(scheme.background) ? scheme.background : '#ffffff');
    }
    if (style.borderColor || style.borderWidth !== undefined) {
      rule.borderStyle = 'solid';
      rule.borderWidth = `${style.borderWidth ?? 1}px`;
      rule.borderColor = style.borderColor ?? theme.palette.divider;
    }
    if (style.radius !== undefined) rule.borderRadius = `${style.radius}px`;
    if (style.shadow) rule.boxShadow = SHADOWS[style.shadow];
    if (style.blur) rule.backdropFilter = `blur(${style.blur}px)`;
    if (style.fontWeight) rule.fontWeight = style.fontWeight;
    if (style.fontSize) rule.fontSize = `${style.fontSize}em`;
    if (style.textTransform) rule.textTransform = style.textTransform;
    css[SELECTORS[part]] = rule;
  }
  if (images.page) {
    css.body = { ...imageCss(images.page, fit), backgroundColor: theme.palette.background.default, backgroundAttachment: 'fixed' };
    // Pages paint the background colour themselves; with an image they leave it to the body.
    css['body .um-page'] = { backgroundColor: 'transparent' };
  }
  if (images.sidebar) css[SELECTORS.sidebar] = { ...css[SELECTORS.sidebar], ...imageCss(images.sidebar, fit) };
  if (images.login) css['.um-part-login'] = imageCss(images.login, fit);
  return css;
}
