// Readable mail in the dark theme. A message shown on the dark page may set its own text
// colours (black, dark grey, a dark brand colour) that vanish there; and a message that sets
// only a light background (a white newsletter card) relies on default black text, while the
// dark page makes the default light. After it loads, each element's text is checked against
// the background really behind it, and only text too faint to read is changed, keeping its
// hue: lightened on dark backgrounds, darkened on light ones. Text that already reads well
// stays as it was designed, and nothing changes under a background image, whose colours
// cannot be known.

export type Rgb = [number, number, number];

/** Text below this contrast ratio against its background is adjusted (WCAG AA for body text). */
const MIN_CONTRAST = 4.5;
/** A huge message is not walked to the end: the reader must stay quick. */
const MAX_ELEMENTS = 5000;

/** An `rgb()`/`rgba()` value as computed styles give it; null when (nearly) transparent. */
export function parseColor(value: string): Rgb | null {
  const match = value.match(/rgba?\(\s*([\d.]+)[ ,]+([\d.]+)[ ,]+([\d.]+)(?:\s*[,/]\s*([\d.]+%?))?\s*\)/);
  if (!match) return null;
  const alpha = match[4] === undefined ? 1 : match[4].endsWith('%') ? parseFloat(match[4]) / 100 : parseFloat(match[4]);
  if (alpha < 0.5) return null;
  return [Number(match[1]), Number(match[2]), Number(match[3])];
}

function luminance([r, g, b]: Rgb): number {
  const channel = (c: number) => {
    const s = c / 255;
    return s <= 0.03928 ? s / 12.92 : ((s + 0.055) / 1.055) ** 2.4;
  };
  return 0.2126 * channel(r) + 0.7152 * channel(g) + 0.0722 * channel(b);
}

export function contrast(a: Rgb, b: Rgb): number {
  const [light, dark] = [luminance(a), luminance(b)].sort((x, y) => y - x);
  return (light + 0.05) / (dark + 0.05);
}

/** `color` lightened (hue and saturation kept) until it reads on the dark `background`. */
export function lighten(color: Rgb, background: Rgb): Rgb {
  return shift(color, background, 'lighter');
}

/** `color` darkened (hue and saturation kept) until it reads on the light `background`. */
export function darken(color: Rgb, background: Rgb): Rgb {
  return shift(color, background, 'darker');
}

function shift(color: Rgb, background: Rgb, direction: 'lighter' | 'darker'): Rgb {
  const [r, g, b] = color.map((c) => c / 255);
  const max = Math.max(r, g, b);
  const min = Math.min(r, g, b);
  const l = (max + min) / 2;
  const d = max - min;
  const s = d === 0 ? 0 : d / (1 - Math.abs(2 * l - 1));
  let h = 0;
  if (d !== 0) {
    if (max === r) h = ((g - b) / d) % 6;
    else if (max === g) h = (b - r) / d + 2;
    else h = (r - g) / d + 4;
  }
  const fromHsl = (lightness: number): Rgb => {
    const c = (1 - Math.abs(2 * lightness - 1)) * s;
    const x = c * (1 - Math.abs((h % 2) - 1));
    const m = lightness - c / 2;
    const [r1, g1, b1] = h < 1 ? [c, x, 0] : h < 2 ? [x, c, 0] : h < 3 ? [0, c, x] : h < 4 ? [0, x, c] : h < 5 ? [x, 0, c] : [c, 0, x];
    return [r1, g1, b1].map((v) => Math.round((v + m) * 255)) as Rgb;
  };
  // Mirror the lightness first (black becomes near white and the other way round), then go
  // further as far as needed.
  if (direction === 'lighter') {
    for (let lightness = Math.max(1 - l, 0.6); lightness <= 1; lightness += 0.05) {
      const candidate = fromHsl(lightness);
      if (contrast(candidate, background) >= MIN_CONTRAST) return candidate;
    }
    return [230, 224, 233];
  }
  for (let lightness = Math.min(1 - l, 0.4); lightness >= 0; lightness -= 0.05) {
    const candidate = fromHsl(lightness);
    if (contrast(candidate, background) >= MIN_CONTRAST) return candidate;
  }
  return [29, 27, 32];
}

/** A readable replacement for `color` on `background`, or null when it reads already. */
export function readable(color: Rgb, background: Rgb): Rgb | null {
  if (contrast(color, background) >= MIN_CONTRAST) return null;
  // On a mid-tone background light text may read as well as dark; take the better one.
  const light = lighten(color, background);
  const dark = darken(color, background);
  return contrast(light, background) >= contrast(dark, background) ? light : dark;
}

/**
 * Fixes faint text in a message shown on the dark `pageBackground`. Every element is judged
 * against the background really behind it: dark text on the page is lightened, and text left
 * light by the page's defaults on the message's own light backgrounds is darkened.
 */
export function adaptForDark(doc: Document, pageBackground: Rgb): void {
  const view = doc.defaultView;
  if (!view || !doc.body) return;
  // The background behind each element, inherited down the tree as it is walked.
  // `background` is null below a background image: its colours are unknown, so text there is
  // left as the message designed it.
  const walk = (element: Element, background: Rgb | null, budget: { left: number }) => {
    if (budget.left-- <= 0) return;
    const style = view.getComputedStyle(element);
    const own = parseColor(style.backgroundColor);
    const image = Boolean(style.backgroundImage) && style.backgroundImage !== 'none';
    const behind = own ?? (image ? null : background);
    const color = parseColor(style.color);
    // Only elements with text of their own; a wrapper's colour matters through its children.
    const hasText = Array.from(element.childNodes).some((node) => node.nodeType === 3 && node.textContent?.trim());
    const better = color && behind && hasText ? readable(color, behind) : null;
    if (better) (element as HTMLElement).style.setProperty('color', `rgb(${better[0]}, ${better[1]}, ${better[2]})`, 'important');
    for (const child of Array.from(element.children)) walk(child, behind, budget);
  };
  walk(doc.body, parseColor(view.getComputedStyle(doc.body).backgroundColor) ?? pageBackground, { left: MAX_ELEMENTS });
}
