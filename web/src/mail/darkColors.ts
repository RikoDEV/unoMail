// Readable mail in the dark theme. A message shown on the dark page may set its own text
// colours (black, dark grey, a dark brand colour) that vanish there. After it loads, each
// element's text is checked against the background really behind it, and only text too faint
// to read is lightened, keeping its hue. Text on the message's own light backgrounds (a white
// newsletter card) already reads well and stays as it was designed.

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
  // Mirror the lightness first (black becomes near white), then go lighter as far as needed.
  for (let lightness = Math.max(1 - l, 0.6); lightness <= 1; lightness += 0.05) {
    const candidate = fromHsl(lightness);
    if (contrast(candidate, background) >= MIN_CONTRAST) return candidate;
  }
  return [230, 224, 233];
}

/**
 * Lightens faint text in a message shown on the dark `pageBackground`. Elements whose own
 * background the message set are judged against that background, so light designs keep
 * their dark text.
 */
export function adaptForDark(doc: Document, pageBackground: Rgb): void {
  const view = doc.defaultView;
  if (!view || !doc.body) return;
  // The background behind each element, inherited down the tree as it is walked.
  const walk = (element: Element, background: Rgb, budget: { left: number }) => {
    if (budget.left-- <= 0) return;
    const style = view.getComputedStyle(element);
    const own = parseColor(style.backgroundColor);
    const behind = own ?? background;
    const color = parseColor(style.color);
    // Only elements with text of their own; a wrapper's colour matters through its children.
    const hasText = Array.from(element.childNodes).some((node) => node.nodeType === 3 && node.textContent?.trim());
    if (color && hasText && contrast(color, behind) < MIN_CONTRAST && luminance(behind) < 0.2) {
      const [r, g, b] = lighten(color, behind);
      (element as HTMLElement).style.setProperty('color', `rgb(${r}, ${g}, ${b})`, 'important');
    }
    for (const child of Array.from(element.children)) walk(child, behind, budget);
  };
  walk(doc.body, parseColor(view.getComputedStyle(doc.body).backgroundColor) ?? pageBackground, { left: MAX_ELEMENTS });
}
