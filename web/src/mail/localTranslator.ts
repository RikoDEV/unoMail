// On-device translation through the browser's built-in Translator API (Chrome and Edge on
// desktop). It is offered when no AI model is configured: the message never leaves the
// device, and the browser downloads its language pack on first use.

interface Translator {
  translate(text: string, options?: { signal?: AbortSignal }): Promise<string>;
  destroy(): void;
}
interface TranslatorFactory {
  availability(options: { sourceLanguage: string; targetLanguage: string }): Promise<'unavailable' | 'downloadable' | 'downloading' | 'available'>;
  create(options: { sourceLanguage: string; targetLanguage: string; signal?: AbortSignal; monitor?: (monitor: EventTarget) => void }): Promise<Translator>;
}

const factory = (): TranslatorFactory | undefined => (globalThis as { Translator?: TranslatorFactory }).Translator;

export const localTranslationSupported = () => Boolean(factory());

/** Whether the browser can translate this language pair, possibly after a download. */
export async function canTranslateLocally(source: string, target: string): Promise<boolean> {
  const api = factory();
  if (!api) return false;
  try {
    return (await api.availability({ sourceLanguage: source, targetLanguage: target })) !== 'unavailable';
  } catch {
    return false;
  }
}

// The browser gives no error when a language-pack download stalls or a call never settles, so
// a step that shows no sign of life for this long is abandoned instead of spinning forever.
const STALL_MS = 60_000;

/**
 * Translates paragraph by paragraph, keeping each under the per-call input limit; `onProgress` gets the download share.
 * The translator is created before `text` settles: a download needs the click's user activation, which an await can outlast.
 */
export async function translateLocally(text: string | Promise<string>, source: string, target: string, signal: AbortSignal, onProgress?: (share: number) => void): Promise<string> {
  const api = factory();
  if (!api) throw new Error('unsupported');
  const stall = new AbortController();
  const combined = AbortSignal.any([signal, stall.signal]);
  let timer = 0;
  const alive = () => { clearTimeout(timer); timer = window.setTimeout(() => stall.abort(new Error('stalled')), STALL_MS); };
  alive();
  try {
    const translator = await api.create({
      sourceLanguage: source,
      targetLanguage: target,
      signal: combined,
      monitor: (monitor) => monitor.addEventListener('downloadprogress', (event) => { alive(); onProgress?.((event as Event & { loaded: number }).loaded); }),
    });
    try {
      const out: string[] = [];
      for (const paragraph of (await text).split(/(\n\s*\n)/)) {
        alive();
        out.push(paragraph.trim() ? await translator.translate(paragraph, { signal: combined }) : paragraph);
      }
      return out.join('');
    } finally {
      translator.destroy();
    }
  } catch (err) {
    // A message-less error lets the caller show its own localized failure text.
    if (stall.signal.aborted && !signal.aborted) throw new Error();
    throw err;
  } finally {
    clearTimeout(timer);
  }
}
