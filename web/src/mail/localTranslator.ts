// On-device translation through the browser's built-in Translator API (Chrome and Edge on
// desktop). It is offered when no AI model is configured: the message never leaves the
// device, and the browser downloads its language pack on first use.

interface Translator {
  translate(text: string): Promise<string>;
  destroy(): void;
}
interface TranslatorFactory {
  availability(options: { sourceLanguage: string; targetLanguage: string }): Promise<'unavailable' | 'downloadable' | 'downloading' | 'available'>;
  create(options: { sourceLanguage: string; targetLanguage: string; monitor?: (monitor: EventTarget) => void }): Promise<Translator>;
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

/** Translates paragraph by paragraph, keeping each under the per-call input limit; `onProgress` gets the download share. */
export async function translateLocally(text: string, source: string, target: string, onProgress?: (share: number) => void): Promise<string> {
  const api = factory();
  if (!api) throw new Error('unsupported');
  const translator = await api.create({
    sourceLanguage: source,
    targetLanguage: target,
    monitor: (monitor) => monitor.addEventListener('downloadprogress', (event) => onProgress?.((event as Event & { loaded: number }).loaded)),
  });
  try {
    const out: string[] = [];
    for (const paragraph of text.split(/(\n\s*\n)/)) out.push(paragraph.trim() ? await translator.translate(paragraph) : paragraph);
    return out.join('');
  } finally {
    translator.destroy();
  }
}
