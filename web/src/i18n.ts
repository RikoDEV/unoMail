// Interface language. The English text itself is the key (`t('Report spam')`), so a string
// without a translation simply shows in English. Translations live in locales/<code>.json;
// English needs a file only for plural forms.
//
// The language is fixed for the lifetime of the page: choosing another one reloads it. That
// lets `t()` be a plain function usable anywhere, including module-level constants. English is
// built in; another language is fetched by loadInterfaceLanguage() before the app's modules
// are loaded (see main.tsx), so only its users download it.

import i18next from 'i18next';
import en from './locales/en.json';

import { readLocal, writeLocal } from './storage';
export const LANGUAGES: { code: string; name: string }[] = [
  { code: 'en', name: 'English' },
  { code: 'pl', name: 'Polski' },
  { code: 'de', name: 'Deutsch' },
  { code: 'fr', name: 'Français' },
  { code: 'cs', name: 'Čeština' },
  { code: 'sk', name: 'Slovenčina' },
];
const TRANSLATIONS = import.meta.glob<Record<string, string>>(['./locales/*.json', '!./locales/en.json'], { import: 'default' });
const STORAGE_KEY = 'unomail.language';

const storedChoice = () => readLocal(STORAGE_KEY);

const supported = (code: string | null | undefined): code is string => Boolean(code && LANGUAGES.some((language) => language.code === code));

/** The language chosen on this device, or the browser's preferred supported language. */
function preferredLanguage(): string {
  const chosen = storedChoice();
  if (supported(chosen)) return chosen;
  const wanted = typeof navigator === 'undefined' ? [] : navigator.languages?.length ? navigator.languages : [navigator.language];
  for (const tag of wanted) {
    const code = tag?.toLowerCase().split('-')[0];
    if (supported(code)) return code;
  }
  return 'en';
}

void i18next.init({
  lng: 'en',
  fallbackLng: 'en',
  resources: { en: { translation: en } },
  // Keys are sentences: dots and colons in them are text, not paths or namespaces.
  keySeparator: false,
  nsSeparator: false,
  // React escapes what it renders; escaping here would show "&amp;".
  interpolation: { escapeValue: false },
  returnEmptyString: false,
  initAsync: false,
});

/** Switches to the preferred language, fetching its translations first. Called once at start-up. */
export async function loadInterfaceLanguage(): Promise<void> {
  const code = preferredLanguage();
  const load = TRANSLATIONS[`./locales/${code}.json`];
  if (code !== 'en' && load) {
    try {
      i18next.addResourceBundle(code, 'translation', await load());
      await i18next.changeLanguage(code);
    } catch {
      /* not reachable (offline, outdated page): the interface stays in English */
    }
  }
  if (typeof document !== 'undefined') document.documentElement.lang = i18next.language;
}

/** Translates an English text; `{{name}}` placeholders are filled from `values`. */
export function t(key: string, values?: Record<string, unknown>): string {
  return i18next.t(key, values ?? {}) as string;
}

/** The current interface language (a code from LANGUAGES). */
export function currentLanguage(): string {
  return i18next.language;
}

/** The choice stored on this device, or null when following the browser. */
export function chosenLanguage(): string | null {
  const chosen = storedChoice();
  return supported(chosen) ? chosen : null;
}

/**
 * Switches the interface language (null: follow the browser). Reloads the page when the
 * language actually changes; returns whether it did.
 */
export function setLanguage(code: string | null): boolean {
  // Without storage the choice lasts for this page only.
  writeLocal(STORAGE_KEY, code && supported(code) ? code : null);
  const next = code && supported(code) ? code : preferredLanguage();
  if (next === i18next.language) return false;
  window.location.reload();
  return true;
}

/**
 * The locale for dates and numbers: the browser's own (with its regional conventions) when it
 * is in the interface language, otherwise the interface language itself.
 */
export function uiLocale(): string {
  const browser = typeof navigator === 'undefined' ? '' : navigator.language;
  return browser && browser.toLowerCase().split('-')[0] === i18next.language ? browser : i18next.language;
}
