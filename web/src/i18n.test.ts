import i18next from 'i18next';
import { readdirSync, readFileSync, statSync } from 'node:fs';
import { join } from 'node:path';
import { describe, expect, it } from 'vitest';
import { t } from './i18n';
import { SERVER_TEXTS } from './admin/serverTexts';
import { SERVER_ERRORS } from './lib/serverErrors';
import en from './locales/en.json';
import cs from './locales/cs.json';
import de from './locales/de.json';
import fr from './locales/fr.json';
import pl from './locales/pl.json';
import sk from './locales/sk.json';

const translations: Record<string, Record<string, string>> = { pl, de, fr, cs, sk };
/** The plural suffixes i18next looks up for a language, e.g. `_one`, `_other`. */
const pluralForms = (language: string) => new Intl.PluralRules(language).resolvedOptions().pluralCategories.map((form) => `_${form}`);

function sources(dir: string): string[] {
  return readdirSync(dir).flatMap((name) => {
    const path = join(dir, name);
    if (statSync(path).isDirectory()) return sources(path);
    return /\.tsx?$/.test(name) && !/\.test\.|\.d\.ts$/.test(name) ? [path] : [];
  });
}

/** Every literal key passed to t() in the web client, and the texts the server sends. */
function usedKeys(): Set<string> {
  const keys = new Set<string>([...SERVER_TEXTS, ...SERVER_ERRORS]);
  for (const file of sources(join(__dirname))) {
    const code = readFileSync(file, 'utf8');
    for (const match of code.matchAll(/\bt\(\s*(?:'((?:[^'\\]|\\.)*)'|"((?:[^"\\]|\\.)*)")/g)) {
      const raw = match[1] ?? match[2];
      keys.add(match[1] !== undefined ? raw.replace(/\\'/g, "'").replace(/\\\\/g, '\\') : JSON.parse(`"${raw}"`));
    }
  }
  return keys;
}

const placeholders = (text: string) => [...text.matchAll(/\{\{(\w+)\}\}/g)].map((m) => m[1]).filter((name) => name !== 'count').sort();
const base = (key: string) => key.replace(/_(one|few|many|other|folder)$/, '');

describe('translations', () => {
  it('cover every text of the interface', () => {
    for (const [language, table] of Object.entries(translations)) {
      const forms = pluralForms(language);
      const missing = [...usedKeys()].filter((key) => !(key in table) && !forms.every((form) => key + form in table));
      expect(missing, `untranslated in ${language}`).toEqual([]);
    }
  });

  it('keep the placeholders and give plurals every form', () => {
    for (const table of [en, ...Object.values(translations)]) {
      for (const [key, value] of Object.entries(table)) {
        expect(placeholders(value), key).toEqual(placeholders(base(key)));
      }
    }
    for (const [language, table] of Object.entries(translations)) {
      const pluralKeys = new Set(Object.keys(table).filter((key) => /_(one|few|many|other)$/.test(key)).map(base));
      for (const key of pluralKeys) {
        for (const form of pluralForms(language)) expect(table, `${language}: ${key}${form}`).toHaveProperty([key + form]);
        expect(en, `${key}_one`).toHaveProperty([`${key}_one`]);
      }
    }
  });

  it('fill placeholders and choose plural forms', () => {
    expect(t('Moved to {{value}}', { value: 'Inbox' })).toBe('Moved to Inbox');
    expect(t('{{count}} members', { count: 1 })).toBe('1 member');
    expect(t('{{count}} members', { count: 3 })).toBe('3 members');
    expect(t('A text without a translation')).toBe('A text without a translation');

    // Another language, on a copy: the shared instance stays in English for the other tests.
    // In the app loadInterfaceLanguage() fetches the bundle; here it is added directly.
    i18next.addResourceBundle('pl', 'translation', pl);
    const polish = i18next.cloneInstance({ lng: 'pl' });
    const tp = (key: string, values: Record<string, unknown> = {}) => polish.t(key, values) as string;
    expect(tp('Report spam')).toBe('Zgłoś spam');
    expect(tp('{{count}} members', { count: 1 })).toBe('1 członek');
    expect(tp('{{count}} members', { count: 3 })).toBe('3 członków');
    expect(tp('{{count}} conversations archived', { count: 2 })).toBe('Zarchiwizowano 2 wątki');
    expect(tp('{{count}} conversations archived', { count: 5 })).toBe('Zarchiwizowano 5 wątków');
    expect(tp('Sent', { context: 'folder' })).toBe('Wysłane');
    expect(tp('A text without a translation')).toBe('A text without a translation');
    // Values are inserted as they are; React escapes them when rendering.
    expect(tp('Moved to {{value}}', { value: '<b>x</b>' })).toBe('Przeniesiono do: <b>x</b>');
  });
});
