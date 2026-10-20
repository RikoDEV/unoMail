import { describe, expect, it } from 'vitest';
import { detectMessageLanguage, translationSuggested } from './messageLanguage';

function message(text: string, html = false) {
  const part = { partId: 'body', blobId: '', size: text.length, type: html ? 'text/html' : 'text/plain' };
  return { textBody: html ? [] : [part], htmlBody: html ? [part] : [], bodyValues: { body: { value: text } } };
}

describe('translation suggestions', () => {
  it('compares detected message text with the user language, ignoring regional variants', () => {
    const english = detectMessageLanguage(message('Meeting Friday at 14:00. Please bring the report.'));
    expect(english).toBe('en');
    expect(translationSuggested(english, 'en-US')).toBe(false);
    expect(translationSuggested(english, 'pl')).toBe(true);
    const polish = detectMessageLanguage(message('Dzień dobry, nasze spotkanie odbędzie się w piątek o godzinie czternastej. Proszę przygotować raport i potwierdzić swoją obecność.'));
    expect(polish).toBe('pl');
    expect(translationSuggested(polish, 'pl-PL')).toBe(false);
    expect(translationSuggested(polish, 'en')).toBe(true);
  });

  it('detects HTML-only messages from their text rather than markup or URLs', () => {
    const french = detectMessageLanguage(message('<div class="the english language"><p>Bonjour, notre réunion aura lieu vendredi à quatorze heures. Merci de préparer le rapport et de confirmer votre présence.</p><a href="https://english.example.com">https://english.example.com</a></div>', true));
    expect(french).toBe('fr');
    expect(translationSuggested(french, 'en')).toBe(true);
    expect(translationSuggested(french, 'fr-CA')).toBe(false);
  });

  it('does not suggest translation for unknown, empty or insufficient text', () => {
    for (const text of ['', 'OK!', '1234 5678 9012', 'https://example.com/long-address-for-a-document']) {
      const language = detectMessageLanguage(message(text));
      expect(language).toBeNull();
      expect(translationSuggested(language, 'en')).toBe(false);
    }
  });
});
