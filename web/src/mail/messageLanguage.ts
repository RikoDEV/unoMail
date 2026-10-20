import { detectAll } from 'tinyld';
import { htmlToText, type EmailFull } from './jmapClient';

/** Identify readable message text locally; no email is sent to a language service. */
export function detectMessageLanguage(email: Pick<EmailFull, 'textBody' | 'htmlBody' | 'bodyValues'>): string | null {
  const plain = email.textBody.map((part) => email.bodyValues[part.partId]?.value ?? '').join('\n');
  const text = plain.trim() ? plain : email.htmlBody.map((part) => htmlToText(email.bodyValues[part.partId]?.value ?? '')).join('\n');
  const sample = text.slice(0, 8000).replace(/https?:\/\/\S+|\b\S+@\S+\b/gi, ' ').trim();
  // Names, codes and very short replies do not provide enough evidence to suggest translation.
  if ((sample.match(/\p{L}/gu)?.length ?? 0) < 20) return null;
  const [first, second] = detectAll(sample);
  if (!first || first.accuracy < 0.6 || first.accuracy - (second?.accuracy ?? 0) < 0.2) return null;
  return first.lang;
}

export function translationSuggested(source: string | null, userLanguage: string): boolean {
  const primary = (tag: string) => tag.toLowerCase().split(/[-_]/)[0];
  return Boolean(source && primary(source) !== primary(userLanguage));
}
