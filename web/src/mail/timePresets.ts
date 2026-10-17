
import { t } from '../i18n';// Suggested times for scheduling a message or snoozing one, relative to now.

export interface Preset {
  label: string;
  at: Date;
}

function at(base: Date, daysAhead: number, hour: number): Date {
  const date = new Date(base);
  date.setDate(date.getDate() + daysAhead);
  date.setHours(hour, 0, 0, 0);
  return date;
}

/** Days until the next `weekday` (0 = Sunday), at least one. */
function untilWeekday(now: Date, weekday: number): number {
  const days = (weekday - now.getDay() + 7) % 7;
  return days === 0 ? 7 : days;
}

/** When to send a scheduled message: tomorrow morning, tomorrow afternoon, next Monday. */
export function schedulePresets(now: Date): Preset[] {
  return [
    { label: t('Tomorrow morning'), at: at(now, 1, 8) },
    { label: t('Tomorrow afternoon'), at: at(now, 1, 13) },
    { label: t('Monday morning'), at: at(now, untilWeekday(now, 1), 8) },
  ];
}

/** When a snoozed message should come back. "Later today" only while the day lasts. */
export function snoozePresets(now: Date): Preset[] {
  const presets: Preset[] = [];
  const later = new Date(now.getTime() + 3 * 3600 * 1000);
  if (later.getDate() === now.getDate() && now.getHours() < 18) presets.push({ label: t('Later today'), at: now.getHours() < 15 ? at(now, 0, 18) : later });
  presets.push({ label: t('Tomorrow'), at: at(now, 1, 8) });
  // Weekend: Saturday morning, unless it is the weekend already.
  if (now.getDay() >= 1 && now.getDay() <= 5) presets.push({ label: t('This weekend'), at: at(now, untilWeekday(now, 6), 8) });
  presets.push({ label: t('Next week'), at: at(now, untilWeekday(now, 1), 8) });
  return presets;
}
