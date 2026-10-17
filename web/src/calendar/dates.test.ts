import { describe, expect, it } from 'vitest';
import {
  addMonths, buildRule, conflicts, dayKey, daySpan, daysOf, describeRule, draft, formatTitle, isBanner, layoutDay, monthGrid, onDay, reminderLabel, shift, startOfWeek, toggleAllDay,
} from './dates';

const local = (year: number, month: number, day: number, hour = 0, minute = 0) => new Date(year, month - 1, day, hour, minute);
const seconds = (date: Date) => Math.floor(date.getTime() / 1000);
const utcDay = (year: number, month: number, day: number) => Date.UTC(year, month - 1, day) / 1000;

describe('calendar dates', () => {
  it('lays a month out as six weeks from a Monday', () => {
    const grid = monthGrid(local(2026, 10, 13));
    expect(grid).toHaveLength(42);
    expect(dayKey(grid[0])).toBe('2026-09-28');
    expect(dayKey(grid[41])).toBe('2026-11-08');
    expect(grid.every((day, index) => day.getDay() === (index + 1) % 7)).toBe(true);
    expect(dayKey(startOfWeek(local(2026, 10, 18)))).toBe('2026-10-12'); // a Sunday belongs to the week before
    expect(dayKey(startOfWeek(local(2026, 10, 12)))).toBe('2026-10-12');
  });

  it('pages through the views', () => {
    expect(dayKey(shift('month', local(2026, 1, 31), 1))).toBe('2026-02-28'); // clamped, not March 3rd
    expect(dayKey(addMonths(local(2026, 12, 15), 1))).toBe('2027-01-15');
    expect(dayKey(shift('week', local(2026, 10, 13), -1))).toBe('2026-10-06');
    expect(dayKey(shift('day', local(2026, 10, 31), 1))).toBe('2026-11-01');
    expect(daysOf('week', local(2026, 10, 13)).map(dayKey)).toEqual(['2026-10-12', '2026-10-13', '2026-10-14', '2026-10-15', '2026-10-16', '2026-10-17', '2026-10-18']);
    expect(daysOf('agenda', local(2026, 10, 13))).toHaveLength(30);
    expect(formatTitle('month', local(2026, 10, 13), 'en-US')).toBe('October 2026');
    expect(formatTitle('week', local(2026, 10, 13), 'en-US')).toBe('Oct 12 – Oct 18, 2026');
    expect(formatTitle('month', local(2026, 10, 13), 'en-US', true)).toBe('Oct 2026');
    expect(formatTitle('week', local(2026, 10, 13), 'en-US', true)).toBe('Oct 12 – Oct 18');
  });

  it('places all-day events on calendar days whatever the local time zone', () => {
    // Stored as UTC midnights with an exclusive end: 20 and 21 October.
    const conference = { start: utcDay(2026, 10, 20), end: utcDay(2026, 10, 22), all_day: true };
    expect(daySpan(conference).map(dayKey)).toEqual(['2026-10-20', '2026-10-21']);
    expect(onDay(conference, local(2026, 10, 19))).toBe(false);
    expect(onDay(conference, local(2026, 10, 20, 15))).toBe(true);
    expect(onDay(conference, local(2026, 10, 21))).toBe(true);
    expect(onDay(conference, local(2026, 10, 22))).toBe(false);
    expect(isBanner(conference)).toBe(true);
    const single = { start: utcDay(2026, 10, 20), end: utcDay(2026, 10, 21), all_day: true };
    expect(daySpan(single).map(dayKey)).toEqual(['2026-10-20', '2026-10-20']);
  });

  it('places timed events in local time', () => {
    const lunch = { start: seconds(local(2026, 10, 13, 12)), end: seconds(local(2026, 10, 13, 13)), all_day: false };
    expect(daySpan(lunch).map(dayKey)).toEqual(['2026-10-13', '2026-10-13']);
    expect(isBanner(lunch)).toBe(false);
    // Ending exactly at midnight does not spill into the next day.
    const evening = { start: seconds(local(2026, 10, 13, 22)), end: seconds(local(2026, 10, 14, 0)), all_day: false };
    expect(onDay(evening, local(2026, 10, 14))).toBe(false);
    const overnight = { start: seconds(local(2026, 10, 13, 22)), end: seconds(local(2026, 10, 14, 2)), all_day: false };
    expect(onDay(overnight, local(2026, 10, 14))).toBe(true);
    expect(isBanner({ start: seconds(local(2026, 10, 13, 8)), end: seconds(local(2026, 10, 15, 8)), all_day: false })).toBe(true);
  });

  it('lays overlapping events side by side', () => {
    const day = local(2026, 10, 13);
    const at = (h1: number, m1: number, h2: number, m2: number) => ({ start: seconds(local(2026, 10, 13, h1, m1)), end: seconds(local(2026, 10, 13, h2, m2)) });
    const placed = layoutDay([at(9, 0, 10, 0), at(9, 30, 10, 30), at(10, 0, 11, 0), at(14, 0, 15, 0), { start: seconds(local(2026, 10, 14, 9)), end: seconds(local(2026, 10, 14, 10)) }], day);
    expect(placed[0]).toEqual({ top: 540, height: 60, column: 0, columns: 2 });
    expect(placed[1]).toEqual({ top: 570, height: 60, column: 1, columns: 2 });
    expect(placed[2]).toEqual({ top: 600, height: 60, column: 0, columns: 2 }); // reuses the freed column
    expect(placed[3]).toEqual({ top: 840, height: 60, column: 0, columns: 1 }); // alone again: full width
    expect(placed[4]).toBeNull(); // another day

    // An event running over midnight is clipped to the day; a zero-length one still gets a line.
    const [overnight, instant] = layoutDay([{ start: seconds(local(2026, 10, 12, 22)), end: seconds(local(2026, 10, 13, 2)) }, at(18, 0, 18, 0)], day);
    expect(overnight).toMatchObject({ top: 0, height: 120 });
    expect(instant).toMatchObject({ top: 1080, height: 20 });
    expect(layoutDay([at(23, 55, 23, 59)], day)[0]).toMatchObject({ top: 1420, height: 20 }); // stays inside the day
  });

  it('translates between recurrence rules and the editor', () => {
    expect(describeRule('')).toEqual({ repeat: 'none', until: '' });
    expect(describeRule('FREQ=WEEKLY')).toEqual({ repeat: 'weekly', until: '' });
    expect(describeRule('RRULE:freq=weekly;byday=mo,tu,we,th,fr')).toEqual({ repeat: 'weekdays', until: '' });
    expect(describeRule('FREQ=DAILY;UNTIL=20261231T235959Z')).toEqual({ repeat: 'daily', until: '2026-12-31' });
    // Anything the editor cannot express is left alone rather than simplified.
    expect(describeRule('FREQ=MONTHLY;BYDAY=2TU')).toEqual({ repeat: 'custom', until: '' });
    expect(describeRule('FREQ=WEEKLY;COUNT=6')).toEqual({ repeat: 'custom', until: '' });

    expect(buildRule('none', '2026-12-31', false)).toBe('');
    expect(buildRule('monthly', '', false)).toBe('FREQ=MONTHLY');
    expect(buildRule('daily', '2026-12-31', false)).toBe('FREQ=DAILY;UNTIL=20261231T235959Z');
    expect(buildRule('yearly', '2030-01-01', true)).toBe('FREQ=YEARLY;UNTIL=20300101');
    expect(buildRule('weekly', 'garbage', false)).toBe('FREQ=WEEKLY');
    expect(buildRule('custom', '', false, 'FREQ=MONTHLY;BYDAY=2TU')).toBe('FREQ=MONTHLY;BYDAY=2TU');
    for (const rule of ['FREQ=DAILY;UNTIL=20261231T235959Z', 'FREQ=WEEKLY;BYDAY=MO,TU,WE,TH,FR']) {
      const { repeat, until } = describeRule(rule);
      expect(buildRule(repeat, until, false)).toBe(rule);
    }
  });

  it('prepares new events', () => {
    expect(draft(local(2026, 10, 13, 9), false, 'Europe/Warsaw')).toMatchObject({ start: '2026-10-13T09:00', end: '2026-10-13T10:00', all_day: false, timezone: 'Europe/Warsaw', rrule: '' });
    expect(draft(local(2026, 10, 13, 23, 30), false, 'UTC')).toMatchObject({ start: '2026-10-13T23:30', end: '2026-10-14T00:30' });
    expect(draft(local(2026, 10, 13, 9), true, 'UTC')).toMatchObject({ start: '2026-10-13', end: '2026-10-13', all_day: true });
    const timed = draft(local(2026, 10, 13, 15), false, 'UTC');
    const whole = toggleAllDay(timed, true);
    expect(whole).toMatchObject({ start: '2026-10-13', end: '2026-10-13', all_day: true });
    expect(toggleAllDay(whole, false)).toMatchObject({ start: '2026-10-13T09:00', end: '2026-10-13T10:00', all_day: false });
    expect(toggleAllDay(timed, false)).toBe(timed);
    expect(timed.reminder).toBe(10);
    expect(whole.attendees).toEqual([]);
    expect(draft(local(2026, 10, 13, 9), true, 'UTC').reminder).toBeNull();
  });

  it('names reminders and finds conflicts', () => {
    expect([null, 0, 1, 10, 60, 120, 1440, 2880, 10080, 90].map(reminderLabel)).toEqual(['No reminder', 'At the start', '1 minute before', '10 minutes before', '1 hour before', '2 hours before', '1 day before', '2 days before', '1 week before', '90 minutes before']);
    const busy = [{ start: 100, end: 200 }, { start: 300, end: 400 }];
    expect(conflicts(busy, 150, 160)).toBe(true);
    expect(conflicts(busy, 200, 300)).toBe(false); // back to back is fine
    expect(conflicts(busy, 0, 1000)).toBe(true);
    expect(conflicts([], 0, 1000)).toBe(false);
    // The event being edited does not collide with itself.
    expect(conflicts(busy, 100, 200, { start: 100, end: 200 })).toBe(false);
    expect(conflicts(busy, 100, 350, { start: 100, end: 200 })).toBe(true);
  });
});
