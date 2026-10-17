
import { t, uiLocale } from '../i18n';// Date arithmetic and layout for the calendar views. Everything here is pure, so it can be
// tested without a browser.

export interface Calendar {
  id: number;
  slug: string;
  name: string;
  color: string;
  description: string;
  url: string;
  /** Shared by a colleague (`owner`) rather than one's own. */
  shared: boolean;
  owner: string;
  writable: boolean;
}

export interface Attendee {
  email: string;
  name: string;
  /** `needs-action`, `accepted`, `tentative` or `declined`. */
  status: string;
}

export interface Task {
  id: number;
  calendar_id: number;
  summary: string;
  description: string;
  /** `YYYY-MM-DD`, or empty. */
  due: string;
  completed: boolean;
}

/** One occurrence of an event, as the server expands it. Times are seconds since the epoch. */
export interface Occurrence {
  id: number;
  calendar_id: number;
  start: number;
  end: number;
  all_day: boolean;
  summary: string;
  location: string;
  description: string;
  recurring: boolean;
  recurrence_id: number | null;
  /** Address of whoever invited the guests; empty for an event without guests. */
  organizer: string;
  attendees: Attendee[];
}

/** An event as the editor and the server exchange it: wall-clock times in `timezone`. */
export interface EventForm {
  summary: string;
  description: string;
  location: string;
  start: string;
  end: string;
  all_day: boolean;
  timezone: string;
  rrule: string;
  /** Addresses of the people invited. */
  attendees: string[];
  /** Minutes before the start; `null` for no reminder. */
  reminder: number | null;
}

export type View = 'month' | 'week' | 'day' | 'agenda' | 'tasks';

const DAY = 86_400_000;
const pad = (n: number) => String(n).padStart(2, '0');

export function startOfDay(date: Date): Date {
  return new Date(date.getFullYear(), date.getMonth(), date.getDate());
}

/** Adds calendar days (not multiples of 24 hours, which drift across clock changes). */
export function addDays(date: Date, days: number): Date {
  return new Date(date.getFullYear(), date.getMonth(), date.getDate() + days, date.getHours(), date.getMinutes());
}

export function addMonths(date: Date, months: number): Date {
  const target = new Date(date.getFullYear(), date.getMonth() + months, 1);
  const last = new Date(target.getFullYear(), target.getMonth() + 1, 0).getDate();
  return new Date(target.getFullYear(), target.getMonth(), Math.min(date.getDate(), last));
}

/** Monday of the week containing `date`. */
export function startOfWeek(date: Date): Date {
  const day = startOfDay(date);
  return addDays(day, -((day.getDay() + 6) % 7));
}

export function sameDay(a: Date, b: Date): boolean {
  return a.getFullYear() === b.getFullYear() && a.getMonth() === b.getMonth() && a.getDate() === b.getDate();
}

/** `YYYY-MM-DD` in local time: the value of a date input, and a stable key for a day. */
export function dayKey(date: Date): string {
  return `${date.getFullYear()}-${pad(date.getMonth() + 1)}-${pad(date.getDate())}`;
}

/** `YYYY-MM-DDTHH:MM` in local time: the value of a datetime-local input. */
export function localInput(date: Date): string {
  return `${dayKey(date)}T${pad(date.getHours())}:${pad(date.getMinutes())}`;
}

/** The six weeks shown for the month of `date`, starting on a Monday. */
export function monthGrid(date: Date): Date[] {
  const first = startOfWeek(new Date(date.getFullYear(), date.getMonth(), 1));
  return Array.from({ length: 42 }, (_, index) => addDays(first, index));
}

/** The days a view shows, in order. */
export function daysOf(view: View, date: Date): Date[] {
  switch (view) {
    case 'month':
    case 'tasks':
      return monthGrid(date);
    case 'week':
      return Array.from({ length: 7 }, (_, index) => addDays(startOfWeek(date), index));
    case 'day':
      return [startOfDay(date)];
    case 'agenda':
      return Array.from({ length: 30 }, (_, index) => addDays(startOfDay(date), index));
  }
}

/** Moves the anchor date one page of the view forwards or backwards. */
export function shift(view: View, date: Date, direction: 1 | -1): Date {
  switch (view) {
    case 'month':
    case 'tasks':
      return addMonths(date, direction);
    case 'week':
      return addDays(date, 7 * direction);
    case 'day':
      return addDays(date, direction);
    case 'agenda':
      return addDays(date, 30 * direction);
  }
}

/**
 * The first and last local day an occurrence touches. All-day events are stored as UTC
 * midnights and mean calendar days wherever the reader is; timed events are placed in local time.
 */
export function daySpan(event: Pick<Occurrence, 'start' | 'end' | 'all_day'>): [Date, Date] {
  if (event.all_day) {
    const day = (seconds: number) => {
      const utc = new Date(seconds * 1000);
      return new Date(utc.getUTCFullYear(), utc.getUTCMonth(), utc.getUTCDate());
    };
    // The stored end is exclusive.
    const last = day(Math.max(event.start, event.end - 86_400));
    return [day(event.start), last];
  }
  const first = startOfDay(new Date(event.start * 1000));
  // An event ending at midnight does not reach into the next day.
  const last = startOfDay(new Date(Math.max(event.start, event.end - 1) * 1000));
  return [first, last];
}

export function onDay(event: Pick<Occurrence, 'start' | 'end' | 'all_day'>, day: Date): boolean {
  const [first, last] = daySpan(event);
  const at = startOfDay(day).getTime();
  return first.getTime() <= at && at <= last.getTime();
}

/** Whether an occurrence is shown in the all-day strip rather than on the time grid. */
export function isBanner(event: Pick<Occurrence, 'start' | 'end' | 'all_day'>): boolean {
  return event.all_day || (event.end - event.start) * 1000 >= DAY;
}

export interface Placement {
  /** Minutes from local midnight. */
  top: number;
  height: number;
  column: number;
  columns: number;
}

/**
 * Places the timed events of one day on the grid: events that overlap share the width,
 * side by side. Returns one placement per input event, in input order; `null` for events
 * that do not touch the day.
 */
export function layoutDay(events: Pick<Occurrence, 'start' | 'end'>[], day: Date): (Placement | null)[] {
  const from = startOfDay(day).getTime();
  const to = addDays(startOfDay(day), 1).getTime();
  const minutes = (to - from) / 60_000;
  const placed: (Placement | null)[] = events.map((event) => {
    const [start, end] = [event.start * 1000, event.end * 1000];
    if (start >= to || (end <= from && end !== start) || (end === start && start < from)) return null;
    const top = Math.max(0, (start - from) / 60_000);
    const bottom = Math.min(minutes, (end - from) / 60_000);
    // Short and zero-length events still need room for a line of text.
    return { top: Math.min(top, minutes - 20), height: Math.max(20, bottom - top), column: 0, columns: 1 };
  });
  const order = placed.map((_, index) => index).filter((index) => placed[index]).sort((a, b) => placed[a]!.top - placed[b]!.top || placed[b]!.height - placed[a]!.height);
  let cluster: number[] = [];
  let clusterEnd = -1;
  let columnEnds: number[] = [];
  const close = () => {
    for (const index of cluster) placed[index]!.columns = columnEnds.length;
    cluster = [];
    columnEnds = [];
  };
  for (const index of order) {
    const item = placed[index]!;
    if (cluster.length > 0 && item.top >= clusterEnd) close();
    let column = columnEnds.findIndex((end) => end <= item.top);
    if (column === -1) column = columnEnds.length;
    columnEnds[column] = item.top + item.height;
    item.column = column;
    cluster.push(index);
    clusterEnd = Math.max(clusterEnd, item.top + item.height);
  }
  close();
  return placed;
}

// --- Recurrence -----------------------------------------------------------------------------

export type Repeat = 'none' | 'daily' | 'weekdays' | 'weekly' | 'monthly' | 'yearly' | 'custom';

const RULES: Record<Exclude<Repeat, 'none' | 'custom'>, string> = {
  daily: 'FREQ=DAILY',
  weekdays: 'FREQ=WEEKLY;BYDAY=MO,TU,WE,TH,FR',
  weekly: 'FREQ=WEEKLY',
  monthly: 'FREQ=MONTHLY',
  yearly: 'FREQ=YEARLY',
};

export const REPEAT_LABELS: Record<Repeat, string> = {
  none: t('Does not repeat'),
  daily: t('Every day'),
  weekdays: t('Every weekday (Monday to Friday)'),
  weekly: t('Every week'),
  monthly: t('Every month'),
  yearly: t('Every year'),
  custom: t('Custom rule (kept as it is)'),
};

/** Splits a recurrence rule into what the editor offers: a preset and an optional last day. */
export function describeRule(rule: string): { repeat: Repeat; until: string } {
  const parts = rule.trim().toUpperCase().replace(/^RRULE:/, '').split(';').filter(Boolean);
  if (parts.length === 0) return { repeat: 'none', until: '' };
  const untilPart = parts.find((part) => part.startsWith('UNTIL='));
  const rest = parts.filter((part) => part !== untilPart).join(';');
  const match = (Object.keys(RULES) as (keyof typeof RULES)[]).find((key) => RULES[key] === rest);
  const stamp = untilPart?.slice(6).match(/^(\d{4})(\d{2})(\d{2})/);
  if (!match || (untilPart && !stamp)) return { repeat: 'custom', until: '' };
  return { repeat: match, until: stamp ? `${stamp[1]}-${stamp[2]}-${stamp[3]}` : '' };
}

/** Builds the rule for a preset. `until` is the last day (`YYYY-MM-DD`) on which the event may occur. */
export function buildRule(repeat: Repeat, until: string, allDay: boolean, custom = ''): string {
  if (repeat === 'none') return '';
  if (repeat === 'custom') return custom;
  const day = until.replaceAll('-', '');
  // The form of UNTIL has to match the start: a date for all-day events, UTC otherwise.
  const end = /^\d{8}$/.test(day) ? `;UNTIL=${allDay ? day : `${day}T235959Z`}` : '';
  return RULES[repeat] + end;
}

// --- Text ------------------------------------------------------------------------------------

export function formatTime(seconds: number, locale?: string): string {
  return new Intl.DateTimeFormat(locale ?? uiLocale(), { hour: 'numeric', minute: '2-digit' }).format(new Date(seconds * 1000));
}

/** "Tue, Oct 13, 12:00 PM – 1:00 PM", "Oct 20 – 21" for all-day events, and so on. */
export function formatSpan(event: Pick<Occurrence, 'start' | 'end' | 'all_day'>, locale?: string): string {
  const [first, last] = daySpan(event);
  const date = new Intl.DateTimeFormat(locale ?? uiLocale(), { weekday: 'short', month: 'short', day: 'numeric' });
  if (event.all_day) return sameDay(first, last) ? date.format(first) : `${date.format(first)} – ${date.format(last)}`;
  if (sameDay(first, last)) return `${date.format(first)}, ${formatTime(event.start, locale)} – ${formatTime(event.end, locale)}`;
  return `${date.format(first)}, ${formatTime(event.start, locale)} – ${date.format(last)}, ${formatTime(event.end, locale)}`;
}

/** The title of what is on screen; `brief` leaves out what a small screen has no room for. */
export function formatTitle(view: View, date: Date, locale?: string, brief = false): string {
  if (view === 'tasks') return t('Tasks');
  const month = brief ? 'short' : 'long';
  if (view === 'month') return new Intl.DateTimeFormat(locale ?? uiLocale(), { month, year: 'numeric' }).format(date);
  if (view === 'day') return new Intl.DateTimeFormat(locale ?? uiLocale(), brief ? { weekday: 'short', month, day: 'numeric' } : { weekday: 'long', month, day: 'numeric', year: 'numeric' }).format(date);
  const days = daysOf(view, date);
  const [first, last] = [days[0], days[days.length - 1]];
  const short = new Intl.DateTimeFormat(locale ?? uiLocale(), { month: 'short', day: 'numeric' });
  return brief ? `${short.format(first)} – ${short.format(last)}` : `${short.format(first)} – ${short.format(last)}, ${last.getFullYear()}`;
}

/** A new event starting at `at`: one hour long, or the whole day. */
export function draft(at: Date, allDay: boolean, timezone: string): EventForm {
  const end = new Date(at.getTime() + 3_600_000);
  return {
    summary: '',
    description: '',
    location: '',
    start: allDay ? dayKey(at) : localInput(at),
    end: allDay ? dayKey(at) : localInput(end),
    all_day: allDay,
    timezone,
    rrule: '',
    attendees: [],
    reminder: allDay ? null : 10,
  };
}

/** The lead times offered for a reminder, in minutes. */
export const REMINDERS = [0, 5, 10, 15, 30, 60, 120, 1440, 2880, 10080];

export function reminderLabel(minutes: number | null): string {
  if (minutes === null) return t('No reminder');
  if (minutes === 0) return t('At the start');
  if (minutes % 10080 === 0) return t('{{count}} weeks before', { count: minutes / 10080 });
  if (minutes % 1440 === 0) return t('{{count}} days before', { count: minutes / 1440 });
  if (minutes % 60 === 0) return t('{{count}} hours before', { count: minutes / 60 });
  return t('{{count}} minutes before', { count: minutes });
}

export const STATUS_LABELS: Record<string, string> = { accepted: t('accepted'), declined: t('declined'), tentative: t('maybe'), 'needs-action': t('no answer yet') };

/**
 * Whether a person is busy during `[start, end)`, given the busy periods the server reports.
 * `exclude` is the period of the event being edited, which is not a conflict with itself.
 */
export function conflicts(busy: { start: number; end: number }[], start: number, end: number, exclude?: { start: number; end: number }): boolean {
  return busy.some((period) => period.start < end && period.end > start && !(exclude && period.start >= exclude.start && period.end <= exclude.end));
}

/** Switches a form between all-day and timed, keeping the days. */
export function toggleAllDay(form: EventForm, allDay: boolean): EventForm {
  if (allDay === form.all_day) return form;
  if (allDay) return { ...form, all_day: true, start: form.start.slice(0, 10), end: form.end.slice(0, 10) };
  return { ...form, all_day: false, start: `${form.start.slice(0, 10)}T09:00`, end: `${form.end.slice(0, 10)}T10:00` };
}

export const COLORS = ['#1a73e8', '#d93025', '#188038', '#f9ab00', '#8430ce', '#e8710a', '#12858f', '#c2185b', '#5f6368'];
