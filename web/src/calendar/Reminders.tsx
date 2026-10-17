import NotificationsActive from '@mui/icons-material/NotificationsActive';
import { Alert, Snackbar, Stack } from '@mui/material';
import { useEffect, useRef, useState } from 'react';
import { get, put } from '../api';
import { loadPrefs, type Prefs } from '../prefs';
import { formatTime } from './dates';

import { t, uiLocale } from '../i18n';
import { readLocalJson, writeLocal } from '../storage';
interface Reminder {
  id: number;
  calendar_id: number;
  /** When the reminder is due, seconds since the epoch. */
  at: number;
  start: number;
  all_day: boolean;
  summary: string;
  location: string;
}

const POLL_SECONDS = 300;
const FIRED_KEY = 'unomail.reminders.fired';

/** Reminders already shown (in any tab of this browser), so that none is shown twice. */
function fired(): Record<string, number> {
  return readLocalJson<Record<string, number>>(FIRED_KEY, {});
}

// Without storage a reminder may show again in another tab; better than not at all.
function markFired(key: string, at: number) {
  const cutoff = Date.now() / 1000 - 2 * 86_400;
  const kept = Object.fromEntries(Object.entries(fired()).filter(([, when]) => when > cutoff));
  writeLocal(FIRED_KEY, JSON.stringify({ ...kept, [key]: at }));
}

export function describeReminder(reminder: Pick<Reminder, 'start' | 'all_day' | 'location'>, now = Date.now() / 1000): string {
  const minutes = Math.round((reminder.start - now) / 60);
  const when = reminder.all_day ? t('Starts today') : minutes <= 0 ? t('Starts now') : minutes < 60 ? t('Starts in {{count}} minutes', { count: minutes }) : t('Starts at {{time}}', { time: formatTime(reminder.start) });
  return reminder.location ? `${when} · ${reminder.location}` : when;
}

/**
 * Announces the reminders of calendar events while the web client is open: as a message on
 * the page, and as a desktop notification where the user allowed those. Mounted once for
 * the whole application. It also tells the server the browser's time zone.
 */
export function Reminders() {
  const [shown, setShown] = useState<Reminder[]>([]);
  const scheduled = useRef(new Map<string, ReturnType<typeof setTimeout>>());

  useEffect(() => {
    // The server needs the zone to place calendar times that name none.
    const zone = Intl.DateTimeFormat(uiLocale()).resolvedOptions().timeZone;
    if (zone) {
      get<Prefs>('/api/me/preferences')
        .then((prefs) => (prefs.timezone === zone ? undefined : put('/api/me/preferences', { ...prefs, timezone: zone }).then(() => loadPrefs())))
        .catch(() => {});
    }
  }, []);

  useEffect(() => {
    const timers = scheduled.current;
    let stopped = false;

    function fire(reminder: Reminder, key: string) {
      timers.delete(key);
      if (stopped || fired()[key]) return;
      markFired(key, reminder.at);
      setShown((current) => [...current.filter((entry) => `${entry.id}:${entry.at}` !== key), reminder]);
      if (typeof Notification !== 'undefined' && Notification.permission === 'granted') {
        try {
          new Notification(reminder.summary || t('Event'), { body: describeReminder(reminder), tag: key });
        } catch {
          // Some browsers only allow notifications from a service worker; the page shows it anyway.
        }
      }
    }

    async function poll() {
      const now = Math.floor(Date.now() / 1000);
      try {
        // A little into the past, for reminders that fell due while the computer slept.
        const list = await get<Reminder[]>(`/api/me/calendars/reminders?from=${now - 600}&to=${now + POLL_SECONDS + 60}`);
        const done = fired();
        for (const reminder of list) {
          const key = `${reminder.id}:${reminder.at}`;
          if (stopped || done[key] || timers.has(key)) continue;
          timers.set(key, setTimeout(() => fire(reminder, key), Math.max(0, reminder.at * 1000 - Date.now())));
        }
      } catch {
        // Offline or signed out: try again at the next round.
      }
    }

    void poll();
    const interval = setInterval(() => void poll(), POLL_SECONDS * 1000);
    const onFocus = () => void poll();
    window.addEventListener('focus', onFocus);
    return () => {
      stopped = true;
      clearInterval(interval);
      window.removeEventListener('focus', onFocus);
      timers.forEach((timer) => clearTimeout(timer));
      timers.clear();
    };
  }, []);

  return (
    <Snackbar open={shown.length > 0} anchorOrigin={{ vertical: 'top', horizontal: 'right' }}>
      <Stack spacing={1}>
        {shown.map((reminder) => (
          <Alert
            key={`${reminder.id}:${reminder.at}`}
            severity="info"
            variant="filled"
            icon={<NotificationsActive fontSize="inherit" />}
            role="alert"
            onClose={() => setShown((current) => current.filter((entry) => entry !== reminder))}
          >
            <strong>{reminder.summary || t('Event')}</strong>
            <br />
            {describeReminder(reminder)}
          </Alert>
        ))}
      </Stack>
    </Snackbar>
  );
}
