import Event from '@mui/icons-material/Event';
import EventAvailable from '@mui/icons-material/EventAvailable';
import EventBusy from '@mui/icons-material/EventBusy';
import { Box, Button, Paper, Stack, Typography } from '@mui/material';
import { useEffect, useState } from 'react';
import { get, post, postRaw, errorText } from '../api';
import { STATUS_LABELS, formatSpan, type Attendee } from './dates';

import { t } from '../i18n';
interface Inspected {
  method: string;
  summary: string;
  location: string;
  start: number | null;
  end: number | null;
  all_day: boolean;
  recurring: boolean;
  organizer: string | null;
  attendees: Attendee[];
  stored: boolean;
  my_status: string | null;
  /** The reader organized this event. */
  own: boolean;
}

const ANSWERS: [string, string][] = [['accepted', t('Accept')], ['tentative', t('Maybe')], ['declined', t('Decline')]];

/**
 * What a calendar file attached to a message means, with the fitting action: answering an
 * invitation, or adding a plain event to the calendar. Answers to one's own invitations and
 * cancellations were applied when the message arrived; they are only explained here.
 */
export function Invitation({ name, url }: { name: string; url: string }) {
  const [ics, setIcs] = useState('');
  const [info, setInfo] = useState<Inspected | null>(null);
  const [notice, setNotice] = useState('');
  const [busy, setBusy] = useState(false);

  useEffect(() => {
    let cancelled = false;
    (async () => {
      const text = await (await fetch(url, { credentials: 'same-origin' })).text();
      const inspected = await postRaw<Inspected>('/api/me/calendars/invitations/inspect', new Blob([text], { type: 'text/calendar' }));
      if (!cancelled) {
        setIcs(text);
        setInfo(inspected);
      }
    })().catch(() => {
      // Not calendar data after all: the attachment stays an ordinary download.
    });
    return () => {
      cancelled = true;
    };
  }, [url]);

  async function act(action: () => Promise<string>) {
    setBusy(true);
    try {
      setNotice(await action());
    } catch (err) {
      setNotice(errorText(err, t('That did not work')));
    } finally {
      setBusy(false);
    }
  }

  const answer = (response: string) =>
    act(async () => {
      const result = await post<{ mail_problems: string[] }>('/api/me/calendars/invitations/respond', { ics, response });
      setInfo((current) => current && { ...current, my_status: response, stored: response !== 'declined' });
      const problem = result.mail_problems[0];
      if (response === 'declined') return problem ? t('Declined, but the organizer could not be told: {{problem}}', { problem }) : t('Declined and the organizer was told');
      return problem ? t('Added to your calendar, but the organizer could not be told: {{problem}}', { problem }) : t('Added to your calendar and the organizer was told');
    });

  const add = () =>
    act(async () => {
      const { calendars } = await get<{ calendars: { id: number; name: string; writable: boolean; shared: boolean }[] }>('/api/me/calendars');
      const target = calendars.find((calendar) => !calendar.shared) ?? calendars[0];
      const result = await postRaw<{ imported: number }>(`/api/me/calendars/${target.id}/import`, new Blob([ics], { type: 'text/calendar' }));
      return result.imported > 0 ? t('Added to {{name}}', { name: target.name }) : t('No event found in this file');
    });

  if (!info) return null;
  const when = info.start !== null && info.end !== null ? formatSpan({ start: info.start, end: info.end, all_day: info.all_day }) : '';
  const invitation = info.method === 'REQUEST' && Boolean(info.organizer) && !info.own;
  const cancelled = info.method === 'CANCEL';
  const reply = info.method === 'REPLY';
  const heading = cancelled ? t('Cancelled') : reply ? t('Answer to your invitation') : invitation ? t('Invitation') : t('Event');
  return (
    <Paper variant="outlined" component="section" aria-label={`${heading}: ${info.summary}`} sx={{ p: 1.5, my: 1, maxWidth: 560, borderLeft: 4, borderLeftColor: cancelled ? 'error.main' : 'primary.main' }}>
      <Stack direction="row" spacing={1.5} alignItems="flex-start">
        {cancelled ? <EventBusy color="error" /> : <Event color="primary" />}
        <Box sx={{ flex: 1, minWidth: 0 }}>
          <Typography variant="overline" color="text.secondary" sx={{ lineHeight: 1.2 }}>{heading}</Typography>
          <Typography variant="subtitle1" sx={{ fontWeight: 600, textDecoration: cancelled ? 'line-through' : undefined, overflowWrap: 'anywhere' }}>{info.summary || t('(no title)')}</Typography>
          <Typography variant="body2">{when}{info.recurring ? t(' · repeats') : ''}</Typography>
          {info.location && <Typography variant="body2" color="text.secondary">{info.location}</Typography>}
          {info.organizer && !reply && <Typography variant="body2" color="text.secondary">{t('Organizer: {{organizer}}', { organizer: info.organizer })}</Typography>}
          {reply && info.attendees.map((guest) => (
            <Typography key={guest.email} variant="body2">{guest.name || guest.email}: {STATUS_LABELS[guest.status] ?? guest.status}</Typography>
          ))}
          {cancelled && <Typography variant="body2" color="text.secondary">{t('The organizer called this event off. If it was in your calendar, it has been removed.')}</Typography>}
          {invitation && (
            <Stack direction="row" spacing={1} sx={{ mt: 1 }} alignItems="center" flexWrap="wrap" useFlexGap>
              {ANSWERS.map(([value, label]) => (
                <Button key={value} size="small" variant={info.my_status === value ? 'contained' : 'outlined'} disabled={busy} aria-pressed={info.my_status === value} onClick={() => void answer(value)}>
                  {label}
                </Button>
              ))}
            </Stack>
          )}
          {!invitation && !cancelled && !reply && (
            <Button size="small" variant="outlined" startIcon={<EventAvailable />} disabled={busy} sx={{ mt: 1 }} aria-label={t('Add {{name}} to calendar', { name })} onClick={() => void add()}>
              {t('Add to calendar')}
            </Button>
          )}
          {notice && <Typography variant="body2" role="status" sx={{ mt: 1 }}>{notice}</Typography>}
        </Box>
      </Stack>
    </Paper>
  );
}
