import ContentCopy from '@mui/icons-material/ContentCopy';
import Delete from '@mui/icons-material/Delete';
import Edit from '@mui/icons-material/Edit';
import Group from '@mui/icons-material/Group';
import Notes from '@mui/icons-material/Notes';
import NotificationsNone from '@mui/icons-material/NotificationsNone';
import Place from '@mui/icons-material/Place';
import Repeat from '@mui/icons-material/Repeat';
import Schedule from '@mui/icons-material/Schedule';
import {
  Alert, Autocomplete, Box, Button, Checkbox, Chip, Dialog, DialogActions, DialogContent, DialogTitle, FormControlLabel, IconButton, InputAdornment, Menu, MenuItem, Stack, TextField,
  Tooltip, Typography,
} from '@mui/material';
import { useEffect, useMemo, useState, type ReactNode } from 'react';
import { get, patch, post, put, errorText } from '../lib/api';
import {
  COLORS, REMINDERS, REPEAT_LABELS, STATUS_LABELS, buildRule, conflicts, describeRule, formatSpan, reminderLabel, toggleAllDay, type Calendar, type EventForm, type Occurrence,
  type Repeat as RepeatKind,
} from './dates';

import { t, uiLocale } from '../i18n';
import { DialogButtons } from '../admin/common';
export interface Listing {
  calendars: Calendar[];
  caldav: { server: string; home: string; username: string };
  carddav: { server: string; addressbook: string };
  timezone: string;
}

export interface Editing {
  /** Set when an existing event is edited. */
  id?: number;
  calendarId: number;
  form: EventForm;
  /** Set when one occurrence of a series is edited: its start in the series. */
  occurrence?: number;
  /** The event is somebody else's invitation: its guest list cannot be changed here. */
  foreign?: boolean;
  /** When the event is now, so that it does not count as a conflict with itself. */
  current?: { start: number; end: number };
}

export const browserZone = () => Intl.DateTimeFormat(uiLocale()).resolvedOptions().timeZone || 'UTC';
const ADDRESS = /^[^\s@,;<>]+@[^\s@,;<>]+\.[^\s@,;<>]+$/;

interface Availability {
  email: string;
  known: boolean;
  busy: { start: number; end: number }[];
}

/** Who of the guests is busy at the chosen time (colleagues of the same domain only). */
function useAvailability(emails: string[], form: EventForm, skip: boolean): Availability[] {
  const [result, setResult] = useState<Availability[]>([]);
  const key = emails.join(',');
  const day = form.start.slice(0, 10);
  useEffect(() => {
    const at = Date.parse(`${day}T00:00`);
    if (skip || !key || Number.isNaN(at)) {
      setResult([]);
      return;
    }
    let cancelled = false;
    // A generous window around the day, so moving the time needs no new request.
    const [from, to] = [Math.floor(at / 1000) - 86_400, Math.floor(at / 1000) + 8 * 86_400];
    const timer = setTimeout(() => {
      get<Availability[]>(`/api/me/calendars/freebusy?from=${from}&to=${to}&emails=${encodeURIComponent(key)}`)
        .then((list) => !cancelled && setResult(list))
        .catch(() => !cancelled && setResult([]));
    }, 300);
    return () => {
      cancelled = true;
      clearTimeout(timer);
    };
  }, [key, day, skip]);
  return result;
}

export function EventDialog({ editing, calendars, onClose }: { editing: Editing; calendars: Calendar[]; onClose: (saved: boolean, problems?: string[]) => void }) {
  const [form, setForm] = useState(editing.form);
  const [calendarId, setCalendarId] = useState(editing.calendarId);
  const initial = useMemo(() => describeRule(editing.form.rrule), [editing.form.rrule]);
  const [repeat, setRepeat] = useState<RepeatKind>(initial.repeat);
  const [until, setUntil] = useState(initial.until);
  const [guestInput, setGuestInput] = useState('');
  const [suggestions, setSuggestions] = useState<string[]>([]);
  const [error, setError] = useState('');
  const [busy, setBusy] = useState(false);
  const set = (changes: Partial<EventForm>) => setForm((current) => ({ ...current, ...changes }));
  const single = editing.occurrence !== undefined;
  const foreignZone = !form.all_day && form.timezone !== browserZone();
  const availability = useAvailability(form.attendees, form, form.all_day || foreignZone || Boolean(editing.foreign));

  useEffect(() => {
    const query = guestInput.trim();
    if (query.length < 2) {
      setSuggestions([]);
      return;
    }
    let cancelled = false;
    const timer = setTimeout(() => {
      get<{ email: string }[]>(`/api/me/contacts/suggest?q=${encodeURIComponent(query)}`)
        .then((list) => !cancelled && setSuggestions([...new Set(list.map((entry) => entry.email).filter(Boolean))]))
        .catch(() => {});
    }, 200);
    return () => {
      cancelled = true;
      clearTimeout(timer);
    };
  }, [guestInput]);

  function setStart(start: string) {
    // Moving the start moves the end along, so the length of the event stays what it was.
    const [before, after, end] = [Date.parse(form.start), Date.parse(start), Date.parse(form.end)];
    if (Number.isNaN(before) || Number.isNaN(after) || Number.isNaN(end)) return set({ start });
    const moved = new Date(end + (after - before));
    const local = new Date(moved.getTime() - moved.getTimezoneOffset() * 60_000).toISOString();
    set({ start, end: form.all_day ? local.slice(0, 10) : local.slice(0, 16) });
  }

  function setGuests(values: string[]) {
    const cleaned = [...new Set(values.flatMap((value) => value.split(/[,;\s]+/)).map((value) => value.trim().toLowerCase()).filter(Boolean))];
    const bad = cleaned.find((value) => !ADDRESS.test(value));
    setError(bad ? t('“{{bad}}” is not an e-mail address', { bad }) : '');
    set({ attendees: cleaned.filter((value) => ADDRESS.test(value)) });
  }

  async function save() {
    setError('');
    setBusy(true);
    try {
      // A guest typed but not confirmed with Enter still counts.
      const pending = guestInput.trim().toLowerCase();
      const attendees = pending && ADDRESS.test(pending) && !form.attendees.includes(pending) ? [...form.attendees, pending] : form.attendees;
      const body = { ...form, attendees, rrule: single ? '' : buildRule(repeat, until, form.all_day, editing.form.rrule) };
      const saved =
        editing.id === undefined
          ? await post<{ mail_problems: string[] }>(`/api/me/calendars/${calendarId}/events`, body)
          : await put<{ mail_problems: string[] }>(`/api/me/calendars/${editing.calendarId}/events/${editing.id}`, { ...body, calendar_id: calendarId, occurrence: editing.occurrence });
      onClose(true, saved.mail_problems);
    } catch (err) {
      setError(errorText(err, t('The event could not be saved')));
      setBusy(false);
    }
  }

  const [start, end] = [Math.floor(Date.parse(form.start) / 1000), Math.floor(Date.parse(form.end) / 1000)];
  const occupied = availability.filter((person) => person.known && conflicts(person.busy, start, end, editing.current)).map((person) => person.email);
  const free = availability.filter((person) => person.known && !occupied.includes(person.email)).map((person) => person.email);
  const reminders = form.reminder !== null && !REMINDERS.includes(form.reminder) ? [...REMINDERS, form.reminder].sort((a, b) => a - b) : REMINDERS;
  const title = editing.id === undefined ? t('New event') : single ? t('Edit this occurrence') : t('Edit event');

  return (
    <Dialog open onClose={() => onClose(false)} fullWidth maxWidth="sm" aria-labelledby="event-editor-title">
      <DialogTitle id="event-editor-title">{title}</DialogTitle>
      <DialogContent>
        <Stack spacing={2} sx={{ mt: 1 }}>
          {error && <Alert severity="error">{error}</Alert>}
          <TextField label={t('Title')} value={form.summary} onChange={(e) => set({ summary: e.target.value })} autoFocus required slotProps={{
            htmlInput: { maxLength: 300 }
          }} />
          <FormControlLabel control={<Checkbox checked={form.all_day} onChange={(e) => setForm((current) => toggleAllDay(current, e.target.checked))} />} label={t('All day')} />
          <Stack direction={{ xs: 'column', sm: 'row' }} spacing={2}>
            <TextField label={t('Starts')} type={form.all_day ? 'date' : 'datetime-local'} value={form.start} onChange={(e) => setStart(e.target.value)} fullWidth slotProps={{
              inputLabel: { shrink: true }
            }} />
            <TextField label={t('Ends')} type={form.all_day ? 'date' : 'datetime-local'} value={form.end} onChange={(e) => set({ end: e.target.value })} fullWidth slotProps={{
              inputLabel: { shrink: true }
            }} />
          </Stack>
          {foreignZone && <Typography variant="caption" sx={{ color: 'text.secondary' }}>{t('Times are in the event’s own time zone: {{timezone}}.', { timezone: form.timezone })}</Typography>}
          {!single && (
            <Stack direction={{ xs: 'column', sm: 'row' }} spacing={2}>
              <TextField select label={t('Repeat')} value={repeat} onChange={(e) => setRepeat(e.target.value as RepeatKind)} fullWidth>
                {(Object.keys(REPEAT_LABELS) as RepeatKind[]).filter((kind) => kind !== 'custom' || initial.repeat === 'custom').map((kind) => (
                  <MenuItem key={kind} value={kind}>{REPEAT_LABELS[kind]}</MenuItem>
                ))}
              </TextField>
              {repeat !== 'none' && repeat !== 'custom' && (
                <TextField label={t('Repeat until')} type="date" value={until} onChange={(e) => setUntil(e.target.value)} fullWidth helperText={t('Empty: no end')} slotProps={{
                  inputLabel: { shrink: true }
                }} />
              )}
            </Stack>
          )}
          <Stack direction={{ xs: 'column', sm: 'row' }} spacing={2}>
            <TextField select label={t('Calendar')} value={calendarId} onChange={(e) => setCalendarId(Number(e.target.value))} fullWidth disabled={single}>
              {calendars.map((calendar) => (
                <MenuItem key={calendar.id} value={calendar.id}>
                  <Box component="span" sx={{ display: 'inline-block', width: 12, height: 12, borderRadius: '50%', bgcolor: calendar.color || 'primary.main', mr: 1 }} />
                  {calendar.name}
                </MenuItem>
              ))}
            </TextField>
            <TextField select label={t('Reminder')} value={form.reminder === null ? 'none' : String(form.reminder)} onChange={(e) => set({ reminder: e.target.value === 'none' ? null : Number(e.target.value) })} fullWidth>
              <MenuItem value="none">{reminderLabel(null)}</MenuItem>
              {reminders.map((minutes) => (
                <MenuItem key={minutes} value={String(minutes)}>{reminderLabel(minutes)}</MenuItem>
              ))}
            </TextField>
          </Stack>
          {!single && !editing.foreign && (
            <Box>
              <Autocomplete
                multiple
                freeSolo
                autoSelect
                options={suggestions.filter((email) => !form.attendees.includes(email))}
                filterOptions={(options) => options}
                value={form.attendees}
                inputValue={guestInput}
                onInputChange={(_, value) => setGuestInput(value)}
                onChange={(_, values) => setGuests(values as string[])}
                renderValue={(values, getItemProps) => values.map((email, index) => {
                  const { key, ...tag } = getItemProps({ index });
                  return <Chip key={key} size="small" label={email} color={occupied.includes(email) ? 'warning' : free.includes(email) ? 'success' : 'default'} variant="outlined" {...tag} />;
                })}
                renderInput={(params) => <TextField {...params} label={t('Guests')} placeholder="name@example.org" helperText={t('They are invited by e-mail when you save, and told about later changes.')} />}
              />
              {occupied.length > 0 && (
                <Alert severity="warning" sx={{ mt: 1 }} role="status">
                  {t('Busy at this time: {{value}}', { value: occupied.join(', ') })}
                </Alert>
              )}
            </Box>
          )}
          {editing.foreign && <Typography variant="caption" sx={{ color: 'text.secondary' }}>{t('You were invited to this event; its guest list belongs to the organizer.')}</Typography>}
          <TextField label={t('Location')} value={form.location} onChange={(e) => set({ location: e.target.value })} slotProps={{
            htmlInput: { maxLength: 300 }
          }} />
          <TextField label={t('Description')} value={form.description} onChange={(e) => set({ description: e.target.value })} multiline minRows={3} />
          {editing.id !== undefined && !single && repeat !== 'none' && <Typography variant="caption" sx={{ color: 'text.secondary' }}>{t('Changes apply to every occurrence of this repeating event.')}</Typography>}
        </Stack>
      </DialogContent>
      <DialogButtons onCancel={() => onClose(false)} onConfirm={() => void save()} disabled={busy || !form.summary.trim()} />
    </Dialog>
  );
}

export function CalendarDialog({ calendar, onClose }: { calendar: Calendar | null; onClose: (saved: boolean) => void }) {
  const [name, setName] = useState(calendar?.name ?? '');
  const [color, setColor] = useState(calendar?.color.slice(0, 7) || COLORS[0]);
  const [error, setError] = useState('');

  async function save() {
    try {
      if (calendar) await patch(`/api/me/calendars/${calendar.id}`, { name, color });
      else await post('/api/me/calendars', { name, color });
      onClose(true);
    } catch (err) {
      setError(errorText(err, t('The calendar could not be saved')));
    }
  }

  return (
    <Dialog open onClose={() => onClose(false)} fullWidth maxWidth="xs">
      <DialogTitle>{calendar ? t('Edit calendar') : t('New calendar')}</DialogTitle>
      <DialogContent>
        <Stack spacing={2} sx={{ mt: 1 }}>
          {error && <Alert severity="error">{error}</Alert>}
          <TextField label={t('Name')} value={name} onChange={(e) => setName(e.target.value)} autoFocus slotProps={{
            htmlInput: { maxLength: 100 }
          }} />
          <Stack direction="row" spacing={1} useFlexGap role="radiogroup" aria-label={t('Colour')} sx={{ flexWrap: 'wrap' }}>
            {COLORS.map((candidate) => (
              <Box
                key={candidate}
                component="button"
                type="button"
                role="radio"
                aria-checked={candidate === color}
                aria-label={t('Colour {{candidate}}', { candidate })}
                onClick={() => setColor(candidate)}
                sx={{ width: 28, height: 28, borderRadius: '50%', bgcolor: candidate, cursor: 'pointer', border: 3, borderColor: candidate === color ? 'text.primary' : 'transparent', outlineOffset: 2 }}
              />
            ))}
          </Stack>
        </Stack>
      </DialogContent>
      <DialogButtons onCancel={() => onClose(false)} onConfirm={() => void save()} disabled={!name.trim()} />
    </Dialog>
  );
}

interface Share {
  email: string;
  write: boolean;
}

/** With which colleagues a calendar is shared. */
export function ShareCalendarDialog({ calendar, onClose }: { calendar: Calendar; onClose: (saved: boolean) => void }) {
  const [shares, setShares] = useState<Share[] | null>(null);
  const [email, setEmail] = useState('');
  const [error, setError] = useState('');

  useEffect(() => {
    get<Share[]>(`/api/me/calendars/${calendar.id}/shares`).then(setShares).catch((err) => setError(errorText(err, t('The sharing settings could not be loaded'))));
  }, [calendar.id]);

  function add() {
    const address = email.trim().toLowerCase();
    if (!ADDRESS.test(address)) return setError(t('Enter the e-mail address of a colleague'));
    setError('');
    setShares((current) => [...(current ?? []).filter((share) => share.email !== address), { email: address, write: false }]);
    setEmail('');
  }

  async function save() {
    try {
      await put(`/api/me/calendars/${calendar.id}/shares`, shares ?? []);
      onClose(true);
    } catch (err) {
      setError(errorText(err, t('The calendar could not be shared')));
    }
  }

  return (
    <Dialog open onClose={() => onClose(false)} fullWidth maxWidth="sm">
      <DialogTitle>{t('Share “{{name}}”', { name: calendar.name })}</DialogTitle>
      <DialogContent>
        <Stack spacing={2} sx={{ mt: 1 }}>
          {error && <Alert severity="error">{error}</Alert>}
          <Typography variant="body2" sx={{ color: 'text.secondary' }}>
            {t('Colleagues with a mailbox in your domain see this calendar next to their own, here and in their calendar programs. With “may edit” they can add and change events, which stay yours.')}
          </Typography>
          <Stack direction="row" spacing={1}>
            <TextField
              label={t('Colleague’s address')}
              size="small"
              fullWidth
              value={email}
              onChange={(e) => setEmail(e.target.value)}
              onKeyDown={(e) => {
                if (e.key === 'Enter') {
                  e.preventDefault();
                  add();
                }
              }}
            />
            <Button variant="outlined" onClick={add}>{t('Add')}</Button>
          </Stack>
          {shares?.length === 0 && <Typography variant="body2" sx={{ color: 'text.secondary' }}>{t('Not shared with anybody.')}</Typography>}
          {shares?.map((share) => (
            <Stack key={share.email} direction="row" spacing={1} data-testid="calendar-share" sx={{ alignItems: 'center' }}>
              <Typography sx={{ flex: 1, minWidth: 0 }} noWrap>{share.email}</Typography>
              <FormControlLabel
                control={<Checkbox size="small" checked={share.write} onChange={(e) => setShares((current) => (current ?? []).map((entry) => (entry.email === share.email ? { ...entry, write: e.target.checked } : entry)))} />}
                label={t('May edit')}
              />
              <IconButton size="small" aria-label={t('Stop sharing with {{email}}', { email: share.email })} onClick={() => setShares((current) => (current ?? []).filter((entry) => entry.email !== share.email))}>
                <Delete fontSize="small" />
              </IconButton>
            </Stack>
          ))}
        </Stack>
      </DialogContent>
      <DialogButtons onCancel={() => onClose(false)} onConfirm={() => void save()} disabled={!shares} />
    </Dialog>
  );
}

function CopyField({ label, value }: { label: string; value: string }) {
  const [copied, setCopied] = useState(false);
  return (
    <TextField
      label={label}
      value={value}
      size="small"
      fullWidth
      slotProps={{
        input: {
          readOnly: true,
          endAdornment: (
            <InputAdornment position="end">
              <Tooltip title={copied ? t('Copied') : t('Copy')}>
                <IconButton edge="end" size="small" aria-label={t('Copy {{value}}', { value: label.toLowerCase() })} onClick={() => void navigator.clipboard?.writeText(value).then(() => setCopied(true), () => {})}>
                  <ContentCopy fontSize="small" />
                </IconButton>
              </Tooltip>
            </InputAdornment>
          ),
        }
      }}
    />
  );
}

export function ConnectDialog({ listing, onClose }: { listing: Listing; onClose: () => void }) {
  return (
    <Dialog open onClose={onClose} fullWidth maxWidth="sm">
      <DialogTitle>{t('Use these calendars in another app')}</DialogTitle>
      <DialogContent>
        <Stack spacing={2} sx={{ mt: 1 }}>
          <Typography variant="body2" sx={{ color: 'text.secondary' }}>
            {t('Calendar programs that speak CalDAV (Thunderbird, Apple Calendar, DAVx⁵ on Android, and others) stay in sync with what you see here. Add a CalDAV account with the server address and sign in with your e-mail address and password. The same account also offers your contacts (CardDAV).')}
          </Typography>
          <CopyField label={t('Server address')} value={listing.caldav.server} />
          <CopyField label={t('User name')} value={listing.caldav.username} />
          <Typography variant="subtitle2">{t('Addresses of single calendars')}</Typography>
          <Typography variant="body2" sx={{ color: 'text.secondary' }}>{t('Only needed by programs that cannot find the calendars from the server address.')}</Typography>
          {listing.calendars.map((calendar) => (
            <CopyField key={calendar.id} label={calendar.shared ? `${calendar.name} (${calendar.owner})` : calendar.name} value={calendar.url} />
          ))}
        </Stack>
      </DialogContent>
      <DialogActions>
        <Button onClick={onClose}>{t('Close')}</Button>
      </DialogActions>
    </Dialog>
  );
}

function Detail({ icon, children }: { icon: ReactNode; children: ReactNode }) {
  return (
    <Stack direction="row" spacing={1.5} sx={{ alignItems: 'flex-start' }}>
      <Box sx={{ color: 'text.secondary', display: 'flex', pt: 0.25 }}>{icon}</Box>
      <Typography variant="body2" component="div" sx={{ whiteSpace: 'pre-wrap', overflowWrap: 'anywhere', minWidth: 0 }}>{children}</Typography>
    </Stack>
  );
}

const STATUS_COLORS: Record<string, 'success' | 'error' | 'warning' | 'default'> = { accepted: 'success', declined: 'error', tentative: 'warning' };

export function EventDetails({ event, calendar, onClose, onEdit, onDelete }: { event: Occurrence; calendar?: Calendar; onClose: () => void; onEdit: (onlyThis: boolean) => void; onDelete: (onlyThis: boolean) => void }) {
  const [menu, setMenu] = useState<{ anchor: HTMLElement; action: 'edit' | 'delete' } | null>(null);
  const writable = calendar?.writable ?? false;
  const choose = (onlyThis: boolean) => {
    const action = menu?.action;
    setMenu(null);
    if (action === 'edit') onEdit(onlyThis);
    else onDelete(onlyThis);
  };
  return (
    <Dialog open onClose={onClose} fullWidth maxWidth="xs" aria-labelledby="event-title">
      <DialogTitle id="event-title" sx={{ display: 'flex', alignItems: 'center', gap: 1.5, pr: 1 }}>
        <Box sx={{ width: 14, height: 14, borderRadius: 0.5, bgcolor: calendar?.color || 'primary.main', flexShrink: 0 }} />
        <Box sx={{ flex: 1, minWidth: 0, overflowWrap: 'anywhere' }}>{event.summary}</Box>
      </DialogTitle>
      <DialogContent>
        <Stack spacing={1.25}>
          <Detail icon={<Schedule fontSize="small" />}>{formatSpan(event)}</Detail>
          {event.recurring && <Detail icon={<Repeat fontSize="small" />}>{t('Repeating event')}</Detail>}
          {event.location && <Detail icon={<Place fontSize="small" />}>{event.location}</Detail>}
          {event.attendees.length > 0 && (
            <Detail icon={<Group fontSize="small" />}>
              <Box component="ul" aria-label={t('Guests')} sx={{ listStyle: 'none', m: 0, p: 0 }}>
                {event.organizer && <li>{event.organizer} <Typography component="span" variant="caption" sx={{ color: 'text.secondary' }}>{t('(organizer)')}</Typography></li>}
                {event.attendees.filter((guest) => guest.email !== event.organizer).map((guest) => (
                  <li key={guest.email}>
                    {guest.name ? `${guest.name} <${guest.email}>` : guest.email}{' '}
                    <Chip size="small" variant="outlined" color={STATUS_COLORS[guest.status] ?? 'default'} label={STATUS_LABELS[guest.status] ?? guest.status} sx={{ height: 20 }} />
                  </li>
                ))}
              </Box>
            </Detail>
          )}
          {event.description && <Detail icon={<Notes fontSize="small" />}>{event.description}</Detail>}
          {calendar && <Typography variant="caption" sx={{ color: 'text.secondary' }}>{calendar.shared ? `${calendar.name} (${calendar.owner})` : calendar.name}{!writable && t(' · read only')}</Typography>}
        </Stack>
      </DialogContent>
      <DialogActions>
        {writable && <Button startIcon={<Delete />} color="error" onClick={(e) => (event.recurring ? setMenu({ anchor: e.currentTarget, action: 'delete' }) : onDelete(false))}>{t('Delete')}</Button>}
        <Menu anchorEl={menu?.anchor} open={Boolean(menu)} onClose={() => setMenu(null)}>
          <MenuItem onClick={() => choose(true)}>{t('Only this occurrence')}</MenuItem>
          <MenuItem onClick={() => choose(false)}>{t('All occurrences')}</MenuItem>
        </Menu>
        <Box sx={{ flex: 1 }} />
        <Button onClick={onClose}>{t('Close')}</Button>
        {writable && <Button variant="contained" startIcon={<Edit />} onClick={(e) => (event.recurring ? setMenu({ anchor: e.currentTarget, action: 'edit' }) : onEdit(false))}>{t('Edit')}</Button>}
      </DialogActions>
    </Dialog>
  );
}

/** Asks the browser for permission to show reminders while unoMail is not in front. */
export function NotificationPrompt() {
  const supported = typeof Notification !== 'undefined';
  const [permission, setPermission] = useState(supported ? Notification.permission : 'denied');
  if (!supported || permission !== 'default') return null;
  return (
    <Button size="small" startIcon={<NotificationsNone />} onClick={() => void Notification.requestPermission().then(setPermission)} sx={{ mx: 1, mt: 1, textTransform: 'none', textAlign: 'left' }}>
      {t('Show reminders as notifications')}
    </Button>
  );
}
