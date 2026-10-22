import Add from '@mui/icons-material/Add';
import ArrowBack from '@mui/icons-material/ArrowBack';
import ChevronLeft from '@mui/icons-material/ChevronLeft';
import ChevronRight from '@mui/icons-material/ChevronRight';
import Mail from '@mui/icons-material/Mail';
import MenuIcon from '@mui/icons-material/Menu';
import Today from '@mui/icons-material/Today';
import MoreVert from '@mui/icons-material/MoreVert';
import Sync from '@mui/icons-material/Sync';
import {
  Box, Button, Checkbox, SwipeableDrawer, Fab, IconButton, List, ListItem, ListItemButton, ListItemIcon, ListItemText, Menu, MenuItem, Select, Snackbar, Stack, ToggleButton, ToggleButtonGroup, Typography,
  useMediaQuery, useTheme,
} from '@mui/material';
import { SWIPE } from '../swipe';
import { useCallback, useEffect, useMemo, useRef, useState, type MouseEvent, type ReactElement } from 'react';
import { useNavigate } from 'react-router-dom';
import { del, get, postRaw, errorText } from '../api';
import { TopBar, useTitle } from '../shell';
import {
  COLORS, addDays, dayKey, daysOf, draft, formatSpan, formatTime, formatTitle, isBanner, layoutDay, onDay, sameDay, shift, startOfDay, type Calendar, type EventForm, type Occurrence,
  type View,
} from './dates';
import { CalendarDialog, ConnectDialog, EventDetails, EventDialog, NotificationPrompt, ShareCalendarDialog, browserZone, type Editing, type Listing } from './dialogs';
import { TasksView } from './Tasks';

import { t, uiLocale } from '../i18n';
import { readLocalJson, writeLocal } from '../storage';
const HOUR = 48;
const VIEWS: View[] = ['month', 'week', 'day', 'agenda', 'tasks'];
const VIEW_LABELS: Record<View, string> = { month: t('Month'), week: t('Week'), day: t('Day'), agenda: t('Agenda'), tasks: t('Tasks') };

const stored = readLocalJson;
const store = (key: string, value: unknown) => void writeLocal(key, JSON.stringify(value));

// --- Events on the page ----------------------------------------------------------------------

function EventChip({ event, color, onOpen, showTime = true, dense = false }: { event: Occurrence; color: string; onOpen: (event: Occurrence, anchor: HTMLElement) => void; showTime?: boolean; dense?: boolean }) {
  const theme = useTheme();
  const timed = !isBanner(event);
  return (
    <Box
      component="button"
      type="button"
      aria-label={`${event.summary}, ${formatSpan(event)}`}
      onClick={(e: MouseEvent<HTMLElement>) => {
        e.stopPropagation();
        onOpen(event, e.currentTarget);
      }}
      sx={{
        display: 'block', width: '100%', height: dense ? undefined : '100%', textAlign: 'left', border: 0, borderRadius: 1, px: 0.75, py: 0.25, cursor: 'pointer', overflow: 'hidden',
        font: 'inherit', fontSize: 12, lineHeight: 1.35, whiteSpace: dense ? 'nowrap' : 'normal', textOverflow: 'ellipsis',
        // Timed events in the month grid are outlined; everything else is filled with the calendar's colour.
        ...(dense && timed
          ? { bgcolor: 'transparent', color: 'text.primary', borderLeft: `3px solid ${color}`, borderRadius: 0 }
          : { bgcolor: color, color: theme.palette.getContrastText(color) }),
        '&:hover': { filter: 'brightness(0.93)' },
        '&:focus-visible': { outline: `2px solid ${theme.palette.primary.main}`, outlineOffset: 1 },
      }}
    >
      {showTime && timed && <Box component="span" sx={{ opacity: 0.85, mr: 0.5 }}>{formatTime(event.start)}</Box>}
      <Box component="span" sx={{ fontWeight: 600 }}>{event.summary}</Box>
      {!dense && event.location && <Box component="span" sx={{ display: 'block', opacity: 0.85 }}>{event.location}</Box>}
    </Box>
  );
}

interface ViewProps {
  date: Date;
  events: Occurrence[];
  colorOf: (event: Occurrence) => string;
  onOpen: (event: Occurrence, anchor: HTMLElement) => void;
  onCreate: (at: Date, allDay: boolean) => void;
  onDay: (day: Date) => void;
}

function MonthView({ date, events, colorOf, onOpen, onCreate, onDay: openDay }: ViewProps) {
  const days = daysOf('month', date);
  const today = new Date();
  const weekday = new Intl.DateTimeFormat(uiLocale(), { weekday: 'short' });
  return (
    <Box sx={{ flex: 1, minHeight: 0, display: 'flex', flexDirection: 'column' }}>
      <Box sx={{ display: 'grid', gridTemplateColumns: 'repeat(7, minmax(0, 1fr))' }}>
        {days.slice(0, 7).map((day) => (
          <Typography key={day.getTime()} variant="caption" color="text.secondary" align="center" sx={{ py: 0.5 }}>
            {weekday.format(day)}
          </Typography>
        ))}
      </Box>
      <Box role="grid" aria-label={t('Month')} sx={{ flex: 1, minHeight: 0, display: 'grid', gridTemplateColumns: 'repeat(7, minmax(0, 1fr))', gridTemplateRows: 'repeat(6, minmax(0, 1fr))', borderTop: 1, borderLeft: 1, borderColor: 'divider' }}>
        {days.map((day) => {
          const list = events.filter((event) => onDay(event, day)).sort((a, b) => Number(isBanner(b)) - Number(isBanner(a)) || a.start - b.start);
          const shown = list.slice(0, 3);
          const outside = day.getMonth() !== date.getMonth();
          return (
            <Box
              key={day.getTime()}
              role="gridcell"
              aria-label={dayKey(day)}
              onClick={() => onCreate(new Date(day.getFullYear(), day.getMonth(), day.getDate(), 9), false)}
              sx={{ borderRight: 1, borderBottom: 1, borderColor: 'divider', p: 0.5, minHeight: 0, overflow: 'hidden', cursor: 'pointer', bgcolor: outside ? 'action.hover' : undefined }}
            >
              <Stack alignItems="center" sx={{ mb: 0.25 }}>
                <Box
                  component="button"
                  type="button"
                  aria-label={t('Open {{day}}', { day: dayKey(day) })}
                  onClick={(e: MouseEvent) => {
                    e.stopPropagation();
                    openDay(day);
                  }}
                  sx={{
                    border: 0, cursor: 'pointer', font: 'inherit', fontSize: 12, width: 24, height: 24, borderRadius: '50%',
                    bgcolor: sameDay(day, today) ? 'primary.main' : 'transparent', color: sameDay(day, today) ? 'primary.contrastText' : outside ? 'text.disabled' : 'text.primary',
                  }}
                >
                  {day.getDate()}
                </Box>
              </Stack>
              <Stack spacing={0.25}>
                {shown.map((event) => (
                  <EventChip key={`${event.id}-${event.start}`} event={event} color={colorOf(event)} onOpen={onOpen} dense />
                ))}
                {list.length > shown.length && (
                  <Box
                    component="button"
                    type="button"
                    onClick={(e: MouseEvent) => {
                      e.stopPropagation();
                      openDay(day);
                    }}
                    sx={{ border: 0, bgcolor: 'transparent', color: 'text.secondary', font: 'inherit', fontSize: 12, textAlign: 'left', cursor: 'pointer', px: 0.75 }}
                  >
                    {t('{{count}} more', { count: list.length - shown.length })}
                  </Box>
                )}
              </Stack>
            </Box>
          );
        })}
      </Box>
    </Box>
  );
}

function TimeGrid({ days, events, colorOf, onOpen, onCreate, onDay: openDay }: ViewProps & { days: Date[] }) {
  const scroller = useRef<HTMLDivElement>(null);
  const [now, setNow] = useState(() => new Date());
  const heading = new Intl.DateTimeFormat(uiLocale(), { weekday: 'short' });
  const hourLabel = new Intl.DateTimeFormat(uiLocale(), { hour: 'numeric' });
  const banners = events.filter(isBanner);
  const timed = events.filter((event) => !isBanner(event));

  useEffect(() => {
    // Start the day where most of it happens rather than at midnight.
    if (scroller.current) scroller.current.scrollTop = 7 * HOUR;
    const timer = setInterval(() => setNow(new Date()), 60_000);
    return () => clearInterval(timer);
  }, []);

  const columns = `56px repeat(${days.length}, minmax(0, 1fr))`;
  return (
    <Box sx={{ flex: 1, minHeight: 0, display: 'flex', flexDirection: 'column' }}>
      <Box sx={{ display: 'grid', gridTemplateColumns: columns, borderBottom: 1, borderColor: 'divider', overflowY: 'scroll', flexShrink: 0 }}>
        <Box />
        {days.map((day) => (
          <Box key={day.getTime()} sx={{ textAlign: 'center', py: 0.5, borderLeft: 1, borderColor: 'divider', minWidth: 0 }}>
            <Typography variant="caption" color="text.secondary" component="div">{heading.format(day)}</Typography>
            <Box
              component="button"
              type="button"
              aria-label={t('Open {{day}}', { day: dayKey(day) })}
              onClick={() => openDay(day)}
              sx={{
                border: 0, cursor: 'pointer', font: 'inherit', fontSize: 18, width: 34, height: 34, borderRadius: '50%',
                bgcolor: sameDay(day, now) ? 'primary.main' : 'transparent', color: sameDay(day, now) ? 'primary.contrastText' : 'text.primary',
              }}
            >
              {day.getDate()}
            </Box>
            <Stack spacing={0.25} sx={{ px: 0.25, pb: 0.25, minHeight: 4 }} onClick={() => onCreate(day, true)}>
              {banners.filter((event) => onDay(event, day)).map((event) => (
                <EventChip key={`${event.id}-${event.start}`} event={event} color={colorOf(event)} onOpen={onOpen} dense showTime={false} />
              ))}
            </Stack>
          </Box>
        ))}
      </Box>
      <Box ref={scroller} sx={{ flex: 1, minHeight: 0, overflowY: 'scroll' }}>
        <Box sx={{ display: 'grid', gridTemplateColumns: columns, height: 24 * HOUR, position: 'relative' }}>
          <Box sx={{ position: 'relative' }}>
            {Array.from({ length: 23 }, (_, index) => (
              <Typography key={index} variant="caption" color="text.secondary" sx={{ position: 'absolute', top: (index + 1) * HOUR - 9, right: 6 }}>
                {hourLabel.format(new Date(2000, 0, 1, index + 1))}
              </Typography>
            ))}
          </Box>
          {days.map((day) => {
            const placements = layoutDay(timed, day);
            return (
              <Box
                key={day.getTime()}
                role="gridcell"
                aria-label={dayKey(day)}
                onClick={(e: MouseEvent<HTMLElement>) => {
                  const offset = e.clientY - e.currentTarget.getBoundingClientRect().top;
                  const minutes = Math.max(0, Math.min(23 * 60 + 30, Math.floor((offset / HOUR) * 2) * 30));
                  onCreate(new Date(day.getFullYear(), day.getMonth(), day.getDate(), Math.floor(minutes / 60), minutes % 60), false);
                }}
                sx={{
                  position: 'relative', borderLeft: 1, borderColor: 'divider', cursor: 'pointer',
                  backgroundImage: (theme) => `linear-gradient(to bottom, ${theme.palette.divider} 1px, transparent 1px)`, backgroundSize: `100% ${HOUR}px`,
                }}
              >
                {timed.map((event, index) => {
                  const place = placements[index];
                  if (!place) return null;
                  return (
                    <Box
                      key={`${event.id}-${event.start}`}
                      sx={{
                        position: 'absolute', top: (place.top / 60) * HOUR, height: Math.max(20, (place.height / 60) * HOUR - 2),
                        left: `calc(${(place.column / place.columns) * 100}% + 1px)`, width: `calc(${100 / place.columns}% - 3px)`,
                      }}
                    >
                      <EventChip event={event} color={colorOf(event)} onOpen={onOpen} />
                    </Box>
                  );
                })}
                {sameDay(day, now) && <Box aria-hidden sx={{ position: 'absolute', left: 0, right: 0, top: ((now.getHours() * 60 + now.getMinutes()) / 60) * HOUR, borderTop: 2, borderColor: 'error.main', pointerEvents: 'none' }} />}
              </Box>
            );
          })}
        </Box>
      </Box>
    </Box>
  );
}

function AgendaView({ date, events, colorOf, onOpen }: ViewProps) {
  const days = daysOf('agenda', date).map((day) => ({ day, list: events.filter((event) => onDay(event, day)).sort((a, b) => Number(isBanner(b)) - Number(isBanner(a)) || a.start - b.start) })).filter((entry) => entry.list.length > 0);
  const heading = new Intl.DateTimeFormat(uiLocale(), { weekday: 'long', month: 'long', day: 'numeric' });
  if (days.length === 0) {
    return <Typography color="text.secondary" sx={{ p: 4, textAlign: 'center' }}>{t('Nothing planned in these 30 days.')}</Typography>;
  }
  return (
    <Box sx={{ flex: 1, minHeight: 0, overflow: 'auto', px: 2, pb: 2 }}>
      {days.map(({ day, list }) => (
        <Box key={day.getTime()} component="section" aria-label={heading.format(day)} sx={{ display: 'flex', gap: 2, py: 1.5, borderBottom: 1, borderColor: 'divider' }}>
          <Typography variant="subtitle2" sx={{ width: 190, flexShrink: 0, color: sameDay(day, new Date()) ? 'primary.main' : 'text.primary' }}>{heading.format(day)}</Typography>
          <Stack spacing={0.5} sx={{ flex: 1, minWidth: 0 }}>
            {list.map((event) => (
              <Stack key={`${event.id}-${event.start}`} direction="row" spacing={1} alignItems="center">
                <Typography variant="body2" color="text.secondary" sx={{ width: 150, flexShrink: 0 }}>
                  {isBanner(event) ? t('All day') : `${formatTime(event.start)} – ${formatTime(event.end)}`}
                </Typography>
                <Box sx={{ flex: 1, minWidth: 0 }}>
                  <EventChip event={event} color={colorOf(event)} onOpen={onOpen} dense showTime={false} />
                </Box>
              </Stack>
            ))}
          </Stack>
        </Box>
      ))}
    </Box>
  );
}

// --- Page ------------------------------------------------------------------------------------

export default function CalendarPage() {
  useTitle(t('Calendar'));
  const navigate = useNavigate();
  // On small screens the calendars slide in over the page, and the toolbar shrinks.
  const theme = useTheme();
  const compact = useMediaQuery(theme.breakpoints.down('md'));
  const phone = useMediaQuery(theme.breakpoints.down('sm'));
  const [drawerOpen, setDrawerOpen] = useState(false);
  const [listing, setListing] = useState<Listing | null>(null);
  const [events, setEvents] = useState<Occurrence[]>([]);
  const [view, setView] = useState<View>(() => {
    const saved = stored<View>('unomail.calendar.view', 'month');
    return VIEWS.includes(saved) ? saved : 'month';
  });
  const [date, setDate] = useState(() => startOfDay(new Date()));
  const [hidden, setHidden] = useState<number[]>(() => stored<number[]>('unomail.calendar.hidden', []));
  const [editing, setEditing] = useState<Editing | null>(null);
  const [details, setDetails] = useState<Occurrence | null>(null);
  const [calendarDialog, setCalendarDialog] = useState<{ calendar: Calendar | null } | null>(null);
  const [calendarMenu, setCalendarMenu] = useState<{ anchor: HTMLElement; calendar: Calendar } | null>(null);
  const [connect, setConnect] = useState(false);
  const [sharing, setSharing] = useState<Calendar | null>(null);
  const [notice, setNotice] = useState('');
  const fileInput = useRef<HTMLInputElement>(null);
  const importTarget = useRef<Calendar | null>(null);

  const calendars = useMemo(() => listing?.calendars ?? [], [listing]);
  const days = useMemo(() => daysOf(view, date), [view, date]);
  // A day of margin on both sides: all-day events are stored as UTC days, the view is local.
  const from = Math.floor(addDays(days[0], -1).getTime() / 1000);
  const to = Math.floor(addDays(days[days.length - 1], 2).getTime() / 1000);

  const loadCalendars = useCallback(async () => {
    try {
      setListing(await get<Listing>('/api/me/calendars'));
    } catch (err) {
      setNotice(errorText(err, t('The calendars could not be loaded')));
    }
  }, []);

  const loadEvents = useCallback(async () => {
    try {
      setEvents(await get<Occurrence[]>(`/api/me/calendars/events?from=${from}&to=${to}`));
    } catch (err) {
      setNotice(errorText(err, t('The events could not be loaded')));
    }
  }, [from, to]);

  useEffect(() => {
    void loadCalendars();
  }, [loadCalendars]);

  useEffect(() => {
    void loadEvents();
    // Changes made in a phone or desktop calendar show up when coming back to this tab.
    const onFocus = () => void loadEvents();
    window.addEventListener('focus', onFocus);
    return () => window.removeEventListener('focus', onFocus);
  }, [loadEvents]);

  useEffect(() => store('unomail.calendar.view', view), [view]);
  useEffect(() => store('unomail.calendar.hidden', hidden), [hidden]);

  const visible = useMemo(() => events.filter((event) => !hidden.includes(event.calendar_id)), [events, hidden]);
  const byId = useMemo(() => new Map(calendars.map((calendar) => [calendar.id, calendar])), [calendars]);
  const colorOf = useCallback((event: Occurrence) => byId.get(event.calendar_id)?.color.slice(0, 7) || COLORS[0], [byId]);

  async function run(action: () => Promise<unknown>, done: string) {
    try {
      await action();
      setNotice(done);
      await Promise.all([loadCalendars(), loadEvents()]);
    } catch (err) {
      setNotice(errorText(err, t('The operation failed')));
    }
  }

  const writable = useMemo(() => calendars.filter((calendar) => calendar.writable), [calendars]);

  function create(at: Date, allDay: boolean) {
    const target = writable.find((calendar) => !hidden.includes(calendar.id)) ?? writable[0];
    if (target) setEditing({ calendarId: target.id, form: draft(at, allDay, browserZone()) });
  }

  /** Says how saving went, including invitations that could not be mailed. */
  function report(done: string, problems?: string[]) {
    setNotice(problems?.length ? t('{{done}}, but the guests could not be told by e-mail: {{value}}', { done, value: problems[0] }) : done);
  }

  function createNow() {
    const now = new Date();
    // Today at the next full hour when today is on screen, otherwise the day being looked at.
    const base = days.some((day) => sameDay(day, now)) ? now : date;
    const hour = sameDay(base, now) ? Math.min(23, now.getHours() + 1) : 9;
    create(new Date(base.getFullYear(), base.getMonth(), base.getDate(), hour), false);
  }

  async function edit(event: Occurrence, onlyThis: boolean) {
    try {
      const occurrence = onlyThis ? (event.recurrence_id ?? event.start) : undefined;
      const loaded = await get<{ event: EventForm }>(`/api/me/calendars/${event.calendar_id}/events/${event.id}${occurrence === undefined ? '' : `?occurrence=${occurrence}`}`);
      // Whoever owns the calendar organizes its events; anybody else's event is an invitation.
      const owner = byId.get(event.calendar_id)?.owner ?? '';
      setDetails(null);
      setEditing({ id: event.id, calendarId: event.calendar_id, form: loaded.event, occurrence, foreign: Boolean(event.organizer) && event.organizer !== owner, current: { start: event.start, end: event.end } });
    } catch (err) {
      setNotice(errorText(err, t('The event could not be opened')));
    }
  }

  async function remove(event: Occurrence, onlyThis: boolean) {
    setDetails(null);
    const occurrence = onlyThis ? `?occurrence=${event.recurrence_id ?? event.start}` : '';
    try {
      const result = await del<{ mail_problems?: string[] }>(`/api/me/calendars/${event.calendar_id}/events/${event.id}${occurrence}`);
      report(onlyThis ? t('Occurrence deleted') : t('Event deleted'), result.mail_problems);
    } catch (err) {
      setNotice(errorText(err, t('The event could not be deleted')));
    }
    await loadEvents();
  }

  function removeCalendar(calendar: Calendar) {
    if (calendar.shared) {
      if (window.confirm(t('Stop showing “{{name}}” of {{owner}}? The calendar itself is not touched.', { name: calendar.name, owner: calendar.owner }))) void run(() => del(`/api/me/calendars/${calendar.id}`), t('Calendar removed from your list'));
      return;
    }
    if (!window.confirm(t('Delete the calendar “{{name}}” with all its events? This cannot be undone.', { name: calendar.name }))) return;
    void run(() => del(`/api/me/calendars/${calendar.id}`), t('Calendar deleted'));
  }

  async function importFile(file: File | undefined) {
    const calendar = importTarget.current;
    if (!file || !calendar) return;
    try {
      const result = await postRaw<{ imported: number; skipped: number }>(`/api/me/calendars/${calendar.id}/import`, new Blob([await file.text()], { type: 'text/calendar' }));
      setNotice(t('{{count}} events imported into {{name}}', { count: result.imported, name: calendar.name }) + (result.skipped ? t(', {{count}} skipped', { count: result.skipped }) : ''));
      await loadEvents();
    } catch (err) {
      setNotice(errorText(err, t('The file could not be imported')));
    }
  }

  const viewProps: ViewProps = {
    date,
    events: visible,
    colorOf,
    onOpen: (event) => setDetails(event),
    onCreate: create,
    onDay: (day) => {
      setDate(startOfDay(day));
      setView('day');
    },
  };

  const wrapNav = (nav: ReactElement) =>
    compact ? (
      <SwipeableDrawer open={drawerOpen} onOpen={() => setDrawerOpen(true)} onClose={() => setDrawerOpen(false)} {...SWIPE} slotProps={{ paper: { sx: { bgcolor: 'background.default' } } }}>
        {nav}
      </SwipeableDrawer>
    ) : (
      nav
    );

  return (
    <Box sx={{ height: '100vh', display: 'flex', flexDirection: 'column', bgcolor: 'background.default' }}>
      <TopBar
        title={t('Calendar')}
        leading={
          compact ? (
            <IconButton aria-label={t('Calendars')} aria-expanded={drawerOpen} onClick={() => setDrawerOpen((open) => !open)}><MenuIcon /></IconButton>
          ) : (
            <IconButton aria-label={t('Back to mail')} onClick={() => navigate('/mail')}><ArrowBack /></IconButton>
          )
        }
      >
        <Stack direction="row" spacing={{ xs: 0, sm: 1 }} alignItems="center">
          {phone ? (
            <IconButton aria-label={t('Today')} onClick={() => setDate(startOfDay(new Date()))}><Today /></IconButton>
          ) : (
            <Button variant="outlined" size="small" onClick={() => setDate(startOfDay(new Date()))}>{t('Today')}</Button>
          )}
          <IconButton aria-label={t('Previous')} onClick={() => setDate(shift(view, date, -1))}><ChevronLeft /></IconButton>
          <IconButton aria-label={t('Next')} onClick={() => setDate(shift(view, date, 1))}><ChevronRight /></IconButton>
          <Typography variant="h6" component="h1" noWrap sx={{ flex: 1, minWidth: 0, fontWeight: 400, fontSize: { xs: '1rem', sm: '1.25rem' } }} aria-live="polite">{formatTitle(view, date, undefined, phone)}</Typography>
          {compact ? (
            <Select size="small" value={view} onChange={(e) => setView(e.target.value as View)} inputProps={{ 'aria-label': t('View') }} sx={{ flexShrink: 0, fontSize: { xs: 14, sm: 16 }, '& .MuiSelect-select': { py: 0.75, pl: 1.25, pr: '28px !important' } }}>
              {VIEWS.map((option) => (
                <MenuItem key={option} value={option}>{VIEW_LABELS[option]}</MenuItem>
              ))}
            </Select>
          ) : (
            <ToggleButtonGroup size="small" exclusive value={view} onChange={(_, next: View | null) => next && setView(next)} aria-label={t('View')}>
              {VIEWS.map((option) => (
                <ToggleButton key={option} value={option} sx={{ px: 1.5 }}>{VIEW_LABELS[option]}</ToggleButton>
              ))}
            </ToggleButtonGroup>
          )}
        </Stack>
      </TopBar>
      <Box sx={{ flex: 1, display: 'flex', minHeight: 0 }}>
        {wrapNav(
        <Box component="nav" aria-label={t('Calendars')} sx={{ width: 260, flexShrink: 0, px: 1, pt: compact ? 1 : 0, overflow: 'auto' }}>
          {compact && (
            <List dense disablePadding>
              <ListItemButton onClick={() => navigate('/mail')}>
                <ListItemIcon sx={{ minWidth: 36 }}><Mail fontSize="small" /></ListItemIcon>
                <ListItemText primary={t('Back to mail')} />
              </ListItemButton>
            </List>
          )}
          <Fab variant="extended" onClick={() => { setDrawerOpen(false); createNow(); }} sx={{ m: 1, mb: 2, alignSelf: 'flex-start' }} disabled={writable.length === 0}><Add />{t('New event')}</Fab>
          <Typography variant="overline" color="text.secondary" sx={{ px: 2, display: 'block', mt: 1 }}>{t('Calendars')}</Typography>
          <List dense disablePadding>
            {calendars.map((calendar) => {
              const color = calendar.color.slice(0, 7) || COLORS[0];
              return (
                <ListItem
                  key={calendar.id}
                  disablePadding
                  secondaryAction={
                    <IconButton edge="end" size="small" aria-label={t('Options for {{name}}', { name: calendar.name })} onClick={(e) => setCalendarMenu({ anchor: e.currentTarget, calendar })}>
                      <MoreVert fontSize="small" />
                    </IconButton>
                  }
                >
                  <ListItemButton onClick={() => setHidden((current) => (current.includes(calendar.id) ? current.filter((id) => id !== calendar.id) : [...current, calendar.id]))}>
                    <ListItemIcon sx={{ minWidth: 36 }}>
                      <Checkbox edge="start" size="small" tabIndex={-1} disableRipple checked={!hidden.includes(calendar.id)} inputProps={{ 'aria-label': t('Show {{name}}', { name: calendar.name }) }} sx={{ color, '&.Mui-checked': { color }, p: 0.5 }} />
                    </ListItemIcon>
                    <ListItemText primary={calendar.name} secondary={calendar.shared ? (calendar.writable ? calendar.owner : t('{{owner}} · read only', { owner: calendar.owner })) : undefined} primaryTypographyProps={{ noWrap: true }} secondaryTypographyProps={{ noWrap: true }} />
                  </ListItemButton>
                </ListItem>
              );
            })}
            <ListItemButton onClick={() => setCalendarDialog({ calendar: null })}>
              <ListItemIcon sx={{ minWidth: 36 }}><Add fontSize="small" /></ListItemIcon>
              <ListItemText primary={t('New calendar')} />
            </ListItemButton>
            <ListItemButton onClick={() => setConnect(true)} disabled={!listing}>
              <ListItemIcon sx={{ minWidth: 36 }}><Sync fontSize="small" /></ListItemIcon>
              <ListItemText primary={t('Sync with other apps')} secondary={t('CalDAV')} />
            </ListItemButton>
          </List>
          <NotificationPrompt />
        </Box>,
        )}
        <Box component="main" sx={{ flex: 1, minWidth: 0, display: 'flex', flexDirection: 'column', bgcolor: 'background.paper', borderRadius: { md: '16px 0 0 0' }, overflow: 'hidden' }}>
          {view === 'month' && <MonthView {...viewProps} />}
          {(view === 'week' || view === 'day') && <TimeGrid {...viewProps} days={days} />}
          {view === 'agenda' && <AgendaView {...viewProps} />}
          {view === 'tasks' && <TasksView calendars={calendars} hidden={hidden} onNotice={setNotice} />}
        </Box>
      </Box>
      {compact && view !== 'tasks' && writable.length > 0 && (
        <Fab color="primary" aria-label={t('New event')} onClick={createNow} sx={{ position: 'fixed', right: 16, bottom: 16, zIndex: 1050 }}>
          <Add />
        </Fab>
      )}

      <Menu anchorEl={calendarMenu?.anchor} open={Boolean(calendarMenu)} onClose={() => setCalendarMenu(null)}>
        {!calendarMenu?.calendar.shared && <MenuItem onClick={() => { setCalendarDialog({ calendar: calendarMenu!.calendar }); setCalendarMenu(null); }}>{t('Rename or recolour')}</MenuItem>}
        {!calendarMenu?.calendar.shared && <MenuItem onClick={() => { setSharing(calendarMenu!.calendar); setCalendarMenu(null); }}>{t('Share with colleagues')}</MenuItem>}
        <MenuItem component="a" href={calendarMenu ? `/api/me/calendars/${calendarMenu.calendar.id}/export` : undefined} download onClick={() => setCalendarMenu(null)}>{t('Export (.ics)')}</MenuItem>
        {calendarMenu?.calendar.writable && <MenuItem onClick={() => { importTarget.current = calendarMenu!.calendar; setCalendarMenu(null); fileInput.current?.click(); }}>{t('Import (.ics)')}</MenuItem>}
        <MenuItem disabled={!calendarMenu?.calendar.shared && calendars.filter((calendar) => !calendar.shared).length <= 1} onClick={() => { const target = calendarMenu!.calendar; setCalendarMenu(null); removeCalendar(target); }}>
          {calendarMenu?.calendar.shared ? t('Remove from my list') : t('Delete')}
        </MenuItem>
      </Menu>
      <input
        ref={fileInput}
        type="file"
        accept=".ics,text/calendar"
        hidden
        aria-label={t('Calendar file to import')}
        onChange={(e) => {
          void importFile(e.target.files?.[0]);
          e.target.value = '';
        }}
      />
      {details && <EventDetails event={details} calendar={byId.get(details.calendar_id)} onClose={() => setDetails(null)} onEdit={(onlyThis) => void edit(details, onlyThis)} onDelete={(onlyThis) => void remove(details, onlyThis)} />}
      {editing && (
        <EventDialog
          editing={editing}
          calendars={writable}
          onClose={(saved, problems) => {
            setEditing(null);
            if (saved) {
              report(t('Event saved'), problems);
              void loadEvents();
            }
          }}
        />
      )}
      {calendarDialog && (
        <CalendarDialog
          calendar={calendarDialog.calendar}
          onClose={(saved) => {
            setCalendarDialog(null);
            if (saved) void loadCalendars();
          }}
        />
      )}
      {connect && listing && <ConnectDialog listing={listing} onClose={() => setConnect(false)} />}
      {sharing && (
        <ShareCalendarDialog
          calendar={sharing}
          onClose={(saved) => {
            setSharing(null);
            if (saved) setNotice(t('Sharing saved'));
          }}
        />
      )}
      <Snackbar open={Boolean(notice)} autoHideDuration={4000} onClose={() => setNotice('')} message={notice} />
    </Box>
  );
}
