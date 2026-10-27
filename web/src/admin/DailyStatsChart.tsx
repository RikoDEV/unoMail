// "Daily stats" on the dashboard: SMTP connections and what became of mail, per day.
//
// Six lines on one count axis starting at zero. The parts of a line (blocked and limited
// connections, local and remote deliveries) are numbers under it in the legend and the
// tooltip rather than lines of their own. Colours are the validated categorical palette in
// fixed order, stepped separately for dark surfaces; the legend names every line, hovering
// shows a day's exact numbers, and a table of the same data is one click away.

import { Box, Card, CardContent, Stack, Table, TableBody, TableCell, TableHead, TableRow, ToggleButton, ToggleButtonGroup, Typography, useTheme } from '@mui/material';
import { useEffect, useId, useMemo, useState } from 'react';

import { get } from '../lib/api';
import { t, uiLocale } from '../i18n';
import { useElementWidth, useLoad } from './common';

export interface DailyStats {
  /** `YYYY-MM-DD`, UTC. */
  date: string;
  connections_valid: number;
  connections_blocked: number;
  connections_limited: number;
  delivered_local: number;
  delivered_remote: number;
  bounced: number;
  quarantined: number;
  discarded: number;
}

interface Series {
  id: string;
  label: string;
  /** Categorical slot colours: light surface, dark surface. */
  color: [string, string];
  value: (day: DailyStats) => number;
  /** The parts that make up the value, shown as "<count> – <name>". */
  parts?: { label: string; value: (day: DailyStats) => number }[];
}

const SERIES: Series[] = [
  { id: 'valid', label: t('Valid connections'), color: ['#2a78d6', '#3987e5'], value: (d) => d.connections_valid },
  {
    id: 'invalid',
    label: t('Invalid connections'),
    color: ['#eb6834', '#d95926'],
    value: (d) => d.connections_blocked + d.connections_limited,
    parts: [
      { label: t('blocked'), value: (d) => d.connections_blocked },
      { label: t('limited'), value: (d) => d.connections_limited },
    ],
  },
  {
    id: 'delivered',
    label: t('Delivered emails'),
    color: ['#1baf7a', '#199e70'],
    value: (d) => d.delivered_local + d.delivered_remote,
    parts: [
      { label: t('local'), value: (d) => d.delivered_local },
      { label: t('remote'), value: (d) => d.delivered_remote },
    ],
  },
  { id: 'bounced', label: t('Bounced emails'), color: ['#eda100', '#c98500'], value: (d) => d.bounced },
  { id: 'quarantined', label: t('Quarantined emails'), color: ['#e87ba4', '#d55181'], value: (d) => d.quarantined },
  { id: 'discarded', label: t('Discarded'), color: ['#008300', '#008300'], value: (d) => d.discarded },
];

const HEIGHT = 280;
const MARGIN = { top: 12, right: 16, bottom: 28, left: 48 };

/** A round top for the axis, and ticks at quarters of it. */
function niceTop(max: number): number {
  if (max <= 4) return 4;
  const step = 10 ** Math.floor(Math.log10(max / 4));
  const nice = [1, 1.25, 1.5, 2, 2.5, 3, 4, 5, 7.5, 10].map((m) => m * step).find((candidate) => candidate * 4 >= max) ?? step * 10;
  return nice * 4;
}

const parseDay = (date: string) => new Date(`${date}T00:00:00Z`);
const number = (value: number) => value.toLocaleString(uiLocale());

export function DailyStatsChart() {
  const theme = useTheme();
  const dark = theme.palette.mode === 'dark';
  const [days, setDays] = useState(30);
  const { data, reload } = useLoad(() => get<{ days: DailyStats[] }>(`/api/dashboard/daily?days=${days}`), [days]);
  useEffect(() => {
    const timer = setInterval(() => void reload(), 60_000);
    return () => clearInterval(timer);
  }, [reload]);
  const [hidden, setHidden] = useState<Set<string>>(new Set());
  const [hover, setHover] = useState<number | null>(null);
  const [showTable, setShowTable] = useState(false);
  const [holder, width] = useElementWidth(800);
  const titleId = useId();

  const rows = data?.days ?? [];
  const shown = SERIES.filter((series) => !hidden.has(series.id));
  const plot = { width: width - MARGIN.left - MARGIN.right, height: HEIGHT - MARGIN.top - MARGIN.bottom };
  const top = niceTop(Math.max(0, ...rows.flatMap((day) => shown.map((series) => series.value(day)))));
  const x = (index: number) => MARGIN.left + (rows.length > 1 ? (index / (rows.length - 1)) * plot.width : plot.width / 2);
  const y = (value: number) => MARGIN.top + plot.height - (value / top) * plot.height;
  const totals = useMemo(() => {
    const sum = (value: (day: DailyStats) => number) => rows.reduce((total, day) => total + value(day), 0);
    return Object.fromEntries(SERIES.map((series) => [series.id, { value: sum(series.value), parts: (series.parts ?? []).map((part) => sum(part.value)) }]));
  }, [rows]);
  const empty = rows.every((day) => SERIES.every((series) => series.value(day) === 0));

  // About six date labels, whatever the width and period.
  const labelEvery = Math.max(1, Math.ceil(rows.length / Math.max(2, Math.floor(plot.width / 110))));
  const dateLabel = (date: string, withYear = false) =>
    parseDay(date).toLocaleDateString(uiLocale(), { timeZone: 'UTC', month: 'short', day: 'numeric', ...(withYear ? { year: 'numeric', weekday: 'short' } : {}) });

  function onMove(event: React.PointerEvent<SVGSVGElement>) {
    if (rows.length === 0) return;
    const box = event.currentTarget.getBoundingClientRect();
    const fraction = (event.clientX - box.left - MARGIN.left) / plot.width;
    setHover(Math.min(rows.length - 1, Math.max(0, Math.round(fraction * (rows.length - 1)))));
  }

  const toggle = (id: string) =>
    setHidden((current) => {
      const next = new Set(current);
      if (next.has(id)) next.delete(id);
      // At least one line stays.
      else if (next.size < SERIES.length - 1) next.add(id);
      return next;
    });

  const hovered = hover !== null ? rows[hover] : null;
  const tooltipLeft = hover !== null ? x(hover) : 0;
  return (
    <Card variant="outlined" sx={{ mb: 3 }} data-testid="daily-stats">
      <CardContent>
        <Stack direction="row" sx={{ alignItems: 'center', flexWrap: 'wrap', gap: 1, mb: 1.5 }}>
          <Typography variant="h6" id={titleId} sx={{ flex: 1 }}>
            {t('Daily stats')}
          </Typography>
          <ToggleButtonGroup size="small" exclusive value={days} onChange={(_, value) => value && setDays(value)} aria-label={t('Period')}>
            <ToggleButton value={7}>{t('7 days')}</ToggleButton>
            <ToggleButton value={30}>{t('30 days')}</ToggleButton>
            <ToggleButton value={90}>{t('90 days')}</ToggleButton>
          </ToggleButtonGroup>
        </Stack>

        {/* The legend: every line by name with its total for the period; a click hides or shows it. */}
        <Box component="ul" aria-label={t('Series')} sx={{ listStyle: 'none', m: 0, mb: 1.5, p: 0, display: 'flex', flexWrap: { xs: 'nowrap', sm: 'wrap' }, gap: 1, overflowX: { xs: 'auto', sm: 'visible' }, scrollbarWidth: 'thin', '& > li': { flexShrink: 0 } }}>
          {SERIES.map((series) => {
            const off = hidden.has(series.id);
            return (
              <li key={series.id}>
                <Box
                  component="button"
                  type="button"
                  aria-pressed={!off}
                  onClick={() => toggle(series.id)}
                  sx={{
                    display: 'flex', gap: 1, alignItems: 'flex-start', textAlign: 'left', font: 'inherit', color: 'text.primary', cursor: 'pointer', bgcolor: 'transparent',
                    border: 1, borderColor: 'divider', borderRadius: 1.5, px: 1.25, py: 0.75, opacity: off ? 0.45 : 1, '&:hover': { bgcolor: 'action.hover' },
                  }}
                >
                  <Box component="span" sx={{ width: 14, height: 3, mt: 1, borderRadius: 2, flexShrink: 0, bgcolor: series.color[dark ? 1 : 0] }} />
                  <Box component="span">
                    <Typography component="span" variant="body2" sx={{ display: 'block' }}>
                      {series.label}{' '}
                      <Typography component="span" variant="body2" sx={{ fontWeight: 600 }}>{number(totals[series.id]?.value ?? 0)}</Typography>
                    </Typography>
                    {series.parts?.map((part, index) => (
                      <Typography
                        key={part.label}
                        component="span"
                        variant="caption"
                        sx={{
                          color: "text.secondary",
                          display: { xs: 'none', sm: 'block' }
                        }}>
                        {number(totals[series.id]?.parts[index] ?? 0)} – {part.label}
                      </Typography>
                    ))}
                  </Box>
                </Box>
              </li>
            );
          })}
        </Box>

        <Box ref={holder} sx={{ position: 'relative' }}>
          {rows.length === 0 ? null : empty ? (
            <Typography sx={{ color: 'text.secondary', height: HEIGHT, display: 'grid', placeItems: 'center' }}>
              {t('No connections or mail in this period yet.')}
            </Typography>
          ) : (
            <svg width={width} height={HEIGHT} role="img" aria-labelledby={titleId} onPointerMove={onMove} onPointerLeave={() => setHover(null)} style={{ display: 'block', touchAction: 'pan-y' }}>
              {[0, 0.25, 0.5, 0.75, 1].map((fraction) => (
                <g key={fraction}>
                  <line x1={MARGIN.left} x2={width - MARGIN.right} y1={y(fraction * top)} y2={y(fraction * top)} stroke={theme.palette.divider} strokeWidth={1} />
                  <text x={MARGIN.left - 8} y={y(fraction * top) + 4} textAnchor="end" fontSize={11} fill={theme.palette.text.secondary} style={{ fontVariantNumeric: 'tabular-nums' }}>
                    {number(fraction * top)}
                  </text>
                </g>
              ))}
              {rows.map((day, index) =>
                // The last day is always labelled; a regular label too close to it is left out.
                (index % labelEvery === 0 && rows.length - 1 - index >= labelEvery * 0.7) || index === rows.length - 1 ? (
                  <text key={day.date} x={x(index)} y={HEIGHT - 8} textAnchor={index === 0 ? 'start' : index === rows.length - 1 ? 'end' : 'middle'} fontSize={11} fill={theme.palette.text.secondary}>
                    {dateLabel(day.date)}
                  </text>
                ) : null,
              )}
              {shown.map((series) => (
                <path
                  key={series.id}
                  d={rows.map((day, index) => `${index === 0 ? 'M' : 'L'}${x(index).toFixed(1)},${y(series.value(day)).toFixed(1)}`).join(' ')}
                  fill="none"
                  stroke={series.color[dark ? 1 : 0]}
                  strokeWidth={2}
                  strokeLinejoin="round"
                  strokeLinecap="round"
                />
              ))}
              {hovered && (
                <>
                  <line x1={x(hover!)} x2={x(hover!)} y1={MARGIN.top} y2={MARGIN.top + plot.height} stroke={theme.palette.text.secondary} strokeWidth={1} strokeDasharray="3 3" />
                  {shown.map((series) => (
                    <circle key={series.id} cx={x(hover!)} cy={y(series.value(hovered))} r={4.5} fill={series.color[dark ? 1 : 0]} stroke={theme.palette.background.paper} strokeWidth={2} />
                  ))}
                </>
              )}
            </svg>
          )}
          {hovered && (
            <Box
              role="status"
              sx={{
                position: 'absolute', top: 8, pointerEvents: 'none', zIndex: 1, minWidth: 200, p: 1.25, borderRadius: 1.5, boxShadow: 4, bgcolor: 'background.paper', border: 1, borderColor: 'divider',
                ...(tooltipLeft > width / 2 ? { right: width - tooltipLeft + 12 } : { left: tooltipLeft + 12 }),
              }}
            >
              <Typography variant="caption" sx={{ color: 'text.secondary', display: 'block', mb: 0.5 }}>
                {dateLabel(hovered.date, true)}
              </Typography>
              {shown.map((series) => (
                <Box key={series.id} sx={{ mb: 0.25 }}>
                  <Stack direction="row" sx={{ alignItems: 'center', gap: 1 }}>
                    <Box sx={{ width: 10, height: 3, borderRadius: 2, bgcolor: series.color[dark ? 1 : 0] }} />
                    <Typography variant="body2" sx={{ flex: 1 }}>{series.label}</Typography>
                    <Typography variant="body2" sx={{ fontWeight: 600, fontVariantNumeric: 'tabular-nums' }}>{number(series.value(hovered))}</Typography>
                  </Stack>
                  {series.parts?.map((part) => (
                    <Typography key={part.label} variant="caption" sx={{ color: 'text.secondary', display: 'block', pl: 2.25 }}>
                      {number(part.value(hovered))} – {part.label}
                    </Typography>
                  ))}
                </Box>
              ))}
            </Box>
          )}
        </Box>

        <Typography component="button" variant="caption" onClick={() => setShowTable((on) => !on)} aria-expanded={showTable} sx={{ mt: 1, p: 0, border: 0, bgcolor: 'transparent', color: 'text.secondary', cursor: 'pointer', textDecoration: 'underline' }}>
          {showTable ? t('Hide the data table') : t('Show as a table')}
        </Typography>
        {showTable && (
          <Box sx={{ overflowX: 'auto', mt: 1 }}>
            <Table size="small" sx={{ '& thead th': { whiteSpace: 'nowrap' } }} aria-label={t('{{title}}, data', { title: t('Daily stats') })}>
              <TableHead>
                <TableRow>
                  <TableCell>{t('Day')}</TableCell>
                  {SERIES.flatMap((series) => [
                    <TableCell key={series.id} align="right">{series.label}</TableCell>,
                    ...(series.parts ?? []).map((part) => <TableCell key={`${series.id}-${part.label}`} align="right" sx={{ color: 'text.secondary' }}>{part.label}</TableCell>),
                  ])}
                </TableRow>
              </TableHead>
              <TableBody>
                {[...rows].reverse().map((day) => (
                  <TableRow key={day.date}>
                    <TableCell sx={{ whiteSpace: 'nowrap' }}>{dateLabel(day.date, true)}</TableCell>
                    {SERIES.flatMap((series) => [
                      <TableCell key={series.id} align="right" sx={{ fontVariantNumeric: 'tabular-nums' }}>{number(series.value(day))}</TableCell>,
                      ...(series.parts ?? []).map((part) => <TableCell key={`${series.id}-${part.label}`} align="right" sx={{ color: 'text.secondary', fontVariantNumeric: 'tabular-nums' }}>{number(part.value(day))}</TableCell>),
                    ])}
                  </TableRow>
                ))}
              </TableBody>
            </Table>
          </Box>
        )}
      </CardContent>
    </Card>
  );
}
