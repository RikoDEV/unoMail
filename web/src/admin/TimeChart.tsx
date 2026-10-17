// A single-series area chart over time, for the capacity graphs on the dashboard.
//
// One measure per chart and one y-axis starting at zero; the line carries the data and
// everything else (grid, axis labels) stays in the background. Hovering shows the exact value,
// and a table of the same data is one click away.

import { Box, Card, CardContent, Table, TableBody, TableCell, TableHead, TableRow, Typography, useTheme } from '@mui/material';
import { useEffect, useId, useMemo, useRef, useState } from 'react';

import { t, uiLocale } from '../i18n';
export interface ChartPoint {
  /** Unix seconds. */
  t: number;
  v: number;
}

interface Props {
  title: string;
  /** The current value in words, shown as the headline. */
  headline: string;
  hint?: string;
  points: ChartPoint[];
  /** Top of the y-axis (for example the total capacity). */
  max: number;
  format: (value: number) => string;
}

const HEIGHT = 200;
const MARGIN = { top: 10, right: 12, bottom: 24, left: 64 };

function timeLabel(seconds: number, spanSeconds: number): string {
  const date = new Date(seconds * 1000);
  return spanSeconds > 36 * 3600
    ? date.toLocaleDateString(uiLocale(), { month: 'short', day: 'numeric', hour: '2-digit' })
    : date.toLocaleTimeString(uiLocale(), { hour: '2-digit', minute: '2-digit' });
}

export function TimeChart({ title, headline, hint, points, max, format }: Props) {
  const theme = useTheme();
  const holder = useRef<HTMLDivElement>(null);
  const [width, setWidth] = useState(480);
  const [hover, setHover] = useState<number | null>(null);
  const [showTable, setShowTable] = useState(false);
  const titleId = useId();
  // The lighter shade keeps the line readable on dark surfaces.
  const color = theme.palette.mode === 'dark' ? theme.palette.primary.light : theme.palette.primary.main;

  useEffect(() => {
    const element = holder.current;
    if (!element) return;
    const observer = new ResizeObserver(([entry]) => setWidth(Math.max(280, Math.floor(entry.contentRect.width))));
    observer.observe(element);
    return () => observer.disconnect();
  }, []);

  const plot = { width: width - MARGIN.left - MARGIN.right, height: HEIGHT - MARGIN.top - MARGIN.bottom };
  const top = Math.max(max, ...points.map((p) => p.v), 1);
  const start = points[0]?.t ?? 0;
  const end = points[points.length - 1]?.t ?? 1;
  const span = Math.max(end - start, 1);
  const x = (t: number) => MARGIN.left + (points.length > 1 ? ((t - start) / span) * plot.width : plot.width);
  const y = (v: number) => MARGIN.top + plot.height - (v / top) * plot.height;
  const line = useMemo(() => points.map((p, i) => `${i === 0 ? 'M' : 'L'}${x(p.t).toFixed(1)},${y(p.v).toFixed(1)}`).join(' '), [points, width, top]); // eslint-disable-line react-hooks/exhaustive-deps
  const area = points.length > 1 ? `${line} L${x(end).toFixed(1)},${y(0)} L${x(start).toFixed(1)},${y(0)} Z` : '';
  const ticks = [0, 0.5, 1].map((fraction) => fraction * top);
  const hovered = hover !== null ? points[hover] : null;

  function onMove(event: React.MouseEvent<SVGSVGElement>) {
    if (points.length === 0) return;
    const box = event.currentTarget.getBoundingClientRect();
    const at = start + ((event.clientX - box.left - MARGIN.left) / plot.width) * span;
    let nearest = 0;
    for (let i = 1; i < points.length; i += 1) if (Math.abs(points[i].t - at) < Math.abs(points[nearest].t - at)) nearest = i;
    setHover(nearest);
  }

  // A table needs far fewer rows than the chart has points.
  const step = Math.max(1, Math.ceil(points.length / 12));
  const rows = points.filter((_, index) => index % step === 0 || index === points.length - 1);
  return (
    <Card variant="outlined" sx={{ flex: '1 1 380px', minWidth: 0 }}>
      <CardContent>
        <Typography variant="body2" color="text.secondary" id={titleId}>
          {title}
        </Typography>
        <Typography variant="h5" component="div" data-testid={`chart-headline-${title}`}>
          {headline}
        </Typography>
        <Typography variant="caption" color="text.secondary" sx={{ display: 'block', minHeight: 20 }}>
          {hovered ? `${new Date(hovered.t * 1000).toLocaleString(uiLocale())}: ${format(hovered.v)}` : hint}
        </Typography>
        <Box ref={holder} sx={{ mt: 1 }}>
          {points.length < 2 ? (
            <Typography color="text.secondary" sx={{ height: HEIGHT, display: 'grid', placeItems: 'center' }}>
              {t('Collecting data. The chart fills in as the server runs.')}
            </Typography>
          ) : (
            <svg width={width} height={HEIGHT} role="img" aria-labelledby={titleId} onMouseMove={onMove} onMouseLeave={() => setHover(null)} style={{ display: 'block', touchAction: 'none' }}>
              {ticks.map((tick) => (
                <g key={tick}>
                  <line x1={MARGIN.left} x2={width - MARGIN.right} y1={y(tick)} y2={y(tick)} stroke={theme.palette.divider} strokeWidth={1} />
                  <text x={MARGIN.left - 8} y={y(tick) + 4} textAnchor="end" fontSize={11} fill={theme.palette.text.secondary}>
                    {format(tick)}
                  </text>
                </g>
              ))}
              {[start, start + span / 2, end].map((t, index) => (
                <text key={t} x={x(t)} y={HEIGHT - 6} textAnchor={index === 0 ? 'start' : index === 2 ? 'end' : 'middle'} fontSize={11} fill={theme.palette.text.secondary}>
                  {timeLabel(t, span)}
                </text>
              ))}
              <path d={area} fill={color} opacity={0.14} />
              <path d={line} fill="none" stroke={color} strokeWidth={2} strokeLinejoin="round" strokeLinecap="round" />
              {hovered && (
                <>
                  <line x1={x(hovered.t)} x2={x(hovered.t)} y1={MARGIN.top} y2={MARGIN.top + plot.height} stroke={theme.palette.text.secondary} strokeWidth={1} strokeDasharray="3 3" />
                  <circle cx={x(hovered.t)} cy={y(hovered.v)} r={4.5} fill={color} stroke={theme.palette.background.paper} strokeWidth={2} />
                </>
              )}
            </svg>
          )}
        </Box>
        <Typography component="button" variant="caption" onClick={() => setShowTable((shown) => !shown)} sx={{ mt: 0.5, p: 0, border: 0, bgcolor: 'transparent', color: 'text.secondary', cursor: 'pointer', textDecoration: 'underline' }} aria-expanded={showTable}>
          {showTable ? t('Hide the data table') : t('Show as a table')}
        </Typography>
        {showTable && (
          <Table size="small" aria-label={t('{{title}}, data', { title })} sx={{ mt: 1 }}>
            <TableHead>
              <TableRow>
                <TableCell>{t('Time')}</TableCell>
                <TableCell align="right">{title}</TableCell>
              </TableRow>
            </TableHead>
            <TableBody>
              {rows.map((row) => (
                <TableRow key={row.t}>
                  <TableCell>{new Date(row.t * 1000).toLocaleString(uiLocale())}</TableCell>
                  <TableCell align="right">{format(row.v)}</TableCell>
                </TableRow>
              ))}
            </TableBody>
          </Table>
        )}
      </CardContent>
    </Card>
  );
}
