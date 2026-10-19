import Delete from '@mui/icons-material/Delete';
import Replay from '@mui/icons-material/Replay';
import { Alert, Button, FormControlLabel, IconButton, MenuItem, Stack, Switch, Tab, TableBody, TableCell, TableHead, TableRow, Tabs, TextField, Tooltip, Typography } from '@mui/material';
import { useCallback, useEffect, useState } from 'react';
import { del, formatBytes, formatTime, get, post, errorText } from '../api';
import { useAuth } from '../app';
import { PageHeader, rowWithDetail, StatusChip, useAction, useCompactTable, useLoad, ScrollTable } from './common';

import { t } from '../i18n';
interface QueueEntry {
  id: number;
  sender: string;
  recipient: string;
  size: number;
  attempts: number;
  next_attempt_at: number;
  created_at: number;
  last_error: string | null;
  status: string;
}

export function Queue() {
  const { data, error, reload } = useLoad(() => get<QueueEntry[]>('/api/queue'), []);
  const { run, feedback } = useAction();
  const compact = useCompactTable();
  useEffect(() => {
    const timer = setInterval(() => void reload(), 5000);
    return () => clearInterval(timer);
  }, [reload]);
  return (
    <>
      <PageHeader title={t('Delivery queue')} />
      {error && <Alert severity="error">{error}</Alert>}
      {feedback}
      {data?.length === 0 && <Typography color="text.secondary">{t('The queue is empty.')}</Typography>}
      {data && data.length > 0 && (
        <ScrollTable size="small" aria-label={t('Queue')}>
          <TableHead>
            <TableRow>
              <TableCell>{t('Queued')}</TableCell>
              <TableCell>{t('Sender')}</TableCell>
              <TableCell>{t('Recipient')}</TableCell>
              <TableCell align="right">{t('Size')}</TableCell>
              <TableCell align="right">{t('Attempts')}</TableCell>
              <TableCell>{t('Next attempt')}</TableCell>
              {!compact && <TableCell>{t('Last error')}</TableCell>}
              <TableCell />
            </TableRow>
          </TableHead>
          <TableBody>
            {data.map((entry) =>
              rowWithDetail(
                entry.id,
                compact,
                <>
                  <TableCell sx={{ whiteSpace: 'nowrap' }}>{formatTime(entry.created_at)}</TableCell>
                  <TableCell>{entry.sender || '<>'}</TableCell>
                  <TableCell>{entry.recipient}</TableCell>
                  <TableCell align="right">{formatBytes(entry.size)}</TableCell>
                  <TableCell align="right">{entry.attempts}</TableCell>
                  <TableCell sx={{ whiteSpace: 'nowrap' }}>{entry.status === 'sending' ? t('in progress') : formatTime(entry.next_attempt_at)}</TableCell>
                  {!compact && <TableCell sx={{ minWidth: 220, maxWidth: 320, overflowWrap: 'anywhere' }}>{entry.last_error}</TableCell>}
                  <TableCell align="right" sx={{ whiteSpace: 'nowrap' }}>
                    <Tooltip title={t('Retry now')}>
                      <IconButton aria-label={t('Retry {{recipient}}', { recipient: entry.recipient })} onClick={async () => { if (await run(() => post(`/api/queue/${entry.id}/retry`), t('Retry scheduled'))) await reload(); }}>
                        <Replay />
                      </IconButton>
                    </Tooltip>
                    <Tooltip title={t('Remove from queue')}>
                      <IconButton aria-label={t('Remove {{recipient}}', { recipient: entry.recipient })} onClick={async () => { if (await run(() => del(`/api/queue/${entry.id}`), t('Removed from queue'))) await reload(); }}>
                        <Delete />
                      </IconButton>
                    </Tooltip>
                  </TableCell>
                </>,
                t('Last error'),
                entry.last_error,
                7,
              ),
            )}
          </TableBody>
        </ScrollTable>
      )}
    </>
  );
}

interface DeliveryRow {
  id: number;
  ts: number;
  direction: string;
  sender: string;
  recipient: string;
  status: string;
  detail: string;
  remote: string;
}

interface AuditRow {
  id: number;
  ts: number;
  actor: string;
  action: string;
  target: string;
  ip: string;
  detail: string;
}

const MAX_ROWS = 1000;

/**
 * Log table data with search and a live tail. New entries are pushed by the server over a
 * server-sent event stream; the search filter is applied to streamed entries in the browser.
 */
function useLogStream<T extends { id: number }>(path: string, kind: string, query: string, needle: string, live: boolean, enabled: boolean) {
  const [rows, setRows] = useState<T[]>([]);
  const [error, setError] = useState('');
  const [connected, setConnected] = useState(false);

  const loadInitial = useCallback(async () => {
    if (!enabled) return;
    try {
      setRows(await get<T[]>(`${path}?limit=200&${query}`));
      setError('');
    } catch (err) {
      setError(errorText(err, t('Failed to load')));
    }
  }, [path, query, enabled]);

  useEffect(() => {
    void loadInitial();
  }, [loadInitial]);

  useEffect(() => {
    if (!live || !enabled) return;
    const source = new EventSource(`/api/logs/stream?kind=${kind}`);
    source.onopen = () => setConnected(true);
    source.onerror = () => setConnected(false);
    source.addEventListener(kind, (event) => {
      const entry = JSON.parse((event as MessageEvent).data) as T;
      const text = JSON.stringify(entry).toLowerCase();
      if (needle && !text.includes(needle.toLowerCase())) return;
      setRows((current) => (current.some((r) => r.id === entry.id) ? current : [entry, ...current].slice(0, MAX_ROWS)));
    });
    return () => {
      source.close();
      setConnected(false);
    };
  }, [live, enabled, kind, needle]);

  const loadOlder = useCallback(async () => {
    const oldest = rows[rows.length - 1]?.id;
    if (!oldest) return;
    const data = await get<T[]>(`${path}?limit=200&before=${oldest}&${query}`).catch(() => [] as T[]);
    setRows((current) => [...current, ...data]);
  }, [rows, path, query]);

  return { rows, error, loadOlder, connected };
}

interface SystemRow {
  id: number;
  ts: number;
  level: string;
  target: string;
  message: string;
}

interface SmtpRow {
  id: number;
  ts: number;
  ip: string;
  code: number;
  text: string;
}

export function Logs() {
  const { account } = useAuth();
  const isSuper = account?.role === 'super_admin';
  const [tab, setTab] = useState<'delivery' | 'audit' | 'system' | 'smtp'>('delivery');
  const [search, setSearch] = useState('');
  const [debounced, setDebounced] = useState('');
  const [status, setStatus] = useState('');
  const [live, setLive] = useState(true);
  const compact = useCompactTable();

  useEffect(() => {
    const timer = setTimeout(() => setDebounced(search.trim()), 300);
    return () => clearTimeout(timer);
  }, [search]);

  const query = `q=${encodeURIComponent(debounced)}${tab === 'delivery' && status ? `&status=${encodeURIComponent(status)}` : ''}`;
  const statusFilter = tab === 'delivery' && status ? status : '';
  const delivery = useLogStream<DeliveryRow>('/api/logs/delivery', 'delivery', query, statusFilter || debounced, live, tab === 'delivery');
  const audit = useLogStream<AuditRow>('/api/logs/audit', 'audit', query, debounced, live, tab === 'audit' && isSuper);
  const system = useLogStream<SystemRow>('/api/logs/system', 'system', query, debounced, live, tab === 'system' && isSuper);
  const smtp = useLogStream<SmtpRow>('/api/logs/smtp', 'smtp', query, debounced, live, tab === 'smtp' && isSuper);
  const active = tab === 'delivery' ? delivery : tab === 'audit' ? audit : tab === 'smtp' ? smtp : system;

  return (
    <>
      <PageHeader title={t('Logs')}>
        <TextField label={t('Search')} value={search} onChange={(e) => setSearch(e.target.value)} sx={{ width: 260 }} />
        {tab === 'delivery' && (
          <TextField select label={t('Status')} value={status} onChange={(e) => setStatus(e.target.value)} sx={{ width: 150 }}>
            <MenuItem value="">{t('All')}</MenuItem>
            {['delivered', 'queued', 'deferred', 'bounced', 'rejected', 'junk'].map((s) => (
              <MenuItem key={s} value={s}>
                {s}
              </MenuItem>
            ))}
          </TextField>
        )}
        <FormControlLabel control={<Switch checked={live} onChange={(e) => setLive(e.target.checked)} />} label={live && active.connected ? t('Live tail (connected)') : t('Live tail')} />
      </PageHeader>
      <Tabs value={tab} onChange={(_, value) => setTab(value)} variant="scrollable" scrollButtons="auto" allowScrollButtonsMobile sx={{ mb: 1 }}>
        <Tab value="delivery" label={t('Mail delivery')} />
        {isSuper && <Tab value="audit" label={t('Security audit')} />}
        {isSuper && <Tab value="smtp" label={t('SMTP replies')} />}
        {isSuper && <Tab value="system" label={t('System')} />}
      </Tabs>
      {active.error && <Alert severity="error">{active.error}</Alert>}
      {tab === 'smtp' ? (
        <ScrollTable size="small" aria-label={t('SMTP replies')} sx={{ '& td': { fontSize: 13 } }}>
          <TableHead>
            <TableRow>
              <TableCell>{t('Time')}</TableCell>
              <TableCell>{t('Status')}</TableCell>
              {!compact && <TableCell>{t('Message')}</TableCell>}
              <TableCell>{t('Sent to')}</TableCell>
            </TableRow>
          </TableHead>
          <TableBody>
            {smtp.rows.map((row) =>
              rowWithDetail(
                row.id,
                compact,
                <>
                  <TableCell sx={{ whiteSpace: 'nowrap' }}>{formatTime(row.ts)}</TableCell>
                  <TableCell>
                    <StatusChip status={row.code >= 500 ? 'error' : row.code >= 400 ? 'warning' : 'ok'} />
                    <Typography component="span" sx={{ ml: 1, fontFamily: 'monospace', fontSize: 13 }}>{row.code}</Typography>
                  </TableCell>
                  {!compact && <TableCell sx={{ wordBreak: 'break-word' }}>{row.text}</TableCell>}
                  <TableCell sx={{ fontFamily: 'monospace' }}>{row.ip}</TableCell>
                </>,
                t('Message'),
                row.text,
                3,
              ),
            )}
          </TableBody>
        </ScrollTable>
      ) : tab === 'system' ? (
        <ScrollTable size="small" aria-label={t('System log')} sx={{ '& td': { fontSize: 13 } }}>
          <TableHead>
            <TableRow>
              <TableCell>{t('Time')}</TableCell>
              <TableCell>{t('Level')}</TableCell>
              <TableCell>{t('Component')}</TableCell>
              {!compact && <TableCell>{t('Message')}</TableCell>}
            </TableRow>
          </TableHead>
          <TableBody>
            {system.rows.map((row) =>
              rowWithDetail(
                row.id,
                compact,
                <>
                  <TableCell sx={{ whiteSpace: 'nowrap' }}>{formatTime(row.ts)}</TableCell>
                  <TableCell>
                    <StatusChip status={row.level === 'ERROR' ? 'error' : row.level === 'WARN' ? 'warning' : 'ok'} />
                  </TableCell>
                  <TableCell sx={{ fontFamily: 'monospace' }}>{row.target}</TableCell>
                  {!compact && <TableCell sx={{ wordBreak: 'break-word' }}>{row.message}</TableCell>}
                </>,
                t('Message'),
                row.message,
                3,
              ),
            )}
          </TableBody>
        </ScrollTable>
      ) : tab === 'delivery' ? (
        <ScrollTable size="small" aria-label={t('Delivery log')} sx={{ '& td': { fontSize: 13 } }}>
          <TableHead>
            <TableRow>
              <TableCell>{t('Time')}</TableCell>
              <TableCell>{t('Direction')}</TableCell>
              <TableCell>{t('Sender')}</TableCell>
              <TableCell>{t('Recipient')}</TableCell>
              <TableCell>{t('Status')}</TableCell>
              {!compact && <TableCell>{t('Detail')}</TableCell>}
            </TableRow>
          </TableHead>
          <TableBody>
            {delivery.rows.map((row) => {
              const detail = [row.remote, row.detail].filter(Boolean).join(' · ');
              return rowWithDetail(
                row.id,
                compact,
                <>
                  <TableCell sx={{ whiteSpace: 'nowrap' }}>{formatTime(row.ts)}</TableCell>
                  <TableCell>{row.direction}</TableCell>
                  <TableCell>{row.sender || '<>'}</TableCell>
                  <TableCell>{row.recipient}</TableCell>
                  <TableCell>
                    <StatusChip status={row.status} />
                  </TableCell>
                  {!compact && <TableCell sx={{ maxWidth: 380, wordBreak: 'break-word' }}>{detail}</TableCell>}
                </>,
                t('Detail'),
                detail,
                5,
              );
            })}
          </TableBody>
        </ScrollTable>
      ) : (
        <ScrollTable size="small" aria-label={t('Audit log')} sx={{ '& td': { fontSize: 13 } }}>
          <TableHead>
            <TableRow>
              <TableCell>{t('Time')}</TableCell>
              <TableCell>{t('Actor')}</TableCell>
              <TableCell>{t('Action')}</TableCell>
              <TableCell>{t('Target')}</TableCell>
              <TableCell>{t('Address')}</TableCell>
              {!compact && <TableCell>{t('Detail')}</TableCell>}
            </TableRow>
          </TableHead>
          <TableBody>
            {audit.rows.map((row) =>
              rowWithDetail(
                row.id,
                compact,
                <>
                  <TableCell sx={{ whiteSpace: 'nowrap' }}>{formatTime(row.ts)}</TableCell>
                  <TableCell>{row.actor}</TableCell>
                  <TableCell sx={{ fontFamily: 'monospace' }}>{row.action}</TableCell>
                  <TableCell>{row.target}</TableCell>
                  <TableCell>{row.ip}</TableCell>
                  {!compact && <TableCell sx={{ maxWidth: 380, wordBreak: 'break-word' }}>{row.detail}</TableCell>}
                </>,
                t('Detail'),
                row.detail,
                5,
              ),
            )}
          </TableBody>
        </ScrollTable>
      )}
      {active.rows.length === 0 && !active.error && <Typography color="text.secondary" sx={{ mt: 2 }}>{t('No log entries match.')}</Typography>}
      {active.rows.length >= 200 && tab !== 'system' && tab !== 'smtp' && (
        <Stack alignItems="center" sx={{ mt: 2 }}>
          <Button onClick={() => void active.loadOlder()}>{t('Load older entries')}</Button>
        </Stack>
      )}
    </>
  );
}
