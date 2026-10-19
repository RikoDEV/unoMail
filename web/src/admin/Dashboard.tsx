import { Alert, Box, Card, CardContent, Chip, Stack, TableBody, TableCell, TableHead, TableRow, ToggleButton, ToggleButtonGroup, Typography } from '@mui/material';
import { useEffect, useState } from 'react';
import { formatBytes, get } from '../api';
import { formatTime } from '../api';
import { PageHeader, StatusChip, useLoad, ScrollTable } from './common';
import { RemoteAddress } from './RemoteAddress';
import { DailyStatsChart } from './DailyStatsChart';
import { type ChartSeries, TimeChart } from './TimeChart';

import { t, uiLocale } from '../i18n';
interface DashboardData {
  hostname: string;
  uptime_seconds: number;
  domains: number;
  mailboxes: number;
  aliases: number;
  queue_size: number;
  queue_deferred: number;
  blocked_accounts: number;
  mail_bytes: number;
  disk_bytes: number;
  active_connections: number;
  spam_blocked: number;
  messages_received: number;
  messages_sent: number;
  messages_rejected: number;
  auth_failures: number;
  last_24h: { direction: string; status: string; count: number }[];
  certificate: { kind: string; not_after: number; seconds_remaining: number; healthy: boolean };
  rspamd_enabled: boolean;
  clamav_enabled: boolean;
}

interface Activity {
  remote_ips: { ip: string; connections: number; last_seen: number; rdns: string | null; country: string | null }[];
  replies: { ts: number; ip: string; code: number; text: string }[];
}

/** Colour of an SMTP status code by its class: 2xx/3xx fine, 4xx temporary, 5xx refused. */
const replyColor = (code: number) => (code >= 500 ? 'error' : code >= 400 ? 'warning' : 'success');

/** Mail flow, who connected and what they were told, side by side on wide screens. */
function ActivityTables({ flow, activity }: { flow: DashboardData['last_24h']; activity: Activity | null }) {
  const countries = Object.fromEntries((activity?.remote_ips ?? []).map((entry) => [entry.ip, entry.country]));
  return (
    // Columns follow the room the section has (the admin menu takes part of the window):
    // three side by side, or mail flow and addresses over the replies, or one below another.
    <Box sx={{ mt: 1, containerType: 'inline-size' }}>
    <Box
      data-testid="activity"
      sx={{
        display: 'grid', gap: 3, alignItems: 'start', gridTemplateColumns: 'minmax(0, 1fr)',
        '@container (min-width: 700px)': { gridTemplateColumns: 'minmax(0, 1fr) minmax(0, 1fr)', '& > :last-of-type': { gridColumn: '1 / -1' } },
        '@container (min-width: 1100px)': { gridTemplateColumns: 'minmax(0, 0.8fr) minmax(0, 1fr) minmax(0, 1.5fr)', '& > :last-of-type': { gridColumn: 'auto' } },
      }}
    >
      <Box sx={{ minWidth: 0 }}>
        <Typography variant="h6" sx={{ mb: 1 }}>
          {t('Mail flow, last 24 hours')}
        </Typography>
        {flow.length === 0 ? (
          <Typography color="text.secondary">{t('No mail has been processed yet.')}</Typography>
        ) : (
          <ScrollTable size="small" aria-label={t('Mail flow, last 24 hours')}>
            <TableHead>
              <TableRow>
                <TableCell>{t('Direction')}</TableCell>
                <TableCell>{t('Status')}</TableCell>
                <TableCell align="right">{t('Messages')}</TableCell>
              </TableRow>
            </TableHead>
            <TableBody>
              {flow.map((row) => (
                <TableRow key={`${row.direction}-${row.status}`}>
                  <TableCell>{row.direction}</TableCell>
                  <TableCell>
                    <StatusChip status={row.status} />
                  </TableCell>
                  <TableCell align="right">{row.count}</TableCell>
                </TableRow>
              ))}
            </TableBody>
          </ScrollTable>
        )}
      </Box>
      <Box sx={{ minWidth: 0 }}>
        <Typography variant="h6" sx={{ mb: 1 }}>
          {t('Remote IPs')}
        </Typography>
        {!activity ? null : activity.remote_ips.length === 0 ? (
          <Typography color="text.secondary">{t('Nobody has connected since the server started.')}</Typography>
        ) : (
          <ScrollTable size="small" aria-label={t('Remote IPs')}>
            <TableHead>
              <TableRow>
                <TableCell>{t('Address')}</TableCell>
                <TableCell align="right">{t('Connections')}</TableCell>
                <TableCell>{t('Last seen')}</TableCell>
              </TableRow>
            </TableHead>
            <TableBody>
              {activity.remote_ips.map((entry) => (
                <TableRow key={entry.ip}>
                  <TableCell>
                    <RemoteAddress address={entry.ip} rdns={entry.rdns} country={entry.country} />
                  </TableCell>
                  <TableCell align="right">{entry.connections}</TableCell>
                  <TableCell sx={{ whiteSpace: 'nowrap' }}>{formatTime(entry.last_seen)}</TableCell>
                </TableRow>
              ))}
            </TableBody>
          </ScrollTable>
        )}
      </Box>
      <Box sx={{ minWidth: 0 }}>
        <Typography variant="h6" sx={{ mb: 1 }}>
          {t('Last messages')}
        </Typography>
        {!activity ? null : activity.replies.length === 0 ? (
          <Typography color="text.secondary">{t('No SMTP conversation has taken place yet.')}</Typography>
        ) : (
          <ScrollTable size="small" aria-label={t('Last messages')}>
            <TableHead>
              <TableRow>
                <TableCell>{t('Time')}</TableCell>
                <TableCell>{t('Status')}</TableCell>
                <TableCell>{t('Message')}</TableCell>
                <TableCell>{t('Sent to')}</TableCell>
              </TableRow>
            </TableHead>
            <TableBody>
              {activity.replies.map((reply, index) => (
                <TableRow key={`${reply.ts}-${index}`}>
                  <TableCell sx={{ whiteSpace: 'nowrap' }}>{new Date(reply.ts * 1000).toLocaleTimeString(uiLocale())}</TableCell>
                  <TableCell>
                    <Chip size="small" label={reply.code} color={replyColor(reply.code)} />
                  </TableCell>
                  <TableCell sx={{ overflowWrap: 'anywhere' }}>{reply.text}</TableCell>
                  <TableCell>
                    <RemoteAddress address={reply.ip} country={countries[reply.ip]} />
                  </TableCell>
                </TableRow>
              ))}
            </TableBody>
          </ScrollTable>
        )}
      </Box>
    </Box>
    </Box>
  );
}

interface SystemSample {
  ts: number;
  disk_free: number;
  disk_total: number;
  mem_used: number;
  mem_total: number;
  process: number;
  /** Bytes per service; missing for samples taken before it was recorded. */
  services: Record<string, number> | null;
}

/** Memory layers, bottom first, in the fixed categorical order; "other" stays neutral. */
const MEMORY_SERIES: ChartSeries[] = [
  { key: 'unomail', label: 'unoMail', light: '#2a78d6', dark: '#3987e5' },
  { key: 'rspamd', label: 'Rspamd', light: '#eb6834', dark: '#d95926' },
  { key: 'clamav', label: 'ClamAV', light: '#1baf7a', dark: '#199e70' },
  { key: 'redis', label: 'Redis', light: '#eda100', dark: '#c98500' },
  { key: 'other', label: t('Other'), light: '#a3a29b', dark: '#6f6e68' },
];

/** Free space on the data volume and memory in use, over the chosen period. */
function Capacity() {
  const [hours, setHours] = useState(24);
  const { data, reload } = useLoad(() => get<{ samples: SystemSample[] }>(`/api/dashboard/system?hours=${hours}`), [hours]);
  useEffect(() => {
    const timer = setInterval(() => void reload(), 60_000);
    return () => clearInterval(timer);
  }, [reload]);
  const samples = data?.samples ?? [];
  const latest = samples[samples.length - 1];
  if (!latest) return null;
  const percent = (part: number, whole: number) => (whole > 0 ? `${Math.round((part / whole) * 100)}%` : '');
  return (
    <Box sx={{ mt: 4 }} data-testid="capacity">
      <Stack direction="row" alignItems="center" sx={{ mb: 1 }}>
        <Typography variant="h6" sx={{ flex: 1 }}>
          {t('Capacity')}
        </Typography>
        <ToggleButtonGroup size="small" exclusive value={hours} onChange={(_, value) => value && setHours(value)} aria-label={t('Period')}>
          <ToggleButton value={24}>{t('24 hours')}</ToggleButton>
          <ToggleButton value={168}>{t('7 days')}</ToggleButton>
        </ToggleButtonGroup>
      </Stack>
      <Stack direction="row" flexWrap="wrap" gap={2}>
        <TimeChart
          title={t('Free disk space')}
          headline={t('{{size}} free', { size: formatBytes(latest.disk_free) })}
          hint={t('{{percent}} of {{disk_total}} on the data volume', { percent: percent(latest.disk_free, latest.disk_total), disk_total: formatBytes(latest.disk_total) })}
          points={samples.map((sample) => ({ t: sample.ts, v: sample.disk_free }))}
          max={latest.disk_total}
          format={formatBytes}
        />
        <TimeChart
          title={t('Memory in use')}
          headline={t('{{size}} used', { size: formatBytes(latest.mem_used) })}
          hint={t('{{percent}} of {{mem_total}}', { percent: percent(latest.mem_used, latest.mem_total), mem_total: formatBytes(latest.mem_total) })}
          points={samples.map((sample) => ({ t: sample.ts, v: sample.mem_used, parts: sample.services ?? { other: sample.mem_used } }))}
          series={MEMORY_SERIES}
          max={latest.mem_total}
          format={formatBytes}
        />
      </Stack>
    </Box>
  );
}

function Metric({ label, value, hint }: { label: string; value: string | number; hint?: string }) {
  return (
    <Card variant="outlined" sx={{ minWidth: 170, flex: '1 1 170px' }}>
      <CardContent>
        <Typography variant="body2" color="text.secondary">
          {label}
        </Typography>
        <Typography variant="h4" component="div" data-testid={`metric-${label}`}>
          {value}
        </Typography>
        {hint && (
          <Typography variant="caption" color="text.secondary">
            {hint}
          </Typography>
        )}
      </CardContent>
    </Card>
  );
}

const CERT_KINDS: Record<string, string> = { self_signed: t('self-signed'), acme: t('Let’s Encrypt'), custom: t('custom') };

function duration(seconds: number): string {
  const days = Math.floor(seconds / 86400);
  const hours = Math.floor((seconds % 86400) / 3600);
  return days > 0 ? `${days}d ${hours}h` : `${hours}h ${Math.floor((seconds % 3600) / 60)}m`;
}

export function DashboardPage() {
  const { data, error, reload } = useLoad(() => get<DashboardData>('/api/dashboard'), []);
  const activity = useLoad(() => get<Activity>('/api/dashboard/activity'), []);
  const reloadActivity = activity.reload;
  // Real-time overview: poll every few seconds while the page is open.
  useEffect(() => {
    const timer = setInterval(() => {
      void reload();
      void reloadActivity();
    }, 5000);
    return () => clearInterval(timer);
  }, [reload, reloadActivity]);

  if (error) return <Alert severity="error">{error}</Alert>;
  if (!data) return null;
  const cert = data.certificate;
  const days = Math.floor(cert.seconds_remaining / 86400);
  return (
    <>
      <PageHeader title={t('Dashboard')}>
        <Chip label={data.hostname} />
        <Chip label={t('up {{duration}}', { duration: duration(data.uptime_seconds) })} variant="outlined" />
      </PageHeader>
      {!cert.healthy && (
        <Alert severity="warning" sx={{ mb: 2 }}>
          {cert.kind === 'self_signed' ? t('The server is using a self-signed certificate. Configure Let’s Encrypt or upload a certificate.') : t('The TLS certificate expires in {{days}} days.', { days })}
        </Alert>
      )}
      {!data.clamav_enabled && !data.rspamd_enabled && (
        <Alert severity="warning" sx={{ mb: 2 }} data-testid="no-virus-scanner">
          {t('Incoming mail is not scanned for viruses. Programs (.exe, .js, …) are refused by name, but infected documents get through. Configure ClamAV (UNOMAIL_CLAMAV_ADDR) or Rspamd with its antivirus module.')}
        </Alert>
      )}
      {data.blocked_accounts > 0 && (
        <Alert severity="error" sx={{ mb: 2 }}>
          {t('{{count}} accounts are blocked from sending because of suspicious outbound activity.', { count: data.blocked_accounts })}
        </Alert>
      )}
      <Stack direction="row" flexWrap="wrap" gap={2} sx={{ mb: 3 }}>
        <Metric label={t('Queue size')} value={data.queue_size} hint={t('{{count}} deferred', { count: data.queue_deferred })} />
        <Metric label={t('Active connections')} value={data.active_connections} />
        <Metric label={t('Disk usage')} value={formatBytes(data.disk_bytes)} hint={t('{{mail_bytes}} in mailboxes', { mail_bytes: formatBytes(data.mail_bytes) })} />
        <Metric label={t('Blocked spam')} value={data.spam_blocked} hint={data.rspamd_enabled ? t('Rspamd active') : t('Rspamd not configured')} />
        <Metric label={t('Certificate')} value={`${days} d`} hint={t('{{value}} · until expiry', { value: CERT_KINDS[cert.kind] ?? cert.kind })} />
        <Metric label={t('Domains')} value={data.domains} />
        <Metric label={t('Mailboxes')} value={data.mailboxes} hint={t('{{count}} aliases', { count: data.aliases })} />
        <Metric label={t('Failed logins')} value={data.auth_failures} hint={t('since start')} />
      </Stack>
      <DailyStatsChart />
      <ActivityTables flow={data.last_24h} activity={activity.data ?? null} />
      <Capacity />
    </>
  );
}
