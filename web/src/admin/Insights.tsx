// DMARC report dashboard, server diagnostics and the interactive API reference.

import ExpandMore from '@mui/icons-material/ExpandMore';
import Refresh from '@mui/icons-material/Refresh';
import UploadFile from '@mui/icons-material/UploadFile';
import {
  Accordion, AccordionDetails, AccordionSummary, Alert, Box, Button, Card, CardContent, Chip, CircularProgress, Dialog, DialogContent, DialogTitle,
  LinearProgress, MenuItem, Stack, Table, TableBody, TableCell, TableHead, TableRow, TextField, Typography,
} from '@mui/material';
import { useState } from 'react';
import { formatTime, get, postRaw } from '../api';
import { useAuth } from '../app';
import { PageHeader, StatusChip, useAction, useLoad } from './common';

import { t, uiLocale } from '../i18n';
interface DomainSummary {
  domain: string;
  reports: number;
  messages: number;
  passed: number;
  quarantined: number;
  rejected: number;
}

interface Source {
  source_ip: string;
  messages: number;
  passed: number;
  dkim_passed: number;
  spf_passed: number;
  rejected: number;
}

interface Report {
  id: number;
  org_name: string;
  report_id: string;
  domain: string;
  date_begin: number;
  date_end: number;
  policy: string;
  messages: number;
  passed: number;
}

interface ReportRecord {
  source_ip: string;
  count: number;
  disposition: string;
  dkim: string;
  spf: string;
  header_from: string;
}

const percent = (part: number, total: number) => (total > 0 ? Math.round((part / total) * 100) : 0);

function Compliance({ passed, total }: { passed: number; total: number }) {
  const value = percent(passed, total);
  return (
    <Stack direction="row" alignItems="center" spacing={1} sx={{ minWidth: 150 }}>
      <LinearProgress variant="determinate" value={value} color={value >= 95 ? 'success' : value >= 70 ? 'warning' : 'error'} sx={{ flex: 1, height: 8, borderRadius: 4 }} />
      <Typography variant="body2" sx={{ width: 42, textAlign: 'right' }}>
        {value}%
      </Typography>
    </Stack>
  );
}

export function Dmarc() {
  const { account } = useAuth();
  const [days, setDays] = useState(30);
  const { data, error, reload } = useLoad(() => get<{ domains: DomainSummary[]; sources: Source[]; reports: Report[] }>(`/api/dmarc?days=${days}`), [days]);
  const { run, feedback } = useAction();
  const [detail, setDetail] = useState<{ report: Report; records: ReportRecord[] } | null>(null);

  async function uploadFile(file: File | undefined) {
    if (!file) return;
    await run(async () => {
      const body = await postRaw<{ duplicate?: boolean }>('/api/dmarc/reports', file);
      if (body.duplicate) throw new Error(t('This report was already imported.'));
    }, t('Report imported'));
    await reload();
  }

  return (
    <>
      <PageHeader title={t('DMARC reports')}>
        <TextField select label={t('Period')} value={days} onChange={(e) => setDays(Number(e.target.value))} sx={{ width: 150 }}>
          {[7, 30, 90, 365].map((d) => (
            <MenuItem key={d} value={d}>
              {t('Last {{d}} days', { d })}
            </MenuItem>
          ))}
        </TextField>
        {account?.role === 'super_admin' && (
          <Button component="label" variant="outlined" startIcon={<UploadFile />}>
            {t('Upload report')}
            <input type="file" hidden accept=".xml,.gz,.zip,.eml" aria-label={t('DMARC report file')} onChange={(e) => { void uploadFile(e.target.files?.[0]); e.target.value = ''; }} />
          </Button>
        )}
      </PageHeader>
      {error && <Alert severity="error">{error}</Alert>}
      {feedback}
      <Typography variant="body2" color="text.secondary" sx={{ mb: 2 }}>
        {t('Aggregate reports sent by other mail providers show who sends mail in the name of your domains and whether it passes SPF and DKIM. Reports mailed to an address of a hosted domain (the')}
        <code> rua= </code>{t('address of your DMARC record) are imported automatically.')}
      </Typography>
      {data && data.domains.length === 0 && <Alert severity="info">{t('No reports received in this period yet.')}</Alert>}
      <Stack direction="row" flexWrap="wrap" gap={2} sx={{ mb: 3 }}>
        {(data?.domains ?? []).map((d) => (
          <Card key={d.domain} variant="outlined" sx={{ minWidth: 260, flex: '1 1 260px' }} data-testid={`dmarc-${d.domain}`}>
            <CardContent>
              <Typography variant="h6">{d.domain}</Typography>
              <Typography variant="h4">{percent(d.passed, d.messages)}%</Typography>
              <Typography variant="body2" color="text.secondary" sx={{ mb: 1 }}>
                {t('DMARC compliant · {{value}} messages in {{count}} reports', { value: d.messages.toLocaleString(uiLocale()), count: d.reports })}
              </Typography>
              <Compliance passed={d.passed} total={d.messages} />
              <Stack direction="row" spacing={1} sx={{ mt: 1 }}>
                <Chip size="small" label={t('{{count}} quarantined', { count: d.quarantined })} color={d.quarantined ? 'warning' : 'default'} />
                <Chip size="small" label={t('{{count}} rejected', { count: d.rejected })} color={d.rejected ? 'error' : 'default'} />
              </Stack>
            </CardContent>
          </Card>
        ))}
      </Stack>
      {data && data.sources.length > 0 && (
        <>
          <Typography variant="h6">{t('Sending sources')}</Typography>
          <Table size="small" sx={{ mb: 3 }} aria-label={t('Sending sources')}>
            <TableHead>
              <TableRow>
                <TableCell>{t('Source address')}</TableCell>
                <TableCell align="right">{t('Messages')}</TableCell>
                <TableCell>{t('DMARC pass')}</TableCell>
                <TableCell align="right">{t('DKIM pass')}</TableCell>
                <TableCell align="right">{t('SPF pass')}</TableCell>
                <TableCell align="right">{t('Rejected')}</TableCell>
              </TableRow>
            </TableHead>
            <TableBody>
              {data.sources.map((s) => (
                <TableRow key={s.source_ip}>
                  <TableCell sx={{ fontFamily: 'monospace' }}>{s.source_ip}</TableCell>
                  <TableCell align="right">{s.messages}</TableCell>
                  <TableCell><Compliance passed={s.passed} total={s.messages} /></TableCell>
                  <TableCell align="right">{percent(s.dkim_passed, s.messages)}%</TableCell>
                  <TableCell align="right">{percent(s.spf_passed, s.messages)}%</TableCell>
                  <TableCell align="right">{s.rejected}</TableCell>
                </TableRow>
              ))}
            </TableBody>
          </Table>
          <Typography variant="h6">{t('Reports')}</Typography>
          <Table size="small" aria-label={t('Reports')}>
            <TableHead>
              <TableRow>
                <TableCell>{t('Period')}</TableCell>
                <TableCell>{t('Reporter')}</TableCell>
                <TableCell>{t('Domain')}</TableCell>
                <TableCell>{t('Policy')}</TableCell>
                <TableCell align="right">{t('Messages')}</TableCell>
                <TableCell>{t('Compliance')}</TableCell>
              </TableRow>
            </TableHead>
            <TableBody>
              {data.reports.map((r) => (
                <TableRow key={r.id} hover sx={{ cursor: 'pointer' }} onClick={() => void get<{ records: ReportRecord[] }>(`/api/dmarc/reports/${r.id}`).then((d) => setDetail({ report: r, records: d.records }))}>
                  <TableCell sx={{ whiteSpace: 'nowrap' }}>{new Date(r.date_begin * 1000).toLocaleDateString(uiLocale())} – {new Date(r.date_end * 1000).toLocaleDateString(uiLocale())}</TableCell>
                  <TableCell>{r.org_name}</TableCell>
                  <TableCell>{r.domain}</TableCell>
                  <TableCell>{r.policy}</TableCell>
                  <TableCell align="right">{r.messages}</TableCell>
                  <TableCell><Compliance passed={r.passed} total={r.messages} /></TableCell>
                </TableRow>
              ))}
            </TableBody>
          </Table>
        </>
      )}
      <Dialog open={Boolean(detail)} onClose={() => setDetail(null)} maxWidth="md" fullWidth>
        <DialogTitle>
          {detail?.report.org_name} · {detail?.report.domain}
        </DialogTitle>
        <DialogContent>
          <Table size="small" aria-label={t('Report records')}>
            <TableHead>
              <TableRow>
                <TableCell>{t('Source')}</TableCell>
                <TableCell align="right">{t('Messages')}</TableCell>
                <TableCell>{t('Header From')}</TableCell>
                <TableCell>DKIM</TableCell>
                <TableCell>SPF</TableCell>
                <TableCell>{t('Disposition')}</TableCell>
              </TableRow>
            </TableHead>
            <TableBody>
              {(detail?.records ?? []).map((rec, i) => (
                <TableRow key={i}>
                  <TableCell sx={{ fontFamily: 'monospace' }}>{rec.source_ip}</TableCell>
                  <TableCell align="right">{rec.count}</TableCell>
                  <TableCell>{rec.header_from}</TableCell>
                  <TableCell><StatusChip status={rec.dkim === 'pass' ? 'ok' : 'error'} /></TableCell>
                  <TableCell><StatusChip status={rec.spf === 'pass' ? 'ok' : 'error'} /></TableCell>
                  <TableCell>{rec.disposition}</TableCell>
                </TableRow>
              ))}
            </TableBody>
          </Table>
        </DialogContent>
      </Dialog>
    </>
  );
}

interface ServerReport {
  hostname: string;
  ports: { name: string; port: number; listening: boolean }[];
  public_addresses: string[];
  blocklisted: string[];
  blocklists_checked: string[];
  outbound_port_25: string;
  outbound_message: string;
  rspamd: string;
  virus_scanner: string;
  virus_message: string;
  score: number;
}

export function Diagnostics() {
  const { data, error, reload } = useLoad(() => get<ServerReport>('/api/diagnostics/server'), []);
  const [busy, setBusy] = useState(false);
  if (error) return <Alert severity="error">{error}</Alert>;
  return (
    <>
      <PageHeader title={t('Server diagnostics')}>
        <Button startIcon={busy ? <CircularProgress size={16} /> : <Refresh />} disabled={busy} onClick={async () => { setBusy(true); await reload(); setBusy(false); }}>
          {t('Run again')}
        </Button>
      </PageHeader>
      {!data ? (
        <Stack direction="row" spacing={2} alignItems="center"><CircularProgress size={20} /><Typography>{t('Running connectivity tests…')}</Typography></Stack>
      ) : (
        <>
          <Card variant="outlined" sx={{ mb: 3, maxWidth: 420 }}>
            <CardContent>
              <Typography variant="body2" color="text.secondary">{t('Deliverability score for {{hostname}}', { hostname: data.hostname })}</Typography>
              <Typography variant="h3" data-testid="deliverability-score" color={data.score >= 85 ? 'success.main' : data.score >= 60 ? 'warning.main' : 'error.main'}>
                {data.score} / 100
              </Typography>
              <LinearProgress variant="determinate" value={data.score} sx={{ height: 8, borderRadius: 4, mt: 1 }} />
            </CardContent>
          </Card>
          <Typography variant="h6">{t('Port health')}</Typography>
          <Table size="small" sx={{ mb: 3, maxWidth: 520 }} aria-label={t('Port health')}>
            <TableHead><TableRow><TableCell>{t('Service')}</TableCell><TableCell align="right">{t('Port')}</TableCell><TableCell>{t('Status')}</TableCell></TableRow></TableHead>
            <TableBody>
              {data.ports.map((p) => (
                <TableRow key={p.name}>
                  <TableCell>{p.name}</TableCell>
                  <TableCell align="right">{p.port}</TableCell>
                  <TableCell><StatusChip status={p.listening ? 'ok' : 'error'} /></TableCell>
                </TableRow>
              ))}
            </TableBody>
          </Table>
          <Typography variant="h6">{t('Outbound delivery')}</Typography>
          <Stack direction="row" spacing={1} alignItems="center" sx={{ mb: 3 }}>
            <StatusChip status={data.outbound_port_25} />
            <Typography variant="body2">{data.outbound_message}</Typography>
          </Stack>
          <Typography variant="h6">{t('Blocklists')}</Typography>
          <Typography variant="body2" sx={{ mb: 1 }}>
            {t('Public addresses:')} {data.public_addresses.join(', ') || 'unknown'} {t('· checked against')} {data.blocklists_checked.join(', ') || t('no blocklists (none configured)')}
          </Typography>
          {data.blocklisted.length > 0 ? (
            <Alert severity="error" sx={{ mb: 3 }}>{t('Listed on: {{value}}. Other servers may reject mail from this server.', { value: data.blocklisted.join(', ') })}</Alert>
          ) : (
            <Alert severity="success" sx={{ mb: 3 }}>{t('Not listed on any checked blocklist.')}</Alert>
          )}
          <Typography variant="h6">{t('Spam and virus filter')}</Typography>
          <Stack direction="row" spacing={1} alignItems="center">
            <StatusChip status={data.rspamd} />
            <Typography variant="body2">{data.rspamd === 'ok' ? t('Rspamd is reachable.') : data.rspamd === 'warning' ? t('No content filter is configured.') : t('Rspamd is configured but unreachable; mail is deferred until it returns.')}</Typography>
          </Stack>
          <Stack direction="row" spacing={1} alignItems="center" sx={{ mt: 1 }} data-testid="virus-scanner-status">
            <StatusChip status={data.virus_scanner} />
            <Typography variant="body2">{data.virus_message}</Typography>
          </Stack>
        </>
      )}
    </>
  );
}

interface Operation {
  tags: string[];
  summary: string;
  description: string;
  parameters: { name: string }[];
  security?: unknown[];
}

const METHOD_COLORS: Record<string, 'success' | 'info' | 'warning' | 'error' | 'default'> = { get: 'success', post: 'info', put: 'warning', patch: 'warning', delete: 'error' };

/** One endpoint; safe (GET) requests without path parameters can be tried in place. */
function Endpoint({ method, path, operation }: { method: string; path: string; operation: Operation }) {
  const [result, setResult] = useState<string | null>(null);
  const [status, setStatus] = useState<number | null>(null);
  const tryable = method === 'get' && operation.parameters.length === 0 && !path.includes('eventsource') && !path.includes('stream');
  async function tryIt() {
    const response = await fetch(path, { credentials: 'same-origin', headers: { Accept: 'application/json' } });
    const text = await response.text();
    setStatus(response.status);
    try {
      setResult(JSON.stringify(JSON.parse(text), null, 2).slice(0, 20000));
    } catch {
      setResult(text.slice(0, 20000));
    }
  }
  return (
    <Accordion disableGutters variant="outlined" slotProps={{ transition: { unmountOnExit: true } }}>
      <AccordionSummary expandIcon={<ExpandMore />}>
        <Stack direction="row" spacing={1.5} alignItems="center" sx={{ minWidth: 0 }}>
          <Chip size="small" label={method.toUpperCase()} color={METHOD_COLORS[method] ?? 'default'} sx={{ width: 72, fontWeight: 700 }} />
          <Typography sx={{ fontFamily: 'monospace', fontSize: 14 }} noWrap>{path}</Typography>
          <Typography variant="body2" color="text.secondary" noWrap>{operation.summary}</Typography>
        </Stack>
      </AccordionSummary>
      <AccordionDetails>
        <Typography variant="body2">{operation.description}</Typography>
        <Typography variant="body2" color="text.secondary" sx={{ mb: 1 }}>
          {operation.security ? (method === 'get' ? t('Authentication: session cookie') : t('Authentication: session cookie and X-CSRF-Token header')) : t('No authentication required')}
          {operation.parameters.length > 0 && t(' · Path parameters: {{value}}', { value: operation.parameters.map((p) => p.name).join(', ') })}
        </Typography>
        {tryable && <Button size="small" variant="outlined" onClick={() => void tryIt()}>{t('Try it')}</Button>}
        {result !== null && (
          <Box sx={{ mt: 1 }}>
            <Chip size="small" label={`HTTP ${status}`} color={status && status < 400 ? 'success' : 'error'} />
            <Box component="pre" sx={{ mt: 1, p: 1.5, bgcolor: 'action.hover', borderRadius: 2, overflow: 'auto', maxHeight: 320, fontSize: 12 }}>{result}</Box>
          </Box>
        )}
      </AccordionDetails>
    </Accordion>
  );
}

export function ApiDocs() {
  const { data, error } = useLoad(() => get<{ info: { title: string; version: string; description: string }; paths: Record<string, Record<string, Operation>> }>('/api/openapi.json'), []);
  const [filter, setFilter] = useState('');
  if (error) return <Alert severity="error">{error}</Alert>;
  if (!data) return null;
  const groups = new Map<string, { method: string; path: string; operation: Operation }[]>();
  for (const [path, methods] of Object.entries(data.paths)) {
    for (const [method, operation] of Object.entries(methods)) {
      if (filter && !`${method} ${path} ${operation.summary}`.toLowerCase().includes(filter.toLowerCase())) continue;
      const tag = operation.tags[0] ?? 'other';
      groups.set(tag, [...(groups.get(tag) ?? []), { method, path, operation }]);
    }
  }
  return (
    <>
      <PageHeader title={t('API reference')}>
        <TextField label={t('Filter')} value={filter} onChange={(e) => setFilter(e.target.value)} sx={{ width: 240 }} />
        <Button component="a" href="/api/openapi.json" target="_blank" rel="noopener">{t('OpenAPI JSON')}</Button>
      </PageHeader>
      <Typography variant="body2" color="text.secondary" sx={{ mb: 2 }}>
        {data.info.title} {data.info.version}. {data.info.description}
      </Typography>
      {[...groups.entries()].map(([tag, endpoints]) => (
        <Box key={tag} sx={{ mb: 3 }}>
          <Typography variant="h6" sx={{ textTransform: 'capitalize', mb: 1 }}>{tag}</Typography>
          {endpoints.map((e) => (
            <Endpoint key={`${e.method} ${e.path}`} {...e} />
          ))}
        </Box>
      ))}
      <Typography variant="caption" color="text.secondary">{t('Generated {{value}} from the running server.', { value: formatTime(Math.floor(Date.now() / 1000)) })}</Typography>
    </>
  );
}
