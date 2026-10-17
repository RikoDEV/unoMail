// SMTP TLS reports (RFC 8460): what other servers report about reaching ours securely, and
// how this server's own outgoing sessions went.

import { Alert, Card, CardContent, Chip, MenuItem, Stack, Table, TableBody, TableCell, TableHead, TableRow, TextField, Typography } from '@mui/material';
import { useState } from 'react';
import { formatTime, get } from '../api';
import { useAuth } from '../app';
import { PageHeader, useLoad } from './common';

import { t } from '../i18n';
interface Received {
  id: number;
  reporter: string;
  report_id: string;
  domain: string;
  policy_type: string;
  date_begin: number;
  date_end: number;
  successes: number;
  failures: number;
  details: { 'result-type': string; 'receiving-mx-hostname'?: string; 'sending-mta-ip'?: string; 'failed-session-count': number }[] | null;
}

interface Outgoing {
  domain: string;
  policy_type: string;
  result: string;
  count: number;
}

const POLICY_LABELS: Record<string, string> = { sts: 'MTA-STS', tlsa: 'DANE', 'no-policy-found': 'none' };

export function TlsReports() {
  const { account } = useAuth();
  const [days, setDays] = useState(30);
  const { data, error } = useLoad(() => get<{ received: Received[]; outgoing: Outgoing[] }>(`/api/tls-reports?days=${days}`), [days]);
  return (
    <>
      <PageHeader title={t('TLS reports')}>
        <TextField select size="small" label={t('Period')} value={days} onChange={(e) => setDays(Number(e.target.value))} sx={{ width: 160 }}>
          {[7, 30, 90, 365].map((n) => (
            <MenuItem key={n} value={n}>{t('Last {{n}} days', { n })}</MenuItem>
          ))}
        </TextField>
      </PageHeader>
      {error && <Alert severity="error">{error}</Alert>}
      <Typography color="text.secondary" sx={{ mb: 2, maxWidth: 820 }}>
        {t('Mail servers that deliver to your domains report once a day whether they could do so over a verified TLS connection. Publish a')} <code>_smtp._tls</code> {t("record (see each domain's DNS page) to receive them.")}
      </Typography>
      <Card variant="outlined" sx={{ mb: 3 }}>
        <CardContent>
          <Typography variant="h6" sx={{ mb: 1 }}>{t('Received reports')}</Typography>
          {data && data.received.length === 0 ? (
            <Typography color="text.secondary">{t('No reports in this period.')}</Typography>
          ) : (
            <Table size="small" aria-label={t('Received TLS reports')}>
              <TableHead>
                <TableRow>
                  <TableCell>{t('Day')}</TableCell>
                  <TableCell>{t('Reporter')}</TableCell>
                  <TableCell>{t('Domain')}</TableCell>
                  <TableCell>{t('Policy')}</TableCell>
                  <TableCell align="right">{t('Sessions')}</TableCell>
                  <TableCell>{t('Failures')}</TableCell>
                </TableRow>
              </TableHead>
              <TableBody>
                {(data?.received ?? []).map((report) => (
                  <TableRow key={report.id}>
                    <TableCell sx={{ whiteSpace: 'nowrap' }}>{formatTime(report.date_begin)}</TableCell>
                    <TableCell>{report.reporter}</TableCell>
                    <TableCell>{report.domain}</TableCell>
                    <TableCell>{POLICY_LABELS[report.policy_type] ?? report.policy_type}</TableCell>
                    <TableCell align="right">{report.successes + report.failures}</TableCell>
                    <TableCell>
                      {report.failures === 0 ? (
                        <Chip size="small" color="success" label="none" />
                      ) : (
                        <Stack direction="row" gap={0.5} flexWrap="wrap">
                          {(report.details ?? []).map((detail, index) => (
                            <Chip key={index} size="small" color="error" variant="outlined" label={`${detail['result-type']} ×${detail['failed-session-count']}${detail['receiving-mx-hostname'] ? ` (${detail['receiving-mx-hostname']})` : ''}`} />
                          ))}
                        </Stack>
                      )}
                    </TableCell>
                  </TableRow>
                ))}
              </TableBody>
            </Table>
          )}
        </CardContent>
      </Card>
      {account?.role === 'super_admin' && (
        <Card variant="outlined">
          <CardContent>
            <Typography variant="h6" sx={{ mb: 1 }}>{t('Outgoing sessions')}</Typography>
            <Typography variant="body2" color="text.secondary" sx={{ mb: 1 }}>
              {t('How this server reached other domains, by the policy they publish. Domains asking for it get these figures as a daily report.')}
            </Typography>
            {data && data.outgoing.length === 0 ? (
              <Typography color="text.secondary">{t('Nothing recorded in this period.')}</Typography>
            ) : (
              <Table size="small" aria-label={t('Outgoing TLS results')}>
                <TableHead>
                  <TableRow>
                    <TableCell>{t('Domain')}</TableCell>
                    <TableCell>{t('Policy')}</TableCell>
                    <TableCell>{t('Result')}</TableCell>
                    <TableCell align="right">{t('Sessions')}</TableCell>
                  </TableRow>
                </TableHead>
                <TableBody>
                  {(data?.outgoing ?? []).map((row) => (
                    <TableRow key={`${row.domain}-${row.policy_type}-${row.result}`}>
                      <TableCell>{row.domain}</TableCell>
                      <TableCell>{POLICY_LABELS[row.policy_type] ?? row.policy_type}</TableCell>
                      <TableCell>
                        <Chip size="small" color={row.result === 'success' ? 'success' : 'error'} variant={row.result === 'success' ? 'filled' : 'outlined'} label={row.result} />
                      </TableCell>
                      <TableCell align="right">{row.count}</TableCell>
                    </TableRow>
                  ))}
                </TableBody>
              </Table>
            )}
          </CardContent>
        </Card>
      )}
    </>
  );
}
