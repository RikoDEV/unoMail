// Backups: where they go, the snapshots kept there and recent runs. Configured with
// environment variables; this page shows the state and starts a backup on demand.

import { Alert, Button, Card, CardContent, Chip, TableBody, TableCell, TableHead, TableRow, Typography } from '@mui/material';
import { useEffect } from 'react';
import { formatBytes, formatTime, get, post } from '../api';
import { PageHeader, useAction, useLoad, ScrollTable } from './common';

import { t } from '../i18n';
interface Snapshot {
  id: string;
  created_at: number;
  version: string;
  blobs: number;
  database_bytes: number;
  encrypted_mail: boolean;
}

interface Run {
  id: number;
  snapshot: string;
  started_at: number;
  finished_at: number | null;
  status: 'running' | 'ok' | 'failed';
  detail: string;
  blobs_copied: number;
  bytes_copied: number;
}

interface State {
  configured: boolean;
  target: string | null;
  hour: number;
  keep: number;
  storage: string;
  encrypted_mail: boolean;
  snapshots: Snapshot[];
  runs: Run[];
  error: string | null;
}

const STATUS_COLOR = { running: 'info', ok: 'success', failed: 'error' } as const;

export function Backups() {
  const { data, error, reload } = useLoad(() => get<State>('/api/backups'), []);
  const { run, feedback } = useAction();
  const running = data?.runs.some((r) => r.status === 'running') ?? false;
  // Follow a running backup until it finishes.
  useEffect(() => {
    if (!running) return;
    const timer = window.setInterval(() => void reload(), 2000);
    return () => window.clearInterval(timer);
  }, [running, reload]);

  return (
    <>
      <PageHeader title={t('Backups')}>
        <Button variant="contained" disabled={!data?.configured || running} onClick={() => void run(() => post('/api/backups').then(reload), t('Backup started'))}>
          {running ? t('Backing up…') : t('Back up now')}
        </Button>
      </PageHeader>
      {feedback}
      {error && <Alert severity="error">{error}</Alert>}
      {data?.error && <Alert severity="error" sx={{ mb: 2 }}>{t('The backup target cannot be read: {{error}}', { error: data.error })}</Alert>}
      {data && (
        <Card variant="outlined" sx={{ mb: 3 }}>
          <CardContent>
            {data.configured ? (
              <Typography>
                {t('Daily at')} {String(data.hour).padStart(2, '0')}{t(':00 UTC to')} <code>{data.target}</code>{t(', keeping the last')} {data.keep} {t('snapshots. Each backup copies the database and the messages added since the previous one.')}
              </Typography>
            ) : (
              <Alert severity="warning">
                {t('No backup target is configured. Set')} <code>UNOMAIL_BACKUP_DIR</code> {t('(a directory, ideally on another disk) or')} <code>UNOMAIL_BACKUP_S3_BUCKET</code> {t('with its')}{' '}
                <code>UNOMAIL_BACKUP_S3_*</code> {t('credentials, and restart the server.')}
              </Alert>
            )}
            <Typography variant="body2" color="text.secondary" sx={{ mt: 1 }}>
              {t('Messages are stored in')} <code>{data.storage}</code>
              {data.encrypted_mail ? t(', encrypted') : ''}{t('. Backups do not contain the keys in the data directory (')}<code>secret.key</code>
              {data.encrypted_mail ? <>, <code>blob.key</code></> : null}{t('): keep a copy of them in a safe place, a restore needs them. Restore with')}{' '}
              <code>unomail restore [snapshot]</code> {t('while the server is stopped.')}
            </Typography>
          </CardContent>
        </Card>
      )}
      {data && data.snapshots.length > 0 && (
        <Card variant="outlined" sx={{ mb: 3 }}>
          <CardContent>
            <Typography variant="h6" sx={{ mb: 1 }}>{t('Snapshots')}</Typography>
            <ScrollTable size="small" aria-label={t('Snapshots')}>
              <TableHead>
                <TableRow>
                  <TableCell>{t('Taken')}</TableCell>
                  <TableCell>{t('Name')}</TableCell>
                  <TableCell align="right">{t('Messages')}</TableCell>
                  <TableCell align="right">{t('Database')}</TableCell>
                  <TableCell>{t('Version')}</TableCell>
                </TableRow>
              </TableHead>
              <TableBody>
                {data.snapshots.map((s) => (
                  <TableRow key={s.id}>
                    <TableCell sx={{ whiteSpace: 'nowrap' }}>{formatTime(s.created_at)}</TableCell>
                    <TableCell><code>{s.id}</code>{s.encrypted_mail && <Chip size="small" label="encrypted" sx={{ ml: 1 }} />}</TableCell>
                    <TableCell align="right">{s.blobs}</TableCell>
                    <TableCell align="right">{formatBytes(s.database_bytes)}</TableCell>
                    <TableCell>{s.version}</TableCell>
                  </TableRow>
                ))}
              </TableBody>
            </ScrollTable>
          </CardContent>
        </Card>
      )}
      {data && (
        <Card variant="outlined">
          <CardContent>
            <Typography variant="h6" sx={{ mb: 1 }}>{t('Recent runs')}</Typography>
            {data.runs.length === 0 ? (
              <Typography color="text.secondary">{t('No backup has run yet.')}</Typography>
            ) : (
              <ScrollTable size="small" aria-label={t('Backup runs')}>
                <TableHead>
                  <TableRow>
                    <TableCell>{t('Started')}</TableCell>
                    <TableCell>{t('Status')}</TableCell>
                    <TableCell align="right">{t('New messages')}</TableCell>
                    <TableCell align="right">{t('Copied')}</TableCell>
                    <TableCell>{t('Details')}</TableCell>
                  </TableRow>
                </TableHead>
                <TableBody>
                  {data.runs.map((r) => (
                    <TableRow key={r.id}>
                      <TableCell sx={{ whiteSpace: 'nowrap' }}>{formatTime(r.started_at)}</TableCell>
                      <TableCell><Chip size="small" color={STATUS_COLOR[r.status]} label={r.status} /></TableCell>
                      <TableCell align="right">{r.blobs_copied}</TableCell>
                      <TableCell align="right">{formatBytes(r.bytes_copied)}</TableCell>
                      <TableCell sx={{ wordBreak: 'break-word' }}>{r.detail}</TableCell>
                    </TableRow>
                  ))}
                </TableBody>
              </ScrollTable>
            )}
          </CardContent>
        </Card>
      )}
    </>
  );
}
