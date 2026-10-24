import { Alert, Button, Chip, Tooltip } from '@mui/material';
import { useState } from 'react';
import { formatTime, get } from '../lib/api';
import { t } from '../i18n';
import { useLoad } from './common';

interface UpdateStatus {
  enabled: boolean;
  current: string;
  latest?: { version: string; url: string; published_at: string | null } | null;
  update_available?: boolean;
  checked_at?: number;
  error?: string | null;
}

/** The running version on the dashboard, and whether a newer release is out. */
export function useUpdateCheck() {
  const [refreshing, setRefreshing] = useState(false);
  const { data, reload } = useLoad(() => get<UpdateStatus>('/api/admin/update-check'), []);
  const [fresh, setFresh] = useState<UpdateStatus | null>(null);
  const status = fresh ?? data;
  const recheck = async () => {
    setRefreshing(true);
    try {
      setFresh(await get<UpdateStatus>('/api/admin/update-check?refresh=true'));
    } catch {
      void reload();
    } finally {
      setRefreshing(false);
    }
  };
  return { status, refreshing, recheck };
}

/** A chip with the running version; clicking it checks again. */
export function VersionChip({ status, refreshing, onRecheck }: { status: UpdateStatus | null | undefined; refreshing: boolean; onRecheck: () => void }) {
  if (!status) return null;
  const label = t('unoMail {{version}}', { version: status.current });
  if (!status.enabled) return <Chip label={label} variant="outlined" />;
  const state = refreshing ? t('checking…') : status.error ? t('update check failed') : status.update_available ? t('update available') : t('up to date');
  const checked = status.checked_at ? t('Last checked {{time}}. Click to check again.', { time: formatTime(status.checked_at) }) : '';
  return (
    <Tooltip title={status.error ? `${status.error}. ${checked}` : checked}>
      <Chip
        label={`${label} · ${state}`}
        variant="outlined"
        color={status.error ? 'default' : status.update_available ? 'info' : 'success'}
        onClick={refreshing ? undefined : onRecheck}
        aria-label={t('Check for updates')}
      />
    </Tooltip>
  );
}

/** The notice shown while a newer release than the running one exists. */
export function UpdateNotice({ status }: { status: UpdateStatus | null | undefined }) {
  if (!status?.update_available || !status.latest) return null;
  return (
    <Alert
      severity="info"
      sx={{ mb: 2 }}
      action={<Button color="inherit" size="small" component="a" href={status.latest.url} target="_blank" rel="noopener noreferrer">{t('Release notes')}</Button>}
    >
      {t('unoMail {{latest}} is available. You are running {{current}}.', { latest: status.latest.version, current: status.current })}
    </Alert>
  );
}
