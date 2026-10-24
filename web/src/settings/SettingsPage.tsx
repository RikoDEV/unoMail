import { LinearProgress } from '../ui/progress';
import AlternateEmail from '@mui/icons-material/AlternateEmail';
import Article from '@mui/icons-material/Article';
import Badge from '@mui/icons-material/Badge';
import BeachAccess from '@mui/icons-material/BeachAccess';
import Draw from '@mui/icons-material/Draw';
import FilterAlt from '@mui/icons-material/FilterAlt';
import Inbox from '@mui/icons-material/Inbox';
import Security from '@mui/icons-material/Security';
import Tune from '@mui/icons-material/Tune';
import { Alert, Box, Button, Card, CardContent, FormControlLabel, Stack, Switch, Table, TableBody, TableCell, TableHead, TableRow, TextField, Typography } from '@mui/material';
import { useEffect, useState, type FormEvent, type ReactElement, type ReactNode } from 'react';
import { useSearchParams } from 'react-router-dom';
import { FiltersCard } from './Filters';
import { SignaturesCard } from './Signatures';
import { ApiError, del, formatBytes, formatTime, get, post, put, errorText } from '../lib/api';
import { UsageBar, useLoad } from '../admin/common';
import { useAuth } from '../app';
import { AppearanceCard, MessageListCard, NotificationsCard, SendingCard } from './Webmail';
import { InboxCard } from './Inbox';
import { EncryptionCard, SmimeCard } from './Encryption';
import { IdentitiesCard, TemplatesCard } from './Identities';
import { SideNavPage, useTitle } from '../ui/shell';
import { AppPasswordsCard, TwoStepCard } from './Security';
import { SmartReplySettings, SummaryCardsSettings } from './SummaryCards';
import { MaskedAddresses } from './MaskedEmail';

import { t } from '../i18n';
interface SessionRow {
  created_at: number;
  expires_at: number;
  ip: string;
  user_agent: string;
  current: boolean;
}

interface Vacation {
  enabled: boolean;
  subject: string;
  body: string;
  starts_at: number | null;
  ends_at: number | null;
  interval_days: number;
}

const toDateInput = (seconds: number | null) => (seconds ? new Date(seconds * 1000).toISOString().slice(0, 10) : '');
const fromDateInput = (value: string) => (value ? Math.floor(new Date(`${value}T00:00:00Z`).getTime() / 1000) : null);

function VacationCard() {
  const [settings, setSettings] = useState<Vacation | null>(null);
  const [error, setError] = useState('');
  const [saved, setSaved] = useState(false);

  useEffect(() => {
    get<Vacation>('/api/me/vacation').then(setSettings).catch(() => setError(t('Could not load the out-of-office settings')));
  }, []);
  if (!settings) return error ? <Alert severity="error">{error}</Alert> : null;
  const set = (changes: Partial<Vacation>) => {
    setSaved(false);
    setSettings({ ...settings, ...changes });
  };

  async function save() {
    setError('');
    try {
      setSettings(await put<Vacation>('/api/me/vacation', settings));
      setSaved(true);
    } catch (err) {
      setError(errorText(err, t('Could not save')));
    }
  }

  return (
    <Card variant="outlined">
      <CardContent>
        <Typography variant="h6" sx={{ mb: 1 }}>
          {t('Out of office')}
        </Typography>
        <Stack spacing={2} sx={{ maxWidth: 520 }}>
          {error && <Alert severity="error">{error}</Alert>}
          {saved && <Alert severity="success">{t('Out-of-office settings saved.')}</Alert>}
          <FormControlLabel control={<Switch checked={settings.enabled} onChange={(e) => set({ enabled: e.target.checked })} />} label={t('Send automatic replies')} />
          <TextField label={t('Reply subject')} value={settings.subject} onChange={(e) => set({ subject: e.target.value })} helperText={t('Leave empty to use “Automatic reply: original subject”')} />
          <TextField label={t('Reply message')} value={settings.body} onChange={(e) => set({ body: e.target.value })} multiline minRows={4} />
          <Stack direction="row" spacing={2}>
            <TextField label={t('First day')} type="date" value={toDateInput(settings.starts_at)} onChange={(e) => set({ starts_at: fromDateInput(e.target.value) })} slotProps={{ inputLabel: { shrink: true } }} />
            <TextField label={t('Until')} type="date" value={toDateInput(settings.ends_at)} onChange={(e) => set({ ends_at: fromDateInput(e.target.value) })} slotProps={{ inputLabel: { shrink: true } }} />
          </Stack>
          <Typography variant="caption" color="text.secondary">
            {t('Each correspondent gets at most one reply every {{interval_days}} days. Mailing lists and automated messages are never answered.', { interval_days: settings.interval_days })}
          </Typography>
          <Box>
            <Button variant="contained" onClick={() => void save()}>
              {t('Save out-of-office settings')}
            </Button>
          </Box>
        </Stack>
      </CardContent>
    </Card>
  );
}

/** Mail sent over the last hour against this mailbox's hourly sending limits. */
interface Sending {
  sent_messages: number;
  sent_recipients: number;
  max_messages_per_hour: number;
  max_recipients_per_hour: number;
  blocked: boolean;
}

export default function SettingsPage() {
  useTitle(t('Settings'));
  const [params, setParams] = useSearchParams();
  const { account } = useAuth();
  const sessions = useLoad(() => get<SessionRow[]>('/api/auth/sessions'), []);
  const sending = useLoad(() => get<Sending>('/api/me/sending'), []);
  const [current, setCurrent] = useState('');
  const [next, setNext] = useState('');
  const [confirm, setConfirm] = useState('');
  const [revokeApps, setRevokeApps] = useState(false);
  const [error, setError] = useState('');
  const [message, setMessage] = useState('');
  if (!account) return null;

  const mismatch = confirm.length > 0 && next !== confirm;
  const tooShort = next.length > 0 && next.length < 10;

  async function changePassword(event: FormEvent) {
    event.preventDefault();
    setError('');
    setMessage('');
    try {
      await post('/api/auth/password', { current_password: current, new_password: next, revoke_app_passwords: revokeApps });
      setCurrent('');
      setNext('');
      setConfirm('');
      setMessage(revokeApps ? t('Password changed. Other devices and app passwords have been signed out.') : t('Password changed. Other devices have been signed out.'));
      setRevokeApps(false);
      await sessions.reload();
    } catch (err) {
      setError(err instanceof ApiError && err.code === 'invalid_credentials' ? t('The current password is incorrect.') : errorText(err, t('Could not change the password')));
    }
  }

  async function revoke() {
    await del('/api/auth/sessions').catch(() => {});
    setMessage(t('Other sessions have been signed out.'));
    await sessions.reload();
  }

  const used = account.quota_bytes > 0 ? Math.min(100, (account.used_bytes / account.quota_bytes) * 100) : 0;
  const accountCard = (
    <Card variant="outlined">
      <CardContent>
        <Typography variant="h6">{account.display_name || account.email}</Typography>
        <Typography color="text.secondary" sx={{ mb: 1 }}>
          {account.email}
        </Typography>
        <Typography variant="body2">
          {t('Storage:')} {t('{{used}} of {{quota}}', { used: formatBytes(account.used_bytes), quota: account.quota_bytes ? formatBytes(account.quota_bytes) : t('unlimited') })}
        </Typography>
        {account.quota_bytes > 0 && <LinearProgress variant="determinate" value={used} color={used >= 90 ? 'error' : 'primary'} sx={{ mt: 1, height: 8, borderRadius: 1.5, maxWidth: 520 }} />}
        {sending.data && (
          <Box sx={{ mt: 2, maxWidth: 520 }}>
            <Typography variant="body2" sx={{ mb: 0.5 }}>{t('Sending in the last hour:')}</Typography>
            <Stack spacing={1}>
              <Box><UsageBar label={t('Messages')} used={sending.data.sent_messages} limit={sending.data.max_messages_per_hour} /></Box>
              <Box><UsageBar label={t('Recipients')} used={sending.data.sent_recipients} limit={sending.data.max_recipients_per_hour} /></Box>
            </Stack>
            {sending.data.blocked && <Alert severity="error" sx={{ mt: 1 }}>{t('This mailbox can no longer send mail; incoming mail still arrives. Contact your administrator.')}</Alert>}
          </Box>
        )}
      </CardContent>
    </Card>
  );
  const passwordCard = (
    <Card variant="outlined">
      <CardContent>
        <Typography variant="h6" sx={{ mb: 2 }}>
          {t('Change password')}
        </Typography>
        <Stack component="form" spacing={2} onSubmit={changePassword} sx={{ maxWidth: 380 }}>
          {error && <Alert severity="error">{error}</Alert>}
          <TextField label={t('Current password')} type="password" autoComplete="current-password" value={current} onChange={(e) => setCurrent(e.target.value)} required />
          <TextField label={t('New password')} type="password" autoComplete="new-password" value={next} onChange={(e) => setNext(e.target.value)} required error={tooShort} helperText={tooShort ? t('Use at least 10 characters') : ''} />
          <TextField label={t('Repeat new password')} type="password" autoComplete="new-password" value={confirm} onChange={(e) => setConfirm(e.target.value)} required error={mismatch} helperText={mismatch ? t('The passwords do not match') : ''} />
          <FormControlLabel control={<Switch checked={revokeApps} onChange={(e) => setRevokeApps(e.target.checked)} />} label={t('Also revoke app passwords (mail, calendar and contacts programs)')} />
          <Box>
            <Button type="submit" variant="contained" disabled={!current || next.length < 10 || next !== confirm}>
              {t('Change password')}
            </Button>
          </Box>
        </Stack>
      </CardContent>
    </Card>
  );
  const sessionsCard = (
    <Card variant="outlined">
      <CardContent>
        <Stack direction="row" alignItems="center" sx={{ mb: 1 }}>
          <Typography variant="h6" sx={{ flex: 1 }}>
            {t('Active sessions')}
          </Typography>
          <Button color="error" onClick={() => void revoke()} disabled={(sessions.data?.length ?? 0) < 2}>
            {t('Sign out other sessions')}
          </Button>
        </Stack>
        <Table size="small" aria-label={t('Sessions')}>
          <TableHead>
            <TableRow>
              <TableCell>{t('Signed in')}</TableCell>
              <TableCell>{t('Address')}</TableCell>
              <TableCell>{t('Browser')}</TableCell>
            </TableRow>
          </TableHead>
          <TableBody>
            {(sessions.data ?? []).map((s) => (
              <TableRow key={`${s.created_at}-${s.ip}-${s.current}`}>
                <TableCell sx={{ whiteSpace: 'nowrap' }}>
                  {formatTime(s.created_at)}
                  {s.current ? t(' (this device)') : ''}
                </TableCell>
                <TableCell>{s.ip}</TableCell>
                <TableCell sx={{ wordBreak: 'break-word' }}>{s.user_agent}</TableCell>
              </TableRow>
            ))}
          </TableBody>
        </Table>
      </CardContent>
    </Card>
  );

  // The settings, grouped. Each group has its own address (?tab=...), so it can be linked to.
  const sections: { id: string; label: string; icon: ReactElement; content: ReactNode }[] = [
    { id: 'general', label: t('General'), icon: <Tune />, content: <>{accountCard}<MessageListCard /><SendingCard /><NotificationsCard /><AppearanceCard /></> },
    { id: 'inbox', label: t('Inbox'), icon: <Inbox />, content: <><InboxCard /><SummaryCardsSettings /><SmartReplySettings /></> },
    { id: 'identities', label: t('Identities'), icon: <Badge />, content: <IdentitiesCard /> },
    { id: 'masked-addresses', label: t('Masked addresses'), icon: <AlternateEmail />, content: <MaskedAddresses /> },
    { id: 'signatures', label: t('Signatures'), icon: <Draw />, content: <SignaturesCard /> },
    { id: 'templates', label: t('Templates'), icon: <Article />, content: <TemplatesCard /> },
    { id: 'filters', label: t('Filters'), icon: <FilterAlt />, content: <FiltersCard /> },
    { id: 'vacation', label: t('Out of office'), icon: <BeachAccess />, content: <VacationCard /> },
    { id: 'security', label: t('Security'), icon: <Security />, content: <>{passwordCard}<TwoStepCard /><AppPasswordsCard /><EncryptionCard /><SmimeCard />{sessionsCard}</> },
  ];
  const active = sections.find((section) => section.id === params.get('tab')) ?? sections[0];
  return (
    <SideNavPage
      title={t('unoMail')}
      navLabel={t('Settings sections')}
      heading={t('Settings')}
      placement="settings"
      items={sections.map((section) => ({ key: section.id, label: section.label, icon: section.icon, selected: section.id === active.id, onClick: () => setParams({ tab: section.id }, { replace: true }) }))}
    >
          <Typography variant="h5" component="h2" sx={{ mb: 2 }}>
            {active.label}
          </Typography>
          {message && <Alert severity="success" sx={{ mb: 2 }} onClose={() => setMessage('')}>{message}</Alert>}
          <Stack spacing={3}>{active.content}</Stack>
    </SideNavPage>
  );
}
