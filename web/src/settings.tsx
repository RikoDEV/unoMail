import Article from '@mui/icons-material/Article';
import Badge from '@mui/icons-material/Badge';
import BeachAccess from '@mui/icons-material/BeachAccess';
import Draw from '@mui/icons-material/Draw';
import FilterAlt from '@mui/icons-material/FilterAlt';
import Inbox from '@mui/icons-material/Inbox';
import MenuIcon from '@mui/icons-material/Menu';
import Security from '@mui/icons-material/Security';
import Tune from '@mui/icons-material/Tune';
import { Alert, Box, Button, Card, CardContent, Drawer, FormControlLabel, IconButton, List, ListItemButton, ListItemIcon, ListItemText, LinearProgress, Paper, Stack, Switch, Table, TableBody, TableCell, TableHead, TableRow, TextField, Tooltip, Typography, useMediaQuery, useTheme } from '@mui/material';
import { useEffect, useState, type FormEvent, type ReactElement, type ReactNode } from 'react';
import { useSearchParams } from 'react-router-dom';
import { FiltersCard } from './settingsFilters';
import { SignaturesCard } from './settingsSignatures';
import { ApiError, del, formatBytes, formatTime, get, post, put, errorText } from './api';
import { useLoad } from './admin/common';
import { useAuth } from './app';
import { AppearanceCard, EncryptionCard, IdentitiesCard, InboxCard, MessageListCard, NotificationsCard, SendingCard, SmimeCard, TemplatesCard } from './settingsWebmail';
import { Copyright, TopBar, useTitle } from './shell';
import { AppPasswordsCard, TwoStepCard } from './settingsSecurity';
import { SmartReplySettings, SummaryCardsSettings } from './settingsSummaryCards';

import { t } from './i18n';
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

export default function SettingsPage() {
  useTitle(t('Settings'));
  const [params, setParams] = useSearchParams();
  const compact = useMediaQuery(useTheme().breakpoints.down('md'));
  const [drawerOpen, setDrawerOpen] = useState(false);
  const { account } = useAuth();
  const sessions = useLoad(() => get<SessionRow[]>('/api/auth/sessions'), []);
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
        {account.quota_bytes > 0 && <LinearProgress variant="determinate" value={used} sx={{ mt: 1, height: 8, borderRadius: 1.5, maxWidth: 520 }} />}
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
    { id: 'signatures', label: t('Signatures'), icon: <Draw />, content: <SignaturesCard /> },
    { id: 'templates', label: t('Templates'), icon: <Article />, content: <TemplatesCard /> },
    { id: 'filters', label: t('Filters'), icon: <FilterAlt />, content: <FiltersCard /> },
    { id: 'vacation', label: t('Out of office'), icon: <BeachAccess />, content: <VacationCard /> },
    { id: 'security', label: t('Security'), icon: <Security />, content: <>{passwordCard}<TwoStepCard /><AppPasswordsCard /><EncryptionCard /><SmimeCard />{sessionsCard}</> },
  ];
  const active = sections.find((section) => section.id === params.get('tab')) ?? sections[0];
  const nav = (
    <Box component="nav" aria-label={t('Settings sections')} sx={{ width: compact ? 260 : 220, flexShrink: 0, px: 1, overflow: 'auto', display: 'flex', flexDirection: 'column', height: compact ? '100%' : undefined }}>
      <Typography variant="h6" component="h1" sx={{ px: 2, pt: compact ? 1 : 0, pb: 1 }}>
        {t('Settings')}
      </Typography>
      <List dense disablePadding>
        {sections.map((section) => (
          <ListItemButton
            key={section.id}
            selected={section.id === active.id}
            aria-current={section.id === active.id ? 'page' : undefined}
            onClick={() => { setParams({ tab: section.id }, { replace: true }); setDrawerOpen(false); }}
            sx={{ mb: 0.25, '&.Mui-selected': { bgcolor: 'action.selected', fontWeight: 600 } }}
          >
            <ListItemIcon sx={{ minWidth: 40 }}>{section.icon}</ListItemIcon>
            <ListItemText primary={section.label} />
          </ListItemButton>
        ))}
      </List>
      <Copyright placement="settings" sx={{ mt: 'auto', px: 2, pt: 3, pb: 2, flexShrink: 0 }} />
    </Box>
  );
  return (
    <Box sx={{ height: '100vh', display: 'flex', flexDirection: 'column', bgcolor: 'background.default' }}>
      <TopBar
        title={t('unoMail')}
        leading={compact && <Tooltip title={t('Menu')}><IconButton aria-label={t('Settings sections')} aria-expanded={drawerOpen} onClick={() => setDrawerOpen((open) => !open)}><MenuIcon /></IconButton></Tooltip>}
      />
      <Box sx={{ flex: 1, display: 'flex', minHeight: 0 }}>
        {compact ? (
          <Drawer open={drawerOpen} onClose={() => setDrawerOpen(false)} slotProps={{ paper: { sx: { bgcolor: 'background.default', pt: 1 } } }}>
            {nav}
          </Drawer>
        ) : (
          nav
        )}
        <Paper elevation={0} component="main" sx={{ flex: 1, minWidth: 0, overflow: 'auto', borderRadius: 1.5, mx: { xs: 1, md: 0 }, mr: { md: 1 }, mb: 1, p: { xs: 2, sm: 3 } }}>
          <Typography variant="h5" component="h2" sx={{ mb: 2 }}>
            {active.label}
          </Typography>
          {message && <Alert severity="success" sx={{ mb: 2 }} onClose={() => setMessage('')}>{message}</Alert>}
          <Stack spacing={3}>{active.content}</Stack>
        </Paper>
      </Box>
    </Box>
  );
}
