import { LinearProgress } from '../ui/progress';
import Add from '@mui/icons-material/Add';
import Delete from '@mui/icons-material/Delete';
import Edit from '@mui/icons-material/Edit';
import MoveToInbox from '@mui/icons-material/MoveToInbox';
import { Alert, Button, Chip, Dialog, DialogActions, DialogContent, DialogTitle, FormControlLabel, IconButton, MenuItem, Stack, Switch, TableBody, TableCell, TableHead, TableRow, TextField, Tooltip, Typography } from '@mui/material';
import { useEffect, useState } from 'react';
import { del, formatBytes, get, patch, post } from '../lib/api';
import { useAuth } from '../app';
import { ConfirmDialog, DialogButtons, PageHeader, routeBy, ScrollTable, StatusChip, UsageBar, useAction, useFormAction, useLoad, validators } from './common';

import { t, uiLocale } from '../i18n';
interface Mailbox {
  id: number;
  email: string;
  display_name: string;
  role: string;
  quota_bytes: number;
  used_bytes: number;
  enabled: boolean;
  imap_enabled: boolean;
  pop3_enabled: boolean;
  smtp_enabled: boolean;
  outbound_blocked: boolean;
  outbound_blocked_reason: string | null;
  send_only: boolean;
  /** Kept by the server (postmaster@): cannot be deleted. */
  system: boolean;
  /** Submitted over the last hour or so, the window the sending limits are checked against. */
  sent_messages: number;
  sent_recipients: number;
  /** Overrides of the server's sending limits; null uses the server setting. */
  max_messages_per_hour: number | null;
  max_recipients_per_hour: number | null;
  max_message_size: number | null;
  max_recipients: number | null;
}

interface MailboxList {
  items: Mailbox[];
  total: number;
  max_messages_per_hour: number;
  max_recipients_per_hour: number;
}

const MB = 1024 * 1024;

interface ImportJob {
  id: number;
  kind: string;
  source: string;
  status: string;
  imported: number;
  skipped: number;
  error: string | null;
  started_at: number;
}

/** Account transfer: copy mail from another server over IMAP, or ingest a Maildir. */
function ImportDialog({ box, isSuper, onClose }: { box: Mailbox; isSuper: boolean; onClose: () => void }) {
  const [kind, setKind] = useState<'imap' | 'maildir'>('imap');
  const [host, setHost] = useState('');
  const [port, setPort] = useState('993');
  const [security, setSecurity] = useState<'tls' | 'starttls'>('tls');
  const [username, setUsername] = useState('');
  const [password, setPassword] = useState('');
  const [insecure, setInsecure] = useState(false);
  const [path, setPath] = useState('');
  const [jobs, setJobs] = useState<ImportJob[]>([]);
  const { run, feedback } = useAction();

  const refresh = () => get<ImportJob[]>(`/api/accounts/${box.id}/import`).then(setJobs).catch(() => {});
  useEffect(() => {
    void refresh();
    const timer = setInterval(() => void refresh(), 2000);
    return () => clearInterval(timer);
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [box.id]);

  const valid = kind === 'imap' ? Boolean(host.trim() && username.trim() && password && /^\d+$/.test(port)) : Boolean(path.trim());
  async function start() {
    const body = kind === 'imap' ? { kind, host: host.trim(), port: Number(port), security, username: username.trim(), password, allow_invalid_certificate: insecure } : { kind, path: path.trim() };
    if (await run(() => post(`/api/accounts/${box.id}/import`, body), t('Import started'))) {
      setPassword('');
      await refresh();
    }
  }

  return (
    <Dialog open onClose={onClose} fullWidth maxWidth="md">
      <DialogTitle>{t('Import mail into {{email}}', { email: box.email })}</DialogTitle>
      <DialogContent>
        {feedback}
        <Stack spacing={2} sx={{ mt: 1 }}>
          <TextField select label={t('Source')} value={kind} onChange={(e) => setKind(e.target.value as 'imap' | 'maildir')} sx={{ maxWidth: 320 }}>
            <MenuItem value="imap">{t('Another mail server (IMAP)')}</MenuItem>
            {isSuper && <MenuItem value="maildir">{t('Maildir on this server')}</MenuItem>}
          </TextField>
          {kind === 'imap' ? (
            <>
              <Stack direction="row" spacing={2}>
                <TextField label={t('IMAP host')} value={host} onChange={(e) => setHost(e.target.value)} placeholder="imap.old-provider.example" fullWidth />
                <TextField
                  select
                  label={t('Encryption')}
                  value={security}
                  onChange={(e) => {
                    const next = e.target.value as 'tls' | 'starttls';
                    // Follow the standard port unless a custom one was entered.
                    if (port === (security === 'tls' ? '993' : '143')) setPort(next === 'tls' ? '993' : '143');
                    setSecurity(next);
                  }}
                  sx={{ width: 170 }}
                >
                  <MenuItem value="tls">TLS</MenuItem>
                  <MenuItem value="starttls">STARTTLS</MenuItem>
                </TextField>
                <TextField label={t('Port')} value={port} onChange={(e) => setPort(e.target.value)} sx={{ width: 110 }} />
              </Stack>
              <Stack direction="row" spacing={2}>
                <TextField label={t('User name')} value={username} onChange={(e) => setUsername(e.target.value)} autoComplete="off" fullWidth />
                <TextField label={t('Remote password')} type="password" value={password} onChange={(e) => setPassword(e.target.value)} autoComplete="new-password" fullWidth helperText={t('Used once, never stored')} />
              </Stack>
              {isSuper && <FormControlLabel control={<Switch checked={insecure} onChange={(e) => setInsecure(e.target.checked)} />} label={t('Accept an invalid or self-signed certificate')} />}
            </>
          ) : (
            <TextField label={t('Directory inside the import folder')} value={path} onChange={(e) => setPath(e.target.value)} helperText={t('Copy the Maildir to <data>/unomail/import/<name> on the server and enter <name>')} />
          )}
          <Typography variant="body2" color="text.secondary">
            {t('Folders, read/replied/flagged state and dates are preserved. Messages that already exist are skipped, so an import can be repeated safely.')}
          </Typography>
          {jobs.length > 0 && (
            <ScrollTable size="small" aria-label={t('Import jobs')}>
              <TableHead>
                <TableRow>
                  <TableCell>{t('Started')}</TableCell>
                  <TableCell>{t('Source')}</TableCell>
                  <TableCell>{t('Status')}</TableCell>
                  <TableCell align="right">{t('Imported')}</TableCell>
                  <TableCell align="right">{t('Skipped')}</TableCell>
                </TableRow>
              </TableHead>
              <TableBody>
                {jobs.map((job) => (
                  <TableRow key={job.id}>
                    <TableCell sx={{ whiteSpace: 'nowrap' }}>{new Date(job.started_at * 1000).toLocaleString(uiLocale())}</TableCell>
                    <TableCell sx={{ wordBreak: 'break-all' }}>{job.source}</TableCell>
                    <TableCell>
                      <StatusChip status={job.status === 'completed' ? 'ok' : job.status === 'failed' ? 'error' : 'queued'} />
                      {job.error && <Typography variant="caption" display="block" color="error">{job.error}</Typography>}
                    </TableCell>
                    <TableCell align="right">{job.imported}</TableCell>
                    <TableCell align="right">{job.skipped}</TableCell>
                  </TableRow>
                ))}
              </TableBody>
            </ScrollTable>
          )}
        </Stack>
      </DialogContent>
      <DialogActions>
        <Button onClick={onClose}>{t('Close')}</Button>
        <Button variant="contained" disabled={!valid || jobs.some((j) => j.status === 'running')} onClick={() => void start()}>
          {t('Start import')}
        </Button>
      </DialogActions>
    </Dialog>
  );
}

interface FormState {
  id?: number;
  email: string;
  display_name: string;
  password: string;
  role: string;
  quota_mb: string;
  enabled: boolean;
  imap_enabled: boolean;
  pop3_enabled: boolean;
  smtp_enabled: boolean;
  outbound_blocked: boolean;
  /** Why the server blocked sending by itself (shown while the block lasts). */
  outbound_blocked_reason?: string | null;
  send_only: boolean;
  /** Sending limit overrides as typed; empty uses the server setting. */
  limits: Record<LimitField, string>;
}

type LimitField = 'max_messages_per_hour' | 'max_recipients_per_hour' | 'max_message_size' | 'max_recipients';
const LIMIT_FIELDS: LimitField[] = ['max_messages_per_hour', 'max_recipients_per_hour', 'max_message_size', 'max_recipients'];
const NO_LIMITS: Record<LimitField, string> = { max_messages_per_hour: '', max_recipients_per_hour: '', max_message_size: '', max_recipients: '' };

/** The message size is shown in megabytes, the other limits as they are. */
const limitText = (field: LimitField, value: number | null) => (value === null ? '' : String(field === 'max_message_size' ? Math.round(value / MB) : value));
const limitValue = (field: LimitField, text: string) => (text.trim() === '' ? null : Number(text) * (field === 'max_message_size' ? MB : 1));

const EMPTY: FormState = { email: '', display_name: '', password: '', role: 'user', quota_mb: '1024', enabled: true, imap_enabled: true, pop3_enabled: true, smtp_enabled: true, outbound_blocked: false, send_only: false, limits: NO_LIMITS };

/** Whether a mailbox uses 2-step sign-in, with a reset for an owner who lost the phone. */
function TwoStepStatus({ id }: { id: number }) {
  const [status, setStatus] = useState<{ enabled: boolean; totp: boolean; passkeys: number; app_passwords: number } | null>(null);
  const [done, setDone] = useState('');
  useEffect(() => {
    get<{ enabled: boolean; totp: boolean; passkeys: number; app_passwords: number }>(`/api/accounts/${id}/two-factor`).then(setStatus).catch(() => {});
  }, [id]);
  if (!status) return null;
  return (
    <Alert severity={status.enabled ? 'info' : 'warning'} action={status.enabled && <Button color="inherit" size="small" onClick={() => void del(`/api/accounts/${id}/two-factor`).then(() => { setStatus({ ...status, enabled: false, totp: false, passkeys: 0, app_passwords: 0 }); setDone(t('2-step verification was reset and app passwords were revoked; the owner signs in with the password alone and can set it up again.')); })}>{t('Reset')}</Button>}>
      {done || (status.enabled ? t('2-step verification is on ({{methods}}).', { methods: [status.totp && t('authenticator app'), status.passkeys > 0 && t('{{count}} passkeys', { count: status.passkeys })].filter(Boolean).join(', ') }) : t('2-step verification is off.'))}
      {status.app_passwords > 0 && ` ${t('{{count}} app passwords.', { count: status.app_passwords })}`}
    </Alert>
  );
}

export function Mailboxes() {
  const { account } = useAuth();
  const isSuper = account?.role === 'super_admin';
  const [search, setSearch] = useState('');
  const [query, setQuery] = useState('');
  const { data, error, reload } = useLoad(() => get<MailboxList>(`/api/accounts?limit=200&q=${encodeURIComponent(query)}`), [query]);
  const { run, feedback, notify } = useAction();
  const [form, setForm] = useState<FormState | null>(null);
  const [removing, setRemoving] = useState<Mailbox | null>(null);
  const [importing, setImporting] = useState<Mailbox | null>(null);
  const saving = useFormAction(
    routeBy<'email' | 'password' | 'quota' | 'display_name' | 'role'>([
      [/password/i, 'password'],
      [/quota/i, 'quota'],
      [/display name/i, 'display_name'],
      [/role|super administrator/i, 'role'],
      [/e-mail address|domain is not hosted|already exists|already in use/i, 'email'],
    ]),
  );

  useEffect(() => {
    const timer = setTimeout(() => setQuery(search.trim()), 250);
    return () => clearTimeout(timer);
  }, [search]);

  const editing = form?.id !== undefined;
  const errors = form
    ? {
        email: editing ? '' : validators.email(form.email),
        password: form.password || !editing ? validators.password(form.password) : '',
        quota: /^\d+$/.test(form.quota_mb) ? '' : t('Enter a whole number of megabytes (0 = unlimited)'),
        limits: LIMIT_FIELDS.some((field) => !/^\s*([1-9]\d*)?\s*$/.test(form.limits[field])),
      }
    : { email: '', password: '', quota: '', limits: false };
  const valid = !errors.email && !errors.password && !errors.quota && !errors.limits;

  async function save() {
    if (!form || !valid) return;
    const quota_bytes = Number(form.quota_mb) * MB;
    const body: Record<string, unknown> = editing
      ? {
          display_name: form.display_name, quota_bytes, enabled: form.enabled, imap_enabled: form.imap_enabled, pop3_enabled: form.pop3_enabled,
          smtp_enabled: form.smtp_enabled, outbound_blocked: form.outbound_blocked, send_only: form.send_only,
          ...Object.fromEntries(LIMIT_FIELDS.map((field) => [field, limitValue(field, form.limits[field])])), ...(form.password ? { password: form.password } : {}), ...(isSuper ? { role: form.role } : {}),
        }
      : { email: form.email.trim(), password: form.password, display_name: form.display_name, quota_bytes, ...(isSuper ? { role: form.role } : {}) };
    const ok = await saving.run(() => (editing ? patch(`/api/accounts/${form.id}`, body) : post('/api/accounts', body)));
    if (ok) {
      notify(editing ? t('Mailbox updated') : t('Mailbox created'));
      setForm(null);
      await reload();
    }
  }

  const set = (changes: Partial<FormState>) => {
    saving.clear();
    setForm((f) => (f ? { ...f, ...changes } : f));
  };
  const open = (next: FormState) => {
    saving.clear();
    setForm(next);
  };
  return (
    <>
      <PageHeader title={t('Mailboxes')}>
        <TextField label={t('Search')} value={search} onChange={(e) => setSearch(e.target.value)} sx={{ width: 240 }} />
        <Button variant="contained" startIcon={<Add />} onClick={() => open(EMPTY)}>
          {t('Add mailbox')}
        </Button>
      </PageHeader>
      {error && <Alert severity="error">{error}</Alert>}
      {!form && feedback}
      <ScrollTable size="small" aria-label={t('Mailboxes')}>
        <TableHead>
          <TableRow>
            <TableCell>{t('Address')}</TableCell>
            <TableCell>{t('Name')}</TableCell>
            <TableCell>{t('Role')}</TableCell>
            <TableCell sx={{ width: 220 }}>{t('Storage')}</TableCell>
            <TableCell sx={{ width: 200 }}>
              <Tooltip title={t('Mail sent over the last hour against the hourly sending limits; going over them blocks the mailbox from sending')}>
                <span>{t('Sending')}</span>
              </Tooltip>
            </TableCell>
            <TableCell>{t('Access')}</TableCell>
            <TableCell />
          </TableRow>
        </TableHead>
        <TableBody>
          {(data?.items ?? []).map((box) => (
            <TableRow key={box.id} hover sx={{ opacity: box.enabled ? 1 : 0.55 }}>
              <TableCell>
                {box.email}
                {box.system && (
                  <Tooltip title={t('Kept by the server for every domain: it receives DMARC and TLS reports and mail to postmaster. Set a password to read it.')}>
                    <Chip size="small" color="info" label={t('system')} sx={{ ml: 1 }} />
                  </Tooltip>
                )}
                {box.send_only && <Chip size="small" color="secondary" label={t('send only')} sx={{ ml: 1 }} />}
                {box.outbound_blocked && <Chip size="small" color="error" label={t('sending blocked')} sx={{ ml: 1 }} />}
                {!box.enabled && <Chip size="small" color="warning" variant="outlined" label={t('disabled')} sx={{ ml: 1 }} />}
              </TableCell>
              <TableCell>{box.display_name}</TableCell>
              <TableCell>{box.role.replace('_', ' ')}</TableCell>
              <TableCell data-sort={box.used_bytes}>
                <Typography variant="caption">
                  {t('{{used}} of {{quota}}', { used: formatBytes(box.used_bytes), quota: box.quota_bytes ? formatBytes(box.quota_bytes) : t('unlimited') })}
                </Typography>
                {box.quota_bytes > 0 && <LinearProgress variant="determinate" value={Math.min(100, (box.used_bytes / box.quota_bytes) * 100)} color={box.used_bytes > box.quota_bytes * 0.9 ? 'error' : 'primary'} />}
              </TableCell>
              <TableCell data-sort={data ? box.sent_recipients / (box.max_recipients_per_hour ?? data.max_recipients_per_hour) : 0}>
                {data && (
                  <>
                    <UsageBar label={t('Messages')} used={box.sent_messages} limit={box.max_messages_per_hour ?? data.max_messages_per_hour} />
                    <UsageBar label={t('Recipients')} used={box.sent_recipients} limit={box.max_recipients_per_hour ?? data.max_recipients_per_hour} />
                  </>
                )}
              </TableCell>
              <TableCell>
                {[box.imap_enabled && 'IMAP', box.pop3_enabled && 'POP3', box.smtp_enabled && 'SMTP'].filter(Boolean).join(' · ')}
              </TableCell>
              <TableCell align="right" sx={{ whiteSpace: 'nowrap' }}>
                <Tooltip title={t('Edit')}>
                  <IconButton
                    aria-label={t('Edit {{email}}', { email: box.email })}
                    onClick={() => open({ ...box, password: '', quota_mb: String(Math.round(box.quota_bytes / MB)), limits: Object.fromEntries(LIMIT_FIELDS.map((field) => [field, limitText(field, box[field])])) as Record<LimitField, string> })}
                  >
                    <Edit />
                  </IconButton>
                </Tooltip>
                <Tooltip title={t('Import mail')}>
                  <IconButton aria-label={t('Import into {{email}}', { email: box.email })} onClick={() => setImporting(box)}>
                    <MoveToInbox />
                  </IconButton>
                </Tooltip>
                {!box.system && (
                  <Tooltip title={t('Delete')}>
                    <IconButton aria-label={t('Delete {{email}}', { email: box.email })} onClick={() => setRemoving(box)}>
                      <Delete />
                    </IconButton>
                  </Tooltip>
                )}
              </TableCell>
            </TableRow>
          ))}
        </TableBody>
      </ScrollTable>
      {data && data.total > data.items.length && (
        <Typography variant="caption" color="text.secondary">
          {t('Showing {{length}} of {{total}}. Refine the search to see more.', { length: data.items.length, total: data.total })}
        </Typography>
      )}

      <Dialog open={Boolean(form)} onClose={() => setForm(null)} fullWidth maxWidth="sm">
        <DialogTitle>{editing ? t('Edit {{email}}', { email: form?.email }) : t('Add mailbox')}</DialogTitle>
        {form && (
          <DialogContent>
            {saving.formError}
            <Stack spacing={2} sx={{ mt: 1 }}>
              {!editing && (
                <TextField
                  label={t('E-mail address')}
                  value={form.email}
                  onChange={(e) => set({ email: e.target.value })}
                  error={Boolean((form.email && errors.email) || saving.fieldError('email'))}
                  helperText={(form.email ? errors.email : '') || saving.fieldError('email')}
                  autoFocus
                />
              )}
              <TextField label={t('Display name')} value={form.display_name} onChange={(e) => set({ display_name: e.target.value })} error={Boolean(saving.fieldError('display_name'))} helperText={saving.fieldError('display_name')} />
              <TextField
                label={editing ? t('New password (leave empty to keep)') : t('Password')}
                type="password"
                autoComplete="new-password"
                value={form.password}
                onChange={(e) => set({ password: e.target.value })}
                error={Boolean((form.password && errors.password) || saving.fieldError('password'))}
                helperText={(form.password ? errors.password : '') || saving.fieldError('password') || (editing ? t('Setting a password signs the user out everywhere and revokes their app passwords.') : t('At least 10 characters'))}
              />
              <TextField
                label={t('Quota (MB, 0 = unlimited)')}
                value={form.quota_mb}
                onChange={(e) => set({ quota_mb: e.target.value })}
                error={Boolean(errors.quota || saving.fieldError('quota'))}
                helperText={errors.quota || saving.fieldError('quota')}
              />
              {isSuper && (
                <TextField select label={t('Role')} value={form.role} onChange={(e) => set({ role: e.target.value })} error={Boolean(saving.fieldError('role'))} helperText={saving.fieldError('role')}>
                  <MenuItem value="user">{t('User')}</MenuItem>
                  <MenuItem value="domain_admin">{t('Domain administrator')}</MenuItem>
                  <MenuItem value="super_admin">{t('Super administrator')}</MenuItem>
                </TextField>
              )}
              {editing && (
                <Stack direction="row" flexWrap="wrap">
                  <FormControlLabel control={<Switch checked={form.enabled} onChange={(e) => set({ enabled: e.target.checked })} />} label={t('Enabled')} />
                  <FormControlLabel control={<Switch checked={form.imap_enabled} onChange={(e) => set({ imap_enabled: e.target.checked })} />} label="IMAP" />
                  <FormControlLabel control={<Switch checked={form.pop3_enabled} onChange={(e) => set({ pop3_enabled: e.target.checked })} />} label="POP3" />
                  <FormControlLabel control={<Switch checked={form.smtp_enabled} onChange={(e) => set({ smtp_enabled: e.target.checked })} />} label="SMTP" />
                </Stack>
              )}
              {editing && (
                <FormControlLabel
                  control={<Switch color="error" checked={form.outbound_blocked} onChange={(e) => set({ outbound_blocked: e.target.checked })} />}
                  label={
                    <>
                      {t('Block sending')}
                      <Typography variant="body2" color="text.secondary">
                        {form.outbound_blocked && form.outbound_blocked_reason
                          ? t('Blocked automatically: {{reason}}', { reason: form.outbound_blocked_reason })
                          : t('The mailbox can no longer send mail; incoming mail still arrives. Set automatically when it goes over its sending limits.')}
                      </Typography>
                    </>
                  }
                />
              )}
              {editing && (
                <FormControlLabel
                  control={<Switch checked={form.send_only} onChange={(e) => set({ send_only: e.target.checked })} />}
                  label={
                    <>
                      {t('Send only')}
                      <Typography variant="body2" color="text.secondary">{t('For noreply addresses: the mailbox can send, and all mail sent to it is discarded without a bounce.')}</Typography>
                    </>
                  }
                />
              )}
              {editing && (
                <Stack spacing={1}>
                  <Typography variant="subtitle2">{t('Sending limits')}</Typography>
                  <Typography variant="body2" color="text.secondary">
                    {t('Leave a field empty to use the server setting. The message size and recipients per message can only be lower than the server allows.')}
                  </Typography>
                  <Stack direction={{ xs: 'column', sm: 'row' }} spacing={2}>
                    {LIMIT_FIELDS.map((field) => {
                      const invalid = !/^\s*([1-9]\d*)?\s*$/.test(form.limits[field]);
                      const serverValue = field === 'max_messages_per_hour' ? data?.max_messages_per_hour : field === 'max_recipients_per_hour' ? data?.max_recipients_per_hour : undefined;
                      return (
                        <TextField
                          key={field}
                          size="small"
                          inputMode="numeric"
                          label={{ max_messages_per_hour: t('Messages per hour'), max_recipients_per_hour: t('Recipients per hour'), max_message_size: t('Message size (MB)'), max_recipients: t('Recipients per message') }[field]}
                          value={form.limits[field]}
                          placeholder={serverValue === undefined ? t('Server default') : t('Server default ({{value}})', { value: serverValue })}
                          InputLabelProps={{ shrink: true }}
                          onChange={(e) => set({ limits: { ...form.limits, [field]: e.target.value } })}
                          error={invalid}
                          helperText={invalid ? t('A whole number of at least 1') : undefined}
                        />
                      );
                    })}
                  </Stack>
                </Stack>
              )}
              {editing && form.id !== undefined && <TwoStepStatus id={form.id} />}
            </Stack>
          </DialogContent>
        )}
        <DialogButtons onCancel={() => setForm(null)} onConfirm={() => void save()} disabled={!valid || saving.busy} label={editing ? t('Save') : t('Create')} />
      </Dialog>
      {importing && <ImportDialog box={importing} isSuper={isSuper} onClose={() => { setImporting(null); void reload(); }} />}
      <ConfirmDialog
        open={Boolean(removing)}
        title={t('Delete {{email}}?', { email: removing?.email ?? '' })}
        text={t('The mailbox and all of its mail are permanently deleted.')}
        onClose={() => setRemoving(null)}
        onConfirm={async () => {
          const target = removing;
          setRemoving(null);
          if (target && (await run(() => del(`/api/accounts/${target.id}`), t('Mailbox deleted')))) await reload();
        }}
      />
    </>
  );
}
