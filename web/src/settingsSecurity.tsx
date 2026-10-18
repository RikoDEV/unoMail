import Delete from '@mui/icons-material/Delete';
import Edit from '@mui/icons-material/Edit';
import Key from '@mui/icons-material/Key';
import PhonelinkLock from '@mui/icons-material/PhonelinkLock';
import {
  Alert, Box, Button, Card, CardContent, Checkbox, Chip, Dialog, DialogActions, DialogContent, DialogTitle, FormControlLabel, FormGroup, IconButton, Stack, Table, TableBody, TableCell,
  TableHead, TableRow, TextField, Tooltip, Typography,
} from '@mui/material';
import { useCallback, useEffect, useState } from 'react';
import { api, del, formatTime, get, post, put, errorText } from './api';
import { createPasskey, keepOnlyAcceptedPasskeys, passkeysAvailable, type CreationOptions, wasDismissed } from './webauthn';

import { t } from './i18n';
interface Overview {
  enabled: boolean;
  totp: boolean;
  recovery_codes_left: number;
  passkeys_supported: boolean;
  passkeys: {
    id: number;
    name: string;
    created_at: number;
    last_used_at: number | null;
    /** Kept by a passkey provider that syncs it to the user's other devices. */
    synced: boolean;
    /** Signs in without an address or password (null: registered before this was recorded). */
    discoverable: boolean | null;
  }[];
}

type Signal = { rpId: string; userId: string; allAcceptedCredentialIds: string[] } | null;


/** Asks for the account password before a change that weakens the account or adds a way in. */
function PasswordPrompt({ title, action, color = 'error', onConfirm, onClose }: { title: string; action: string; color?: 'error' | 'primary'; onConfirm: (password: string) => Promise<void>; onClose: () => void }) {
  const [password, setPassword] = useState('');
  const [error, setError] = useState('');
  return (
    <Dialog open onClose={onClose} maxWidth="xs" fullWidth>
      <DialogTitle>{title}</DialogTitle>
      <DialogContent>
        <Stack
          spacing={2}
          sx={{ mt: 1 }}
          component="form"
          onSubmit={(e) => {
            e.preventDefault();
            onConfirm(password).catch((err) => setError(errorText(err, t('That did not work'))));
          }}
        >
          {error && <Alert severity="error">{error}</Alert>}
          <TextField label={t('Your password')} type="password" autoComplete="current-password" value={password} onChange={(e) => setPassword(e.target.value)} autoFocus />
          <DialogActions sx={{ px: 0 }}>
            <Button onClick={onClose}>{t('Cancel')}</Button>
            <Button type="submit" variant="contained" color={color} disabled={!password}>{action}</Button>
          </DialogActions>
        </Stack>
      </DialogContent>
    </Dialog>
  );
}

function RecoveryCodes({ codes, onClose }: { codes: string[]; onClose: () => void }) {
  const text = codes.join('\n');
  return (
    <Dialog open onClose={onClose} maxWidth="xs" fullWidth>
      <DialogTitle>{t('Recovery codes')}</DialogTitle>
      <DialogContent>
        <Typography variant="body2" sx={{ mb: 2 }}>
          {t('Keep these codes somewhere safe. Each one signs you in once if you lose your phone or passkey. They are shown only now.')}
        </Typography>
        <Box component="ul" aria-label={t('Recovery codes')} sx={{ m: 0, p: 2, bgcolor: 'action.hover', borderRadius: 1, columns: 2, listStyle: 'none', fontFamily: 'monospace', fontSize: 16 }}>
          {codes.map((code) => (
            <li key={code}>{code}</li>
          ))}
        </Box>
      </DialogContent>
      <DialogActions>
        <Button onClick={() => void navigator.clipboard?.writeText(text)}>{t('Copy')}</Button>
        <Button
          onClick={() => {
            const url = URL.createObjectURL(new Blob([`${t('unoMail recovery codes')}\n\n${text}\n`], { type: 'text/plain' }));
            const link = document.createElement('a');
            link.href = url;
            link.download = 'unomail-recovery-codes.txt';
            link.click();
            setTimeout(() => URL.revokeObjectURL(url), 1000);
          }}
        >
          {t('Download')}
        </Button>
        <Button variant="contained" onClick={onClose}>{t('I have saved them')}</Button>
      </DialogActions>
    </Dialog>
  );
}

function TotpSetup({ onDone, onClose }: { onDone: (codes: string[] | null) => void; onClose: () => void }) {
  const [setup, setSetup] = useState<{ secret: string; uri: string } | null>(null);
  const [qr, setQr] = useState('');
  const [code, setCode] = useState('');
  const [password, setPassword] = useState('');
  const [error, setError] = useState('');

  useEffect(() => {
    post<{ secret: string; uri: string }>('/api/me/two-factor/totp')
      .then(async (created) => {
        setSetup(created);
        // Loaded only here: the QR encoder is not needed anywhere else.
        const { default: QRCode } = await import('qrcode');
        setQr(await QRCode.toDataURL(created.uri, { margin: 1, width: 200 }));
      })
      .catch((err) => setError(errorText(err, t('Could not start'))));
  }, []);

  async function confirm() {
    try {
      const result = await put<{ recovery_codes: string[] | null }>('/api/me/two-factor/totp', { code, password });
      onDone(result.recovery_codes);
    } catch (err) {
      setError(errorText(err, t('The code is not correct')));
    }
  }

  return (
    <Dialog open onClose={onClose} maxWidth="sm" fullWidth>
      <DialogTitle>{t('Set up an authenticator app')}</DialogTitle>
      <DialogContent>
        <Stack spacing={2} sx={{ mt: 1 }}>
          {error && <Alert severity="error">{error}</Alert>}
          <Typography variant="body2">{t('Scan the code with an authenticator app (Google Authenticator, Microsoft Authenticator, Aegis, 1Password, …), then enter the six digits it shows.')}</Typography>
          <Stack direction={{ xs: 'column', sm: 'row' }} spacing={2} alignItems="center">
            {qr ? <Box component="img" src={qr} alt={t('QR code for the authenticator app')} sx={{ width: 200, height: 200, borderRadius: 1, bgcolor: '#fff' }} /> : <Box sx={{ width: 200, height: 200 }} />}
            <Box sx={{ minWidth: 0 }}>
              <Typography variant="caption" color="text.secondary">{t('Or enter this key by hand:')}</Typography>
              <Typography sx={{ fontFamily: 'monospace', overflowWrap: 'anywhere' }} data-testid="totp-secret">{setup?.secret.replace(/(.{4})/g, '$1 ').trim()}</Typography>
            </Box>
          </Stack>
          <TextField
            label={t('Code from the app')}
            value={code}
            onChange={(e) => setCode(e.target.value)}
            slotProps={{ htmlInput: { inputMode: 'numeric', autoComplete: 'one-time-code', maxLength: 7 } }}
            onKeyDown={(e) => e.key === 'Enter' && code.trim() && password && void confirm()}
          />
          <TextField label={t('Your password')} type="password" autoComplete="current-password" value={password} onChange={(e) => setPassword(e.target.value)} onKeyDown={(e) => e.key === 'Enter' && code.trim() && password && void confirm()} />
        </Stack>
      </DialogContent>
      <DialogActions>
        <Button onClick={onClose}>{t('Cancel')}</Button>
        <Button variant="contained" onClick={() => void confirm()} disabled={!setup || !code.trim() || !password}>{t('Turn on')}</Button>
      </DialogActions>
    </Dialog>
  );
}

/** Two-step sign-in: an authenticator app, passkeys and recovery codes. */
export function TwoStepCard() {
  const [overview, setOverview] = useState<Overview | null>(null);
  const [error, setError] = useState('');
  const [notice, setNotice] = useState('');
  const [codes, setCodes] = useState<string[] | null>(null);
  const [setup, setSetup] = useState(false);
  const [prompt, setPrompt] = useState<{ title: string; action: string; color?: 'error' | 'primary'; run: (password: string) => Promise<void> } | null>(null);

  const load = useCallback(() => get<Overview>('/api/me/two-factor').then(setOverview).catch((err) => setError(errorText(err, t('Could not load')))), []);
  useEffect(() => {
    void load();
  }, [load]);

  /** The password is checked first (it throws into the prompt); then the device makes the passkey. */
  async function addPasskey(password: string) {
    setError('');
    const options = await post<CreationOptions>('/api/me/passkeys/register/options', { password });
    setPrompt(null);
    try {
      const created = await createPasskey(options);
      const name = window.prompt(t('A name for this passkey (to tell it apart later)'), t('Passkey')) ?? t('Passkey');
      const result = await post<{ recovery_codes: string[] | null }>('/api/me/passkeys/register', { name, ...created });
      if (result.recovery_codes) setCodes(result.recovery_codes);
      setNotice(t('Passkey added'));
      await load();
    } catch (err) {
      if (err instanceof DOMException && err.name === 'InvalidStateError') setError(t('This device already has a passkey for your account.'));
      else setError(wasDismissed(err) || err instanceof DOMException ? t('The passkey was not created.') : errorText(err, t('The passkey could not be added')));
    }
  }

  async function renamePasskey(id: number, current: string) {
    const name = window.prompt(t('A name for this passkey (to tell it apart later)'), current);
    if (!name || name.trim() === current) return;
    try {
      await api('PATCH', `/api/me/passkeys/${id}`, { name });
      await load();
    } catch (err) {
      setError(errorText(err, t('The passkey could not be renamed')));
    }
  }

  if (!overview) return error ? <Alert severity="error">{error}</Alert> : null;
  return (
    <Card variant="outlined">
      <CardContent>
        <Stack direction="row" alignItems="center" spacing={1} sx={{ mb: 1 }}>
          <Typography variant="h6" sx={{ flex: 1 }}>{t('2-step verification')}</Typography>
          <Chip label={overview.enabled ? t('On') : t('Off')} color={overview.enabled ? 'success' : 'default'} size="small" />
        </Stack>
        <Typography variant="body2" color="text.secondary" sx={{ mb: 2, maxWidth: 720 }}>
          {t('Ask for a second proof after the password: a code from an app on your phone, or a passkey. Mail and calendar programs then sign in with app passwords (below) instead of your password.')}
        </Typography>
        {error && <Alert severity="error" sx={{ mb: 2 }} onClose={() => setError('')}>{error}</Alert>}
        {notice && <Alert severity="success" sx={{ mb: 2 }} onClose={() => setNotice('')}>{notice}</Alert>}
        <Stack spacing={2.5} sx={{ maxWidth: 720 }}>
          <Stack direction="row" spacing={2} alignItems="center">
            <PhonelinkLock color="action" />
            <Box sx={{ flex: 1 }}>
              <Typography fontWeight={600}>{t('Authenticator app')}</Typography>
              <Typography variant="body2" color="text.secondary">{overview.totp ? t('Codes from your app are asked for when you sign in.') : t('Not set up.')}</Typography>
            </Box>
            {overview.totp ? (
              <Button color="error" onClick={() => setPrompt({ title: t('Turn off the authenticator app'), action: t('Turn off'), run: async (password) => { await api('DELETE', '/api/me/two-factor/totp', { password }); setPrompt(null); setNotice(t('The authenticator app is off')); await load(); } })}>
                {t('Turn off')}
              </Button>
            ) : (
              <Button variant="outlined" onClick={() => setSetup(true)}>{t('Set up')}</Button>
            )}
          </Stack>
          <Box>
            <Stack direction="row" spacing={2} alignItems="center">
              <Key color="action" />
              <Box sx={{ flex: 1 }}>
                <Typography fontWeight={600}>{t('Passkeys and security keys')}</Typography>
                <Typography variant="body2" color="text.secondary">
                  {!overview.passkeys_supported
                    ? t('Passkeys need the web client to be reached by a host name, not an IP address.')
                    : !passkeysAvailable()
                      ? t('This browser cannot use passkeys.')
                      : t('Sign in with your fingerprint, face, screen lock or a security key instead of your password. After the password, a passkey also serves as the second step.')}
                </Typography>
              </Box>
              <Button variant="outlined" onClick={() => setPrompt({ title: t('Add a passkey'), action: t('Continue'), color: 'primary', run: addPasskey })} disabled={!overview.passkeys_supported || !passkeysAvailable()}>{t('Add a passkey')}</Button>
            </Stack>
            {overview.passkeys.length > 0 && (
              <Table size="small" aria-label={t('Passkeys')} sx={{ mt: 1 }}>
                <TableBody>
                  {overview.passkeys.map((passkey) => (
                    <TableRow key={passkey.id}>
                      <TableCell>
                        {passkey.name}
                        <Stack direction="row" spacing={0.5} sx={{ mt: 0.5 }} flexWrap="wrap" useFlexGap>
                          <Chip size="small" variant="outlined" label={passkey.synced ? t('Synced across devices') : t('On one device')} />
                          {passkey.discoverable !== false && <Chip size="small" variant="outlined" color="success" label={t('Signs in without a password')} />}
                        </Stack>
                      </TableCell>
                      <TableCell>{t('added {{time}}', { time: formatTime(passkey.created_at) })}</TableCell>
                      <TableCell>{passkey.last_used_at ? t('used {{time}}', { time: formatTime(passkey.last_used_at) }) : t('not used yet')}</TableCell>
                      <TableCell align="right" sx={{ whiteSpace: 'nowrap' }}>
                        <Tooltip title={t('Rename')}>
                          <IconButton size="small" aria-label={t('Rename {{name}}', { name: passkey.name })} onClick={() => void renamePasskey(passkey.id, passkey.name)}>
                            <Edit fontSize="small" />
                          </IconButton>
                        </Tooltip>
                        <Tooltip title={t('Remove')}>
                          <IconButton
                            size="small"
                            aria-label={t('Remove {{name}}', { name: passkey.name })}
                            onClick={() =>
                              setPrompt({
                                title: t('Remove “{{name}}”', { name: passkey.name }),
                                action: t('Remove'),
                                run: async (password) => {
                                  const result = await api<{ signal: Signal }>('DELETE', `/api/me/passkeys/${passkey.id}`, { password });
                                  // The device stops offering the removed passkey (where the browser supports it).
                                  keepOnlyAcceptedPasskeys(result.signal);
                                  setPrompt(null);
                                  setNotice(t('Passkey removed'));
                                  await load();
                                },
                              })
                            }
                          >
                            <Delete fontSize="small" />
                          </IconButton>
                        </Tooltip>
                      </TableCell>
                    </TableRow>
                  ))}
                </TableBody>
              </Table>
            )}
          </Box>
          {overview.enabled && (
            <Stack direction="row" spacing={2} alignItems="center">
              <Box sx={{ flex: 1 }}>
                <Typography fontWeight={600}>{t('Recovery codes')}</Typography>
                <Typography variant="body2" color="text.secondary">{t('{{recovery_codes_left}} unused. Each signs you in once without the phone or passkey.', { recovery_codes_left: overview.recovery_codes_left })}</Typography>
              </Box>
              <Button onClick={() => setPrompt({ title: t('New recovery codes'), action: t('Make new codes'), run: async (password) => { const result = await post<{ recovery_codes: string[] }>('/api/me/two-factor/recovery-codes', { password }); setPrompt(null); setCodes(result.recovery_codes); await load(); } })}>
                {t('Make new codes')}
              </Button>
            </Stack>
          )}
        </Stack>
      </CardContent>
      {setup && (
        <TotpSetup
          onClose={() => setSetup(false)}
          onDone={(created) => {
            setSetup(false);
            setNotice(t('The authenticator app is on'));
            if (created) setCodes(created);
            void load();
          }}
        />
      )}
      {codes && <RecoveryCodes codes={codes} onClose={() => setCodes(null)} />}
      {prompt && <PasswordPrompt title={prompt.title} action={prompt.action} color={prompt.color} onConfirm={prompt.run} onClose={() => setPrompt(null)} />}
    </Card>
  );
}

interface AppPassword {
  id: number;
  name: string;
  scopes: string[];
  created_at: number;
  last_used_at: number | null;
  last_ip: string;
}

const SCOPE_LABELS: Record<string, string> = { mail: t('Mail (IMAP, POP3, SMTP, filters)'), dav: t('Calendars and contacts (CalDAV, CardDAV)'), jmap: 'JMAP' };

/** Passwords for one program each. */
export function AppPasswordsCard() {
  const [list, setList] = useState<AppPassword[]>([]);
  const [error, setError] = useState('');
  const [creating, setCreating] = useState(false);
  const [name, setName] = useState('');
  const [scopes, setScopes] = useState<string[]>(['mail', 'dav']);
  const [password, setPassword] = useState('');
  const [created, setCreated] = useState<{ name: string; password: string } | null>(null);

  const load = useCallback(() => get<AppPassword[]>('/api/me/app-passwords').then(setList).catch((err) => setError(errorText(err, t('Could not load')))), []);
  useEffect(() => {
    void load();
  }, [load]);

  async function create() {
    setError('');
    try {
      const result = await post<{ name: string; password: string }>('/api/me/app-passwords', { name, scopes, password });
      setCreating(false);
      setCreated(result);
      setName('');
      setPassword('');
      await load();
    } catch (err) {
      setError(errorText(err, t('The app password could not be made')));
    }
  }

  return (
    <Card variant="outlined">
      <CardContent>
        <Stack direction="row" alignItems="center" sx={{ mb: 1 }}>
          <Typography variant="h6" sx={{ flex: 1 }}>{t('App passwords')}</Typography>
          <Button variant="outlined" onClick={() => setCreating(true)}>{t('Create app password')}</Button>
        </Stack>
        <Typography variant="body2" color="text.secondary" sx={{ mb: 2, maxWidth: 720 }}>
          {t('A separate password for each mail, calendar or contacts program. It works only for what you allow, never for signing in here, and can be revoked without changing your password. With 2-step verification on, programs need one.')}
        </Typography>
        {error && !creating && <Alert severity="error" sx={{ mb: 2 }} onClose={() => setError('')}>{error}</Alert>}
        {list.length === 0 ? (
          <Typography color="text.secondary">{t('No app passwords.')}</Typography>
        ) : (
          <Table size="small" aria-label={t('App passwords')}>
            <TableHead>
              <TableRow>
                <TableCell>{t('Program')}</TableCell>
                <TableCell>{t('For')}</TableCell>
                <TableCell>{t('Created')}</TableCell>
                <TableCell>{t('Last used')}</TableCell>
                <TableCell />
              </TableRow>
            </TableHead>
            <TableBody>
              {list.map((entry) => (
                <TableRow key={entry.id}>
                  <TableCell>{entry.name}</TableCell>
                  <TableCell>{entry.scopes.join(', ')}</TableCell>
                  <TableCell>{formatTime(entry.created_at)}</TableCell>
                  <TableCell>{entry.last_used_at ? t('{{time}} from {{ip}}', { time: formatTime(entry.last_used_at), ip: entry.last_ip }) : 'never'}</TableCell>
                  <TableCell align="right">
                    <Button size="small" color="error" onClick={() => void del(`/api/me/app-passwords/${entry.id}`).then(load).catch((err) => setError(errorText(err, t('Could not revoke'))))}>
                      {t('Revoke')}
                    </Button>
                  </TableCell>
                </TableRow>
              ))}
            </TableBody>
          </Table>
        )}
      </CardContent>
      {creating && (
        <Dialog open onClose={() => setCreating(false)} maxWidth="sm" fullWidth>
          <DialogTitle>{t('Create an app password')}</DialogTitle>
          <DialogContent>
            <Stack spacing={2} sx={{ mt: 1 }}>
              {error && <Alert severity="error">{error}</Alert>}
              <TextField label={t('Program')} placeholder={t('Thunderbird on the laptop')} value={name} onChange={(e) => setName(e.target.value)} autoFocus />
              <FormGroup>
                {Object.entries(SCOPE_LABELS).map(([scope, label]) => (
                  <FormControlLabel key={scope} control={<Checkbox checked={scopes.includes(scope)} onChange={(e) => setScopes((current) => (e.target.checked ? [...current, scope] : current.filter((s) => s !== scope)))} />} label={label} />
                ))}
              </FormGroup>
              <TextField label={t('Your password')} type="password" autoComplete="current-password" value={password} onChange={(e) => setPassword(e.target.value)} />
            </Stack>
          </DialogContent>
          <DialogActions>
            <Button onClick={() => setCreating(false)}>{t('Cancel')}</Button>
            <Button variant="contained" onClick={() => void create()} disabled={!name.trim() || scopes.length === 0 || !password}>{t('Create')}</Button>
          </DialogActions>
        </Dialog>
      )}
      {created && (
        <Dialog open onClose={() => setCreated(null)} maxWidth="xs" fullWidth>
          <DialogTitle>{t('App password for {{name}}', { name: created.name })}</DialogTitle>
          <DialogContent>
            <Typography variant="body2" sx={{ mb: 2 }}>{t('Enter it in the program instead of your password. It is shown only now.')}</Typography>
            <Typography data-testid="new-app-password" sx={{ fontFamily: 'monospace', fontSize: 22, letterSpacing: 1, textAlign: 'center', p: 1.5, bgcolor: 'action.hover', borderRadius: 1 }}>
              {created.password}
            </Typography>
          </DialogContent>
          <DialogActions>
            <Button onClick={() => void navigator.clipboard?.writeText(created.password)}>{t('Copy')}</Button>
            <Button variant="contained" onClick={() => setCreated(null)}>{t('Done')}</Button>
          </DialogActions>
        </Dialog>
      )}
    </Card>
  );
}
