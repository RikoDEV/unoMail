// OpenPGP and S/MIME settings.

import {
  Alert, Box, Button, Card, CardContent, Chip, FormControlLabel, Stack, Switch,
  TextField, Typography,
} from '@mui/material';
import { useCallback, useEffect, useState } from 'react';
import { useAuth } from '../app';
import { get, put, errorText } from '../lib/api';
import { type CertInfo, fetchSmime, importSmime, removeSmime } from '../mail/Smime';
import { fetchKeys, fingerprint, generateKeys, importKeys, isUnlocked, localPrivateKey, lock, removeKeys, type StoredKeys, unlock } from '../mail/pgp';

import { t, uiLocale } from '../i18n';

/** The user's S/MIME certificate: signing and encrypting mail, reading encrypted mail. */
export function SmimeCard() {
  const [certificate, setCertificate] = useState<CertInfo | null | undefined>(undefined);
  const [known, setKnown] = useState(0);
  const [file, setFile] = useState<File | null>(null);
  const [password, setPassword] = useState('');
  const [error, setError] = useState('');
  const [busy, setBusy] = useState(false);
  useEffect(() => {
    fetchSmime().then((s) => { setCertificate(s.certificate); setKnown(s.correspondents.length); }, (e: Error) => setError(e.message));
  }, []);
  const day = (seconds: number) => new Date(seconds * 1000).toLocaleDateString(uiLocale());
  return (
    <Card variant="outlined">
      <CardContent>
        <Typography variant="h6" sx={{ mb: 1 }}>
          {t('S/MIME certificate')}
        </Typography>
        <Stack spacing={2} sx={{ maxWidth: 640 }}>
          <Typography variant="body2" sx={{ color: 'text.secondary' }}>
            {t('With a personal certificate (from your organisation or a certificate authority) your mail can be signed and encrypted with S/MIME, the standard built into Outlook, Apple Mail and Thunderbird. The private key is stored on this server, sealed with its key; the server uses it to sign what you send and to decrypt mail encrypted to you when you read it.')}
          </Typography>
          {error && <Alert severity="error" onClose={() => setError('')}>{error}</Alert>}
          {certificate === undefined ? null : certificate ? (
            <>
              <Box>
                <Typography>{certificate.emails.join(', ')}</Typography>
                <Typography variant="body2" sx={{ color: 'text.secondary' }}>{t('Issued by {{issuer}}', { issuer: certificate.issuer })}</Typography>
                <Typography variant="body2" sx={{ color: 'text.secondary' }}>{t('Valid until {{not_after}}', { not_after: day(certificate.not_after) })}</Typography>
                <Typography variant="caption" sx={{ fontFamily: 'monospace', wordBreak: 'break-all' }}>{certificate.fingerprint}</Typography>
              </Box>
              <Typography variant="body2" sx={{ color: 'text.secondary' }}>
                {t('Certificates of {{count}} correspondents are known, collected from their signed mail; you can encrypt mail to them.', { count: known })}
              </Typography>
              <Box>
                <Button color="error" onClick={() => window.confirm(t('Remove your S/MIME certificate? Mail encrypted to it can no longer be read here.')) && void removeSmime().then(() => setCertificate(null), (e: Error) => setError(e.message))}>
                  {t('Remove certificate')}
                </Button>
              </Box>
            </>
          ) : (
            <Stack direction={{ xs: 'column', sm: 'row' }} spacing={1} sx={{
              alignItems: { sm: 'center' }
            }}>
              <Button variant="outlined" component="label">
                {file ? file.name : t('Choose .p12 / .pfx file')}
                <input hidden type="file" accept=".p12,.pfx,application/x-pkcs12" aria-label={t('Certificate file')} onChange={(e) => setFile(e.target.files?.[0] ?? null)} />
              </Button>
              <TextField size="small" type="password" label={t('File password')} autoComplete="off" value={password} onChange={(e) => setPassword(e.target.value)} />
              <Button
                variant="contained"
                disabled={!file || busy}
                onClick={async () => {
                  if (!file) return;
                  setBusy(true);
                  setError('');
                  try {
                    setCertificate(await importSmime(file, password));
                    setPassword('');
                  } catch (err) {
                    setError(errorText(err, t('The certificate could not be imported')));
                  } finally {
                    setBusy(false);
                  }
                }}
              >
                {t('Import')}
              </Button>
            </Stack>
          )}
        </Stack>
      </CardContent>
    </Card>
  );
}

// --- Encryption ----------------------------------------------------------------------------

function download(name: string, content: string) {
  const url = URL.createObjectURL(new Blob([content], { type: 'application/pgp-keys' }));
  const link = document.createElement('a');
  link.href = url;
  link.download = name;
  link.click();
  setTimeout(() => URL.revokeObjectURL(url), 1000);
}

interface AtRest {
  enabled: boolean;
  key: { fingerprint: string } | null;
  problem: string | null;
}

/** Storing incoming mail encrypted to the account's public key (encryption at rest). */
function EncryptIncoming() {
  const [state, setState] = useState<AtRest | null>(null);
  const [error, setError] = useState('');
  useEffect(() => {
    get<AtRest>('/api/me/pgp/encryption').then(setState, (e: Error) => setError(e.message));
  }, []);
  if (!state) return error ? <Alert severity="error">{error}</Alert> : null;
  const toggle = (enabled: boolean) => put<AtRest>('/api/me/pgp/encryption', { enabled }).then(setState, (e: Error) => setError(e.message));
  return (
    <Box>
      <FormControlLabel
        control={<Switch checked={state.enabled} onChange={(e) => void toggle(e.target.checked)} slotProps={{ input: { 'aria-label': t('Store incoming mail encrypted') } }} />}
        label={t('Store incoming mail encrypted to this key')}
      />
      <Typography variant="caption" component="div" sx={{ color: 'text.secondary' }}>
        {t('New messages are encrypted on arrival, before they are stored. Only you can read them, here after unlocking the key or in any mail program that has your private key; search covers their subject and senders only. Messages already stored are not changed.')}
      </Typography>
      {state.problem && <Alert severity="warning" sx={{ mt: 1 }}>{t('This key cannot be used for it: {{problem}}', { problem: state.problem })}</Alert>}
      {error && <Alert severity="error" sx={{ mt: 1 }} onClose={() => setError('')}>{error}</Alert>}
    </Box>
  );
}

export function EncryptionCard() {
  const { account } = useAuth();
  const email = account?.email ?? '';
  const [keys, setKeys] = useState<StoredKeys | null | undefined>(undefined);
  const [print, setPrint] = useState('');
  const [mode, setMode] = useState<'idle' | 'generate' | 'import'>('idle');
  const [passphrase, setPassphrase] = useState('');
  const [repeat, setRepeat] = useState('');
  const [imported, setImported] = useState('');
  const [keepOnServer, setKeepOnServer] = useState(true);
  const [unlockWith, setUnlockWith] = useState('');
  const [unlocked, setUnlocked] = useState(isUnlocked());
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState('');
  const [notice, setNotice] = useState('');

  const reload = useCallback(async () => {
    try {
      const stored = await fetchKeys();
      setKeys(stored);
      setPrint(stored ? await fingerprint(stored.public_key) : '');
    } catch {
      setKeys(null);
    }
  }, []);
  useEffect(() => {
    void reload();
  }, [reload]);

  async function run(action: () => Promise<void>, done: string) {
    setBusy(true);
    setError('');
    setNotice('');
    try {
      await action();
      setNotice(done);
      setMode('idle');
      setPassphrase('');
      setRepeat('');
      setImported('');
      setUnlockWith('');
      setUnlocked(isUnlocked());
      await reload();
    } catch (err) {
      setError(errorText(err, t('The operation failed')));
    } finally {
      setBusy(false);
    }
  }

  const privateKey = keys?.private_key || localPrivateKey(email);
  return (
    <Card variant="outlined">
      <CardContent>
        <Typography variant="h6" sx={{ mb: 1 }}>
          {t('Encryption (OpenPGP)')}
        </Typography>
        <Stack spacing={2} sx={{ maxWidth: 640 }}>
          {error && <Alert severity="error" onClose={() => setError('')}>{error}</Alert>}
          {notice && <Alert severity="success" onClose={() => setNotice('')}>{notice}</Alert>}
          <Typography variant="body2" sx={{ color: 'text.secondary' }}>
            {t("Encrypted messages are encrypted and decrypted in your browser. The server stores your public key so that colleagues can write to you, and your private key only in its passphrase-protected form, if you choose so. Without the passphrase nobody, including the server's administrator, can read your encrypted mail; if you lose it, neither can you.")}
          </Typography>
          {keys === undefined ? null : keys ? (
            <>
              <Box>
                <Typography variant="body2">{t('Key fingerprint')}</Typography>
                <Typography sx={{ fontFamily: 'monospace', wordBreak: 'break-all' }} data-testid="pgp-fingerprint">
                  {print}
                </Typography>
                <Typography variant="caption" sx={{ color: 'text.secondary' }}>
                  {keys.private_key ? t('The protected private key is stored on the server and available on every device.') : privateKey ? t('The private key is kept in this browser only.') : t('The private key is not available on this device.')}
                </Typography>
              </Box>
              <EncryptIncoming key={keys.public_key} />
              {privateKey &&
                (unlocked ? (
                  <Stack direction="row" spacing={1} sx={{ alignItems: 'center' }}>
                    <Chip color="success" label={t('Unlocked for this session')} />
                    <Button onClick={() => { lock(); setUnlocked(false); }}>{t('Lock')}</Button>
                  </Stack>
                ) : (
                  <Stack direction="row" spacing={1} sx={{ alignItems: 'flex-start' }}>
                    <TextField label={t('Passphrase')} type="password" autoComplete="off" value={unlockWith} onChange={(e) => setUnlockWith(e.target.value)} />
                    <Button variant="outlined" disabled={busy || !unlockWith} onClick={() => void run(() => unlock(privateKey, unlockWith), t('Key unlocked: messages you send are signed and encrypted mail can be read'))}>
                      {t('Unlock key')}
                    </Button>
                  </Stack>
                ))}
              <Stack direction="row" spacing={1} useFlexGap sx={{ flexWrap: 'wrap' }}>
                <Button onClick={() => download(`${email}-public.asc`, keys.public_key)}>{t('Export public key')}</Button>
                {privateKey && <Button onClick={() => download(`${email}-private.asc`, privateKey)}>{t('Back up private key')}</Button>}
                <Button color="error" disabled={busy} onClick={() => window.confirm(t('Remove your keys? Mail encrypted to this key can no longer be read unless you kept a backup.')) && void run(() => removeKeys(email), t('Keys removed'))}>
                  {t('Remove keys')}
                </Button>
              </Stack>
            </>
          ) : mode === 'idle' ? (
            <Stack direction="row" spacing={1}>
              <Button variant="contained" onClick={() => setMode('generate')}>
                {t('Create a key')}
              </Button>
              <Button onClick={() => setMode('import')}>{t('Import an existing key')}</Button>
            </Stack>
          ) : (
            <Stack spacing={2}>
              {mode === 'generate' ? (
                <>
                  <TextField label={t('New passphrase')} type="password" autoComplete="new-password" value={passphrase} onChange={(e) => setPassphrase(e.target.value)} error={Boolean(passphrase) && passphrase.length < 10} helperText={t('At least 10 characters. It cannot be recovered.')} />
                  <TextField label={t('Repeat passphrase')} type="password" autoComplete="new-password" value={repeat} onChange={(e) => setRepeat(e.target.value)} error={Boolean(repeat) && repeat !== passphrase} />
                </>
              ) : (
                <TextField
                  label={t('Private key')}
                  value={imported}
                  onChange={(e) => setImported(e.target.value)}
                  multiline
                  minRows={4}
                  maxRows={10}
                  placeholder="-----BEGIN PGP PRIVATE KEY BLOCK-----"
                  helperText={t('The key must be protected with a passphrase')}
                  slotProps={{ htmlInput: { spellCheck: false, style: { fontFamily: 'monospace', fontSize: 12 } } }}
                />
              )}
              <FormControlLabel control={<Switch checked={keepOnServer} onChange={(e) => setKeepOnServer(e.target.checked)} />} label={t('Keep the passphrase-protected key on the server, so it works on all my devices')} />
              <Stack direction="row" spacing={1}>
                {mode === 'generate' ? (
                  <Button variant="contained" disabled={busy || passphrase.length < 10 || passphrase !== repeat} onClick={() => void run(() => generateKeys(account?.display_name ?? '', email, passphrase, keepOnServer).then(() => undefined), t('Your key was created'))}>
                    {t('Create key')}
                  </Button>
                ) : (
                  <Button variant="contained" disabled={busy || !imported.trim()} onClick={() => void run(() => importKeys(email, imported, keepOnServer), t('Your key was imported'))}>
                    {t('Import key')}
                  </Button>
                )}
                <Button onClick={() => setMode('idle')}>{t('Cancel')}</Button>
              </Stack>
            </Stack>
          )}
        </Stack>
      </CardContent>
    </Card>
  );
}

