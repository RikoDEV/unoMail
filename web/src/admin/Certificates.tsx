import Autorenew from '@mui/icons-material/Autorenew';
import UploadFile from '@mui/icons-material/UploadFile';
import { Alert, Box, Button, Card, CardContent, Chip, MenuItem, Stack, Tab, Tabs, TextField, Typography } from '@mui/material';
import { useEffect, useState } from 'react';
import { get, post, put } from '../api';
import { ConfirmDialog, PageHeader, useAction, useLoad } from './common';

import { t, uiLocale } from '../i18n';
interface TlsStatus {
  certificate: { kind: string; domains: string[]; issuer: string; not_before: number; not_after: number; seconds_remaining: number; expires_soon: boolean; covers_hostname: boolean };
  hostname: string;
  mode: 'acme' | 'custom' | 'self_signed';
  acme: { domains: string[]; email: string; challenge: string; has_cloudflare_token: boolean } | null;
  acme_last_error: string | null;
  issued?: boolean;
  warnings?: string[];
}

interface Validation {
  valid: boolean;
  error?: string;
  domains?: string[];
  issuer?: string;
  not_after?: number;
  warnings?: string[];
}

/** Live "expires in" countdown. */
function Countdown({ notAfter }: { notAfter: number }) {
  const [now, setNow] = useState(Date.now() / 1000);
  useEffect(() => {
    const timer = setInterval(() => setNow(Date.now() / 1000), 1000);
    return () => clearInterval(timer);
  }, []);
  const remaining = Math.max(0, Math.floor(notAfter - now));
  const days = Math.floor(remaining / 86400);
  const pad = (n: number) => String(n).padStart(2, '0');
  return (
    <Typography variant="h4" component="div" aria-label={t('Time until expiry')} color={days < 14 ? 'error' : days < 30 ? 'warning.main' : 'text.primary'}>
      {days}d {pad(Math.floor((remaining % 86400) / 3600))}:{pad(Math.floor((remaining % 3600) / 60))}:{pad(remaining % 60)}
    </Typography>
  );
}

async function readFile(file: File | undefined): Promise<string | null> {
  if (!file) return null;
  if (file.size > 64 * 1024) throw new Error(t('The file is too large to be a certificate or key.'));
  return file.text();
}

export function Certificates() {
  const { data, error, reload } = useLoad(() => get<TlsStatus>('/api/tls'), []);
  const { run, feedback, setError } = useAction();
  const [tab, setTab] = useState<'acme' | 'custom'>('acme');
  const [domains, setDomains] = useState('');
  const [email, setEmail] = useState('');
  const [challenge, setChallenge] = useState('http-01');
  const [token, setToken] = useState('');
  const [certPem, setCertPem] = useState('');
  const [keyPem, setKeyPem] = useState('');
  const [validation, setValidation] = useState<Validation | null>(null);
  const [busy, setBusy] = useState(false);
  const [warnings, setWarnings] = useState<string[]>([]);
  const [confirmReset, setConfirmReset] = useState(false);

  useEffect(() => {
    if (!data) return;
    setTab(data.mode === 'custom' ? 'custom' : 'acme');
    setDomains((data.acme?.domains ?? [data.hostname]).join(', '));
    setEmail(data.acme?.email ?? '');
    setChallenge(data.acme?.challenge ?? 'http-01');
    // Only initialise the form once per load of the status.
  }, [data?.mode, data?.hostname]);

  if (error) return <Alert severity="error">{error}</Alert>;
  if (!data) return null;
  const cert = data.certificate;

  async function withBusy(action: () => Promise<void>) {
    setBusy(true);
    try {
      await action();
    } finally {
      setBusy(false);
    }
  }

  const requestAcme = () =>
    withBusy(async () => {
      let result: TlsStatus | undefined;
      const body = { domains: domains.split(',').map((d) => d.trim()).filter(Boolean), email: email.trim(), challenge, ...(token ? { cloudflare_token: token } : {}) };
      const ok = await run(async () => {
        result = await put<TlsStatus>('/api/tls/acme', body);
      });
      setToken('');
      await reload();
      if (ok && result && !result.issued) setError(t('The certificate could not be issued: {{reason}}. The current certificate stays active and the request is retried automatically.', { reason: result.acme_last_error ?? t('unknown error') }));
      else if (ok) await run(async () => {}, t('Certificate issued and activated'));
    });

  const renew = () =>
    withBusy(async () => {
      let result: TlsStatus | undefined;
      const ok = await run(async () => {
        result = await post<TlsStatus>('/api/tls/acme/renew');
      });
      await reload();
      if (ok && result && !result.issued) setError(t('Renewal failed: {{reason}}', { reason: result.acme_last_error ?? t('unknown error') }));
      else if (ok) await run(async () => {}, t('Certificate renewed'));
    });

  const validate = () =>
    withBusy(async () => {
      setValidation(null);
      await run(async () => setValidation(await post<Validation>('/api/tls/validate', { cert_pem: certPem, key_pem: keyPem })));
    });

  const install = () =>
    withBusy(async () => {
      let result: TlsStatus | undefined;
      const ok = await run(async () => {
        result = await put<TlsStatus>('/api/tls/custom', { cert_pem: certPem, key_pem: keyPem });
      }, t('Certificate installed and active on all services'));
      if (ok) {
        setWarnings(result?.warnings ?? []);
        setCertPem('');
        setKeyPem('');
        setValidation(null);
        await reload();
      }
    });

  return (
    <>
      <PageHeader title={t('TLS certificates')} />
      {feedback}
      <Card variant="outlined" sx={{ mb: 3 }}>
        <CardContent>
          <Stack direction="row" spacing={4} flexWrap="wrap" useFlexGap alignItems="center">
            <Box>
              <Typography variant="body2" color="text.secondary">
                {t('Active certificate expires in')}
              </Typography>
              <Countdown notAfter={cert.not_after} />
              <Typography variant="caption" color="text.secondary">
                {new Date(cert.not_after * 1000).toLocaleString(uiLocale())}
              </Typography>
            </Box>
            <Box sx={{ flex: 1, minWidth: 260 }}>
              <Stack direction="row" spacing={1} sx={{ mb: 1 }} flexWrap="wrap" useFlexGap>
                <Chip label={data.mode === 'acme' ? t("Let's Encrypt (automatic)") : data.mode === 'custom' ? t('Custom certificate') : t('Self-signed')} color={data.mode === 'self_signed' ? 'warning' : 'success'} data-testid="tls-mode" />
                {!cert.covers_hostname && <Chip label={t('not valid for {{hostname}}', { hostname: data.hostname })} color="error" />}
                {cert.expires_soon && <Chip label={t('expires soon')} color="warning" />}
              </Stack>
              <Typography variant="body2">{t('Names:')} {cert.domains.join(', ') || t('(none)')}</Typography>
              <Typography variant="body2" color="text.secondary" sx={{ wordBreak: 'break-all' }}>
                {t('Issuer: {{issuer}}', { issuer: cert.issuer })}
              </Typography>
            </Box>
            {data.mode === 'acme' && (
              <Button variant="outlined" startIcon={<Autorenew />} disabled={busy} onClick={() => void renew()}>
                {t('Renew now')}
              </Button>
            )}
          </Stack>
        </CardContent>
      </Card>
      {data.acme_last_error && data.mode === 'acme' && (
        <Alert severity="warning" sx={{ mb: 2 }}>
          {t('Last automatic request failed: {{acme_last_error}}', { acme_last_error: data.acme_last_error })}
        </Alert>
      )}
      {warnings.map((warning) => (
        <Alert key={warning} severity="warning" sx={{ mb: 1 }} onClose={() => setWarnings((w) => w.filter((x) => x !== warning))}>
          {warning}
        </Alert>
      ))}

      <Tabs value={tab} onChange={(_, value) => setTab(value)} sx={{ mb: 2 }}>
        <Tab value="acme" label={t("Automated (Let's Encrypt)")} />
        <Tab value="custom" label={t('Custom certificate')} />
      </Tabs>

      {tab === 'acme' && (
        <Stack spacing={2} sx={{ maxWidth: 560 }}>
          <Typography variant="body2" color="text.secondary">
            {t('Certificates are requested automatically, renewed 30 days before expiry and activated on every service without a restart.')}
          </Typography>
          <TextField label={t('Domain names')} value={domains} onChange={(e) => setDomains(e.target.value)} helperText={t('Comma separated; each must point to this server')} />
          <TextField label={t('Contact e-mail')} type="email" value={email} onChange={(e) => setEmail(e.target.value)} helperText={t('Used by the certificate authority for expiry notices')} />
          <TextField select label={t('Validation method')} value={challenge} onChange={(e) => setChallenge(e.target.value)}>
            <MenuItem value="http-01">{t('HTTP-01 (port 80 must be reachable)')}</MenuItem>
            <MenuItem value="dns-01">{t('DNS-01 via Cloudflare (supports wildcards)')}</MenuItem>
          </TextField>
          {challenge === 'dns-01' && (
            <TextField
              label={t('Cloudflare API token')}
              type="password"
              autoComplete="off"
              value={token}
              onChange={(e) => setToken(e.target.value)}
              helperText={data.acme?.has_cloudflare_token ? t('A token is stored. Leave empty to keep it.') : t('Token with DNS edit permission for the zone')}
            />
          )}
          <Box>
            <Button variant="contained" disabled={busy || !domains.trim() || !email.trim()} onClick={() => void requestAcme()}>
              {busy ? t('Requesting…') : t('Save and request certificate')}
            </Button>
          </Box>
        </Stack>
      )}

      {tab === 'custom' && (
        <Stack spacing={2} sx={{ maxWidth: 720 }}>
          <Typography variant="body2" color="text.secondary">
            {t('Installing a custom certificate turns automatic issuance off. The private key is stored on the server and can never be read back.')}
          </Typography>
          <Stack direction="row" spacing={1} alignItems="flex-start">
            <TextField label={t('Certificate chain (PEM)')} value={certPem} onChange={(e) => { setCertPem(e.target.value); setValidation(null); }} multiline minRows={5} maxRows={10} fullWidth placeholder="-----BEGIN CERTIFICATE-----" slotProps={{ htmlInput: { spellCheck: false, style: { fontFamily: 'monospace', fontSize: 12 } } }} />
            <Button component="label" startIcon={<UploadFile />} sx={{ whiteSpace: 'nowrap' }}>
              {t('Upload')}
              <input type="file" hidden accept=".pem,.crt,.cer" aria-label={t('Certificate file')} onChange={(e) => void run(async () => { const text = await readFile(e.target.files?.[0]); if (text) { setCertPem(text); setValidation(null); } })} />
            </Button>
          </Stack>
          <Stack direction="row" spacing={1} alignItems="flex-start">
            <TextField label={t('Private key (PEM)')} value={keyPem} onChange={(e) => { setKeyPem(e.target.value); setValidation(null); }} multiline minRows={4} maxRows={8} fullWidth placeholder="-----BEGIN PRIVATE KEY-----" slotProps={{ htmlInput: { spellCheck: false, autoComplete: 'off', style: { fontFamily: 'monospace', fontSize: 12 } } }} />
            <Button component="label" startIcon={<UploadFile />} sx={{ whiteSpace: 'nowrap' }}>
              {t('Upload')}
              <input type="file" hidden accept=".pem,.key" aria-label={t('Private key file')} onChange={(e) => void run(async () => { const text = await readFile(e.target.files?.[0]); if (text) { setKeyPem(text); setValidation(null); } })} />
            </Button>
          </Stack>
          {validation && !validation.valid && <Alert severity="error">{validation.error}</Alert>}
          {validation?.valid && (
            <Alert severity={validation.warnings?.length ? 'warning' : 'success'}>
              {t('Valid for {{names}} until {{date}}.', { names: validation.domains?.join(', ') || t('(no names)'), date: new Date((validation.not_after ?? 0) * 1000).toLocaleDateString(uiLocale()) })}
              {validation.warnings?.map((w) => (
                <div key={w}>• {w}</div>
              ))}
            </Alert>
          )}
          <Stack direction="row" spacing={1}>
            <Button variant="outlined" disabled={busy || !certPem || !keyPem} onClick={() => void validate()}>
              {t('Validate')}
            </Button>
            <Button variant="contained" disabled={busy || !certPem || !keyPem} onClick={() => void install()}>
              {t('Install certificate')}
            </Button>
          </Stack>
        </Stack>
      )}

      {data.mode !== 'self_signed' && (
        <Box sx={{ mt: 4 }}>
          <Button color="error" onClick={() => setConfirmReset(true)}>
            {t('Revert to a self-signed certificate')}
          </Button>
        </Box>
      )}
      <ConfirmDialog
        open={confirmReset}
        title={t('Revert to self-signed?')}
        text={t('Mail clients and browsers will show certificate warnings until a trusted certificate is installed again.')}
        confirmLabel={t('Revert')}
        onClose={() => setConfirmReset(false)}
        onConfirm={async () => {
          setConfirmReset(false);
          if (await run(() => post('/api/tls/self-signed'), t('Self-signed certificate active'))) await reload();
        }}
      />
    </>
  );
}
