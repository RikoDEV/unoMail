// Administration of everything that connects the server to its surroundings: single sign-on,
// the LDAP directory, webhooks, skins, and plug-in and theme packages.

import Delete from '@mui/icons-material/Delete';
import { Alert, Box, Button, Card, CardContent, Checkbox, FormControlLabel, IconButton, Stack, Switch, TableBody, TableCell, TableHead, TableRow, TextField, Tooltip, Typography } from '@mui/material';
import { useEffect, useState } from 'react';
import { del, formatTime, get, post, put, errorText } from '../lib/api';
import { useAppearance } from '../app';
import { BUILT_IN_SKINS } from '../ui/skins';
import { PageHeader, useAction, useLoad, ScrollTable } from './common';
import { Packages } from './Packages';

import { t } from '../i18n';
// --- Single sign-on ------------------------------------------------------------------------

interface OauthView {
  enabled: boolean;
  name?: string;
  issuer?: string;
  client_id?: string;
  scopes?: string;
  require_verified_email?: boolean;
  has_secret?: boolean;
  redirect_uri: string;
}

function SingleSignOn() {
  const { run, feedback } = useAction();
  const [config, setConfig] = useState<OauthView | null>(null);
  const [secret, setSecret] = useState('');
  useEffect(() => {
    get<OauthView>('/api/oauth').then(setConfig).catch(() => {});
  }, []);
  if (!config) return null;
  const set = (changes: Partial<OauthView>) => setConfig({ ...config, ...changes });
  const save = () =>
    run(async () => {
      const body = {
        enabled: config.enabled,
        name: config.name || 'Single sign-on',
        issuer: config.issuer ?? '',
        client_id: config.client_id ?? '',
        scopes: config.scopes || 'openid email profile',
        require_verified_email: config.require_verified_email ?? true,
        ...(secret ? { secret } : {}),
      };
      setConfig(await put<OauthView>('/api/oauth', body));
      setSecret('');
    }, t('Single sign-on settings saved'));
  return (
    <Card variant="outlined">
      <CardContent>
        <Typography variant="h6">{t('Single sign-on (OpenID Connect)')}</Typography>
        <Typography variant="body2" sx={{ color: 'text.secondary', mb: 2 }}>
          {t('Lets users sign in through your identity provider, in the browser and (with XOAUTH2 / OAUTHBEARER) in mail programs. An identity is matched to an existing mailbox by its verified e-mail address; mailboxes are never created automatically.')}
        </Typography>
        {feedback}
        <Stack spacing={2} sx={{ maxWidth: 640 }}>
          <FormControlLabel control={<Switch checked={config.enabled} onChange={(e) => set({ enabled: e.target.checked })} />} label={t('Enable single sign-on')} />
          <TextField label={t('Issuer URL')} value={config.issuer ?? ''} onChange={(e) => set({ issuer: e.target.value })} placeholder="https://id.example.org/realms/company" />
          <Stack direction="row" spacing={2}>
            <TextField label={t('Client ID')} value={config.client_id ?? ''} onChange={(e) => set({ client_id: e.target.value })} fullWidth />
            <TextField label={t('Client secret')} type="password" autoComplete="new-password" value={secret} onChange={(e) => setSecret(e.target.value)} fullWidth helperText={config.has_secret ? t('Leave empty to keep the stored secret') : ''} />
          </Stack>
          <Stack direction="row" spacing={2}>
            <TextField label={t('Button label')} value={config.name ?? ''} onChange={(e) => set({ name: e.target.value })} fullWidth />
            <TextField label={t('Scopes')} value={config.scopes ?? 'openid email profile'} onChange={(e) => set({ scopes: e.target.value })} fullWidth />
          </Stack>
          <FormControlLabel
            control={<Checkbox checked={config.require_verified_email ?? true} onChange={(e) => set({ require_verified_email: e.target.checked })} />}
            label={t('Only accept addresses the provider reports as verified')}
          />
          <TextField label={t('Redirect URI to register with the provider')} value={config.redirect_uri} slotProps={{ htmlInput: { readOnly: true } }} />
          <Box>
            <Button variant="contained" onClick={() => void save()} disabled={!config.issuer?.trim() || !config.client_id?.trim()}>
              {t('Save single sign-on')}
            </Button>
          </Box>
        </Stack>
      </CardContent>
    </Card>
  );
}

// --- LDAP ----------------------------------------------------------------------------------

interface LdapView {
  enabled: boolean;
  url: string;
  starttls: boolean;
  bind_dn: string;
  base_dn: string;
  filter: string;
  name_attribute: string;
  mail_attribute: string;
  has_password?: boolean;
}

const LDAP_DEFAULTS: LdapView = { enabled: false, url: '', starttls: false, bind_dn: '', base_dn: '', filter: '(&(mail=*)(|(cn=*{q}*)(mail=*{q}*)))', name_attribute: 'cn', mail_attribute: 'mail' };

function Ldap() {
  const { run, feedback, setError } = useAction();
  const [config, setConfig] = useState<LdapView | null>(null);
  const [password, setPassword] = useState('');
  const [query, setQuery] = useState('');
  const [found, setFound] = useState<{ name: string; email: string }[] | null>(null);
  useEffect(() => {
    get<LdapView | null>('/api/ldap').then((stored) => setConfig(stored ?? LDAP_DEFAULTS)).catch(() => {});
  }, []);
  if (!config) return null;
  const set = (changes: Partial<LdapView>) => setConfig({ ...config, ...changes });
  const body = () => {
    const { has_password: _ignored, ...rest } = config;
    return { ...rest, ...(password ? { password } : {}) };
  };
  const save = () =>
    run(async () => {
      setConfig(await put<LdapView>('/api/ldap', body()));
      setPassword('');
    }, t('Directory settings saved'));
  async function test() {
    setFound(null);
    try {
      const result = await post<{ ok: boolean; error?: string; entries?: { name: string; email: string }[] }>('/api/ldap/test', { ...body(), query });
      if (result.ok) setFound(result.entries ?? []);
      else setError(result.error ?? t('The directory search failed'));
    } catch (err) {
      setError(errorText(err, t('The directory search failed')));
    }
  }
  return (
    <Card variant="outlined">
      <CardContent>
        <Typography variant="h6">{t('LDAP directory')}</Typography>
        <Typography variant="body2" sx={{ color: 'text.secondary', mb: 2 }}>
          {t('Recipient suggestions in the composer are also looked up in this directory.')}
        </Typography>
        {feedback}
        <Stack spacing={2} sx={{ maxWidth: 640 }}>
          <FormControlLabel control={<Switch checked={config.enabled} onChange={(e) => set({ enabled: e.target.checked })} />} label={t('Use the directory for recipient suggestions')} />
          <Stack direction="row" spacing={2} sx={{ alignItems: 'center' }}>
            <TextField label={t('Directory URL')} value={config.url} onChange={(e) => set({ url: e.target.value })} placeholder="ldaps://ldap.example.org" fullWidth />
            <FormControlLabel control={<Checkbox checked={config.starttls} onChange={(e) => set({ starttls: e.target.checked })} />} label={t('StartTLS')} />
          </Stack>
          <TextField label={t('Base DN')} value={config.base_dn} onChange={(e) => set({ base_dn: e.target.value })} placeholder="ou=people,dc=example,dc=org" />
          <Stack direction="row" spacing={2}>
            <TextField label={t('Bind DN')} value={config.bind_dn} onChange={(e) => set({ bind_dn: e.target.value })} fullWidth helperText={t('Empty for an anonymous search')} />
            <TextField label={t('Bind password')} type="password" autoComplete="new-password" value={password} onChange={(e) => setPassword(e.target.value)} fullWidth helperText={config.has_password ? t('Leave empty to keep the stored password') : ''} />
          </Stack>
          <TextField label={t('Search filter')} value={config.filter} onChange={(e) => set({ filter: e.target.value })} helperText="{q} is replaced by the (escaped) text being typed" />
          <Stack direction="row" spacing={2}>
            <TextField label={t('Name attribute')} value={config.name_attribute} onChange={(e) => set({ name_attribute: e.target.value })} fullWidth />
            <TextField label={t('Mail attribute')} value={config.mail_attribute} onChange={(e) => set({ mail_attribute: e.target.value })} fullWidth />
          </Stack>
          <Stack direction="row" spacing={1} sx={{ alignItems: 'flex-start' }}>
            <Button variant="contained" onClick={() => void save()} disabled={!config.url.trim() || !config.base_dn.trim()}>
              {t('Save directory')}
            </Button>
            <TextField label={t('Test search')} value={query} onChange={(e) => setQuery(e.target.value)} />
            <Button onClick={() => void test()} disabled={!query.trim() || !config.url.trim()}>
              {t('Test')}
            </Button>
          </Stack>
          {found && (
            <Alert severity={found.length ? 'success' : 'info'}>
              {found.length ? found.map((entry) => `${entry.name} <${entry.email}>`).join(', ') : t('The directory answered, but nothing matched.')}
            </Alert>
          )}
        </Stack>
      </CardContent>
    </Card>
  );
}

// --- Webhooks ------------------------------------------------------------------------------

interface Webhook {
  id: number;
  url: string;
  events: string[];
  enabled: boolean;
  last_status: string;
  last_at: number | null;
}

function Webhooks() {
  const { run, feedback } = useAction();
  const { data, reload } = useLoad(() => get<{ webhooks: Webhook[]; events: string[] }>('/api/webhooks'), []);
  const [url, setUrl] = useState('');
  const [events, setEvents] = useState<string[]>(['message.received']);
  const [secret, setSecret] = useState('');
  const create = () =>
    run(async () => {
      const created = await post<{ secret: string }>('/api/webhooks', { url, events });
      setSecret(created.secret);
      setUrl('');
      await reload();
    }, t('Webhook created'));
  return (
    <Card variant="outlined">
      <CardContent>
        <Typography variant="h6">{t('Webhooks')}</Typography>
        <Typography variant="body2" sx={{ color: 'text.secondary', mb: 2 }}>
          {t('Other systems are notified of mail events with a signed JSON request (header X-Unomail-Signature, HMAC-SHA256 of the body). Notifications carry addresses and sizes, never message content.')}
        </Typography>
        {feedback}
        {secret && (
          <Alert severity="warning" onClose={() => setSecret('')} sx={{ mb: 2 }}>
            {t('Signing secret (shown only once):')} <code data-testid="webhook-secret">{secret}</code>
          </Alert>
        )}
        <Stack spacing={2}>
          <Stack direction="row" spacing={2} useFlexGap sx={{ alignItems: 'flex-start', flexWrap: 'wrap' }}>
            <TextField label={t('Webhook URL')} value={url} onChange={(e) => setUrl(e.target.value)} placeholder="https://hooks.example.org/unomail" sx={{ minWidth: 320, flex: 1 }} />
            <Button variant="contained" onClick={() => void create()} disabled={!url.trim() || events.length === 0}>
              {t('Add webhook')}
            </Button>
          </Stack>
          <Stack direction="row" useFlexGap spacing={1} sx={{ flexWrap: 'wrap' }}>
            {(data?.events ?? []).map((event) => (
              <FormControlLabel key={event} label={event} control={<Checkbox size="small" checked={events.includes(event)} onChange={(e) => setEvents((current) => (e.target.checked ? [...current, event] : current.filter((x) => x !== event)))} />} />
            ))}
          </Stack>
          {(data?.webhooks.length ?? 0) > 0 && (
            <ScrollTable size="small" aria-label={t('Webhooks')}>
              <TableHead>
                <TableRow>
                  <TableCell>URL</TableCell>
                  <TableCell>{t('Events')}</TableCell>
                  <TableCell>{t('Last delivery')}</TableCell>
                  <TableCell />
                </TableRow>
              </TableHead>
              <TableBody>
                {data!.webhooks.map((hook) => (
                  <TableRow key={hook.id}>
                    <TableCell sx={{ wordBreak: 'break-all' }}>{hook.url}</TableCell>
                    <TableCell>{hook.events.join(', ')}</TableCell>
                    <TableCell>{hook.last_at ? `${hook.last_status} (${formatTime(hook.last_at)})` : t('Never')}</TableCell>
                    <TableCell align="right" sx={{ whiteSpace: 'nowrap' }}>
                      <Button size="small" onClick={() => void run(async () => { await post(`/api/webhooks/${hook.id}/test`); await reload(); }, t('Test event sent'))}>
                        {t('Test')}
                      </Button>
                      <Tooltip title={t('Delete webhook')}>
                        <IconButton size="small" aria-label={t('Delete webhook {{url}}', { url: hook.url })} onClick={() => void run(async () => { await del(`/api/webhooks/${hook.id}`); await reload(); }, t('Webhook deleted'))}>
                          <Delete fontSize="small" />
                        </IconButton>
                      </Tooltip>
                    </TableCell>
                  </TableRow>
                ))}
              </TableBody>
            </ScrollTable>
          )}
        </Stack>
      </CardContent>
    </Card>
  );
}

// --- Skins ---------------------------------------------------------------------------------

const SKIN_EXAMPLE = JSON.stringify([{ id: 'ocean', name: 'Ocean', mode: 'dark', primary: '#4fc3f7', background: '#0a1929', paper: '#102a43', radius: 8, density: 'compact', font: 'system' }], null, 2);

function Skins() {
  const { run, feedback, setError } = useAction();
  const { reloadSkins } = useAppearance();
  const [text, setText] = useState('');
  useEffect(() => {
    get<unknown[]>('/api/skins').then((skins) => setText(JSON.stringify(skins, null, 2))).catch(() => {});
  }, []);
  async function save() {
    let parsed: unknown;
    try {
      parsed = JSON.parse(text || '[]');
    } catch {
      setError(t('The skins are not valid JSON'));
      return;
    }
    await run(async () => {
      await put('/api/skins', parsed);
      await reloadSkins();
    }, t('Skins saved'));
  }
  return (
    <Card variant="outlined">
      <CardContent>
        <Typography variant="h6">{t('Custom skins')}</Typography>
        <Typography variant="body2" sx={{ color: 'text.secondary', mb: 2 }}>
          {t('Skins are sets of design tokens, in addition to the built-in ones ({{value}}). Users pick a skin in their settings. Allowed properties: id, name, mode (light, dark, auto), primary, secondary, background, paper, text (#rrggbb), radius (0 to 32), density (comfortable, compact) and font (roboto, system, serif, mono).', { value: BUILT_IN_SKINS.map((skin) => skin.name).join(', ') })}
        </Typography>
        {feedback}
        <Stack spacing={2}>
          <TextField label={t('Skins (JSON)')} value={text} onChange={(e) => setText(e.target.value)} multiline minRows={6} maxRows={20} slotProps={{ htmlInput: { spellCheck: false, style: { fontFamily: 'monospace', fontSize: 13 } } }} />
          <Stack direction="row" spacing={1}>
            <Button variant="contained" onClick={() => void save()}>
              {t('Save skins')}
            </Button>
            <Button onClick={() => setText(SKIN_EXAMPLE)}>{t('Insert an example')}</Button>
          </Stack>
        </Stack>
      </CardContent>
    </Card>
  );
}

export function Integrations() {
  return (
    <>
      <PageHeader title={t('Integrations')} />
      <Stack spacing={3}>
        <SingleSignOn />
        <Ldap />
        <Webhooks />
        <Packages />
        <Skins />
      </Stack>
    </>
  );
}
