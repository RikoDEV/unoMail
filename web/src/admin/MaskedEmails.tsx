import { Alert, Autocomplete, Box, Button, FormControlLabel, Stack, Switch, TextField, Typography } from '@mui/material';
import { useState } from 'react';
import { get, put } from '../lib/api';
import { useAuth } from '../app';
import { t } from '../i18n';
import { MaskedAddresses } from '../settings/MaskedEmail';
import { PageHeader, useAction, useLoad } from './common';

function AccountPolicy({ id, onSaved }: { id: number; onSaved: () => void }) {
  const current = useLoad(() => get<{ max_masks: number | null; extra_domains: string[] }>(`/api/accounts/${id}/masked-policy`), [id]);
  const [limit, setLimit] = useState<string | null>(null);
  const [domains, setDomains] = useState<string | null>(null);
  const { run, feedback } = useAction();
  return <Stack spacing={1} sx={{ mb: 3 }}>
    {feedback}{current.error && <Alert severity="error">{current.error}</Alert>}
    <Stack direction="row" spacing={2} flexWrap="wrap" useFlexGap>
      <TextField label={t('Mask quota override')} type="number" value={limit ?? current.data?.max_masks ?? ''} onChange={(e) => setLimit(e.target.value)} helperText={t('Blank inherits the server limit; zero disables creation.')} />
      <TextField label={t('Additional mask domains')} value={domains ?? current.data?.extra_domains.join(', ') ?? ''} onChange={(e) => setDomains(e.target.value)} helperText={t('Comma-separated hosted domains this mailbox may use.')} />
      <Button disabled={!current.data} onClick={() => void run(() => put(`/api/accounts/${id}/masked-policy`, { max_masks: (limit ?? current.data?.max_masks ?? '') === '' ? null : Number(limit ?? current.data?.max_masks), extra_domains: (domains ?? current.data?.extra_domains.join(',') ?? '').split(',').map((s) => s.trim()).filter(Boolean) }), t('Settings saved')).then((ok) => { if (ok) { void current.reload(); onSaved(); } })}>{t('Save')}</Button>
    </Stack>
  </Stack>;
}
function ServerPolicy() {
  const current = useLoad(() => get<{ enabled: boolean; default_limit: number; disabled_domains: string[] }>('/api/masked-email/config'), []);
  const domains = useLoad(() => get<{ name: string }[]>('/api/domains'), []);
  const [draft, setDraft] = useState<typeof current.data>(null);
  const { run, feedback } = useAction();
  const value = draft ?? current.data;
  if (!value) return current.error ? <Alert severity="error">{current.error}</Alert> : null;
  return <Box component="section" aria-label={t('Masked address policy')} sx={{ mb: 3 }}>
    <Typography variant="h6">{t('Masked address policy')}</Typography>{feedback}
    <Stack spacing={1} alignItems="flex-start">
      <FormControlLabel control={<Switch checked={value.enabled} onChange={(e) => setDraft({ ...value, enabled: e.target.checked })} />} label={t('Allow new masked addresses')} />
      <TextField type="number" label={t('Default mask quota')} value={value.default_limit} onChange={(e) => setDraft({ ...value, default_limit: Number(e.target.value) })} />
      {/* Hosted domains to pick from; a closed domain since removed stays listed so it can be cleared. */}
      <Autocomplete
        multiple
        filterSelectedOptions
        options={[...new Set([...(domains.data ?? []).map((d) => d.name), ...value.disabled_domains])]}
        value={value.disabled_domains}
        onChange={(_, picked) => setDraft({ ...value, disabled_domains: picked })}
        sx={{ minWidth: 320 }}
        renderInput={(params) => <TextField {...params} label={t('Domains closed to new masks')} helperText={t('Creation policy does not disable existing active addresses.')} />}
      />
      <Button disabled={!draft} variant="outlined" onClick={() => void run(() => put('/api/masked-email/config', { ...value, disabled_domains: value.disabled_domains.filter(Boolean) }), t('Settings saved')).then((ok) => { if (ok) { setDraft(null); void current.reload(); } })}>{t('Save')}</Button>
    </Stack>
  </Box>;
}
export function MaskedEmails() {
  const { account } = useAuth();
  const [email, setEmail] = useState('');
  const [target, setTarget] = useState<{ id: number; email: string } | null>(null);
  const [version, setVersion] = useState(0);
  const { run, feedback } = useAction();
  return <>
    <PageHeader title={t('Masked addresses')} />
    {account?.role === 'super_admin' && <ServerPolicy />}
    {feedback}
    <Stack direction="row" spacing={1} sx={{ mb: 2 }}><TextField label={t('Mailbox address')} value={email} onChange={(e) => setEmail(e.target.value)} /><Button onClick={() => void run(async () => { const result = await get<{ items: { id: number; email: string }[] }>(`/api/accounts?q=${encodeURIComponent(email)}&limit=100`); const found = result.items.find((a) => a.email.toLowerCase() === email.trim().toLowerCase()); if (!found) throw new Error(t('Mailbox not found')); setTarget(found); })}>{t('Load mailbox')}</Button></Stack>
    {target && <Box key={target.id}><Typography variant="h6" sx={{ mb: 2 }}>{target.email}</Typography><AccountPolicy id={target.id} onSaved={() => setVersion((v) => v + 1)} /><MaskedAddresses key={`${target.id}-${version}`} accountId={target.id} /></Box>}
  </>;
}
