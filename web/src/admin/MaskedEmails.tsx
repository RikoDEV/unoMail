import Search from '@mui/icons-material/Search';
import { Alert, Autocomplete, Box, Button, Card, CardContent, Divider, FormControlLabel, Stack, Switch, TextField, Typography } from '@mui/material';
import { type ReactNode, useState } from 'react';
import { get, put } from '../lib/api';
import { useAuth } from '../app';
import { t } from '../i18n';
import { MaskedAddresses } from '../settings/MaskedEmail';
import { PageHeader, useAction, useLoad } from './common';

/** One titled card of the page, so each group of settings reads as a unit. */
function Section({ title, text, children }: { title: string; text?: string; children: ReactNode }) {
  return (
    <Card variant="outlined" component="section" aria-label={title}>
      <CardContent>
        <Typography variant="h6" component="h2">{title}</Typography>
        {text && <Typography variant="body2" sx={{ color: 'text.secondary', mb: 2 }}>{text}</Typography>}
        {children}
      </CardContent>
    </Card>
  );
}

/** A heading with a line of explanation inside a section. */
function SubHeading({ title, text }: { title: string; text?: string }) {
  return (
    <Box sx={{ mb: 1.5 }}>
      <Typography variant="subtitle1" component="h4" sx={{ fontWeight: 600 }}>{title}</Typography>
      {text && <Typography variant="body2" sx={{ color: 'text.secondary' }}>{text}</Typography>}
    </Box>
  );
}

function AccountPolicy({ id, onSaved }: { id: number; onSaved: () => void }) {
  const current = useLoad(() => get<{ max_masks: number | null; extra_domains: string[] }>(`/api/accounts/${id}/masked-policy`), [id]);
  const [limit, setLimit] = useState<string | null>(null);
  const [domains, setDomains] = useState<string | null>(null);
  const { run, feedback } = useAction();
  const save = () => void run(() => put(`/api/accounts/${id}/masked-policy`, {
    max_masks: (limit ?? current.data?.max_masks ?? '') === '' ? null : Number(limit ?? current.data?.max_masks),
    extra_domains: (domains ?? current.data?.extra_domains.join(',') ?? '').split(',').map((s) => s.trim()).filter(Boolean),
  }), t('Settings saved')).then((ok) => { if (ok) { void current.reload(); onSaved(); } });
  return (
    <Box>
      <SubHeading title={t('Limits for this mailbox')} text={t('These override the server policy for this mailbox only.')} />
      {feedback}{current.error && <Alert severity="error" sx={{ mb: 2 }}>{current.error}</Alert>}
      <Stack direction={{ xs: 'column', sm: 'row' }} spacing={2} useFlexGap sx={{ alignItems: { sm: 'flex-start' } }}>
        <TextField label={t('Mask quota override')} type="number" value={limit ?? current.data?.max_masks ?? ''} onChange={(e) => setLimit(e.target.value)} helperText={t('Blank inherits the server limit; zero disables creation.')} sx={{ flex: 1 }} />
        <TextField label={t('Additional mask domains')} value={domains ?? current.data?.extra_domains.join(', ') ?? ''} onChange={(e) => setDomains(e.target.value)} helperText={t('Comma-separated hosted domains this mailbox may use.')} sx={{ flex: 2 }} />
      </Stack>
      <Button variant="contained" sx={{ mt: 1 }} disabled={!current.data} onClick={save}>{t('Save')}</Button>
    </Box>
  );
}

function ServerPolicy() {
  const current = useLoad(() => get<{ enabled: boolean; default_limit: number; disabled_domains: string[] }>('/api/masked-email/config'), []);
  const domains = useLoad(() => get<{ name: string }[]>('/api/domains'), []);
  const [draft, setDraft] = useState<typeof current.data>(null);
  const { run, feedback } = useAction();
  const value = draft ?? current.data;
  if (!value) return current.error ? <Alert severity="error">{current.error}</Alert> : null;
  return (
    <Section title={t('Masked address policy')} text={t('Applies to every mailbox unless a mailbox has its own limits. Creation policy does not disable existing active addresses.')}>
      {feedback}
      <FormControlLabel control={<Switch checked={value.enabled} onChange={(e) => setDraft({ ...value, enabled: e.target.checked })} />} label={t('Allow new masked addresses')} sx={{ mb: 2 }} />
      <Stack direction={{ xs: 'column', sm: 'row' }} spacing={2} useFlexGap sx={{ alignItems: { sm: 'flex-start' } }}>
        <TextField type="number" label={t('Default mask quota')} value={value.default_limit} onChange={(e) => setDraft({ ...value, default_limit: Number(e.target.value) })} helperText={t('How many masked addresses each mailbox may have.')} sx={{ flex: 1 }} />
        {/* Hosted domains to pick from; a closed domain since removed stays listed so it can be cleared. */}
        <Autocomplete
          multiple
          filterSelectedOptions
          options={[...new Set([...(domains.data ?? []).map((d) => d.name), ...value.disabled_domains])]}
          value={value.disabled_domains}
          onChange={(_, picked) => setDraft({ ...value, disabled_domains: picked })}
          sx={{ flex: 2, minWidth: 0 }}
          renderInput={(params) => <TextField {...params} label={t('Domains closed to new masks')} helperText={t('No new masked addresses can be created on these domains.')} />}
        />
      </Stack>
      <Button disabled={!draft} variant="contained" sx={{ mt: 1 }} onClick={() => void run(() => put('/api/masked-email/config', { ...value, disabled_domains: value.disabled_domains.filter(Boolean) }), t('Settings saved')).then((ok) => { if (ok) { setDraft(null); void current.reload(); } })}>{t('Save')}</Button>
    </Section>
  );
}

export function MaskedEmails() {
  const { account } = useAuth();
  const [email, setEmail] = useState('');
  const [target, setTarget] = useState<{ id: number; email: string } | null>(null);
  const [version, setVersion] = useState(0);
  const { run, feedback } = useAction();
  const load = () => void run(async () => {
    const result = await get<{ items: { id: number; email: string }[] }>(`/api/accounts?q=${encodeURIComponent(email)}&limit=100`);
    const found = result.items.find((a) => a.email.toLowerCase() === email.trim().toLowerCase());
    if (!found) throw new Error(t('Mailbox not found'));
    setTarget(found);
  });
  return (
    <>
      <PageHeader title={t('Masked addresses')} />
      <Stack spacing={3}>
        {account?.role === 'super_admin' && <ServerPolicy />}
        <Section title={t('Mailbox')} text={t('Look up a mailbox to change its limits and manage its masked addresses.')}>
          {feedback}
          <Stack component="form" direction="row" spacing={1} sx={{ alignItems: 'flex-start' }} onSubmit={(e) => { e.preventDefault(); load(); }}>
            <TextField label={t('Mailbox address')} value={email} onChange={(e) => setEmail(e.target.value)} sx={{ flex: 1, maxWidth: 420 }} slotProps={{ htmlInput: { inputMode: 'email', spellCheck: false } }} />
            <Button type="submit" variant="outlined" startIcon={<Search />} disabled={!email.trim()} sx={{ flexShrink: 0, height: 56 }}>{t('Load mailbox')}</Button>
          </Stack>
          {target && (
            <Box key={target.id} sx={{ mt: 3 }}>
              <Divider sx={{ mb: 2 }} />
              <Typography variant="h6" component="h3" sx={{ mb: 2, overflowWrap: 'anywhere' }}>{target.email}</Typography>
              <Stack spacing={3} divider={<Divider flexItem />}>
                <AccountPolicy id={target.id} onSaved={() => setVersion((v) => v + 1)} />
                <Box>
                  <SubHeading title={t('Masked addresses of this mailbox')} />
                  <MaskedAddresses key={`${target.id}-${version}`} accountId={target.id} />
                </Box>
              </Stack>
            </Box>
          )}
        </Section>
      </Stack>
    </>
  );
}
