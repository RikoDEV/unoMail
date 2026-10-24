import Add from '@mui/icons-material/Add';
import ContentCopy from '@mui/icons-material/ContentCopy';
import Delete from '@mui/icons-material/Delete';
import Edit from '@mui/icons-material/Edit';
import { Alert, Box, Button, Chip, Dialog, DialogContent, DialogTitle, IconButton, MenuItem, Stack, Table, TableBody, TableCell, TableHead, TableRow, TextField, Typography } from '@mui/material';
import { useState } from 'react';
import { del, formatTime, get, patch, post } from '../lib/api';
import { ConfirmDialog, DialogButtons, useAction, useFormAction, useLoad } from '../admin/common';
import { t } from '../i18n';

interface Mask { id: number; email: string; description: string; for_domain: string; integration_url: string; enabled: boolean; status: 'active' | 'disabled' | 'expired'; created_at: number; expires_at: number | null; created_by: string }
interface Listing { items: Mask[]; used: number; limit: number; domains: string[]; creation_enabled: boolean }
const STATES = { active: t('Active'), disabled: t('Disabled'), expired: t('Expired') };

function MaskDialog({ current, domains, base, onClose, onSaved }: { current: Mask | null; domains: string[]; base: string; onClose: () => void; onSaved: () => void }) {
  const [description, setDescription] = useState(current?.description ?? '');
  const [website, setWebsite] = useState(current?.for_domain ?? '');
  const [url, setUrl] = useState(current?.integration_url ?? '');
  const [domain, setDomain] = useState(domains[0] ?? '');
  const [prefix, setPrefix] = useState('');
  const [expires, setExpires] = useState('');
  const form = useFormAction<string>(() => null);
  return <Dialog open fullWidth maxWidth="sm" onClose={form.busy ? undefined : onClose}><Box component="form" onSubmit={(e) => {
    e.preventDefault();
    const metadata = { description, for_domain: website, integration_url: url };
    void form.run(() => current ? patch(`${base}/${current.id}`, metadata) : post(base, { ...metadata, domain, prefix, expires_at: expires ? Math.floor(new Date(expires).getTime() / 1000) : null })).then((ok) => { if (ok) onSaved(); });
  }}>
    <DialogTitle>{current ? t('Edit masked address') : t('Create masked address')}</DialogTitle>
    <DialogContent>{form.formError}<Stack spacing={2} sx={{ pt: 1 }}>
      {current && <TextField label={t('E-mail address')} value={current.email} disabled />}
      <TextField autoFocus label={t('Description')} value={description} onChange={(e) => setDescription(e.target.value)} slotProps={{ htmlInput: { maxLength: 200 } }} />
      <TextField label={t('Website')} value={website} onChange={(e) => setWebsite(e.target.value)} placeholder="example.com" helperText={t('A label for the website, not a sender restriction.')} />
      {!current && <>
        <TextField required select label={t('Domain')} value={domain} onChange={(e) => setDomain(e.target.value)}>{domains.map((d) => <MenuItem key={d} value={d}>{d}</MenuItem>)}</TextField>
        <TextField label={t('Address prefix')} value={prefix} onChange={(e) => setPrefix(e.target.value)} helperText={t('Optional: up to 37 lowercase letters, digits or underscores. A random suffix is always added.')} slotProps={{ htmlInput: { maxLength: 37, pattern: '[a-z0-9_]*' } }} />
        <TextField label={t('Expires at')} type="datetime-local" value={expires} onChange={(e) => setExpires(e.target.value)} slotProps={{ inputLabel: { shrink: true } }} helperText={t('Optional. The address and expiration cannot be changed later.')} />
      </>}
      <TextField label={t('Integration URL')} type="url" value={url} onChange={(e) => setUrl(e.target.value)} helperText={t('Optional HTTPS link to the entry using this address.')} />
    </Stack></DialogContent>
    <DialogButtons onCancel={onClose} cancelDisabled={form.busy} submit disabled={form.busy} />
  </Box></Dialog>;
}

export function MaskedAddresses({ accountId }: { accountId?: number }) {
  const base = accountId ? `/api/accounts/${accountId}/masked-addresses` : '/api/me/masked-addresses';
  const masks = useLoad(() => get<Listing>(base), [base]);
  const [dialog, setDialog] = useState<{ current: Mask | null } | null>(null);
  const [removing, setRemoving] = useState<Mask | null>(null);
  const [search, setSearch] = useState('');
  const { run, feedback } = useAction();
  const filtered = masks.data?.items.filter((m) => `${m.email} ${m.description} ${m.for_domain}`.toLowerCase().includes(search.toLowerCase())) ?? [];
  return <Stack spacing={2}>
    <Typography variant="body2" color="text.secondary">{t('Create a separate address for each website. Mail arrives in your existing mailbox and replies use the same masked address.')}</Typography>
    {feedback}{masks.error && <Alert severity="error">{masks.error}</Alert>}
    <Stack direction="row" spacing={2} alignItems="center" flexWrap="wrap" useFlexGap>
      <Button startIcon={<Add />} variant="contained" disabled={!masks.data?.creation_enabled || masks.data.used >= masks.data.limit || !masks.data.domains.length} onClick={() => setDialog({ current: null })}>{t('Create masked address')}</Button>
      {masks.data && <Typography variant="body2">{t('{{used}} of {{limit}} masked addresses', { used: masks.data.used, limit: masks.data.limit })}</Typography>}
      <TextField size="small" label={t('Search')} value={search} onChange={(e) => setSearch(e.target.value)} />
    </Stack>
    <Box sx={{ overflow: 'auto' }}><Table size="small" aria-label={t('Masked addresses')}><TableHead><TableRow>
      <TableCell>{t('E-mail address')}</TableCell><TableCell>{t('Status')}</TableCell><TableCell>{t('Created')}</TableCell><TableCell>{t('Expires at')}</TableCell><TableCell>{t('Actions')}</TableCell>
    </TableRow></TableHead><TableBody>{filtered.map((m) => <TableRow key={m.id}>
      <TableCell sx={{ minWidth: 230 }}><Typography variant="body2" sx={{ overflowWrap: 'anywhere' }}>{m.email}<IconButton size="small" aria-label={t('Copy {{address}}', { address: m.email })} onClick={() => void run(() => navigator.clipboard.writeText(m.email), t('Copied'))}><ContentCopy fontSize="inherit" /></IconButton></Typography>
        <Typography variant="caption" color="text.secondary" display="block">{[m.description, m.for_domain].filter(Boolean).join(' · ')}</Typography>
        {m.integration_url && <Button size="small" component="a" href={m.integration_url} target="_blank" rel="noopener noreferrer">{t('Open website')}</Button>}
      </TableCell>
      <TableCell><Chip size="small" variant="outlined" label={STATES[m.status]} /></TableCell>
      <TableCell><Typography variant="caption">{formatTime(m.created_at)}</Typography><Typography variant="caption" color="text.secondary" display="block">{m.created_by}</Typography></TableCell>
      <TableCell>{m.expires_at ? formatTime(m.expires_at) : t('Never')}</TableCell>
      <TableCell><Stack direction="row" spacing={0.5}>
        <Button size="small" disabled={m.status === 'expired'} onClick={() => void run(() => patch(`${base}/${m.id}`, { enabled: !m.enabled })).then((ok) => { if (ok) void masks.reload(); })}>{m.enabled ? t('Disable') : t('Enable')}</Button>
        <IconButton size="small" aria-label={t('Edit {{name}}', { name: m.email })} onClick={() => setDialog({ current: m })}><Edit fontSize="small" /></IconButton>
        <IconButton size="small" aria-label={t('Delete {{name}}', { name: m.email })} onClick={() => setRemoving(m)}><Delete fontSize="small" /></IconButton>
      </Stack></TableCell>
    </TableRow>)}</TableBody></Table></Box>
    {masks.data && !filtered.length && <Typography color="text.secondary">{t('No masked addresses found.')}</Typography>}
    {dialog && <MaskDialog current={dialog.current} domains={masks.data?.domains ?? []} base={base} onClose={() => setDialog(null)} onSaved={() => { setDialog(null); void masks.reload(); }} />}
    <ConfirmDialog open={Boolean(removing)} title={t('Delete masked address')} text={t('This address will stop working permanently and will never be reassigned. Existing mail is kept.')} onClose={() => setRemoving(null)} onConfirm={() => { if (removing) void run(() => del(`${base}/${removing.id}`)).then((ok) => { if (ok) { setRemoving(null); void masks.reload(); } }); }} />
    {!accountId && <MaskIntegrations />}
  </Stack>;
}

function MaskIntegrations() {
  const tokens = useLoad(() => get<{ id: number; name: string; expires_at: number }[]>('/api/me/masked-addresses/tokens'), []);
  const [name, setName] = useState('');
  const [secret, setSecret] = useState('');
  const { run, feedback } = useAction();
  return <Box component="section" aria-label={t('Mask integrations')} sx={{ borderTop: 1, borderColor: 'divider', pt: 2 }}>
    <Typography variant="h6">{t('Mask integrations')}</Typography>
    <Typography variant="body2" color="text.secondary">{t('These tokens can manage your masked addresses only. They cannot read or send mail. Tokens expire after 90 days.')}</Typography>
    {feedback}{tokens.error && <Alert severity="error">{tokens.error}</Alert>}
    <Stack direction="row" spacing={1} sx={{ my: 2 }}><TextField size="small" label={t('Integration name')} value={name} onChange={(e) => setName(e.target.value)} /><Button disabled={!name.trim()} onClick={() => void run(async () => { const value = await post<{ token: string }>('/api/me/masked-addresses/tokens', { name, expires_at: Math.floor(Date.now() / 1000) + 90 * 86400 }); setSecret(value.token); setName(''); await tokens.reload(); })}>{t('Create token')}</Button></Stack>
    {secret && <Alert severity="success" onClose={() => setSecret('')}><Typography variant="body2">{t('Copy this token now. It is shown only once.')}</Typography><TextField label={t('Integration token')} value={secret} fullWidth slotProps={{ input: { readOnly: true } }} sx={{ my: 1 }} /><Button onClick={() => void run(() => navigator.clipboard.writeText(secret), t('Copied'))}>{t('Copy')}</Button></Alert>}
    <Typography variant="caption" component="div" sx={{ overflowWrap: 'anywhere' }}>{t('Session URL')}: {window.location.origin}/api/masked-email/session</Typography>
    <Typography variant="caption" component="div" sx={{ overflowWrap: 'anywhere' }}>{t('JMAP URL')}: {window.location.origin}/api/masked-email/jmap</Typography>
    {tokens.data?.map((token) => <Stack key={token.id} direction="row" spacing={1} alignItems="center"><Typography variant="body2" sx={{ flex: 1 }}>{token.name} · {formatTime(token.expires_at)}</Typography><Button onClick={() => void run(() => del(`/api/me/masked-addresses/tokens/${token.id}`)).then((ok) => { if (ok) void tokens.reload(); })}>{t('Revoke')}</Button></Stack>)}
  </Box>;
}
