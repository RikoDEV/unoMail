import Add from '@mui/icons-material/Add';
import ArrowBack from '@mui/icons-material/ArrowBack';
import ArrowForward from '@mui/icons-material/ArrowForward';
import CheckCircle from '@mui/icons-material/CheckCircle';
import ContentCopy from '@mui/icons-material/ContentCopy';
import Delete from '@mui/icons-material/Delete';
import ErrorOutline from '@mui/icons-material/ErrorOutlineOutlined';
import HelpOutline from '@mui/icons-material/HelpOutlineOutlined';
import Refresh from '@mui/icons-material/Refresh';
import WarningAmber from '@mui/icons-material/WarningAmber';
import {
  Alert, Box, Button, Chip, Dialog, DialogContent, DialogTitle, FormControlLabel, IconButton, MenuItem, Stack, Switch, TableBody,
  TableCell, TableHead, TableRow, TextField, Tooltip, Typography, Link,
} from '@mui/material';
import { useState } from 'react';
import { Link as RouterLink, useNavigate, useParams } from 'react-router-dom';
import { del, formatBytes, get, patch, post, put } from '../lib/api';
import { useAuth } from '../app';
import { ConfirmDialog, DialogButtons, PageHeader, routeBy, ScrollTable, StatusChip, useAction, useFormAction, useLoad, validators } from './common';

import { t } from '../i18n';
import { serverText } from './serverTexts';
interface Domain {
  id: number;
  name: string;
  enabled: boolean;
  max_mailboxes: number;
  default_quota_bytes: number;
  catch_all: string | null;
  mta_sts_mode: 'none' | 'testing' | 'enforce';
  mailbox_count: number;
  alias_count: number;
  used_bytes: number;
}

interface Check {
  id: string;
  /** English; `title_key` and `title_params` give the text to translate (see serverTexts.ts). */
  title: string;
  title_key?: string;
  title_params?: Record<string, string>;
  status: string;
  message: string;
  message_key?: string;
  message_params?: Record<string, string>;
  record_type: string;
  record_name: string;
  record_value: string;
  found: string[];
}

interface DkimKey {
  id: number;
  selector: string;
  algorithm: string;
  active: boolean;
  created_at: number;
  dns_name: string;
  dns_value: string;
}

export function Domains() {
  const { account } = useAuth();
  const isSuper = account?.role === 'super_admin';
  const { data, error, reload } = useLoad(() => get<Domain[]>('/api/domains'), []);
  const { run, feedback, notify } = useAction();
  const [name, setName] = useState<string | null>(null);
  const [removing, setRemoving] = useState<Domain | null>(null);
  const nameError = name ? validators.domain(name) : '';
  const adding = useFormAction(routeBy<'name'>([], 'name'));

  async function create() {
    if (!name || nameError) return;
    if (await adding.run(() => post('/api/domains', { name }))) {
      notify(t('Domain created'));
      setName(null);
      await reload();
    }
  }

  return (
    <>
      <PageHeader title={t('Domains')}>
        {isSuper && (
          <Button variant="contained" startIcon={<Add />} onClick={() => { adding.clear(); setName(''); }}>
            {t('Add domain')}
          </Button>
        )}
      </PageHeader>
      {error && <Alert severity="error">{error}</Alert>}
      {feedback}
      <ScrollTable size="small" aria-label={t('Domains')}>
        <TableHead>
          <TableRow>
            <TableCell>{t('Domain')}</TableCell>
            <TableCell>{t('Status')}</TableCell>
            <TableCell align="right">{t('Mailboxes')}</TableCell>
            <TableCell align="right">{t('Aliases')}</TableCell>
            <TableCell align="right">{t('Storage')}</TableCell>
            <TableCell />
          </TableRow>
        </TableHead>
        <TableBody>
          {(data ?? []).map((domain) => (
            <TableRow key={domain.id} hover>
              <TableCell>
                {/* The theme's colour: the browser's default link blue is unreadable on dark skins. */}
                <Link
                  component={RouterLink}
                  to={`/admin/domains/${domain.id}`}
                  underline="hover"
                  sx={{ fontWeight: 600, color: (theme) => (theme.palette.mode === 'dark' ? theme.palette.primary.light : theme.palette.primary.main) }}>
                  {domain.name}
                </Link>
              </TableCell>
              <TableCell>
                <StatusChip status={domain.enabled ? 'ok' : 'disabled'} />
              </TableCell>
              <TableCell align="right">
                {domain.mailbox_count}
                {domain.max_mailboxes > 0 ? ` / ${domain.max_mailboxes}` : ''}
              </TableCell>
              <TableCell align="right">{domain.alias_count}</TableCell>
              <TableCell align="right">{formatBytes(domain.used_bytes)}</TableCell>
              <TableCell align="right">
                {isSuper && (
                  <Tooltip title={t('Delete domain')}>
                    <IconButton aria-label={t('Delete {{name}}', { name: domain.name })} onClick={() => setRemoving(domain)}>
                      <Delete />
                    </IconButton>
                  </Tooltip>
                )}
              </TableCell>
            </TableRow>
          ))}
        </TableBody>
      </ScrollTable>
      <Dialog open={name !== null} onClose={() => setName(null)} fullWidth maxWidth="xs">
        <DialogTitle>{t('Add domain')}</DialogTitle>
        <DialogContent>
          <TextField
            autoFocus
            fullWidth
            label={t('Domain name')}
            placeholder="example.com"
            value={name ?? ''}
            onChange={(e) => { adding.clear(); setName(e.target.value); }}
            error={Boolean(nameError || adding.fieldError('name'))}
            helperText={nameError || adding.fieldError('name') || t('A DKIM signing key is generated automatically.')}
            onKeyDown={(e) => e.key === 'Enter' && void create()}
            sx={{ mt: 1 }}
          />
        </DialogContent>
        <DialogButtons onCancel={() => setName(null)} onConfirm={() => void create()} disabled={!name || Boolean(nameError) || adding.busy} label={t('Create')} />
      </Dialog>
      <ConfirmDialog
        open={Boolean(removing)}
        title={t('Delete {{name}}?', { name: removing?.name ?? '' })}
        text={t('This permanently deletes the domain with its {{count}} mailboxes, all their mail, and its aliases.', { count: removing?.mailbox_count ?? 0 })}
        onClose={() => setRemoving(null)}
        onConfirm={async () => {
          const target = removing;
          setRemoving(null);
          if (target && (await run(() => del(`/api/domains/${target.id}`), t('Domain deleted')))) await reload();
        }}
      />
    </>
  );
}

function CopyButton({ value }: { value: string }) {
  return (
    <Tooltip title={t('Copy')}>
      <IconButton size="small" aria-label={t('Copy value')} onClick={() => void navigator.clipboard?.writeText(value)}>
        <ContentCopy fontSize="inherit" />
      </IconButton>
    </Tooltip>
  );
}

const DNS_STATUS = {
  ok: { color: 'success' as const, icon: CheckCircle },
  warning: { color: 'warning' as const, icon: WarningAmber },
  error: { color: 'error' as const, icon: ErrorOutline },
  unknown: { color: 'info' as const, icon: HelpOutline },
};

function DnsCheckRow({ check }: { check: Check }) {
  const status = DNS_STATUS[check.status as keyof typeof DNS_STATUS] ?? DNS_STATUS.unknown;
  const StatusIcon = status.icon;
  const optional = check.status === 'warning' && (check.message.startsWith('Optional:') || check.message.startsWith('No TLS reporting record:'));
  const title = check.title_key ? serverText(check.title_key, check.title_params, check.title) : check.title;
  const message = check.message_key ? serverText(check.message_key, check.message_params, check.message) : check.message;
  return (
    <Box component="article" role="listitem" sx={{ display: 'flex', gap: 1.5, px: { xs: 1.5, sm: 2 }, py: 1.5, '&:not(:last-child)': { borderBottom: 1, borderColor: 'divider' } }}>
      <Box sx={{ display: 'grid', placeItems: 'center', width: 30, height: 30, mt: 0.25, flexShrink: 0, borderRadius: 1, bgcolor: optional ? 'action.selected' : `${status.color}.main`, color: optional ? 'text.secondary' : `${status.color}.contrastText` }}>
        <StatusIcon aria-hidden sx={{ fontSize: 18 }} />
      </Box>
      <Box sx={{ minWidth: 0, flex: 1, display: 'grid', gridTemplateColumns: { xs: '1fr', md: 'minmax(210px, 0.7fr) minmax(0, 1.3fr)' }, gap: { xs: 1, md: 2.5 } }}>
        <Box>
          <Typography variant="subtitle2" component="h3">{title}</Typography>
          <Typography variant="caption" sx={{ display: 'block', color: 'text.secondary', mt: 0.25 }}>{message}</Typography>
        </Box>
        <Box sx={{ minWidth: 0 }}>
          {check.record_value && (
            <>
              <Typography variant="caption" sx={{ color: 'text.secondary' }}>{t('Record to publish')}</Typography>
              <Stack direction="row" spacing={0.5} useFlexGap sx={{ alignItems: 'center', flexWrap: 'wrap' }}>
                <Chip label={check.record_type} size="small" variant="outlined" sx={{ height: 22, flexShrink: 0, fontFamily: 'monospace' }} />
                <Typography component="code" variant="caption" sx={{ fontFamily: 'monospace', overflowWrap: 'anywhere' }}>{check.record_name}</Typography>
                <ArrowForward aria-hidden sx={{ fontSize: 16, flexShrink: 0, color: 'text.secondary', userSelect: 'none' }} />
                <Typography component="code" variant="caption" sx={{ minWidth: 0, fontFamily: 'monospace', overflowWrap: 'anywhere' }}>{check.record_value}</Typography>
                <CopyButton value={check.record_value} />
              </Stack>
            </>
          )}
          {check.found.length > 0 && (
            <Box sx={{ mt: check.record_value ? 0.5 : 0 }}>
              <Typography variant="caption" sx={{ color: 'text.secondary' }}>{t('Found in DNS')}: </Typography>
              {check.found.map((value, index) => (
                <Typography key={`${value}-${index}`} component="code" variant="caption" sx={{ fontFamily: 'monospace', overflowWrap: 'anywhere', '&:not(:last-child)::after': { content: '", "' } }}>
                  {value}
                </Typography>
              ))}
            </Box>
          )}
        </Box>
      </Box>
    </Box>
  );
}

function DnsHealth({ checks, error, onReload }: { checks: Check[]; error: string; onReload: () => Promise<unknown> }) {
  return (
    <Box component="section" aria-labelledby="dns-health-title" sx={{ mb: 4 }}>
      <Stack
        direction={{ xs: 'column', sm: 'row' }}
        spacing={1.5}
        sx={{
          alignItems: { xs: 'stretch', sm: 'center' },
          mb: 2
        }}>
        <Box sx={{ flex: 1 }}>
          <Typography id="dns-health-title" variant="h6">{t('DNS health')}</Typography>
          <Typography variant="body2" sx={{ color: 'text.secondary' }}>{t('DNS records')}</Typography>
        </Box>
        <Button variant="outlined" startIcon={<Refresh />} onClick={() => void onReload()} sx={{ alignSelf: { xs: 'flex-start', sm: 'center' } }}>
          {t('Check again')}
        </Button>
      </Stack>
      {error && <Alert severity="error" sx={{ mb: 2 }}>{error}</Alert>}
      <Box role="list" aria-label={t('DNS records')} sx={{ border: 1, borderColor: 'divider', borderRadius: 1.5, overflow: 'hidden' }}>
        {checks.map((check) => <DnsCheckRow key={check.id} check={check} />)}
      </Box>
    </Box>
  );
}

export function DomainDetail() {
  const { id } = useParams();
  const navigate = useNavigate();
  const { account } = useAuth();
  const isSuper = account?.role === 'super_admin';
  const domain = useLoad(() => get<Domain>(`/api/domains/${id}`), [id]);
  const dns = useLoad(() => get<{ checks: Check[]}>(`/api/domains/${id}/dns`), [id]);
  const keys = useLoad(() => get<DkimKey[]>(`/api/domains/${id}/dkim`), [id]);
  const admins = useLoad(() => (isSuper ? get<string[]>(`/api/domains/${id}/admins`) : Promise.resolve([])), [id, isSuper]);
  const { run, feedback } = useAction();
  const [selector, setSelector] = useState('');
  const [algorithm, setAlgorithm] = useState('rsa-sha256');
  const [catchAll, setCatchAll] = useState<string | null>(null);
  const [adminList, setAdminList] = useState<string | null>(null);

  if (domain.error) return <Alert severity="error">{domain.error}</Alert>;
  if (!domain.data) return null;
  const d = domain.data;
  const update = (body: Record<string, unknown>, message: string) => run(() => patch(`/api/domains/${id}`, body), message).then(async (ok) => {
      if (ok) await domain.reload();
    });

  return (
    <>
      <PageHeader title={d.name}>
        <Button startIcon={<ArrowBack />} onClick={() => navigate('/admin/domains')}>
          {t('All domains')}
        </Button>
      </PageHeader>
      {feedback}
      {/* Top-aligned: the MTA-STS description makes that field taller than the others. */}
      <Stack direction="row" spacing={3} useFlexGap sx={{ flexWrap: 'wrap', alignItems: 'flex-start', mb: 3 }}>
        <FormControlLabel sx={{ m: 0 }} control={<Switch checked={d.enabled} disabled={!isSuper} onChange={(e) => void update({ enabled: e.target.checked }, t('Domain updated'))} />} label={t('Enabled')} />
        <TextField
          label={t('Catch-all address')}
          value={catchAll ?? d.catch_all ?? ''}
          onChange={(e) => setCatchAll(e.target.value)}
          onBlur={() => catchAll !== null && catchAll !== (d.catch_all ?? '') && void update({ catch_all: catchAll || null }, t('Catch-all updated'))}
          placeholder={`postmaster@${d.name}`}
          sx={{ minWidth: 280 }}
        />
        <TextField
          label={t('Mailbox limit (0 = unlimited)')}
          type="number"
          defaultValue={d.max_mailboxes}
          disabled={!isSuper}
          onBlur={(e) => Number(e.target.value) !== d.max_mailboxes && void update({ max_mailboxes: Math.max(0, Number(e.target.value)) }, t('Limit updated'))}
          sx={{ width: 220 }}
        />
        <TextField
          select
          label={t('MTA-STS policy')}
          value={d.mta_sts_mode}
          onChange={(e) => void update({ mta_sts_mode: e.target.value }, t('MTA-STS policy updated')).then(() => dns.reload())}
          helperText={t('Tells other servers to deliver here only over verified TLS')}
          sx={{ width: 380, maxWidth: '100%' }}
        >
          <MenuItem value="none">{t('Not published')}</MenuItem>
          <MenuItem value="testing">{t('Testing (report only)')}</MenuItem>
          <MenuItem value="enforce">{t('Enforce')}</MenuItem>
        </TextField>
      </Stack>

      <DnsHealth checks={dns.data?.checks ?? []} error={dns.error ?? ''} onReload={dns.reload} />

      <Typography variant="h6">{t('DKIM keys')}</Typography>
      <Typography variant="body2" sx={{ color: 'text.secondary', mb: 1 }}>
        {t('To rotate a key: add a new selector, publish its DNS record, then deactivate and delete the old one. Mail is signed with every active key.')}
      </Typography>
      <ScrollTable size="small" aria-label={t('DKIM keys')}>
        <TableHead>
          <TableRow>
            <TableCell>{t('Selector')}</TableCell>
            <TableCell>{t('Algorithm')}</TableCell>
            <TableCell>{t('Active')}</TableCell>
            <TableCell>{t('DNS record')}</TableCell>
            <TableCell />
          </TableRow>
        </TableHead>
        <TableBody>
          {(keys.data ?? []).map((key) => (
            <TableRow key={key.id}>
              <TableCell>{key.selector}</TableCell>
              <TableCell>{key.algorithm}</TableCell>
              <TableCell>
                <Switch
                  checked={key.active}
                  slotProps={{ input: { 'aria-label': t('Active {{selector}}', { selector: key.selector }) } }}
                  onChange={async (e) => {
                    if (await run(() => patch(`/api/domains/${id}/dkim/${key.id}`, { active: e.target.checked }), t('Key updated'))) await Promise.all([keys.reload(), dns.reload()]);
                  }}
                />
              </TableCell>
              <TableCell sx={{ fontFamily: 'monospace', fontSize: 12, wordBreak: 'break-all', maxWidth: 420 }}>
                {key.dns_name}
                <CopyButton value={key.dns_value} />
              </TableCell>
              <TableCell align="right">
                <Tooltip title={t('Delete key')}>
                  <IconButton
                    aria-label={t('Delete key {{selector}}', { selector: key.selector })}
                    onClick={async () => {
                      if (await run(() => del(`/api/domains/${id}/dkim/${key.id}`), t('Key deleted'))) await Promise.all([keys.reload(), dns.reload()]);
                    }}
                  >
                    <Delete />
                  </IconButton>
                </Tooltip>
              </TableCell>
            </TableRow>
          ))}
        </TableBody>
      </ScrollTable>
      <Stack direction="row" spacing={1} sx={{ alignItems: 'flex-start', mt: 2, mb: 4 }}>
        <TextField label={t('New selector')} value={selector} onChange={(e) => setSelector(e.target.value.toLowerCase())} placeholder="mail2026" />
        <TextField select label={t('Algorithm')} value={algorithm} onChange={(e) => setAlgorithm(e.target.value)} sx={{ width: 190 }}>
          <MenuItem value="rsa-sha256">RSA 2048</MenuItem>
          <MenuItem value="ed25519-sha256">Ed25519</MenuItem>
        </TextField>
        <Button
          variant="outlined"
          disabled={!/^[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?$/.test(selector)}
          onClick={async () => {
            if (await run(() => post(`/api/domains/${id}/dkim`, { selector, algorithm }), t('Key generated'))) {
              setSelector('');
              await Promise.all([keys.reload(), dns.reload()]);
            }
          }}
        >
          {t('Generate key')}
        </Button>
      </Stack>

      {isSuper && (
        <Box>
          <Typography variant="h6">{t('Domain administrators')}</Typography>
          <Typography variant="body2" sx={{ color: 'text.secondary', mb: 1 }}>
            {t('Delegated administrators can manage mailboxes and aliases of this domain only.')}
          </Typography>
          <Stack direction="row" spacing={1} sx={{ alignItems: 'flex-start' }}>
            <TextField
              label={t('Administrator e-mail addresses')}
              value={adminList ?? (admins.data ?? []).join(', ')}
              onChange={(e) => setAdminList(e.target.value)}
              helperText={t('Comma separated; accounts must already exist')}
              sx={{ minWidth: 380 }}
            />
            <Button
              variant="outlined"
              disabled={adminList === null}
              onClick={async () => {
                const emails = (adminList ?? '').split(',').map((s) => s.trim()).filter(Boolean);
                if (await run(() => put(`/api/domains/${id}/admins`, { emails }), t('Administrators updated'))) {
                  setAdminList(null);
                  await admins.reload();
                }
              }}
            >
              {t('Save')}
            </Button>
          </Stack>
        </Box>
      )}
    </>
  );
}
