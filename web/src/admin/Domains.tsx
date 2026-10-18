import Add from '@mui/icons-material/Add';
import ArrowBack from '@mui/icons-material/ArrowBack';
import ContentCopy from '@mui/icons-material/ContentCopy';
import Delete from '@mui/icons-material/Delete';
import Refresh from '@mui/icons-material/Refresh';
import {
  Alert, Box, Button, Dialog, DialogActions, DialogContent, DialogTitle, FormControlLabel, IconButton, MenuItem, Stack, Switch, TableBody,
  TableCell, TableHead, TableRow, TextField, Tooltip, Typography, Link,
} from '@mui/material';
import { useState } from 'react';
import { Link as RouterLink, useNavigate, useParams } from 'react-router-dom';
import { del, formatBytes, get, patch, post, put } from '../api';
import { useAuth } from '../app';
import { ConfirmDialog, PageHeader, routeBy, StatusChip, useAction, useFormAction, useLoad, validators, ScrollTable } from './common';

import { t } from '../i18n';
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
  title: string;
  status: string;
  message: string;
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
                  fontWeight={600}
                  // The lighter shade keeps enough contrast on dark backgrounds.
                  sx={{ color: (theme) => (theme.palette.mode === 'dark' ? theme.palette.primary.light : theme.palette.primary.main) }}
                >
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
        <DialogActions>
          <Button onClick={() => setName(null)}>{t('Cancel')}</Button>
          <Button variant="contained" disabled={!name || Boolean(nameError) || adding.busy} onClick={() => void create()}>
            {t('Create')}
          </Button>
        </DialogActions>
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
      <Stack direction="row" spacing={3} flexWrap="wrap" useFlexGap alignItems="center" sx={{ mb: 3 }}>
        <FormControlLabel control={<Switch checked={d.enabled} disabled={!isSuper} onChange={(e) => void update({ enabled: e.target.checked }, t('Domain updated'))} />} label={t('Enabled')} />
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
          sx={{ width: 300 }}
        >
          <MenuItem value="none">{t('Not published')}</MenuItem>
          <MenuItem value="testing">{t('Testing (report only)')}</MenuItem>
          <MenuItem value="enforce">{t('Enforce')}</MenuItem>
        </TextField>
      </Stack>

      <Stack direction="row" alignItems="center" spacing={1}>
        <Typography variant="h6" sx={{ flex: 1 }}>
          {t('DNS health')}
        </Typography>
        <Button startIcon={<Refresh />} onClick={() => void dns.reload()}>
          {t('Check again')}
        </Button>
      </Stack>
      <ScrollTable size="small" sx={{ mb: 4 }} aria-label={t('DNS records')}>
        <TableHead>
          <TableRow>
            <TableCell>{t('Check')}</TableCell>
            <TableCell>{t('Status')}</TableCell>
            <TableCell>{t('Record to publish')}</TableCell>
          </TableRow>
        </TableHead>
        <TableBody>
          {(dns.data?.checks ?? []).map((check) => (
            <TableRow key={check.id}>
              <TableCell sx={{ whiteSpace: 'nowrap' }}>{check.title}</TableCell>
              <TableCell>
                <StatusChip status={check.status} />
                <Typography variant="caption" display="block" color="text.secondary">
                  {check.message}
                </Typography>
              </TableCell>
              <TableCell sx={{ fontFamily: 'monospace', fontSize: 12, wordBreak: 'break-all' }}>
                {check.record_value && (
                  <>
                    {check.record_type} {check.record_name} → {check.record_value}
                    <CopyButton value={check.record_value} />
                  </>
                )}
              </TableCell>
            </TableRow>
          ))}
        </TableBody>
      </ScrollTable>

      <Typography variant="h6">{t('DKIM keys')}</Typography>
      <Typography variant="body2" color="text.secondary" sx={{ mb: 1 }}>
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
                  inputProps={{ 'aria-label': t('Active {{selector}}', { selector: key.selector }) }}
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
      <Stack direction="row" spacing={1} sx={{ mt: 2, mb: 4 }} alignItems="flex-start">
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
          <Typography variant="body2" color="text.secondary" sx={{ mb: 1 }}>
            {t('Delegated administrators can manage mailboxes and aliases of this domain only.')}
          </Typography>
          <Stack direction="row" spacing={1} alignItems="flex-start">
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
