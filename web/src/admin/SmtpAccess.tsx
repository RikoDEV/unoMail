// SMTP blacklist and whitelist: rules defined by the administrator, rules the server created
// on its own, and the behaviour scores ("karma") those are based on.

import Add from '@mui/icons-material/Add';
import Block from '@mui/icons-material/Block';
import Delete from '@mui/icons-material/Delete';
import Edit from '@mui/icons-material/Edit';
import LockOpen from '@mui/icons-material/LockOpen';
import VerifiedUser from '@mui/icons-material/VerifiedUser';
import {
  Alert, Box, Button, Chip, CircularProgress, Dialog, DialogContent, DialogTitle, IconButton, MenuItem, Stack, Tab, TableBody, TableCell, TableHead, TableRow, Tabs, TextField,
  Tooltip, Typography,
} from '@mui/material';
import { useState } from 'react';
import { del, formatTime, get, post, put } from '../lib/api';
import { DialogButtons, PageHeader, routeBy, ScrollTable, useAction, useFormAction, useLoad, usePaged } from './common';
import { RemoteAddress } from './RemoteAddress';

import { t } from '../i18n';
interface Rule {
  id: number;
  list: 'blacklist' | 'whitelist';
  source: 'user' | 'auto';
  network: string;
  priority: number;
  hits: number;
  last_seen: number | null;
  description: string;
  expires_at: number | null;
  rdns: string | null;
  country: string | null;
}

interface Karma {
  ip: string;
  score: number;
  good: number;
  bad: number;
  hits: number;
  last_seen: number;
  last_event: string;
  rdns: string | null;
  country: string | null;
}

interface LoginBlock {
  key: string;
  kind: 'ip' | 'pair' | 'acct';
  network: string | null;
  email: string | null;
  failures: number;
  until: number;
  rdns: string | null;
  country: string | null;
}

interface RuleForm {
  id?: number;
  list: 'blacklist' | 'whitelist';
  network: string;
  priority: string;
  description: string;
}

const lastSeen = (seconds: number | null) => (seconds ? formatTime(seconds) : t('Never'));

/** Shown in place of a table until its rows have arrived. */
function Loading() {
  return (
    <Box sx={{ display: 'flex', justifyContent: 'center', py: 4 }}>
      <CircularProgress size={28} aria-label={t('Loading')} />
    </Box>
  );
}

function ListChip({ list }: { list: Rule['list'] }) {
  return list === 'blacklist' ? <Chip size="small" color="error" icon={<Block />} label={t('Blacklist')} /> : <Chip size="small" color="success" icon={<VerifiedUser />} label={t('Whitelist')} />;
}

function RuleDialog({ initial, onClose }: { initial: RuleForm; onClose: (saved: boolean) => void }) {
  const [form, setForm] = useState(initial);
  const saving = useFormAction(
    routeBy<'network' | 'priority' | 'description'>([
      [/priority/i, 'priority'],
      [/description/i, 'description'],
      [/address|network|wider|on that list/i, 'network'],
    ]),
  );
  const set = (changes: Partial<RuleForm>) => {
    saving.clear();
    setForm((current) => ({ ...current, ...changes }));
  };
  const priorityValid = /^-?\d+$/.test(form.priority.trim());

  async function save() {
    const body = { list: form.list, network: form.network.trim(), priority: Number(form.priority), description: form.description };
    if (await saving.run(() => (form.id ? put(`/api/smtp-access/rules/${form.id}`, body) : post('/api/smtp-access/rules', body)))) onClose(true);
  }

  return (
    <Dialog open onClose={() => onClose(false)} fullWidth maxWidth="sm">
      <DialogTitle>{form.id ? t('Edit rule') : t('Add rule')}</DialogTitle>
      <DialogContent>
        <Stack spacing={2} sx={{ mt: 1 }}>
          {saving.formError}
          <TextField select label={t('List')} value={form.list} onChange={(e) => set({ list: e.target.value as Rule['list'] })}>
            <MenuItem value="blacklist">{t('Blacklist: refuse connections')}</MenuItem>
            <MenuItem value="whitelist">{t('Whitelist: skip blocklist, reputation and greylisting checks')}</MenuItem>
          </TextField>
          <TextField
            label={t('IP address or network')}
            value={form.network}
            onChange={(e) => set({ network: e.target.value })}
            placeholder={t('203.0.113.7 or 203.0.113.0/24')}
            autoFocus={!form.id}
            error={Boolean(saving.fieldError('network'))}
            helperText={saving.fieldError('network')}
            slotProps={{ htmlInput: { spellCheck: false } }}
          />
          <TextField
            label={t('Priority')}
            value={form.priority}
            onChange={(e) => set({ priority: e.target.value })}
            error={!priorityValid || Boolean(saving.fieldError('priority'))}
            helperText={saving.fieldError('priority') || t('When several rules match, the highest priority wins; among equals the most specific network, then the whitelist')}
            sx={{ maxWidth: 480 }}
          />
          <TextField label={t('Description (optional)')} value={form.description} onChange={(e) => set({ description: e.target.value })} error={Boolean(saving.fieldError('description'))} helperText={saving.fieldError('description')} />
        </Stack>
      </DialogContent>
      <DialogButtons onCancel={() => onClose(false)} onConfirm={() => void save()} disabled={!form.network.trim() || !priorityValid || saving.busy} label={t('Save rule')} />
    </Dialog>
  );
}

function RulesTable({ source }: { source: 'user' | 'auto' }) {
  const { data, error, reload } = useLoad(() => get<Rule[]>(`/api/smtp-access/rules?source=${source}`), [source]);
  const { run, feedback } = useAction();
  const [editing, setEditing] = useState<RuleForm | null>(null);
  const rules = data ?? [];
  const { visible: visibleRules, pager } = usePaged(rules, t('Rules per page:'));
  return (
    <>
      {feedback}
      {error && <Alert severity="error" sx={{ mb: 2 }}>{error}</Alert>}
      <Stack direction="row" sx={{ alignItems: 'center', mb: 1 }}>
        <Typography variant="body2" sx={{ color: 'text.secondary', flex: 1 }}>
          {source === 'user'
            ? t('Addresses and networks you allow or block yourself. The rules apply on every SMTP port, as soon as they are saved.')
            : t('Created by the server when an address keeps misbehaving. These rules lapse after a day; editing one makes it permanent and moves it to your own list.')}
        </Typography>
        {source === 'user' && (
          <Button variant="contained" startIcon={<Add />} onClick={() => setEditing({ list: 'blacklist', network: '', priority: '0', description: '' })}>
            {t('Add rule')}
          </Button>
        )}
      </Stack>
      {!data ? (!error && <Loading />) : rules.length === 0 ? (
        <Typography sx={{ color: 'text.secondary', py: 4, textAlign: 'center' }}>
          {source === 'user' ? t('No rules yet.') : t('Nothing has been blocked automatically.')}
        </Typography>
      ) : (
        <>
          <ScrollTable size="small" aria-label={source === 'user' ? t('User defined rules') : t('Automatic rules')}>
            <TableHead>
              <TableRow>
                <TableCell>{t('Address or network')}</TableCell>
                <TableCell>{t('List')}</TableCell>
                <TableCell align="right">{t('Priority')}</TableCell>
                <TableCell align="right">{t('Hits')}</TableCell>
                <TableCell>{t('Last seen')}</TableCell>
                <TableCell>{t('Description')}</TableCell>
                <TableCell />
              </TableRow>
            </TableHead>
            <TableBody>
              {visibleRules.map((rule) => (
                <TableRow key={rule.id} hover>
                  <TableCell>
                    <RemoteAddress address={rule.network} rdns={rule.rdns} country={rule.country} />
                  </TableCell>
                  <TableCell>
                    <ListChip list={rule.list} />
                  </TableCell>
                  <TableCell align="right">{rule.priority}</TableCell>
                  <TableCell align="right">{rule.hits}</TableCell>
                  <TableCell sx={{ whiteSpace: 'nowrap' }}>{lastSeen(rule.last_seen)}</TableCell>
                  <TableCell sx={{ overflowWrap: 'anywhere' }}>
                    {rule.description}
                    {rule.expires_at && (
                      <Typography variant="caption" sx={{ color: 'text.secondary', display: 'block' }}>
                        {t('Until {{expires_at}}', { expires_at: formatTime(rule.expires_at) })}
                      </Typography>
                    )}
                  </TableCell>
                  <TableCell align="right" sx={{ whiteSpace: 'nowrap' }}>
                    <Tooltip title={source === 'auto' ? t('Edit and keep permanently') : t('Edit')}>
                      <IconButton size="small" aria-label={t('Edit rule {{network}}', { network: rule.network })} onClick={() => setEditing({ id: rule.id, list: rule.list, network: rule.network, priority: String(rule.priority), description: rule.description })}>
                        <Edit fontSize="small" />
                      </IconButton>
                    </Tooltip>
                    <Tooltip title={t('Delete')}>
                      <IconButton size="small" aria-label={t('Delete rule {{network}}', { network: rule.network })} onClick={() => void run(async () => { await del(`/api/smtp-access/rules/${rule.id}`); await reload(); }, t('Rule deleted'))}>
                        <Delete fontSize="small" />
                      </IconButton>
                    </Tooltip>
                  </TableCell>
                </TableRow>
              ))}
            </TableBody>
          </ScrollTable>
          {pager}
        </>
      )}
      {editing && (
        <RuleDialog
          initial={editing}
          onClose={(saved) => {
            setEditing(null);
            if (saved) void run(reload, t('Rule saved'));
          }}
        />
      )}
    </>
  );
}

function KarmaTable() {
  const { data, error, reload } = useLoad(() => get<Karma[]>('/api/smtp-access/karma'), []);
  const { run, feedback } = useAction();
  const records = data ?? [];
  const addRule = (record: Karma, list: Rule['list']) =>
    run(async () => {
      await post('/api/smtp-access/rules', { list, network: record.ip, priority: 0, description: t('From karma record (score {{score}})', { score: record.score }) });
    }, list === 'blacklist' ? t('Address blacklisted') : t('Address whitelisted'));
  return (
    <>
      {feedback}
      {error && <Alert severity="error" sx={{ mb: 2 }}>{error}</Alert>}
      <Typography variant="body2" sx={{ color: 'text.secondary', mb: 1 }}>
        {t('How remote servers have behaved. Accepted mail raises the score; rejected mail, failed logins, unknown recipients and protocol errors lower it. At a score of -20 an address is blacklisted for a day. Records idle for a month are forgotten.')}
      </Typography>
      {!data ? (!error && <Loading />) : records.length === 0 ? (
        <Typography sx={{ color: 'text.secondary', py: 4, textAlign: 'center' }}>
          {t('No remote server has been scored yet.')}
        </Typography>
      ) : (
        <ScrollTable size="small" aria-label={t('Karma records')}>
          <TableHead>
            <TableRow>
              <TableCell>{t('Address')}</TableCell>
              <TableCell align="right">{t('Score')}</TableCell>
              <TableCell align="right">{t('Good / bad')}</TableCell>
              <TableCell align="right">{t('Hits')}</TableCell>
              <TableCell>{t('Last seen')}</TableCell>
              <TableCell>{t('Last event')}</TableCell>
              <TableCell />
            </TableRow>
          </TableHead>
          <TableBody>
            {records.map((record) => (
              <TableRow key={record.ip} hover>
                <TableCell>
                  <RemoteAddress address={record.ip} rdns={record.rdns} country={record.country} />
                </TableCell>
                <TableCell align="right">
                  <Chip size="small" label={record.score > 0 ? `+${record.score}` : record.score} color={record.score <= -20 ? 'error' : record.score < 0 ? 'warning' : record.score > 0 ? 'success' : 'default'} />
                </TableCell>
                <TableCell align="right">
                  {record.good} / {record.bad}
                </TableCell>
                <TableCell align="right">{record.hits}</TableCell>
                <TableCell sx={{ whiteSpace: 'nowrap' }}>{lastSeen(record.last_seen)}</TableCell>
                <TableCell>{record.last_event}</TableCell>
                <TableCell align="right" sx={{ whiteSpace: 'nowrap' }}>
                  <Tooltip title={t('Add to the blacklist')}>
                    <IconButton size="small" aria-label={t('Blacklist {{ip}}', { ip: record.ip })} onClick={() => void addRule(record, 'blacklist')}>
                      <Block fontSize="small" />
                    </IconButton>
                  </Tooltip>
                  <Tooltip title={t('Add to the whitelist')}>
                    <IconButton size="small" aria-label={t('Whitelist {{ip}}', { ip: record.ip })} onClick={() => void addRule(record, 'whitelist')}>
                      <VerifiedUser fontSize="small" />
                    </IconButton>
                  </Tooltip>
                  <Tooltip title={t('Forget this record')}>
                    <IconButton size="small" aria-label={t('Forget {{ip}}', { ip: record.ip })} onClick={() => void run(async () => { await del(`/api/smtp-access/karma/${encodeURIComponent(record.ip)}`); await reload(); }, t('Record forgotten'))}>
                      <Delete fontSize="small" />
                    </IconButton>
                  </Tooltip>
                </TableCell>
              </TableRow>
            ))}
          </TableBody>
        </ScrollTable>
      )}
    </>
  );
}

function LoginBlocksTable() {
  const { data, error, reload } = useLoad(() => get<LoginBlock[]>('/api/smtp-access/login-blocks'), []);
  const { run, feedback } = useAction();
  const blocks = data ?? [];
  const kindLabel = (kind: LoginBlock['kind']) => (kind === 'ip' ? t('Network') : kind === 'pair' ? t('Account from network') : t('Account'));
  return (
    <>
      {feedback}
      {error && <Alert severity="error" sx={{ mb: 2 }}>{error}</Alert>}
      <Typography variant="body2" sx={{ color: 'text.secondary', mb: 1 }}>
        {t('Networks and accounts refused for too many failed logins, on every protocol. The limits are set in the server settings. Unblocking also forgets the failures and earlier lockouts.')}
      </Typography>
      {!data ? (!error && <Loading />) : blocks.length === 0 ? (
        <Typography sx={{ color: 'text.secondary', py: 4, textAlign: 'center' }}>
          {t('Nothing is rate limited.')}
        </Typography>
      ) : (
        <ScrollTable size="small" aria-label={t('Login rate limited')}>
          <TableHead>
            <TableRow>
              <TableCell>{t('Blocked')}</TableCell>
              <TableCell>{t('Address or network')}</TableCell>
              <TableCell>{t('Account')}</TableCell>
              <TableCell align="right">{t('Failures')}</TableCell>
              <TableCell>{t('Until')}</TableCell>
              <TableCell />
            </TableRow>
          </TableHead>
          <TableBody>
            {blocks.map((block) => (
              <TableRow key={block.key} hover>
                <TableCell>
                  <Chip size="small" color="error" label={kindLabel(block.kind)} />
                </TableCell>
                <TableCell>{block.network ? <RemoteAddress address={block.network} rdns={block.rdns} country={block.country} /> : '—'}</TableCell>
                <TableCell sx={{ overflowWrap: 'anywhere' }}>{block.email ?? '—'}</TableCell>
                <TableCell align="right">{block.failures}</TableCell>
                <TableCell sx={{ whiteSpace: 'nowrap' }}>{formatTime(block.until)}</TableCell>
                <TableCell align="right">
                  <Tooltip title={t('Unblock')}>
                    <IconButton size="small" aria-label={t('Unblock {{target}}', { target: [block.email, block.network].filter(Boolean).join(' / ') })} onClick={() => void run(async () => { await post('/api/smtp-access/login-blocks/unblock', { key: block.key }); await reload(); }, t('Unblocked'))}>
                      <LockOpen fontSize="small" />
                    </IconButton>
                  </Tooltip>
                </TableCell>
              </TableRow>
            ))}
          </TableBody>
        </ScrollTable>
      )}
    </>
  );
}

export function SmtpAccess() {
  const [tab, setTab] = useState<'user' | 'auto' | 'karma' | 'login'>('user');
  return (
    <>
      <PageHeader title={t('SMTP blacklist and whitelist')} />
      <Tabs value={tab} onChange={(_, value) => setTab(value)} sx={{ mb: 2 }}>
        <Tab value="user" label={t('User defined')} />
        <Tab value="auto" label={t('Automatically generated')} />
        <Tab value="karma" label={t('Karma records')} />
        <Tab value="login" label={t('Login rate limited')} />
      </Tabs>
      {tab === 'karma' ? <KarmaTable /> : tab === 'login' ? <LoginBlocksTable /> : <RulesTable key={tab} source={tab} />}
    </>
  );
}
