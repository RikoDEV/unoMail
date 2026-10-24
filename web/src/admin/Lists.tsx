// Mailing lists: the lists, their settings, members and the posts waiting for a moderator.

import Add from '@mui/icons-material/Add';
import ArrowBack from '@mui/icons-material/ArrowBack';
import Delete from '@mui/icons-material/Delete';
import { Alert, Badge, Box, Button, Card, CardContent, Chip, Dialog, DialogActions, DialogContent, DialogTitle, FormControlLabel, IconButton, MenuItem, Stack, Switch, TableBody, TableCell, TableHead, TableRow, TextField, Tooltip, Typography } from '@mui/material';
import { useState } from 'react';
import { del, formatTime, get, patch, post } from '../lib/api';
import { ConfirmDialog, PageHeader, routeBy, useAction, useFormAction, useLoad, UsageBar, validators, ScrollTable } from './common';

import { t } from '../i18n';
interface MailingList {
  id: number;
  address: string;
  name: string;
  description: string;
  posting: 'anyone' | 'members' | 'moderated' | 'announce';
  subscription: 'open' | 'closed';
  reply_to_list: boolean;
  subject_prefix: string;
  enabled: boolean;
  members?: number;
  held?: number;
  forwarded?: number;
  forward_limit?: number;
}

interface Member {
  id: number;
  email: string;
  name: string;
  role: 'member' | 'moderator' | 'owner';
  bounces: number;
}

interface Held {
  token: string;
  sender: string;
  subject: string;
  reason: string;
  received_at: number;
}

const POSTING: Record<MailingList['posting'], string> = {
  anyone: t('Anyone'),
  members: t('Members (others are held)'),
  moderated: t('Moderators (others are held)'),
  announce: t('Owners and moderators only (announcements)'),
};

export function Lists() {
  const { data, error, reload } = useLoad(() => get<MailingList[]>('/api/lists'), []);
  const { feedback, notify } = useAction();
  const [creating, setCreating] = useState<{ address: string; name: string } | null>(null);
  // Everything the server can object to when creating a list is about its address.
  const create = useFormAction(routeBy<'address'>([], 'address'));
  const [open, setOpen] = useState<number | null>(null);
  const addressError = creating?.address ? validators.email(creating.address) : '';

  if (open !== null) return <ListDetail id={open} onBack={() => { setOpen(null); void reload(); }} />;
  return (
    <>
      <PageHeader title={t('Mailing lists')}>
        <Button variant="contained" startIcon={<Add />} onClick={() => { create.clear(); setCreating({ address: '', name: '' }); }}>
          {t('New list')}
        </Button>
      </PageHeader>
      {error && <Alert severity="error">{error}</Alert>}
      {feedback}
      {data && data.length === 0 ? (
        <Typography color="text.secondary">
          {t('No lists yet. A list is an address whose mail goes to all its members, with moderation, subscribing by mail and one-click unsubscribe.')}
        </Typography>
      ) : (
        <ScrollTable size="small" aria-label={t('Mailing lists')}>
          <TableHead>
            <TableRow>
              <TableCell>{t('Address')}</TableCell>
              <TableCell>{t('Name')}</TableCell>
              <TableCell>{t('Who may post')}</TableCell>
              <TableCell align="right">{t('Members')}</TableCell>
              <TableCell align="right">{t('Waiting')}</TableCell>
              <TableCell sx={{ width: 200 }}>
                <Tooltip title={t('Copies sent to members over the last hour; beyond the limit, further posts are deferred')}>
                  <span>{t('Sending')}</span>
                </Tooltip>
              </TableCell>
            </TableRow>
          </TableHead>
          <TableBody>
            {(data ?? []).map((list) => (
              <TableRow key={list.id} hover sx={{ cursor: 'pointer' }} onClick={() => setOpen(list.id)}>
                <TableCell>
                  {list.address}
                  {!list.enabled && <Chip size="small" label={t('off')} sx={{ ml: 1 }} />}
                </TableCell>
                <TableCell>{list.name}</TableCell>
                <TableCell>{POSTING[list.posting]}</TableCell>
                <TableCell align="right">{list.members}</TableCell>
                <TableCell align="right">{list.held ? <Chip size="small" color="warning" label={list.held} /> : 0}</TableCell>
                <TableCell data-sort={(list.forwarded ?? 0) / (list.forward_limit || 1)}>
                  <UsageBar label={t('Copies')} used={list.forwarded ?? 0} limit={list.forward_limit ?? 0} />
                </TableCell>
              </TableRow>
            ))}
          </TableBody>
        </ScrollTable>
      )}
      <Dialog open={creating !== null} onClose={() => setCreating(null)} fullWidth maxWidth="xs">
        <DialogTitle>{t('New mailing list')}</DialogTitle>
        <DialogContent>
          <Stack spacing={2} sx={{ mt: 1 }}>
            <TextField
              label={t('List address')}
              autoFocus
              value={creating?.address ?? ''}
              error={Boolean(addressError || create.fieldError('address'))}
              helperText={addressError || create.fieldError('address') || t('For example team@example.org')}
              onChange={(e) => { create.clear(); setCreating((c) => c && { ...c, address: e.target.value }); }}
            />
            <TextField label={t('Name')} value={creating?.name ?? ''} onChange={(e) => { create.clear(); setCreating((c) => c && { ...c, name: e.target.value }); }} />
          </Stack>
        </DialogContent>
        <DialogActions>
          <Button onClick={() => setCreating(null)}>{t('Cancel')}</Button>
          <Button
            variant="contained"
            disabled={!creating?.address || Boolean(addressError) || create.busy}
            onClick={async () => {
              let createdId = 0;
              const ok = await create.run(async () => {
                createdId = (await post<MailingList>('/api/lists', { address: creating?.address.trim(), name: creating?.name.trim() || undefined })).id;
              });
              if (ok) {
                notify(t('List created'));
                setCreating(null);
                setOpen(createdId);
              }
            }}
          >
            {t('Create')}
          </Button>
        </DialogActions>
      </Dialog>
    </>
  );
}

function ListDetail({ id, onBack }: { id: number; onBack: () => void }) {
  const list = useLoad(() => get<MailingList>(`/api/lists/${id}`), [id]);
  const members = useLoad(() => get<Member[]>(`/api/lists/${id}/members`), [id]);
  const held = useLoad(() => get<Held[]>(`/api/lists/${id}/held`), [id]);
  const { run, feedback } = useAction();
  const [draft, setDraft] = useState<MailingList | null>(null);
  const [adding, setAdding] = useState('');
  const [role, setRole] = useState<Member['role']>('member');
  const [removing, setRemoving] = useState<Member | null>(null);
  const [deleting, setDeleting] = useState(false);
  const current = draft ?? list.data;
  if (!current) return list.error ? <Alert severity="error">{list.error}</Alert> : null;
  const change = (values: Partial<MailingList>) => setDraft({ ...current, ...values });

  return (
    <>
      <PageHeader title={current.address}>
        <Button startIcon={<ArrowBack />} onClick={onBack}>{t('All lists')}</Button>
        <Button color="error" startIcon={<Delete />} onClick={() => setDeleting(true)}>{t('Delete list')}</Button>
      </PageHeader>
      {feedback}
      <Stack spacing={3}>
        {(held.data?.length ?? 0) > 0 && (
          <Card variant="outlined">
            <CardContent>
              <Typography variant="h6" sx={{ mb: 1 }}>
                <Badge color="warning" badgeContent={held.data?.length} sx={{ pr: 2 }}>{t('Waiting for approval')}</Badge>
              </Typography>
              <ScrollTable size="small" aria-label={t('Held messages')}>
                <TableBody>
                  {held.data?.map((item) => (
                    <TableRow key={item.token}>
                      <TableCell sx={{ whiteSpace: 'nowrap' }}>{formatTime(item.received_at)}</TableCell>
                      <TableCell>{item.sender}</TableCell>
                      <TableCell>{item.subject || t('(no subject)')}<Typography variant="caption" color="text.secondary" component="div">{item.reason}</Typography></TableCell>
                      <TableCell align="right" sx={{ whiteSpace: 'nowrap' }}>
                        <Button size="small" onClick={() => void run(() => post(`/api/lists/${id}/held/${item.token}`, { action: 'approve' }), t('Sent to the list')).then(() => held.reload())}>{t('Approve')}</Button>
                        <Button size="small" color="error" onClick={() => void run(() => post(`/api/lists/${id}/held/${item.token}`, { action: 'discard' }), t('Discarded')).then(() => held.reload())}>{t('Discard')}</Button>
                      </TableCell>
                    </TableRow>
                  ))}
                </TableBody>
              </ScrollTable>
            </CardContent>
          </Card>
        )}
        <Card variant="outlined">
          <CardContent>
            <Typography variant="h6" sx={{ mb: 2 }}>{t('Settings')}</Typography>
            <Stack spacing={2} sx={{ maxWidth: 560 }}>
              <TextField label={t('Name')} value={current.name} onChange={(e) => change({ name: e.target.value })} />
              <TextField label={t('Description')} multiline minRows={2} value={current.description} onChange={(e) => change({ description: e.target.value })} helperText={t('Sent to people asking the list for help')} />
              <TextField select label={t('Who may post')} value={current.posting} onChange={(e) => change({ posting: e.target.value as MailingList['posting'] })}>
                {Object.entries(POSTING).map(([value, label]) => <MenuItem key={value} value={value}>{label}</MenuItem>)}
              </TextField>
              <TextField select label={t('Joining')} value={current.subscription} onChange={(e) => change({ subscription: e.target.value as MailingList['subscription'] })}>
                <MenuItem value="open">{t('Anyone can subscribe by mail (confirmed by a link)')}</MenuItem>
                <MenuItem value="closed">{t('Only administrators add members')}</MenuItem>
              </TextField>
              <TextField label={t('Subject prefix')} value={current.subject_prefix} placeholder="[team]" onChange={(e) => change({ subject_prefix: e.target.value })} />
              <FormControlLabel control={<Switch checked={current.reply_to_list} onChange={(e) => change({ reply_to_list: e.target.checked })} />} label={t('Replies go to the list')} />
              <FormControlLabel control={<Switch checked={current.enabled} onChange={(e) => change({ enabled: e.target.checked })} />} label={t('List is active')} />
              <Box>
                <Button variant="contained" disabled={!draft} onClick={() => void run(() => patch(`/api/lists/${id}`, draft), t('Saved')).then((ok) => { if (ok) { setDraft(null); void list.reload(); } })}>
                  {t('Save')}
                </Button>
              </Box>
              <Typography variant="body2" color="text.secondary">
                {t('Also in use:')} {current.address.replace('@', '-request@')} {t('(subscribe, unsubscribe, help),')} {current.address.replace('@', '-owner@')} {t('(reaches the owners) and')}{' '}
                {current.address.replace('@', '-bounces@')} {t('(bounce handling).')}
              </Typography>
            </Stack>
          </CardContent>
        </Card>
        <Card variant="outlined">
          <CardContent>
            <Typography variant="h6" sx={{ mb: 2 }}>{t('Members ({{length}})', { length: members.data?.length ?? 0 })}</Typography>
            <Stack direction={{ xs: 'column', sm: 'row' }} spacing={1} sx={{ mb: 2 }} alignItems="flex-start">
              <TextField label={t('Add addresses')} multiline minRows={2} sx={{ flex: 1, maxWidth: 480 }} value={adding} onChange={(e) => setAdding(e.target.value)} helperText={t('One per line; Name <address> works too')} />
              <TextField select label={t('As')} value={role} onChange={(e) => setRole(e.target.value as Member['role'])} sx={{ width: 150 }}>
                <MenuItem value="member">{t('Members')}</MenuItem>
                <MenuItem value="moderator">{t('Moderators')}</MenuItem>
                <MenuItem value="owner">{t('Owners')}</MenuItem>
              </TextField>
              <Button
                variant="outlined"
                disabled={!adding.trim()}
                onClick={async () => {
                  let message = '';
                  const ok = await run(async () => {
                    const result = await post<{ added: string[]; invalid: string[] }>(`/api/lists/${id}/members`, { addresses: adding, role });
                    message = result.invalid.length ? t('{{count}} added; not understood: {{invalid}}', { count: result.added.length, invalid: result.invalid.join(', ') }) : t('{{count}} added', { count: result.added.length });
                  });
                  if (ok) {
                    setAdding('');
                    await members.reload();
                    if (message) window.setTimeout(() => void run(async () => {}, message), 0);
                  }
                }}
              >
                {t('Add')}
              </Button>
            </Stack>
            <ScrollTable size="small" aria-label={t('Members')}>
              <TableHead>
                <TableRow>
                  <TableCell>{t('Address')}</TableCell>
                  <TableCell>{t('Role')}</TableCell>
                  <TableCell align="right">{t('Bounces')}</TableCell>
                  <TableCell />
                </TableRow>
              </TableHead>
              <TableBody>
                {(members.data ?? []).map((member) => (
                  <TableRow key={member.id}>
                    <TableCell>{member.name ? `${member.name} <${member.email}>` : member.email}</TableCell>
                    <TableCell>
                      <TextField select size="small" variant="standard" value={member.role} inputProps={{ 'aria-label': t('Role of {{email}}', { email: member.email }) }} onChange={(e) => void run(() => patch(`/api/lists/${id}/members/${member.id}`, { role: e.target.value })).then(() => members.reload())}>
                        <MenuItem value="member">{t('Member')}</MenuItem>
                        <MenuItem value="moderator">{t('Moderator')}</MenuItem>
                        <MenuItem value="owner">{t('Owner')}</MenuItem>
                      </TextField>
                    </TableCell>
                    <TableCell align="right">{member.bounces}</TableCell>
                    <TableCell align="right">
                      <Tooltip title={t('Remove from the list')}>
                        <IconButton aria-label={t('Remove {{email}}', { email: member.email })} onClick={() => setRemoving(member)}><Delete /></IconButton>
                      </Tooltip>
                    </TableCell>
                  </TableRow>
                ))}
              </TableBody>
            </ScrollTable>
          </CardContent>
        </Card>
      </Stack>
      <ConfirmDialog
        open={removing !== null}
        title={t('Remove member?')}
        text={t('{{email}} will no longer receive mail from this list.', { email: removing?.email })}
        confirmLabel={t('Remove')}
        onClose={() => setRemoving(null)}
        onConfirm={() => void run(() => del(`/api/lists/${id}/members/${removing?.id}`), t('Member removed')).then(() => { setRemoving(null); void members.reload(); })}
      />
      <ConfirmDialog
        open={deleting}
        title={t('Delete list?')}
        text={t('{{address}} and its members will be removed. Mail to it will be refused.', { address: current.address })}
        onClose={() => setDeleting(false)}
        onConfirm={() => void run(() => del(`/api/lists/${id}`), t('List deleted')).then((ok) => { if (ok) onBack(); })}
      />
    </>
  );
}
