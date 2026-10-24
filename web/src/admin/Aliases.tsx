import Add from '@mui/icons-material/Add';
import Delete from '@mui/icons-material/Delete';
import Edit from '@mui/icons-material/Edit';
import { Alert, Button, Dialog, DialogContent, DialogTitle, IconButton, Stack, Switch, TableBody, TableCell, TableHead, TableRow, TextField, Tooltip } from '@mui/material';
import { useState } from 'react';
import { del, get, patch, post } from '../lib/api';
import { ConfirmDialog, DialogButtons, PageHeader, routeBy, ScrollTable, UsageBar, useAction, useFormAction, useLoad, validators } from './common';

import { t } from '../i18n';
interface Alias {
  id: number;
  source: string;
  destinations: string[];
  enabled: boolean;
  forwarded: number;
  forward_limit: number;
}

interface FormState {
  id?: number;
  source: string;
  destinations: string;
}

export function Aliases() {
  const { data, error, reload } = useLoad(() => get<Alias[]>('/api/aliases'), []);
  const { run, feedback, notify } = useAction();
  const [form, setForm] = useState<FormState | null>(null);
  const saving = useFormAction(
    routeBy<'source' | 'destinations'>(
      [
        [/alias address|domain is not hosted|already exists|already in use/i, 'source'],
        [/destination|itself|address/i, 'destinations'],
      ],
    ),
  );
  const edit = (next: FormState) => {
    saving.clear();
    setForm(next);
  };
  const [removing, setRemoving] = useState<Alias | null>(null);

  const destinations = (form?.destinations ?? '').split(/[,\n]/).map((s) => s.trim()).filter(Boolean);
  const sourceError = form && form.id === undefined && form.source ? validators.email(form.source) : '';
  const destinationError = destinations.find((d) => validators.email(d)) ? t('Every destination must be a valid e-mail address') : '';
  const valid = Boolean(form && form.source && !sourceError && destinations.length > 0 && !destinationError);

  async function save() {
    if (!form || !valid) return;
    const ok = await saving.run(() => (form.id === undefined ? post('/api/aliases', { source: form.source.trim(), destinations }) : patch(`/api/aliases/${form.id}`, { destinations })));
    if (ok) {
      notify(form.id === undefined ? t('Alias created') : t('Alias updated'));
      setForm(null);
      await reload();
    }
  }

  return (
    <>
      <PageHeader title={t('Aliases')}>
        <Button variant="contained" startIcon={<Add />} onClick={() => edit({ source: '', destinations: '' })}>
          {t('Add alias')}
        </Button>
      </PageHeader>
      {error && <Alert severity="error">{error}</Alert>}
      {!form && feedback}
      <ScrollTable size="small" aria-label={t('Aliases')}>
        <TableHead>
          <TableRow>
            <TableCell>{t('Alias')}</TableCell>
            <TableCell>{t('Delivers to')}</TableCell>
            <TableCell sx={{ width: 200 }}>
              <Tooltip title={t('Copies sent on to other servers over the last hour; beyond the limit, further mail to the alias is deferred')}>
                <span>{t('Forwarding')}</span>
              </Tooltip>
            </TableCell>
            <TableCell>{t('Enabled')}</TableCell>
            <TableCell />
          </TableRow>
        </TableHead>
        <TableBody>
          {(data ?? []).map((alias) => (
            <TableRow key={alias.id} hover>
              <TableCell>{alias.source}</TableCell>
              <TableCell>{alias.destinations.join(', ')}</TableCell>
              <TableCell data-sort={alias.forwarded / alias.forward_limit}>
                <UsageBar label={t('Copies')} used={alias.forwarded} limit={alias.forward_limit} />
              </TableCell>
              <TableCell>
                <Switch
                  checked={alias.enabled}
                  slotProps={{ input: { 'aria-label': t('Enabled {{source}}', { source: alias.source }) } }}
                  onChange={async (e) => {
                    if (await run(() => patch(`/api/aliases/${alias.id}`, { enabled: e.target.checked }))) await reload();
                  }}
                />
              </TableCell>
              <TableCell align="right" sx={{ whiteSpace: 'nowrap' }}>
                <Tooltip title={t('Edit')}>
                  <IconButton aria-label={t('Edit {{source}}', { source: alias.source })} onClick={() => edit({ id: alias.id, source: alias.source, destinations: alias.destinations.join(', ') })}>
                    <Edit />
                  </IconButton>
                </Tooltip>
                <Tooltip title={t('Delete')}>
                  <IconButton aria-label={t('Delete {{source}}', { source: alias.source })} onClick={() => setRemoving(alias)}>
                    <Delete />
                  </IconButton>
                </Tooltip>
              </TableCell>
            </TableRow>
          ))}
        </TableBody>
      </ScrollTable>
      <Dialog open={Boolean(form)} onClose={() => setForm(null)} fullWidth maxWidth="sm">
        <DialogTitle>{form?.id === undefined ? t('Add alias') : t('Edit {{source}}', { source: form.source })}</DialogTitle>
        {form && (
          <DialogContent>
            {saving.formError}
            <Stack spacing={2} sx={{ mt: 1 }}>
              {form.id === undefined && (
                <TextField
                  label={t('Alias address')}
                  value={form.source}
                  onChange={(e) => edit({ ...form, source: e.target.value })}
                  error={Boolean(sourceError || saving.fieldError('source'))}
                  helperText={sourceError || saving.fieldError('source')}
                  autoFocus
                />
              )}
              <TextField
                label={t('Destinations')}
                value={form.destinations}
                onChange={(e) => edit({ ...form, destinations: e.target.value })}
                multiline
                minRows={2}
                error={Boolean((form.destinations && destinationError) || saving.fieldError('destinations'))}
                helperText={(form.destinations && destinationError) || saving.fieldError('destinations') || t('Comma separated. External addresses are forwarded with SRS.')}
              />
            </Stack>
          </DialogContent>
        )}
        <DialogButtons onCancel={() => setForm(null)} onConfirm={() => void save()} disabled={!valid || saving.busy} />
      </Dialog>
      <ConfirmDialog
        open={Boolean(removing)}
        title={t('Delete {{source}}?', { source: removing?.source ?? '' })}
        text={t('Mail sent to this address will be rejected.')}
        onClose={() => setRemoving(null)}
        onConfirm={async () => {
          const target = removing;
          setRemoving(null);
          if (target && (await run(() => del(`/api/aliases/${target.id}`), t('Alias deleted')))) await reload();
        }}
      />
    </>
  );
}
