// Sender identities and message templates.

import {
  Alert, Checkbox, Chip, Dialog, DialogContent, DialogTitle, FormControlLabel, MenuItem, Stack, Switch, Table,
  TableBody, TableCell, TableHead, TableRow, TextField, Typography,
} from '@mui/material';
import { useState } from 'react';
import { deleteIdentity, deleteTemplate, type Identity, type IdentityInput, listIdentities, listTemplates, saveIdentity, saveTemplate, type Template } from './mail/extra';
import { errorText } from './api';
import { htmlToText } from './mail/jmapClient';

import { t } from './i18n';
import { useList } from './useLoad';
import { DialogButtons } from './admin/common';
import { escapeHtml } from './mail/sanitize';
import { ListCard, RowActions } from './settingsParts';

const textToStoredHtml = (text: string) => (text.trim() ? escapeHtml(text.trim()).replace(/\n/g, '<br>') : '');

// --- Identities ----------------------------------------------------------------------------

interface IdentityForm {
  name: string;
  email: string;
  reply_to: string;
  is_default: boolean;
  external: boolean;
  host: string;
  port: string;
  security: string;
  username: string;
  password: string;
}

function IdentityDialog({ identity, onClose }: { identity: Identity | null; onClose: (saved: boolean) => void }) {
  const [form, setForm] = useState<IdentityForm>({
    name: identity?.name ?? '',
    email: identity?.email ?? '',
    reply_to: identity?.reply_to ?? '',
    is_default: identity?.is_default ?? false,
    external: Boolean(identity?.smtp),
    host: identity?.smtp?.host ?? '',
    port: String(identity?.smtp?.port ?? 465),
    security: identity?.smtp?.security ?? 'tls',
    username: identity?.smtp?.username ?? '',
    password: '',
  });
  const [error, setError] = useState('');
  const set = (changes: Partial<IdentityForm>) => setForm((current) => ({ ...current, ...changes }));

  async function save() {
    setError('');
    const input: IdentityInput = {
      name: form.name,
      email: form.email,
      reply_to: form.reply_to,
      is_default: form.is_default,
      smtp: form.external
        ? // An empty password field keeps the one that is already stored.
          { host: form.host, port: Number(form.port), security: form.security, username: form.username, ...(form.password ? { password: form.password } : {}) }
        : null,
    };
    try {
      await saveIdentity(identity?.id ?? 0, input);
      onClose(true);
    } catch (err) {
      setError(errorText(err, t('The identity could not be saved')));
    }
  }

  return (
    <Dialog open onClose={() => onClose(false)} fullWidth maxWidth="sm">
      <DialogTitle>{identity ? t('Edit identity') : t('New identity')}</DialogTitle>
      <DialogContent>
        <Stack spacing={2} sx={{ mt: 1 }}>
          {error && <Alert severity="error">{error}</Alert>}
          <TextField label={t('Display name')} value={form.name} onChange={(e) => set({ name: e.target.value })} autoFocus />
          <TextField label={t('E-mail address')} type="email" value={form.email} onChange={(e) => set({ email: e.target.value })} required helperText={t('Your own address or one of your aliases, unless you add an SMTP server below')} />
          <TextField label={t('Reply-to address')} value={form.reply_to} onChange={(e) => set({ reply_to: e.target.value })} />
          <FormControlLabel control={<Checkbox checked={form.is_default} onChange={(e) => set({ is_default: e.target.checked })} />} label={t('Use by default for new messages')} />
          <FormControlLabel control={<Switch checked={form.external} onChange={(e) => set({ external: e.target.checked })} />} label={t("Send through another provider's SMTP server")} />
          {form.external && (
            <>
              <Typography variant="body2" color="text.secondary">
                {t('Messages from this identity are handed to that server only. The password is stored encrypted and is never shown again.')}
              </Typography>
              <Stack direction="row" spacing={2}>
                <TextField label={t('SMTP host')} value={form.host} onChange={(e) => set({ host: e.target.value })} placeholder="smtp.provider.example" fullWidth />
                <TextField label={t('SMTP port')} value={form.port} onChange={(e) => set({ port: e.target.value })} sx={{ width: 110 }} />
                <TextField select label={t('Security')} value={form.security} onChange={(e) => set({ security: e.target.value, port: e.target.value === 'tls' ? '465' : '587' })} sx={{ width: 150 }}>
                  <MenuItem value="tls">TLS</MenuItem>
                  <MenuItem value="starttls">STARTTLS</MenuItem>
                </TextField>
              </Stack>
              <Stack direction="row" spacing={2}>
                <TextField label={t('SMTP user name')} value={form.username} onChange={(e) => set({ username: e.target.value })} autoComplete="off" fullWidth />
                <TextField label={t('SMTP password')} type="password" value={form.password} onChange={(e) => set({ password: e.target.value })} autoComplete="new-password" fullWidth helperText={identity?.smtp?.has_password ? t('Leave empty to keep the stored password') : ''} />
              </Stack>
            </>
          )}
        </Stack>
      </DialogContent>
      <DialogButtons onCancel={() => onClose(false)} onConfirm={() => void save()} disabled={!form.email.trim() || (form.external && (!form.host.trim() || !/^\d+$/.test(form.port)))} label={t('Save identity')} />
    </Dialog>
  );
}

export function IdentitiesCard() {
  const { items, error, setError, reload } = useList(listIdentities);
  const [editing, setEditing] = useState<Identity | null | undefined>(undefined);
  const remove = (id: number) => void deleteIdentity(id).then(reload).catch((err) => setError(errorText(err, t('Could not delete'))));
  return (
    <ListCard title={t('Sender identities')} addLabel={t('Add identity')} onAdd={() => setEditing(null)} error={error} onDismiss={() => setError('')}>
      <Table size="small" aria-label={t('Identities')}>
        <TableHead>
          <TableRow>
            <TableCell>{t('Name')}</TableCell>
            <TableCell>{t('Address')}</TableCell>
            <TableCell>{t('Sent through')}</TableCell>
            <TableCell />
          </TableRow>
        </TableHead>
        <TableBody>
          {items.filter((identity) => !identity.masked || identity.id > 0).map((identity) => (
            <TableRow key={`${identity.id}-${identity.email}`}>
              <TableCell>{identity.name || '—'}</TableCell>
              <TableCell>
                {identity.email} {identity.is_default && <Chip size="small" label={t('Default')} sx={{ ml: 0.5 }} />}
              </TableCell>
              <TableCell>{identity.smtp ? identity.smtp.host : t('This server')}</TableCell>
              <RowActions
                editLabel={t('Edit identity {{email}}', { email: identity.email })}
                onEdit={() => setEditing(identity)}
                // The account's own address (id 0) cannot be deleted.
                {...(identity.id !== 0 && {
                  deleteLabel: t('Delete identity {{email}}', { email: identity.email }),
                  confirm: t('Delete the identity {{email}}?', { email: identity.email }),
                  onDelete: () => remove(identity.id),
                })}
              />
            </TableRow>
          ))}
        </TableBody>
      </Table>
      {editing !== undefined && (
        <IdentityDialog
          identity={editing}
          onClose={(saved) => {
            setEditing(undefined);
            if (saved) void reload();
          }}
        />
      )}
    </ListCard>
  );
}

// --- Templates -----------------------------------------------------------------------------

function TemplateDialog({ template, onClose }: { template: Template | null; onClose: (saved: boolean) => void }) {
  const [name, setName] = useState(template?.name ?? '');
  const [subject, setSubject] = useState(template?.subject ?? '');
  const [body, setBody] = useState(template ? htmlToText(template.html) : '');
  const [error, setError] = useState('');

  async function save() {
    setError('');
    try {
      await saveTemplate(template?.id ?? 0, { name, subject, html: textToStoredHtml(body) });
      onClose(true);
    } catch (err) {
      setError(errorText(err, t('The template could not be saved')));
    }
  }

  return (
    <Dialog open onClose={() => onClose(false)} fullWidth maxWidth="sm">
      <DialogTitle>{template ? t('Edit template') : t('New template')}</DialogTitle>
      <DialogContent>
        <Stack spacing={2} sx={{ mt: 1 }}>
          {error && <Alert severity="error">{error}</Alert>}
          <TextField label={t('Template name')} value={name} onChange={(e) => setName(e.target.value)} autoFocus required />
          <TextField label={t('Template subject')} value={subject} onChange={(e) => setSubject(e.target.value)} helperText={t('Used when the message has no subject yet')} />
          <TextField label={t('Template text')} value={body} onChange={(e) => setBody(e.target.value)} multiline minRows={6} />
        </Stack>
      </DialogContent>
      <DialogButtons onCancel={() => onClose(false)} onConfirm={() => void save()} disabled={!name.trim()} label={t('Save template')} />
    </Dialog>
  );
}

export function TemplatesCard() {
  const { items, error, setError, reload } = useList(listTemplates);
  const [editing, setEditing] = useState<Template | null | undefined>(undefined);
  const remove = (id: number) => void deleteTemplate(id).then(reload).catch((err) => setError(errorText(err, t('Could not delete'))));
  return (
    <ListCard title={t('Response templates')} addLabel={t('Add template')} onAdd={() => setEditing(null)} error={error} onDismiss={() => setError('')}>
      {items.length === 0 ? (
        <Typography color="text.secondary">{t("No templates yet. Templates are inserted from the composer's toolbar.")}</Typography>
      ) : (
        <Table size="small" aria-label={t('Templates')}>
          <TableBody>
            {items.map((template) => (
              <TableRow key={template.id}>
                <TableCell>{template.name}</TableCell>
                <TableCell sx={{ color: 'text.secondary' }}>{template.subject}</TableCell>
                <RowActions
                  editLabel={t('Edit template {{name}}', { name: template.name })}
                  onEdit={() => setEditing(template)}
                  deleteLabel={t('Delete template {{name}}', { name: template.name })}
                  confirm={t('Delete the template “{{name}}”?', { name: template.name })}
                  onDelete={() => remove(template.id)}
                />
              </TableRow>
            ))}
          </TableBody>
        </Table>
      )}
      {editing !== undefined && (
        <TemplateDialog
          template={editing}
          onClose={(saved) => {
            setEditing(undefined);
            if (saved) void reload();
          }}
        />
      )}
    </ListCard>
  );
}

