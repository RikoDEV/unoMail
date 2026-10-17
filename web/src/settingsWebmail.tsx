// Settings of the web client itself: sender identities, response templates, the skin and
// OpenPGP encryption.

import Check from '@mui/icons-material/Check';
import Delete from '@mui/icons-material/Delete';
import Edit from '@mui/icons-material/Edit';
import {
  Alert, Box, Button, Card, CardContent, Checkbox, Chip, Dialog, DialogActions, DialogContent, DialogTitle, FormControlLabel, IconButton, MenuItem, Stack, Switch, Table,
  LinearProgress, TableBody, TableCell, TableHead, TableRow, TextField, Typography,
} from '@mui/material';
import { type ReactNode, useCallback, useEffect, useState } from 'react';
import { SEEDS, useAppearance, useAuth } from './app';
import { blockSender, CATEGORIES, categoryLearning, type CategoryLearning, deleteIdentity, deleteTemplate, type Identity, type IdentityInput, listBlockedSenders, listIdentities, listTemplates, resetCategoryLearning, resetSpamFilter, saveIdentity, saveTemplate, spamFilterState, type SpamFilterState, type Template, unblockSender } from './mail/extra';
import { updatePrefs, usePrefs } from './prefs';
import { get, put, errorText } from './api';
import { type CertInfo, fetchSmime, importSmime, removeSmime } from './mail/Smime';
import { disableNotifications, enableNotifications, notificationsEnabled, notificationsSupported } from './mail/notifications';
import { htmlToText } from './mail/jmapClient';
import { persistentCacheEnabled, setPersistentCache } from './mail/cache';
import { fetchKeys, fingerprint, generateKeys, importKeys, isUnlocked, localPrivateKey, lock, removeKeys, type StoredKeys, unlock } from './mail/pgp';
import { escapeHtml } from './mail/sanitize';
import { BUILT_IN_SKINS, skinIsDark } from './skins';

import { chosenLanguage, LANGUAGES, setLanguage, t, uiLocale } from './i18n';
import { useList } from './useLoad';
/** Plain text typed into a settings field, as the HTML that is stored. */
const textToStoredHtml = (text: string) => (text.trim() ? escapeHtml(text.trim()).replace(/\n/g, '<br>') : '');

/** A settings card listing things the user adds, edits and deletes. */
export function ListCard({ title, addLabel, onAdd, error, onDismiss, children }: { title: string; addLabel: string; onAdd: () => void; error: string; onDismiss: () => void; children: ReactNode }) {
  return (
    <Card variant="outlined">
      <CardContent>
        <Stack direction="row" alignItems="center" sx={{ mb: 1 }}>
          <Typography variant="h6" sx={{ flex: 1 }}>
            {title}
          </Typography>
          <Button onClick={onAdd}>{addLabel}</Button>
        </Stack>
        {error && <Alert severity="error" onClose={onDismiss} sx={{ mb: 1 }}>{error}</Alert>}
        {children}
      </CardContent>
    </Card>
  );
}

/** The edit and delete buttons at the end of a row; deleting asks first. Without `onDelete` there is no delete button. */
export function RowActions({ editLabel, onEdit, deleteLabel, confirm, onDelete }: { editLabel: string; onEdit: () => void; deleteLabel?: string; confirm?: string; onDelete?: () => void }) {
  return (
    <TableCell align="right" sx={{ whiteSpace: 'nowrap' }}>
      <IconButton size="small" aria-label={editLabel} onClick={onEdit}>
        <Edit fontSize="small" />
      </IconButton>
      {onDelete && (
        <IconButton size="small" aria-label={deleteLabel} onClick={() => (!confirm || window.confirm(confirm)) && onDelete()}>
          <Delete fontSize="small" />
        </IconButton>
      )}
    </TableCell>
  );
}

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
      <DialogActions>
        <Button onClick={() => onClose(false)}>{t('Cancel')}</Button>
        <Button variant="contained" onClick={() => void save()} disabled={!form.email.trim() || (form.external && (!form.host.trim() || !/^\d+$/.test(form.port)))}>
          {t('Save identity')}
        </Button>
      </DialogActions>
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
          {items.map((identity) => (
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
      <DialogActions>
        <Button onClick={() => onClose(false)}>{t('Cancel')}</Button>
        <Button variant="contained" onClick={() => void save()} disabled={!name.trim()}>
          {t('Save template')}
        </Button>
      </DialogActions>
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

/** Sending: the time to call a message back, and answering read receipt requests. */
export function SendingCard() {
  const prefs = usePrefs();
  return (
    <Card variant="outlined">
      <CardContent>
        <Typography variant="h6" sx={{ mb: 2 }}>
          {t('Sending')}
        </Typography>
        <Stack spacing={2} sx={{ maxWidth: 420 }}>
          <TextField select label={t('Undo send')} value={prefs.undo_send_seconds ?? 5} onChange={(e) => void updatePrefs({ undo_send_seconds: Number(e.target.value) }).catch(() => {})} helperText={t('How long a sent message can be called back')}>
            {[0, 5, 10, 20, 30].map((seconds) => (
              <MenuItem key={seconds} value={seconds}>{seconds === 0 ? t('Off') : t('{{count}} seconds', { count: seconds })}</MenuItem>
            ))}
          </TextField>
          <TextField select label={t('Read receipts')} value={prefs.receipts ?? 'ask'} onChange={(e) => void updatePrefs({ receipts: e.target.value as 'ask' | 'always' | 'never' }).catch(() => {})} helperText={t('When a sender asks to be told that you read their message')}>
            <MenuItem value="ask">{t('Ask me each time')}</MenuItem>
            <MenuItem value="always">{t('Always send one')}</MenuItem>
            <MenuItem value="never">{t('Never send one')}</MenuItem>
          </TextField>
        </Stack>
      </CardContent>
    </Card>
  );
}

/** The user's S/MIME certificate: signing and encrypting mail, reading encrypted mail. */
export function SmimeCard() {
  const [certificate, setCertificate] = useState<CertInfo | null | undefined>(undefined);
  const [known, setKnown] = useState(0);
  const [file, setFile] = useState<File | null>(null);
  const [password, setPassword] = useState('');
  const [error, setError] = useState('');
  const [busy, setBusy] = useState(false);
  useEffect(() => {
    fetchSmime().then((s) => { setCertificate(s.certificate); setKnown(s.correspondents.length); }, (e: Error) => setError(e.message));
  }, []);
  const day = (seconds: number) => new Date(seconds * 1000).toLocaleDateString(uiLocale());
  return (
    <Card variant="outlined">
      <CardContent>
        <Typography variant="h6" sx={{ mb: 1 }}>
          {t('S/MIME certificate')}
        </Typography>
        <Stack spacing={2} sx={{ maxWidth: 640 }}>
          <Typography variant="body2" color="text.secondary">
            {t('With a personal certificate (from your organisation or a certificate authority) your mail can be signed and encrypted with S/MIME, the standard built into Outlook, Apple Mail and Thunderbird. The private key is stored on this server, sealed with its key; the server uses it to sign what you send and to decrypt mail encrypted to you when you read it.')}
          </Typography>
          {error && <Alert severity="error" onClose={() => setError('')}>{error}</Alert>}
          {certificate === undefined ? null : certificate ? (
            <>
              <Box>
                <Typography>{certificate.emails.join(', ')}</Typography>
                <Typography variant="body2" color="text.secondary">{t('Issued by {{issuer}}', { issuer: certificate.issuer })}</Typography>
                <Typography variant="body2" color="text.secondary">{t('Valid until {{not_after}}', { not_after: day(certificate.not_after) })}</Typography>
                <Typography variant="caption" sx={{ fontFamily: 'monospace', wordBreak: 'break-all' }}>{certificate.fingerprint}</Typography>
              </Box>
              <Typography variant="body2" color="text.secondary">
                {t('Certificates of {{count}} correspondents are known, collected from their signed mail; you can encrypt mail to them.', { count: known })}
              </Typography>
              <Box>
                <Button color="error" onClick={() => window.confirm(t('Remove your S/MIME certificate? Mail encrypted to it can no longer be read here.')) && void removeSmime().then(() => setCertificate(null), (e: Error) => setError(e.message))}>
                  {t('Remove certificate')}
                </Button>
              </Box>
            </>
          ) : (
            <Stack direction={{ xs: 'column', sm: 'row' }} spacing={1} alignItems={{ sm: 'center' }}>
              <Button variant="outlined" component="label">
                {file ? file.name : t('Choose .p12 / .pfx file')}
                <input hidden type="file" accept=".p12,.pfx,application/x-pkcs12" aria-label={t('Certificate file')} onChange={(e) => setFile(e.target.files?.[0] ?? null)} />
              </Button>
              <TextField size="small" type="password" label={t('File password')} autoComplete="off" value={password} onChange={(e) => setPassword(e.target.value)} />
              <Button
                variant="contained"
                disabled={!file || busy}
                onClick={async () => {
                  if (!file) return;
                  setBusy(true);
                  setError('');
                  try {
                    setCertificate(await importSmime(file, password));
                    setPassword('');
                  } catch (err) {
                    setError(errorText(err, t('The certificate could not be imported')));
                  } finally {
                    setBusy(false);
                  }
                }}
              >
                {t('Import')}
              </Button>
            </Stack>
          )}
        </Stack>
      </CardContent>
    </Card>
  );
}

/** New-mail notifications in this browser, through Web Push. */
export function NotificationsCard() {
  const { account } = useAuth();
  const email = account?.email ?? '';
  const [enabled, setEnabled] = useState<boolean | null>(null);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState('');
  useEffect(() => {
    notificationsEnabled(email).then(setEnabled, () => setEnabled(false));
  }, [email]);
  const toggle = async (on: boolean) => {
    setBusy(true);
    setError('');
    try {
      await (on ? enableNotifications(email) : disableNotifications(email));
      setEnabled(on);
    } catch (err) {
      setError(errorText(err, t('Notifications could not be changed')));
    } finally {
      setBusy(false);
    }
  };
  return (
    <Card variant="outlined">
      <CardContent>
        <Typography variant="h6" sx={{ mb: 1 }}>
          {t('Notifications')}
        </Typography>
        {notificationsSupported() ? (
          <FormControlLabel
            control={<Switch checked={Boolean(enabled)} disabled={busy || enabled === null} onChange={(e) => void toggle(e.target.checked)} inputProps={{ 'aria-label': t('Notify me of new mail') }} />}
            label={t('Notify me of new mail in this browser, also when unoMail is closed')}
          />
        ) : (
          <Typography color="text.secondary">{t('This browser cannot show notifications.')}</Typography>
        )}
        {error && <Alert severity="error" sx={{ mt: 1 }} onClose={() => setError('')}>{error}</Alert>}
      </CardContent>
    </Card>
  );
}

// --- Appearance ----------------------------------------------------------------------------

/** How the message list shows conversations; the same next to an open conversation as without. */
export function MessageListCard() {
  const [offline, setOffline] = useState(persistentCacheEnabled);
  const prefs = usePrefs();
  const density = prefs.density ?? 'condensed';
  const options: { value: 'condensed' | 'expanded'; title: string; text: string }[] = [
    { value: 'condensed', title: t('Condensed'), text: t('One line per conversation: sender, subject and the start of the text.') },
    { value: 'expanded', title: t('Expanded'), text: t('Sender picture, subject and text on separate lines, and the attached files.') },
  ];
  return (
    <Card variant="outlined">
      <CardContent>
        <Typography variant="h6" sx={{ mb: 1 }}>
          {t('Message list')}
        </Typography>
        <Stack direction={{ xs: 'column', sm: 'row' }} gap={1.5} role="radiogroup" aria-label={t('Message list density')}>
          {options.map((option) => (
            <Box
              key={option.value}
              component="button"
              type="button"
              role="radio"
              aria-checked={density === option.value}
              onClick={() => void updatePrefs({ density: option.value }).catch(() => {})}
              sx={{ flex: 1, maxWidth: 340, p: 1.5, textAlign: 'left', font: 'inherit', color: 'text.primary', bgcolor: 'background.paper', cursor: 'pointer', borderRadius: 2, border: 2, borderColor: density === option.value ? 'primary.main' : 'divider' }}
            >
              {/* A small drawing of a list row in this style. */}
              <Box aria-hidden sx={{ mb: 1, p: 1, borderRadius: 1, bgcolor: 'action.hover', display: 'flex', gap: 1, alignItems: option.value === 'expanded' ? 'flex-start' : 'center' }}>
                <Box sx={{ width: option.value === 'expanded' ? 24 : 14, height: option.value === 'expanded' ? 24 : 14, borderRadius: '50%', bgcolor: 'secondary.main', flexShrink: 0 }} />
                {option.value === 'expanded' ? (
                  <Stack spacing={0.5} sx={{ flex: 1 }}>
                    <Box sx={{ height: 6, width: '40%', bgcolor: 'text.primary', opacity: 0.6, borderRadius: 1 }} />
                    <Box sx={{ height: 6, width: '85%', bgcolor: 'text.secondary', opacity: 0.5, borderRadius: 1 }} />
                    <Box sx={{ height: 12, width: 64, border: 1, borderColor: 'text.secondary', opacity: 0.6, borderRadius: 2 }} />
                  </Stack>
                ) : (
                  <Stack direction="row" spacing={1} sx={{ flex: 1 }}>
                    <Box sx={{ height: 6, width: '25%', bgcolor: 'text.primary', opacity: 0.6, borderRadius: 1 }} />
                    <Box sx={{ height: 6, flex: 1, bgcolor: 'text.secondary', opacity: 0.5, borderRadius: 1 }} />
                  </Stack>
                )}
              </Box>
              <Typography fontWeight={600}>{option.title}</Typography>
              <Typography variant="body2" color="text.secondary">{option.text}</Typography>
            </Box>
          ))}
        </Stack>
        <FormControlLabel control={<Switch checked={offline} onChange={(_, enabled) => { setPersistentCache(enabled); setOffline(enabled); }} />} label="Keep mail offline on this trusted device" />
        <Typography variant="body2" color="text.secondary">Off by default. Cached messages are stored unencrypted in this browser and removed on sign-out.</Typography>
      </CardContent>
    </Card>
  );
}

/** The interface language, stored with the account so it follows the user between devices. */
export function LanguageCard() {
  const [value, setValue] = useState(chosenLanguage() ?? '');
  async function choose(code: string) {
    setValue(code);
    await updatePrefs({ language: code }).catch(() => {});
    setLanguage(code || null);
  }
  return (
    <Card variant="outlined">
      <CardContent>
        <Typography variant="h6" sx={{ mb: 1 }}>
          {t('Language')}
        </Typography>
        <TextField select label={t('Interface language')} value={value} onChange={(e) => void choose(e.target.value)} sx={{ minWidth: 260 }}>
          <MenuItem value="">{t('Automatic (browser language)')}</MenuItem>
          {LANGUAGES.map((language) => (
            <MenuItem key={language.code} value={language.code} lang={language.code}>
              {language.name}
            </MenuItem>
          ))}
        </TextField>
      </CardContent>
    </Card>
  );
}

/** The nearest ancestor that scrolls, or the page. */
function scrollParent(element: HTMLElement): HTMLElement {
  for (let node = element.parentElement; node; node = node.parentElement) {
    if (/(auto|scroll)/.test(getComputedStyle(node).overflowY) && node.scrollHeight > node.clientHeight) return node;
  }
  return (document.scrollingElement as HTMLElement | null) ?? document.documentElement;
}

/**
 * Applies a change that restyles the whole page (another skin brings other spacing and fonts)
 * while keeping the control that was clicked where it is on screen, so the page does not jump.
 */
function keepInPlace(element: HTMLElement, change: () => void) {
  const before = element.getBoundingClientRect().top;
  const scroller = scrollParent(element);
  change();
  // A few frames: the new styles apply on the next render, a skin's font may come a little later.
  const settle = (frames: number) =>
    requestAnimationFrame(() => {
      const target = scroller.scrollTop + element.getBoundingClientRect().top - before;
      // Near the end of the page a shorter skin leaves too little to scroll; room is added below
      // (until the settings section is left), rather than letting the page pull the control down.
      scroller.style.removeProperty('padding-bottom');
      const missing = target - (scroller.scrollHeight - scroller.clientHeight);
      if (missing > 0) {
        scroller.style.paddingBottom = `${parseFloat(getComputedStyle(scroller).paddingBottom) + missing}px`;
        scroller.dataset.keptRoom = 'true';
      }
      scroller.scrollTop = target;
      if (frames > 1) settle(frames - 1);
    });
  settle(4);
}

/** Takes back the room added by keepInPlace. */
function releaseKeptRoom() {
  document.querySelectorAll<HTMLElement>('[data-kept-room]').forEach((element) => {
    element.style.removeProperty('padding-bottom');
    delete element.dataset.keptRoom;
  });
}

export function AppearanceCard() {
  const { skin, skins, setSkin, seed, setSeed } = useAppearance();
  useEffect(() => releaseKeptRoom, []);
  // Skins with a colour scheme of their own ignore the accent colour.
  const takesAccent = !skin.primary;
  return (
    <Card variant="outlined">
      <CardContent>
        <Typography variant="h6" sx={{ mb: 1 }}>
          {t('Appearance')}
        </Typography>
        <Typography variant="body2" color="text.secondary" sx={{ mb: 2 }}>
          {t('Choose a skin. Light and dark mode are in the account menu.')}
        </Typography>
        <Stack direction="row" flexWrap="wrap" gap={1.5} role="radiogroup" aria-label={t('Skin')}>
          {skins.map((candidate) => {
            const dark = skinIsDark(candidate, false);
            const custom = !BUILT_IN_SKINS.some((builtIn) => builtIn.id === candidate.id);
            return (
              <Box
                key={candidate.id}
                component="button"
                role="radio"
                aria-checked={candidate.id === skin.id}
                onClick={(event) => keepInPlace(event.currentTarget, () => setSkin(candidate.id))}
                sx={{
                  width: 132, p: 1, cursor: 'pointer', textAlign: 'left', font: 'inherit', color: candidate.text ?? (dark ? '#e6e0e9' : '#1d1b20'),
                  bgcolor: candidate.background ?? (dark ? '#141218' : '#f7f2fa'), borderRadius: `${Math.min(candidate.radius ?? 16, 16)}px`,
                  border: 2, borderColor: candidate.id === skin.id ? 'primary.main' : 'divider',
                }}
              >
                <Box sx={{ height: 28, mb: 0.5, bgcolor: candidate.paper ?? (dark ? '#1d1b20' : '#fffbfe'), borderRadius: `${Math.min(candidate.radius ?? 16, 12)}px`, display: 'flex', alignItems: 'center', px: 1 }}>
                  <Box sx={{ width: 36, height: 10, bgcolor: candidate.primary ?? 'primary.main', borderRadius: `${Math.min(candidate.radius ?? 16, 5)}px` }} />
                </Box>
                <Typography variant="body2" fontWeight={600} noWrap>
                  {candidate.name}
                </Typography>
                {custom && <Typography variant="caption">{t('Custom')}</Typography>}
              </Box>
            );
          })}
        </Stack>
        {takesAccent && (
          <Box sx={{ mt: 3 }}>
            <Typography variant="subtitle1" fontWeight={600}>
              {t('Accent colour')}
            </Typography>
            <Typography variant="body2" color="text.secondary" sx={{ mb: 1.5 }}>
              {t('The colour of buttons, links and highlights. The interface builds its shades from it.')}
            </Typography>
            <Stack direction="row" flexWrap="wrap" useFlexGap gap={1.5} role="group" aria-label={t('Accent colour')}>
              {SEEDS.map((color) => (
                <Box
                  key={color}
                  component="button"
                  aria-label={t('Accent colour {{color}}', { color })}
                  aria-pressed={color === seed}
                  onClick={() => setSeed(color)}
                  sx={{
                    width: 36, height: 36, p: 0, border: 0, borderRadius: '50%', bgcolor: color, color: '#fff', cursor: 'pointer', display: 'grid', placeItems: 'center',
                    outline: color === seed ? '2px solid' : 'none', outlineColor: color, outlineOffset: 3, transition: 'transform 120ms',
                    '&:hover': { transform: 'scale(1.08)' },
                    '&:focus-visible': { outline: '2px solid', outlineColor: 'text.primary', outlineOffset: 3 },
                  }}
                >
                  {color === seed && <Check fontSize="small" />}
                </Box>
              ))}
            </Stack>
          </Box>
        )}
      </CardContent>
    </Card>
  );
}

// --- Encryption ----------------------------------------------------------------------------

function download(name: string, content: string) {
  const url = URL.createObjectURL(new Blob([content], { type: 'application/pgp-keys' }));
  const link = document.createElement('a');
  link.href = url;
  link.download = name;
  link.click();
  setTimeout(() => URL.revokeObjectURL(url), 1000);
}

interface AtRest {
  enabled: boolean;
  key: { fingerprint: string } | null;
  problem: string | null;
}

/** Storing incoming mail encrypted to the account's public key (encryption at rest). */
function EncryptIncoming() {
  const [state, setState] = useState<AtRest | null>(null);
  const [error, setError] = useState('');
  useEffect(() => {
    get<AtRest>('/api/me/pgp/encryption').then(setState, (e: Error) => setError(e.message));
  }, []);
  if (!state) return error ? <Alert severity="error">{error}</Alert> : null;
  const toggle = (enabled: boolean) => put<AtRest>('/api/me/pgp/encryption', { enabled }).then(setState, (e: Error) => setError(e.message));
  return (
    <Box>
      <FormControlLabel
        control={<Switch checked={state.enabled} onChange={(e) => void toggle(e.target.checked)} inputProps={{ 'aria-label': t('Store incoming mail encrypted') }} />}
        label={t('Store incoming mail encrypted to this key')}
      />
      <Typography variant="caption" color="text.secondary" component="div">
        {t('New messages are encrypted on arrival, before they are stored. Only you can read them, here after unlocking the key or in any mail program that has your private key; search covers their subject and senders only. Messages already stored are not changed.')}
      </Typography>
      {state.problem && <Alert severity="warning" sx={{ mt: 1 }}>{t('This key cannot be used for it: {{problem}}', { problem: state.problem })}</Alert>}
      {error && <Alert severity="error" sx={{ mt: 1 }} onClose={() => setError('')}>{error}</Alert>}
    </Box>
  );
}

export function EncryptionCard() {
  const { account } = useAuth();
  const email = account?.email ?? '';
  const [keys, setKeys] = useState<StoredKeys | null | undefined>(undefined);
  const [print, setPrint] = useState('');
  const [mode, setMode] = useState<'idle' | 'generate' | 'import'>('idle');
  const [passphrase, setPassphrase] = useState('');
  const [repeat, setRepeat] = useState('');
  const [imported, setImported] = useState('');
  const [keepOnServer, setKeepOnServer] = useState(true);
  const [unlockWith, setUnlockWith] = useState('');
  const [unlocked, setUnlocked] = useState(isUnlocked());
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState('');
  const [notice, setNotice] = useState('');

  const reload = useCallback(async () => {
    try {
      const stored = await fetchKeys();
      setKeys(stored);
      setPrint(stored ? await fingerprint(stored.public_key) : '');
    } catch {
      setKeys(null);
    }
  }, []);
  useEffect(() => {
    void reload();
  }, [reload]);

  async function run(action: () => Promise<void>, done: string) {
    setBusy(true);
    setError('');
    setNotice('');
    try {
      await action();
      setNotice(done);
      setMode('idle');
      setPassphrase('');
      setRepeat('');
      setImported('');
      setUnlockWith('');
      setUnlocked(isUnlocked());
      await reload();
    } catch (err) {
      setError(errorText(err, t('The operation failed')));
    } finally {
      setBusy(false);
    }
  }

  const privateKey = keys?.private_key || localPrivateKey(email);
  return (
    <Card variant="outlined">
      <CardContent>
        <Typography variant="h6" sx={{ mb: 1 }}>
          {t('Encryption (OpenPGP)')}
        </Typography>
        <Stack spacing={2} sx={{ maxWidth: 640 }}>
          {error && <Alert severity="error" onClose={() => setError('')}>{error}</Alert>}
          {notice && <Alert severity="success" onClose={() => setNotice('')}>{notice}</Alert>}
          <Typography variant="body2" color="text.secondary">
            {t("Encrypted messages are encrypted and decrypted in your browser. The server stores your public key so that colleagues can write to you, and your private key only in its passphrase-protected form, if you choose so. Without the passphrase nobody, including the server's administrator, can read your encrypted mail; if you lose it, neither can you.")}
          </Typography>
          {keys === undefined ? null : keys ? (
            <>
              <Box>
                <Typography variant="body2">{t('Key fingerprint')}</Typography>
                <Typography sx={{ fontFamily: 'monospace', wordBreak: 'break-all' }} data-testid="pgp-fingerprint">
                  {print}
                </Typography>
                <Typography variant="caption" color="text.secondary">
                  {keys.private_key ? t('The protected private key is stored on the server and available on every device.') : privateKey ? t('The private key is kept in this browser only.') : t('The private key is not available on this device.')}
                </Typography>
              </Box>
              <EncryptIncoming key={keys.public_key} />
              {privateKey &&
                (unlocked ? (
                  <Stack direction="row" spacing={1} alignItems="center">
                    <Chip color="success" label={t('Unlocked for this session')} />
                    <Button onClick={() => { lock(); setUnlocked(false); }}>{t('Lock')}</Button>
                  </Stack>
                ) : (
                  <Stack direction="row" spacing={1} alignItems="flex-start">
                    <TextField label={t('Passphrase')} type="password" autoComplete="off" value={unlockWith} onChange={(e) => setUnlockWith(e.target.value)} />
                    <Button variant="outlined" disabled={busy || !unlockWith} onClick={() => void run(() => unlock(privateKey, unlockWith), t('Key unlocked: messages you send are signed and encrypted mail can be read'))}>
                      {t('Unlock key')}
                    </Button>
                  </Stack>
                ))}
              <Stack direction="row" spacing={1} flexWrap="wrap" useFlexGap>
                <Button onClick={() => download(`${email}-public.asc`, keys.public_key)}>{t('Export public key')}</Button>
                {privateKey && <Button onClick={() => download(`${email}-private.asc`, privateKey)}>{t('Back up private key')}</Button>}
                <Button color="error" disabled={busy} onClick={() => window.confirm(t('Remove your keys? Mail encrypted to this key can no longer be read unless you kept a backup.')) && void run(() => removeKeys(email), t('Keys removed'))}>
                  {t('Remove keys')}
                </Button>
              </Stack>
            </>
          ) : mode === 'idle' ? (
            <Stack direction="row" spacing={1}>
              <Button variant="contained" onClick={() => setMode('generate')}>
                {t('Create a key')}
              </Button>
              <Button onClick={() => setMode('import')}>{t('Import an existing key')}</Button>
            </Stack>
          ) : (
            <Stack spacing={2}>
              {mode === 'generate' ? (
                <>
                  <TextField label={t('New passphrase')} type="password" autoComplete="new-password" value={passphrase} onChange={(e) => setPassphrase(e.target.value)} error={Boolean(passphrase) && passphrase.length < 10} helperText={t('At least 10 characters. It cannot be recovered.')} />
                  <TextField label={t('Repeat passphrase')} type="password" autoComplete="new-password" value={repeat} onChange={(e) => setRepeat(e.target.value)} error={Boolean(repeat) && repeat !== passphrase} />
                </>
              ) : (
                <TextField
                  label={t('Private key')}
                  value={imported}
                  onChange={(e) => setImported(e.target.value)}
                  multiline
                  minRows={4}
                  maxRows={10}
                  placeholder="-----BEGIN PGP PRIVATE KEY BLOCK-----"
                  helperText={t('The key must be protected with a passphrase')}
                  slotProps={{ htmlInput: { spellCheck: false, style: { fontFamily: 'monospace', fontSize: 12 } } }}
                />
              )}
              <FormControlLabel control={<Switch checked={keepOnServer} onChange={(e) => setKeepOnServer(e.target.checked)} />} label={t('Keep the passphrase-protected key on the server, so it works on all my devices')} />
              <Stack direction="row" spacing={1}>
                {mode === 'generate' ? (
                  <Button variant="contained" disabled={busy || passphrase.length < 10 || passphrase !== repeat} onClick={() => void run(() => generateKeys(account?.display_name ?? '', email, passphrase, keepOnServer).then(() => undefined), t('Your key was created'))}>
                    {t('Create key')}
                  </Button>
                ) : (
                  <Button variant="contained" disabled={busy || !imported.trim()} onClick={() => void run(() => importKeys(email, imported, keepOnServer), t('Your key was imported'))}>
                    {t('Import key')}
                  </Button>
                )}
                <Button onClick={() => setMode('idle')}>{t('Cancel')}</Button>
              </Stack>
            </Stack>
          )}
        </Stack>
      </CardContent>
    </Card>
  );
}

// --- Inbox ---------------------------------------------------------------------------------

/** What the inbox categories learned from the user's corrections, and a way to reset it. */
function CategoryLearningSection() {
  const [state, setState] = useState<CategoryLearning | null>(null);
  const [confirm, setConfirm] = useState(false);
  const load = useCallback(() => void categoryLearning().then(setState).catch(() => setState(null)), []);
  useEffect(load, [load]);
  if (!state) return null;
  const known = CATEGORIES.filter((category) => state.learned[category.id] >= state.needed);
  return (
    <Box data-testid="category-learning" sx={{ pl: 6 }}>
      <Typography variant="body2" color="text.secondary">
        {t('The categories learn from you: move a message to another category and new mail from its sender goes there too. After {{needed}} corrections into each of two categories, mail from new senders is sorted by what it resembles.', { needed: state.needed })}
      </Typography>
      {state.total > 0 && (
        <Typography variant="body2" sx={{ mt: 0.5 }}>
          {t('Moved messages learned from: {{messages}}. Senders remembered: {{senders}}.', { messages: state.total, senders: state.senders })}{' '}
          {known.length >= 2 && t('Sorting by content between: {{list}}.', { list: known.map((category) => category.label).join(', ') })}
        </Typography>
      )}
      {state.total > 0 && (
        <Button color="error" size="small" sx={{ mt: 0.5 }} onClick={() => setConfirm(true)}>
          {t('Forget what it learned')}
        </Button>
      )}
      <Dialog open={confirm} onClose={() => setConfirm(false)}>
        <DialogTitle>{t('Reset the inbox categories?')}</DialogTitle>
        <DialogContent>{t('New mail is sorted by the built-in rules again. Messages already in your inbox keep their category.')}</DialogContent>
        <DialogActions>
          <Button onClick={() => setConfirm(false)}>{t('Cancel')}</Button>
          <Button color="error" onClick={() => void resetCategoryLearning().then(() => { setConfirm(false); load(); })}>{t('Reset')}</Button>
        </DialogActions>
      </Dialog>
    </Box>
  );
}

/** What the personal spam filter has learned from the user's reports, and a way to reset it. */
function SpamFilterSection() {
  const [state, setState] = useState<SpamFilterState | null>(null);
  const [confirm, setConfirm] = useState(false);
  const load = useCallback(() => void spamFilterState().then(setState).catch(() => setState(null)), []);
  useEffect(load, [load]);
  if (!state) return null;
  const progress = Math.round((100 * (Math.min(state.spam, state.needed) + Math.min(state.ham, state.needed))) / (2 * state.needed));
  return (
    <Box data-testid="spam-filter">
      <Typography variant="subtitle1" fontWeight={600}>
        {t('Personal spam filter')}
      </Typography>
      <Typography variant="body2" color="text.secondary" sx={{ mb: 1 }}>
        {t('It learns from you: “Report spam” teaches it what you do not want; “Not spam”, your replies and mail from people you write to teach it what you do. Mail from your contacts is never filed away by it.')}
      </Typography>
      {!state.enabled ? (
        <Alert severity="info">{t('The administrator has turned the personal spam filter off.')}</Alert>
      ) : state.active ? (
        <Alert severity="success">{t('Active: new mail it is confident about goes to Junk. Learned from {{spam}} spam and {{ham}} wanted messages.', { spam: state.spam, ham: state.ham })}</Alert>
      ) : (
        <>
          <Typography variant="body2">
            {t('Still learning: {{spam}} of {{needed}} spam and {{ham}} of {{needed}} wanted messages seen. It starts sorting once it has seen enough of both.', { spam: state.spam, ham: state.ham, needed: state.needed })}
          </Typography>
          <LinearProgress variant="determinate" value={progress} sx={{ mt: 1, maxWidth: 360, height: 6, borderRadius: 3 }} aria-label={t('Spam filter training progress')} />
        </>
      )}
      {(state.spam > 0 || state.ham > 0) && (
        <Button color="error" sx={{ mt: 1 }} onClick={() => setConfirm(true)}>
          {t('Forget what it learned')}
        </Button>
      )}
      <Dialog open={confirm} onClose={() => setConfirm(false)}>
        <DialogTitle>{t('Reset the spam filter?')}</DialogTitle>
        <DialogContent>{t('It forgets every message it has learned from and starts again. Your mail is not changed.')}</DialogContent>
        <DialogActions>
          <Button onClick={() => setConfirm(false)}>{t('Cancel')}</Button>
          <Button color="error" onClick={() => void resetSpamFilter().then(() => { setConfirm(false); load(); })}>{t('Reset')}</Button>
        </DialogActions>
      </Dialog>
    </Box>
  );
}

export function InboxCard() {
  const prefs = usePrefs();
  const { items, error, setError, reload } = useList(listBlockedSenders);
  const [sender, setSender] = useState('');

  async function add() {
    try {
      await blockSender(sender);
      setSender('');
      await reload();
    } catch (err) {
      setError(errorText(err, t('The sender could not be blocked')));
    }
  }

  return (
    <Card variant="outlined">
      <CardContent>
        <Typography variant="h6" sx={{ mb: 1 }}>
          {t('Inbox')}
        </Typography>
        <Stack spacing={2} sx={{ maxWidth: 640 }}>
          <FormControlLabel
            control={<Switch checked={prefs.categories !== false} onChange={(e) => void updatePrefs({ categories: e.target.checked }).catch(() => {})} />}
            label={t('Sort the inbox into categories (General, Offers, Communities, Notifications, Forums)')}
          />
          {prefs.categories !== false && <CategoryLearningSection />}
          <SpamFilterSection />
          <Box>
            <Typography variant="subtitle1" fontWeight={600}>
              {t('Blocked senders')}
            </Typography>
            <Typography variant="body2" color="text.secondary" sx={{ mb: 1 }}>
              {t('Mail from these senders goes straight to Junk. The sender is not told. Enter an address, or @domain for everybody at a domain.')}
            </Typography>
            {error && <Alert severity="error" onClose={() => setError('')} sx={{ mb: 1 }}>{error}</Alert>}
            <Stack direction="row" spacing={1} alignItems="flex-start" sx={{ mb: 1 }}>
              <TextField label={t('Sender to block')} value={sender} onChange={(e) => setSender(e.target.value)} onKeyDown={(e) => e.key === 'Enter' && sender.trim() && void add()} placeholder={t('pest@example.com or @example.com')} fullWidth />
              <Button variant="outlined" disabled={!sender.trim()} onClick={() => void add()}>
                {t('Block')}
              </Button>
            </Stack>
            {items.length === 0 ? (
              <Typography color="text.secondary">{t('Nobody is blocked.')}</Typography>
            ) : (
              <Stack direction="row" flexWrap="wrap" gap={1} role="list" aria-label={t('Blocked senders')}>
                {items.map((entry) => (
                  <Chip key={entry} role="listitem" label={entry} onDelete={() => void unblockSender(entry).then(reload).catch((err) => setError(errorText(err, t('Could not unblock'))))} />
                ))}
              </Stack>
            )}
          </Box>
        </Stack>
      </CardContent>
    </Card>
  );
}
