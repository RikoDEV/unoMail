import Add from '@mui/icons-material/Add';
import ArrowBack from '@mui/icons-material/ArrowBack';
import Delete from '@mui/icons-material/Delete';
import Edit from '@mui/icons-material/Edit';
import Group from '@mui/icons-material/Group';
import Key from '@mui/icons-material/Key';
import People from '@mui/icons-material/People';
import Send from '@mui/icons-material/Send';
import {
  Alert, Box, Button, Checkbox, Dialog, DialogActions, DialogContent, DialogTitle, FormControlLabel, FormGroup, IconButton, List, ListItemButton, ListItemIcon, ListItemText, Paper,
  Snackbar, Stack, Table, TableBody, TableCell, TableHead, TableRow, TextField, Tooltip, Typography,
} from '@mui/material';
import { useCallback, useEffect, useRef, useState } from 'react';
import { useNavigate } from 'react-router-dom';
import { del, get, post, postRaw, put, errorText } from '../lib/api';
import type { Contact, ContactGroup } from '../mail/extra';
import { TopBar, useTitle } from '../ui/shell';

import { t } from '../i18n';
import { DialogButtons } from '../admin/common';
const EMPTY: Omit<Contact, 'id'> = { name: '', email: '', phone: '', organization: '', notes: '', pgp_key: '' };

function ContactDialog({ contact, groups, onClose }: { contact: Contact | null; groups: ContactGroup[]; onClose: (saved: boolean) => void }) {
  const [form, setForm] = useState<Omit<Contact, 'id'>>(contact ?? EMPTY);
  // Group id -> ids of its members, loaded once so membership can be edited here.
  const [members, setMembers] = useState<Record<number, number[]>>({});
  const [selected, setSelected] = useState<number[]>([]);
  const [error, setError] = useState('');
  const set = (changes: Partial<Contact>) => setForm((current) => ({ ...current, ...changes }));

  useEffect(() => {
    let cancelled = false;
    Promise.all(groups.map(async (group) => [group.id, await get<number[]>(`/api/me/contact-groups/${group.id}/members`)] as const))
      .then((entries) => {
        if (cancelled) return;
        const loaded = Object.fromEntries(entries);
        setMembers(loaded);
        if (contact) setSelected(groups.filter((group) => loaded[group.id]?.includes(contact.id)).map((group) => group.id));
      })
      .catch(() => {});
    return () => {
      cancelled = true;
    };
  }, [groups, contact]);

  async function save() {
    setError('');
    try {
      const saved = contact ? await put<Contact>(`/api/me/contacts/${contact.id}`, form) : await post<Contact>('/api/me/contacts', form);
      for (const group of groups) {
        const current = members[group.id] ?? [];
        const wanted = selected.includes(group.id);
        if (wanted === current.includes(saved.id)) continue;
        const next = wanted ? [...current, saved.id] : current.filter((id) => id !== saved.id);
        await put(`/api/me/contact-groups/${group.id}/members`, { contact_ids: next });
      }
      onClose(true);
    } catch (err) {
      setError(errorText(err, t('The contact could not be saved')));
    }
  }

  return (
    <Dialog open onClose={() => onClose(false)} fullWidth maxWidth="sm">
      <DialogTitle>{contact ? t('Edit contact') : t('New contact')}</DialogTitle>
      <DialogContent>
        <Stack spacing={2} sx={{ mt: 1 }}>
          {error && <Alert severity="error">{error}</Alert>}
          <TextField label={t('Name')} value={form.name} onChange={(e) => set({ name: e.target.value })} autoFocus />
          <TextField label={t('E-mail address')} type="email" value={form.email} onChange={(e) => set({ email: e.target.value })} required />
          <Stack direction="row" spacing={2}>
            <TextField label={t('Phone')} value={form.phone} onChange={(e) => set({ phone: e.target.value })} fullWidth />
            <TextField label={t('Organization')} value={form.organization} onChange={(e) => set({ organization: e.target.value })} fullWidth />
          </Stack>
          <TextField label={t('Notes')} value={form.notes} onChange={(e) => set({ notes: e.target.value })} multiline minRows={2} />
          {groups.length > 0 && (
            <Box>
              <Typography variant="body2" sx={{ color: 'text.secondary' }}>
                {t('Groups')}
              </Typography>
              <FormGroup row>
                {groups.map((group) => (
                  <FormControlLabel
                    key={group.id}
                    label={group.name}
                    control={<Checkbox checked={selected.includes(group.id)} onChange={(e) => setSelected((current) => (e.target.checked ? [...current, group.id] : current.filter((id) => id !== group.id)))} />}
                  />
                ))}
              </FormGroup>
            </Box>
          )}
          <TextField
            label={t('OpenPGP public key')}
            value={form.pgp_key}
            onChange={(e) => set({ pgp_key: e.target.value })}
            multiline
            minRows={3}
            maxRows={8}
            placeholder="-----BEGIN PGP PUBLIC KEY BLOCK-----"
            helperText={t("Paste the contact's public key to send them encrypted mail")}
            slotProps={{ htmlInput: { spellCheck: false, style: { fontFamily: 'monospace', fontSize: 12 } } }}
          />
        </Stack>
      </DialogContent>
      <DialogButtons onCancel={() => onClose(false)} onConfirm={() => void save()} disabled={!form.email.trim()} />
    </Dialog>
  );
}

/** The personal address book: contacts, groups, and vCard import/export. */
export default function ContactsPage() {
  useTitle(t('Contacts'));
  const navigate = useNavigate();
  const [contacts, setContacts] = useState<Contact[]>([]);
  const [groups, setGroups] = useState<ContactGroup[]>([]);
  const [group, setGroup] = useState<number | null>(null);
  const [query, setQuery] = useState('');
  const [editing, setEditing] = useState<Contact | null | undefined>(undefined);
  const [notice, setNotice] = useState('');
  const [sync, setSync] = useState<{ carddav: { server: string; addressbook: string }; caldav: { username: string } } | null>(null);
  const fileInput = useRef<HTMLInputElement>(null);

  const load = useCallback(async () => {
    const params = new URLSearchParams();
    if (query.trim()) params.set('q', query.trim());
    if (group !== null) params.set('group', String(group));
    try {
      const [list, groupList] = await Promise.all([get<Contact[]>(`/api/me/contacts?${params}`), get<ContactGroup[]>('/api/me/contact-groups')]);
      setContacts(list);
      setGroups(groupList);
    } catch (err) {
      setNotice(errorText(err, t('The address book could not be loaded')));
    }
  }, [query, group]);

  useEffect(() => {
    const timer = setTimeout(() => void load(), 200);
    return () => clearTimeout(timer);
  }, [load]);

  async function run(action: () => Promise<unknown>, done: string) {
    try {
      await action();
      setNotice(done);
      await load();
    } catch (err) {
      setNotice(errorText(err, t('The operation failed')));
    }
  }

  function addGroup() {
    const name = window.prompt(t('Name of the new group'))?.trim();
    if (name) void run(() => post('/api/me/contact-groups', { name }), t('Group created'));
  }

  function removeGroup(target: ContactGroup) {
    if (!window.confirm(t('Delete the group “{{name}}”? The contacts themselves are kept.', { name: target.name }))) return;
    if (group === target.id) setGroup(null);
    void run(() => del(`/api/me/contact-groups/${target.id}`), t('Group deleted'));
  }

  async function importFile(file: File | undefined) {
    if (!file) return;
    try {
      const result = await postRaw<{ imported: number; skipped: number }>('/api/me/contacts/import', new Blob([await file.text()], { type: 'text/vcard' }));
      setNotice(t('{{count}} contacts imported', { count: result.imported }) + (result.skipped ? t(', {{count}} skipped', { count: result.skipped }) : ''));
      await load();
    } catch (err) {
      setNotice(errorText(err, t('The file could not be imported')));
    }
  }

  const currentGroup = groups.find((candidate) => candidate.id === group);
  const syncDialog = sync && (
    <Dialog open onClose={() => setSync(null)} fullWidth maxWidth="sm">
      <DialogTitle>{t('Use these contacts on a phone or in a mail program')}</DialogTitle>
      <DialogContent>
        <Stack spacing={2} sx={{ mt: 1 }}>
          <Typography variant="body2" sx={{ color: 'text.secondary' }}>
            {t('Add a CardDAV account (on Android with DAVx⁵; built into iOS, macOS and Thunderbird) with the server address below and sign in with your e-mail address and password. Contacts added or changed there appear here, and the other way round.')}
          </Typography>
          <TextField label={t('Server address')} value={sync.carddav.server} size="small" onFocus={(e) => e.target.select()} slotProps={{
            input: { readOnly: true }
          }} />
          <TextField label={t('User name')} value={sync.caldav.username} size="small" onFocus={(e) => e.target.select()} slotProps={{
            input: { readOnly: true }
          }} />
          <TextField label={t('Address book (if the program asks for it)')} value={sync.carddav.addressbook} size="small" onFocus={(e) => e.target.select()} slotProps={{
            input: { readOnly: true }
          }} />
        </Stack>
      </DialogContent>
      <DialogActions>
        <Button onClick={() => setSync(null)}>{t('Close')}</Button>
      </DialogActions>
    </Dialog>
  );
  return (
    <Box className="um-page" sx={{ height: '100vh', display: 'flex', flexDirection: 'column', bgcolor: 'background.default' }}>
      <TopBar title={t('Contacts')} leading={<IconButton aria-label={t('Back to mail')} onClick={() => navigate('/mail')}><ArrowBack /></IconButton>} />
      <Box sx={{ flex: 1, display: 'flex', minHeight: 0 }}>
        <Box component="nav" aria-label={t('Contact groups')} sx={{ width: 240, flexShrink: 0, px: 1, overflow: 'auto', display: { xs: 'none', md: 'block' } }}>
          <List dense disablePadding>
            <ListItemButton selected={group === null} onClick={() => setGroup(null)} sx={{ mb: 0.25 }}>
              <ListItemIcon sx={{ minWidth: 40 }}><People /></ListItemIcon>
              <ListItemText primary={t('All contacts')} />
            </ListItemButton>
            {groups.map((candidate) => (
              <ListItemButton key={candidate.id} selected={group === candidate.id} onClick={() => setGroup(candidate.id)} sx={{ mb: 0.25 }}>
                <ListItemIcon sx={{ minWidth: 40 }}><Group /></ListItemIcon>
                <ListItemText primary={candidate.name} secondary={t('{{count}} members', { count: candidate.members })} slotProps={{
                  primary: { noWrap: true }
                }} />
                <IconButton size="small" aria-label={t('Delete group {{name}}', { name: candidate.name })} onClick={(e) => { e.stopPropagation(); removeGroup(candidate); }}>
                  <Delete fontSize="inherit" />
                </IconButton>
              </ListItemButton>
            ))}
            <ListItemButton onClick={addGroup}>
              <ListItemIcon sx={{ minWidth: 40 }}><Add /></ListItemIcon>
              <ListItemText primary={t('New group')} />
            </ListItemButton>
          </List>
        </Box>
        <Paper elevation={0} component="main" sx={{ flex: 1, minWidth: 0, overflow: 'auto', borderRadius: 1.5, mr: 1, mb: 1, p: 3 }}>
          <Stack direction="row" spacing={1} useFlexGap sx={{ alignItems: 'center', flexWrap: 'wrap', mb: 2 }}>
            <Typography variant="h5" component="h1" sx={{ flex: 1 }}>
              {currentGroup ? currentGroup.name : t('All contacts')}
            </Typography>
            <TextField label={t('Search contacts')} value={query} onChange={(e) => setQuery(e.target.value)} sx={{ minWidth: 220 }} />
            {currentGroup && contacts.length > 0 && (
              <Button startIcon={<Send />} onClick={() => navigate(`/mail/inbox?compose=${encodeURIComponent(contacts.map((c) => c.email).join(', '))}`)}>
                {t('Write to group')}
              </Button>
            )}
            <Button onClick={() => fileInput.current?.click()}>{t('Import vCard')}</Button>
            <Button onClick={() => void get<{ carddav: { server: string; addressbook: string }; caldav: { username: string } }>('/api/me/calendars').then(setSync).catch(() => setNotice(t('The addresses could not be loaded')))}>
              {t('Sync with phone')}
            </Button>
            <Button component="a" href="/api/me/contacts/export" download="contacts.vcf">
              {t('Export')}
            </Button>
            <Button variant="contained" startIcon={<Add />} onClick={() => setEditing(null)}>
              {t('New contact')}
            </Button>
          </Stack>
          {contacts.length === 0 ? (
            <Typography sx={{ color: 'text.secondary', p: 4, textAlign: 'center' }}>
              {query ? t('No contacts match your search.') : t('No contacts yet.')}
            </Typography>
          ) : (
            <Table size="small" aria-label={t('Contacts')}>
              <TableHead>
                <TableRow>
                  <TableCell>{t('Name')}</TableCell>
                  <TableCell>{t('E-mail')}</TableCell>
                  <TableCell>{t('Organization')}</TableCell>
                  <TableCell>{t('Phone')}</TableCell>
                  <TableCell />
                </TableRow>
              </TableHead>
              <TableBody>
                {contacts.map((contact) => (
                  <TableRow key={contact.id} hover>
                    <TableCell>
                      {contact.name || '—'}
                      {contact.pgp_key && (
                        <Tooltip title={t('Has an OpenPGP key')}>
                          <Key fontSize="inherit" color="success" sx={{ ml: 0.5, verticalAlign: 'middle' }} />
                        </Tooltip>
                      )}
                    </TableCell>
                    <TableCell sx={{ wordBreak: 'break-all' }}>{contact.email}</TableCell>
                    <TableCell>{contact.organization}</TableCell>
                    <TableCell sx={{ whiteSpace: 'nowrap' }}>{contact.phone}</TableCell>
                    <TableCell align="right" sx={{ whiteSpace: 'nowrap' }}>
                      <Tooltip title={t('Write a message')}>
                        <IconButton size="small" aria-label={t('Write to {{email}}', { email: contact.email })} onClick={() => navigate(`/mail/inbox?compose=${encodeURIComponent(contact.name ? `${contact.name} <${contact.email}>` : contact.email)}`)}>
                          <Send fontSize="small" />
                        </IconButton>
                      </Tooltip>
                      <IconButton size="small" aria-label={t('Edit {{email}}', { email: contact.email })} onClick={() => setEditing(contact)}>
                        <Edit fontSize="small" />
                      </IconButton>
                      <IconButton size="small" aria-label={t('Delete {{email}}', { email: contact.email })} onClick={() => window.confirm(t('Delete {{name}}?', { name: contact.name || contact.email })) && void run(() => del(`/api/me/contacts/${contact.id}`), t('Contact deleted'))}>
                        <Delete fontSize="small" />
                      </IconButton>
                    </TableCell>
                  </TableRow>
                ))}
              </TableBody>
            </Table>
          )}
        </Paper>
      </Box>
      <input ref={fileInput} type="file" accept=".vcf,text/vcard" hidden aria-label={t('vCard file')} onChange={(e) => { void importFile(e.target.files?.[0]); e.target.value = ''; }} />
      {editing !== undefined && (
        <ContactDialog
          contact={editing}
          groups={groups}
          onClose={(saved) => {
            setEditing(undefined);
            if (saved) {
              setNotice(t('Contact saved'));
              void load();
            }
          }}
        />
      )}
      {syncDialog}
      <Snackbar open={Boolean(notice)} autoHideDuration={4000} onClose={() => setNotice('')} message={notice} />
    </Box>
  );
}
