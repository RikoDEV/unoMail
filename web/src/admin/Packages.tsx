// Plug-in and theme packages: installed from a git repository at a tag, branch or commit,
// after the administrator has seen what the package is and what it may do.

import Delete from '@mui/icons-material/Delete';
import Settings from '@mui/icons-material/Settings';
import Update from '@mui/icons-material/Update';
import WarningAmber from '@mui/icons-material/WarningAmber';
import { Alert, Box, Button, Card, CardContent, Chip, Dialog, DialogContent, DialogTitle, FormControlLabel, IconButton, Link, List, ListItem, ListItemIcon, ListItemText, Stack, Switch, TableBody, TableCell, TableRow, TextField, Tooltip, Typography } from '@mui/material';
import { useEffect, useState } from 'react';
import { del, errorText, formatTime, get, post, put } from '../lib/api';
import { useAppearance } from '../app';
import { declaredPermissions, describePermission, isSensitive, type PackageManifest } from '../plugins/permissions';
import { declaredSettings, initialValues, type SettingValues, SettingsFields } from '../plugins/SettingsFields';
import { ConfirmDialog, DialogButtons, ScrollTable, useAction, useLoad } from './common';

import { t } from '../i18n';

interface Installed {
  id: string;
  type: 'plugin' | 'theme';
  url: string;
  ref: string;
  commit: string;
  manifest: PackageManifest;
  enabled: boolean;
  installedAt: number;
  installedBy: string;
}

interface Preview {
  token: string;
  url: string;
  ref: string;
  commit: string;
  manifest: PackageManifest;
  update: { from: string; fromVersion: string } | null;
  newPermissions: string[];
}

const short = (commit: string) => commit.slice(0, 10);

function Permissions({ permissions, added }: { permissions: string[]; added?: string[] }) {
  if (permissions.length === 0) return <Typography variant="body2">{t('This plug-in asks for no permissions.')}</Typography>;
  return (
    <List dense disablePadding aria-label={t('Permissions')}>
      {permissions.map((permission) => (
        <ListItem key={permission} disableGutters>
          <ListItemIcon sx={{ minWidth: 32 }}>{isSensitive(permission) && <WarningAmber fontSize="small" color="warning" />}</ListItemIcon>
          <ListItemText primary={describePermission(permission)} secondary={added?.includes(permission) ? t('New in this version') : undefined} />
        </ListItem>
      ))}
    </List>
  );
}

/** Shows what a fetched package is before it is installed. */
function PreviewDialog({ preview, onClose, onInstalled }: { preview: Preview; onClose: () => void; onInstalled: () => void }) {
  const [error, setError] = useState('');
  const [busy, setBusy] = useState(false);
  const { manifest } = preview;
  const install = async () => {
    setBusy(true);
    setError('');
    try {
      await post('/api/packages', { token: preview.token });
      onInstalled();
    } catch (err) {
      setError(errorText(err, t('The package could not be installed')));
    } finally {
      setBusy(false);
    }
  };
  return (
    <Dialog open onClose={onClose} fullWidth maxWidth="sm">
      <DialogTitle>{preview.update ? t('Update {{name}}?', { name: manifest.name }) : t('Install {{name}}?', { name: manifest.name })}</DialogTitle>
      <DialogContent>
        <Stack spacing={2}>
          {error && <Alert severity="error">{error}</Alert>}
          <Box>
            <Typography>
              {manifest.name} <Chip size="small" label={manifest.version} sx={{ ml: 1 }} /> <Chip size="small" variant="outlined" label={manifest.type === 'theme' ? t('Theme') : t('Plug-in')} sx={{ ml: 0.5 }} />
            </Typography>
            {manifest.description && <Typography variant="body2" sx={{ color: 'text.secondary', mt: 0.5 }}>{manifest.description}</Typography>}
            <Typography variant="body2" sx={{ mt: 1 }}>
              {manifest.author && <>{t('By {{author}}', { author: manifest.author })} · </>}
              {manifest.license && <>{manifest.license} · </>}
              {manifest.homepage && <Link href={manifest.homepage} target="_blank" rel="noopener noreferrer">{t('Home page')}</Link>}
            </Typography>
            <Typography variant="body2" sx={{ color: 'text.secondary', mt: 1, overflowWrap: 'anywhere' }}>
              {preview.url} @ {preview.ref} ({short(preview.commit)})
              {preview.update && <> · {t('replaces {{version}} ({{commit}})', { version: preview.update.fromVersion, commit: short(preview.update.from) })}</>}
            </Typography>
          </Box>
          {manifest.type === 'plugin' ? (
            <Box>
              <Typography variant="subtitle2">{t('If users turn it on, this plug-in can:')}</Typography>
              <Permissions permissions={declaredPermissions(manifest)} added={preview.update ? preview.newPermissions : undefined} />
              <Alert severity="info" sx={{ mt: 1 }}>{t('Plug-ins run in an isolated frame and can only do what is listed here. Review the code at this commit before installing: it runs in the browser of every user who turns it on.')}</Alert>
            </Box>
          ) : (
            <Alert severity="info">{t('A theme contains only colours, shapes and fonts; it cannot run code.')}</Alert>
          )}
        </Stack>
      </DialogContent>
      <DialogButtons onCancel={onClose} onConfirm={() => void install()} disabled={busy} label={preview.update ? t('Update') : t('Install')} />
    </Dialog>
  );
}

/** The administrator's settings of a package, and how its mail hooks behave when they fail. */
function AdminSettingsDialog({ pkg, onClose }: { pkg: Installed; onClose: () => void }) {
  const declared = declaredSettings(pkg.manifest, 'admin');
  const hooks = pkg.manifest.server?.hooks ?? [];
  const [stored, setStored] = useState<Record<string, unknown> | null>(null);
  const [values, setValues] = useState<SettingValues>({});
  const [failClosed, setFailClosed] = useState(false);
  const [error, setError] = useState('');
  useEffect(() => {
    get<{ settings: Record<string, unknown>; failClosed: boolean }>(`/api/packages/${encodeURIComponent(pkg.id)}/settings`)
      .then((data) => {
        setStored(data.settings);
        setValues(initialValues(declared, data.settings));
        setFailClosed(data.failClosed);
      })
      .catch((err) => setError(errorText(err, t('The settings could not be loaded'))));
    // The declared settings come with the package and do not change while the dialog is open.
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [pkg.id]);
  const save = async () => {
    setError('');
    try {
      await put(`/api/packages/${encodeURIComponent(pkg.id)}/settings`, { settings: values, failClosed });
      onClose();
    } catch (err) {
      setError(errorText(err, t('The change could not be saved')));
    }
  };
  return (
    <Dialog open onClose={onClose} fullWidth maxWidth="sm">
      <DialogTitle>{t('Settings of {{name}}', { name: pkg.manifest.name })}</DialogTitle>
      <DialogContent>
        <Stack spacing={2} sx={{ pt: 1 }}>
          {error && <Alert severity="error">{error}</Alert>}
          {stored && <SettingsFields declared={declared} stored={stored} values={values} onChange={setValues} />}
          {hooks.length > 0 && (
            <FormControlLabel
              control={<Switch checked={failClosed} onChange={(e) => setFailClosed(e.target.checked)} />}
              label={t('Hold mail when the plug-in fails')}
            />
          )}
          {hooks.length > 0 && <Typography variant="body2" sx={{ color: 'text.secondary' }}>{t('Off: mail is delivered as if the plug-in were not installed. On: mail is deferred and retried later.')}</Typography>}
        </Stack>
      </DialogContent>
      <DialogButtons onCancel={onClose} onConfirm={() => void save()} disabled={!stored} />
    </Dialog>
  );
}

function InstallForm({ onPreview }: { onPreview: (preview: Preview) => void }) {
  const [url, setUrl] = useState('');
  const [ref, setRef] = useState('');
  const [error, setError] = useState('');
  const [busy, setBusy] = useState(false);
  const fetchPreview = async () => {
    setBusy(true);
    setError('');
    try {
      onPreview(await post<Preview>('/api/packages/preview', { url: url.trim(), ref: ref.trim() || 'main' }));
    } catch (err) {
      setError(errorText(err, t('The repository could not be fetched')));
    } finally {
      setBusy(false);
    }
  };
  return (
    <Box component="form" onSubmit={(e) => { e.preventDefault(); void fetchPreview(); }}>
      {error && <Alert severity="error" sx={{ mb: 2 }}>{error}</Alert>}
      <Stack direction={{ xs: 'column', sm: 'row' }} spacing={1} sx={{ alignItems: { sm: 'flex-start' } }}>
        <TextField size="small" label={t('Git repository (https)')} placeholder="https://github.com/example/unomail-plugin" value={url} onChange={(e) => setUrl(e.target.value)} required sx={{ flex: 1 }} slotProps={{ htmlInput: { inputMode: 'url', spellCheck: false } }} />
        <TextField size="small" label={t('Tag, branch or commit')} placeholder="v1.0.0" value={ref} onChange={(e) => setRef(e.target.value)} sx={{ width: { sm: 200 } }} helperText={t('A tag is recommended')} slotProps={{ htmlInput: { spellCheck: false } }} />
        <Button type="submit" variant="contained" disabled={busy || !url.trim()}>{busy ? t('Fetching…') : t('Fetch')}</Button>
      </Stack>
    </Box>
  );
}

export function Packages() {
  const { run, feedback, notify } = useAction();
  const { reloadSkins } = useAppearance();
  const { data, reload } = useLoad(() => get<Installed[]>('/api/packages'), []);
  const [preview, setPreview] = useState<Preview | null>(null);
  const [removing, setRemoving] = useState<Installed | null>(null);
  const [configuring, setConfiguring] = useState<Installed | null>(null);
  const changed = async () => {
    await reload();
    await reloadSkins();
  };
  const checkUpdate = (pkg: Installed) =>
    run(async () => {
      const result = await post<Preview | { upToDate: true }>(`/api/packages/${encodeURIComponent(pkg.id)}/update`, {});
      if ('upToDate' in result) notify(t('{{name}} is up to date', { name: pkg.manifest.name }));
      else setPreview(result);
    });
  return (
    <Card variant="outlined">
      <CardContent>
        <Typography variant="h6">{t('Plug-ins and themes')}</Typography>
        <Typography variant="body2" sx={{ color: 'text.secondary', mb: 2 }}>
          {t('Install packages from a git repository. A package is fixed to the commit you approve and changes only when you update it. Plug-ins are off until you make them available, and then each user decides whether to turn them on.')}
        </Typography>
        {feedback}
        <InstallForm onPreview={setPreview} />
        {(data?.length ?? 0) > 0 && (
          <ScrollTable size="small" aria-label={t('Installed packages')} sx={{ mt: 2 }}>
            <TableBody>
              {data!.map((pkg) => (
                <TableRow key={pkg.id}>
                  <TableCell>
                    <Typography sx={{ fontWeight: 600 }}>{pkg.manifest.name}</Typography>
                    <Typography variant="body2" sx={{ color: 'text.secondary' }}>{pkg.manifest.description}</Typography>
                    <Typography variant="caption" sx={{ color: 'text.secondary', overflowWrap: 'anywhere' }} component="div">
                      {pkg.url} @ {pkg.ref} ({short(pkg.commit)}) · {t('installed {{time}} by {{who}}', { time: formatTime(pkg.installedAt), who: pkg.installedBy })}
                    </Typography>
                  </TableCell>
                  <TableCell>
                    <Stack direction="row" spacing={0.5}>
                      <Chip size="small" label={pkg.manifest.version} />
                      <Chip size="small" variant="outlined" label={pkg.type === 'theme' ? t('Theme') : t('Plug-in')} />
                    </Stack>
                  </TableCell>
                  <TableCell align="right" sx={{ whiteSpace: 'nowrap' }}>
                    <FormControlLabel
                      label={t('Available')}
                      control={<Switch checked={pkg.enabled} onChange={(e) => void run(async () => { await put(`/api/packages/${encodeURIComponent(pkg.id)}`, { enabled: e.target.checked }); await changed(); }, e.target.checked ? t('Available to users') : t('No longer available'))} slotProps={{ input: { 'aria-label': t('Make {{name}} available', { name: pkg.manifest.name }) } }} />}
                    />
                    {(declaredSettings(pkg.manifest, 'admin').length > 0 || (pkg.manifest.server?.hooks.length ?? 0) > 0) && (
                      <Tooltip title={t('Settings')}>
                        <IconButton aria-label={t('Settings of {{name}}', { name: pkg.manifest.name })} onClick={() => setConfiguring(pkg)}><Settings /></IconButton>
                      </Tooltip>
                    )}
                    <Tooltip title={t('Check for updates')}>
                      <IconButton aria-label={t('Check {{name}} for updates', { name: pkg.manifest.name })} onClick={() => void checkUpdate(pkg)}><Update /></IconButton>
                    </Tooltip>
                    <Tooltip title={t('Uninstall')}>
                      <IconButton aria-label={t('Uninstall {{name}}', { name: pkg.manifest.name })} onClick={() => setRemoving(pkg)}><Delete /></IconButton>
                    </Tooltip>
                  </TableCell>
                </TableRow>
              ))}
            </TableBody>
          </ScrollTable>
        )}
      </CardContent>
      {configuring && <AdminSettingsDialog pkg={configuring} onClose={() => setConfiguring(null)} />}
      {preview && <PreviewDialog preview={preview} onClose={() => setPreview(null)} onInstalled={() => { setPreview(null); notify(preview.update ? t('Package updated') : t('Package installed')); void changed(); }} />}
      <ConfirmDialog
        open={Boolean(removing)}
        title={t('Uninstall {{name}}?', { name: removing?.manifest.name ?? '' })}
        text={t('Its files are deleted, along with every user’s settings and data for it.')}
        confirmLabel={t('Uninstall')}
        onClose={() => setRemoving(null)}
        onConfirm={() => {
          const pkg = removing!;
          setRemoving(null);
          void run(async () => { await del(`/api/packages/${encodeURIComponent(pkg.id)}`); await changed(); }, t('Package uninstalled'));
        }}
      />
    </Card>
  );
}
