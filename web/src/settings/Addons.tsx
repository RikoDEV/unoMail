// The plug-ins an administrator made available: each user turns them on for themselves, sees
// what they may do and fills in their settings.

import { Alert, Box, Button, Card, CardContent, Chip, Collapse, FormControlLabel, Stack, Switch, Typography } from '@mui/material';
import { useState } from 'react';
import { useAuth } from '../app';
import { errorText, get, put } from '../lib/api';
import { useLoad } from '../lib/useLoad';
import { settingsChanged, startPackages, stopPlugin } from '../plugins/host';
import { declaredPermissions, describePermission, type PackageManifest } from '../plugins/permissions';
import { declaredSettings, initialValues, SettingsFields } from '../plugins/SettingsFields';

import { t } from '../i18n';

interface Available {
  id: string;
  type: 'plugin' | 'theme';
  commit: string;
  manifest: PackageManifest;
  user: { enabled: boolean; settings: Record<string, unknown> };
}

function Addon({ pkg, onChange }: { pkg: Available; onChange: () => void }) {
  const { account } = useAuth();
  const settings = declaredSettings(pkg.manifest, 'user');
  const [values, setValues] = useState(() => initialValues(settings, pkg.user.settings));
  const [error, setError] = useState('');
  const [saved, setSaved] = useState(false);
  const { manifest } = pkg;
  const save = async (enabled: boolean, withSettings: boolean) => {
    setError('');
    setSaved(false);
    try {
      await put(`/api/me/packages/${encodeURIComponent(pkg.id)}`, withSettings ? { enabled, settings: values } : { enabled });
      if (enabled && !pkg.user.enabled && account) await startPackages(account.email, [{ id: pkg.id, commit: pkg.commit, name: manifest.name, permissions: manifest.permissions ?? [] }]);
      if (!enabled) stopPlugin(pkg.id);
      if (withSettings) {
        settingsChanged(pkg.id);
        setSaved(true);
      }
      onChange();
    } catch (err) {
      setError(errorText(err, t('The change could not be saved')));
    }
  };
  return (
    <Box sx={{ py: 1.5, borderTop: 1, borderColor: 'divider' }}>
      <Stack direction="row" spacing={1} sx={{ alignItems: 'flex-start' }}>
        <Box sx={{ flex: 1, minWidth: 0 }}>
          <Typography sx={{ fontWeight: 600 }}>
            {manifest.name} <Chip size="small" label={manifest.version} sx={{ ml: 0.5 }} />
          </Typography>
          {manifest.description && <Typography variant="body2" sx={{ color: 'text.secondary' }}>{manifest.description}</Typography>}
          {declaredPermissions(manifest).length > 0 && (
            <Typography variant="body2" component="ul" sx={{ m: 0, mt: 0.5, pl: 2.5, color: 'text.secondary' }} aria-label={t('Permissions')}>
              {declaredPermissions(manifest).map((p) => <li key={p}>{describePermission(p)}</li>)}
            </Typography>
          )}
        </Box>
        <FormControlLabel
          label={t('On')}
          labelPlacement="start"
          control={<Switch checked={pkg.user.enabled} onChange={(e) => void save(e.target.checked, false)} slotProps={{ input: { 'aria-label': t('Turn on {{name}}', { name: manifest.name }) } }} />}
        />
      </Stack>
      {error && <Alert severity="error" sx={{ mt: 1 }}>{error}</Alert>}
      <Collapse in={pkg.user.enabled && settings.length > 0}>
        <Stack spacing={2} sx={{ mt: 2, maxWidth: 420 }} component="form" onSubmit={(e) => { e.preventDefault(); void save(true, true); }}>
          <SettingsFields declared={settings} stored={pkg.user.settings} values={values} onChange={setValues} />
          <Box>
            <Button type="submit" variant="contained" size="small">{t('Save')}</Button>
            {saved && <Typography component="span" variant="body2" role="status" sx={{ ml: 1.5, color: 'text.secondary' }}>{t('Saved')}</Typography>}
          </Box>
        </Stack>
      </Collapse>
    </Box>
  );
}

export function AddonsCard() {
  const { data, reload } = useLoad(() => get<Available[]>('/api/packages'), []);
  // Server-only plug-ins work without anyone turning them on.
  const plugins = (data ?? []).filter((pkg) => pkg.type === 'plugin' && pkg.manifest?.entry);
  if (plugins.length === 0) return null;
  return (
    <Card variant="outlined">
      <CardContent>
        <Typography variant="h6">{t('Add-ons')}</Typography>
        <Typography variant="body2" sx={{ color: 'text.secondary', mb: 1 }}>
          {t('Plug-ins your administrator made available. Each runs isolated from your mail and can only do what is listed.')}
        </Typography>
        {plugins.map((pkg) => <Addon key={`${pkg.id}:${pkg.commit}`} pkg={pkg} onChange={() => void reload()} />)}
      </CardContent>
    </Card>
  );
}
