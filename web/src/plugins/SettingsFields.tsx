// The form fields for a plug-in's declared settings, for users (Add-ons) and administrators
// (the package's settings in Integrations). Secrets are never shown again once stored.

import { FormControlLabel, MenuItem, Switch, TextField } from '@mui/material';
import type { PackageManifest } from './permissions';

import { t } from '../i18n';

export type SettingValues = Record<string, string | boolean>;
type Declared = NonNullable<PackageManifest['settings']>;

export function declaredSettings(manifest: PackageManifest, scope: 'user' | 'admin'): Declared {
  return (manifest.settings ?? []).filter((setting) => (setting.scope ?? 'user') === scope);
}

/** The values a form starts with: what is stored, or the defaults; secrets start empty. */
export function initialValues(declared: Declared, stored: Record<string, unknown>): SettingValues {
  const values: SettingValues = {};
  for (const setting of declared) {
    const value = stored[setting.key];
    if (setting.secret) values[setting.key] = '';
    else if (typeof value === 'string' || typeof value === 'boolean') values[setting.key] = value;
    else values[setting.key] = setting.default ?? (setting.type === 'boolean' ? false : setting.type === 'select' ? setting.options?.[0] ?? '' : '');
  }
  return values;
}

export function SettingsFields({ declared, stored, values, onChange }: { declared: Declared; stored: Record<string, unknown>; values: SettingValues; onChange: (values: SettingValues) => void }) {
  return (
    <>
      {declared.map((setting) => {
        const value = values[setting.key];
        const set = (next: string | boolean) => onChange({ ...values, [setting.key]: next });
        if (setting.type === 'boolean') return <FormControlLabel key={setting.key} label={setting.label} control={<Switch checked={value === true} onChange={(e) => set(e.target.checked)} />} />;
        if (setting.type === 'select')
          return (
            <TextField key={setting.key} select size="small" label={setting.label} value={String(value)} onChange={(e) => set(e.target.value)}>
              {(setting.options ?? []).map((option) => <MenuItem key={option} value={option}>{option}</MenuItem>)}
            </TextField>
          );
        const isSet = (stored[setting.key] as { set?: boolean } | undefined)?.set;
        if (setting.type === 'host')
          return (
            <TextField key={setting.key} size="small" label={setting.label} value={String(value)} onChange={(e) => set(e.target.value.trim().toLowerCase())} placeholder="cloud.example.org" autoComplete="off"
              helperText={t('A host name only. The plug-in may connect to this server over https.')} slotProps={{ htmlInput: { spellCheck: false, inputMode: 'url' } }} />
          );
        return (
          <TextField key={setting.key} size="small" label={setting.label} value={String(value)} onChange={(e) => set(e.target.value)} type={setting.secret ? 'password' : 'text'} autoComplete="off"
            helperText={setting.secret && isSet ? t('Stored; leave empty to keep it') : undefined} />
        );
      })}
    </>
  );
}
