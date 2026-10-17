import { Box, Button, Checkbox, FormControlLabel, MenuItem, Popover, Stack, TextField, Typography } from '@mui/material';
import { useEffect, useState, type ReactNode } from 'react';
import { WITHIN_LABELS, emptyForm, formToQuery, queryToForm, type SearchForm } from './searchQuery';

import { t } from '../i18n';
function Row({ label, children }: { label: string; children: ReactNode }) {
  return (
    <Stack direction={{ xs: 'column', sm: 'row' }} alignItems={{ sm: 'center' }} spacing={{ xs: 0.5, sm: 2 }}>
      <Typography variant="body2" sx={{ width: { sm: 130 }, flexShrink: 0, color: 'text.secondary' }}>{label}</Typography>
      <Box sx={{ flex: 1, minWidth: 0, display: 'flex', gap: 1 }}>{children}</Box>
    </Stack>
  );
}

/**
 * Gmail's search form: fields for the common conditions, turned into an ordinary query in the
 * search box (so the result can be refined by typing, and the operators can be learned).
 */
export function AdvancedSearch({ anchor, query, folders, onSearch, onClose }: { anchor: HTMLElement | null; query: string; folders: { value: string; label: string }[]; onSearch: (query: string) => void; onClose: () => void }) {
  const [form, setForm] = useState<SearchForm>(() => queryToForm(query));
  useEffect(() => {
    if (anchor) setForm(queryToForm(query));
  }, [anchor, query]);
  const set = (changes: Partial<SearchForm>) => setForm((current) => ({ ...current, ...changes }));
  const result = formToQuery(form);
  const field = (label: string, key: 'from' | 'to' | 'subject' | 'words' | 'without', autoFocus = false) => (
    <Row label={label}>
      <TextField variant="standard" fullWidth value={form[key]} onChange={(e) => set({ [key]: e.target.value })} inputProps={{ 'aria-label': label }} autoFocus={autoFocus} />
    </Row>
  );
  return (
    <Popover
      open={Boolean(anchor)}
      anchorEl={anchor}
      onClose={onClose}
      anchorOrigin={{ vertical: 'bottom', horizontal: 'left' }}
      slotProps={{ paper: { sx: { width: anchor ? Math.max(anchor.offsetWidth, 360) : undefined, maxWidth: 'calc(100vw - 32px)', p: 2.5, mt: 0.5, borderRadius: 2 } } }}
    >
      <Stack
        component="form"
        role="search"
        aria-label={t('Advanced search')}
        spacing={1.5}
        onSubmit={(e) => {
          e.preventDefault();
          onSearch(result);
        }}
      >
        {field(t('From'), 'from', true)}
        {field(t('To'), 'to')}
        {field(t('Subject'), 'subject')}
        {field(t('Has the words'), 'words')}
        {field(t("Doesn't have"), 'without')}
        <Row label={t('Size')}>
          <TextField select variant="standard" value={form.sizeOp} onChange={(e) => set({ sizeOp: e.target.value as SearchForm['sizeOp'] })} inputProps={{ 'aria-label': t('Size is') }} sx={{ width: 130 }}>
            <MenuItem value="larger">{t('greater than')}</MenuItem>
            <MenuItem value="smaller">{t('less than')}</MenuItem>
          </TextField>
          <TextField variant="standard" type="number" value={form.size} onChange={(e) => set({ size: e.target.value })} inputProps={{ 'aria-label': t('Size'), min: 0 }} sx={{ flex: 1 }} />
          <TextField select variant="standard" value={form.sizeUnit} onChange={(e) => set({ sizeUnit: e.target.value as SearchForm['sizeUnit'] })} inputProps={{ 'aria-label': t('Size unit') }} sx={{ width: 70 }}>
            <MenuItem value="MB">MB</MenuItem>
            <MenuItem value="KB">KB</MenuItem>
          </TextField>
        </Row>
        <Row label={t('Date within')}>
          <TextField select variant="standard" value={form.within} onChange={(e) => set({ within: e.target.value as SearchForm['within'] })} inputProps={{ 'aria-label': t('Date within') }} SelectProps={{ displayEmpty: true }} sx={{ width: 130 }}>
            <MenuItem value="">{t('any time')}</MenuItem>
            {(Object.keys(WITHIN_LABELS) as (keyof typeof WITHIN_LABELS)[]).map((key) => (
              <MenuItem key={key} value={key}>{WITHIN_LABELS[key]}</MenuItem>
            ))}
          </TextField>
          <TextField variant="standard" type="date" value={form.date} disabled={!form.within} onChange={(e) => set({ date: e.target.value })} inputProps={{ 'aria-label': t('Of the date') }} sx={{ flex: 1 }} />
        </Row>
        <Row label={t('Search')}>
          <TextField select variant="standard" fullWidth value={form.folder} onChange={(e) => set({ folder: e.target.value })} inputProps={{ 'aria-label': t('Search in') }}>
            <MenuItem value="default">{t('All mail')}</MenuItem>
            <MenuItem value="anywhere">{t('Mail & Junk & Trash')}</MenuItem>
            {folders.map((folder) => (
              <MenuItem key={folder.value} value={folder.value}>{folder.label}</MenuItem>
            ))}
          </TextField>
        </Row>
        <FormControlLabel control={<Checkbox size="small" checked={form.attachment} onChange={(e) => set({ attachment: e.target.checked })} />} label={t('Has attachment')} />
        <Stack direction="row" spacing={1} alignItems="center">
          <Typography variant="caption" color="text.secondary" sx={{ flex: 1, minWidth: 0, overflowWrap: 'anywhere' }} aria-live="polite">{result}</Typography>
          <Button onClick={() => setForm(emptyForm())}>{t('Clear')}</Button>
          <Button type="submit" variant="contained" disabled={!result}>{t('Search')}</Button>
        </Stack>
      </Stack>
    </Popover>
  );
}
