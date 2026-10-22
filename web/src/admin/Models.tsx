import Add from '@mui/icons-material/Add';
import Delete from '@mui/icons-material/Delete';
import Edit from '@mui/icons-material/Edit';
import { Alert, Box, Button, Chip, CircularProgress, Dialog, DialogActions, DialogContent, DialogTitle, FormControlLabel, IconButton, MenuItem, Stack, Switch, TextField, Tooltip, Typography } from '@mui/material';
import { useState } from 'react';
import { del, get, post, put } from '../api';
import { t } from '../i18n';
import { ConfirmDialog, PageHeader, useAction, useFormAction, useLoad } from './common';

const PROVIDERS = [
  { id: 'openai', name: 'OpenAI', url: 'https://api.openai.com/v1', model: 'gpt-4.1-mini' },
  { id: 'anthropic', name: 'Anthropic', url: 'https://api.anthropic.com/v1', model: 'claude-sonnet-4-6' },
  { id: 'gemini', name: 'Google Gemini', url: 'https://generativelanguage.googleapis.com/v1beta', model: 'gemini-2.5-flash' },
  { id: 'openrouter', name: 'OpenRouter', url: 'https://openrouter.ai/api/v1', model: '' },
  { id: 'groq', name: 'Groq', url: 'https://api.groq.com/openai/v1', model: 'llama-3.3-70b-versatile' },
  { id: 'deepseek', name: 'DeepSeek', url: 'https://api.deepseek.com/v1', model: 'deepseek-chat' },
  { id: 'ollama', name: 'Ollama', url: 'http://localhost:11434', model: 'llama3.2' },
  { id: 'custom', name: t('OpenAI-compatible'), url: '', model: '' },
];

interface Model {
  id: string;
  name: string;
  provider: string;
  model: string;
  base_url: string;
  enabled: boolean;
  has_api_key: boolean;
}

const emptyModel: Model = { id: '', name: '', provider: 'openai', model: '', base_url: PROVIDERS[0].url, enabled: true, has_api_key: false };

const LOCAL_ONLY = '__local__';

function ExtractionSettings({ models }: { models: Model[] }) {
  const settings = useLoad(() => get<{ model_id: string; automatic_ai: boolean }>('/api/models/summary-cards'), []);
  const [draft, setDraft] = useState<{ model_id: string; automatic_ai: boolean } | null>(null);
  const [busy, setBusy] = useState(false);
  const { run, feedback } = useAction();
  const value = draft ?? settings.data;
  if (!value) return settings.error ? <Alert severity="error">{settings.error}</Alert> : null;
  return <Box component="section" aria-label={t('Purchase card extraction')} sx={{ mt: 3, pt: 2, borderTop: 1, borderColor: 'divider' }}>
    <Typography variant="h6" sx={{ mb: 1 }}>{t('Purchase card extraction')}</Typography>
    {feedback}
    <Stack spacing={1.5} alignItems="flex-start">
      {/* MUI renders an empty-string select value as nothing selected, so local-only uses a sentinel. */}
      <TextField select label={t('Extraction model')} value={models.some((m) => m.id === value.model_id && m.enabled) ? value.model_id : LOCAL_ONLY} onChange={(e) => { const id = e.target.value === LOCAL_ONLY ? '' : e.target.value; setDraft({ ...value, model_id: id, automatic_ai: id ? value.automatic_ai : false }); }} sx={{ minWidth: 260 }}>
        <MenuItem value={LOCAL_ONLY}>{t('Local structured data only')}</MenuItem>
        {models.filter((m) => m.enabled).map((m) => <MenuItem key={m.id} value={m.id}>{m.name}</MenuItem>)}
      </TextField>
      <FormControlLabel control={<Switch checked={value.automatic_ai} disabled={!value.model_id} onChange={(e) => setDraft({ ...value, automatic_ai: e.target.checked })} />} label={t('Allow automatic AI extraction')} />
      <Typography variant="body2" color="text.secondary">{t('Automatic AI extraction also requires each user to opt in. Structured data is always processed locally.')}</Typography>
      <Button variant="contained" disabled={busy || !draft} onClick={() => {
        setBusy(true);
        void run(() => put('/api/models/summary-cards', value), t('Extraction settings saved')).then((ok) => { if (ok) { setDraft(null); void settings.reload(); } }).finally(() => setBusy(false));
      }}>{t('Save extraction settings')}</Button>
    </Stack>
  </Box>;
}

function ModelDialog({ model, onClose, onSaved }: { model: Model; onClose: () => void; onSaved: () => void }) {
  const [draft, setDraft] = useState(model);
  const [key, setKey] = useState('');
  const form = useFormAction<string>(() => null);
  const edit = Boolean(model.id);
  async function save() {
    const payload = { ...draft, api_key: key || undefined };
    if (await form.run(() => edit ? put(`/api/models/${model.id}`, payload) : post('/api/models', payload))) onSaved();
  }
  return (
    <Dialog open onClose={form.busy ? undefined : onClose} fullWidth maxWidth="sm">
      <Box component="form" onSubmit={(event) => { event.preventDefault(); void save(); }}>
        <DialogTitle>{edit ? t('Edit model') : t('Add model')}</DialogTitle>
        <DialogContent>
          {form.formError}
          <Stack spacing={2} sx={{ pt: 1 }}>
            <TextField autoFocus required label={t('Display name')} value={draft.name} onChange={(e) => setDraft({ ...draft, name: e.target.value })} slotProps={{ htmlInput: { maxLength: 80 } }} />
            <TextField select label={t('Provider')} value={draft.provider} onChange={(e) => {
              const provider = PROVIDERS.find((p) => p.id === e.target.value)!;
              setDraft({ ...draft, provider: provider.id, base_url: provider.url, model: provider.model });
              setKey('');
            }}>
              {PROVIDERS.map((p) => <MenuItem key={p.id} value={p.id}>{p.name}</MenuItem>)}
            </TextField>
            <TextField required label={t('Model ID')} value={draft.model} placeholder={PROVIDERS.find((p) => p.id === draft.provider)?.model} onChange={(e) => setDraft({ ...draft, model: e.target.value })} helperText={t('Use the exact model identifier from your provider.')} slotProps={{ htmlInput: { maxLength: 200 } }} />
            <TextField required label={t('Base URL')} type="url" value={draft.base_url} onChange={(e) => setDraft({ ...draft, base_url: e.target.value })} helperText={t('For local models, use an address reachable from the mail server.')} />
            <TextField label={t('API key')} type="password" autoComplete="new-password" value={key} onChange={(e) => setKey(e.target.value)} helperText={model.has_api_key && draft.provider === model.provider && draft.base_url === model.base_url ? t('A key is saved. Leave blank to keep it.') : t('Optional for Ollama and local OpenAI-compatible providers.')} />
            <FormControlLabel control={<Switch checked={draft.enabled} onChange={(e) => setDraft({ ...draft, enabled: e.target.checked })} />} label={t('Available in webmail')} />
          </Stack>
        </DialogContent>
        <DialogActions>
          <Button onClick={onClose} disabled={form.busy}>{t('Cancel')}</Button>
          <Button type="submit" variant="contained" disabled={form.busy}>{form.busy ? t('Saving…') : t('Save')}</Button>
        </DialogActions>
      </Box>
    </Dialog>
  );
}

export function Models() {
  const models = useLoad(() => get<Model[]>('/api/models'), []);
  const { run, feedback } = useAction();
  const [editing, setEditing] = useState<Model | null>(null);
  const [removing, setRemoving] = useState<Model | null>(null);
  const [testing, setTesting] = useState('');
  async function test(model: Model) {
    setTesting(model.id);
    await run(() => post(`/api/models/${model.id}/test`), t('Model connection successful'));
    setTesting('');
  }
  return (
    <>
      <PageHeader title={t('Models')}><Button variant="contained" startIcon={<Add />} onClick={() => setEditing({ ...emptyModel })}>{t('Add model')}</Button></PageHeader>
      <Typography color="text.secondary" variant="body2" sx={{ mb: 2 }}>{t('Configure AI models for email summaries and translations. API keys are encrypted and kept on the server.')}</Typography>
      {feedback}
      {models.error && <Alert severity="error">{models.error}</Alert>}
      {!models.data && !models.error && <CircularProgress aria-label={t('Loading models')} />}
      {models.data?.length === 0 && <Alert severity="info">{t('No AI models configured. Add a model to enable summaries and translations in webmail.')}</Alert>}
      <Stack divider={<Box sx={{ borderBottom: 1, borderColor: 'divider' }} />}>
        {models.data?.map((model) => (
          <Stack key={model.id} direction={{ xs: 'column', sm: 'row' }} spacing={2} alignItems={{ sm: 'center' }} sx={{ py: 2 }}>
            <Box sx={{ flex: 1, minWidth: 0 }}>
              <Stack direction="row" spacing={1} alignItems="center"><Typography fontWeight={600}>{model.name}</Typography><Chip size="small" variant="outlined" label={model.enabled ? t('Enabled') : t('Disabled')} /></Stack>
              <Typography variant="body2" color="text.secondary" sx={{ overflowWrap: 'anywhere' }}>{PROVIDERS.find((p) => p.id === model.provider)?.name} · {model.model}</Typography>
              <Typography variant="caption" color="text.secondary" sx={{ overflowWrap: 'anywhere' }}>{model.base_url}</Typography>
            </Box>
            <Stack direction="row" spacing={1} alignItems="center">
              <Button variant="outlined" disabled={Boolean(testing)} onClick={() => void test(model)}>{testing === model.id ? t('Testing…') : t('Test connection')}</Button>
              <Tooltip title={t('Edit model')}><IconButton aria-label={t('Edit {{name}}', { name: model.name })} onClick={() => setEditing(model)}><Edit /></IconButton></Tooltip>
              <Tooltip title={t('Delete model')}><IconButton aria-label={t('Delete {{name}}', { name: model.name })} onClick={() => setRemoving(model)}><Delete /></IconButton></Tooltip>
            </Stack>
          </Stack>
        ))}
      </Stack>
      {models.data && <ExtractionSettings models={models.data} />}
      {editing && <ModelDialog model={editing} onClose={() => setEditing(null)} onSaved={() => { setEditing(null); void models.reload(); }} />}
      <ConfirmDialog open={Boolean(removing)} title={t('Delete model')} text={t('Delete {{name}}?', { name: removing?.name ?? '' })} onClose={() => setRemoving(null)} onConfirm={() => {
        if (removing) void run(() => del(`/api/models/${removing.id}`), t('Model deleted')).then((ok) => { if (ok) { setRemoving(null); void models.reload(); } });
      }} />
    </>
  );
}
