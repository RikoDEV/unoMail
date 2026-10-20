import AutoAwesome from '@mui/icons-material/AutoAwesome';
import Translate from '@mui/icons-material/Translate';
import { Alert, Box, Button, CircularProgress, MenuItem, Stack, TextField, Typography } from '@mui/material';
import { createContext, useContext, useEffect, useRef, useState, type ReactNode } from 'react';
import { errorText, get, post } from '../api';
import { currentLanguage, t } from '../i18n';
import type { EmailFull } from './jmapClient';

interface Model { id: string; name: string; provider: string }
const ModelsContext = createContext<{ models: Model[]; selected: string; select: (id: string) => void }>({ models: [], selected: '', select: () => {} });

export function useAiModel() {
  const { models, selected, select } = useContext(ModelsContext);
  const model = models.find((m) => m.id === selected) ?? models[0];
  return { models, model, select };
}

/** Load once per reader, rather than once for every message in a thread. */
export function AiModelsProvider({ children }: { children: ReactNode }) {
  const [models, setModels] = useState<Model[]>([]);
  const [selected, select] = useState('');
  useEffect(() => {
    let active = true;
    get<Model[]>('/api/me/ai/models').then((value) => { if (active) setModels(value); }).catch(() => {});
    return () => { active = false; };
  }, []);
  return <ModelsContext.Provider value={{ models, selected, select }}>{children}</ModelsContext.Provider>;
}

const LANGUAGES = [
  ['en', 'English'], ['pl', 'Polski'], ['de', 'Deutsch'], ['fr', 'Français'], ['cs', 'Čeština'], ['sk', 'Slovenčina'],
  ['es', 'Español'], ['it', 'Italiano'], ['pt', 'Português'], ['nl', 'Nederlands'], ['uk', 'Українська'], ['ja', '日本語'], ['ko', '한국어'], ['zh', '中文'], ['ar', 'العربية'],
];
type Task = 'summary' | 'translate';

export function AiAssist({ email }: { email: EmailFull }) {
  const { models, model, select } = useAiModel();
  const [foreignLanguage, setForeignLanguage] = useState(false);
  useEffect(() => {
    if (!models.length) return;
    let active = true;
    import('./messageLanguage').then(({ detectMessageLanguage, translationSuggested }) => {
      if (active) setForeignLanguage(translationSuggested(detectMessageLanguage(email), currentLanguage()));
    }).catch(() => { if (active) setForeignLanguage(false); });
    return () => { active = false; };
  }, [email, models.length]);
  const modelId = model?.id ?? '';
  const [language, setLanguage] = useState(currentLanguage());
  const [busy, setBusy] = useState<Task | null>(null);
  const [error, setError] = useState('');
  const [results, setResults] = useState<Partial<Record<Task, { text: string; model: string }>>>({});
  const generation = useRef(0);
  useEffect(() => () => { generation.current += 1; }, []);

  function reset() {
    generation.current += 1;
    setResults({});
    setError('');
    setBusy(null);
  }
  async function request(task: Task) {
    const version = ++generation.current;
    setBusy(task);
    setError('');
    try {
      const result = await post<{ text: string; model: string }>('/api/me/ai/assist', { email_id: email.id, model_id: modelId, task, language });
      if (generation.current === version) setResults((old) => ({ ...old, [task]: result }));
    } catch (err) {
      if (generation.current === version) setError(errorText(err, t('AI assistance failed')));
    } finally {
      if (generation.current === version) setBusy(null);
    }
  }
  if (models.length === 0) return null;
  return (
    <Box component="section" aria-label={t('AI assistance')} sx={{ border: 1, borderColor: 'divider', borderRadius: 1, p: 1.5, my: 1.5 }}>
      <Stack direction="row" spacing={1} flexWrap="wrap" useFlexGap alignItems="center">
        <AutoAwesome color="action" fontSize="small" />
        <TextField select size="small" label={t('AI model')} value={modelId} disabled={Boolean(busy)} onChange={(e) => { select(e.target.value); reset(); }} sx={{ minWidth: 140 }}>
          {models.map((model) => <MenuItem key={model.id} value={model.id}>{model.name}</MenuItem>)}
        </TextField>
        {foreignLanguage && <TextField select size="small" label={t('Target language')} value={language} disabled={Boolean(busy)} onChange={(e) => { setLanguage(e.target.value); reset(); }} sx={{ minWidth: 140 }}>
          {LANGUAGES.map(([code, name]) => <MenuItem key={code} value={code}>{name}</MenuItem>)}
        </TextField>}
        <Button size="small" startIcon={busy === 'summary' ? <CircularProgress size={16} /> : <AutoAwesome />} disabled={Boolean(busy)} onClick={() => void request('summary')}>{t('Summarize')}</Button>
        {foreignLanguage && <Button size="small" startIcon={busy === 'translate' ? <CircularProgress size={16} /> : <Translate />} disabled={Boolean(busy)} onClick={() => void request('translate')}>{t('Translate to {{language}}', { language: LANGUAGES.find(([code]) => code === language)?.[1] ?? language })}</Button>}
      </Stack>
      <Typography variant="caption" color="text.secondary" display="block" sx={{ mt: 1 }}>{foreignLanguage ? t('Request a summary or translation using the selected model.') : t('Request a summary using the selected model.')}</Typography>
      {error && <Alert severity="error" sx={{ mt: 1 }} onClose={() => setError('')}>{error}</Alert>}
      <Box aria-live="polite" aria-busy={Boolean(busy)}>
        {(['summary', 'translate'] as const).map((task) => results[task] && (
          <Box key={task} sx={{ mt: 1.5, borderTop: 1, borderColor: 'divider', pt: 1 }}>
            <Stack direction="row" alignItems="center" spacing={1}>
              <Typography variant="subtitle2" component="h3" sx={{ flex: 1 }}>{task === 'summary' ? t('Summary') : t('Translation')}</Typography>
              <Typography variant="caption" color="text.secondary">{results[task]!.model}</Typography>
              <Button size="small" onClick={() => setResults((old) => ({ ...old, [task]: undefined }))}>{t('Hide')}</Button>
            </Stack>
            <Typography variant="body2" dir="auto" sx={{ whiteSpace: 'pre-wrap', overflowWrap: 'anywhere', mt: 0.5 }}>{results[task]!.text}</Typography>
          </Box>
        ))}
      </Box>
    </Box>
  );
}
