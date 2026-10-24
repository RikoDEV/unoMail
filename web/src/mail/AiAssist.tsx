import AutoAwesome from '@mui/icons-material/AutoAwesome';
import Translate from '@mui/icons-material/Translate';
import { Alert, Box, Button, CircularProgress, IconButton, ListSubheader, MenuItem, Stack, TextField, Tooltip, Typography } from '@mui/material';
import { createContext, useContext, useEffect, useRef, useState, type ReactNode } from 'react';
import { errorText, get, post } from '../lib/api';
import { SplitButton } from '../ui/splitButton';
import { currentLanguage, t } from '../i18n';
import type { EmailFull } from './jmapClient';
import { canTranslateLocally, localTranslationSupported, translateLocally } from './localTranslator';

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

/** AI summary and translation of one message: state shared by the header buttons and the result shown above the body. */
export function useAiAssist(email: EmailFull) {
  const { models, model, select } = useAiModel();
  const [foreignLanguage, setForeignLanguage] = useState(false);
  const [source, setSource] = useState<string | null>(null);
  // Without an AI model, translation can still run on the device where the browser supports it.
  const local = models.length === 0 && localTranslationSupported();
  useEffect(() => {
    if (!models.length && !local) return;
    let active = true;
    import('./messageLanguage').then(({ detectMessageLanguage, translationSuggested }) => {
      const detected = detectMessageLanguage(email);
      if (active) { setSource(detected); setForeignLanguage(translationSuggested(detected, currentLanguage())); }
    }).catch(() => { if (active) setForeignLanguage(false); });
    return () => { active = false; };
  }, [email, models.length, local]);
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
  return {
    email, models, modelId, foreignLanguage, source, local, language, busy, error, results,
    chooseModel: (id: string) => { select(id); reset(); },
    chooseLanguage: (code: string) => { setLanguage(code); reset(); },
    request,
    dismissError: () => setError(''),
    hide: (task: Task) => setResults((old) => ({ ...old, [task]: undefined })),
  };
}

export type AiAssistState = ReturnType<typeof useAiAssist>;

const languageName = (code: string) => LANGUAGES.find(([c]) => c === code)?.[1] ?? code;

/** Summarize and Translate, beside Unsubscribe in the message header; icons only on a phone. */
export function AiAssistButtons({ ai, compact }: { ai: AiAssistState; compact: boolean }) {
  if (ai.models.length === 0) return null;
  const busy = Boolean(ai.busy);
  const translateLabel = t('Translate to {{language}}', { language: languageName(ai.language) });
  const icon = (task: Task, symbol: ReactNode) => (ai.busy === task ? <CircularProgress size={compact ? 18 : 16} /> : symbol);
  // The model and target language are the options of the last action, as one split button.
  const options = (close: () => void) => [
    ...(ai.models.length > 1 ? [
      <ListSubheader key="model">{t('AI model')}</ListSubheader>,
      ...ai.models.map((model) => <MenuItem key={model.id} selected={model.id === ai.modelId} onClick={() => { ai.chooseModel(model.id); close(); }}>{model.name}</MenuItem>),
    ] : []),
    ...(ai.foreignLanguage ? [
      <ListSubheader key="language">{t('Target language')}</ListSubheader>,
      ...LANGUAGES.map(([code, name]) => <MenuItem key={code} selected={code === ai.language} onClick={() => { ai.chooseLanguage(code); close(); }}>{name}</MenuItem>),
    ] : []),
  ];
  const withOptions = ai.models.length > 1 || ai.foreignLanguage;
  const action = (task: Task, label: string, symbol: ReactNode, last: boolean) => {
    if (last && withOptions) {
      return (
        <SplitButton variant="text" size="small" disabled={busy} onClick={() => void ai.request(task)} menuLabel={t('AI options')} menu={options}
          {...(compact ? { 'aria-label': label } : { startIcon: icon(task, symbol) })}>
          {compact ? icon(task, symbol) : label}
        </SplitButton>
      );
    }
    return compact ? (
      <Tooltip title={label}><span><IconButton size="small" aria-label={label} disabled={busy} onClick={() => void ai.request(task)}>{icon(task, symbol)}</IconButton></span></Tooltip>
    ) : (
      <Button size="small" startIcon={icon(task, symbol)} disabled={busy} onClick={() => void ai.request(task)} sx={{ flexShrink: 0 }}>{label}</Button>
    );
  };
  return (
    <Stack direction="row" role="group" aria-label={t('AI assistance')} sx={{ alignItems: 'center', flexShrink: 0, gap: 0.5 }}>
      {action('summary', t('Summarize'), <AutoAwesome />, !ai.foreignLanguage)}
      {ai.foreignLanguage && action('translate', translateLabel, <Translate />, true)}
    </Stack>
  );
}

/** The summary or translation asked for, above the message; nothing until one is requested. */
export function AiAssistResults({ ai }: { ai: AiAssistState }) {
  if (ai.models.length === 0) return ai.local && ai.foreignLanguage && ai.source ? <LocalTranslation email={ai.email} source={ai.source} /> : null;
  const shown = (['summary', 'translate'] as const).filter((task) => ai.results[task]);
  return (
    <Box aria-live="polite" aria-busy={Boolean(ai.busy)}>
      {ai.error && <Alert severity="error" sx={{ my: 1 }} onClose={ai.dismissError}>{ai.error}</Alert>}
      {shown.map((task) => (
        <Box key={task} component="section" aria-label={task === 'summary' ? t('Summary') : t('Translation')} sx={{ my: 1, pl: 1.5, borderLeft: 3, borderColor: 'primary.main' }}>
          <Stack direction="row" spacing={1} sx={{ alignItems: 'center' }}>
            {task === 'summary' ? <AutoAwesome color="primary" sx={{ fontSize: 16 }} /> : <Translate color="primary" sx={{ fontSize: 16 }} />}
            <Typography variant="subtitle2" component="h3" sx={{ flex: 1 }}>{task === 'summary' ? t('Summary') : t('Translation')}</Typography>
            <Typography variant="caption" sx={{ color: 'text.secondary' }}>{ai.results[task]!.model}</Typography>
            <Button size="small" onClick={() => ai.hide(task)}>{t('Hide')}</Button>
          </Stack>
          <Typography variant="body2" dir="auto" sx={{ whiteSpace: 'pre-wrap', overflowWrap: 'anywhere' }}>{ai.results[task]!.text}</Typography>
        </Box>
      ))}
    </Box>
  );
}

/** Translation by the browser's on-device model, offered when no AI model is configured. */
function LocalTranslation({ email, source }: { email: EmailFull; source: string }) {
  const [language, setLanguage] = useState(currentLanguage().split(/[-_]/)[0]);
  const [available, setAvailable] = useState(false);
  const [busy, setBusy] = useState(false);
  const [progress, setProgress] = useState<number | null>(null);
  const [error, setError] = useState('');
  const [result, setResult] = useState('');
  const generation = useRef(0);
  const running = useRef<AbortController | null>(null);
  const cancel = () => { generation.current += 1; running.current?.abort(); running.current = null; };
  useEffect(() => cancel, []);
  useEffect(() => {
    let active = true;
    setAvailable(false);
    void canTranslateLocally(source, language).then((ok) => { if (active) setAvailable(ok); });
    return () => { active = false; };
  }, [source, language]);

  async function translate() {
    cancel();
    const version = generation.current;
    const controller = new AbortController();
    running.current = controller;
    setBusy(true);
    setError('');
    setProgress(null);
    try {
      const text = import('./messageLanguage').then(({ messageText }) => `${email.subject ?? ''}

${messageText(email)}`.trim());
      const translated = await translateLocally(text, source, language, controller.signal, (share) => { if (generation.current === version) setProgress(share); });
      if (generation.current === version) setResult(translated);
    } catch (err) {
      if (generation.current === version) setError(errorText(err, t('Translation on this device failed')));
    } finally {
      if (generation.current === version) { setBusy(false); setProgress(null); running.current = null; }
    }
  }
  const languageName = LANGUAGES.find(([code]) => code === language)?.[1] ?? language;
  return (
    <Box component="section" aria-label={t('Translation')} sx={{ border: 1, borderColor: 'divider', borderRadius: 1, p: 1.5, my: 1.5 }}>
      <Stack direction="row" spacing={1} useFlexGap sx={{ flexWrap: 'wrap', alignItems: 'center' }}>
        <Translate color="action" fontSize="small" />
        <TextField select size="small" label={t('Target language')} value={language} disabled={busy} onChange={(e) => { cancel(); setLanguage(e.target.value); setResult(''); setError(''); setBusy(false); }} sx={{ minWidth: 140 }}>
          {LANGUAGES.map(([code, name]) => <MenuItem key={code} value={code}>{name}</MenuItem>)}
        </TextField>
        <Button size="small" startIcon={busy ? <CircularProgress size={16} /> : <Translate />} disabled={busy || !available} onClick={() => void translate()}>{t('Translate to {{language}}', { language: languageName })}</Button>
      </Stack>
      <Typography variant="caption" sx={{ color: 'text.secondary', display: 'block', mt: 1 }}>
        {!available ? t('This browser cannot translate into this language on the device.') : progress !== null && progress < 1 ? t('Downloading the language pack: {{percent}}%', { percent: Math.round(progress * 100) }) : t('Translated on this device; the message is not sent anywhere.')}
      </Typography>
      {error && <Alert severity="error" sx={{ mt: 1 }} onClose={() => setError('')}>{error}</Alert>}
      <Box aria-live="polite" aria-busy={busy}>
        {result && (
          <Box sx={{ mt: 1.5, borderTop: 1, borderColor: 'divider', pt: 1 }}>
            <Stack direction="row" spacing={1} sx={{ alignItems: 'center' }}>
              <Typography variant="subtitle2" component="h3" sx={{ flex: 1 }}>{t('Translation')}</Typography>
              <Button size="small" onClick={() => setResult('')}>{t('Hide')}</Button>
            </Stack>
            <Typography variant="body2" dir="auto" sx={{ whiteSpace: 'pre-wrap', overflowWrap: 'anywhere', mt: 0.5 }}>{result}</Typography>
          </Box>
        )}
      </Box>
    </Box>
  );
}
