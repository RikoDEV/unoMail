import AutoAwesome from '@mui/icons-material/AutoAwesome';
import { Alert, Box, Button, Checkbox, CircularProgress, FormControlLabel, ListSubheader, MenuItem, Stack, Tooltip, Typography } from '@mui/material';
import { useEffect, useRef, useState } from 'react';
import { errorText, post } from '../lib/api';
import { currentLanguage, LANGUAGES, t } from '../i18n';
import { usePrefs } from '../lib/prefs';
import { SplitButton } from '../ui/splitButton';
import { useAiModel } from './AiAssist';

interface Suggestion { label: string; text: string }

/** Reply suggestions for one message: state shared by the button beside Reply and the suggestions above it. */
export function useSmartReplies(emailId: string, allowed: boolean) {
  const { model } = useAiModel();
  const prefs = usePrefs();
  const [language, setLanguage] = useState('auto');
  const [replyAll, setReplyAll] = useState(false);
  const [state, setState] = useState<{ key: string; replies: Suggestion[] } | null>(null);
  const [busyKey, setBusyKey] = useState('');
  const [error, setError] = useState<{ key: string; text: string } | null>(null);
  const key = `${emailId}:${model?.id ?? ''}:${language}`;
  const latestKey = useRef(key);
  latestKey.current = key;
  const generation = useRef(0);
  useEffect(() => () => { generation.current += 1; }, []);

  async function suggest() {
    if (!model) return;
    const version = ++generation.current;
    const requestKey = key;
    setBusyKey(requestKey);
    setError(null);
    try {
      const response = await post<{ replies: Suggestion[] }>('/api/me/ai/replies', { email_id: emailId, model_id: model.id, language });
      if (generation.current === version && latestKey.current === requestKey) setState({ key: requestKey, replies: response.replies });
    } catch (err) {
      if (generation.current === version && latestKey.current === requestKey) setError({ key: requestKey, text: errorText(err, t('Could not suggest replies')) });
    } finally {
      if (generation.current === version) setBusyKey('');
    }
  }
  return {
    available: allowed && Boolean(model) && prefs.smart_reply !== false,
    language, replyAll, setReplyAll,
    busy: busyKey === key,
    result: state?.key === key ? state.replies : null,
    error: error?.key === key ? error.text : '',
    suggest,
    chooseLanguage: (code: string) => { generation.current += 1; setBusyKey(''); setLanguage(code); },
    dismissError: () => setError(null),
    hide: () => setState(null),
  };
}

export type SmartRepliesState = ReturnType<typeof useSmartReplies>;

/** "Suggest replies" in the row of Reply / Reply all / Forward, with the reply language in its menu. */
export function SmartReplyButton({ replies }: { replies: SmartRepliesState }) {
  if (!replies.available) return null;
  return (
    <SplitButton
      startIcon={replies.busy ? <CircularProgress size={16} /> : <AutoAwesome />}
      disabled={replies.busy}
      onClick={() => void replies.suggest()}
      menuLabel={t('Reply language')}
      menu={(close) => [
        <ListSubheader key="heading">{t('Reply language')}</ListSubheader>,
        <MenuItem key="auto" selected={replies.language === 'auto'} onClick={() => { replies.chooseLanguage('auto'); close(); }}>{t('Same language as message')}</MenuItem>,
        ...LANGUAGES.map((l) => (
          <MenuItem key={l.code} selected={replies.language === l.code} onClick={() => { replies.chooseLanguage(l.code); close(); }}>
            {l.name}{l.code === currentLanguage() ? ` · ${t('Interface language')}` : ''}
          </MenuItem>
        )),
      ]}
    >
      {replies.result ? t('Suggest again') : t('Suggest replies')}
    </SplitButton>
  );
}

/** The suggestions asked for, as chips above the reply buttons; nothing until requested. */
export function SmartReplySuggestions({ replies, onChoose }: { replies: SmartRepliesState; onChoose: (text: string, replyAll: boolean) => void }) {
  if (!replies.available) return null;
  const { result } = replies;
  return (
    <Box component="section" aria-label={t('Smart replies')} aria-live="polite" aria-busy={replies.busy}>
      {replies.error && <Alert severity="error" sx={{ mt: 2 }} onClose={replies.dismissError}>{replies.error}</Alert>}
      {result && result.length > 0 && (
        <Stack direction="row" spacing={1} useFlexGap sx={{ flexWrap: 'wrap', alignItems: 'center', mt: 2 }}>
          <AutoAwesome color="primary" sx={{ fontSize: 18 }} aria-hidden />
          {result.map((reply) => (
            <Tooltip key={reply.label} title={reply.text} describeChild>
              <Button variant="outlined" size="small" onClick={() => onChoose(reply.text, replies.replyAll)} sx={{ textTransform: 'none', borderRadius: 4, whiteSpace: 'normal', overflowWrap: 'anywhere' }}>{reply.label}</Button>
            </Tooltip>
          ))}
          <FormControlLabel sx={{ ml: 0.5 }} control={<Checkbox size="small" checked={replies.replyAll} onChange={(e) => replies.setReplyAll(e.target.checked)} />} label={t('Reply all')} />
          <Button size="small" onClick={replies.hide}>{t('Hide')}</Button>
        </Stack>
      )}
      {result && result.length === 0 && <Typography variant="body2" sx={{ color: 'text.secondary', mt: 2 }}>{t('No reply suggestions for this message.')}</Typography>}
    </Box>
  );
}
