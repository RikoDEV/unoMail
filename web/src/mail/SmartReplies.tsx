import AutoAwesome from '@mui/icons-material/AutoAwesome';
import { Alert, Box, Button, Checkbox, CircularProgress, FormControlLabel, MenuItem, Stack, TextField, Tooltip, Typography } from '@mui/material';
import { useEffect, useRef, useState } from 'react';
import { errorText, post } from '../lib/api';
import { currentLanguage, LANGUAGES, t } from '../i18n';
import { usePrefs } from '../lib/prefs';
import { useAiModel } from './AiAssist';

interface Suggestion { label: string; text: string }

/** The model is shared with the summary/translation tools above this message. */
export function SmartReplies({ emailId, onChoose }: { emailId: string; onChoose: (text: string, replyAll: boolean) => void }) {
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
  const busy = busyKey === key;
  const result = state?.key === key ? state.replies : null;

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
  if (!model || prefs.smart_reply === false) return null;
  return (
    <Box component="section" aria-label={t('Smart replies')} sx={{ mt: 2, pt: 1.5, borderTop: 1, borderColor: 'divider' }}>
      <Stack direction="row" alignItems="center" spacing={1} flexWrap="wrap" useFlexGap>
        <Button size="small" startIcon={busy ? <CircularProgress size={16} /> : <AutoAwesome />} disabled={busy} onClick={() => void suggest()}>{result ? t('Suggest again') : t('Suggest replies')}</Button>
        <TextField select size="small" label={t('Reply language')} value={language} disabled={busy} onChange={(e) => { generation.current += 1; setBusyKey(''); setLanguage(e.target.value); }} sx={{ minWidth: 190 }}>
          <MenuItem value="auto">{t('Same language as message')}</MenuItem>
          {LANGUAGES.map((l) => <MenuItem key={l.code} value={l.code}>{l.name}{l.code === currentLanguage() ? ` · ${t('Interface language')}` : ''}</MenuItem>)}
        </TextField>
        <Typography variant="caption" color="text.secondary">{model.name}</Typography>
      </Stack>
      {error?.key === key && <Alert severity="error" sx={{ mt: 1 }} onClose={() => setError(null)}>{error.text}</Alert>}
      <Box aria-live="polite" aria-busy={busy}>
        {result && result.length > 0 && <>
          <Stack direction="row" spacing={1} useFlexGap flexWrap="wrap" sx={{ mt: 1 }}>
            {result.map((reply) => <Tooltip key={reply.label} title={reply.text} describeChild>
              <Button variant="outlined" size="small" onClick={() => onChoose(reply.text, replyAll)} sx={{ textTransform: 'none', borderRadius: 1, whiteSpace: 'normal', overflowWrap: 'anywhere' }}>{reply.label}</Button>
            </Tooltip>)}
          </Stack>
          <Stack direction="row" alignItems="center" flexWrap="wrap" useFlexGap spacing={1}>
            <FormControlLabel control={<Checkbox size="small" checked={replyAll} onChange={(e) => setReplyAll(e.target.checked)} />} label={t('Reply all')} />
            <Typography variant="caption" color="text.secondary">{t('Choose a suggestion to open an editable reply draft.')}</Typography>
            <Button size="small" onClick={() => setState(null)}>{t('Hide')}</Button>
          </Stack>
        </>}
        {result && result.length === 0 && <Typography variant="body2" color="text.secondary" sx={{ mt: 1 }}>{t('No reply suggestions for this message.')}</Typography>}
      </Box>
    </Box>
  );
}
