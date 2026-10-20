import { Alert, Button, Card, CardContent, FormControlLabel, Stack, Switch, Typography } from '@mui/material';
import { useState } from 'react';
import { errorText, post } from './api';
import { updatePrefs, usePrefs, type Prefs } from './prefs';
import { t } from './i18n';

export function SummaryCardsSettings() {
  const prefs = usePrefs();
  const [error, setError] = useState('');
  const [message, setMessage] = useState('');
  const [busy, setBusy] = useState(false);
  async function update(patch: Partial<Prefs>) {
    setBusy(true);
    setError('');
    try { await updatePrefs(patch); }
    catch (err) { setError(errorText(err, t('Could not save'))); }
    finally { setBusy(false); }
  }
  async function backfill() {
    setBusy(true);
    setError('');
    try { await post('/api/me/summary-cards/backfill'); setMessage(t('Recent mail queued for purchase cards.')); }
    catch (err) { setError(errorText(err, t('Could not extract purchase card'))); }
    finally { setBusy(false); }
  }
  return <Card variant="outlined"><CardContent>
    <Typography variant="h6">{t('Purchase cards')}</Typography>
    <Typography variant="body2" color="text.secondary" sx={{ mb: 1 }}>{t('Show order and delivery details above your messages. Structured email data is processed locally.')}</Typography>
    {error && <Alert severity="error">{error}</Alert>}
    {message && <Alert severity="success" onClose={() => setMessage('')}>{message}</Alert>}
    <Stack alignItems="flex-start" spacing={1}>
      <FormControlLabel control={<Switch disabled={busy} checked={prefs.summary_cards !== false} onChange={(e) => void update({ summary_cards: e.target.checked })} />} label={t('Show purchase cards')} />
      <FormControlLabel control={<Switch disabled={busy || prefs.summary_cards === false} checked={prefs.summary_cards_ai === true} onChange={(e) => void update({ summary_cards_ai: e.target.checked })} />} label={t('Automatically extract purchases with AI')} />
      <Typography variant="caption" color="text.secondary">{t('When enabled by the administrator, purchase emails may be sent to the configured AI provider. Off by default.')}</Typography>
      <Button variant="outlined" disabled={busy || prefs.summary_cards === false} onClick={() => void backfill()}>{t('Process recent mail')}</Button>
      <Typography variant="caption" color="text.secondary">{t('Processes up to 200 recent messages using your current extraction settings.')}</Typography>
    </Stack>
  </CardContent></Card>;
}

export function SmartReplySettings() {
  const prefs = usePrefs();
  const [error, setError] = useState('');
  const [busy, setBusy] = useState(false);
  return <Card variant="outlined"><CardContent>
    <Typography variant="h6">{t('Smart replies')}</Typography>
    {error && <Alert severity="error">{error}</Alert>}
    <FormControlLabel control={<Switch checked={prefs.smart_reply !== false} disabled={busy} onChange={(event) => {
      setBusy(true);
      setError('');
      void updatePrefs({ smart_reply: event.target.checked }).catch((err) => setError(errorText(err, t('Could not save')))).finally(() => setBusy(false));
    }} />} label={t('Offer AI reply suggestions')} />
    <Typography variant="body2" color="text.secondary">{t('Suggestions are generated only when you request them. Choose one to open a reply draft you can edit before sending.')}</Typography>
  </CardContent></Card>;
}
