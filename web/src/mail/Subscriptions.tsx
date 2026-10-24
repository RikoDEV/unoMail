// Manage subscriptions, as in Gmail: the senders of recent mail that offers a way to unsubscribe,
// with how much they send and a button to unsubscribe from each.

import { Alert, Avatar, Box, Button, CircularProgress, Paper, Snackbar, Typography } from '@mui/material';
import { useCallback, useEffect, useState } from 'react';
import { errorText, get, post } from '../lib/api';
import { t } from '../i18n';

interface Subscription {
  sender: string;
  name: string;
  /** Messages from the sender in the last 30 days. */
  recent: number;
}

const COLORS = ['#1a73e8', '#188038', '#d93025', '#e37400', '#9334e6', '#c5221f', '#12b5cb', '#795548', '#e52592', '#5f6368'];
const colorFor = (sender: string) => COLORS[[...sender].reduce((sum, c) => sum + c.charCodeAt(0), 0) % COLORS.length];

function volume(recent: number) {
  if (recent > 20) return t('More than 20 emails recently');
  if (recent > 10) return t('Up to 20 emails recently');
  return t('Up to 10 emails recently');
}

export function Subscriptions() {
  const [list, setList] = useState<Subscription[] | null>(null);
  const [error, setError] = useState('');
  const [busy, setBusy] = useState<string | null>(null);
  const [notice, setNotice] = useState('');

  const load = useCallback(() => {
    get<Subscription[]>('/api/me/subscriptions').then(setList, (err) => setError(errorText(err, t('The subscriptions could not be loaded.'))));
  }, []);
  useEffect(load, [load]);

  async function unsubscribe(entry: Subscription) {
    const name = entry.name || entry.sender;
    if (!window.confirm(t('Unsubscribe from {{sender}}?', { sender: name }))) return;
    setBusy(entry.sender);
    try {
      const result = await post<{ method: 'one-click' | 'mail' | 'link'; to?: string; url?: string }>('/api/me/subscriptions/unsubscribe', { sender: entry.sender });
      if (result.method === 'link' && result.url && /^https?:\/\//i.test(result.url)) {
        // The sender only offers a web page: open it, without telling it where the reader came from.
        window.open(result.url, '_blank', 'noopener,noreferrer');
        setNotice(t('The unsubscribe page of {{sender}} was opened.', { sender: name }));
      } else if (result.method === 'mail') {
        setNotice(t('An unsubscribe request was sent to {{to}}.', { to: result.to }));
      } else {
        setNotice(t('You have been unsubscribed.'));
      }
      setList((current) => current?.filter((s) => s.sender !== entry.sender) ?? null);
    } catch (err) {
      setNotice(errorText(err, t('Unsubscribing failed.')));
    } finally {
      setBusy(null);
    }
  }

  return (
    <Paper elevation={0} sx={{ flex: 1, display: 'flex', flexDirection: 'column', borderRadius: 1.5, mx: { xs: 1, md: 0 }, mr: { md: 1 }, mb: 1, overflow: 'auto', minWidth: 0 }}>
      <Box sx={{ px: 2, pt: 2, pb: 1 }}>
        <Typography variant="h6" component="h1">{t('Subscriptions')}</Typography>
        <Typography variant="caption" sx={{ color: 'text.secondary' }}>{t('After you unsubscribe, it can take senders a few days to stop sending you mail.')}</Typography>
      </Box>
      {error && <Alert severity="error" sx={{ mx: 2 }}>{error}</Alert>}
      {!list && !error && <CircularProgress sx={{ m: 4, alignSelf: 'center' }} aria-label={t('Loading')} />}
      {list?.length === 0 && <Typography
        sx={{ color: 'text.secondary', px: 2, py: 4 }}>{t('No subscriptions in your recent mail.')}</Typography>}
      <Box component="ul" aria-label={t('Subscriptions')} sx={{ listStyle: 'none', m: 0, p: 0 }}>
        {list?.map((entry) => {
          const name = entry.name || entry.sender;
          return (
            <Box
              component="li"
              key={entry.sender}
              sx={{
                display: 'grid', alignItems: 'center', columnGap: 2, px: 2, minHeight: 50,
                gridTemplateColumns: { xs: 'minmax(0, 1fr) auto', md: 'minmax(0, 3fr) minmax(0, 3.5fr) minmax(0, 3.5fr) auto' },
              }}
            >
              <Box sx={{ display: 'flex', alignItems: 'center', gap: 1.5, minWidth: 0 }}>
                <Avatar aria-hidden sx={{ width: 20, height: 20, fontSize: 11, bgcolor: colorFor(entry.sender), color: '#fff' }}>{name[0]?.toUpperCase()}</Avatar>
                <Box sx={{ minWidth: 0 }}>
                  <Typography variant="body2" noWrap sx={{ fontWeight: 600 }}>{name}</Typography>
                  <Typography
                    variant="caption"
                    noWrap
                    component="div"
                    sx={{
                      color: "text.secondary",
                      display: { md: 'none' }
                    }}>{entry.sender}</Typography>
                </Box>
              </Box>
              <Typography
                variant="body2"
                noWrap
                sx={{
                  color: "text.secondary",
                  display: { xs: 'none', md: 'block' }
                }}>{entry.sender}</Typography>
              <Typography
                variant="body2"
                noWrap
                sx={{
                  color: "text.secondary",
                  display: { xs: 'none', md: 'block' }
                }}>{volume(entry.recent)}</Typography>
              <Button size="small" color="inherit" disabled={busy === entry.sender} onClick={() => void unsubscribe(entry)} sx={{ textTransform: 'none', fontWeight: 600 }} aria-label={t('Unsubscribe from {{sender}}', { sender: name })}>
                {t('Unsubscribe')}
              </Button>
            </Box>
          );
        })}
      </Box>
      <Snackbar open={Boolean(notice)} autoHideDuration={6000} onClose={() => setNotice('')} message={notice} />
    </Paper>
  );
}
