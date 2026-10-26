import CloudOff from '@mui/icons-material/CloudOff';
import ErrorOutlined from '@mui/icons-material/ErrorOutlined';
import { Box, Button, CircularProgress, Paper, Stack, Typography } from '@mui/material';
import { useEffect, useState } from 'react';
import { ApiError } from '../lib/api';
import { t } from '../i18n';
import { Logo } from './shell';

/** Whether an error means the server could not be reached, rather than a fault of the page. */
export function isUnreachable(error: unknown): boolean {
  if (typeof navigator !== 'undefined' && !navigator.onLine) return true;
  if (error instanceof ApiError) return error.status >= 500;
  // fetch() rejects with a TypeError when there is no answer at all; a lazily loaded page whose
  // code cannot be downloaded fails with a message naming the module.
  const message = error instanceof Error ? error.message : String(error);
  return error instanceof TypeError || /dynamically imported module|Importing a module script failed|Loading chunk|error loading dynamically/i.test(message);
}

const CHECK_EVERY_MS = 5000;

/**
 * The whole page when something stops it: the server cannot be reached (it checks again by itself
 * and reloads once the server answers), or the page itself failed to render.
 */
export function ProblemPage({ kind, onRetry }: { kind: 'unreachable' | 'failed'; onRetry: () => void }) {
  const [checking, setChecking] = useState(false);

  useEffect(() => {
    if (kind !== 'unreachable') return;
    let stopped = false;
    const check = async () => {
      setChecking(true);
      try {
        // Any answer below 500, even "not signed in", means the server is back.
        const response = await fetch('/api/auth/me', { credentials: 'same-origin' });
        if (!stopped && response.status < 500) onRetry();
      } catch {
        // Still unreachable.
      } finally {
        if (!stopped) setChecking(false);
      }
    };
    const timer = window.setInterval(() => void check(), CHECK_EVERY_MS);
    const online = () => void check();
    window.addEventListener('online', online);
    return () => {
      stopped = true;
      window.clearInterval(timer);
      window.removeEventListener('online', online);
    };
  }, [kind, onRetry]);

  const unreachable = kind === 'unreachable';
  return (
    <Box sx={{ minHeight: '100vh', display: 'flex', alignItems: 'center', justifyContent: 'center', p: 2, bgcolor: 'background.default' }}>
      <Paper elevation={0} role="alert" sx={{ width: '100%', maxWidth: 440, p: { xs: 3, sm: 4 }, textAlign: 'center', bgcolor: 'm3.surfaceContainerHigh' }}>
        <Stack spacing={2} sx={{ alignItems: 'center' }}>
          <Box sx={{ position: 'relative', mb: 1 }}>
            <Logo size={56} />
            <Box sx={{ position: 'absolute', right: -10, bottom: -10, display: 'flex', p: 0.5, borderRadius: '50%', bgcolor: 'm3.surfaceContainerHigh' }}>
              {unreachable ? <CloudOff color="action" /> : <ErrorOutlined color="error" />}
            </Box>
          </Box>
          <Typography variant="h5" component="h1">
            {unreachable ? t("unoMail can't be reached") : t('Something went wrong')}
          </Typography>
          <Typography sx={{ color: 'text.secondary' }}>
            {unreachable
              ? t('The server may be restarting, or your connection is down. This page reloads by itself once the server is back.')
              : t('This page could not be shown. Try again, or go back to your inbox.')}
          </Typography>
          <Stack direction="row" spacing={1} sx={{ pt: 1, alignItems: 'center' }}>
            <Button variant="contained" disableElevation onClick={onRetry}>{t('Try again')}</Button>
            {!unreachable && <Button href="/mail">{t('Go to the inbox')}</Button>}
          </Stack>
          {unreachable && (
            <Stack direction="row" spacing={1} sx={{ alignItems: 'center', color: 'text.secondary', minHeight: 20 }} aria-live="polite">
              {checking && <CircularProgress size={14} color="inherit" />}
              <Typography variant="caption">{checking ? t('Checking the connection…') : t('Checking again every few seconds')}</Typography>
            </Stack>
          )}
        </Stack>
      </Paper>
    </Box>
  );
}
