// The sandboxed frames plug-ins run in. They stay mounted, in a fixed order, for the whole
// session: moving an iframe in the document reloads it, so opening a plug-in's panel only
// changes where its frame is shown. The panel's title bar belongs to us, so a plug-in cannot
// pass its panel off as part of the application.

import Close from '@mui/icons-material/Close';
import { Box, Button, Dialog, DialogActions, DialogContent, DialogContentText, DialogTitle, IconButton, Paper, Tooltip, Typography, useTheme } from '@mui/material';
import { useEffect } from 'react';
import { useNavigate } from 'react-router-dom';
import { answerAuth, connectFrame, setHostNavigator, setPanelClosed, useAuthRequest, useFrames } from './host';

import { chosenLanguage, isRtl, t } from '../i18n';

export function PluginFrames() {
  const frames = useFrames();
  const theme = useTheme();
  const navigate = useNavigate();
  useEffect(() => setHostNavigator(navigate), [navigate]);
  const dark = theme.palette.mode === 'dark';
  const auth = useAuthRequest();
  return (
    <>
      {/* The user sees who asks to sign them in where, and the window opens from their click. */}
      <Dialog open={Boolean(auth)} onClose={() => answerAuth(false)}>
        <DialogTitle>{t('Sign in to {{host}}?', { host: auth?.host ?? '' })}</DialogTitle>
        <DialogContent>
          <DialogContentText>{t('The plug-in {{name}} asks you to sign in at {{host}} in a new window, to connect your account there.', { name: auth?.pluginName ?? '', host: auth?.host ?? '' })}</DialogContentText>
        </DialogContent>
        <DialogActions>
          <Button onClick={() => answerAuth(false)}>{t('Cancel')}</Button>
          <Button variant="contained" onClick={() => answerAuth(true)}>{t('Continue')}</Button>
        </DialogActions>
      </Dialog>
      {frames.map((frame) => (
        <Paper
          key={frame.id}
          elevation={frame.panel.open ? 8 : 0}
          role={frame.panel.open ? 'complementary' : undefined}
          aria-label={frame.panel.open ? t('{{name}} (plug-in)', { name: frame.name }) : undefined}
          aria-hidden={!frame.panel.open}
          sx={
            frame.panel.open
              ? { position: 'fixed', insetBlock: 0, insetInlineEnd: 0, width: { xs: '100vw', sm: 380 }, zIndex: theme.zIndex.drawer + 1, display: 'flex', flexDirection: 'column', borderRadius: 0 }
              : { position: 'fixed', width: 0, height: 0, overflow: 'hidden', visibility: 'hidden', pointerEvents: 'none' }
          }>
          <Box sx={{ display: 'flex', alignItems: 'center', gap: 1, px: 2, py: 1, borderBottom: 1, borderColor: 'divider' }}>
            <Box sx={{ flex: 1, minWidth: 0 }}>
              <Typography variant="subtitle1" noWrap>{frame.panel.title}</Typography>
              <Typography variant="caption" color="text.secondary" noWrap component="div">{t('Plug-in: {{name}}', { name: frame.name })}</Typography>
            </Box>
            <Tooltip title={t('Close')}>
              <IconButton aria-label={t('Close')} onClick={() => setPanelClosed(frame.id)}><Close /></IconButton>
            </Tooltip>
          </Box>
          <Box
            component="iframe"
            title={t('{{name}} (plug-in)', { name: frame.name })}
            sandbox="allow-scripts"
            referrerPolicy="no-referrer"
            src={`/plugin-frame/${encodeURIComponent(frame.id)}/${encodeURIComponent(frame.commit)}`}
            onLoad={(e) => connectFrame(frame.id, e.currentTarget as HTMLIFrameElement, { locale: chosenLanguage() ?? document.documentElement.lang, dir: isRtl() ? 'rtl' : 'ltr', dark })}
            sx={{ flex: 1, border: 0, width: '100%', bgcolor: 'background.paper' }}
          />
        </Paper>
      ))}
    </>
  );
}
