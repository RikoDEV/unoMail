// Settings of the web client itself: sending, notifications, the message list and the skin.

import Check from '@mui/icons-material/Check';
import {
  Alert, Box, Button, Card, CardContent, FormControlLabel, MenuItem, Stack, Switch,
  TextField, Typography,
} from '@mui/material';
import { useEffect, useState } from 'react';
import { SEEDS, useAppearance, useAuth } from './app';
import { updatePrefs, usePrefs } from './prefs';
import { errorText } from './api';
import { mailtoHandlerSupported, registerMailtoHandler } from './mail/mailto';
import { disableNotifications, enableNotifications, notificationsEnabled, notificationsSupported, pageNotificationsOn } from './mail/notifications';
import { persistentCacheEnabled, setPersistentCache } from './mail/cache';
import { BUILT_IN_SKINS, skinIsDark } from './skins';

import { t } from './i18n';
/** Plain text typed into a settings field, as the HTML that is stored. */

/** Sending: the time to call a message back, and answering read receipt requests. */
export function SendingCard() {
  const prefs = usePrefs();
  return (
    <Card variant="outlined">
      <CardContent>
        <Typography variant="h6" sx={{ mb: 2 }}>
          {t('Sending')}
        </Typography>
        <Stack spacing={2} sx={{ maxWidth: 420 }}>
          <TextField select label={t('Undo send')} value={prefs.undo_send_seconds ?? 5} onChange={(e) => void updatePrefs({ undo_send_seconds: Number(e.target.value) }).catch(() => {})} helperText={t('How long a sent message can be called back')}>
            {[0, 5, 10, 20, 30].map((seconds) => (
              <MenuItem key={seconds} value={seconds}>{seconds === 0 ? t('Off') : t('{{count}} seconds', { count: seconds })}</MenuItem>
            ))}
          </TextField>
          <TextField select label={t('Read receipts')} value={prefs.receipts ?? 'ask'} onChange={(e) => void updatePrefs({ receipts: e.target.value as 'ask' | 'always' | 'never' }).catch(() => {})} helperText={t('When a sender asks to be told that you read their message')}>
            <MenuItem value="ask">{t('Ask me each time')}</MenuItem>
            <MenuItem value="always">{t('Always send one')}</MenuItem>
            <MenuItem value="never">{t('Never send one')}</MenuItem>
          </TextField>
        </Stack>
      </CardContent>
    </Card>
  );
}

/** New-mail notifications in this browser (Web Push, or from the open tab), and mailto: links. */
export function NotificationsCard() {
  const { account } = useAuth();
  const email = account?.email ?? '';
  const [enabled, setEnabled] = useState<boolean | null>(null);
  const [pageOnly, setPageOnly] = useState(false);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState('');
  const [mailtoAsked, setMailtoAsked] = useState(false);
  useEffect(() => {
    notificationsEnabled(email).then(setEnabled, () => setEnabled(false));
    setPageOnly(pageNotificationsOn(email));
  }, [email]);
  const toggle = async (on: boolean) => {
    setBusy(true);
    setError('');
    try {
      if (on) setPageOnly((await enableNotifications(email)) === 'page');
      else await disableNotifications(email);
      setEnabled(on);
    } catch (err) {
      setError(errorText(err, t('Notifications could not be changed')));
    } finally {
      setBusy(false);
    }
  };
  return (
    <Card variant="outlined">
      <CardContent>
        <Typography variant="h6" sx={{ mb: 1 }}>
          {t('Notifications')}
        </Typography>
        {notificationsSupported() ? (
          <FormControlLabel
            control={<Switch checked={Boolean(enabled)} disabled={busy || enabled === null} onChange={(e) => void toggle(e.target.checked)} inputProps={{ 'aria-label': t('Notify me of new mail') }} />}
            label={t('Notify me of new mail in this browser, also when unoMail is closed')}
          />
        ) : (
          <Typography color="text.secondary">{t('This browser cannot show notifications.')}</Typography>
        )}
        {enabled && pageOnly && (
          <Typography variant="body2" color="text.secondary">{t('Push notifications are not available here, so they appear only while unoMail is open in a tab.')}</Typography>
        )}
        {error && <Alert severity="error" sx={{ mt: 1 }} onClose={() => setError('')}>{error}</Alert>}
        {mailtoHandlerSupported() && (
          <Stack direction="row" spacing={2} alignItems="center" flexWrap="wrap" useFlexGap sx={{ mt: 2 }}>
            <Button
              variant="outlined"
              onClick={() => {
                try {
                  registerMailtoHandler();
                  setMailtoAsked(true);
                } catch (err) {
                  setError(errorText(err, t('The browser did not accept unoMail for mail links')));
                }
              }}
            >
              {t('Open mail links with unoMail')}
            </Button>
            <Typography variant="body2" color="text.secondary">
              {mailtoAsked ? t('Confirm in the browser (look for a prompt near the address bar).') : t('mailto: links on other sites will open a new message here.')}
            </Typography>
          </Stack>
        )}
      </CardContent>
    </Card>
  );
}

// --- Appearance ----------------------------------------------------------------------------

/** How the message list shows conversations; the same next to an open conversation as without. */
export function MessageListCard() {
  const [offline, setOffline] = useState(persistentCacheEnabled);
  const prefs = usePrefs();
  const density = prefs.density ?? 'condensed';
  const options: { value: 'condensed' | 'expanded'; title: string; text: string }[] = [
    { value: 'condensed', title: t('Condensed'), text: t('One line per conversation: sender, subject and the start of the text.') },
    { value: 'expanded', title: t('Expanded'), text: t('Sender picture, subject and text on separate lines, and the attached files.') },
  ];
  return (
    <Card variant="outlined">
      <CardContent>
        <Typography variant="h6" sx={{ mb: 1 }}>
          {t('Message list')}
        </Typography>
        <Stack direction={{ xs: 'column', sm: 'row' }} gap={1.5} role="radiogroup" aria-label={t('Message list density')}>
          {options.map((option) => (
            <Box
              key={option.value}
              component="button"
              type="button"
              role="radio"
              aria-checked={density === option.value}
              onClick={() => void updatePrefs({ density: option.value }).catch(() => {})}
              sx={{ flex: 1, maxWidth: 340, p: 1.5, textAlign: 'left', font: 'inherit', color: 'text.primary', bgcolor: 'background.paper', cursor: 'pointer', borderRadius: 2, border: 2, borderColor: density === option.value ? 'primary.main' : 'divider' }}
            >
              {/* A small drawing of a list row in this style. */}
              <Box aria-hidden sx={{ mb: 1, p: 1, borderRadius: 1, bgcolor: 'action.hover', display: 'flex', gap: 1, alignItems: option.value === 'expanded' ? 'flex-start' : 'center' }}>
                <Box sx={{ width: option.value === 'expanded' ? 24 : 14, height: option.value === 'expanded' ? 24 : 14, borderRadius: '50%', bgcolor: 'secondary.main', flexShrink: 0 }} />
                {option.value === 'expanded' ? (
                  <Stack spacing={0.5} sx={{ flex: 1 }}>
                    <Box sx={{ height: 6, width: '40%', bgcolor: 'text.primary', opacity: 0.6, borderRadius: 1 }} />
                    <Box sx={{ height: 6, width: '85%', bgcolor: 'text.secondary', opacity: 0.5, borderRadius: 1 }} />
                    <Box sx={{ height: 12, width: 64, border: 1, borderColor: 'text.secondary', opacity: 0.6, borderRadius: 2 }} />
                  </Stack>
                ) : (
                  <Stack direction="row" spacing={1} sx={{ flex: 1 }}>
                    <Box sx={{ height: 6, width: '25%', bgcolor: 'text.primary', opacity: 0.6, borderRadius: 1 }} />
                    <Box sx={{ height: 6, flex: 1, bgcolor: 'text.secondary', opacity: 0.5, borderRadius: 1 }} />
                  </Stack>
                )}
              </Box>
              <Typography fontWeight={600}>{option.title}</Typography>
              <Typography variant="body2" color="text.secondary">{option.text}</Typography>
            </Box>
          ))}
        </Stack>
        <FormControlLabel sx={{ mt: 1.5 }} control={<Switch checked={offline} onChange={(_, enabled) => { setPersistentCache(enabled); setOffline(enabled); }} />} label="Keep mail offline on this trusted device" />
        <Typography variant="body2" color="text.secondary">Off by default. Cached messages are stored unencrypted in this browser and removed on sign-out.</Typography>
      </CardContent>
    </Card>
  );
}

/** The nearest ancestor that scrolls, or the page. */
function scrollParent(element: HTMLElement): HTMLElement {
  for (let node = element.parentElement; node; node = node.parentElement) {
    if (/(auto|scroll)/.test(getComputedStyle(node).overflowY) && node.scrollHeight > node.clientHeight) return node;
  }
  return (document.scrollingElement as HTMLElement | null) ?? document.documentElement;
}

/**
 * Applies a change that restyles the whole page (another skin brings other spacing and fonts)
 * while keeping the control that was clicked where it is on screen, so the page does not jump.
 */
function keepInPlace(element: HTMLElement, change: () => void) {
  const before = element.getBoundingClientRect().top;
  const scroller = scrollParent(element);
  change();
  // A few frames: the new styles apply on the next render, a skin's font may come a little later.
  const settle = (frames: number) =>
    requestAnimationFrame(() => {
      const target = scroller.scrollTop + element.getBoundingClientRect().top - before;
      // Near the end of the page a shorter skin leaves too little to scroll; room is added below
      // (until the settings section is left), rather than letting the page pull the control down.
      scroller.style.removeProperty('padding-bottom');
      const missing = target - (scroller.scrollHeight - scroller.clientHeight);
      if (missing > 0) {
        scroller.style.paddingBottom = `${parseFloat(getComputedStyle(scroller).paddingBottom) + missing}px`;
        scroller.dataset.keptRoom = 'true';
      }
      scroller.scrollTop = target;
      if (frames > 1) settle(frames - 1);
    });
  settle(4);
}

/** Takes back the room added by keepInPlace. */
function releaseKeptRoom() {
  document.querySelectorAll<HTMLElement>('[data-kept-room]').forEach((element) => {
    element.style.removeProperty('padding-bottom');
    delete element.dataset.keptRoom;
  });
}

export function AppearanceCard() {
  const { skin, skins, setSkin, seed, setSeed } = useAppearance();
  useEffect(() => releaseKeptRoom, []);
  // Skins with a colour scheme of their own ignore the accent colour.
  const takesAccent = !skin.primary;
  return (
    <Card variant="outlined">
      <CardContent>
        <Typography variant="h6" sx={{ mb: 1 }}>
          {t('Appearance')}
        </Typography>
        <Typography variant="body2" color="text.secondary" sx={{ mb: 2 }}>
          {t('Choose a skin. Light and dark mode are in the account menu.')}
        </Typography>
        <Stack direction="row" flexWrap="wrap" gap={1.5} role="radiogroup" aria-label={t('Skin')}>
          {skins.map((candidate) => {
            const dark = skinIsDark(candidate, false);
            const custom = !BUILT_IN_SKINS.some((builtIn) => builtIn.id === candidate.id);
            return (
              <Box
                key={candidate.id}
                component="button"
                role="radio"
                aria-checked={candidate.id === skin.id}
                onClick={(event) => keepInPlace(event.currentTarget, () => setSkin(candidate.id))}
                sx={{
                  width: 132, p: 1, cursor: 'pointer', textAlign: 'left', font: 'inherit', color: candidate.text ?? (dark ? '#e6e0e9' : '#1d1b20'),
                  bgcolor: candidate.background ?? (dark ? '#141218' : '#f7f2fa'), borderRadius: `${Math.min(candidate.radius ?? 16, 16)}px`,
                  border: 2, borderColor: candidate.id === skin.id ? 'primary.main' : 'divider',
                }}
              >
                <Box sx={{ height: 28, mb: 0.5, bgcolor: candidate.paper ?? (dark ? '#1d1b20' : '#fffbfe'), borderRadius: `${Math.min(candidate.radius ?? 16, 12)}px`, display: 'flex', alignItems: 'center', px: 1 }}>
                  <Box sx={{ width: 36, height: 10, bgcolor: candidate.primary ?? 'primary.main', borderRadius: `${Math.min(candidate.radius ?? 16, 5)}px` }} />
                </Box>
                <Typography variant="body2" fontWeight={600} noWrap>
                  {candidate.name}
                </Typography>
                {custom && <Typography variant="caption">{t('Custom')}</Typography>}
              </Box>
            );
          })}
        </Stack>
        {takesAccent && (
          <Box sx={{ mt: 3 }}>
            <Typography variant="subtitle1" fontWeight={600}>
              {t('Accent colour')}
            </Typography>
            <Typography variant="body2" color="text.secondary" sx={{ mb: 1.5 }}>
              {t('The colour of buttons, links and highlights. The interface builds its shades from it.')}
            </Typography>
            <Stack direction="row" flexWrap="wrap" useFlexGap gap={1.5} role="group" aria-label={t('Accent colour')}>
              {SEEDS.map((color) => (
                <Box
                  key={color}
                  component="button"
                  aria-label={t('Accent colour {{color}}', { color })}
                  aria-pressed={color === seed}
                  onClick={() => setSeed(color)}
                  sx={{
                    width: 36, height: 36, p: 0, border: 0, borderRadius: '50%', bgcolor: color, color: '#fff', cursor: 'pointer', display: 'grid', placeItems: 'center',
                    outline: color === seed ? '2px solid' : 'none', outlineColor: color, outlineOffset: 3, transition: 'transform 120ms',
                    '&:hover': { transform: 'scale(1.08)' },
                    '&:focus-visible': { outline: '2px solid', outlineColor: 'text.primary', outlineOffset: 3 },
                  }}
                >
                  {color === seed && <Check fontSize="small" />}
                </Box>
              ))}
            </Stack>
          </Box>
        )}
      </CardContent>
    </Card>
  );
}

