// Inbox settings: categories, the personal spam filter and blocked senders.

import {
  Alert, Box, Button, Card, CardContent, Chip, FormControlLabel, Stack, Switch,
  LinearProgress, TextField, Typography,
} from '@mui/material';
import { useCallback, useEffect, useState } from 'react';
import { blockSender, CATEGORIES, categoryLearning, type CategoryLearning, listBlockedSenders, resetCategoryLearning, resetSpamFilter, spamFilterState, type SpamFilterState, unblockSender } from './mail/extra';
import { updatePrefs, usePrefs } from './prefs';
import { errorText } from './api';

import { t } from './i18n';
import { useList } from './useLoad';
import { ConfirmDialog } from './admin/common';

// --- Inbox ---------------------------------------------------------------------------------

/** What the inbox categories learned from the user's corrections, and a way to reset it. */
function CategoryLearningSection() {
  const [state, setState] = useState<CategoryLearning | null>(null);
  const [confirm, setConfirm] = useState(false);
  const load = useCallback(() => void categoryLearning().then(setState).catch(() => setState(null)), []);
  useEffect(load, [load]);
  if (!state) return null;
  const known = CATEGORIES.filter((category) => state.learned[category.id] >= state.needed);
  return (
    <Box data-testid="category-learning" sx={{ pl: 6 }}>
      <Typography variant="body2" color="text.secondary">
        {t('The categories learn from you: move a message to another category and new mail from its sender goes there too. After {{needed}} corrections into each of two categories, mail from new senders is sorted by what it resembles.', { needed: state.needed })}
      </Typography>
      {state.total > 0 && (
        <Typography variant="body2" sx={{ mt: 0.5 }}>
          {t('Moved messages learned from: {{messages}}. Senders remembered: {{senders}}.', { messages: state.total, senders: state.senders })}{' '}
          {known.length >= 2 && t('Sorting by content between: {{list}}.', { list: known.map((category) => category.label).join(', ') })}
        </Typography>
      )}
      {state.total > 0 && (
        <Button color="error" size="small" sx={{ mt: 0.5 }} onClick={() => setConfirm(true)}>
          {t('Forget what it learned')}
        </Button>
      )}
      <ConfirmDialog
        open={confirm}
        title={t('Reset the inbox categories?')}
        text={t('New mail is sorted by the built-in rules again. Messages already in your inbox keep their category.')}
        confirmLabel={t('Reset')}
        onClose={() => setConfirm(false)}
        onConfirm={() => void resetCategoryLearning().then(() => { setConfirm(false); load(); })}
      />
    </Box>
  );
}

/** What the personal spam filter has learned from the user's reports, and a way to reset it. */
function SpamFilterSection() {
  const [state, setState] = useState<SpamFilterState | null>(null);
  const [confirm, setConfirm] = useState(false);
  const load = useCallback(() => void spamFilterState().then(setState).catch(() => setState(null)), []);
  useEffect(load, [load]);
  if (!state) return null;
  const progress = Math.round((100 * (Math.min(state.spam, state.needed) + Math.min(state.ham, state.needed))) / (2 * state.needed));
  return (
    <Box data-testid="spam-filter">
      <Typography variant="subtitle1" fontWeight={600}>
        {t('Personal spam filter')}
      </Typography>
      <Typography variant="body2" color="text.secondary" sx={{ mb: 1 }}>
        {t('It learns from you: “Report spam” teaches it what you do not want; “Not spam”, your replies and mail from people you write to teach it what you do. Mail from your contacts is never filed away by it.')}
      </Typography>
      {!state.enabled ? (
        <Alert severity="info">{t('The administrator has turned the personal spam filter off.')}</Alert>
      ) : state.active ? (
        <Alert severity="success">{t('Active: new mail it is confident about goes to Junk. Learned from {{spam}} spam and {{ham}} wanted messages.', { spam: state.spam, ham: state.ham })}</Alert>
      ) : (
        <>
          <Typography variant="body2">
            {t('Still learning: {{spam}} of {{needed}} spam and {{ham}} of {{needed}} wanted messages seen. It starts sorting once it has seen enough of both.', { spam: state.spam, ham: state.ham, needed: state.needed })}
          </Typography>
          <LinearProgress variant="determinate" value={progress} sx={{ mt: 1, maxWidth: 360, height: 6, borderRadius: 3 }} aria-label={t('Spam filter training progress')} />
        </>
      )}
      {(state.spam > 0 || state.ham > 0) && (
        <Button color="error" sx={{ mt: 1 }} onClick={() => setConfirm(true)}>
          {t('Forget what it learned')}
        </Button>
      )}
      <ConfirmDialog
        open={confirm}
        title={t('Reset the spam filter?')}
        text={t('It forgets every message it has learned from and starts again. Your mail is not changed.')}
        confirmLabel={t('Reset')}
        onClose={() => setConfirm(false)}
        onConfirm={() => void resetSpamFilter().then(() => { setConfirm(false); load(); })}
      />
    </Box>
  );
}

export function InboxCard() {
  const prefs = usePrefs();
  const { items, error, setError, reload } = useList(listBlockedSenders);
  const [sender, setSender] = useState('');

  async function add() {
    try {
      await blockSender(sender);
      setSender('');
      await reload();
    } catch (err) {
      setError(errorText(err, t('The sender could not be blocked')));
    }
  }

  return (
    <Card variant="outlined">
      <CardContent>
        <Typography variant="h6" sx={{ mb: 1 }}>
          {t('Inbox')}
        </Typography>
        <Stack spacing={2} sx={{ maxWidth: 640 }}>
          <FormControlLabel
            control={<Switch checked={prefs.categories !== false} onChange={(e) => void updatePrefs({ categories: e.target.checked }).catch(() => {})} />}
            label={t('Sort the inbox into categories (General, Offers, Communities, Notifications, Forums)')}
          />
          {prefs.categories !== false && <CategoryLearningSection />}
          <SpamFilterSection />
          <Box>
            <Typography variant="subtitle1" fontWeight={600}>
              {t('Blocked senders')}
            </Typography>
            <Typography variant="body2" color="text.secondary" sx={{ mb: 1 }}>
              {t('Mail from these senders goes straight to Junk. The sender is not told. Enter an address, or @domain for everybody at a domain.')}
            </Typography>
            {error && <Alert severity="error" onClose={() => setError('')} sx={{ mb: 1 }}>{error}</Alert>}
            <Stack direction="row" spacing={1} alignItems="flex-start" sx={{ mb: 1 }}>
              <TextField label={t('Sender to block')} value={sender} onChange={(e) => setSender(e.target.value)} onKeyDown={(e) => e.key === 'Enter' && sender.trim() && void add()} placeholder={t('pest@example.com or @example.com')} fullWidth />
              <Button variant="outlined" disabled={!sender.trim()} onClick={() => void add()}>
                {t('Block')}
              </Button>
            </Stack>
            {items.length === 0 ? (
              <Typography color="text.secondary">{t('Nobody is blocked.')}</Typography>
            ) : (
              <Stack direction="row" flexWrap="wrap" gap={1} role="list" aria-label={t('Blocked senders')}>
                {items.map((entry) => (
                  <Chip key={entry} role="listitem" label={entry} onDelete={() => void unblockSender(entry).then(reload).catch((err) => setError(errorText(err, t('Could not unblock'))))} />
                ))}
              </Stack>
            )}
          </Box>
        </Stack>
      </CardContent>
    </Card>
  );
}
