import { Alert, Button, Chip, Dialog, DialogActions, DialogContent, DialogContentText, DialogTitle, Snackbar, Stack, Typography } from '@mui/material';
import { type ReactNode, useCallback, useState } from 'react';

import { t } from '../i18n';
import { errorText } from '../api';
export { useLoad } from '../useLoad';

/** Wraps mutations: shows failures inline and successes as a toast. */
export function useAction() {
  const [error, setError] = useState('');
  const [message, setMessage] = useState('');
  const run = useCallback(async (action: () => Promise<unknown>, success?: string): Promise<boolean> => {
    setError('');
    try {
      await action();
      if (success) setMessage(success);
      return true;
    } catch (err) {
      setError(errorText(err, t('The operation failed')));
      return false;
    }
  }, []);
  const feedback = (
    <>
      {error && (
        <Alert severity="error" onClose={() => setError('')} sx={{ mb: 2 }}>
          {error}
        </Alert>
      )}
      <Snackbar open={Boolean(message)} autoHideDuration={3500} onClose={() => setMessage('')} message={message} />
    </>
  );
  return { run, feedback, setError, notify: setMessage };
}

/**
 * Submits a form shown in a dialog. A failure is shown in the dialog, under the field it is
 * about (`route` picks it from the server's message) or above the form, never on the page
 * behind the dialog. It disappears once the form is changed.
 */
export function useFormAction<Field extends string>(route: (message: string) => Field | null) {
  const [failure, setFailure] = useState<{ field: Field | null; message: string } | null>(null);
  const [busy, setBusy] = useState(false);
  const run = async (action: () => Promise<unknown>): Promise<boolean> => {
    setFailure(null);
    setBusy(true);
    try {
      await action();
      return true;
    } catch (err) {
      const message = errorText(err, t('The operation failed'));
      // Server messages start in lower case; under a field they read as a sentence.
      setFailure({ field: route(message), message: message.charAt(0).toUpperCase() + message.slice(1) });
      return false;
    } finally {
      setBusy(false);
    }
  };
  return {
    run,
    busy,
    /** The failure to show under `field`, if it is about that field. */
    fieldError: (field: Field) => (failure?.field === field ? failure.message : ''),
    /** A failure that is about no single field, for the top of the form. */
    formError: failure && !failure.field ? <Alert severity="error" sx={{ mb: 2 }}>{failure.message}</Alert> : null,
    clear: () => setFailure(null),
  };
}

/** Picks the field a server message is about: the first whose pattern matches it. */
export const routeBy =
  <Field extends string>(patterns: [RegExp, Field][], fallback: Field | null = null) =>
  (message: string): Field | null =>
    patterns.find(([pattern]) => pattern.test(message))?.[1] ?? fallback;

export function PageHeader({ title, children }: { title: string; children?: ReactNode }) {
  return (
    <Stack direction="row" alignItems="center" spacing={2} sx={{ mb: 2 }} flexWrap="wrap" useFlexGap>
      <Typography variant="h5" component="h1" sx={{ flex: 1 }}>
        {title}
      </Typography>
      {children}
    </Stack>
  );
}

const STATUS_COLORS: Record<string, 'success' | 'warning' | 'error' | 'default' | 'info'> = {
  ok: 'success', delivered: 'success', warning: 'warning', deferred: 'warning', junk: 'warning', queued: 'info',
  error: 'error', bounced: 'error', rejected: 'error', unknown: 'default',
};

export function StatusChip({ status }: { status: string }) {
  return <Chip size="small" label={status} color={STATUS_COLORS[status] ?? 'default'} variant={status === 'unknown' ? 'outlined' : 'filled'} />;
}

export function ConfirmDialog({ open, title, text, confirmLabel = t('Delete'), onConfirm, onClose }: { open: boolean; title: string; text: string; confirmLabel?: string; onConfirm: () => void; onClose: () => void }) {
  return (
    <Dialog open={open} onClose={onClose}>
      <DialogTitle>{title}</DialogTitle>
      <DialogContent>
        <DialogContentText>{text}</DialogContentText>
      </DialogContent>
      <DialogActions>
        <Button onClick={onClose}>{t('Cancel')}</Button>
        <Button color="error" variant="contained" onClick={onConfirm}>
          {confirmLabel}
        </Button>
      </DialogActions>
    </Dialog>
  );
}

/** Inline validation helpers shared by the forms. */
export const validators = {
  domain: (v: string) => (/^(?!-)[a-z0-9-]{1,63}(?<!-)(\.(?!-)[a-z0-9-]{1,63}(?<!-))+$/i.test(v.trim()) ? '' : t('Enter a valid domain name, e.g. example.com')),
  // Letters and digits of any script are valid in the local part (internationalized addresses).
  email: (v: string) => (/^[\p{L}\p{N}._+-]+@[\p{L}\p{N}-]+(\.[\p{L}\p{N}-]+)+$/u.test(v.trim()) ? '' : t('Enter a valid e-mail address')),
  password: (v: string) => (v.length >= 10 ? '' : t('Use at least 10 characters')),
};
