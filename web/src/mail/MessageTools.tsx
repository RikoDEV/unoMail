// Per-message tools of the reader: show the original, block the sender, move to another inbox
// category, and unsubscribe from a mailing list.

import Block from '@mui/icons-material/Block';
import Code from '@mui/icons-material/Code';
import ContentCopy from '@mui/icons-material/ContentCopy';
import Download from '@mui/icons-material/Download';
import MoreVert from '@mui/icons-material/MoreVert';
import Unsubscribe from '@mui/icons-material/Unsubscribe';
import { Alert, Box, Button, Chip, CircularProgress, Dialog, DialogActions, DialogContent, DialogTitle, Divider, IconButton, ListItemIcon, ListSubheader, Menu, MenuItem, Snackbar, Stack, Table, TableBody, TableCell, TableRow, Tooltip } from '@mui/material';
import { useEffect, useState } from 'react';
import { downloadUrl, formatBytes, post, errorText } from '../api';
import { blockSender, CATEGORIES, type CategoryName, listBlockedSenders, unblockSender } from './extra';
import { type EmailFull, setCategory } from './jmapClient';

import { t } from '../i18n';
const MAX_ORIGINAL_BYTES = 2 * 1024 * 1024;

/** Tells the mail page that messages changed and its lists should be reloaded. */
export function requestRefresh() {
  window.dispatchEvent(new Event('unomail:refresh'));
}

/** The header block of a raw message, with folded lines joined. */
export function parseHeaders(raw: string): [string, string][] {
  const end = raw.search(/\r?\n\r?\n/);
  const block = end === -1 ? raw : raw.slice(0, end);
  const headers: [string, string][] = [];
  for (const line of block.split(/\r?\n/)) {
    if (/^[ \t]/.test(line) && headers.length > 0) headers[headers.length - 1][1] += ` ${line.trim()}`;
    else {
      const colon = line.indexOf(':');
      if (colon > 0) headers.push([line.slice(0, colon), line.slice(colon + 1).trim()]);
    }
  }
  return headers;
}

/** The verdicts of the receiving server's sender checks, from Authentication-Results. */
export function authenticationResults(headers: [string, string][]): { check: string; result: string }[] {
  const value = headers.find(([name]) => name.toLowerCase() === 'authentication-results')?.[1] ?? '';
  const found: { check: string; result: string }[] = [];
  for (const check of ['spf', 'dkim', 'dmarc']) {
    const match = value.match(new RegExp(`\\b${check}=([a-z]+)`, 'i'));
    if (match) found.push({ check: check.toUpperCase(), result: match[1].toLowerCase() });
  }
  return found;
}

function OriginalDialog({ email, accountId, onClose }: { email: EmailFull; accountId: string; onClose: () => void }) {
  const [raw, setRaw] = useState<{ text: string; size: number } | null>(null);
  const [error, setError] = useState('');
  const [copied, setCopied] = useState(false);
  const fileName = `${(email.subject || 'message').replace(/[^\w .-]+/g, '_').slice(0, 80)}.eml`;
  const url = downloadUrl(accountId, email.blobId ?? '', fileName);

  useEffect(() => {
    let cancelled = false;
    (async () => {
      try {
        const response = await fetch(url, { credentials: 'same-origin' });
        if (!response.ok) throw new Error(t('The original message could not be loaded.'));
        const blob = await response.blob();
        const text = new TextDecoder('utf-8', { fatal: false }).decode(await blob.slice(0, MAX_ORIGINAL_BYTES).arrayBuffer());
        if (!cancelled) setRaw({ text, size: blob.size });
      } catch (err) {
        if (!cancelled) setError(errorText(err, t('The original message could not be loaded.')));
      }
    })();
    return () => {
      cancelled = true;
    };
  }, [url]);

  const headers = raw ? parseHeaders(raw.text) : [];
  const header = (name: string) => headers.find(([key]) => key.toLowerCase() === name)?.[1] ?? '';
  const checks = authenticationResults(headers);
  return (
    <Dialog open onClose={onClose} fullWidth maxWidth="lg">
      <DialogTitle>{t('Original message')}</DialogTitle>
      <DialogContent dividers>
        {error && <Alert severity="error">{error}</Alert>}
        {!error && !raw && <CircularProgress size={24} />}
        {raw && (
          <>
            <Table size="small" sx={{ mb: 2, maxWidth: 760 }} aria-label={t('Message summary')}>
              <TableBody>
                {[
                  [t('Message ID'), header('message-id')],
                  [t('Created'), header('date')],
                  [t('From'), header('from')],
                  [t('To'), header('to')],
                  [t('Subject'), header('subject')],
                  [t('Size'), formatBytes(raw.size)],
                ].map(([label, value]) => (
                  <TableRow key={label}>
                    <TableCell sx={{ color: 'text.secondary', whiteSpace: 'nowrap', width: 130 }}>{label}</TableCell>
                    <TableCell sx={{ overflowWrap: 'anywhere' }}>{value}</TableCell>
                  </TableRow>
                ))}
                {checks.length > 0 && (
                  <TableRow>
                    <TableCell sx={{ color: 'text.secondary' }}>{t('Sender checks')}</TableCell>
                    <TableCell>
                      <Stack direction="row" spacing={1}>
                        {checks.map(({ check, result }) => (
                          <Chip key={check} size="small" label={`${check}: ${result}`} color={result === 'pass' ? 'success' : result === 'none' || result === 'neutral' ? 'default' : 'error'} variant="outlined" />
                        ))}
                      </Stack>
                    </TableCell>
                  </TableRow>
                )}
              </TableBody>
            </Table>
            {raw.size > MAX_ORIGINAL_BYTES && <Alert severity="info" sx={{ mb: 1 }}>{t('Only the first 2 MB are shown. Download the message to see all of it.')}</Alert>}
            {/* Shown strictly as text: this is exactly what arrived, markup and all. */}
            <Box component="pre" data-testid="original-source" sx={{ m: 0, p: 1.5, bgcolor: 'action.hover', borderRadius: 1, whiteSpace: 'pre-wrap', overflowWrap: 'anywhere', fontFamily: 'monospace', fontSize: 12 }}>
              {raw.text}
            </Box>
          </>
        )}
      </DialogContent>
      <DialogActions>
        <Button
          startIcon={<ContentCopy />}
          disabled={!raw}
          onClick={() => {
            void navigator.clipboard?.writeText(raw?.text ?? '').then(() => setCopied(true));
          }}
        >
          {copied ? t('Copied') : t('Copy to clipboard')}
        </Button>
        <Button component="a" href={url} download={fileName} startIcon={<Download />}>
          {t('Download')}
        </Button>
        <Button onClick={onClose}>{t('Close')}</Button>
      </DialogActions>
    </Dialog>
  );
}

/** "Unsubscribe" next to the sender of a mailing-list message (RFC 2369 / RFC 8058). */
export function UnsubscribeButton({ email }: { email: EmailFull }) {
  const [busy, setBusy] = useState(false);
  const [notice, setNotice] = useState('');
  if (!email.unsubscribe) return null;

  async function unsubscribe() {
    const sender = email.from?.[0]?.name || email.from?.[0]?.email || t('this sender');
    if (!window.confirm(t('Unsubscribe from {{sender}}?', { sender }))) return;
    setBusy(true);
    try {
      const result = await post<{ method: 'one-click' | 'mail' | 'link'; to?: string; url?: string }>('/api/me/unsubscribe', { email_id: email.id });
      if (result.method === 'link' && result.url && /^https?:\/\//i.test(result.url)) {
        // The sender only offers a web page: open it, without telling it where the reader came from.
        window.open(result.url, '_blank', 'noopener,noreferrer');
        setNotice(t('The sender asks you to finish unsubscribing on their page, which was opened in a new tab.'));
      } else if (result.method === 'mail') {
        setNotice(t('An unsubscribe request was sent to {{to}}.', { to: result.to }));
      } else {
        setNotice(t('You have been unsubscribed.'));
      }
    } catch (err) {
      setNotice(errorText(err, t('Unsubscribing failed.')));
    } finally {
      setBusy(false);
    }
  }

  return (
    <>
      <Button size="small" startIcon={<Unsubscribe />} disabled={busy} onClick={(e) => { e.stopPropagation(); void unsubscribe(); }} sx={{ flexShrink: 0 }}>
        {t('Unsubscribe')}
      </Button>
      <Snackbar open={Boolean(notice)} autoHideDuration={6000} onClose={() => setNotice('')} message={notice} />
    </>
  );
}

/** The "more actions" menu of one message. */
export function MessageMenu({ email, accountId, ownEmail, inInbox }: { email: EmailFull; accountId: string; ownEmail: string; inInbox: boolean }) {
  const [anchor, setAnchor] = useState<HTMLElement | null>(null);
  const [original, setOriginal] = useState(false);
  const [blocked, setBlocked] = useState<string[] | null>(null);
  const [notice, setNotice] = useState('');
  const sender = email.from?.[0]?.email.toLowerCase() ?? '';
  const isBlocked = Boolean(sender) && (blocked ?? []).some((entry) => entry === sender || entry === `@${sender.split('@')[1]}`);
  const current: CategoryName = CATEGORIES.find((category) => email.keywords[`$cat_${category.id}`])?.id ?? 'general';
  const fileName = `${(email.subject || 'message').replace(/[^\w .-]+/g, '_').slice(0, 80)}.eml`;

  function open(target: HTMLElement) {
    setAnchor(target);
    listBlockedSenders().then(setBlocked).catch(() => setBlocked([]));
  }

  async function run(action: () => Promise<unknown>, done: string, refresh = false) {
    setAnchor(null);
    try {
      await action();
      setNotice(done);
      if (refresh) requestRefresh();
    } catch (err) {
      setNotice(errorText(err, t('The action failed.')));
    }
  }

  return (
    <>
      <Tooltip title={t('More actions')}>
        <IconButton size="small" aria-label={t('More actions')} onClick={(e) => { e.stopPropagation(); open(e.currentTarget); }}>
          <MoreVert fontSize="small" />
        </IconButton>
      </Tooltip>
      <Menu anchorEl={anchor} open={Boolean(anchor)} onClose={() => setAnchor(null)} onClick={(e) => e.stopPropagation()}>
        {email.blobId && (
          <MenuItem component="a" href={downloadUrl(accountId, email.blobId, fileName)} download={fileName} onClick={() => setAnchor(null)}>
            <ListItemIcon><Download fontSize="small" /></ListItemIcon>
            {t('Download message')}
          </MenuItem>
        )}
        {email.blobId && (
          <MenuItem onClick={() => { setAnchor(null); setOriginal(true); }}>
            <ListItemIcon><Code fontSize="small" /></ListItemIcon>
            {t('Show original')}
          </MenuItem>
        )}
        {sender && sender !== ownEmail.toLowerCase() && (
          <MenuItem
            onClick={() =>
              void (isBlocked
                ? run(() => unblockSender(sender).catch(() => unblockSender(`@${sender.split('@')[1]}`)), t('{{sender}} is no longer blocked.', { sender }))
                : run(() => blockSender(sender), t('{{sender}} is blocked. New mail from this sender goes to Junk.', { sender })))
            }
          >
            <ListItemIcon><Block fontSize="small" /></ListItemIcon>
            {isBlocked ? t('Unblock {{sender}}', { sender }) : t('Block {{sender}}', { sender })}
          </MenuItem>
        )}
        {inInbox && <Divider />}
        {inInbox && <ListSubheader sx={{ lineHeight: '32px', bgcolor: 'transparent' }}>{t('Move to category')}</ListSubheader>}
        {inInbox &&
          CATEGORIES.map((category) => (
            <MenuItem key={category.id} dense selected={category.id === current} disabled={category.id === current} onClick={() => void run(() => setCategory([email.id], category.id), t('Moved to {{label}}. New mail from this sender will go there too.', { label: category.label }), true)}>
              {category.label}
            </MenuItem>
          ))}
      </Menu>
      {original && <OriginalDialog email={email} accountId={accountId} onClose={() => setOriginal(false)} />}
      <Snackbar open={Boolean(notice)} autoHideDuration={5000} onClose={() => setNotice('')} message={notice} />
    </>
  );
}
