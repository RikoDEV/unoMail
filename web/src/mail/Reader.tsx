import Archive from '@mui/icons-material/Archive';
import ArrowBack from '@mui/icons-material/ArrowBack';
import AttachFile from '@mui/icons-material/AttachFile';
import Delete from '@mui/icons-material/Delete';
import Forward from '@mui/icons-material/Forward';
import ImageIcon from '@mui/icons-material/Image';
import Label from '@mui/icons-material/Label';
import Lock from '@mui/icons-material/Lock';
import MarkEmailUnread from '@mui/icons-material/MarkEmailUnread';
import Reply from '@mui/icons-material/Reply';
import Visibility from '@mui/icons-material/Visibility';
import WarningAmber from '@mui/icons-material/WarningAmber';
import ReplyAll from '@mui/icons-material/ReplyAll';
import Report from '@mui/icons-material/Report';
import ReportOff from '@mui/icons-material/ReportOff';
import Snooze from '@mui/icons-material/Snooze';
import {
  Alert, Box, Button, Checkbox, Chip, CircularProgress, Collapse, Dialog, DialogActions, DialogContent, DialogTitle, IconButton, ListItemText, Menu, MenuItem, Paper, Stack, TextField, Tooltip,
  Typography, useMediaQuery, useTheme,
} from '@mui/material';
import { useCallback, useEffect, useMemo, useRef, useState } from 'react';
import { downloadUrl, formatBytes, errorText } from '../api';
import { Invitation } from '../calendar/Invitation';
import { emit, type PluginMessage, usePlugins } from '../plugins';
import { updatePrefs, usePrefs } from '../prefs';
import { imageProxyUrl } from './extra';
import { answerReceipt, type EmailFull, formatAddress, labelsOf, normalizeLabel } from './jmapClient';
import { SmimeBadges } from './Smime';
import { AiAssist, AiModelsProvider } from './AiAssist';
import { SummaryCards } from './SummaryCards';
import { SmartReplies } from './SmartReplies';
import { snoozePresets } from './timePresets';
import { adaptForDark, type Rgb } from './darkColors';

/** The page behind a message in the dark theme (see buildFrameDocument). */
const DARK_PAGE: Rgb = [29, 27, 32];
import { guardedDownload, useRiskConfirm } from './RiskConfirm';
import { attachmentRisk } from './risk';
import { AttachmentPreview, type PreviewFile, previewKind } from './Preview';
import { listDate } from './EmailRow';
import { MessageMenu, UnsubscribeButton } from './MessageTools';
import { SecurityWarnings, SenderAvatar, SenderHover, useAvatarInfo } from './Sender';
import { type Decrypted, decryptArmored, fetchKeys, isUnlocked, localPrivateKey, lookupKeys, looksEncrypted, unlock } from './pgp';
import { buildFrameDocument, sanitizeEmail, sanitizeEmailHtml, textToHtml } from './sanitize';

import { t, uiLocale } from '../i18n';
export type ReaderAction = 'reply' | 'replyAll' | 'forward';

/** Bodies of messages decrypted in this session, so replies can quote them. */
const decryptedBodies = new Map<string, string>();

function rawHtml(email: EmailFull): string {
  const decrypted = decryptedBodies.get(email.id);
  if (decrypted !== undefined) return decrypted;
  const htmlPart = email.htmlBody[0];
  const textPart = email.textBody[0];
  const html = htmlPart && email.bodyValues[htmlPart.partId] && htmlPart.type === 'text/html' ? email.bodyValues[htmlPart.partId].value : null;
  return html ?? textToHtml(textPart ? (email.bodyValues[textPart.partId]?.value ?? '') : '');
}

/** Sanitized HTML of a message, with inline (cid:) images resolved to downloadable blobs. */
export function emailHtml(email: EmailFull, accountId: string, cidUrls: Record<string, string> = {}): string {
  void accountId;
  return sanitizeEmailHtml(rawHtml(email), (cid) => cidUrls[cid.replace(/^<|>$/g, '')]);
}

/** Where the OpenPGP payload of a message is, if it is encrypted. */
function encryptedSource(email: EmailFull): { blobId: string } | { text: string } | null {
  // PGP/MIME: a control part plus the armored payload.
  if (email.attachments.some((a) => a.type === 'application/pgp-encrypted')) {
    const payload = email.attachments.find((a) => a.type !== 'application/pgp-encrypted' && (a.type === 'application/octet-stream' || /\.(asc|pgp|gpg)$/i.test(a.name ?? '')));
    if (payload) return { blobId: payload.blobId };
  }
  // Inline PGP: the armored text is the body itself.
  const textPart = email.textBody[0];
  const text = textPart ? (email.bodyValues[textPart.partId]?.value ?? '') : '';
  return looksEncrypted(text) ? { text } : null;
}

/** An attachment as a download link, with a preview button when the browser can show it. */
/** Whether an attachment is an invitation or another iCalendar file. */
function isCalendarFile(file: PreviewFile): boolean {
  return file.type.toLowerCase().startsWith('text/calendar') || /[.]ics$/i.test(file.name);
}

function AttachmentChip({ file, size, onPreview }: { file: PreviewFile; size: number; onPreview: (file: PreviewFile) => void }) {
  const [ask, dialog] = useRiskConfirm();
  const risk = attachmentRisk(file.name);
  return (
    <Stack direction="row" alignItems="center">
      {dialog}
      {/* describeChild: the reason is a description, the file name stays the link's name. */}
      <Tooltip title={risk?.reason ?? ''} describeChild>
        <Chip
          icon={risk ? <WarningAmber /> : <AttachFile />}
          color={risk?.level === 'danger' ? 'error' : risk ? 'warning' : 'default'}
          label={`${file.name} (${formatBytes(size)})`}
          component="a"
          href={file.url}
          download={file.name}
          clickable
          variant="outlined"
          data-risk={risk?.level}
          onClick={(event: React.MouseEvent) => {
            if (!risk) return;
            event.preventDefault();
            void guardedDownload(ask, file.name, file.url);
          }}
        />
      </Tooltip>
      {previewKind(file) && (
        <Tooltip title={t('Preview')}>
          <IconButton size="small" aria-label={t('Preview {{name}}', { name: file.name })} onClick={() => onPreview(file)}>
            <Visibility fontSize="small" />
          </IconButton>
        </Tooltip>
      )}
    </Stack>
  );
}

/** Asks for the passphrase of the user's private key and unlocks it for this session. */
function UnlockPrompt({ ownEmail, onUnlocked }: { ownEmail: string; onUnlocked: () => void }) {
  const [passphrase, setPassphrase] = useState('');
  const [error, setError] = useState('');
  const [busy, setBusy] = useState(false);

  async function submit() {
    setBusy(true);
    setError('');
    try {
      const stored = await fetchKeys();
      const privateKey = stored?.private_key || localPrivateKey(ownEmail);
      if (!privateKey) throw new Error(t('No private key is available on this device. Set up encryption in Settings.'));
      await unlock(privateKey, passphrase);
      setPassphrase('');
      onUnlocked();
    } catch (err) {
      setError(errorText(err, t('Could not unlock the key')));
    } finally {
      setBusy(false);
    }
  }

  return (
    <Alert severity="info" icon={<Lock />} sx={{ mb: 1 }}>
      <Typography variant="body2" sx={{ mb: 1 }}>
        {t('This message is encrypted. Enter the passphrase of your private key to read it.')}
      </Typography>
      <Stack direction="row" spacing={1} alignItems="flex-start">
        <TextField label={t('Key passphrase')} type="password" autoComplete="off" value={passphrase} onChange={(e) => setPassphrase(e.target.value)} onKeyDown={(e) => e.key === 'Enter' && void submit()} error={Boolean(error)} helperText={error} />
        <Button variant="contained" onClick={() => void submit()} disabled={busy || !passphrase}>
          {t('Unlock')}
        </Button>
      </Stack>
    </Alert>
  );
}

const SIGNATURE_LABEL: Record<Decrypted['signature'], { label: string; color: 'success' | 'error' | 'default' } | null> = {
  none: null,
  valid: { label: t('Signature verified'), color: 'success' },
  invalid: { label: t('Invalid signature'), color: 'error' },
  unknown: { label: t('Signed (sender key unknown)'), color: 'default' },
};

function MessageBody({ email, accountId, ownEmail }: { email: EmailFull; accountId: string; ownEmail: string }) {
  const theme = useTheme();
  const prefs = usePrefs();
  const frame = useRef<HTMLIFrameElement>(null);
  const [height, setHeight] = useState(120);
  const [cidUrls, setCidUrls] = useState<Record<string, string>>({});
  const sender = email.from?.[0]?.email.toLowerCase() ?? '';
  const trusted = Boolean(sender) && (prefs.image_senders ?? []).includes(sender);
  const [showRemote, setShowRemote] = useState(false);
  const source = useMemo(() => encryptedSource(email), [email]);
  const [unlockedNow, setUnlockedNow] = useState(isUnlocked());
  const [decrypted, setDecrypted] = useState<Decrypted | null>(null);
  const [decryptError, setDecryptError] = useState('');
  const [fileUrls, setFileUrls] = useState<{ name: string; type: string; size: number; url: string }[]>([]);
  const [preview, setPreview] = useState<PreviewFile | null>(null);

  // Inline images are fetched with the session cookie and handed to the frame as blob URLs,
  // because the frame itself is not allowed to make network requests.
  useEffect(() => {
    let cancelled = false;
    const created: string[] = [];
    const inline = email.attachments.filter((a) => a.cid && a.type.startsWith('image/'));
    Promise.all(
      inline.map(async (part) => {
        const response = await fetch(downloadUrl(accountId, part.blobId, part.name ?? 'image'), { credentials: 'same-origin' });
        if (!response.ok) return null;
        const url = URL.createObjectURL(await response.blob());
        created.push(url);
        return [part.cid!.replace(/^<|>$/g, ''), url] as const;
      }),
    ).then((entries) => {
      if (!cancelled) setCidUrls(Object.fromEntries(entries.filter((e): e is readonly [string, string] => e !== null)));
    });
    return () => {
      cancelled = true;
      created.forEach((url) => URL.revokeObjectURL(url));
    };
  }, [email, accountId]);

  // Encrypted messages are decrypted in the browser once the private key is unlocked.
  useEffect(() => {
    if (!source || !unlockedNow) return;
    let cancelled = false;
    const created: string[] = [];
    (async () => {
      try {
        const armored = 'text' in source ? source.text : await (await fetch(downloadUrl(accountId, source.blobId, 'encrypted.asc'), { credentials: 'same-origin' })).text();
        const keys = sender ? await lookupKeys([sender]).catch(() => ({}) as Record<string, string>) : {};
        const opened = await decryptArmored(armored, Object.values(keys));
        if (cancelled) return;
        const inline: Record<string, string> = {};
        const files: { name: string; type: string; size: number; url: string }[] = [];
        for (const file of opened.attachments) {
          const url = URL.createObjectURL(new Blob([file.data as BlobPart], { type: file.cid && /^image\/(png|jpeg|gif|webp)$/.test(file.type) ? file.type : 'application/octet-stream' }));
          created.push(url);
          if (file.cid) inline[file.cid] = url;
          else files.push({ name: file.name, type: file.type, size: file.data.length, url });
        }
        decryptedBodies.set(email.id, opened.html ?? textToHtml(opened.text ?? ''));
        setCidUrls(inline);
        setFileUrls(files);
        setDecrypted(opened);
        setDecryptError('');
      } catch (err) {
        if (!cancelled) setDecryptError(errorText(err, t('The message could not be decrypted')));
      }
    })();
    return () => {
      cancelled = true;
      created.forEach((url) => URL.revokeObjectURL(url));
    };
  }, [source, unlockedNow, accountId, email.id, sender]);

  const remote = showRemote || trusted;
  const rendered = useMemo(() => {
    const body = decrypted ? (decrypted.html ?? textToHtml(decrypted.text ?? '')) : rawHtml(email);
    return sanitizeEmail(body, { resolveCid: (cid) => cidUrls[cid.replace(/^<|>$/g, '')], proxyImage: remote ? imageProxyUrl : undefined });
  }, [email, decrypted, cidUrls, remote]);
  const srcDoc = useMemo(
    () => buildFrameDocument(rendered.html, theme.palette.mode === 'dark', remote ? window.location.origin : ''),
    [rendered.html, theme.palette.mode, remote],
  );
  const [askLink, linkDialog] = useRiskConfirm();
  /**
   * Shrinks a message laid out wider than the frame (a newsletter's fixed 600px table on a phone)
   * until it fits, as mobile mail apps do, then takes the height it needs.
   */
  const fit = useCallback(() => {
    const element = frame.current;
    const doc = element?.contentDocument;
    if (!element || !doc?.documentElement || !doc.body) return;
    doc.body.style.removeProperty('zoom');
    const available = element.clientWidth;
    const needed = doc.documentElement.scrollWidth;
    if (available > 0 && needed > available + 1) doc.body.style.setProperty('zoom', String(Math.max(available / needed, 0.3)));
    setHeight(Math.min(Math.max(doc.documentElement.scrollHeight, 60), 20000));
  }, []);
  useEffect(() => {
    window.addEventListener('resize', fit);
    return () => window.removeEventListener('resize', fit);
  }, [fit]);

  const resize = () => {
    const doc = frame.current?.contentDocument;
    // Dark text of the message would vanish on the dark page (buildFrameDocument's background).
    if (doc && theme.palette.mode === 'dark') adaptForDark(doc, DARK_PAGE);
    fit();
    // A suspicious link (marked by the sanitizer) asks before it opens.
    doc?.addEventListener('click', (event) => {
      // mailto: links write a new message here instead of in another mail program.
      const mailto = (event.target as Element | null)?.closest?.('a[href^="mailto:" i]');
      if (mailto && !(event as MouseEvent).ctrlKey && !(event as MouseEvent).metaKey) {
        event.preventDefault();
        window.dispatchEvent(new CustomEvent('unomail:mailto', { detail: mailto.getAttribute('href') }));
        return;
      }
      const link = (event.target as Element | null)?.closest?.('a[data-unomail-warning]');
      if (!link) return;
      event.preventDefault();
      const href = link.getAttribute('href') ?? '';
      void askLink(t('Careful with this link'), link.getAttribute('data-unomail-warning') ?? '', t('Open the link anyway'), href).then((ok) => {
        if (ok) window.open(href, '_blank', 'noopener,noreferrer');
      });
    });
  };

  // Let plug-ins know which message is being read.
  useEffect(() => {
    if (source && !decrypted) return;
    emit('message:open', pluginMessage(email, rendered.html));
    // Only when the message (or its decrypted content) changes, not on every re-render.
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [email.id, decrypted]);

  if (source && !decrypted) {
    if (!unlockedNow) return <UnlockPrompt ownEmail={ownEmail} onUnlocked={() => setUnlockedNow(true)} />;
    return decryptError ? <Alert severity="error">{t('This message could not be decrypted: {{decryptError}}', { decryptError })}</Alert> : <CircularProgress size={20} />;
  }
  const signature = decrypted ? SIGNATURE_LABEL[decrypted.signature] : null;
  return (
    <>
      {decrypted && (
        <Stack direction="row" spacing={1} sx={{ mb: 1 }}>
          <Chip size="small" icon={<Lock />} label={t('Decrypted')} color="success" variant="outlined" />
          {signature && <Chip size="small" label={signature.label} color={signature.color} variant="outlined" />}
        </Stack>
      )}
      {rendered.blockedImages > 0 && !remote && (
        <Alert
          severity="info"
          icon={<ImageIcon />}
          sx={{ mb: 1 }}
          action={
            <Stack direction="row" spacing={1}>
              <Button size="small" color="inherit" onClick={() => setShowRemote(true)}>
                {t('Show images')}
              </Button>
              {sender && (
                <Button
                  size="small"
                  color="inherit"
                  onClick={() => {
                    setShowRemote(true);
                    void updatePrefs({ image_senders: [...new Set([...(prefs.image_senders ?? []), sender])].slice(-200) }).catch(() => {});
                  }}
                >
                  {t('Always from this sender')}
                </Button>
              )}
            </Stack>
          }
        >
          {t('Remote images are hidden to protect your privacy.')}
        </Alert>
      )}
      {linkDialog}
      <iframe
        ref={frame}
        title={t('Message body')}
        // No allow-scripts: content inside can never execute code. allow-same-origin only lets
        // the parent measure the document height.
        sandbox="allow-same-origin allow-popups allow-popups-to-escape-sandbox"
        srcDoc={srcDoc}
        onLoad={resize}
        style={{ width: '100%', height, border: 0, display: 'block' }}
      />
      {fileUrls.length > 0 && (
        <Stack direction="row" flexWrap="wrap" gap={1} sx={{ mt: 2 }}>
          {fileUrls.map((file) => (
            <AttachmentChip key={file.url} file={file} size={file.size} onPreview={setPreview} />
          ))}
        </Stack>
      )}
      {preview && <AttachmentPreview file={preview} onClose={() => setPreview(null)} />}
    </>
  );
}

function pluginMessage(email: EmailFull, html: string): PluginMessage {
  return { id: email.id, subject: email.subject, from: email.from ?? [], to: email.to ?? [], receivedAt: email.receivedAt, html };
}

function Message({ email, accountId, ownEmail, inboxId, expanded, collapsible, onToggle, onAction }: { email: EmailFull; accountId: string; ownEmail: string; inboxId: string; expanded: boolean; collapsible: boolean; onToggle: () => void; onAction: (action: ReaderAction, email: EmailFull, suggestedText?: string) => void }) {
  const sender = email.from?.[0];
  const plugins = usePlugins();
  const encrypted = encryptedSource(email) !== null;
  // The parts of an encrypted message are ciphertext; its real attachments appear once decrypted.
  const files = encrypted ? [] : email.attachments.filter((a) => !a.cid);
  // An invitation usually comes twice in a message (inline and attached): explain it once.
  const invite = files.find((a) => isCalendarFile({ name: a.name ?? '', type: a.type, url: '' }));
  const [preview, setPreview] = useState<PreviewFile | null>(null);
  const avatarInfo = useAvatarInfo(accountId, email);
  const phone = useMediaQuery(useTheme().breakpoints.down('sm'));
  // An open message's sender (picture, name, address) is for reading and hovering, not a switch.
  const keepOpen = (event: { stopPropagation: () => void }) => {
    if (expanded) event.stopPropagation();
  };
  const received = new Date(email.receivedAt).toLocaleString(uiLocale());
  return (
    <Paper variant="outlined" sx={{ borderRadius: { xs: 0, sm: 1.5 }, borderLeft: { xs: 0, sm: 1 }, borderRight: { xs: 0, sm: 1 }, borderColor: { xs: 'divider', sm: 'divider' }, overflow: 'hidden' }} data-testid="message">
      <Stack
        direction="row"
        spacing={1.5}
        alignItems="center"
        sx={{ p: 1.5, cursor: collapsible ? 'pointer' : 'default' }}
        onClick={collapsible ? onToggle : undefined}
        data-collapsible={collapsible}
      >
        <Box onClick={keepOpen} sx={{ display: 'flex', cursor: expanded ? 'default' : undefined }}>
          <SenderAvatar accountId={accountId} email={email} info={avatarInfo} />
        </Box>
        <Box sx={{ flex: 1, minWidth: 0 }}>
          <Box onClick={keepOpen} sx={{ display: 'inline-block', maxWidth: '100%', cursor: expanded ? 'text' : undefined }} data-testid="sender-block">
          <Typography fontWeight={600} noWrap>
            <SenderHover email={email} info={avatarInfo}>{sender ? sender.name || sender.email : t('Unknown sender')}</SenderHover>
            {sender?.name && expanded && (
              <Typography component="span" variant="body2" color="text.secondary" sx={{ ml: 1 }}>
                &lt;{sender.email}&gt;
              </Typography>
            )}
          </Typography>
          <Typography variant="body2" color="text.secondary" noWrap>
            {expanded ? t('to {{recipients}}', { recipients: (email.to ?? []).map(formatAddress).join(', ') || t('undisclosed recipients') }) : encrypted ? t('Encrypted message') : email.preview}
          </Typography>
          </Box>
        </Box>
        {/* Clicks inside these tools (and their dialogs) must not toggle the message. */}
        {expanded && (
          <Box onClick={(e) => e.stopPropagation()} sx={{ flexShrink: 0 }}>
            <UnsubscribeButton email={email} />
          </Box>
        )}
        {encrypted && <Lock fontSize="small" color="action" aria-label={t('Encrypted')} />}
        {/* A phone has room for the sender's name only beside a short date; the full one is in the tooltip. */}
        <Typography variant="caption" color="text.secondary" sx={{ whiteSpace: 'nowrap' }} title={received}>
          {phone ? listDate(email.receivedAt) : received}
        </Typography>
        {expanded && (
          <Box onClick={(e) => e.stopPropagation()} sx={{ flexShrink: 0 }}>
            <MessageMenu email={email} accountId={accountId} ownEmail={ownEmail} inInbox={Boolean(inboxId) && Boolean(email.mailboxIds[inboxId])} />
          </Box>
        )}
      </Stack>
      <Collapse in={expanded} unmountOnExit>
        <Box sx={{ px: { xs: 1.5, sm: 2 }, pb: 2 }}>
          {email.cc && email.cc.length > 0 && (
            <Typography variant="body2" color="text.secondary" sx={{ mb: 1 }}>
              {t('cc {{recipients}}', { recipients: email.cc.map(formatAddress).join(', ') })}
            </Typography>
          )}
          <SecurityWarnings email={email} />
          {email.maskedAddresses?.map((address) => <Typography key={address} variant="caption" color="text.secondary" display="block" sx={{ mb: 1 }}>{t('Received via {{address}}', { address })}</Typography>)}
          <SmimeBadges status={email.smime} />
          {!encrypted && !email.smime?.encrypted && <SummaryCards key={`cards-${email.id}`} emailId={email.id} />}
          {!encrypted && !email.smime?.encrypted && <AiAssist key={email.id} email={email} />}
          <MessageBody email={email} accountId={accountId} ownEmail={ownEmail} />
          {invite && <Invitation key={invite.blobId} name={invite.name ?? 'invite.ics'} url={downloadUrl(accountId, invite.blobId, invite.name ?? 'invite.ics')} />}
          {files.length > 0 && (
            <Stack direction="row" flexWrap="wrap" gap={1} sx={{ mt: 2 }}>
              {files.map((file) => (
                <AttachmentChip
                  key={file.partId}
                  file={{ name: file.name ?? 'attachment', type: file.type, url: downloadUrl(accountId, file.blobId, file.name ?? 'attachment') }}
                  size={file.size}
                  onPreview={setPreview}
                />
              ))}
            </Stack>
          )}
          {!encrypted && !email.smime?.encrypted && !email.keywords.$draft && email.from?.some((sender) => sender.email.toLowerCase() !== ownEmail.toLowerCase()) && <SmartReplies key={`replies-${email.id}`} emailId={email.id} onChoose={(text, replyAll) => onAction(replyAll ? 'replyAll' : 'reply', email, text)} />}
          <Stack direction="row" spacing={1} sx={{ mt: 2 }} flexWrap="wrap" useFlexGap>
            <Button variant="outlined" startIcon={<Reply />} onClick={() => onAction('reply', email)}>
              {t('Reply')}
            </Button>
            <Button variant="outlined" startIcon={<ReplyAll />} onClick={() => onAction('replyAll', email)}>
              {t('Reply all')}
            </Button>
            <Button variant="outlined" startIcon={<Forward />} onClick={() => onAction('forward', email)}>
              {t('Forward')}
            </Button>
            {preview && <AttachmentPreview file={preview} onClose={() => setPreview(null)} />}
            {plugins.messageActions.map((action) => (
              <Button key={action.id} onClick={() => action.onClick(pluginMessage(email, emailHtml(email, accountId)))}>
                {action.label}
              </Button>
            ))}
          </Stack>
        </Box>
      </Collapse>
    </Paper>
  );
}

export interface ReaderProps {
  emails: EmailFull[] | null;
  accountId: string;
  /** Address of the signed-in user. */
  ownEmail: string;
  /** Id of the user's inbox, where categories apply. */
  inboxId: string;
  onBack: () => void;
  onArchive: () => void;
  onDelete: () => void;
  onJunk: () => void;
  /** Set while reading in Junk: the conversation is wanted after all. */
  onNotSpam?: () => void;
  onMarkUnread: () => void;
  /** Puts the conversation away until a time. */
  onSnooze: (until: Date) => void;
  /** Calls back a message scheduled to be sent. */
  onCancelScheduled: (emailId: string) => void;
  /** Every label in use in the account. */
  labels: string[];
  onToggleLabel: (label: string, on: boolean) => void;
  onAction: (action: ReaderAction, email: EmailFull, suggestedText?: string) => void;
}

/** A sender's request for a read receipt: answered as the user prefers (asked by default). */
function ReceiptRequest({ emails, ownEmail }: { emails: EmailFull[]; ownEmail: string }) {
  const prefs = usePrefs();
  const policy = prefs.receipts ?? 'ask';
  const [answered, setAnswered] = useState<Record<string, boolean>>({});
  const [error, setError] = useState('');
  const pending = emails.find((e) => e.receiptRequestedBy && !e.keywords.$mdnsent && !answered[e.id] && !(e.from ?? []).some((a) => a.email.toLowerCase() === ownEmail.toLowerCase()));
  const answer = useCallback(async (emailId: string, send: boolean, automatic = false) => {
    setAnswered((state) => ({ ...state, [emailId]: true }));
    try {
      await answerReceipt(emailId, send, automatic);
    } catch (err) {
      setError(errorText(err, t('The receipt could not be sent')));
    }
  }, []);
  useEffect(() => {
    // Without asking only when the receipt goes back to the sender itself (RFC 8098 2.1): a
    // message cannot make this mailbox write to a third party.
    if (pending && policy === 'always' && pending.receiptAutomaticAllowed) void answer(pending.id, true, true);
  }, [pending, policy, answer]);
  if (error) return <Alert severity="error" sx={{ mb: 2 }} onClose={() => setError('')}>{error}</Alert>;
  const asks = policy === 'ask' || (policy === 'always' && !pending?.receiptAutomaticAllowed);
  if (!pending || !asks) return null;
  return (
    <Alert
      severity="info"
      sx={{ mb: 2 }}
      action={
        <Stack direction="row" spacing={1}>
          <Button color="inherit" size="small" onClick={() => void answer(pending.id, true)}>{t('Send receipt')}</Button>
          <Button color="inherit" size="small" onClick={() => void answer(pending.id, false)}>{t("Don't send")}</Button>
        </Stack>
      }
    >
      {t('{{receiptRequestedBy}} asked to be told when you have read this message.', { receiptRequestedBy: pending.receiptRequestedBy })}
    </Alert>
  );
}

/** Conversation view: every message of a thread, the latest one expanded. */
export function Reader({ emails, accountId, ownEmail, inboxId, onBack, onArchive, onDelete, onJunk, onNotSpam, onMarkUnread, onSnooze, onCancelScheduled, onAction, labels, onToggleLabel }: ReaderProps) {
  const [labelAnchor, setLabelAnchor] = useState<HTMLElement | null>(null);
  const [snoozeAnchor, setSnoozeAnchor] = useState<HTMLElement | null>(null);
  const [snoozeAt, setSnoozeAt] = useState<string | null>(null);
  const [newLabel, setNewLabel] = useState('');
  const [expanded, setExpanded] = useState<Record<string, boolean>>({});
  const last = emails?.[emails.length - 1];
  useEffect(() => setExpanded(last ? { [last.id]: true } : {}), [last?.id]);

  // A label counts as applied when every message of the conversation carries it.
  const applied = emails && emails.length > 0 ? labelsOf(emails[0]).filter((label) => emails.every((e) => e.keywords[label])) : [];
  if (!emails) {
    return (
      <Box sx={{ display: 'grid', placeItems: 'center', height: '100%' }}>
        <CircularProgress />
      </Box>
    );
  }
  return (
    <Box sx={{ height: '100%', display: 'flex', flexDirection: 'column' }} role="region" aria-label={t('Conversation')}>
      <Stack direction="row" spacing={0.5} alignItems="center" sx={{ p: 1 }}>
        <Tooltip title={t('Back to list (u)')}><IconButton aria-label={t('Back to list')} onClick={onBack}><ArrowBack /></IconButton></Tooltip>
        <Tooltip title={t('Archive (e)')}><IconButton aria-label={t('Archive')} onClick={onArchive}><Archive /></IconButton></Tooltip>
        {onNotSpam ? (
          <Tooltip title={t('Not spam: move to the inbox')}><IconButton aria-label={t('Not spam')} onClick={onNotSpam}><ReportOff /></IconButton></Tooltip>
        ) : (
          <Tooltip title={t('Report spam')}><IconButton aria-label={t('Report spam')} onClick={onJunk}><Report /></IconButton></Tooltip>
        )}
        <Tooltip title={t('Delete (#)')}><IconButton aria-label={t('Delete')} onClick={onDelete}><Delete /></IconButton></Tooltip>
        <Tooltip title={t('Mark as unread')}><IconButton aria-label={t('Mark as unread')} onClick={onMarkUnread}><MarkEmailUnread /></IconButton></Tooltip>
        <Tooltip title={t('Snooze')}><IconButton aria-label={t('Snooze')} onClick={(e) => setSnoozeAnchor(e.currentTarget)}><Snooze /></IconButton></Tooltip>
        <Menu anchorEl={snoozeAnchor} open={Boolean(snoozeAnchor)} onClose={() => setSnoozeAnchor(null)}>
          <MenuItem disabled sx={{ opacity: '1 !important' }}><Typography variant="caption" color="text.secondary">{t('Snooze until')}</Typography></MenuItem>
          {snoozePresets(new Date()).map((preset) => (
            <MenuItem key={preset.label} onClick={() => { setSnoozeAnchor(null); onSnooze(preset.at); }}>
              <ListItemText primary={preset.label} secondary={preset.at.toLocaleString(uiLocale(), { weekday: 'short', day: 'numeric', month: 'short', hour: '2-digit', minute: '2-digit' })} />
            </MenuItem>
          ))}
          <MenuItem onClick={() => { setSnoozeAnchor(null); setSnoozeAt(''); }}>{t('Pick a date and time…')}</MenuItem>
        </Menu>
        <Dialog open={snoozeAt !== null} onClose={() => setSnoozeAt(null)}>
          <DialogTitle>{t('Snooze until')}</DialogTitle>
          <DialogContent>
            <TextField type="datetime-local" label={t('Bring back at')} value={snoozeAt ?? ''} onChange={(e) => setSnoozeAt(e.target.value)} sx={{ mt: 1 }} slotProps={{ inputLabel: { shrink: true } }} />
          </DialogContent>
          <DialogActions>
            <Button onClick={() => setSnoozeAt(null)}>{t('Cancel')}</Button>
            <Button variant="contained" disabled={!snoozeAt || new Date(snoozeAt).getTime() <= Date.now()} onClick={() => { const at = new Date(snoozeAt ?? ''); setSnoozeAt(null); onSnooze(at); }}>
              {t('Snooze')}
            </Button>
          </DialogActions>
        </Dialog>
        <Tooltip title={t('Labels')}><IconButton aria-label={t('Labels')} onClick={(e) => setLabelAnchor(e.currentTarget)}><Label /></IconButton></Tooltip>
        <Menu anchorEl={labelAnchor} open={Boolean(labelAnchor)} onClose={() => setLabelAnchor(null)} slotProps={{ paper: { sx: { minWidth: 240 } } }}>
          {[...new Set([...labels, ...applied])].sort().map((label) => (
            <MenuItem key={label} dense onClick={() => { setLabelAnchor(null); onToggleLabel(label, !applied.includes(label)); }}>
              <Checkbox edge="start" size="small" checked={applied.includes(label)} tabIndex={-1} disableRipple />
              <ListItemText primary={label} />
            </MenuItem>
          ))}
          <Box sx={{ px: 2, py: 1 }} onKeyDown={(e) => e.stopPropagation()}>
            <TextField
              label={t('New label')}
              value={newLabel}
              onChange={(e) => setNewLabel(e.target.value)}
              error={Boolean(newLabel) && !normalizeLabel(newLabel)}
              helperText={newLabel && !normalizeLabel(newLabel) ? t('Letters, digits, - _ . only') : t('Press Enter to add')}
              onKeyDown={(e) => {
                const label = normalizeLabel(newLabel);
                if (e.key === 'Enter' && label) {
                  // Without this the same key press re-activates the Labels button once
                  // focus returns to it, reopening the menu.
                  e.preventDefault();
                  onToggleLabel(label, true);
                  setNewLabel('');
                  setLabelAnchor(null);
                }
              }}
              fullWidth
            />
          </Box>
        </Menu>
      </Stack>
      <Box sx={{ flex: 1, overflow: 'auto', px: { xs: 0, sm: 2 }, pb: 3 }}>
        <Box sx={{ px: { xs: 2, sm: 0 } }}>
        <Typography variant="h5" component="h2" sx={{ mb: applied.length ? 1 : 2, overflowWrap: 'anywhere', fontSize: { xs: '1.25rem', sm: '1.5rem' } }}>
          {emails[0]?.subject || t('(no subject)')}
        </Typography>
        {applied.length > 0 && (
          <Stack direction="row" flexWrap="wrap" gap={0.5} sx={{ mb: 2 }}>
            {applied.map((label) => (
              <Chip key={label} size="small" icon={<Label />} label={label} onDelete={() => onToggleLabel(label, false)} />
            ))}
          </Stack>
        )}
        {emails.filter((email) => email.keywords.$scheduled).map((email) => (
          <Alert key={`scheduled-${email.id}`} severity="info" sx={{ mb: 2 }} action={<Button color="inherit" size="small" onClick={() => onCancelScheduled(email.id)}>{t('Cancel sending')}</Button>}>
            {t('This message is waiting to be sent.')}
          </Alert>
        ))}
        <ReceiptRequest emails={emails} ownEmail={ownEmail} />
        </Box>
        <AiModelsProvider key={accountId}>
        <Stack spacing={1.5}>
          {emails.map((email) => (
            <Message
              key={email.id}
              email={email}
              accountId={accountId}
              ownEmail={ownEmail}
              inboxId={inboxId}
              // A conversation of one message has nothing to fold away.
              expanded={emails.length === 1 || Boolean(expanded[email.id])}
              collapsible={emails.length > 1}
              onToggle={() => setExpanded((state) => ({ ...state, [email.id]: !state[email.id] }))}
              onAction={onAction}
            />
          ))}
        </Stack>
        </AiModelsProvider>
      </Box>
    </Box>
  );
}
