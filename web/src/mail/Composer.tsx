import AttachFile from '@mui/icons-material/AttachFile';
import Close from '@mui/icons-material/Close';
import DeleteOutline from '@mui/icons-material/DeleteOutline';
import Draw from '@mui/icons-material/Draw';
import CloseFullscreen from '@mui/icons-material/CloseFullscreen';
import Minimize from '@mui/icons-material/Minimize';
import MoreVert from '@mui/icons-material/MoreVert';
import OpenInFull from '@mui/icons-material/OpenInFull';
import TextFormat from '@mui/icons-material/TextFormat';
import EmojiEmotionsOutlined from '@mui/icons-material/EmojiEmotionsOutlined';
import Image from '@mui/icons-material/Image';
import InsertLink from '@mui/icons-material/InsertLink';
import Lock from '@mui/icons-material/Lock';
import LockOpen from '@mui/icons-material/LockOpen';
import Spellcheck from '@mui/icons-material/Spellcheck';
import TextSnippet from '@mui/icons-material/TextSnippet';
import {
  alpha, Alert, Box, Button, Chip, Divider, IconButton, ListItemIcon, ListItemText, Menu, MenuItem, Paper, Select,
  Stack, Tooltip, Typography, useMediaQuery, useTheme,
} from '@mui/material';
import { useCallback, useEffect, useRef, useState } from 'react';
import { formatBytes, uploadBlob, errorText } from '../api';
import { useAuth } from '../app';
import { type ComposerHandle, emit, usePlugins } from '../plugins';
import { updatePrefs, usePrefs } from '../prefs';
import { type Identity, listIdentities, listSignatures, listTemplates, type Signatures, saveTemplate, type Template } from './extra';
import { type Draft, type DraftAttachment, destroyEmails, draftRecipients, saveDraft, type Sent, type SendOptions, sendEmail, sendEncrypted } from './jmapClient';
import { EmojiPicker } from './EmojiPicker';
import { FormattingToolbar, SendButton } from './ComposerTools';
import { fetchSmime } from './Smime';
import { isNetworkError, performOrQueue } from './outbox';
import { pendingFilesAvailable, removePendingFiles, storePendingFile } from './pendingFiles';
import { fetchKeys, isUnlocked, lookupKeys } from './pgp';
import { escapeHtml, sanitizeEmailHtml } from './sanitize';

import { t } from '../i18n';
import { FIELD_ROW, Field, RecipientField } from './ComposerFields';
const AUTOSAVE_DELAY_MS = 2500;
/** Files attached without a connection are kept in the browser until the message is sent. */
const MAX_OFFLINE_ATTACHMENT_BYTES = 25 * 1024 * 1024;
/** Without IndexedDB the file travels inside the queued message in local storage. */
const MAX_INLINE_OFFLINE_BYTES = 2 * 1024 * 1024;
const SIGNATURE_CLASS = 'unomail-signature';
/** Languages offered for spell checking; the browser provides the dictionaries. */
const SPELL_LANGUAGES: [string, string][] = [
  ['', 'Browser default'], ['en', 'English'], ['pl', 'Polski'], ['de', 'Deutsch'], ['fr', 'Français'], ['es', 'Español'], ['it', 'Italiano'],
  ['nl', 'Nederlands'], ['pt', 'Português'], ['cs', 'Čeština'], ['sk', 'Slovenčina'], ['uk', 'Українська'],
];

async function toBase64(file: Blob): Promise<string> {
  const bytes = new Uint8Array(await file.arrayBuffer());
  let binary = '';
  for (let i = 0; i < bytes.length; i += 0x8000) binary += String.fromCharCode(...bytes.subarray(i, i + 0x8000));
  return btoa(binary);
}

export interface ComposerProps {
  initial: Draft;
  accountId: string;
  draftsId: string;
  sentId: string;
  /** A stored draft this composer continues (its copy is replaced on save and send). */
  draftEmailId?: string;
  /**
   * `queued` is set when the message was stored to be sent once the connection returns;
   * `info` says how to call the message back, or when it is scheduled.
   */
  onClose: (sent: boolean, queued?: boolean, info?: SentInfo) => void;
}

export interface SentInfo extends Sent {
  draft: Draft;
  /** Seconds left to call the message back. */
  undoSeconds?: number;
  scheduledAt?: Date;
}

export function Composer({ initial, accountId, draftsId, sentId, draftEmailId, onClose }: ComposerProps) {
  const { account } = useAuth();
  const prefs = usePrefs();
  const plugins = usePlugins();
  const [to, setTo] = useState(initial.to);
  const [cc, setCc] = useState(initial.cc);
  const [bcc, setBcc] = useState(initial.bcc);
  const [showCc, setShowCc] = useState(Boolean(initial.cc || initial.bcc));
  const [subject, setSubject] = useState(initial.subject);
  const [attachments, setAttachments] = useState<DraftAttachment[]>(initial.attachments);
  const [status, setStatus] = useState('');
  const [error, setError] = useState('');
  const [busy, setBusy] = useState(false);
  const [identities, setIdentities] = useState<Identity[]>([]);
  const [identityId, setIdentityId] = useState<number | null>(null);
  const [templates, setTemplates] = useState<Template[] | null>(null);
  const [templateAnchor, setTemplateAnchor] = useState<HTMLElement | null>(null);
  const [signatures, setSignatures] = useState<Signatures | null>(null);
  const [signatureAnchor, setSignatureAnchor] = useState<HTMLElement | null>(null);
  const [encrypt, setEncrypt] = useState(false);
  const [wantFullScreen, setFullScreen] = useState(false);
  const [minimized, setMinimized] = useState(false);
  const [formatting, setFormatting] = useState(true);
  const [moreMenu, setMoreMenu] = useState<HTMLElement | null>(null);
  const [emojiAnchor, setEmojiAnchor] = useState<HTMLElement | null>(null);
  // Where the cursor was in the message when the emoji picker took the focus.
  const emojiRange = useRef<Range | null>(null);
  const theme = useTheme();
  const phone = useMediaQuery(theme.breakpoints.down('sm'));
  const fullScreen = wantFullScreen || phone;
  const editor = useRef<HTMLDivElement>(null);
  const fileInput = useRef<HTMLInputElement>(null);
  const imageInput = useRef<HTMLInputElement>(null);
  const draftId = useRef<string | undefined>(draftEmailId);
  const [receipt, setReceipt] = useState(Boolean(initial.receiptTo));
  // S/MIME is offered once the user has a certificate.
  const [smimeAvailable, setSmimeAvailable] = useState(false);
  const [smime, setSmime] = useState({ sign: false, encrypt: false });
  useEffect(() => {
    fetchSmime().then((s) => setSmimeAvailable(Boolean(s.certificate)), () => {});
  }, []);
  const dirty = useRef(initial.saveOnOpen === true);
  const saving = useRef(false);
  const closed = useRef(false);
  // Inline images are shown from local object URLs and referenced by Content-ID when sent.
  const inlineImages = useRef<Map<string, string>>(new Map());
  const identity = identities.find((candidate) => candidate.id === identityId);
  const spellcheck = prefs.spellcheck !== false;

  // Read when a signature is put in, without making the loading effects depend on them.
  const placement = useRef({ separator: false, belowQuote: false });
  useEffect(() => {
    placement.current = { separator: prefs.signature_separator === true, belowQuote: prefs.signature_below_quote === true };
  }, [prefs.signature_separator, prefs.signature_below_quote]);
  /** Counts signature changes, so that a slow one does not overwrite a later one. */
  const signatureTurn = useRef(0);

  /** Images in a signature are stored inside it; in a message they travel as inline parts. */
  const attachSignatureImages = useCallback(
    async (html: string) => {
      const holder = document.createElement('div');
      holder.innerHTML = html;
      for (const img of Array.from(holder.querySelectorAll('img'))) {
        const src = img.getAttribute('src') ?? '';
        if (!src.startsWith('data:')) continue;
        try {
          const blob = await (await fetch(src)).blob();
          const cid = `${crypto.randomUUID()}@unomail`;
          const attachment: DraftAttachment = { blobId: (await uploadBlob(accountId, blob)).blobId, name: `signature.${blob.type.split('/')[1] ?? 'png'}`, type: blob.type, size: blob.size, cid };
          const url = URL.createObjectURL(blob);
          inlineImages.current.set(url, cid);
          img.setAttribute('src', url);
          setAttachments((list) => [...list, attachment]);
        } catch {
          // Offline: the image stays inside the message as it is.
        }
      }
      return holder.innerHTML;
    },
    [accountId],
  );

  /** Puts a signature into the message, replacing the one already there ('' removes it). */
  const applySignature = useCallback(
    async (html: string) => {
      const turn = ++signatureTurn.current;
      let signature = sanitizeEmailHtml(html);
      if (signature) {
        signature = await attachSignatureImages(signature);
        if (placement.current.separator) signature = `-- <br>${signature}`;
      }
      const root = editor.current;
      if (!root || turn !== signatureTurn.current) return;
      const existing = root.querySelector(`.${SIGNATURE_CLASS}`);
      if (existing) {
        if (signature) existing.innerHTML = signature;
        else existing.remove();
      } else if (signature) {
        const block = `<div class="${SIGNATURE_CLASS}">${signature}</div>`;
        // Below the place where the user writes: above any quoted text, or under it if preferred.
        if (initial.answer && placement.current.belowQuote) root.insertAdjacentHTML('beforeend', `<p><br></p>${block}`);
        else if (root.querySelector(':scope > .unomail-reply-text')) root.querySelector(':scope > .unomail-reply-text')!.insertAdjacentHTML('afterend', `<p><br></p>${block}`);
        else root.insertAdjacentHTML('afterbegin', `<p><br></p>${block}`);
      }
    },
    [attachSignatureImages, initial.answer],
  );

  /** The signature an identity uses by default for this kind of message. */
  const defaultSignature = useCallback(
    (chosen: Identity | undefined, list: Signatures | null) => {
      if (!chosen) return '';
      if (!list) return chosen.signature_html;
      const choice = list.defaults[chosen.email];
      const id = initial.answer ? choice?.reply_signature_id : choice?.new_signature_id;
      return list.signatures.find((signature) => signature.id === id)?.html ?? '';
    },
    [initial.answer],
  );

  useEffect(() => {
    if (editor.current) editor.current.innerHTML = sanitizeEmailHtml(initial.html);
    const urls = inlineImages.current;
    return () => urls.forEach((_, url) => URL.revokeObjectURL(url));
  }, [initial.html]);

  // Sender identities: when replying, prefer the address the original was sent to.
  useEffect(() => {
    let cancelled = false;
    Promise.all([listIdentities(), listSignatures().catch(() => null)])
      .then(([list, signatureList]) => {
        if (cancelled) return;
        const hints = (initial.fromHint ?? []).map((address) => address.toLowerCase());
        const intended = initial.from?.email;
        const unavailable: Identity | undefined = intended && !list.some((candidate) => candidate.email === intended) ? { id: -Number.MAX_SAFE_INTEGER, name: '', email: intended, reply_to: intended, signature_html: '', is_default: false, smtp: null, masked: true, available: false } : undefined;
        const chosen = intended ? list.find((candidate) => candidate.email === intended) ?? unavailable : list.find((candidate) => hints.includes(candidate.email)) ?? list.find((candidate) => candidate.is_default) ?? list[0];
        setIdentities(unavailable ? [...list, unavailable] : list);
        setSignatures(signatureList);
        setIdentityId(chosen?.id ?? null);
        // A draft being continued keeps the signature it has (or the lack of one).
        if (!draftEmailId) void applySignature(defaultSignature(chosen, signatureList));
      })
      // Offline: the message goes out from the account's own address.
      .catch(() => {});
    return () => {
      cancelled = true;
    };
  }, [initial.fromHint, initial.from, applySignature, defaultSignature, draftEmailId]);

  const currentDraft = useCallback((): Draft => {
    let html = editor.current?.innerHTML ?? '';
    inlineImages.current.forEach((cid, url) => {
      html = html.split(url).join(`cid:${cid}`);
    });
    // Whatever was typed or pasted is sanitized again before it leaves the browser.
    html = sanitizeEmailHtml(html, (cid) => `cid:${cid}`);
    const used = attachments.filter((a) => !a.cid || html.includes(`cid:${a.cid}`));
    const from = identity ? { name: identity.name || null, email: identity.email } : initial.from;
    return { to, cc, bcc, subject, html, attachments: used, inReplyTo: initial.inReplyTo, references: initial.references, from, replyTo: identity?.reply_to || undefined };
  }, [to, cc, bcc, subject, attachments, initial.inReplyTo, initial.references, initial.from, identity]);

  const markDirty = () => {
    dirty.current = true;
    setStatus('');
  };

  // Auto-save: a few seconds after the last change the draft is stored on the server.
  useEffect(() => {
    if (!dirty.current) return;
    // A message that is going to be encrypted is never stored on the server in the clear.
    if (encrypt) return;
    const timer = setTimeout(async () => {
      if (saving.current || closed.current) return;
      saving.current = true;
      dirty.current = false;
      try {
        draftId.current = await saveDraft(currentDraft(), draftsId, draftId.current);
        if (!closed.current) setStatus(t('Draft saved'));
      } catch {
        dirty.current = true;
        if (!closed.current) setStatus(t('Draft not saved'));
      } finally {
        saving.current = false;
      }
    }, AUTOSAVE_DELAY_MS);
    return () => clearTimeout(timer);
  });

  async function addFiles(files: FileList | null, inline: boolean) {
    if (!files) return;
    setError('');
    for (const file of Array.from(files)) {
      try {
        const attachment: DraftAttachment = { blobId: '', name: file.name, type: file.type || 'application/octet-stream', size: file.size };
        try {
          attachment.blobId = (await uploadBlob(accountId, file)).blobId;
        } catch (err) {
          // Offline: keep the file with the message and upload it when the message is sent.
          if (!isNetworkError(err)) throw err;
          if (file.size > MAX_OFFLINE_ATTACHMENT_BYTES) throw new Error(t('files over 25 MB cannot be attached while offline'));
          const stored = pendingFilesAvailable() ? await storePendingFile(file).catch(() => null) : null;
          if (stored) {
            attachment.blobId = stored;
          } else {
            if (file.size > MAX_INLINE_OFFLINE_BYTES) throw new Error(t('this browser cannot keep files over 2 MB while offline'));
            attachment.blobId = `pending:${crypto.randomUUID()}`;
            attachment.pendingData = await toBase64(file);
          }
        }
        if (inline && file.type.startsWith('image/')) {
          attachment.cid = `${crypto.randomUUID()}@unomail`;
          const url = URL.createObjectURL(file);
          inlineImages.current.set(url, attachment.cid);
          editor.current?.focus();
          document.execCommand('insertHTML', false, `<img src="${url}" alt="${escapeHtml(file.name)}">`);
        }
        setAttachments((list) => [...list, attachment]);
        markDirty();
      } catch (err) {
        setError(t('Could not attach {{name}}: {{reason}}', { name: file.name, reason: errorText(err, t('upload failed')) }));
      }
    }
  }

  function openEmoji(button: HTMLElement) {
    const selection = window.getSelection();
    const range = selection?.rangeCount ? selection.getRangeAt(0) : null;
    emojiRange.current = range && editor.current?.contains(range.commonAncestorContainer) ? range.cloneRange() : null;
    setEmojiAnchor(button);
  }

  function insertEmoji(emoji: string) {
    setEmojiAnchor(null);
    editor.current?.focus();
    const selection = window.getSelection();
    if (emojiRange.current && selection) {
      selection.removeAllRanges();
      selection.addRange(emojiRange.current);
    }
    document.execCommand('insertText', false, emoji);
    emojiRange.current = selection?.rangeCount ? selection.getRangeAt(0).cloneRange() : null;
    markDirty();
  }

  function format(command: string, value?: string) {
    editor.current?.focus();
    document.execCommand(command, false, value);
    markDirty();
  }

  /** Inserts HTML at the cursor, sanitized first. */
  function insertHtml(html: string) {
    editor.current?.focus();
    document.execCommand('insertHTML', false, sanitizeEmailHtml(html));
    markDirty();
  }

  function insertLink() {
    const url = window.prompt(t('Link address'), 'https://')?.trim();
    if (!url) return;
    // Only web and mail links; anything else (javascript:, data:) is refused.
    if (!/^(https?:\/\/|mailto:)/i.test(url)) {
      setError(t('Links must start with https://, http:// or mailto:'));
      return;
    }
    format('createLink', url);
  }

  function onPaste(event: React.ClipboardEvent<HTMLDivElement>) {
    // Pasted markup comes from arbitrary pages; never insert it unsanitized.
    event.preventDefault();
    const html = event.clipboardData.getData('text/html');
    const text = event.clipboardData.getData('text/plain');
    document.execCommand('insertHTML', false, html ? sanitizeEmailHtml(html) : escapeHtml(text).replace(/\n/g, '<br>'));
    markDirty();
  }

  function changeIdentity(id: number) {
    setIdentityId(id);
    void applySignature(defaultSignature(identities.find((candidate) => candidate.id === id), signatures));
    markDirty();
  }

  async function openTemplates(anchor: HTMLElement) {
    setTemplateAnchor(anchor);
    try {
      setTemplates(await listTemplates());
    } catch {
      setTemplates([]);
    }
  }

  function insertTemplate(template: Template) {
    setTemplateAnchor(null);
    if (!subject.trim() && template.subject) setSubject(template.subject);
    insertHtml(template.html);
  }

  async function saveAsTemplate() {
    setTemplateAnchor(null);
    const name = window.prompt(t('Name of the new template'))?.trim();
    if (!name) return;
    try {
      // The signature belongs to the identity, not to the template.
      const copy = document.createElement('div');
      copy.innerHTML = currentDraft().html;
      copy.querySelector(`.${SIGNATURE_CLASS}`)?.remove();
      await saveTemplate(0, { name, subject, html: copy.innerHTML });
      setStatus(t('Template saved'));
    } catch (err) {
      setError(errorText(err, t('The template could not be saved')));
    }
  }

  /** Sends the message end-to-end encrypted; every recipient needs a known public key. */
  async function sendWithEncryption(draft: Draft, options?: SendOptions): Promise<Sent> {
    const own = await fetchKeys();
    if (!own?.public_key) throw new Error(t('Set up encryption in Settings before sending encrypted mail.'));
    const recipients = draftRecipients(draft);
    const keys = await lookupKeys(recipients);
    const missing = recipients.filter((address) => !keys[address]);
    if (missing.length > 0) throw new Error(t('No public key is known for {{value}}. Add it to the contact, or send without encryption.', { value: missing.join(', ') }));
    const sender = draft.from ?? { name: account?.display_name || null, email: account?.email ?? '' };
    // Encrypted to the sender as well, so the copy in Sent stays readable.
    return sendEncrypted(draft, sender, [...Object.values(keys), own.public_key], draftsId, sentId, draftId.current, options);
  }

  async function send(at?: Date) {
    if (identity?.available === false) { setError(t('Selected sending address is unavailable. Choose another address.')); return; }
    const sender = identity?.email ?? initial.from?.email ?? account?.email;
    const draft = { ...currentDraft(), receiptTo: receipt ? sender : undefined, smime: smimeAvailable ? smime : undefined };
    const undoSeconds = at ? undefined : (prefs.undo_send_seconds ?? 5);
    const options: SendOptions | undefined = at ? { sendAt: at } : undoSeconds ? { holdFor: undoSeconds } : undefined;
    if (!draft.to.trim() && !draft.cc.trim() && !draft.bcc.trim()) {
      setError(t('Add at least one recipient.'));
      return;
    }
    setBusy(true);
    setError('');
    closed.current = true;
    try {
      const sent = encrypt ? await sendWithEncryption(draft, options) : await sendEmail(draft, draftsId, sentId, draftId.current, options);
      releasePending();
      emit('message:sent', { subject: draft.subject, recipients: [draft.to, draft.cc].filter(Boolean).join(', ') });
      onClose(true, false, { ...sent, draft, undoSeconds: sent.submissionId ? undoSeconds : undefined, scheduledAt: at });
    } catch (err) {
      // No connection: keep the message in the outbox and send it when back online.
      // Encrypted messages are not queued: encrypting needs the recipients' keys from the server.
      if (isNetworkError(err) && !encrypt) {
        try {
          await performOrQueue({ type: 'send', draft, draftsId, sentId });
          onClose(true, true);
          return;
        } catch (queueError) {
          err = queueError;
        }
      }
      closed.current = false;
      setError(isNetworkError(err) ? t('Encrypted messages cannot be sent while offline.') : errorText(err, t('The message could not be sent.')));
      setBusy(false);
    }
  }

  /** Files kept for offline sending are no longer needed once the composer lets go of them. */
  function releasePending() {
    void removePendingFiles(attachments.map((a) => a.blobId));
  }

  async function discard() {
    closed.current = true;
    releasePending();
    if (draftId.current) await destroyEmails([draftId.current]).catch(() => {});
    onClose(false);
  }

  async function saveAndClose() {
    closed.current = true;
    if (dirty.current && !encrypt) {
      try {
        await saveDraft(currentDraft(), draftsId, draftId.current);
      } catch {
        // Closing must not be blocked by a failed save; the last auto-saved copy remains.
      }
    }
    releasePending();
    onClose(false);
  }

  const handle: ComposerHandle = {
    getSubject: () => subject,
    setSubject: (value) => {
      setSubject(String(value));
      markDirty();
    },
    getRecipients: () => [to, cc].filter(Boolean).join(', '),
    insertHtml: (html) => insertHtml(String(html)),
  };

  const tint = alpha(theme.palette.primary.main, theme.palette.mode === 'dark' ? 0.16 : 0.08);
  return (
    <Paper
      elevation={8}
      role="dialog"
      aria-label={t('New message')}
      data-fullscreen={fullScreen}
      onKeyDown={(e) => {
        // Escape leaves full screen instead of doing anything else on the page.
        if (e.key === 'Escape' && fullScreen && !e.defaultPrevented) {
          e.stopPropagation();
          setFullScreen(false);
        }
      }}
      sx={
        fullScreen && !minimized
          ? { position: 'fixed', inset: 0, width: '100%', height: '100%', display: 'flex', flexDirection: 'column', borderRadius: 0, zIndex: 1300, overflow: 'hidden' }
          : { position: 'fixed', right: { xs: 0, sm: 24 }, bottom: 0, width: minimized ? { xs: '100%', sm: 320 } : { xs: '100%', sm: 600 }, maxHeight: '90vh', display: 'flex', flexDirection: 'column', borderRadius: '16px 16px 0 0', zIndex: 1300, overflow: 'hidden' }
      }
    >
      <Stack
        direction="row"
        alignItems="center"
        onClick={() => minimized && setMinimized(false)}
        sx={{ bgcolor: tint, pl: 2, pr: 1, py: 0.5, minHeight: 44, cursor: minimized ? 'pointer' : undefined }}
      >
        <Typography sx={{ flex: 1, fontSize: 14 }} fontWeight={500} noWrap>
          {minimized && subject ? subject : t('New message')}
        </Typography>
        <Typography variant="caption" color="text.secondary" sx={{ mr: 1 }} aria-live="polite">
          {status}
        </Typography>
        <Tooltip title={t('Minimize')}>
          <IconButton size="small" aria-label={t('Minimize')} aria-pressed={minimized} onClick={(e) => { e.stopPropagation(); setMinimized((on) => !on); }}><Minimize fontSize="small" /></IconButton>
        </Tooltip>
        {!phone && <Tooltip title={fullScreen ? t('Exit full screen') : t('Full screen')}>
          <IconButton size="small" aria-label={fullScreen ? t('Exit full screen') : t('Full screen')} onClick={(e) => { e.stopPropagation(); setMinimized(false); setFullScreen((on) => !on); }}>
            {fullScreen ? <CloseFullscreen fontSize="small" /> : <OpenInFull fontSize="small" />}
          </IconButton>
        </Tooltip>}
        <Tooltip title={t('Save and close')}>
          <IconButton size="small" aria-label={t('Save and close')} onClick={(e) => { e.stopPropagation(); saveAndClose(); }}><Close fontSize="small" /></IconButton>
        </Tooltip>
      </Stack>
      <Box sx={{ display: minimized ? 'none' : 'flex', flexDirection: 'column', flex: 1, minHeight: 0 }}>
        {error && <Alert severity="error" onClose={() => setError('')}>{error}</Alert>}
        {identity?.available === false && <Alert severity="warning">{t('Selected sending address is unavailable. Choose another address.')}</Alert>}
        {encrypt && (
          <Alert severity="success" icon={<Lock />} sx={{ py: 0 }}>
            {t('Body and attachments will be encrypted')}{isUnlocked() ? t(' and signed') : ''}{t('. The subject stays readable.')}
          </Alert>
        )}
        {identities.length > 1 && (
          <Stack direction="row" alignItems="center" sx={FIELD_ROW}>
            <Typography variant="body2" color="text.secondary" sx={{ mr: 1 }}>
              {t('From')}
            </Typography>
            <Select variant="standard" disableUnderline fullWidth value={identityId ?? ''} onChange={(e) => changeIdentity(Number(e.target.value))} SelectDisplayProps={{ 'aria-label': t('From') }} sx={{ fontSize: 14 }}>
              {identities.map((candidate) => (
                <MenuItem key={candidate.id} value={candidate.id} disabled={candidate.available === false}>
                  {candidate.name ? `${candidate.name} <${candidate.email}>` : candidate.email}
                </MenuItem>
              ))}
            </Select>
          </Stack>
        )}
        <RecipientField
          label={t('To')}
          placeholder={t('Recipients')}
          value={to}
          onChange={(v) => { setTo(v); markDirty(); }}
          autoFocus={!initial.to}
          end={!showCc && <Button size="small" sx={{ color: 'text.secondary', minWidth: 0, textTransform: 'none' }} onClick={() => setShowCc(true)}>{t('Cc/Bcc')}</Button>}
        />
        {showCc && <RecipientField label={t('Cc')} value={cc} onChange={(v) => { setCc(v); markDirty(); }} />}
        {showCc && <RecipientField label={t('Bcc')} value={bcc} onChange={(v) => { setBcc(v); markDirty(); }} />}
        <Field label={t('Subject')} value={subject} onChange={(v) => { setSubject(v); markDirty(); }} />
        <Box
          ref={editor}
          contentEditable
          suppressContentEditableWarning
          role="textbox"
          aria-multiline="true"
          aria-label={t('Message body')}
          // The browser's own spell checker, in the language the user chose.
          spellCheck={spellcheck}
          lang={prefs.spell_lang || undefined}
          onInput={markDirty}
          onPaste={onPaste}
          sx={{
            // contain: quoted mail can never paint outside the editor (no overlay over the app).
            flex: 1, minHeight: 180, overflow: 'auto', contain: 'paint', px: 2, py: 1.5, outline: 'none', '& img': { maxWidth: '100%' },
            '& blockquote': { ml: 1, pl: 1, borderLeft: 3, borderColor: 'divider', color: 'text.secondary' },
            [`& .${SIGNATURE_CLASS}`]: { color: 'text.secondary' },
          }}
        />
        {attachments.filter((a) => !a.cid).length > 0 && (
          <Stack direction="row" flexWrap="wrap" gap={1} sx={{ px: 2, pb: 1 }}>
            {attachments.filter((a) => !a.cid).map((a) => (
              <Chip key={a.blobId} label={`${a.name} (${formatBytes(a.size)})`} onDelete={() => { setAttachments((list) => list.filter((x) => x.blobId !== a.blobId)); void removePendingFiles([a.blobId]); markDirty(); }} />
            ))}
          </Stack>
        )}
        {formatting && <FormattingToolbar onFormat={format} tint={tint} />}
        <Stack direction="row" alignItems="center" flexWrap="wrap" useFlexGap sx={{ px: 1.5, pt: 0.5, pb: 1.5, columnGap: 0.25, rowGap: 0.5 }}>
          <SendButton
            busy={busy}
            onSend={(at) => void send(at)}
            receipt={receipt}
            onToggleReceipt={() => setReceipt((on) => !on)}
            smime={smimeAvailable ? smime : null}
            onToggleSmime={(key) => setSmime((s) => ({ ...s, [key]: !s[key] }))}
          />
          <Tooltip title={t('Formatting options')}>
            <IconButton aria-label={t('Formatting options')} aria-pressed={formatting} onClick={() => setFormatting((on) => !on)} sx={formatting ? { bgcolor: tint } : undefined}><TextFormat /></IconButton>
          </Tooltip>
          <Tooltip title={t('Attach files')}><IconButton aria-label={t('Attach files')} onClick={() => fileInput.current?.click()}><AttachFile /></IconButton></Tooltip>
          <Tooltip title={t('Insert link')}><IconButton aria-label={t('Insert link')} onClick={insertLink}><InsertLink /></IconButton></Tooltip>
          <Tooltip title={t('Insert emoji')}><IconButton aria-label={t('Insert emoji')} onClick={(e) => openEmoji(e.currentTarget)}><EmojiEmotionsOutlined /></IconButton></Tooltip>
          <EmojiPicker anchor={emojiAnchor} onClose={() => setEmojiAnchor(null)} onPick={insertEmoji} />
          <Tooltip title={t('Insert image')}><IconButton aria-label={t('Insert image')} onClick={() => imageInput.current?.click()}><Image /></IconButton></Tooltip>
          <Tooltip title={encrypt ? t('Encryption is on') : t('Encrypt this message (OpenPGP)')}>
            <IconButton aria-label={t('Encrypt message')} aria-pressed={encrypt} color={encrypt ? 'success' : 'default'} onClick={() => setEncrypt((on) => !on)}>
              {encrypt ? <Lock /> : <LockOpen />}
            </IconButton>
          </Tooltip>
          <Tooltip title={t('Signature')}><IconButton aria-label={t('Signature')} onClick={(e) => setSignatureAnchor(e.currentTarget)}><Draw /></IconButton></Tooltip>
          <Tooltip title={t('Templates')}><IconButton aria-label={t('Templates')} onClick={(e) => void openTemplates(e.currentTarget)}><TextSnippet /></IconButton></Tooltip>
          <Tooltip title={t('More actions')}><IconButton aria-label={t('More actions')} onClick={(e) => setMoreMenu(e.currentTarget)}><MoreVert /></IconButton></Tooltip>
          <Menu anchorEl={moreMenu} open={Boolean(moreMenu)} onClose={() => setMoreMenu(null)}>
            <MenuItem onClick={() => void updatePrefs({ spellcheck: !spellcheck }).catch(() => {})}>
              <ListItemIcon><Spellcheck fontSize="small" color={spellcheck ? 'primary' : 'inherit'} /></ListItemIcon>
              <ListItemText primary={spellcheck ? t('Spell checking is on') : t('Spell checking is off')} />
            </MenuItem>
            {spellcheck && (
              <MenuItem disableRipple sx={{ '&:hover': { bgcolor: 'transparent' } }}>
                <ListItemText primary={t('Spelling language')} sx={{ mr: 2 }} />
                <Select
                  size="small"
                  variant="standard"
                  disableUnderline
                  displayEmpty
                  value={prefs.spell_lang ?? ''}
                  onChange={(e) => void updatePrefs({ spell_lang: String(e.target.value) }).catch(() => {})}
                  inputProps={{ 'aria-label': t('Spelling language') }}
                  sx={{ fontSize: 13, minWidth: 70 }}
                >
                  {SPELL_LANGUAGES.map(([code, name]) => (
                    <MenuItem key={code} value={code}>
                      {name}
                    </MenuItem>
                  ))}
                </Select>
              </MenuItem>
            )}
          </Menu>
          {plugins.composerActions.map((action) => (
            <Button key={action.id} size="small" onClick={() => action.onClick(handle)}>
              {action.label}
            </Button>
          ))}
          <Box sx={{ flex: 1 }} />
          <Tooltip title={t('Discard draft')}><IconButton aria-label={t('Discard draft')} onClick={discard}><DeleteOutline /></IconButton></Tooltip>
          <input ref={fileInput} type="file" multiple hidden aria-label={t('Attachment files')} onChange={(e) => { void addFiles(e.target.files, false); e.target.value = ''; }} />
          <input ref={imageInput} type="file" accept="image/png,image/jpeg,image/gif,image/webp" hidden onChange={(e) => { void addFiles(e.target.files, true); e.target.value = ''; }} />
        </Stack>
      </Box>
      <Menu anchorEl={templateAnchor} open={Boolean(templateAnchor)} onClose={() => setTemplateAnchor(null)} slotProps={{ paper: { sx: { minWidth: 260, maxHeight: 360 } } }}>
        {templates === null && <MenuItem disabled>{t('Loading…')}</MenuItem>}
        {templates?.length === 0 && <MenuItem disabled>{t('No templates yet')}</MenuItem>}
        {templates?.map((template) => (
          <MenuItem key={template.id} onClick={() => insertTemplate(template)}>
            <ListItemText primary={template.name} secondary={template.subject || undefined} />
          </MenuItem>
        ))}
        <Divider />
        <MenuItem onClick={() => void saveAsTemplate()}>{t('Save this message as a template…')}</MenuItem>
      </Menu>
      <Menu anchorEl={signatureAnchor} open={Boolean(signatureAnchor)} onClose={() => setSignatureAnchor(null)} slotProps={{ paper: { sx: { minWidth: 220, maxHeight: 360 } } }}>
        {signatures?.signatures.map((signature) => (
          <MenuItem key={signature.id} onClick={() => { setSignatureAnchor(null); void applySignature(signature.html); markDirty(); }}>
            {signature.name}
          </MenuItem>
        ))}
        {signatures?.signatures.length === 0 && <MenuItem disabled>{t('No signatures yet')}</MenuItem>}
        <MenuItem onClick={() => { setSignatureAnchor(null); void applySignature(''); markDirty(); }}>
          <em>{t('No signature')}</em>
        </MenuItem>
        <Divider />
        <MenuItem component="a" href="/settings?tab=signatures" target="_blank" rel="noopener" onClick={() => setSignatureAnchor(null)}>
          {t('Manage signatures…')}
        </MenuItem>
      </Menu>
    </Paper>
  );
}
