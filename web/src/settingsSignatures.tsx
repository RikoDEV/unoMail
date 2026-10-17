// Settings for signatures: named signatures written with simple formatting, which one each
// sender identity uses for new messages and for replies, and where the composer puts them.

import FormatBold from '@mui/icons-material/FormatBold';
import FormatClear from '@mui/icons-material/FormatClear';
import FormatItalic from '@mui/icons-material/FormatItalic';
import FormatUnderlined from '@mui/icons-material/FormatUnderlined';
import Image from '@mui/icons-material/Image';
import InsertLink from '@mui/icons-material/InsertLink';
import {
  Alert, Box, Button, Card, CardContent, Dialog, DialogActions, DialogContent, DialogTitle, FormControlLabel, IconButton, MenuItem, Stack, Switch, Table, TableBody, TableCell, TableHead,
  TableRow, TextField, Tooltip, Typography,
} from '@mui/material';
import { useCallback, useEffect, useRef, useState } from 'react';
import { errorText } from './api';
import { t } from './i18n';
import { chooseSignatures, deleteSignature, type Signature, type SignatureChoice, type Signatures, listSignatures, saveSignature } from './mail/extra';
import { htmlToText } from './mail/jmapClient';
import { sanitizeEmailHtml } from './mail/sanitize';
import { updatePrefs, usePrefs } from './prefs';
import { ListCard, RowActions } from './settingsWebmail';

/** Images are kept inside the signature; a logo should be small. */
const MAX_IMAGE_BYTES = 100 * 1024;

function readAsDataUrl(file: File): Promise<string> {
  return new Promise((resolve, reject) => {
    const reader = new FileReader();
    reader.onload = () => resolve(String(reader.result));
    reader.onerror = () => reject(reader.error);
    reader.readAsDataURL(file);
  });
}

/** A small rich text editor: bold, italic, underline, links and images. */
function SignatureEditor({ initial, onChange }: { initial: string; onChange: (html: string) => void }) {
  const editor = useRef<HTMLDivElement>(null);
  const imageInput = useRef<HTMLInputElement>(null);
  const [error, setError] = useState('');

  useEffect(() => {
    if (editor.current) editor.current.innerHTML = sanitizeEmailHtml(initial);
  }, [initial]);

  const changed = () => onChange(editor.current?.innerHTML ?? '');
  function format(command: string, value?: string) {
    editor.current?.focus();
    document.execCommand(command, false, value);
    changed();
  }
  function insertLink() {
    const url = window.prompt(t('Link address'), 'https://')?.trim();
    if (!url) return;
    if (!/^(https?:\/\/|mailto:)/i.test(url)) {
      setError(t('Links must start with https://, http:// or mailto:'));
      return;
    }
    setError('');
    format('createLink', url);
  }
  async function insertImage(file: File | undefined) {
    if (!file) return;
    if (file.size > MAX_IMAGE_BYTES) {
      setError(t('Images in a signature can be at most 100 KB.'));
      return;
    }
    setError('');
    format('insertImage', await readAsDataUrl(file));
  }
  function onPaste(event: React.ClipboardEvent<HTMLDivElement>) {
    event.preventDefault();
    const html = event.clipboardData.getData('text/html');
    const text = event.clipboardData.getData('text/plain');
    const div = document.createElement('div');
    div.textContent = text;
    document.execCommand('insertHTML', false, html ? sanitizeEmailHtml(html) : div.innerHTML.replace(/\n/g, '<br>'));
    changed();
  }

  return (
    <Box>
      {error && <Alert severity="error" onClose={() => setError('')} sx={{ mb: 1 }}>{error}</Alert>}
      <Box sx={{ border: 1, borderColor: 'divider', borderRadius: 1 }}>
        <Stack direction="row" sx={{ borderBottom: 1, borderColor: 'divider', px: 0.5 }}>
          <Tooltip title={t('Bold')}><IconButton size="small" aria-label={t('Bold')} onClick={() => format('bold')}><FormatBold fontSize="small" /></IconButton></Tooltip>
          <Tooltip title={t('Italic')}><IconButton size="small" aria-label={t('Italic')} onClick={() => format('italic')}><FormatItalic fontSize="small" /></IconButton></Tooltip>
          <Tooltip title={t('Underline')}><IconButton size="small" aria-label={t('Underline')} onClick={() => format('underline')}><FormatUnderlined fontSize="small" /></IconButton></Tooltip>
          <Tooltip title={t('Insert link')}><IconButton size="small" aria-label={t('Insert link')} onClick={insertLink}><InsertLink fontSize="small" /></IconButton></Tooltip>
          <Tooltip title={t('Insert image')}><IconButton size="small" aria-label={t('Insert image')} onClick={() => imageInput.current?.click()}><Image fontSize="small" /></IconButton></Tooltip>
          <Tooltip title={t('Clear formatting')}><IconButton size="small" aria-label={t('Clear formatting')} onClick={() => format('removeFormat')}><FormatClear fontSize="small" /></IconButton></Tooltip>
        </Stack>
        <Box
          ref={editor}
          contentEditable
          suppressContentEditableWarning
          role="textbox"
          aria-multiline="true"
          aria-label={t('Signature text')}
          onInput={changed}
          onPaste={onPaste}
          sx={{ minHeight: 120, maxHeight: 320, overflowY: 'auto', p: 1.5, outline: 'none', typography: 'body2', '& img': { maxWidth: '100%' }, '& p': { my: 0 } }}
        />
      </Box>
      <input ref={imageInput} type="file" accept="image/png,image/jpeg,image/gif,image/webp" hidden onChange={(e) => { void insertImage(e.target.files?.[0]); e.target.value = ''; }} />
    </Box>
  );
}

function SignatureDialog({ signature, onClose }: { signature: Signature | null; onClose: (saved: boolean) => void }) {
  const [name, setName] = useState(signature?.name ?? '');
  const [html, setHtml] = useState(signature?.html ?? '');
  const [error, setError] = useState('');

  async function save() {
    setError('');
    const clean = sanitizeEmailHtml(html);
    // Formatting with no words or pictures in it is no signature.
    const empty = !htmlToText(clean).trim() && !/<img\b/i.test(clean);
    try {
      await saveSignature(signature?.id ?? 0, { name, html: empty ? '' : clean });
      onClose(true);
    } catch (err) {
      setError(errorText(err, t('The signature could not be saved')));
    }
  }

  return (
    <Dialog open onClose={() => onClose(false)} fullWidth maxWidth="sm">
      <DialogTitle>{signature ? t('Edit signature') : t('New signature')}</DialogTitle>
      <DialogContent>
        <Stack spacing={2} sx={{ mt: 1 }}>
          {error && <Alert severity="error">{error}</Alert>}
          <TextField label={t('Signature name')} value={name} onChange={(e) => setName(e.target.value)} autoFocus required helperText={t('Only you see the name, when choosing a signature')} />
          <SignatureEditor initial={signature?.html ?? ''} onChange={setHtml} />
        </Stack>
      </DialogContent>
      <DialogActions>
        <Button onClick={() => onClose(false)}>{t('Cancel')}</Button>
        <Button variant="contained" onClick={() => void save()} disabled={!name.trim()}>
          {t('Save signature')}
        </Button>
      </DialogActions>
    </Dialog>
  );
}

/** A choice among the signatures, or none. */
function SignatureSelect({ label, value, signatures, onChange }: { label: string; value: number | null; signatures: Signature[]; onChange: (id: number | null) => void }) {
  return (
    <TextField select size="small" label={label} value={value ?? ''} onChange={(e) => onChange(e.target.value === '' ? null : Number(e.target.value))} sx={{ minWidth: 180 }} fullWidth>
      <MenuItem value="">
        <em>{t('No signature')}</em>
      </MenuItem>
      {signatures.map((signature) => (
        <MenuItem key={signature.id} value={signature.id}>
          {signature.name}
        </MenuItem>
      ))}
    </TextField>
  );
}

export function SignaturesCard() {
  const prefs = usePrefs();
  const [data, setData] = useState<Signatures | null>(null);
  const [error, setError] = useState('');
  const [editing, setEditing] = useState<Signature | null | undefined>(undefined);
  const reload = useCallback(() => listSignatures().then(setData, (err) => setError(errorText(err, t('Signatures could not be loaded')))), []);
  useEffect(() => void reload(), [reload]);

  const signatures = data?.signatures ?? [];
  const remove = (id: number) => void deleteSignature(id).then(reload).catch((err) => setError(errorText(err, t('Could not delete'))));
  async function choose(email: string, choice: SignatureChoice) {
    setData((current) => current && { ...current, defaults: { ...current.defaults, [email]: choice } });
    try {
      await chooseSignatures(email, choice);
    } catch (err) {
      setError(errorText(err, t('The choice could not be saved')));
      void reload();
    }
  }

  return (
    <Stack spacing={2}>
      <ListCard title={t('Signatures')} addLabel={t('Add signature')} onAdd={() => setEditing(null)} error={error} onDismiss={() => setError('')}>
        {signatures.length === 0 ? (
          <Typography color="text.secondary">{t('No signatures yet. Add one, then choose below which addresses use it.')}</Typography>
        ) : (
          <Table size="small" aria-label={t('Signatures')}>
            <TableBody>
              {signatures.map((signature) => (
                <TableRow key={signature.id}>
                  <TableCell sx={{ fontWeight: 500, width: '30%' }}>{signature.name}</TableCell>
                  <TableCell sx={{ color: 'text.secondary', maxWidth: 0, overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>{htmlToText(signature.html).replace(/\s+/g, ' ').trim() || '—'}</TableCell>
                  <RowActions
                    editLabel={t('Edit signature {{name}}', { name: signature.name })}
                    onEdit={() => setEditing(signature)}
                    deleteLabel={t('Delete signature {{name}}', { name: signature.name })}
                    confirm={t('Delete the signature {{name}}? Addresses using it will send without a signature.', { name: signature.name })}
                    onDelete={() => remove(signature.id)}
                  />
                </TableRow>
              ))}
            </TableBody>
          </Table>
        )}
      </ListCard>

      {data && signatures.length > 0 && (
        <Card variant="outlined">
          <CardContent>
            <Typography variant="h6">{t('Signature defaults')}</Typography>
            <Typography variant="body2" color="text.secondary" sx={{ mb: 1 }}>
              {t('The signature each of your addresses adds by itself. Another one can always be picked in the composer.')}
            </Typography>
            <Table size="small" aria-label={t('Signature defaults')}>
              <TableHead>
                <TableRow>
                  <TableCell>{t('Address')}</TableCell>
                  <TableCell>{t('New messages')}</TableCell>
                  <TableCell>{t('Replies and forwards')}</TableCell>
                </TableRow>
              </TableHead>
              <TableBody>
                {Object.entries(data.defaults).map(([email, choice]) => (
                  <TableRow key={email}>
                    <TableCell sx={{ wordBreak: 'break-all' }}>{email}</TableCell>
                    <TableCell>
                      <SignatureSelect label={t('For new messages from {{email}}', { email })} value={choice.new_signature_id} signatures={signatures} onChange={(id) => void choose(email, { ...choice, new_signature_id: id })} />
                    </TableCell>
                    <TableCell>
                      <SignatureSelect label={t('For replies from {{email}}', { email })} value={choice.reply_signature_id} signatures={signatures} onChange={(id) => void choose(email, { ...choice, reply_signature_id: id })} />
                    </TableCell>
                  </TableRow>
                ))}
              </TableBody>
            </Table>
          </CardContent>
        </Card>
      )}

      <Card variant="outlined">
        <CardContent>
          <Typography variant="h6" sx={{ mb: 1 }}>
            {t('Signature placement')}
          </Typography>
          <Stack>
            <FormControlLabel
              control={<Switch checked={prefs.signature_separator === true} onChange={(e) => void updatePrefs({ signature_separator: e.target.checked }).catch(() => {})} />}
              label={t('Put a “-- ” line above the signature, so that mail programs recognise it')}
            />
            <FormControlLabel
              control={<Switch checked={prefs.signature_below_quote === true} onChange={(e) => void updatePrefs({ signature_below_quote: e.target.checked }).catch(() => {})} />}
              label={t('In replies and forwards, put the signature below the quoted message')}
            />
          </Stack>
        </CardContent>
      </Card>

      {editing !== undefined && (
        <SignatureDialog
          signature={editing}
          onClose={(saved) => {
            setEditing(undefined);
            if (saved) void reload();
          }}
        />
      )}
    </Stack>
  );
}
