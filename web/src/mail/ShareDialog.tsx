import Delete from '@mui/icons-material/Delete';
import { Alert, Button, Dialog, DialogActions, DialogContent, DialogTitle, IconButton, MenuItem, Stack, Table, TableBody, TableCell, TableHead, TableRow, TextField, Typography } from '@mui/material';
import { useEffect, useState } from 'react';
import { type AclEntry, getAcl, setAcl, SHARE_LEVELS, shareLevel } from './extra';
import { folderName, type Mailbox } from './jmapClient';

import { t } from '../i18n';
import { errorText } from '../api';
/** Lets the owner of a folder share it with colleagues, or with everyone in the domain. */
export function ShareDialog({ mailbox, onClose }: { mailbox: Mailbox; onClose: (changed: boolean) => void }) {
  const [entries, setEntries] = useState<AclEntry[]>([]);
  const [identifier, setIdentifier] = useState('');
  const [level, setLevel] = useState<string>('read');
  const [error, setError] = useState('');
  const [changed, setChanged] = useState(false);

  useEffect(() => {
    getAcl(mailbox.id)
      .then(setEntries)
      .catch((err) => setError(errorText(err, t('Could not load the sharing settings'))));
  }, [mailbox.id]);

  async function apply(who: string, rights: string) {
    setError('');
    try {
      setEntries(await setAcl(mailbox.id, who, rights));
      setChanged(true);
      return true;
    } catch (err) {
      setError(errorText(err, t('Could not change the sharing settings')));
      return false;
    }
  }

  async function add() {
    const who = identifier.trim();
    if (!who) return;
    const rights = SHARE_LEVELS.find((candidate) => candidate.id === level)?.rights ?? 'lrs';
    if (await apply(who, rights)) setIdentifier('');
  }

  const name = folderName(mailbox);
  return (
    <Dialog open onClose={() => onClose(changed)} fullWidth maxWidth="sm">
      <DialogTitle>{t('Share “{{name}}”', { name })}</DialogTitle>
      <DialogContent>
        <Stack spacing={2} sx={{ mt: 1 }}>
          {error && <Alert severity="error" onClose={() => setError('')}>{error}</Alert>}
          <Typography variant="body2" color="text.secondary">
            {t("People you share with see this folder under “Shared with me”, in the web client and in any IMAP mail program. Enter a colleague's address, or “anyone” for everybody in your domain.")}
          </Typography>
          <Stack direction="row" spacing={1} alignItems="flex-start">
            <TextField label={t('Share with')} value={identifier} onChange={(e) => setIdentifier(e.target.value)} onKeyDown={(e) => e.key === 'Enter' && void add()} placeholder="colleague@example.org" fullWidth />
            <TextField select label={t('Access')} value={level} onChange={(e) => setLevel(e.target.value)} sx={{ minWidth: 220 }}>
              {SHARE_LEVELS.map((option) => (
                <MenuItem key={option.id} value={option.id}>
                  {option.label}
                </MenuItem>
              ))}
            </TextField>
            <Button variant="contained" onClick={() => void add()} disabled={!identifier.trim()}>
              {t('Share')}
            </Button>
          </Stack>
          {entries.length > 0 ? (
            <Table size="small" aria-label={t('Shared with')}>
              <TableHead>
                <TableRow>
                  <TableCell>{t('Shared with')}</TableCell>
                  <TableCell>{t('Access')}</TableCell>
                  <TableCell />
                </TableRow>
              </TableHead>
              <TableBody>
                {entries.map((entry) => (
                  <TableRow key={entry.identifier}>
                    <TableCell>{entry.identifier === 'anyone' ? t('Everyone in the domain') : entry.identifier}</TableCell>
                    <TableCell>
                      <TextField
                        select
                        variant="standard"
                        value={shareLevel(entry.rights)}
                        onChange={(e) => void apply(entry.identifier, SHARE_LEVELS.find((candidate) => candidate.id === e.target.value)?.rights ?? 'lrs')}
                        inputProps={{ 'aria-label': t('Access for {{identifier}}', { identifier: entry.identifier }) }}
                      >
                        {SHARE_LEVELS.map((option) => (
                          <MenuItem key={option.id} value={option.id}>
                            {option.label}
                          </MenuItem>
                        ))}
                      </TextField>
                    </TableCell>
                    <TableCell align="right">
                      <IconButton size="small" aria-label={t('Stop sharing with {{identifier}}', { identifier: entry.identifier })} onClick={() => void apply(entry.identifier, '')}>
                        <Delete fontSize="small" />
                      </IconButton>
                    </TableCell>
                  </TableRow>
                ))}
              </TableBody>
            </Table>
          ) : (
            <Typography color="text.secondary">{t('This folder is not shared with anyone.')}</Typography>
          )}
        </Stack>
      </DialogContent>
      <DialogActions>
        <Button onClick={() => onClose(changed)}>{t('Done')}</Button>
      </DialogActions>
    </Dialog>
  );
}
