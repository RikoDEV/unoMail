import { Box, Button, Dialog, DialogActions, DialogContent, DialogTitle, Stack, Typography } from '@mui/material';
import { t } from '../i18n';

/** The keys MailPage handles, in the order they are listed. */
const SHORTCUTS: { keys: string[]; label: () => string }[] = [
  { keys: ['j'], label: () => t('Next conversation') },
  { keys: ['k'], label: () => t('Previous conversation') },
  { keys: ['Enter', 'o'], label: () => t('Open conversation') },
  { keys: ['u', 'Esc'], label: () => t('Back to the list') },
  { keys: ['x'], label: () => t('Select or deselect conversation') },
  { keys: ['e'], label: () => t('Archive') },
  { keys: ['#'], label: () => t('Delete') },
  { keys: ['s'], label: () => t('Star') },
  { keys: ['r'], label: () => t('Reply') },
  { keys: ['a'], label: () => t('Reply all') },
  { keys: ['f'], label: () => t('Forward') },
  { keys: ['c'], label: () => t('Compose') },
  { keys: ['/'], label: () => t('Search mail') },
  { keys: ['?'], label: () => t('Show keyboard shortcuts') },
];

/** Lists the keyboard shortcuts of the mail view. */
export function ShortcutsDialog({ onClose }: { onClose: () => void }) {
  return (
    <Dialog open onClose={onClose} fullWidth maxWidth="xs">
      <DialogTitle>{t('Keyboard shortcuts')}</DialogTitle>
      <DialogContent>
        <Box component="dl" sx={{ m: 0 }}>
          {SHORTCUTS.map(({ keys, label }) => (
            <Stack key={keys.join()} direction="row" sx={{ alignItems: 'center', py: 0.75, gap: 2 }}>
              <Box component="dt" sx={{ display: 'flex', gap: 0.5, minWidth: 96 }}>
                {keys.map((key) => (
                  <Box key={key} component="kbd" sx={{ px: 0.75, minWidth: 24, textAlign: 'center', fontFamily: 'monospace', fontSize: 13, lineHeight: '22px', borderRadius: 1, border: 1, borderColor: 'divider', bgcolor: 'action.hover' }}>
                    {key}
                  </Box>
                ))}
              </Box>
              <Typography component="dd" variant="body2" sx={{ m: 0 }}>{label()}</Typography>
            </Stack>
          ))}
        </Box>
      </DialogContent>
      <DialogActions>
        <Button onClick={onClose}>{t('Close')}</Button>
      </DialogActions>
    </Dialog>
  );
}
