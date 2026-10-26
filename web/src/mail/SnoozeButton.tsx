// The Snooze button: a menu of preset times, and a dialog to pick any other.

import Snooze from '@mui/icons-material/Snooze';
import { Dialog, DialogContent, DialogTitle, IconButton, ListItemText, Menu, MenuItem, TextField, Tooltip, Typography } from '@mui/material';
import { useState } from 'react';
import { DialogButtons } from '../admin/common';
import { t, uiLocale } from '../i18n';
import { snoozePresets } from './timePresets';

const WHEN = { weekday: 'short', day: 'numeric', month: 'short', hour: '2-digit', minute: '2-digit' } as const;

export function SnoozeButton({ onSnooze, label = t('Snooze') }: { onSnooze: (until: Date) => void; label?: string }) {
  const [anchor, setAnchor] = useState<HTMLElement | null>(null);
  const [at, setAt] = useState<string | null>(null);
  return (
    <>
      <Tooltip title={t('Snooze')}>
        <IconButton aria-label={label} aria-haspopup="menu" onClick={(e) => setAnchor(e.currentTarget)}><Snooze /></IconButton>
      </Tooltip>
      <Menu anchorEl={anchor} open={Boolean(anchor)} onClose={() => setAnchor(null)}>
        <MenuItem disabled sx={{ opacity: '1 !important' }}><Typography variant="caption" sx={{ color: 'text.secondary' }}>{t('Snooze until')}</Typography></MenuItem>
        {snoozePresets(new Date()).map((preset) => (
          <MenuItem key={preset.label} onClick={() => { setAnchor(null); onSnooze(preset.at); }}>
            <ListItemText primary={preset.label} secondary={preset.at.toLocaleString(uiLocale(), WHEN)} />
          </MenuItem>
        ))}
        <MenuItem onClick={() => { setAnchor(null); setAt(''); }}>{t('Pick a date and time…')}</MenuItem>
      </Menu>
      <Dialog open={at !== null} onClose={() => setAt(null)}>
        <DialogTitle>{t('Snooze until')}</DialogTitle>
        <DialogContent>
          <TextField type="datetime-local" label={t('Bring back at')} value={at ?? ''} onChange={(e) => setAt(e.target.value)} sx={{ mt: 1 }} slotProps={{ inputLabel: { shrink: true } }} />
        </DialogContent>
        <DialogButtons onCancel={() => setAt(null)} onConfirm={() => { const until = new Date(at ?? ''); setAt(null); onSnooze(until); }} disabled={!at || new Date(at).getTime() <= Date.now()} label={t('Snooze')} />
      </Dialog>
    </>
  );
}
