// The composer's formatting toolbar and its Send button with the scheduling menu.

import ArrowDropDown from '@mui/icons-material/ArrowDropDown';
import FormatBold from '@mui/icons-material/FormatBold';
import FormatClear from '@mui/icons-material/FormatClear';
import FormatIndentDecrease from '@mui/icons-material/FormatIndentDecrease';
import FormatIndentIncrease from '@mui/icons-material/FormatIndentIncrease';
import FormatItalic from '@mui/icons-material/FormatItalic';
import FormatListBulleted from '@mui/icons-material/FormatListBulleted';
import FormatListNumbered from '@mui/icons-material/FormatListNumbered';
import FormatSize from '@mui/icons-material/FormatSize';
import FormatUnderlined from '@mui/icons-material/FormatUnderlined';
import Redo from '@mui/icons-material/Redo';
import Undo from '@mui/icons-material/Undo';
import {
  Box, Button, ButtonGroup, Checkbox, Dialog, DialogContent, DialogTitle, Divider, IconButton, ListItemIcon, ListItemText, Menu, MenuItem, Select, Stack, TextField, Tooltip, Typography,
} from '@mui/material';
import { type ReactNode, useState } from 'react';
import { DialogButtons } from '../admin/common';
import { useFeature } from '../lib/plugins';
import { t, uiLocale } from '../i18n';
import { schedulePresets } from './timePresets';

const toolDivider = <Divider orientation="vertical" flexItem sx={{ mx: 0.5, my: 1 }} />;
const tool = (label: string, icon: ReactNode, onClick: () => void) => (
  <Tooltip title={label}><IconButton size="small" aria-label={label} onClick={onClick}>{icon}</IconButton></Tooltip>
);

/** Rich text commands for the message body. */
export function FormattingToolbar({ onFormat, tint }: { onFormat: (command: string, value?: string) => void; tint: string }) {
  return (
    <Stack direction="row" role="toolbar" aria-label={t('Formatting options')} sx={{ alignItems: 'center', flexWrap: 'wrap', mx: 1.5, mb: 0.5, px: 1, py: 0.25, borderRadius: 999, bgcolor: tint }}>
      {tool(t('Undo'), <Undo fontSize="small" />, () => onFormat('undo'))}
      {tool(t('Redo'), <Redo fontSize="small" />, () => onFormat('redo'))}
      {toolDivider}
      <Select
        size="small"
        variant="standard"
        disableUnderline
        value=""
        displayEmpty
        renderValue={() => <FormatSize fontSize="small" sx={{ display: 'block' }} />}
        onChange={(e) => onFormat('fontSize', String(e.target.value))}
        inputProps={{ 'aria-label': t('Font size') }}
        sx={{ mx: 0.5 }}
      >
        <MenuItem value="2">{t('Small')}</MenuItem>
        <MenuItem value="3">{t('Normal')}</MenuItem>
        <MenuItem value="5">{t('Large')}</MenuItem>
        <MenuItem value="6">{t('Huge')}</MenuItem>
      </Select>
      {toolDivider}
      {tool(t('Bold'), <FormatBold fontSize="small" />, () => onFormat('bold'))}
      {tool(t('Italic'), <FormatItalic fontSize="small" />, () => onFormat('italic'))}
      {tool(t('Underline'), <FormatUnderlined fontSize="small" />, () => onFormat('underline'))}
      <Tooltip title={t('Text colour')}>
        <Box component="input" type="color" aria-label={t('Text colour')} defaultValue="#1d1b20" onChange={(e: React.ChangeEvent<HTMLInputElement>) => onFormat('foreColor', e.target.value)} sx={{ width: 26, height: 26, mx: 0.5, p: 0, border: 0, bgcolor: 'transparent', cursor: 'pointer' }} />
      </Tooltip>
      {toolDivider}
      {tool(t('Numbered list'), <FormatListNumbered fontSize="small" />, () => onFormat('insertOrderedList'))}
      {tool(t('Bulleted list'), <FormatListBulleted fontSize="small" />, () => onFormat('insertUnorderedList'))}
      {tool(t('Indent less'), <FormatIndentDecrease fontSize="small" />, () => onFormat('outdent'))}
      {tool(t('Indent more'), <FormatIndentIncrease fontSize="small" />, () => onFormat('indent'))}
      {toolDivider}
      {tool(t('Clear formatting'), <FormatClear fontSize="small" />, () => onFormat('removeFormat'))}
    </Stack>
  );
}

/** Send now, or later: a split button whose menu schedules the message and sets its options. */
export function SendButton({ busy, onSend, receipt, onToggleReceipt, smime, onToggleSmime }: {
  busy: boolean;
  onSend: (at?: Date) => void;
  receipt: boolean;
  onToggleReceipt: () => void;
  /** The S/MIME choices, when the user has a certificate. */
  smime: { sign: boolean; encrypt: boolean } | null;
  onToggleSmime: (key: 'sign' | 'encrypt') => void;
}) {
  const [sendMenu, setSendMenu] = useState<HTMLElement | null>(null);
  const [scheduling, setScheduling] = useState<string | null>(null);
  const showSchedule = useFeature('composer.schedule');
  return (
    <>
      <ButtonGroup variant="contained" disabled={busy} disableElevation sx={{ mr: 1, '& .MuiButtonGroup-firstButton': { px: 2.5 }, '& .MuiButtonGroup-lastButton': { px: 1 } }}>
        <Button onClick={() => onSend()} sx={{ fontWeight: 600 }}>
          {t('Send')}
        </Button>
        <Button aria-label={t('More options')} aria-haspopup="menu" aria-expanded={Boolean(sendMenu)} onClick={(e) => setSendMenu(e.currentTarget)}>
          <ArrowDropDown />
        </Button>
      </ButtonGroup>
      <Menu anchorEl={sendMenu} open={Boolean(sendMenu)} onClose={() => setSendMenu(null)}>
        {showSchedule && (
          <MenuItem disabled sx={{ opacity: '1 !important' }}>
            <Typography variant="caption" sx={{ color: 'text.secondary' }}>{t('Schedule send')}</Typography>
          </MenuItem>
        )}
        {showSchedule && schedulePresets(new Date()).map((preset) => (
          <MenuItem key={preset.label} onClick={() => { setSendMenu(null); onSend(preset.at); }}>
            <ListItemText primary={preset.label} secondary={preset.at.toLocaleString(uiLocale(), { weekday: 'short', hour: '2-digit', minute: '2-digit', day: 'numeric', month: 'short' })} />
          </MenuItem>
        ))}
        {showSchedule && <MenuItem onClick={() => { setSendMenu(null); setScheduling(''); }}>{t('Pick a date and time…')}</MenuItem>}
        <Divider />
        <MenuItem onClick={onToggleReceipt}>
          <ListItemIcon><Checkbox edge="start" size="small" checked={receipt} tabIndex={-1} disableRipple /></ListItemIcon>
          <ListItemText primary={t('Request a read receipt')} />
        </MenuItem>
        {smime && (
          <MenuItem onClick={() => onToggleSmime('sign')}>
            <ListItemIcon><Checkbox edge="start" size="small" checked={smime.sign} tabIndex={-1} disableRipple /></ListItemIcon>
            <ListItemText primary={t('Sign with S/MIME')} />
          </MenuItem>
        )}
        {smime && (
          <MenuItem onClick={() => onToggleSmime('encrypt')}>
            <ListItemIcon><Checkbox edge="start" size="small" checked={smime.encrypt} tabIndex={-1} disableRipple /></ListItemIcon>
            <ListItemText primary={t('Encrypt with S/MIME')} secondary={t('Needs a certificate for every recipient')} />
          </MenuItem>
        )}
      </Menu>
      <Dialog open={scheduling !== null} onClose={() => setScheduling(null)}>
        <DialogTitle>{t('Schedule send')}</DialogTitle>
        <DialogContent>
          <TextField
            type="datetime-local"
            label={t('Send at')}
            value={scheduling ?? ''}
            onChange={(e) => setScheduling(e.target.value)}
            sx={{ mt: 1 }}
            slotProps={{ inputLabel: { shrink: true } }}
          />
        </DialogContent>
        <DialogButtons
          onCancel={() => setScheduling(null)}
          disabled={!scheduling || new Date(scheduling).getTime() <= Date.now()}
          label={t('Schedule')}
          onConfirm={() => {
            const at = new Date(scheduling ?? '');
            setScheduling(null);
            onSend(at);
          }}
        />
      </Dialog>
    </>
  );
}
