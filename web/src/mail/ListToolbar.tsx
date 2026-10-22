// The bar above the message list: select, act on the selection, refresh, and the count.

import Archive from '@mui/icons-material/Archive';
import ArrowDropDown from '@mui/icons-material/ArrowDropDown';
import Delete from '@mui/icons-material/Delete';
import DriveFileMove from '@mui/icons-material/DriveFileMove';
import LabelIcon from '@mui/icons-material/Label';
import MarkEmailRead from '@mui/icons-material/MarkEmailRead';
import MarkEmailUnread from '@mui/icons-material/MarkEmailUnread';
import MoreVert from '@mui/icons-material/MoreVert';
import Refresh from '@mui/icons-material/Refresh';
import Report from '@mui/icons-material/Report';
import ReportOff from '@mui/icons-material/ReportOff';
import { Box, Checkbox, IconButton, ListItemIcon, Menu, MenuItem, Stack, Tooltip, Typography } from '@mui/material';
import { useState } from 'react';
import { t } from '../i18n';
import { type EmailSummary, folderName, type Mailbox } from './jmapClient';

export type BulkAction = 'archive' | 'trash' | 'junk' | 'inbox' | 'read' | 'unread' | 'move' | 'label';

export function ListToolbar({ heading, visible, total, selected, allInFolder, inJunk, folders, labels, labelColor, onSelect, onBulk, onRefresh }: {
  /** What the list shows, for screen readers. */
  heading: string;
  visible: EmailSummary[];
  total: number;
  selected: Set<string>;
  allInFolder: boolean;
  inJunk: boolean;
  /** Where the selection can be moved. */
  folders: Mailbox[];
  labels: string[];
  labelColor: (name: string) => string;
  onSelect: (ids: Set<string>) => void;
  onBulk: (action: BulkAction, argument?: string, all?: boolean) => void;
  onRefresh: () => void;
}) {
  const [bulkMenu, setBulkMenu] = useState<{ anchor: HTMLElement; kind: 'move' | 'label' } | null>(null);
  const [selectMenu, setSelectMenu] = useState<HTMLElement | null>(null);
  const [moreMenu, setMoreMenu] = useState<HTMLElement | null>(null);
  return (
    <>
      <Stack direction="row" alignItems="center" sx={{ pl: 0.5, pr: 2, py: 0.5, minHeight: 48 }}>
        <Typography component="h1" sx={{ position: 'absolute', width: 1, height: 1, overflow: 'hidden', clip: 'rect(0 0 0 0)', whiteSpace: 'nowrap' }}>{heading}</Typography>
        <Checkbox
          size="small"
          inputProps={{ 'aria-label': t('Select all conversations') }}
          checked={visible.length > 0 && visible.every((e) => selected.has(e.id))}
          indeterminate={selected.size > 0 && !visible.every((e) => selected.has(e.id))}
          disabled={visible.length === 0}
          onChange={(e) => onSelect(e.target.checked ? new Set(visible.map((email) => email.id)) : new Set())}
          sx={{ mr: -1 }}
        />
        <IconButton size="small" aria-label={t('Select')} aria-haspopup="menu" disabled={visible.length === 0} onClick={(e) => setSelectMenu(e.currentTarget)} sx={{ width: 20, borderRadius: 1 }}>
          <ArrowDropDown fontSize="small" />
        </IconButton>
        {selected.size > 0 ? (
          <Stack direction="row" alignItems="center" sx={{ flex: 1, minWidth: 0 }} role="toolbar" aria-label={t('Actions for the selection')}>
            <Tooltip title={t('Archive')}><IconButton aria-label={t('Archive selected')} onClick={() => onBulk('archive')}><Archive /></IconButton></Tooltip>
            {inJunk ? (
              <Tooltip title={t('Not spam')}><IconButton aria-label={t('Mark selected as not spam')} onClick={() => onBulk('inbox')}><ReportOff /></IconButton></Tooltip>
            ) : (
              <Tooltip title={t('Report spam')}><IconButton aria-label={t('Report selected as spam')} onClick={() => onBulk('junk')}><Report /></IconButton></Tooltip>
            )}
            <Tooltip title={t('Delete')}><IconButton aria-label={t('Delete selected')} onClick={() => onBulk('trash')}><Delete /></IconButton></Tooltip>
            <Tooltip title={t('Mark as read')}><IconButton aria-label={t('Mark selected as read')} onClick={() => onBulk('read')}><MarkEmailRead /></IconButton></Tooltip>
            <Tooltip title={t('Mark as unread')}><IconButton aria-label={t('Mark selected as unread')} onClick={() => onBulk('unread')}><MarkEmailUnread /></IconButton></Tooltip>
            <Tooltip title={t('Move to')}><IconButton aria-label={t('Move selected to a folder')} onClick={(e) => setBulkMenu({ anchor: e.currentTarget, kind: 'move' })}><DriveFileMove /></IconButton></Tooltip>
            <Tooltip title={t('Label')}><IconButton aria-label={t('Label selected')} onClick={(e) => setBulkMenu({ anchor: e.currentTarget, kind: 'label' })}><LabelIcon /></IconButton></Tooltip>
            <Typography variant="body2" color="text.secondary" sx={{ ml: 1 }} noWrap>
              {t('{{count}} selected', { count: allInFolder ? total : selected.size })}
            </Typography>
          </Stack>
        ) : (
          <>
            <Tooltip title={t('Refresh')}><IconButton aria-label={t('Refresh')} onClick={onRefresh}><Refresh fontSize="small" /></IconButton></Tooltip>
            <Tooltip title={t('More')}><IconButton aria-label={t('More')} aria-haspopup="menu" onClick={(e) => setMoreMenu(e.currentTarget)}><MoreVert fontSize="small" /></IconButton></Tooltip>
            <Box sx={{ flex: 1 }} />
            {visible.length > 0 && (
              <Typography variant="caption" color="text.secondary">
                {t('{{from}}–{{to}} of {{total}}', { from: 1, to: visible.length, total: total.toLocaleString() })}
              </Typography>
            )}
          </>
        )}
      </Stack>
      <Menu anchorEl={selectMenu} open={Boolean(selectMenu)} onClose={() => setSelectMenu(null)}>
        {([
          [t('All'), () => true],
          [t('None'), () => false],
          [t('Read'), (e: EmailSummary) => Boolean(e.keywords.$seen)],
          [t('Unread'), (e: EmailSummary) => !e.keywords.$seen],
          [t('Starred'), (e: EmailSummary) => Boolean(e.keywords.$flagged)],
          [t('Unstarred'), (e: EmailSummary) => !e.keywords.$flagged],
        ] as const).map(([name, pick]) => (
          <MenuItem key={name} dense onClick={() => { onSelect(new Set(visible.filter(pick).map((e) => e.id))); setSelectMenu(null); }}>{name}</MenuItem>
        ))}
      </Menu>
      <Menu anchorEl={moreMenu} open={Boolean(moreMenu)} onClose={() => setMoreMenu(null)}>
        <MenuItem dense disabled={visible.length === 0} onClick={() => { setMoreMenu(null); onBulk('read', undefined, true); }}>{t('Mark all as read')}</MenuItem>
      </Menu>
      <Menu anchorEl={bulkMenu?.anchor} open={Boolean(bulkMenu)} onClose={() => setBulkMenu(null)} slotProps={{ paper: { sx: { maxHeight: 360, minWidth: 200 } } }}>
        {bulkMenu?.kind === 'move' &&
          folders.map((m) => (
              <MenuItem key={m.id} dense onClick={() => { setBulkMenu(null); onBulk('move', m.id); }}>
                {folderName(m)}
              </MenuItem>
            ))}
        {bulkMenu?.kind === 'label' && labels.length === 0 && <MenuItem disabled>{t('No labels yet')}</MenuItem>}
        {bulkMenu?.kind === 'label' &&
          labels.map((name) => (
            <MenuItem key={name} dense onClick={() => { setBulkMenu(null); onBulk('label', name); }}>
              <ListItemIcon><LabelIcon fontSize="small" sx={{ color: labelColor(name) || undefined }} /></ListItemIcon>
              {name}
            </MenuItem>
          ))}
      </Menu>
    </>
  );
}
