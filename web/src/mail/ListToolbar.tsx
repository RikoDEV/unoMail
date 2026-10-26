// The bar above the message list: select, act on the selection, refresh, and the count.

import ArrowDropDown from '@mui/icons-material/ArrowDropDown';
import DriveFileMove from '@mui/icons-material/DriveFileMove';
import LabelIcon from '@mui/icons-material/Label';
import MarkEmailRead from '@mui/icons-material/MarkEmailRead';
import MarkEmailUnread from '@mui/icons-material/MarkEmailUnread';
import MoreVert from '@mui/icons-material/MoreVert';
import Star from '@mui/icons-material/Star';
import StarBorder from '@mui/icons-material/StarBorder';
import Refresh from '@mui/icons-material/Refresh';
import { Box, Checkbox, Divider, IconButton, ListItemIcon, ListItemText, Menu, MenuItem, Stack, Tooltip, Typography } from '@mui/material';
import { useState } from 'react';
import { t } from '../i18n';
import { ActionButton, type FolderAction, folderActions, type Place } from './actions';
import { type EmailSummary, folderName, type Mailbox } from './jmapClient';
import { SnoozeButton } from './SnoozeButton';

/** What can be done to a selection. `snooze` takes the time as an ISO string; `move` and `label` take the folder id and label name. */
export type BulkAction = FolderAction | 'read' | 'unread' | 'star' | 'unstar' | 'snooze' | 'move' | 'label';

export function ListToolbar({ heading, showHeading, visible, total, selected, allInFolder, place, folders, labels, labelColor, onSelect, onBulk, onRefresh }: {
  /** What the list shows, for screen readers. */
  heading: string;
  /** Shows the heading above the toolbar too (phones, where the sidebar is hidden). */
  showHeading?: boolean;
  visible: EmailSummary[];
  total: number;
  selected: Set<string>;
  allInFolder: boolean;
  /** Where the selected conversations are, which decides the folder actions offered. */
  place: Place;
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
  const [selectionMenu, setSelectionMenu] = useState<HTMLElement | null>(null);
  // As in Gmail: "Mark as read" while any of the selection is unread, else "Mark as unread"; the
  // other one is in the selection's menu.
  const anyUnread = visible.some((e) => selected.has(e.id) && !e.keywords.$seen);
  const seenAction = anyUnread
    ? { action: 'read' as const, label: t('Mark selected as read'), title: t('Mark as read'), icon: <MarkEmailRead /> }
    : { action: 'unread' as const, label: t('Mark selected as unread'), title: t('Mark as unread'), icon: <MarkEmailUnread /> };
  const otherSeen = anyUnread ? { action: 'unread' as const, title: t('Mark as unread'), icon: <MarkEmailUnread fontSize="small" /> } : { action: 'read' as const, title: t('Mark as read'), icon: <MarkEmailRead fontSize="small" /> };
  const fromSelectionMenu = (action: BulkAction) => {
    setSelectionMenu(null);
    onBulk(action);
  };
  return (
    <>
      {showHeading && heading && (
        <Typography component="h1" variant="h6" noWrap sx={{ px: 2, pt: 1.5 }}>{heading}</Typography>
      )}
      <Stack direction="row" sx={{ alignItems: 'center', pl: 0.5, pr: 2, py: 0.5, minHeight: 48 }}>
        {!(showHeading && heading) && (
          <Typography component="h1" sx={{ position: 'absolute', width: '1px', height: '1px', overflow: 'hidden', clip: 'rect(0 0 0 0)', whiteSpace: 'nowrap' }}>{heading}</Typography>
        )}
        <Checkbox
          size="small"
          slotProps={{ input: { 'aria-label': t('Select all conversations') } }}
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
          <Stack direction="row" role="toolbar" aria-label={t('Actions for the selection')} sx={{ alignItems: 'center', flex: 1, minWidth: 0 }}>
            {folderActions(place).map((action) => (
              <ActionButton key={action} action={action} place={place} variant="selection" onRun={onBulk} />
            ))}
            <Divider orientation="vertical" flexItem sx={{ mx: 0.5, my: 1 }} />
            <Tooltip title={seenAction.title}><IconButton aria-label={seenAction.label} onClick={() => onBulk(seenAction.action)}>{seenAction.icon}</IconButton></Tooltip>
            {!place.trash && <SnoozeButton label={t('Snooze selected')} onSnooze={(until) => onBulk('snooze', until.toISOString())} />}
            <Divider orientation="vertical" flexItem sx={{ mx: 0.5, my: 1 }} />
            <Tooltip title={t('Move to')}><IconButton aria-label={t('Move selected to a folder')} onClick={(e) => setBulkMenu({ anchor: e.currentTarget, kind: 'move' })}><DriveFileMove /></IconButton></Tooltip>
            <Tooltip title={t('Label')}><IconButton aria-label={t('Label selected')} onClick={(e) => setBulkMenu({ anchor: e.currentTarget, kind: 'label' })}><LabelIcon /></IconButton></Tooltip>
            <Tooltip title={t('More')}><IconButton aria-label={t('More actions for the selection')} aria-haspopup="menu" onClick={(e) => setSelectionMenu(e.currentTarget)}><MoreVert /></IconButton></Tooltip>
            <Typography variant="body2" noWrap sx={{ color: 'text.secondary', ml: 1 }}>
              {t('{{count}} selected', { count: allInFolder ? total : selected.size })}
            </Typography>
          </Stack>
        ) : (
          <>
            <Tooltip title={t('Refresh')}><IconButton aria-label={t('Refresh')} onClick={onRefresh}><Refresh fontSize="small" /></IconButton></Tooltip>
            <Tooltip title={t('More')}><IconButton aria-label={t('More')} aria-haspopup="menu" onClick={(e) => setMoreMenu(e.currentTarget)}><MoreVert fontSize="small" /></IconButton></Tooltip>
            <Box sx={{ flex: 1 }} />
            {visible.length > 0 && (
              <Typography variant="caption" sx={{ color: 'text.secondary' }}>
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
      <Menu anchorEl={selectionMenu} open={Boolean(selectionMenu)} onClose={() => setSelectionMenu(null)}>
        <MenuItem dense onClick={() => fromSelectionMenu('star')}><ListItemIcon><StarBorder fontSize="small" /></ListItemIcon><ListItemText>{t('Add star')}</ListItemText></MenuItem>
        <MenuItem dense onClick={() => fromSelectionMenu('unstar')}><ListItemIcon><Star fontSize="small" /></ListItemIcon><ListItemText>{t('Remove star')}</ListItemText></MenuItem>
        <MenuItem dense onClick={() => fromSelectionMenu(otherSeen.action)}><ListItemIcon>{otherSeen.icon}</ListItemIcon><ListItemText>{otherSeen.title}</ListItemText></MenuItem>
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
