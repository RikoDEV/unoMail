// The menu a right click on a conversation in the list opens, as in Gmail: the actions of the
// row (or of the whole selection, when the row is part of it), with Move to, Label as and
// Snooze opening to the side.

import ChevronRight from '@mui/icons-material/ChevronRight';
import DriveFileMove from '@mui/icons-material/DriveFileMove';
import Forward from '@mui/icons-material/Forward';
import LabelIcon from '@mui/icons-material/Label';
import MarkEmailRead from '@mui/icons-material/MarkEmailRead';
import MarkEmailUnread from '@mui/icons-material/MarkEmailUnread';
import OpenInNew from '@mui/icons-material/OpenInNew';
import Reply from '@mui/icons-material/Reply';
import ReplyAll from '@mui/icons-material/ReplyAll';
import SearchIcon from '@mui/icons-material/Search';
import Snooze from '@mui/icons-material/Snooze';
import Star from '@mui/icons-material/Star';
import StarBorder from '@mui/icons-material/StarBorder';
import { Checkbox, Divider, ListItemIcon, ListItemText, Menu, MenuItem, MenuList, Paper, Popper, Typography } from '@mui/material';
import { type ReactNode, useRef, useState } from 'react';
import { t, uiLocale } from '../i18n';
import { ActionMenuItem, type FolderAction, folderActions, type Place } from './actions';
import { type EmailSummary, folderName, type Mailbox } from './jmapClient';
import { snoozePresets } from './timePresets';

export type RowMenuPick =
  | { kind: FolderAction | 'reply' | 'replyAll' | 'forward' | 'read' | 'unread' | 'star' | 'findFrom' | 'newTab' }
  | { kind: 'move'; mailbox: Mailbox }
  | { kind: 'label'; name: string; on: boolean }
  | { kind: 'snooze'; until: Date };

export interface RowMenuTarget {
  email: EmailSummary;
  x: number;
  y: number;
  /** How many conversations the menu acts on: more than one when the row is part of the selection. */
  count: number;
}

interface Props {
  target: RowMenuTarget | null;
  /** Folders a conversation can be moved to from the one shown. */
  folders: Mailbox[];
  labels: string[];
  labelColor: (name: string) => string;
  /** Where the conversations the menu acts on are, which decides the folder actions offered. */
  place: Place;
  onPick: (pick: RowMenuPick, target: RowMenuTarget) => void;
  onClose: () => void;
}

type Side = 'move' | 'label' | 'snooze';

const WHEN = { weekday: 'short', day: 'numeric', month: 'short', hour: '2-digit', minute: '2-digit' } as const;

export function RowMenu({ target, folders, labels, labelColor, place, onPick, onClose }: Props) {
  const [side, setSide] = useState<{ kind: Side; anchor: HTMLElement } | null>(null);
  const sideList = useRef<HTMLUListElement>(null);
  const email = target?.email;
  const single = (target?.count ?? 1) <= 1;
  const unread = email ? !email.keywords.$seen : false;
  const sender = email?.from?.[0];

  const close = () => {
    setSide(null);
    onClose();
  };
  const pick = (choice: RowMenuPick) => {
    if (!target) return;
    close();
    onPick(choice, target);
  };
  const item = (label: string, icon: ReactNode, choice: RowMenuPick) => (
    <MenuItem dense onClick={() => pick(choice)} onMouseEnter={() => setSide(null)}>
      <ListItemIcon>{icon}</ListItemIcon>
      <ListItemText>{label}</ListItemText>
    </MenuItem>
  );
  // An entry that opens a list to its side: on hover, a click or the right arrow key.
  const opener = (kind: Side, label: string, icon: ReactNode) => (
    <MenuItem
      dense
      aria-haspopup="menu"
      aria-expanded={side?.kind === kind}
      selected={side?.kind === kind}
      onMouseEnter={(e) => setSide({ kind, anchor: e.currentTarget })}
      onClick={(e) => setSide({ kind, anchor: e.currentTarget })}
      onKeyDown={(e) => {
        if (e.key !== 'ArrowRight') return;
        e.preventDefault();
        e.stopPropagation();
        setSide({ kind, anchor: e.currentTarget });
        requestAnimationFrame(() => sideList.current?.querySelector<HTMLElement>('[role="menuitem"]:not([aria-disabled="true"])')?.focus());
      }}
    >
      <ListItemIcon>{icon}</ListItemIcon>
      <ListItemText>{label}</ListItemText>
      <ChevronRight fontSize="small" sx={{ ml: 2, color: 'text.secondary' }} />
    </MenuItem>
  );
  const backToParent = (e: React.KeyboardEvent) => {
    if (e.key !== 'ArrowLeft' && e.key !== 'Escape') return;
    e.preventDefault();
    e.stopPropagation();
    const anchor = side?.anchor;
    setSide(null);
    anchor?.focus();
  };

  return (
    <>
      <Menu
        open={Boolean(target)}
        onClose={close}
        anchorReference="anchorPosition"
        anchorPosition={target ? { top: target.y, left: target.x } : undefined}
        // The list to the side lives outside the menu, so the menu must let the focus go there.
        disableEnforceFocus
        // A second right click on the backdrop closes the menu instead of opening the browser's.
        slotProps={{ root: { onContextMenu: (e: React.MouseEvent) => { e.preventDefault(); close(); } }, paper: { sx: { minWidth: 240 } } }}
        aria-label={t('Actions for the conversation')}
      >
        {!single && (
          <MenuItem disabled dense sx={{ opacity: '1 !important' }}>
            <Typography variant="caption" sx={{ color: 'text.secondary' }}>{t('{{count}} selected', { count: target?.count ?? 0 })}</Typography>
          </MenuItem>
        )}
        {single && item(t('Reply'), <Reply fontSize="small" />, { kind: 'reply' })}
        {single && item(t('Reply all'), <ReplyAll fontSize="small" />, { kind: 'replyAll' })}
        {single && item(t('Forward'), <Forward fontSize="small" />, { kind: 'forward' })}
        {single && <Divider />}
        {folderActions(place).map((action) => (
          <ActionMenuItem key={action} action={action} place={place} onRun={(kind) => pick({ kind })} onMouseEnter={() => setSide(null)} />
        ))}
        {single
          ? unread
            ? item(t('Mark as read'), <MarkEmailRead fontSize="small" />, { kind: 'read' })
            : item(t('Mark as unread'), <MarkEmailUnread fontSize="small" />, { kind: 'unread' })
          : [
              <MenuItem key="read" dense onClick={() => pick({ kind: 'read' })} onMouseEnter={() => setSide(null)}><ListItemIcon><MarkEmailRead fontSize="small" /></ListItemIcon><ListItemText>{t('Mark as read')}</ListItemText></MenuItem>,
              <MenuItem key="unread" dense onClick={() => pick({ kind: 'unread' })} onMouseEnter={() => setSide(null)}><ListItemIcon><MarkEmailUnread fontSize="small" /></ListItemIcon><ListItemText>{t('Mark as unread')}</ListItemText></MenuItem>,
            ]}
        {single && item(email?.keywords.$flagged ? t('Remove star') : t('Star'), email?.keywords.$flagged ? <StarBorder fontSize="small" /> : <Star fontSize="small" />, { kind: 'star' })}
        {single && !place.trash && opener('snooze', t('Snooze'), <Snooze fontSize="small" />)}
        <Divider />
        {opener('move', t('Move to'), <DriveFileMove fontSize="small" />)}
        {opener('label', t('Label as'), <LabelIcon fontSize="small" />)}
        {single && <Divider />}
        {single && sender && item(t('Find emails from {{name}}', { name: sender.name || sender.email }), <SearchIcon fontSize="small" />, { kind: 'findFrom' })}
        {single && item(t('Open in a new tab'), <OpenInNew fontSize="small" />, { kind: 'newTab' })}
      </Menu>
      <Popper open={Boolean(target && side)} anchorEl={side?.anchor} placement="right-start" sx={{ zIndex: (theme) => theme.zIndex.modal + 1 }}>
        <Paper elevation={8} sx={{ minWidth: 200, maxHeight: 360, overflow: 'auto' }}>
          <MenuList ref={sideList} dense onKeyDown={backToParent} aria-label={side?.kind === 'move' ? t('Move to') : side?.kind === 'label' ? t('Label as') : t('Snooze until')}>
            {side?.kind === 'move' && folders.length === 0 && <MenuItem disabled>{t('No other folders')}</MenuItem>}
            {side?.kind === 'move' &&
              folders.map((m) => (
                <MenuItem key={m.id} onClick={() => pick({ kind: 'move', mailbox: m })}>
                  {folderName(m)}
                </MenuItem>
              ))}
            {side?.kind === 'label' && labels.length === 0 && <MenuItem disabled>{t('No labels yet')}</MenuItem>}
            {side?.kind === 'label' &&
              labels.map((name) => {
                // One conversation shows which labels it has; a selection can only gain one.
                const on = single && Boolean(email?.keywords[name]);
                return (
                  <MenuItem key={name} role={single ? 'menuitemcheckbox' : 'menuitem'} aria-checked={single ? on : undefined} onClick={() => pick({ kind: 'label', name, on: !on })}>
                    <ListItemIcon>
                      {single ? <Checkbox size="small" checked={on} tabIndex={-1} disableRipple sx={{ p: 0 }} /> : <LabelIcon fontSize="small" sx={{ color: labelColor(name) || undefined }} />}
                    </ListItemIcon>
                    <ListItemText>{name}</ListItemText>
                    {single && <LabelIcon fontSize="small" sx={{ ml: 1, color: labelColor(name) || 'action.disabled' }} />}
                  </MenuItem>
                );
              })}
            {side?.kind === 'snooze' &&
              snoozePresets(new Date()).map((preset) => (
                <MenuItem key={preset.label} onClick={() => pick({ kind: 'snooze', until: preset.at })}>
                  <ListItemText primary={preset.label} secondary={preset.at.toLocaleString(uiLocale(), WHEN)} />
                </MenuItem>
              ))}
          </MenuList>
        </Paper>
      </Popper>
    </>
  );
}
