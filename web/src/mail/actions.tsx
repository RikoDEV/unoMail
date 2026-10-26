// The actions that move a conversation between the special folders (archive, junk, trash, back
// to the inbox), described once for every place that offers them: the reader's toolbar, a row's
// quick actions, the row menu and the selection toolbar. Which of them apply depends on where the
// conversation actually is, not on the folder being looked at, so search results and All mail
// offer the right one too.

import Archive from '@mui/icons-material/Archive';
import Delete from '@mui/icons-material/Delete';
import Report from '@mui/icons-material/Report';
import ReportOff from '@mui/icons-material/ReportOff';
import Unarchive from '@mui/icons-material/Unarchive';
import type { SvgIconComponent } from '@mui/icons-material';
import { IconButton, ListItemIcon, ListItemText, MenuItem, Tooltip } from '@mui/material';
import { t } from '../i18n';
import type { Mailbox } from './jmapClient';

export type FolderAction = 'archive' | 'unarchive' | 'junk' | 'notSpam' | 'trash';

/** Ids of the special folders, by role. */
export interface Roles {
  inbox?: string;
  archive?: string;
  junk?: string;
  trash?: string;
}

export function rolesOf(mailboxes: Mailbox[]): Roles {
  const id = (role: string) => mailboxes.find((m) => m.role === role)?.id;
  return { inbox: id('inbox'), archive: id('archive'), junk: id('junk'), trash: id('trash') };
}

/** Where one or more conversations are: in a special folder only when all of them are. */
export interface Place {
  archive: boolean;
  junk: boolean;
  trash: boolean;
  /** The account has an archive folder at all. */
  canArchive: boolean;
}

export function placeOf(roles: Roles, conversations: { mailboxIds: Record<string, boolean> }[]): Place {
  const all = (id: string | undefined) => Boolean(id) && conversations.length > 0 && conversations.every((c) => c.mailboxIds[id!]);
  return { archive: all(roles.archive), junk: all(roles.junk), trash: all(roles.trash), canArchive: Boolean(roles.archive) };
}

/** The folder actions offered for conversations in a place, in toolbar order. */
export function folderActions(place: Place): FolderAction[] {
  const actions: FolderAction[] = [];
  if (place.archive) actions.push('unarchive');
  else if (place.canArchive) actions.push('archive');
  actions.push(place.junk ? 'notSpam' : 'junk', 'trash');
  return actions;
}

/** Where messages are sent: a folder, or nowhere (deleted for good). */
export type Destination = { mailboxId: string } | 'destroy';

/** Message ids by the folder they were in, so that a move can be undone. */
export type Origins = Record<string, string[]>;

export function originsOf(messages: { id: string; mailboxIds: Record<string, boolean> }[]): Origins {
  const origins: Origins = {};
  for (const message of messages) {
    const from = Object.keys(message.mailboxIds)[0];
    if (from) (origins[from] ??= []).push(message.id);
  }
  return origins;
}

/** Where an action sends the messages, or null when the account lacks that folder. */
export function destinationOf(action: FolderAction, place: Place, roles: Roles): Destination | null {
  if (action === 'trash' && place.trash) return 'destroy';
  const role = action === 'unarchive' || action === 'notSpam' ? 'inbox' : action;
  const mailboxId = roles[role];
  return mailboxId ? { mailboxId } : null;
}

interface Description {
  icon: SvgIconComponent;
  /** The name of the button or menu item. */
  label: string;
  /** The name of the selection toolbar's button. */
  selectionLabel: string;
  /** The reader's tooltip, with the keyboard shortcut where there is one. */
  hint: string;
}

export function describe(action: FolderAction, place: Place): Description {
  switch (action) {
    case 'archive':
      return { icon: Archive, label: t('Archive'), selectionLabel: t('Archive selected'), hint: t('Archive (e)') };
    case 'unarchive':
      return { icon: Unarchive, label: t('Move to inbox'), selectionLabel: t('Move selected to inbox'), hint: t('Move to inbox (e)') };
    case 'junk':
      return { icon: Report, label: t('Report spam'), selectionLabel: t('Report selected as spam'), hint: t('Report spam') };
    case 'notSpam':
      return { icon: ReportOff, label: t('Not spam'), selectionLabel: t('Mark selected as not spam'), hint: t('Not spam: move to the inbox') };
    case 'trash': {
      const label = place.trash ? t('Delete forever') : t('Delete');
      return { icon: Delete, label, selectionLabel: t('Delete selected'), hint: place.trash ? label : t('Delete (#)') };
    }
  }
}

/** What the notice says once the action is done. */
export function doneText(action: FolderAction, count: number): string {
  switch (action) {
    case 'archive':
      return t('{{count}} conversations archived', { count });
    case 'unarchive':
      return t('{{count}} conversations moved to the inbox', { count });
    case 'junk':
      return t('{{count}} conversations reported as spam', { count });
    case 'notSpam':
      return t('{{count}} conversations marked as not spam', { count });
    case 'trash':
      return t('{{count}} conversations deleted', { count });
  }
}

/**
 * A folder action as an icon button. `variant` picks the name: "selection" for the selection
 * toolbar, "hint" for the reader (whose tooltip names the shortcut).
 */
export function ActionButton({ action, place, onRun, size, variant = 'plain' }: { action: FolderAction; place: Place; onRun: (action: FolderAction) => void; size?: 'small'; variant?: 'plain' | 'selection' | 'hint' }) {
  const info = describe(action, place);
  const Icon = info.icon;
  return (
    <Tooltip title={variant === 'hint' ? info.hint : info.label}>
      <IconButton size={size} aria-label={variant === 'selection' ? info.selectionLabel : info.label} onClick={() => onRun(action)}>
        <Icon fontSize={size} />
      </IconButton>
    </Tooltip>
  );
}

/** A folder action as a menu item. */
export function ActionMenuItem({ action, place, onRun, onMouseEnter }: { action: FolderAction; place: Place; onRun: (action: FolderAction) => void; onMouseEnter?: () => void }) {
  const info = describe(action, place);
  const Icon = info.icon;
  return (
    <MenuItem dense onClick={() => onRun(action)} onMouseEnter={onMouseEnter}>
      <ListItemIcon><Icon fontSize="small" /></ListItemIcon>
      <ListItemText>{info.label}</ListItemText>
    </MenuItem>
  );
}
