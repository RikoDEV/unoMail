// The folder list beside the messages: compose, folders, shared folders, labels and links.

import { LinearProgress } from '../ui/progress';
import Add from '@mui/icons-material/Add';
import AllInbox from '@mui/icons-material/AllInbox';
import Archive from '@mui/icons-material/Archive';
import CalendarMonth from '@mui/icons-material/CalendarMonth';
import Contacts from '@mui/icons-material/Contacts';
import Delete from '@mui/icons-material/Delete';
import Drafts from '@mui/icons-material/Drafts';
import Edit from '@mui/icons-material/Edit';
import Extension from '@mui/icons-material/Extension';
import Folder from '@mui/icons-material/Folder';
import FolderShared from '@mui/icons-material/FolderShared';
import Inbox from '@mui/icons-material/Inbox';
import LabelIcon from '@mui/icons-material/Label';
import MoreVert from '@mui/icons-material/MoreVert';
import Palette from '@mui/icons-material/Palette';
import Report from '@mui/icons-material/Report';
import ScheduleSend from '@mui/icons-material/ScheduleSend';
import SendIcon from '@mui/icons-material/Send';
import Snooze from '@mui/icons-material/Snooze';
import UnsubscribeIcon from '@mui/icons-material/Unsubscribe';
import { Badge, Box, Fab, IconButton, List, ListItemButton, ListItemIcon, ListItemText, Tooltip, Typography } from '@mui/material';
import type { ReactElement } from 'react';
import { Link as RouterLink } from 'react-router-dom';
import { formatBytes } from '../lib/api';
import type { Account } from '../lib/api';
import { t } from '../i18n';
import type { SidebarLink } from '../lib/plugins';
import { FeatureGate, itemIcon, PluginSlot, usePluginPages } from '../plugins/Slot';
import { Copyright } from '../ui/shell';
import { folderName, type Mailbox } from './jmapClient';

const ICONS: Record<string, ReactElement> = { inbox: <Inbox />, drafts: <Drafts />, sent: <SendIcon />, archive: <Archive />, junk: <Report />, trash: <Delete />, snoozed: <Snooze /> };

export interface LabelDialogState { name: string; color: string; existing: boolean }

export function MailSidebar({
  mini, compact, scheduledCount, label, mailbox, ownMailboxes, sharedMailboxes, allMail, subscriptionsPage, labels, labelColor, sidebarLinks, account,
  linkTo, dropProps, dropStyle, onCompose, onFolderMenu, onNewFolder, onLabelDialog, onRenameLabel, onDeleteLabel,
}: {
  /** Reduced to a strip of icons. */
  mini: boolean;
  /** Shown in a drawer on a small screen. */
  compact: boolean;
  scheduledCount: number;
  label: string | null;
  mailbox: Mailbox | undefined;
  ownMailboxes: Mailbox[];
  sharedMailboxes: Mailbox[];
  allMail: boolean;
  subscriptionsPage: boolean;
  labels: string[];
  labelColor: (name: string) => string;
  sidebarLinks: SidebarLink[];
  account: Account | null;
  /** Props that make an entry a router link. */
  linkTo: (to: string) => object;
  /** Props that make an entry a drop target for dragged conversations, and its highlight. */
  dropProps: (key: string, target: { mailbox?: Mailbox; label?: string }) => object;
  dropStyle: (key: string) => object;
  onCompose: () => void;
  onFolderMenu: (anchor: HTMLElement, mailbox: Mailbox) => void;
  onNewFolder: () => void;
  onLabelDialog: (state: LabelDialogState) => void;
  onRenameLabel: (name: string) => void;
  onDeleteLabel: (name: string) => void;
}) {
  /** In the icon strip an entry has no visible text: name it for screen readers and show it in a tooltip. */
  const named = (name: string) => (mini ? { 'aria-label': name } : {});
  const pages = usePluginPages('app.navigation');
  const tip = (name: string, item: ReactElement) => (mini ? <Tooltip key={item.key} title={name} placement="right">{item}</Tooltip> : item);
  return (
    <Box
      component="nav"
      className="um-part-sidebar"
      aria-label={t('Folders')}
      data-mini={mini}
      sx={{
        width: mini ? 72 : compact ? 280 : 240, flexShrink: 0, px: 1, pt: compact ? 2 : 0, overflowY: 'auto', overflowX: 'hidden', transition: 'width 150ms',
        // A column, so that the copyright line can sit at the bottom.
        display: 'flex', flexDirection: 'column', height: compact ? '100%' : undefined,
        // The strip keeps the icons of everything that can be opened and drops the rest.
        ...(mini && {
          '& .MuiListItemText-root, & .MuiTypography-overline, & .MuiListItemButton-root .MuiIconButton-root, & .mini-hide': { display: 'none' },
          '& .MuiListItemButton-root': { justifyContent: 'center', px: 0 },
          '& .MuiListItemIcon-root': { minWidth: 0 },
          '& .MuiBadge-root': { position: 'absolute', top: 10, right: 12, mr: 0 },
        }),
      }}
    >
      <Fab variant={mini ? 'circular' : 'extended'} color="primary" aria-label={t('Compose')} onClick={onCompose} sx={{ m: mini ? 0 : 1, mb: 2, flexShrink: 0, alignSelf: mini ? 'center' : 'flex-start' }}>
        <Edit />
        {!mini && t('Compose')}
      </Fab>
      <List dense disablePadding aria-label={t('Folder list')}>
        {scheduledCount > 0 && (
          tip(t('Scheduled'), <ListItemButton selected={label === '$scheduled'} {...linkTo(`/mail/label:${encodeURIComponent('$scheduled')}`)} sx={{ mb: 0.25 }} {...named(t('Scheduled'))}>
            <ListItemIcon sx={{ minWidth: 40 }}><ScheduleSend /></ListItemIcon>
            <ListItemText primary={t('Scheduled')} />
            <Badge badgeContent={scheduledCount} color="secondary" variant={mini ? 'dot' : 'standard'} sx={{ mr: 1.5 }} />
          </ListItemButton>)
        )}
        {ownMailboxes.map((m) => tip(folderName(m),
          <ListItemButton
            key={m.id}
            selected={mailbox?.id === m.id}
            {...linkTo(`/mail/${m.role ?? m.id}`)}
            sx={{ mb: 0.25, ...dropStyle(m.id) }}
            data-testid="folder"
            {...named(folderName(m))}
            {...dropProps(m.id, { mailbox: m })}
          >
            <ListItemIcon sx={{ minWidth: 40 }}>{ICONS[m.role ?? ''] ?? (m.sharedWith ? <FolderShared /> : <Folder />)}</ListItemIcon>
            <ListItemText primary={folderName(m)} slotProps={{
              primary: { sx: { fontWeight: m.unreadEmails ? 700 : 400 }, noWrap: true }
            }} />
            {m.unreadEmails > 0 && m.role !== 'drafts' ? <Badge badgeContent={m.unreadEmails} color="primary" variant={mini ? 'dot' : 'standard'} sx={{ mr: 1.5 }} /> : <FolderCount count={m.totalEmails} />}
            <IconButton size="small" aria-label={t('Folder actions {{value}}', { value: folderName(m) })} onClick={(e) => { e.preventDefault(); e.stopPropagation(); onFolderMenu(e.currentTarget, m); }}>
              <MoreVert fontSize="inherit" />
            </IconButton>
          </ListItemButton>,
        ))}
        {tip(t('All mail'), <ListItemButton
          selected={allMail}
          {...linkTo('/mail/all')}
          sx={{ mb: 0.25 }}
          data-testid="folder-all"
          {...named(t('All mail'))}
        >
          <ListItemIcon sx={{ minWidth: 40 }}><AllInbox /></ListItemIcon>
          <ListItemText primary={t('All mail')} slotProps={{
            primary: { noWrap: true }
          }} />
        </ListItemButton>)}
        {tip(t('Manage subscriptions'), <ListItemButton selected={subscriptionsPage} {...linkTo('/mail/subscriptions')} sx={{ mb: 0.25 }} {...named(t('Manage subscriptions'))}>
          <ListItemIcon sx={{ minWidth: 40 }}><UnsubscribeIcon /></ListItemIcon>
          <ListItemText primary={t('Manage subscriptions')} slotProps={{
            primary: { noWrap: true }
          }} />
        </ListItemButton>)}
        <ListItemButton className="mini-hide" onClick={onNewFolder}>
          <ListItemIcon sx={{ minWidth: 40 }}><Add /></ListItemIcon>
          <ListItemText primary={t('New folder')} />
        </ListItemButton>
      </List>
      {sharedMailboxes.length > 0 && (
        <>
          <Typography variant="overline" sx={{ color: 'text.secondary', px: 2, mt: 1, display: 'block' }}>
            {t('Shared with me')}
          </Typography>
          <List dense disablePadding aria-label={t('Shared folders')}>
            {sharedMailboxes.map((m) => tip(`${m.name.split('/').slice(2).join('/') || m.name} (${m.shareOwner ?? 'shared'})`,
              <ListItemButton
                key={m.id}
                selected={mailbox?.id === m.id}
                {...linkTo(`/mail/${m.id}`)}
                sx={{ mb: 0.25, ...dropStyle(m.id) }}
                {...named(`${m.name.split('/').slice(2).join('/') || m.name} (${m.shareOwner ?? 'shared'})`)}
                {...(m.myRights?.mayAddItems ? dropProps(m.id, { mailbox: m }) : {})}
              >
                <ListItemIcon sx={{ minWidth: 40 }}><FolderShared /></ListItemIcon>
                <ListItemText
                  primary={m.name.split('/').slice(2).join('/') || m.name}
                  secondary={m.shareOwner}
                  slotProps={{
                    primary: { sx: { fontWeight: m.unreadEmails ? 700 : 400 }, noWrap: true },
                    secondary: { noWrap: true }
                  }} />
                <FolderCount count={m.totalEmails} />
                <IconButton size="small" aria-label={t('Folder actions {{name}}', { name: m.name })} onClick={(e) => { e.preventDefault(); e.stopPropagation(); onFolderMenu(e.currentTarget, m); }}>
                  <MoreVert fontSize="inherit" />
                </IconButton>
              </ListItemButton>,
            ))}
          </List>
        </>
      )}
      <Typography variant="overline" sx={{ color: 'text.secondary', px: 2, mt: 1, mb: 0.5, display: 'block' }}>
        {t('Labels')}
      </Typography>
      <List dense disablePadding aria-label={t('Labels')}>
        {labels.map((name) => tip(t('Label {{name}}', { name }),
          <ListItemButton
            key={name}
            selected={label === name}
            {...linkTo(`/mail/label:${encodeURIComponent(name)}`)}
            sx={{ mb: 0.25, ...dropStyle(`label:${name}`) }}
            {...named(t('Label {{name}}', { name }))}
            {...dropProps(`label:${name}`, { label: name })}
          >
            <ListItemIcon sx={{ minWidth: 40 }}><LabelIcon sx={{ color: labelColor(name) || undefined }} /></ListItemIcon>
            <ListItemText primary={name} slotProps={{
              primary: { noWrap: true }
            }} />
            <IconButton size="small" aria-label={t('Colour of label {{name}}', { name })} onClick={(e) => { e.preventDefault(); e.stopPropagation(); onLabelDialog({ name, color: labelColor(name), existing: true }); }}>
              <Palette fontSize="inherit" />
            </IconButton>
            <IconButton size="small" aria-label={t('Rename label {{name}}', { name })} onClick={(e) => { e.preventDefault(); e.stopPropagation(); onRenameLabel(name); }}>
              <Edit fontSize="inherit" />
            </IconButton>
            <IconButton size="small" aria-label={t('Delete label {{name}}', { name })} onClick={(e) => { e.preventDefault(); e.stopPropagation(); onDeleteLabel(name); }}>
              <Delete fontSize="inherit" />
            </IconButton>
          </ListItemButton>,
        ))}
        <ListItemButton className="mini-hide" onClick={() => onLabelDialog({ name: '', color: '', existing: false })}>
          <ListItemIcon sx={{ minWidth: 40 }}><Add /></ListItemIcon>
          <ListItemText primary={t('New label')} />
        </ListItemButton>
      </List>
      <List dense disablePadding sx={{ mt: 1 }} aria-label={t('More')}>
        <FeatureGate id="calendar">
          {tip(t('Calendar'), <ListItemButton component={RouterLink} to="/calendar" {...named(t('Calendar'))}>
            <ListItemIcon sx={{ minWidth: 40 }}><CalendarMonth /></ListItemIcon>
            <ListItemText primary={t('Calendar')} />
          </ListItemButton>)}
        </FeatureGate>
        <FeatureGate id="contacts">
          {tip(t('Contacts'), <ListItemButton component={RouterLink} to="/contacts" {...named(t('Contacts'))}>
            <ListItemIcon sx={{ minWidth: 40 }}><Contacts /></ListItemIcon>
            <ListItemText primary={t('Contacts')} />
          </ListItemButton>)}
        </FeatureGate>
        {pages.map((page) => tip(page.title,
          <ListItemButton key={`${page.plugin}:${page.id}`} component={RouterLink} to={`/x/${encodeURIComponent(page.plugin)}/${encodeURIComponent(page.id)}`} {...named(page.title)}>
            <ListItemIcon sx={{ minWidth: 40 }}>{itemIcon('extension')}</ListItemIcon>
            <ListItemText primary={page.title} />
          </ListItemButton>,
        ))}
        {sidebarLinks.map((link) => tip(link.label,
          <ListItemButton key={link.id} component="a" href={link.href} target="_blank" rel="noopener noreferrer" {...named(link.label)}>
            <ListItemIcon sx={{ minWidth: 40 }}><Extension /></ListItemIcon>
            <ListItemText primary={link.label} />
          </ListItemButton>,
        ))}
      </List>
      {!mini && <Box sx={{ px: 1, mt: 1 }}><PluginSlot slot="mail.sidebar" direction="column" /></Box>}
      {account && (
        <Box className="mini-hide" sx={{ mt: 'auto', px: 2, pt: 3, flexShrink: 0 }}>
          <Typography variant="caption" component="div" sx={{ color: 'text.secondary' }}>
            {t('{{used}} of {{quota}}', { used: formatBytes(account.used_bytes), quota: account.quota_bytes ? formatBytes(account.quota_bytes) : t('unlimited') })}
          </Typography>
          {account.quota_bytes > 0 && (
            <LinearProgress
              variant="determinate"
              value={Math.min(100, (account.used_bytes / account.quota_bytes) * 100)}
              aria-label={t('Storage')}
              sx={{ mt: 0.5 }}
            />
          )}
        </Box>
      )}
      <Copyright placement="sidebar" className="mini-hide" sx={{ mt: account ? 0 : 'auto', px: 2, pt: account ? 1 : 3, pb: 2, flexShrink: 0 }} />
    </Box>
  );
}

/** Muted message total beside a folder name; hidden when the sidebar is collapsed. */
function FolderCount({ count }: { count: number }) {
  if (!count) return null;
  return (
    <Typography className="mini-hide" variant="caption" aria-label={t('{{count}} messages', { count })} sx={{ color: 'text.secondary', mr: 0.5, fontVariantNumeric: 'tabular-nums' }}>
      {count}
    </Typography>
  );
}
