// One conversation in the message list. Memoised: a row renders again only when its own
// email, selection or highlight changes, not on every change of the page around it.

import Archive from '@mui/icons-material/Archive';
import AttachFile from '@mui/icons-material/AttachFile';
import Delete from '@mui/icons-material/Delete';
import MarkEmailRead from '@mui/icons-material/MarkEmailRead';
import MarkEmailUnread from '@mui/icons-material/MarkEmailUnread';
import Star from '@mui/icons-material/Star';
import StarBorder from '@mui/icons-material/StarBorder';
import { Box, Checkbox, Chip, IconButton, ListItemButton, Stack, Tooltip, Typography } from '@mui/material';
import { memo } from 'react';
import { t, uiLocale } from '../i18n';
import { readableOn } from './extra';
import { type EmailSummary, labelsOf } from './jmapClient';
import { ListAttachments, ListAvatar, listedAttachments } from './ListParts';
import type { PreviewFile } from './Preview';

export type RowAction = 'archive' | 'trash' | 'read' | 'unread' | 'star';

/** What a row can ask of the page. The object stays the same across renders. */
export interface RowHandlers {
  open: (email: EmailSummary, index: number) => void;
  toggleSelected: (id: string) => void;
  act: (email: EmailSummary, action: RowAction) => void;
  dragStart: (email: EmailSummary, event: React.DragEvent) => void;
  dragEnd: () => void;
  preview: (file: PreviewFile) => void;
  /** A right click (or a long press) on the row. */
  contextMenu: (email: EmailSummary, event: React.MouseEvent) => void;
}

export interface EmailRowProps {
  email: EmailSummary;
  index: number;
  accountId: string;
  density: 'condensed' | 'expanded';
  /** Beside an open conversation the list is narrow. */
  narrow: boolean;
  /** Sent and Drafts show whom a message went to rather than who sent it. */
  showRecipients: boolean;
  chosen: boolean;
  highlighted: boolean;
  /** Colours of the labels in use (an unchanged object keeps rows from rendering again). */
  labelColors: Record<string, string>;
  canArchive: boolean;
  inTrash: boolean;
  handlers: RowHandlers;
}

export function listDate(iso: string): string {
  const date = new Date(iso);
  const today = new Date();
  return date.toDateString() === today.toDateString()
    ? date.toLocaleTimeString(uiLocale(), { hour: '2-digit', minute: '2-digit' })
    : date.toLocaleDateString(uiLocale(), { month: 'short', day: 'numeric', year: date.getFullYear() === today.getFullYear() ? undefined : 'numeric' });
}

// Styles are constants: the style engine then finds them in its cache instead of resolving
// new objects for every row on every render.
const QUICK_ACTIONS_SX = { display: 'none', position: 'absolute', right: 4, bgcolor: 'background.paper', borderRadius: 4, boxShadow: 1 } as const;
const QUICK_CONDENSED_SX = { ...QUICK_ACTIONS_SX, top: '50%', transform: 'translateY(-50%)' } as const;
const QUICK_EXPANDED_SX = { ...QUICK_ACTIONS_SX, top: 2 } as const;
const ROW_SX = {
  borderRadius: 0,
  borderBottom: 1,
  borderColor: 'divider',
  gap: 0.5,
  pl: 0.5,
  // Only where a pointer can hover: on touch screens the actions would stick after a tap.
  '@media (hover: hover)': {
    '&:hover .row-actions, &:focus-within .row-actions': { display: 'flex' },
    '&:hover .row-date, &:focus-within .row-date': { visibility: 'hidden' },
  },
} as const;
const ROW_CONDENSED_SX = { ...ROW_SX, alignItems: 'center', py: 0.25 } as const;
const ROW_EXPANDED_SX = { ...ROW_SX, alignItems: 'flex-start', py: 1 } as const;
const ROW_UNREAD_CONDENSED_SX = { ...ROW_CONDENSED_SX, bgcolor: 'action.hover' } as const;
const ROW_UNREAD_EXPANDED_SX = { ...ROW_EXPANDED_SX, bgcolor: 'action.hover' } as const;
const CHECKBOX_SX = { p: 0.5 } as const;
const ATTACH_ICON_SX = { fontSize: 16, color: 'text.secondary', flexShrink: 0 } as const;
const PRIMARY_SX = { color: 'text.primary' } as const;
const SECONDARY_SX = { color: 'text.secondary' } as const;

function EmailRowView({ email, index, accountId, density, narrow, showRecipients, chosen, highlighted, labelColors, canArchive, inTrash, handlers }: EmailRowProps) {
  const unread = !email.keywords.$seen;
  const expanded = density === 'expanded';
  const people = showRecipients ? (email.to ?? []) : (email.from ?? []);
  const names = people.map((a) => a.name || a.email).join(', ') || '(unknown)';
  const weight = unread ? 700 : 400;
  const subject = email.subject || t('(no subject)');
  const chips = labelsOf(email).map((name) => {
    const color = labelColors[name] ?? '';
    return <Chip key={name} size="small" label={name} variant={color ? 'filled' : 'outlined'} sx={{ height: 20, flexShrink: 0, ...(color ? { bgcolor: color, color: readableOn(color) } : {}) }} />;
  });
  const controls = (
    <>
      <Checkbox
        size="small"
        checked={chosen}
        inputProps={{ 'aria-label': t('Select {{subject}}', { subject }) }}
        onClick={(e) => e.stopPropagation()}
        onChange={() => handlers.toggleSelected(email.id)}
        sx={CHECKBOX_SX}
      />
      <IconButton size="small" aria-label={email.keywords.$flagged ? t('Remove star') : t('Add star')} onClick={(e) => { e.stopPropagation(); handlers.act(email, 'star'); }}>
        {email.keywords.$flagged ? <Star fontSize="small" color="warning" /> : <StarBorder fontSize="small" />}
      </IconButton>
    </>
  );
  // Shown over the date while the pointer is on the row (or a control in it has the focus).
  const quick = (
    <Stack className="row-actions" direction="row" role="group" aria-label={t('Quick actions for {{subject}}', { subject })} onClick={(e) => e.stopPropagation()} sx={expanded ? QUICK_EXPANDED_SX : QUICK_CONDENSED_SX}>
      {canArchive && (
        <Tooltip title={t('Archive')}><IconButton size="small" aria-label={t('Archive')} onClick={() => handlers.act(email, 'archive')}><Archive fontSize="small" /></IconButton></Tooltip>
      )}
      <Tooltip title={inTrash ? t('Delete forever') : t('Delete')}>
        <IconButton size="small" aria-label={t('Delete')} onClick={() => handlers.act(email, 'trash')}><Delete fontSize="small" /></IconButton>
      </Tooltip>
      <Tooltip title={unread ? t('Mark as read') : t('Mark as unread')}>
        <IconButton size="small" aria-label={unread ? t('Mark as read') : t('Mark as unread')} onClick={() => handlers.act(email, unread ? 'read' : 'unread')}>
          {unread ? <MarkEmailRead fontSize="small" /> : <MarkEmailUnread fontSize="small" />}
        </IconButton>
      </Tooltip>
    </Stack>
  );
  const subjectAndPreview = (
    <>
      <Box component="span" sx={{ fontWeight: weight, ...PRIMARY_SX }}>{subject}</Box>
      <Box component="span" sx={SECONDARY_SX}>{email.preview ? ` – ${email.preview}` : ''}</Box>
    </>
  );
  return (
    <ListItemButton
      selected={chosen || highlighted}
      onClick={() => handlers.open(email, index)}
      onContextMenu={(event) => handlers.contextMenu(email, event)}
      draggable
      onDragStart={(event) => handlers.dragStart(email, event)}
      onDragEnd={handlers.dragEnd}
      sx={unread ? (expanded ? ROW_UNREAD_EXPANDED_SX : ROW_UNREAD_CONDENSED_SX) : expanded ? ROW_EXPANDED_SX : ROW_CONDENSED_SX}
      data-testid="email-row"
      data-unread={unread}
      data-density={density}
    >
      {expanded ? (
        // Expanded: picture, then sender and date, subject and text, and the files.
        <>
          <Stack direction="row" alignItems="center" sx={{ mt: -0.25 }}>{controls}</Stack>
          <Box sx={{ pt: 0.25 }}><ListAvatar accountId={accountId} email={email} people={people} size={36} /></Box>
          <Box sx={{ flex: 1, minWidth: 0, ml: 1 }}>
            <Stack direction="row" spacing={1} alignItems="baseline">
              <Typography noWrap sx={{ flex: 1, fontWeight: weight }}>{names}</Typography>
              {email.hasAttachment && listedAttachments(email).length === 0 && <AttachFile className="row-date" sx={ATTACH_ICON_SX} />}
              <Typography className="row-date" variant="caption" color={unread ? 'primary' : 'text.secondary'} sx={{ whiteSpace: 'nowrap', fontWeight: weight }}>
                {listDate(email.receivedAt)}
              </Typography>
            </Stack>
            {narrow ? (
              <>
                <Typography noWrap variant="body2" sx={{ fontWeight: weight }}>{subject}</Typography>
                <Typography noWrap variant="body2" color="text.secondary">{email.preview}</Typography>
              </>
            ) : (
              <Typography noWrap variant="body2">{subjectAndPreview}</Typography>
            )}
            {chips.length > 0 && <Stack direction="row" gap={0.5} sx={{ mt: 0.5 }} flexWrap="wrap">{chips}</Stack>}
            <ListAttachments accountId={accountId} email={email} onPreview={handlers.preview} />
          </Box>
        </>
      ) : (
        // Condensed: one line per conversation, like a table, wherever the list is.
        <>
          {controls}
          <ListAvatar accountId={accountId} email={email} people={people} size={24} />
          <Typography noWrap sx={{ width: narrow ? 96 : { xs: 110, sm: 180 }, flexShrink: 0, fontWeight: weight, ml: 0.75 }}>{names}</Typography>
          <Stack direction="row" alignItems="center" gap={0.75} sx={{ flex: 1, minWidth: 0 }}>
            {!narrow && chips}
            <Typography noWrap variant="body2" sx={{ minWidth: 0 }}>{subjectAndPreview}</Typography>
          </Stack>
          {email.hasAttachment && <AttachFile className="row-date" sx={ATTACH_ICON_SX} />}
          <Typography className="row-date" variant="caption" color={unread ? 'primary' : 'text.secondary'} sx={{ whiteSpace: 'nowrap', fontWeight: weight, width: narrow ? 'auto' : 64, textAlign: 'right', flexShrink: 0 }}>
            {listDate(email.receivedAt)}
          </Typography>
        </>
      )}
      {quick}
    </ListItemButton>
  );
}

export const EmailRow = memo(EmailRowView);
