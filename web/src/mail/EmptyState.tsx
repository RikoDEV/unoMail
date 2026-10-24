import DeleteOutline from '@mui/icons-material/DeleteOutlineOutlined';
import Drafts from '@mui/icons-material/DraftsOutlined';
import FolderOpen from '@mui/icons-material/FolderOpenOutlined';
import GppGood from '@mui/icons-material/GppGoodOutlined';
import Inbox from '@mui/icons-material/InboxOutlined';
import LabelIcon from '@mui/icons-material/LabelOutlined';
import MarkEmailRead from '@mui/icons-material/MarkEmailReadOutlined';
import SearchOff from '@mui/icons-material/SearchOff';
import Send from '@mui/icons-material/SendOutlined';
import type { SvgIconComponent } from '@mui/icons-material';
import { Box, Typography } from '@mui/material';
import { t } from '../i18n';

export type EmptyKind = 'search' | 'inbox' | 'category' | 'label' | 'trash' | 'junk' | 'sent' | 'drafts' | 'folder' | 'other';

const CONTENT: Record<EmptyKind, { Icon: SvgIconComponent; title: () => string; hint: () => string }> = {
  search: { Icon: SearchOff, title: () => t('No messages match your search.'), hint: () => t('Try other words, or check the search filters.') },
  inbox: { Icon: MarkEmailRead, title: () => t('You’re all caught up'), hint: () => t('New mail will show up here.') },
  trash: { Icon: DeleteOutline, title: () => t('Trash is empty'), hint: () => t('Deleted messages wait here before they are removed for good.') },
  junk: { Icon: GppGood, title: () => t('No spam here'), hint: () => t('Mail that looks like spam is kept out of your inbox and lands here.') },
  sent: { Icon: Send, title: () => t('Nothing sent yet'), hint: () => t('Messages you send will show up here.') },
  drafts: { Icon: Drafts, title: () => t('No drafts'), hint: () => t('Messages you start writing are saved here until you send them.') },
  category: { Icon: Inbox, title: () => t('No messages in this tab'), hint: () => t('Mail sorted into this tab will show up here.') },
  label: { Icon: LabelIcon, title: () => t('No messages with this label'), hint: () => t('Messages you give this label will show up here.') },
  other: { Icon: Inbox, title: () => t('Nothing here yet.'), hint: () => '' },
  folder: { Icon: FolderOpen, title: () => t('This folder is empty'), hint: () => t('Move messages here to keep them together.') },
};

/** An empty mail list: a small illustration in the theme's colours, with a line on what belongs here. */
export function EmptyState({ kind }: { kind: EmptyKind }) {
  const { Icon, title, hint } = CONTENT[kind];
  return (
    <Box sx={{ py: 6, px: 3, display: 'flex', flexDirection: 'column', alignItems: 'center', textAlign: 'center' }}>
      <Box sx={{ position: 'relative', width: 160, height: 128, mb: 2 }} aria-hidden>
        <Box component="svg" viewBox="0 0 160 128" sx={{ position: 'absolute', inset: 0, width: 1, height: 1 }}>
          {/* A soft, slightly irregular blob behind the icon, with a few sparkles around it. */}
          <Box component="path" d="M82 10c26 0 52 14 56 40s-8 54-38 64-62 4-76-18S10 46 28 28 56 10 82 10z" sx={{ fill: (theme) => theme.palette.m3.primaryContainer }} />
          <Box component="circle" cx="22" cy="96" r="6" sx={{ fill: (theme) => theme.palette.m3.tertiaryContainer }} />
          <Box component="circle" cx="146" cy="26" r="4" sx={{ fill: (theme) => theme.palette.m3.tertiaryContainer }} />
          <Box component="path" d="M136 92l3 7 7 3-7 3-3 7-3-7-7-3 7-3z" sx={{ fill: (theme) => theme.palette.primary.main, opacity: 0.6 }} />
          <Box component="path" d="M30 18l2 5 5 2-5 2-2 5-2-5-5-2 5-2z" sx={{ fill: (theme) => theme.palette.primary.main, opacity: 0.45 }} />
        </Box>
        <Icon sx={{ position: 'absolute', left: '50%', top: '50%', transform: 'translate(-50%, -50%)', fontSize: 56, color: 'm3.onPrimaryContainer' }} />
      </Box>
      <Typography variant="subtitle1" sx={{ fontWeight: 500 }}>{title()}</Typography>
      {hint() && <Typography variant="body2" sx={{ color: 'text.secondary', mt: 0.5, maxWidth: 360 }}>{hint()}</Typography>}
    </Box>
  );
}
