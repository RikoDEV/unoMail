// The inbox categories as tabs, Gmail style: each with its unread count and, when closed, a
// glimpse of its newest mail.

import ForumOutlined from '@mui/icons-material/ForumOutlined';
import Inbox from '@mui/icons-material/Inbox';
import InfoOutlined from '@mui/icons-material/InfoOutlined';
import LocalOfferOutlined from '@mui/icons-material/LocalOfferOutlined';
import PeopleOutlined from '@mui/icons-material/PeopleOutlined';
import { Box, Chip, Stack, Tab, Tabs, Typography } from '@mui/material';
import type { ReactElement } from 'react';
import { t } from '../i18n';
import { CATEGORIES, type CategoryLatest, type CategoryName } from './extra';

const CATEGORY_ICONS: Record<CategoryName, ReactElement> = {
  general: <Inbox />,
  offers: <LocalOfferOutlined />,
  communities: <PeopleOutlined />,
  notifications: <InfoOutlined />,
  forums: <ForumOutlined />,
};

export function CategoryTabs({ category, onChange, counts, latest, dropProps, dropStyle }: {
  category: CategoryName;
  onChange: (category: CategoryName) => void;
  counts: Partial<Record<CategoryName, number>>;
  latest: Partial<Record<CategoryName, CategoryLatest>>;
  dropProps: (key: string, target: { category: CategoryName }) => object;
  dropStyle: (key: string) => object;
}) {
  return (
    <Tabs
      value={category}
      onChange={(_, value) => onChange(value)}
      variant="scrollable"
      scrollButtons="auto"
      aria-label={t('Inbox categories')}
      // Like Gmail: equal tabs with the icon and name on the left, and a rounded bar under the open one.
      sx={{ minHeight: 56, mb: 1, bgcolor: 'background.paper', borderRadius: '16px' }}
    >
      {CATEGORIES.map((entry) => (
        <Tab
          key={entry.id}
          value={entry.id}
          icon={CATEGORY_ICONS[entry.id]}
          iconPosition="start"
          sx={{
            minHeight: 56, flex: '1 0 auto', minWidth: 160, maxWidth: 'none', justifyContent: 'flex-start', gap: 1.5, px: 2,
            textTransform: 'none', fontWeight: entry.id === category ? 700 : 400, ...dropStyle(`category:${entry.id}`),
          }}
          label={
            <Box sx={{ minWidth: 0, textAlign: 'left' }}>
              <Stack direction="row" spacing={1} alignItems="center">
                <span>{entry.label}</span>
                {entry.id !== 'general' && (counts[entry.id] ?? 0) > 0 && <Chip size="small" color="primary" label={t('{{count}} new', { count: counts[entry.id] })} sx={{ height: 18, fontSize: 11, fontWeight: 700 }} aria-label={t('{{count}} unread', { count: counts[entry.id] })} />}
              </Stack>
              {/* Like Gmail, a closed category with new mail shows who wrote and about what. */}
              {entry.id !== 'general' && entry.id !== category && (counts[entry.id] ?? 0) > 0 && latest[entry.id] && (
                <Typography variant="caption" color="text.secondary" noWrap component="div" sx={{ maxWidth: 220, fontWeight: 400 }}>
                  {latest[entry.id]!.senders.join(', ')}{latest[entry.id]!.subject ? ` – ${latest[entry.id]!.subject}` : ''}
                </Typography>
              )}
            </Box>
          }
          {...(entry.id === category ? {} : dropProps(`category:${entry.id}`, { category: entry.id }))}
        />
      ))}
    </Tabs>
  );
}
