// What plug-ins put into the layout: items and views in named slots, their own pages, and the
// gate around each built-in feature a plug-in may hide or replace. Views are sandboxed frames
// of the plug-in's own document; the chrome around them (titles, labels) is ours.

import BoltOutlined from '@mui/icons-material/BoltOutlined';
import CalendarMonthOutlined from '@mui/icons-material/CalendarMonthOutlined';
import CloudOutlined from '@mui/icons-material/CloudOutlined';
import Extension from '@mui/icons-material/Extension';
import InfoOutlined from '@mui/icons-material/InfoOutlined';
import InsertChartOutlined from '@mui/icons-material/InsertChartOutlined';
import LabelOutlined from '@mui/icons-material/LabelOutlined';
import Link from '@mui/icons-material/Link';
import StickyNote2Outlined from '@mui/icons-material/StickyNote2Outlined';
import StarOutline from '@mui/icons-material/StarBorder';
import TaskAltOutlined from '@mui/icons-material/TaskAltOutlined';
import Translate from '@mui/icons-material/Translate';
import { Box, Button, Chip, Stack, useTheme } from '@mui/material';
import { type ReactElement, type ReactNode, useEffect } from 'react';
import { Navigate, useParams } from 'react-router-dom';
import { type Feature, type Mount, type Slot, usePlugins } from '../lib/plugins';
import { TopBar } from '../ui/shell';
import { connectFrame, disconnectView } from './host';

import { chosenLanguage, isRtl, t } from '../i18n';

const ICONS: Record<string, ReactElement> = {
  extension: <Extension fontSize="small" />,
  star: <StarOutline fontSize="small" />,
  bolt: <BoltOutlined fontSize="small" />,
  translate: <Translate fontSize="small" />,
  note: <StickyNote2Outlined fontSize="small" />,
  link: <Link fontSize="small" />,
  label: <LabelOutlined fontSize="small" />,
  info: <InfoOutlined fontSize="small" />,
  chart: <InsertChartOutlined fontSize="small" />,
  calendar: <CalendarMonthOutlined fontSize="small" />,
  task: <TaskAltOutlined fontSize="small" />,
  cloud: <CloudOutlined fontSize="small" />,
};

export const itemIcon = (name?: string) => ICONS[name ?? ''] ?? ICONS.extension;

/** One of a plug-in's views: a sandboxed frame told which view to draw. */
export function PluginView({ mount, fill }: { mount: Mount; fill?: boolean }) {
  const theme = useTheme();
  const dark = theme.palette.mode === 'dark';
  useEffect(() => () => disconnectView(mount.plugin, mount.id), [mount.plugin, mount.id]);
  return (
    <Box
      component="iframe"
      title={t('{{name}} (plug-in)', { name: mount.title })}
      sandbox="allow-scripts"
      referrerPolicy="no-referrer"
      src={`/plugin-frame/${encodeURIComponent(mount.plugin)}/${encodeURIComponent(mount.commit)}?view=${encodeURIComponent(mount.id)}`}
      onLoad={(e) => connectFrame(mount.plugin, e.currentTarget as HTMLIFrameElement, { locale: chosenLanguage() ?? document.documentElement.lang, dir: isRtl() ? 'rtl' : 'ltr', dark }, mount.id)}
      sx={{ display: 'block', border: 0, width: '100%', height: fill ? '100%' : mount.height, minHeight: fill ? 320 : undefined, bgcolor: 'transparent', colorScheme: dark ? 'dark' : 'light' }}
    />
  );
}

/** The items and views plug-ins placed in a slot. Renders nothing when there are none. */
export function PluginSlot({ slot, direction = 'row' }: { slot: Slot; direction?: 'row' | 'column' }) {
  const { items, mounts } = usePlugins();
  const here = items.filter((item) => item.slot === slot);
  const views = mounts.filter((m) => m.slot === slot);
  if (here.length === 0 && views.length === 0) return null;
  return (
    <Box data-slot={slot} sx={{ display: 'flex', flexDirection: 'column', gap: 1, minWidth: 0 }}>
      {here.length > 0 && (
        <Stack direction={direction} spacing={1} useFlexGap sx={{ flexWrap: 'wrap', alignItems: direction === 'row' ? 'center' : 'stretch' }}>
          {here.map((item) =>
            item.kind === 'badge' ? (
              <Chip key={item.id} size="small" icon={itemIcon(item.icon)} label={item.label} />
            ) : item.kind === 'link' ? (
              <Button key={item.id} size="small" component="a" startIcon={itemIcon(item.icon)} href={item.href} target="_blank" rel="noopener noreferrer">{item.label}</Button>
            ) : (
              <Button key={item.id} size="small" startIcon={itemIcon(item.icon)} onClick={item.onClick}>{item.label}</Button>
            ),
          )}
        </Stack>
      )}
      {views.map((mount) => <PluginView key={`${mount.plugin}:${mount.id}`} mount={mount} />)}
    </Box>
  );
}

/**
 * A built-in feature plug-ins may hide or replace. Without plug-ins it is simply `children`;
 * hidden, it shows the replacing view if there is one, otherwise `fallback`.
 */
export function FeatureGate({ id, children, fallback = null }: { id: Feature; children: ReactNode; fallback?: ReactNode }) {
  const { hidden, mounts } = usePlugins();
  if (!hidden[id]?.length) return <>{children}</>;
  const replacement = mounts.find((m) => m.slot === `replace:${id}`);
  return replacement ? <PluginView mount={replacement} /> : <>{fallback}</>;
}

/** A full page of a plug-in (`/x/<plug-in>/<view>`), listed in the navigation. */
export function PluginPage() {
  const { plugin, view } = useParams();
  const { mounts } = usePlugins();
  const mount = mounts.find((m) => m.plugin === plugin && m.id === view && m.slot === 'app.navigation');
  // The plug-in may still be starting; its pages appear once it has registered them.
  const known = usePlugins().mounts.length > 0;
  if (!mount) return known ? <Navigate to="/mail" replace /> : null;
  return (
    <Box sx={{ height: '100vh', display: 'flex', flexDirection: 'column' }}>
      <TopBar title={mount.title} />
      <Box sx={{ flex: 1, minHeight: 0, px: { xs: 0, sm: 2 }, pb: 2 }}>
        <PluginView mount={mount} fill />
      </Box>
    </Box>
  );
}

/** Plug-in pages for the navigation. */
export function usePluginPages(slot: 'app.navigation' | 'settings.section' | 'admin.section'): Mount[] {
  return usePlugins().mounts.filter((m) => m.slot === slot);
}
