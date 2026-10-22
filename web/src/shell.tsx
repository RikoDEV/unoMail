import AdminPanelSettings from '@mui/icons-material/AdminPanelSettings';
import MenuIcon from '@mui/icons-material/Menu';
import PersonAdd from '@mui/icons-material/PersonAdd';
import CalendarMonth from '@mui/icons-material/CalendarMonth';
import DarkMode from '@mui/icons-material/DarkMode';
import LightMode from '@mui/icons-material/LightMode';
import LanguageIcon from '@mui/icons-material/Language';
import Check from '@mui/icons-material/Check';
import Logout from '@mui/icons-material/Logout';
import Mail from '@mui/icons-material/Mail';
import Settings from '@mui/icons-material/Settings';
import SettingsBrightness from '@mui/icons-material/SettingsBrightness';
import { Avatar, Link, type SxProps, type Theme, Badge, Box, Divider, IconButton, List, ListItemButton, ListItemIcon, ListItemText, Menu, MenuItem, Paper, Stack, SwipeableDrawer, ToggleButton, ToggleButtonGroup, Tooltip, Typography, useMediaQuery } from '@mui/material';
import { useEffect, useState, type ReactElement, type ReactNode } from 'react';
import { Link as RouterLink } from 'react-router-dom';
import { useAppearance, useAuth } from './app';
import { pendingCount } from './mail/outbox';

import { chosenLanguage, LANGUAGES, setLanguage, t } from './i18n';
import { updatePrefs } from './prefs';
import { SWIPE } from './swipe';
/** Account menu shown in the top-right corner of every page. */
/** A round picture for an account: its first letter, in a colour of its own. */
function AccountAvatar({ email, size }: { email: string; size: number }) {
  // A stable hue per address, so accounts are told apart at a glance.
  const hue = [...email].reduce((sum, c) => (sum * 31 + c.charCodeAt(0)) % 360, 7);
  return <Avatar sx={{ width: size, height: size, fontSize: size * 0.45, bgcolor: `hsl(${hue} 45% 45%)`, color: '#fff' }}>{email[0].toUpperCase()}</Avatar>;
}

function AccountMenu() {
  const { account, accounts, refreshAccounts, switchAccount, logout } = useAuth();
  const { mode, setMode } = useAppearance();
  const [anchor, setAnchor] = useState<HTMLElement | null>(null);
  if (!account) return null;
  // The pages are links, so a middle click or Ctrl+click opens them in a new tab.
  const close = () => setAnchor(null);
  const others = accounts.filter((entry) => !entry.active);
  const otherUnread = others.reduce((sum, entry) => sum + entry.unread, 0);
  // Leaving an account loses its unsent offline changes; say so first.
  const confirmLeave = () => {
    const waiting = pendingCount();
    return waiting === 0 || window.confirm(t('{{count}} changes made offline have not been synchronised yet and will be lost. Sign out anyway?', { count: waiting }));
  };
  return (
    <>
      <Tooltip title={account.email}>
        <IconButton
          aria-label={t('Account menu')}
          onClick={(e) => {
            setAnchor(e.currentTarget);
            void refreshAccounts();
          }}
        >
          {/* A dot when another signed-in account has unread mail. */}
          <Badge color="error" variant="dot" invisible={otherUnread === 0} overlap="circular">
            <AccountAvatar email={account.email} size={36} />
          </Badge>
        </IconButton>
      </Tooltip>
      <Menu anchorEl={anchor} open={Boolean(anchor)} onClose={() => setAnchor(null)} slotProps={{ paper: { sx: { minWidth: 280 } } }}>
        <Stack direction="row" spacing={1.5} alignItems="center" sx={{ px: 2, py: 1 }}>
          <AccountAvatar email={account.email} size={40} />
          <Box sx={{ minWidth: 0 }}>
            <Typography fontWeight={600} noWrap>{account.display_name || account.email}</Typography>
            <Typography variant="body2" color="text.secondary" noWrap>
              {account.email}
            </Typography>
          </Box>
        </Stack>
        <Divider />
        {/* The other accounts signed in on this browser, one click away. */}
        {others.map((entry) => (
          <MenuItem
            key={entry.account.id}
            aria-label={t('Switch to {{email}}', { email: entry.account.email })}
            onClick={() => {
              setAnchor(null);
              void switchAccount(entry.account.id);
            }}
          >
            <ListItemIcon><AccountAvatar email={entry.account.email} size={28} /></ListItemIcon>
            <ListItemText primary={entry.account.display_name || entry.account.email} secondary={entry.account.display_name ? entry.account.email : undefined} />
            {entry.unread > 0 && <Typography variant="caption" color="text.secondary" sx={{ ml: 2 }} aria-label={t('{{count}} unread', { count: entry.unread })}>{entry.unread}</Typography>}
          </MenuItem>
        ))}
        {accounts.length < 5 && (
          <MenuItem component={RouterLink} to="/login?add=1" onClick={close}>
            <ListItemIcon><PersonAdd fontSize="small" /></ListItemIcon>
            {t('Add another account')}
          </MenuItem>
        )}
        <Divider />
        <MenuItem component={RouterLink} to="/mail" onClick={close}>
          <ListItemIcon><Mail fontSize="small" /></ListItemIcon>
          {t('Mail')}
        </MenuItem>
        <MenuItem component={RouterLink} to="/calendar" onClick={close}>
          <ListItemIcon><CalendarMonth fontSize="small" /></ListItemIcon>
          {t('Calendar')}
        </MenuItem>
        {account.role !== 'user' && (
          <MenuItem component={RouterLink} to="/admin" onClick={close}>
            <ListItemIcon><AdminPanelSettings fontSize="small" /></ListItemIcon>
            {t('Administration')}
          </MenuItem>
        )}
        <MenuItem component={RouterLink} to="/settings" onClick={close}>
          <ListItemIcon><Settings fontSize="small" /></ListItemIcon>
          {t('Settings')}
        </MenuItem>
        <Divider />
        {/* Appearance: laid out like the rest of the menu. The accent colour is in the settings. */}
        <Box sx={{ px: 2, pt: 0.5, pb: 1.5 }}>
          <Typography variant="overline" color="text.secondary" sx={{ display: 'block', lineHeight: 2.5 }}>
            {t('Appearance')}
          </Typography>
          <ToggleButtonGroup
            fullWidth
            size="small"
            exclusive
            value={mode}
            onChange={(_, value) => value && setMode(value)}
            aria-label={t('Colour mode')}
          >
            <ToggleButton value="light"><LightMode sx={{ fontSize: 18 }} />{t('Light')}</ToggleButton>
            <ToggleButton value="system"><SettingsBrightness sx={{ fontSize: 18 }} />{t('System')}</ToggleButton>
            <ToggleButton value="dark"><DarkMode sx={{ fontSize: 18 }} />{t('Dark')}</ToggleButton>
          </ToggleButtonGroup>
        </Box>
        <Divider />
        <MenuItem
          onClick={() => {
            setAnchor(null);
            // Signing out wipes this account's data on this device, including unsent changes.
            if (confirmLeave()) void logout();
          }}
        >
          <ListItemIcon><Logout fontSize="small" /></ListItemIcon>
          {others.length > 0 ? t('Sign out of {{email}}', { email: account.email }) : t('Sign out')}
        </MenuItem>
        {others.length > 0 && (
          <MenuItem
            onClick={() => {
              setAnchor(null);
              if (confirmLeave()) void logout(true);
            }}
          >
            <ListItemIcon><Logout fontSize="small" /></ListItemIcon>
            {t('Sign out of all accounts')}
          </MenuItem>
        )}
      </Menu>
    </>
  );
}

/** Sets the browser tab title: the given parts, most specific first, then "unoMail". */
export function useTitle(...parts: (string | null | undefined | false)[]) {
  const title = [...parts.filter(Boolean), 'unoMail'].join(' · ');
  useEffect(() => {
    document.title = title;
  }, [title]);
}

/** The copyright line under the sign-in form and at the foot of the side navigation. */
export function Copyright({ placement, sx, className }: { placement: 'login' | 'sidebar' | 'settings' | 'admin'; sx?: SxProps<Theme>; className?: string }) {
  // The link sends no referrer, so the campaign tags say where the visit came from.
  const href = `https://riko.dev/?utm_source=unomail&utm_medium=referral&utm_campaign=copyright&utm_content=${placement}`;
  return (
    <Typography variant="caption" color="text.secondary" component="p" className={className} sx={[{ opacity: 0.8 }, ...(Array.isArray(sx) ? sx : [sx])]}>
      © {new Date().getFullYear()} unoMail by{' '}
      <Link href={href} target="_blank" rel="nofollow noreferrer noopener" color="inherit" underline="hover">
        riko.dev
      </Link>
    </Typography>
  );
}

/** The interface language, stored with the account so it follows the user between devices. */
function LanguageMenu() {
  const [anchor, setAnchor] = useState<HTMLElement | null>(null);
  const chosen = chosenLanguage() ?? '';
  async function choose(code: string) {
    setAnchor(null);
    await updatePrefs({ language: code }).catch(() => {});
    setLanguage(code || null);
  }
  const options = [{ code: '', name: t('Automatic (browser language)') }, ...LANGUAGES];
  return (
    <>
      <Tooltip title={t('Interface language')}>
        <IconButton aria-label={t('Interface language')} aria-haspopup="menu" aria-expanded={Boolean(anchor)} onClick={(e) => setAnchor(e.currentTarget)}>
          <LanguageIcon />
        </IconButton>
      </Tooltip>
      <Menu anchorEl={anchor} open={Boolean(anchor)} onClose={() => setAnchor(null)}>
        {options.map((option) => (
          <MenuItem key={option.code} selected={option.code === chosen} lang={option.code || undefined} onClick={() => void choose(option.code)}>
            <ListItemIcon>{option.code === chosen && <Check fontSize="small" />}</ListItemIcon>
            <ListItemText>{option.name}</ListItemText>
          </MenuItem>
        ))}
      </Menu>
    </>
  );
}

/**
 * The unoMail mark: an envelope whose flap folds into a soft "u", with a single dot for "uno".
 * Drawn in the theme's colours so it follows the chosen seed and the dark mode.
 */
export function Logo({ size = 32, sx }: { size?: number; sx?: SxProps<Theme> }) {
  return (
    <Box component="svg" viewBox="0 0 64 64" aria-hidden width={size} height={size} sx={{ flexShrink: 0, display: 'block', ...sx }}>
      <Box component="rect" width={64} height={64} rx={18} sx={{ fill: (theme) => theme.palette.primary.main }} />
      <Box component="g" sx={{ fill: 'none', stroke: (theme) => theme.palette.primary.contrastText, strokeWidth: 4.5, strokeLinecap: 'round', strokeLinejoin: 'round' }}>
        <rect x={12} y={18} width={40} height={28} rx={7} />
        <path d="M14 22 26.5 33.5a8 8 0 0 0 11 0L50 22" />
      </Box>
      <Box component="circle" cx={49} cy={17} r={7} strokeWidth={3} sx={{ fill: (theme) => theme.palette.secondary.light, stroke: (theme) => theme.palette.primary.main }} />
    </Box>
  );
}

export function TopBar({ title, children, leading, onHome }: { title: string; children?: ReactNode; leading?: ReactNode; onHome?: () => void }) {
  return (
    <Stack component="header" direction="row" alignItems="center" spacing={{ xs: 1, sm: 2 }} sx={{ px: { xs: 1, sm: 2 }, height: 64, flexShrink: 0 }}>
      {leading}
      {/* The name in the header leads home, to the inbox, from every page. */}
      <Typography
        variant="h6"
        component={RouterLink}
        to="/mail"
        onClick={onHome}
        title={t('Go to the inbox')}
        color="primary"
        fontWeight={600}
        noWrap
        sx={{ display: { xs: children ? 'none' : 'flex', sm: 'flex' }, alignItems: 'center', gap: 1.25, minWidth: { sm: 150 }, flexShrink: children ? 0 : 1, textDecoration: 'none', borderRadius: 1, '&:focus-visible': { outline: '2px solid', outlineColor: 'primary.main', outlineOffset: 2 } }}
      >
        <Logo size={32} />
        <Box component="span" sx={{ overflow: 'hidden', textOverflow: 'ellipsis' }}>{title}</Box>
      </Typography>
      <Box sx={{ flex: 1, minWidth: 0 }}>{children}</Box>
      <LanguageMenu />
      <AccountMenu />
    </Stack>
  );
}

export interface SideNavItem {
  key: string;
  label: string;
  icon: ReactElement;
  selected?: boolean;
  /** A link (the item is then a router link, marked active by the router) or a click handler. */
  to?: string;
  onClick?: () => void;
}

/**
 * A page with the top bar, a list of sections on the left (a drawer on small screens) and
 * the open section on a pane beside it. Used by the settings and the administration.
 */
export function SideNavPage({ title, navLabel, heading, placement, items, linkComponent, children }: {
  title: string;
  navLabel: string;
  heading?: string;
  placement: 'settings' | 'admin';
  items: SideNavItem[];
  /** The router's link component for items with `to` (NavLink marks the active one). */
  linkComponent?: React.ElementType;
  children: ReactNode;
}) {
  const compact = useMediaQuery((theme: Theme) => theme.breakpoints.down('md'));
  const [drawerOpen, setDrawerOpen] = useState(false);
  const nav = (
    <Box component="nav" aria-label={navLabel} sx={{ width: compact ? 260 : 220, flexShrink: 0, px: 1, overflow: 'auto', display: 'flex', flexDirection: 'column', height: compact ? '100%' : undefined }}>
      {heading && (
        <Typography variant="h6" component="h1" sx={{ px: 2, pt: compact ? 1 : 0, pb: 1 }}>
          {heading}
        </Typography>
      )}
      <List dense disablePadding={Boolean(heading)} onClick={() => setDrawerOpen(false)}>
        {items.map((item) => (
          <ListItemButton
            key={item.key}
            selected={item.selected}
            aria-current={item.selected ? 'page' : undefined}
            onClick={item.onClick}
            {...(item.to ? { component: linkComponent ?? RouterLink, to: item.to } : {})}
            sx={{ mb: 0.25 }}
          >
            <ListItemIcon sx={{ minWidth: 40 }}>{item.icon}</ListItemIcon>
            <ListItemText primary={item.label} />
          </ListItemButton>
        ))}
      </List>
      <Copyright placement={placement} sx={{ mt: 'auto', px: 2, pt: 3, pb: 2, flexShrink: 0 }} />
    </Box>
  );
  return (
    <Box sx={{ height: '100vh', display: 'flex', flexDirection: 'column', bgcolor: 'background.default' }}>
      <TopBar
        title={title}
        leading={compact && <Tooltip title={t('Menu')}><IconButton aria-label={navLabel} aria-expanded={drawerOpen} onClick={() => setDrawerOpen((open) => !open)}><MenuIcon /></IconButton></Tooltip>}
      />
      <Box sx={{ flex: 1, display: 'flex', minHeight: 0 }}>
        {compact ? (
          <SwipeableDrawer open={drawerOpen} onOpen={() => setDrawerOpen(true)} onClose={() => setDrawerOpen(false)} {...SWIPE} slotProps={{ paper: { sx: { bgcolor: 'background.default', pt: 1 } } }}>
            {nav}
          </SwipeableDrawer>
        ) : (
          nav
        )}
        <Paper elevation={0} component="main" sx={{ flex: 1, minWidth: 0, overflow: 'auto', borderRadius: 1.5, mx: { xs: 1, md: 0 }, mr: { md: 1 }, mb: 1, p: { xs: 2, sm: 3 } }}>
          {children}
        </Paper>
      </Box>
    </Box>
  );
}
