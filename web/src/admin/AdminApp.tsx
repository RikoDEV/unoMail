import Groups from '@mui/icons-material/Groups';
import Backup from '@mui/icons-material/Backup';
import AlternateEmail from '@mui/icons-material/AlternateEmail';
import Block from '@mui/icons-material/Block';
import FilterAlt from '@mui/icons-material/FilterAlt';
import Api from '@mui/icons-material/Api';
import HealthAndSafety from '@mui/icons-material/HealthAndSafety';
import Policy from '@mui/icons-material/Policy';
import Lock from '@mui/icons-material/Lock';
import Tune from '@mui/icons-material/Tune';
import Dashboard from '@mui/icons-material/Dashboard';
import MenuIcon from '@mui/icons-material/Menu';
import Dns from '@mui/icons-material/Dns';
import Hub from '@mui/icons-material/Hub';
import ListAlt from '@mui/icons-material/ListAlt';
import People from '@mui/icons-material/People';
import Schedule from '@mui/icons-material/Schedule';
import Security from '@mui/icons-material/Security';
import { Box, Drawer, IconButton, List, ListItemButton, ListItemIcon, ListItemText, Paper, Tooltip, useMediaQuery, useTheme } from '@mui/material';
import { type ReactElement, useEffect, useState } from 'react';
import { Navigate, NavLink, Route, Routes, useLocation } from 'react-router-dom';
import { useAuth } from '../app';
import { TopBar } from '../shell';
import { Aliases } from './Aliases';
import { Certificates } from './Certificates';
import { DashboardPage } from './Dashboard';
import { DomainDetail, Domains } from './Domains';
import { ApiDocs, Diagnostics, Dmarc } from './Insights';
import { Integrations } from './Integrations';
import { Logs, Queue } from './QueueLogs';
import { ServerSettings } from './ServerSettings';
import { SmtpAccess } from './SmtpAccess';
import { SpamFilter } from './SpamFilter';
import { TlsReports } from './TlsReports';
import { Backups } from './Backups';
import { Lists } from './Lists';
import { Mailboxes } from './Mailboxes';

import { t } from '../i18n';
interface NavItem {
  path: string;
  label: string;
  icon: ReactElement;
  superOnly?: boolean;
}

const NAV: NavItem[] = [
  { path: 'dashboard', label: t('Dashboard'), icon: <Dashboard />, superOnly: true },
  { path: 'domains', label: t('Domains'), icon: <Dns /> },
  { path: 'mailboxes', label: t('Mailboxes'), icon: <People /> },
  { path: 'aliases', label: t('Aliases'), icon: <AlternateEmail /> },
  { path: 'lists', label: t('Mailing lists'), icon: <Groups /> },
  { path: 'certificates', label: t('Certificates'), icon: <Security />, superOnly: true },
  { path: 'queue', label: t('Queue'), icon: <Schedule />, superOnly: true },
  { path: 'smtp-access', label: t('SMTP blacklist'), icon: <Block />, superOnly: true },
  { path: 'spam-filter', label: t('Spam filter'), icon: <FilterAlt />, superOnly: true },
  { path: 'dmarc', label: t('DMARC reports'), icon: <Policy /> },
  { path: 'tls-reports', label: t('TLS reports'), icon: <Lock /> },
  { path: 'diagnostics', label: t('Diagnostics'), icon: <HealthAndSafety />, superOnly: true },
  { path: 'backups', label: t('Backups'), icon: <Backup />, superOnly: true },
  { path: 'logs', label: t('Logs'), icon: <ListAlt /> },
  { path: 'settings', label: t('Server settings'), icon: <Tune />, superOnly: true },
  { path: 'integrations', label: t('Integrations'), icon: <Hub />, superOnly: true },
  { path: 'api', label: t('API reference'), icon: <Api /> },
];

export default function AdminApp() {
  const { account } = useAuth();
  const isSuper = account?.role === 'super_admin';
  const items = NAV.filter((item) => isSuper || !item.superOnly);
  const theme = useTheme();
  const compact = useMediaQuery(theme.breakpoints.down('md'));
  const [drawerOpen, setDrawerOpen] = useState(false);
  const location = useLocation();
  useEffect(() => setDrawerOpen(false), [location.pathname, compact]);
  const nav = (
        <Box component="nav" aria-label={t('Administration')} sx={{ width: compact ? 260 : 220, flexShrink: 0, px: 1, overflow: 'auto' }}>
          <List dense>
            {items.map((item) => (
              <ListItemButton key={item.path} component={NavLink} to={`/admin/${item.path}`} sx={{ mb: 0.25, '&.active': { bgcolor: 'action.selected', fontWeight: 600 } }}>
                <ListItemIcon sx={{ minWidth: 40 }}>{item.icon}</ListItemIcon>
                <ListItemText primary={item.label} />
              </ListItemButton>
            ))}
          </List>
        </Box>
  );
  return (
    <Box sx={{ height: '100vh', display: 'flex', flexDirection: 'column', bgcolor: 'background.default' }}>
      <TopBar
        title={t('unoMail Admin')}
        leading={compact && <Tooltip title={t('Menu')}><IconButton aria-label={t('Administration menu')} aria-expanded={drawerOpen} onClick={() => setDrawerOpen((open) => !open)}><MenuIcon /></IconButton></Tooltip>}
      />
      <Box sx={{ flex: 1, display: 'flex', minHeight: 0 }}>
        {compact ? (
          <Drawer open={drawerOpen} onClose={() => setDrawerOpen(false)} slotProps={{ paper: { sx: { bgcolor: 'background.default', pt: 1 } } }}>
            {nav}
          </Drawer>
        ) : (
          nav
        )}
        <Paper elevation={0} component="main" sx={{ flex: 1, minWidth: 0, overflow: 'auto', borderRadius: 1.5, mx: { xs: 1, md: 0 }, mr: { md: 1 }, mb: 1, p: { xs: 2, sm: 3 } }}>
          <Routes>
            <Route index element={<Navigate to={isSuper ? '/admin/dashboard' : '/admin/domains'} replace />} />
            {isSuper && <Route path="dashboard" element={<DashboardPage />} />}
            <Route path="domains" element={<Domains />} />
            <Route path="domains/:id" element={<DomainDetail />} />
            <Route path="mailboxes" element={<Mailboxes />} />
            <Route path="aliases" element={<Aliases />} />
            {isSuper && <Route path="certificates" element={<Certificates />} />}
            {isSuper && <Route path="queue" element={<Queue />} />}
            <Route path="logs" element={<Logs />} />
            <Route path="dmarc" element={<Dmarc />} />
            <Route path="tls-reports" element={<TlsReports />} />
            <Route path="backups" element={<Backups />} />
            <Route path="lists" element={<Lists />} />
            <Route path="api" element={<ApiDocs />} />
            {isSuper && <Route path="diagnostics" element={<Diagnostics />} />}
            {isSuper && <Route path="settings" element={<ServerSettings />} />}
            {isSuper && <Route path="smtp-access" element={<SmtpAccess />} />}
            {isSuper && <Route path="spam-filter" element={<SpamFilter />} />}
            {isSuper && <Route path="integrations" element={<Integrations />} />}
            <Route path="*" element={<Navigate to="/admin" replace />} />
          </Routes>
        </Paper>
      </Box>
    </Box>
  );
}
