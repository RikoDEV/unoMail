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
import Dns from '@mui/icons-material/Dns';
import Hub from '@mui/icons-material/Hub';
import AutoAwesome from '@mui/icons-material/AutoAwesome';
import ListAlt from '@mui/icons-material/ListAlt';
import People from '@mui/icons-material/People';
import Schedule from '@mui/icons-material/Schedule';
import Security from '@mui/icons-material/Security';
import { type ReactElement } from 'react';
import { Navigate, NavLink, Route, Routes } from 'react-router-dom';
import { useAuth } from '../app';
import { SideNavPage } from '../ui/shell';
import { Aliases } from './Aliases';
import { Certificates } from './Certificates';
import { DashboardPage } from './Dashboard';
import { DomainDetail, Domains } from './Domains';
import { ApiDocs, Diagnostics, Dmarc } from './Insights';
import { Integrations } from './Integrations';
import { Models } from './Models';
import { MaskedEmails } from './MaskedEmails';
import { Logs, Queue } from './QueueLogs';
import { ServerSettings } from './ServerSettings';
import { SmtpAccess } from './SmtpAccess';
import { SpamFilter } from './SpamFilter';
import { TlsReports } from './TlsReports';
import { Backups } from './Backups';
import { Lists } from './Lists';
import { Mailboxes } from './Mailboxes';

import Extension from '@mui/icons-material/Extension';
import { useParams } from 'react-router-dom';
import { PluginView, usePluginPages } from '../plugins/Slot';
import { PageHeader } from './common';
import { t } from '../i18n';

/** An administration page a plug-in added (`admin.section`). */
function AdminPluginPage() {
  const { plugin, view } = useParams();
  const page = usePluginPages('admin.section').find((p) => p.plugin === plugin && p.id === view);
  if (!page) return null;
  return (
    <>
      <PageHeader title={page.title} />
      <PluginView mount={page} fill />
    </>
  );
}
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
  { path: 'masked-addresses', label: t('Masked addresses'), icon: <AlternateEmail /> },
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
  { path: 'models', label: t('Models'), icon: <AutoAwesome />, superOnly: true },
  { path: 'api', label: t('API reference'), icon: <Api /> },
];

export default function AdminApp() {
  const { account } = useAuth();
  const isSuper = account?.role === 'super_admin';
  const pages = usePluginPages('admin.section');
  const items = [
    ...NAV.filter((item) => isSuper || !item.superOnly),
    ...(isSuper ? pages.map((page) => ({ path: `x/${encodeURIComponent(page.plugin)}/${encodeURIComponent(page.id)}`, label: page.title, icon: <Extension />, superOnly: true })) : []),
  ];
  return (
    <SideNavPage
      title={t('unoMail Admin')}
      navLabel={t('Administration menu')}
      placement="admin"
      linkComponent={NavLink}
      items={items.map((item) => ({ key: item.path, label: item.label, icon: item.icon, to: `/admin/${item.path}` }))}
    >
          <Routes>
            <Route index element={<Navigate to={isSuper ? '/admin/dashboard' : '/admin/domains'} replace />} />
            {isSuper && <Route path="dashboard" element={<DashboardPage />} />}
            <Route path="domains" element={<Domains />} />
            <Route path="domains/:id" element={<DomainDetail />} />
            <Route path="mailboxes" element={<Mailboxes />} />
            <Route path="aliases" element={<Aliases />} />
            <Route path="masked-addresses" element={<MaskedEmails />} />
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
            {isSuper && <Route path="models" element={<Models />} />}
            {isSuper && <Route path="x/:plugin/:view" element={<AdminPluginPage />} />}
            <Route path="*" element={<Navigate to="/admin" replace />} />
          </Routes>
    </SideNavPage>
  );
}
