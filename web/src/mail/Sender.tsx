import GppBad from '@mui/icons-material/GppBad';
import Verified from '@mui/icons-material/Verified';
import { Alert, AlertTitle, Avatar, Badge, Box, Chip, Stack, Tooltip, Typography } from '@mui/material';
import { senderNameWarning } from './risk';
import { useEffect, useState, type ReactNode } from 'react';
import { get } from '../api';
import { type EmailFull, formatAddress } from './jmapClient';

import { t, uiLocale } from '../i18n';
/** What the server established about a message when it arrived. */
export interface Security {
  origin: 'remote' | 'submitted' | 'unknown';
  verdict: 'verified' | 'partial' | 'unverified' | 'failed' | 'internal' | 'unknown';
  spf: string | null;
  dkim: string | null;
  dmarc: string | null;
  /** Domain of the envelope sender. */
  mailed_by: string | null;
  /** Domains whose DKIM signature verified. */
  signed_by: string[];
  from_domain: string | null;
  tls: boolean | null;
  /** Name of the malware found, if any (possibly empty). */
  virus: string | null;
  problems: string[];
}

interface AvatarInfo {
  source: 'bimi-verified' | 'bimi' | 'gravatar' | 'none';
  verified: boolean;
  detail: string;
}

/** Whether a sender may have a picture at all: not when the message looks forged. */
const mayHavePicture = (security?: Security | null) => security !== undefined && security !== null && ['verified', 'partial', 'internal'].includes(security.verdict);

const infoCache = new Map<string, Promise<AvatarInfo>>();

/** What kind of picture the server has for the sender of a message (asked once per message). */
export function useAvatarInfo(accountId: string, email: Pick<EmailFull, 'id' | 'security'>): AvatarInfo | null {
  const [info, setInfo] = useState<AvatarInfo | null>(null);
  const wanted = mayHavePicture(email.security);
  useEffect(() => {
    if (!wanted) return;
    let cancelled = false;
    const key = `${accountId}/${email.id}`;
    if (!infoCache.has(key)) infoCache.set(key, get<AvatarInfo>(`/jmap/avatar/${accountId}/${email.id}?info=1`));
    infoCache.get(key)!.then((found) => !cancelled && setInfo(found), () => infoCache.delete(key));
    return () => {
      cancelled = true;
    };
  }, [accountId, email.id, wanted]);
  return wanted ? info : null;
}

/**
 * The sender's picture: the brand logo its domain publishes (BIMI), else a Gravatar, else the
 * initial. Pictures come through the server, never straight from their hosts.
 */
export function SenderAvatar({ accountId, email, info }: { accountId: string; email: EmailFull; info: AvatarInfo | null }) {
  const sender = email.from?.[0];
  const initial = (sender?.name || sender?.email || '?')[0].toUpperCase();
  const picture = info && info.source !== 'none' ? `/jmap/avatar/${accountId}/${email.id}` : undefined;
  const brand = info?.source === 'bimi' || info?.source === 'bimi-verified';
  const avatar = (
    <Avatar
      src={picture}
      alt=""
      // Logos are drawn for a square with their own background; photos fill the circle.
      variant={brand ? 'rounded' : 'circular'}
      imgProps={{ loading: 'lazy', referrerPolicy: 'no-referrer' }}
      sx={{ bgcolor: picture ? 'background.paper' : 'secondary.main', width: 36, height: 36 }}
      data-avatar-source={info?.source ?? 'initial'}
    >
      {initial}
    </Avatar>
  );
  if (!info?.verified) return avatar;
  return (
    <Tooltip title={info.detail ? t('Verified logo of {{owner}}', { owner: info.detail }) : t('Verified logo of the sender')}>
      <Badge overlap="circular" anchorOrigin={{ vertical: 'bottom', horizontal: 'right' }} badgeContent={<Verified color="primary" sx={{ fontSize: 16, bgcolor: 'background.paper', borderRadius: '50%' }} aria-label={t('Verified sender logo')} />}>
        {avatar}
      </Badge>
    </Tooltip>
  );
}

function Row({ label, children }: { label: string; children: ReactNode }) {
  return (
    <Box component="tr" sx={{ verticalAlign: 'top' }}>
      <Box component="th" scope="row" sx={{ textAlign: 'right', fontWeight: 400, color: 'text.secondary', pr: 1.5, py: 0.25, whiteSpace: 'nowrap' }}>{label}:</Box>
      <Box component="td" sx={{ py: 0.25, overflowWrap: 'anywhere' }}>{children}</Box>
    </Box>
  );
}

function encryption(security: Security): string {
  if (security.origin === 'submitted') return t('Sent from within this mail server');
  if (security.tls === true) return t('Standard encryption (TLS) on the way to this server');
  if (security.tls === false) return t('Not encrypted on the way to this server');
  return t('Unknown (the message was imported)');
}

const VERDICTS: Record<Security['verdict'], string> = {
  verified: t('Sender verified'),
  partial: t('Partly verified: the visible sender is not confirmed'),
  unverified: t('Sender not verified'),
  failed: t('Verification failed'),
  internal: t('From a signed-in user of this server'),
  unknown: t('Not checked (imported or older message)'),
};

/** The details shown when hovering a sender: who, to whom, when, and how it got here. */
function SenderDetails({ email, info }: { email: EmailFull; info: AvatarInfo | null }) {
  const security = email.security;
  const list = (addresses: EmailFull['to']) => (addresses ?? []).map(formatAddress).join(', ');
  return (
    <Box component="table" aria-label={t('Message details')} sx={{ borderCollapse: 'collapse', fontSize: 13, maxWidth: 520 }} onClick={(e) => e.stopPropagation()}>
      <tbody>
        <Row label="from">{list(email.from) || t('unknown sender')}</Row>
        {email.replyTo && email.replyTo.length > 0 && <Row label={t('reply to')}>{list(email.replyTo)}</Row>}
        <Row label="to">{list(email.to) || t('undisclosed recipients')}</Row>
        {email.cc && email.cc.length > 0 && <Row label="cc">{list(email.cc)}</Row>}
        <Row label="date">{new Date(email.receivedAt).toLocaleString(uiLocale(), { dateStyle: 'medium', timeStyle: 'short' })}</Row>
        <Row label="subject">{email.subject || t('(no subject)')}</Row>
        {security?.mailed_by && <Row label="mailed-by">{security.mailed_by}</Row>}
        {security && security.signed_by.length > 0 && <Row label="signed-by">{security.signed_by.join(', ')}</Row>}
        {security && <Row label="security">{encryption(security)}</Row>}
        {security && (
          <Row label="sender">
            {VERDICTS[security.verdict]}
            {security.origin === 'remote' && (
              <Typography component="span" variant="caption" color="text.secondary" sx={{ display: 'block' }}>
                SPF {security.spf ?? t('not checked')} {t('· DKIM')} {security.dkim ?? t('not checked')} {t('· DMARC')} {security.dmarc ?? t('not checked')}
              </Typography>
            )}
          </Row>
        )}
        {info?.verified && <Row label="logo">{t('Verified mark of {{detail}}', { detail: info.detail })}</Row>}
        {security?.virus !== null && security?.virus !== undefined && <Row label={t('virus scan')}>{t('Malware found')}{security.virus ? `: ${security.virus}` : ''}</Row>}
      </tbody>
    </Box>
  );
}

/** Wraps the sender's name: hovering (or focusing) it shows the message details. */
export function SenderHover({ email, info, children }: { email: EmailFull; info: AvatarInfo | null; children: ReactNode }) {
  return (
    <Tooltip
      title={<SenderDetails email={email} info={info} />}
      placement="bottom-start"
      enterDelay={350}
      enterNextDelay={350}
      leaveDelay={150}
      slotProps={{ tooltip: { sx: { bgcolor: 'background.paper', color: 'text.primary', boxShadow: 6, border: 1, borderColor: 'divider', maxWidth: 560, p: 1.5, fontWeight: 400 } } }}
    >
      <Box component="span" tabIndex={0} sx={{ borderRadius: 0.5, '&:focus-visible': { outline: '2px solid', outlineColor: 'primary.main' } }} data-testid="sender-name">
        {children}
      </Box>
    </Tooltip>
  );
}

const check = (name: string, result: string | null) => <Chip key={name} size="small" variant="outlined" color={result === 'pass' ? 'success' : result === null || result === 'none' ? 'default' : 'warning'} label={`${name}: ${result ?? t('not checked')}`} />;

/** Warnings above a message: malware found by the scanner, and a sender that failed verification. */
export function SecurityWarnings({ email }: { email: EmailFull }) {
  const security = email.security;
  if (!security) return null;
  const sender = email.from?.[0]?.email ?? t('the sender shown');
  const infected = security.virus !== null;
  const doubtful = security.verdict === 'failed' || security.verdict === 'unverified';
  const misleadingName = senderNameWarning(email.from?.[0]?.name, email.from?.[0]?.email ?? '');
  if (!infected && !doubtful && !misleadingName) return null;
  return (
    <Stack spacing={1} sx={{ mb: 1.5 }}>
      {misleadingName && (
        <Alert severity="warning" data-testid="sender-name-warning">
          <AlertTitle>{t("The sender's name may be misleading")}</AlertTitle>
          {misleadingName} {t('Check the real address before trusting the message.')}
        </Alert>
      )}
      {infected && (
        <Alert severity="error" icon={<GppBad />}>
          <AlertTitle>{t('The virus scanner found malware in this message')}{security.virus ? `: ${security.virus}` : ''}</AlertTitle>
          {t('Do not open its attachments or follow its links, even if you know the sender.')}
        </Alert>
      )}
      {doubtful && (
        <Alert severity="warning" data-testid="sender-warning">
          <AlertTitle>{security.verdict === 'failed' ? t('This message may not really be from {{sender}}', { sender }) : t('It could not be confirmed that this message is from {{sender}}', { sender })}</AlertTitle>
          {security.verdict === 'failed' ? (
            <Box component="ul" sx={{ m: 0, pl: 2.5 }}>
              {security.problems.filter((problem) => !problem.startsWith('The virus scanner')).map((problem) => (
                <li key={problem}>{problem}</li>
              ))}
            </Box>
          ) : (
            t('The sending domain offers nothing to check the message against (no valid SPF record, no DKIM signature).')
          )}
          <Typography variant="body2" sx={{ mt: 0.5 }}>{t('Be careful with links, attachments and requests for money or passwords.')}</Typography>
          <Stack direction="row" spacing={0.5} sx={{ mt: 1 }} flexWrap="wrap" useFlexGap>
            {check('SPF', security.spf)}
            {check('DKIM', security.dkim)}
            {check('DMARC', security.dmarc)}
          </Stack>
        </Alert>
      )}
    </Stack>
  );
}
