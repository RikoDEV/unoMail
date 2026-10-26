import ArrowDropDown from '@mui/icons-material/ArrowDropDown';
import ContentCopy from '@mui/icons-material/ContentCopy';
import GppBad from '@mui/icons-material/GppBad';
import HowToReg from '@mui/icons-material/HowToReg';
import MailOutlined from '@mui/icons-material/MailOutlined';
import PersonAddAlt from '@mui/icons-material/PersonAddAlt';
import Search from '@mui/icons-material/Search';
import Verified from '@mui/icons-material/Verified';
import { Alert, AlertTitle, Avatar, Badge, Box, Button, Chip, ClickAwayListener, IconButton, Popover, Snackbar, Stack, Tooltip, Typography } from '@mui/material';
import { Link as RouterLink } from 'react-router-dom';
import { senderNameWarning } from './risk';
import { useEffect, useState, type ReactNode } from 'react';
import { errorText, get, post } from '../lib/api';
import { useFeature } from '../lib/plugins';
import type { Contact } from './extra';
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
export function SenderAvatar({ accountId, email, info, size = 36 }: { accountId: string; email: EmailFull; info: AvatarInfo | null; size?: number }) {
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
      sx={{ bgcolor: picture ? 'background.paper' : 'secondary.main', width: size, height: size, fontSize: size > 36 ? size * 0.45 : undefined }}
      data-avatar-source={info?.source ?? 'initial'}
      slotProps={{
        img: { loading: 'lazy', referrerPolicy: 'no-referrer' }
      }}
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
              <Typography component="span" variant="caption" sx={{ color: 'text.secondary', display: 'block' }}>
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

/** The small arrow beside the recipients that opens the message details. */
export function DetailsButton({ email, info }: { email: EmailFull; info: AvatarInfo | null }) {
  const [anchor, setAnchor] = useState<HTMLElement | null>(null);
  return (
    <>
      <IconButton size="small" aria-label={t('Show details')} aria-expanded={Boolean(anchor)} onClick={(e) => { e.stopPropagation(); setAnchor(e.currentTarget); }} sx={{ p: 0, ml: 0.25 }}>
        <ArrowDropDown fontSize="small" />
      </IconButton>
      <Popover
        open={Boolean(anchor)}
        anchorEl={anchor}
        onClose={() => setAnchor(null)}
        onClick={(e) => e.stopPropagation()}
        anchorOrigin={{ vertical: 'bottom', horizontal: 'left' }}
        slotProps={{ paper: { sx: { p: 1.5, maxWidth: 'min(560px, calc(100vw - 32px))' } } }}
      >
        <SenderDetails email={email} info={info} />
      </Popover>
    </>
  );
}

/** Whether an address is in the user's address book (null while asking). */
function useInContacts(address: string, enabled: boolean) {
  const [known, setKnown] = useState<boolean | null>(null);
  useEffect(() => {
    if (!enabled) return;
    let cancelled = false;
    get<Contact[]>(`/api/me/contacts?q=${encodeURIComponent(address)}`)
      .then((list) => !cancelled && setKnown(list.some((c) => c.email.toLowerCase() === address.toLowerCase())))
      .catch(() => !cancelled && setKnown(false));
    return () => {
      cancelled = true;
    };
  }, [address, enabled]);
  return [known, setKnown] as const;
}

/** The card about the sender: who it is, and what can be done with the address. */
function SenderCardBody({ accountId, email, info, onDone, onNotice }: { accountId: string; email: EmailFull; info: AvatarInfo | null; onDone: () => void; onNotice: (text: string) => void }) {
  const sender = email.from![0];
  const contactsOn = useFeature('contacts');
  const [inContacts, setInContacts] = useInContacts(sender.email, contactsOn);
  const act = (run: () => void) => () => {
    onDone();
    run();
  };
  async function addContact() {
    try {
      await post('/api/me/contacts', { name: sender.name ?? '', email: sender.email, phone: '', organization: '', notes: '', pgp_key: '' });
      setInContacts(true);
      onNotice(t('{{email}} added to contacts', { email: sender.email }));
    } catch (err) {
      onNotice(errorText(err, t('The contact could not be saved')));
    }
  }
  return (
    <Box onClick={(e) => e.stopPropagation()} sx={{ width: 320, maxWidth: 'calc(100vw - 32px)' }} role="dialog" aria-label={t('About {{sender}}', { sender: sender.name || sender.email })}>
      <Stack direction="row" spacing={2} sx={{ alignItems: 'center' }}>
        <SenderAvatar accountId={accountId} email={email} info={info} size={64} />
        <Box sx={{ flex: 1, minWidth: 0 }}>
          <Typography noWrap sx={{ fontSize: 18 }}>{sender.name || sender.email}</Typography>
          {sender.name && <Typography noWrap variant="body2" sx={{ color: 'text.secondary' }}>{sender.email}</Typography>}
        </Box>
        {contactsOn && inContacts === false && (
          <Tooltip title={t('Add to contacts')}>
            <IconButton aria-label={t('Add to contacts')} onClick={() => void addContact()} sx={{ alignSelf: 'flex-start' }}><PersonAddAlt /></IconButton>
          </Tooltip>
        )}
        {contactsOn && inContacts && (
          <Tooltip title={t('In your contacts')}>
            <IconButton aria-label={t('In your contacts')} component={RouterLink} to="/contacts" sx={{ alignSelf: 'flex-start' }}><HowToReg /></IconButton>
          </Tooltip>
        )}
      </Stack>
      <Stack direction="row" spacing={1} sx={{ alignItems: 'center', mt: 2 }}>
        <Button
          variant="contained"
          disableElevation
          startIcon={<MailOutlined />}
          onClick={act(() => window.dispatchEvent(new CustomEvent('unomail:mailto', { detail: `mailto:${sender.email}` })))}
          sx={{ flex: 1, borderRadius: 5 }}
        >
          {t('Send email')}
        </Button>
        <Tooltip title={t('Find emails from {{sender}}', { sender: sender.email })}>
          <IconButton aria-label={t('Find emails from {{sender}}', { sender: sender.email })} onClick={act(() => window.dispatchEvent(new CustomEvent('unomail:search', { detail: `from:${sender.email}` })))} sx={{ border: 1, borderColor: 'divider' }}>
            <Search fontSize="small" />
          </IconButton>
        </Tooltip>
        <Tooltip title={t('Copy address')}>
          <IconButton
            aria-label={t('Copy address')}
            onClick={() => void navigator.clipboard.writeText(sender.email).then(() => onNotice(t('Address copied')), () => onNotice(t('The address could not be copied')))}
            sx={{ border: 1, borderColor: 'divider' }}
          >
            <ContentCopy fontSize="small" />
          </IconButton>
        </Tooltip>
      </Stack>
    </Box>
  );
}

/**
 * Wraps the sender's picture or name: hovering, focusing or clicking it shows the card about the
 * sender. Only on an open message; a folded one opens on a click instead.
 */
export function SenderCard({ accountId, email, info, enabled, testId, children }: { accountId: string; email: EmailFull; info: AvatarInfo | null; enabled: boolean; testId?: string; children: ReactNode }) {
  const [open, setOpen] = useState(false);
  const [notice, setNotice] = useState('');
  const sender = email.from?.[0];
  if (!enabled || !sender) return <Box component="span" data-testid={testId}>{children}</Box>;
  return (
    <>
      <ClickAwayListener touchEvent={false} onClickAway={() => setOpen(false)}>
        <Box component="span">
          <Tooltip
            open={open}
            onOpen={() => setOpen(true)}
            onClose={() => setOpen(false)}
            title={<SenderCardBody accountId={accountId} email={email} info={info} onDone={() => setOpen(false)} onNotice={setNotice} />}
            placement="bottom-start"
            enterDelay={350}
            enterNextDelay={350}
            leaveDelay={200}
            disableTouchListener
            slotProps={{ tooltip: { sx: { bgcolor: 'm3.surfaceContainerHigh', color: 'text.primary', boxShadow: 6, borderRadius: '12px', maxWidth: 'none', p: 2, fontWeight: 400, fontSize: 14 } } }}
          >
            <Box
              component="span"
              tabIndex={0}
              onClick={(e) => { e.stopPropagation(); setOpen(true); }}
              sx={{ cursor: 'pointer', borderRadius: 0.5, '&:focus-visible': { outline: '2px solid', outlineColor: 'primary.main' } }}
              data-testid={testId}
            >
              {children}
            </Box>
          </Tooltip>
        </Box>
      </ClickAwayListener>
      <Snackbar open={Boolean(notice)} autoHideDuration={4000} onClose={() => setNotice('')} message={notice} />
    </>
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
          <Stack direction="row" spacing={0.5} useFlexGap sx={{ flexWrap: 'wrap', mt: 1 }}>
            {check('SPF', security.spf)}
            {check('DKIM', security.dkim)}
            {check('DMARC', security.dmarc)}
          </Stack>
        </Alert>
      )}
    </Stack>
  );
}
