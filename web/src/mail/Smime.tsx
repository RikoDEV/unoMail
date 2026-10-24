// S/MIME in the web client: what the server found out about a message's signature and
// encryption, and the user's own certificate.

import GppBad from '@mui/icons-material/GppBad';
import GppGood from '@mui/icons-material/GppGood';
import GppMaybe from '@mui/icons-material/GppMaybe';
import Lock from '@mui/icons-material/Lock';
import { Alert, Chip, Stack, Tooltip } from '@mui/material';
import { del, get, put } from '../lib/api';

import { t } from '../i18n';
export interface CertInfo {
  subject: string;
  issuer: string;
  emails: string[];
  not_before: number;
  not_after: number;
  fingerprint: string;
}

export interface SmimeStatus {
  encrypted: boolean;
  decrypted: boolean;
  signature: { status: 'valid' | 'untrusted' | 'expired' | 'invalid'; signer: CertInfo | null; matches_sender: boolean; reason: string | null } | null;
  problem: string | null;
}

export interface SmimeSettings {
  certificate: CertInfo | null;
  correspondents: { email: string; not_after: number }[];
}

export const fetchSmime = () => get<SmimeSettings>('/api/me/smime');
export const removeSmime = () => del('/api/me/smime');

export async function importSmime(file: File, password: string): Promise<CertInfo> {
  const bytes = new Uint8Array(await file.arrayBuffer());
  let binary = '';
  for (let i = 0; i < bytes.length; i += 0x8000) binary += String.fromCharCode(...bytes.subarray(i, i + 0x8000));
  const result = await put<{ certificate: CertInfo }>('/api/me/smime', { file: btoa(binary), password });
  return result.certificate;
}

/** Signature and encryption of a message, next to its other security information. */
export function SmimeBadges({ status }: { status: SmimeStatus | null | undefined }) {
  if (!status) return null;
  const signature = status.signature;
  const signer = signature?.signer?.emails.join(', ') || signature?.signer?.subject || t('unknown signer');
  return (
    <Stack spacing={1} sx={{ mb: 1 }}>
      <Stack direction="row" spacing={1} useFlexGap sx={{ flexWrap: 'wrap' }}>
        {status.encrypted && status.decrypted && (
          <Chip size="small" icon={<Lock />} label={t('Encrypted (S/MIME)')} variant="outlined" />
        )}
        {signature && signature.status === 'valid' && signature.matches_sender && (
          <Tooltip title={t('Certificate issued by {{issuer}}', { issuer: signature.signer?.issuer ?? t('an unknown authority') })}>
            <Chip size="small" color="success" icon={<GppGood />} label={t('Signed by {{signer}}', { signer })} variant="outlined" />
          </Tooltip>
        )}
        {signature && signature.status === 'untrusted' && (
          <Tooltip title={t('The signature is intact, but the certificate was issued by {{issuer}}, which this server does not know.', { issuer: signature.signer?.issuer ?? t('an unknown authority') })}>
            <Chip size="small" icon={<GppMaybe />} label={t('Signed by {{signer}} (unverified certificate)', { signer })} variant="outlined" />
          </Tooltip>
        )}
        {signature && (signature.status === 'invalid' || signature.status === 'expired') && (
          <Chip size="small" color="error" icon={<GppBad />} label={signature.status === 'expired' ? t('Signature certificate expired') : t('Invalid signature')} variant="outlined" />
        )}
      </Stack>
      {signature && signature.status === 'invalid' && (
        <Alert severity="error">{t('The S/MIME signature does not match:')} {signature.reason ?? t('the message was changed or the signature is broken')}.</Alert>
      )}
      {signature && signature.status !== 'invalid' && !signature.matches_sender && (
        <Alert severity="warning">{t('The message is signed with a certificate for {{signer}}, not for the address it claims to be from.', { signer })}</Alert>
      )}
      {status.problem && <Alert severity="info">{status.problem}</Alert>}
    </Stack>
  );
}
