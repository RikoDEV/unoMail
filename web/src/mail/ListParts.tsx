import Description from '@mui/icons-material/Description';
import Image from '@mui/icons-material/Image';
import InsertDriveFile from '@mui/icons-material/InsertDriveFile';
import PictureAsPdf from '@mui/icons-material/PictureAsPdf';
import WarningAmber from '@mui/icons-material/WarningAmber';
import { Avatar, Chip, Stack, Tooltip } from '@mui/material';
import { type MouseEvent, useEffect, useSyncExternalStore } from 'react';
import { downloadUrl, formatBytes, get } from '../lib/api';
import type { BodyPart, EmailSummary } from './jmapClient';
import { previewKind, type PreviewFile } from './Preview';
import { attachmentRisk } from './risk';
import { guardedDownload, useRiskConfirm } from './RiskConfirm';

import { t } from '../i18n';
// Which listed messages have a sender picture, asked for in batches: the rows that render
// within a few milliseconds of each other share one request, and only the pictures that
// exist are then loaded (most senders have none).
const pictures = new Map<string, boolean>();
const waiting = new Map<string, Set<string>>();
const listeners = new Set<() => void>();
let flushTimer: ReturnType<typeof setTimeout> | null = null;

function subscribePictures(listener: () => void) {
  listeners.add(listener);
  return () => listeners.delete(listener);
}

async function flushPictures() {
  flushTimer = null;
  const batches = [...waiting.entries()];
  waiting.clear();
  for (const [accountId, ids] of batches) {
    const list = [...ids];
    for (let i = 0; i < list.length; i += 200) {
      const chunk = list.slice(i, i + 200);
      const found = await get<Record<string, string>>(`/jmap/avatars/${accountId}?ids=${chunk.join(',')}`).catch(() => ({}) as Record<string, string>);
      for (const id of chunk) pictures.set(`${accountId}/${id}`, Boolean(found[id]) && found[id] !== 'none');
    }
  }
  listeners.forEach((listener) => listener());
}

function askForPicture(accountId: string, emailId: string) {
  const key = `${accountId}/${emailId}`;
  if (pictures.has(key) || waiting.get(accountId)?.has(emailId)) return;
  if (!waiting.has(accountId)) waiting.set(accountId, new Set());
  waiting.get(accountId)!.add(emailId);
  flushTimer ??= setTimeout(() => void flushPictures(), 15);
}

/** Whether the sender of a listed message has a picture (false until known). */
function useHasPicture(accountId: string, emailId: string): boolean {
  const key = `${accountId}/${emailId}`;
  const known = useSyncExternalStore(subscribePictures, () => pictures.get(key));
  useEffect(() => {
    if (accountId) askForPicture(accountId, emailId);
  }, [accountId, emailId]);
  return known === true;
}

/** The sender's picture in the message list (the initial when there is none). */
export function ListAvatar({ accountId, email, size, people }: { accountId: string; email: EmailSummary; size: number; people: EmailSummary['from'] }) {
  const first = people?.[0];
  const initial = (first?.name || first?.email || '?')[0].toUpperCase();
  const hasPicture = useHasPicture(accountId, email.id);
  return (
    <Avatar
      src={hasPicture ? `/jmap/avatar/${accountId}/${email.id}` : undefined}
      alt=""
      imgProps={{ loading: 'lazy', referrerPolicy: 'no-referrer' }}
      sx={{ width: size, height: size, fontSize: size * 0.45, bgcolor: 'm3.primaryContainer', color: 'm3.onPrimaryContainer', flexShrink: 0 }}
      aria-hidden
    >
      {initial}
    </Avatar>
  );
}

function iconFor(type: string) {
  if (type === 'application/pdf') return <PictureAsPdf fontSize="small" />;
  if (type.startsWith('image/')) return <Image fontSize="small" />;
  if (type.startsWith('text/') || type.includes('word') || type.includes('document')) return <Description fontSize="small" />;
  return <InsertDriveFile fontSize="small" />;
}

/** The files attached to a message, as chips below it in the list (embedded pictures are left out). */
export function listedAttachments(email: EmailSummary): BodyPart[] {
  return (email.attachments ?? []).filter((part) => !part.cid);
}

const SHOWN = 3;

export function ListAttachments({ accountId, email, onPreview }: { accountId: string; email: EmailSummary; onPreview: (file: PreviewFile) => void }) {
  const files = listedAttachments(email);
  const [ask, dialog] = useRiskConfirm();
  if (files.length === 0) return null;
  const stop = (event: MouseEvent) => event.stopPropagation();
  return (
    <Stack direction="row" gap={0.75} sx={{ mt: 0.75, minWidth: 0, overflow: 'hidden' }} role="list" aria-label={t('Attachments of {{subject}}', { subject: email.subject || t('(no subject)') })} onClick={stop}>
      {dialog}
      {files.slice(0, SHOWN).map((part) => {
        const name = part.name ?? 'attachment';
        const risk = attachmentRisk(name);
        const file: PreviewFile = { name, type: part.type, url: downloadUrl(accountId, part.blobId, name) };
        const canPreview = Boolean(previewKind(file));
        return (
          <Tooltip key={part.partId ?? part.blobId} title={`${name} (${formatBytes(part.size)}) · ${risk ? risk.reason : canPreview ? t('click to preview') : t('click to download')}`}>
            <Chip
              role="listitem"
              size="small"
              variant="outlined"
              icon={risk ? <WarningAmber fontSize="small" /> : iconFor(part.type)}
              color={risk?.level === 'danger' ? 'error' : risk ? 'warning' : 'default'}
              data-risk={risk?.level}
              label={name}
              clickable
              {...(canPreview
                ? { onClick: (event: MouseEvent) => { event.stopPropagation(); onPreview(file); } }
                : {
                    component: 'a',
                    href: file.url,
                    download: name,
                    onClick: (event: MouseEvent) => {
                      stop(event);
                      if (!attachmentRisk(name)) return;
                      event.preventDefault();
                      void guardedDownload(ask, name, file.url);
                    },
                  })}
              sx={{ maxWidth: 200, borderRadius: 4, '& .MuiChip-label': { overflow: 'hidden', textOverflow: 'ellipsis' } }}
            />
          </Tooltip>
        );
      })}
      {files.length > SHOWN && <Chip role="listitem" size="small" variant="outlined" label={`+${files.length - SHOWN}`} sx={{ borderRadius: 4 }} />}
    </Stack>
  );
}
