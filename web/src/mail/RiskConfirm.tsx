// A confirmation step before something risky: following a suspicious link, saving a file
// that runs code.

import WarningAmber from '@mui/icons-material/WarningAmber';
import { Alert, Button, Dialog, DialogActions, DialogContent, DialogTitle, Typography } from '@mui/material';
import { type ReactNode, useCallback, useState } from 'react';
import { attachmentRisk } from './risk';

import { t } from '../i18n';
interface Question {
  title: string;
  reason: string;
  detail?: string;
  proceed: string;
  resolve: (ok: boolean) => void;
}

/** Returns a function that asks for confirmation (resolving to the answer) and its dialog. */
export function useRiskConfirm(): [(title: string, reason: string, proceed: string, detail?: string) => Promise<boolean>, ReactNode] {
  const [question, setQuestion] = useState<Question | null>(null);
  const ask = useCallback(
    (title: string, reason: string, proceed: string, detail?: string) => new Promise<boolean>((resolve) => setQuestion({ title, reason, detail, proceed, resolve })),
    [],
  );
  const answer = (ok: boolean) => {
    question?.resolve(ok);
    setQuestion(null);
  };
  const dialog = (
    <Dialog open={question !== null} onClose={() => answer(false)} maxWidth="sm" fullWidth>
      <DialogTitle sx={{ display: 'flex', alignItems: 'center', gap: 1 }}>
        <WarningAmber color="warning" />
        {question?.title}
      </DialogTitle>
      <DialogContent>
        <Alert severity="warning" sx={{ mb: question?.detail ? 2 : 0 }}>{question?.reason}</Alert>
        {question?.detail && <Typography sx={{ fontFamily: 'monospace', wordBreak: 'break-all' }}>{question.detail}</Typography>}
      </DialogContent>
      <DialogActions>
        <Button variant="contained" autoFocus onClick={() => answer(false)}>{t('Cancel')}</Button>
        <Button color="warning" onClick={() => answer(true)}>{question?.proceed}</Button>
      </DialogActions>
    </Dialog>
  );
  return [ask, dialog];
}

/** Saves a file; a risky one only after the user confirms. */
export async function guardedDownload(ask: ReturnType<typeof useRiskConfirm>[0], name: string, url: string): Promise<void> {
  const risk = attachmentRisk(name);
  if (risk && !(await ask(t('Download {{value}}?', { value: name.replace(/[​-‏‪-‮⁦-⁩﻿]/g, '') }), risk.reason, t('Download anyway'), t('Only open it if you expected this file from this sender.')))) return;
  const link = document.createElement('a');
  link.href = url;
  link.download = name;
  document.body.appendChild(link);
  link.click();
  link.remove();
}
