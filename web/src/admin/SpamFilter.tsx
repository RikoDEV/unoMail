// Configuration of the Rspamd spam filter: thresholds, rule scores and recent verdicts.

import Edit from '@mui/icons-material/Edit';
import { Alert, Box, Button, Card, CardContent, Chip, Dialog, DialogActions, DialogContent, DialogTitle, IconButton, Stack, Table, TableBody, TableCell, TableHead, TableRow, TextField, Tooltip, Typography } from '@mui/material';
import { useEffect, useMemo, useState } from 'react';
import { formatTime, get, put } from '../api';
import { PageHeader, routeBy, useAction, useFormAction, useLoad } from './common';

import { t } from '../i18n';
interface RuleInfo {
  symbol: string;
  weight: number;
  description?: string;
  frequency?: number;
}

interface Verdict {
  time: number | null;
  ip: string | null;
  action: string | null;
  score: number | null;
  required_score: number | null;
  sender: string | null;
  recipient: string | string[] | null;
  subject: string | null;
  symbols: { name: string; score: number }[] | null;
}

interface Overview {
  configured: boolean;
  available: boolean;
  error?: string;
  stat?: { version?: string; scanned?: number; learned?: number; actions?: Record<string, number>; fuzzy_hashes?: Record<string, number> };
  actions?: { action: string; value: number | null }[];
  groups?: { group: string; rules: RuleInfo[] }[];
  history?: Verdict[];
}

const MAX_RULES_SHOWN = 100;
const ACTION_COLORS: Record<string, 'error' | 'warning' | 'success' | 'default'> = { reject: 'error', 'add header': 'warning', 'rewrite subject': 'warning', greylist: 'warning', 'soft reject': 'warning', 'no action': 'success' };

function Thresholds({ overview, onSaved }: { overview: Overview; onSaved: () => Promise<unknown> }) {
  const { run, feedback } = useAction();
  const current = (name: string) => overview.actions?.find((action) => action.action === name)?.value;
  const [reject, setReject] = useState(String(current('reject') ?? 15));
  const [addHeader, setAddHeader] = useState(String(current('add header') ?? 6));
  const numbers = [Number(reject), Number(addHeader)];
  const valid = [reject, addHeader].every((value) => value.trim() !== '') && numbers.every((value) => Number.isFinite(value) && value >= 0 && value <= 1000) && numbers[1] < numbers[0];
  return (
    <Card variant="outlined">
      <CardContent>
        <Typography variant="h6">{t('Thresholds')}</Typography>
        <Typography variant="body2" color="text.secondary" sx={{ mb: 2 }}>
          {t('Every message gets a spam score, the sum of the scores of the rules it triggers. These two values decide what happens to it.')}
        </Typography>
        {feedback}
        <Stack direction="row" spacing={2} alignItems="flex-start" flexWrap="wrap" useFlexGap>
          <TextField label={t('Mark as spam at')} value={addHeader} onChange={(e) => setAddHeader(e.target.value)} helperText={t('Delivered to the Junk folder')} sx={{ width: 220 }} slotProps={{ htmlInput: { inputMode: 'decimal' } }} />
          <TextField label={t('Reject at')} value={reject} onChange={(e) => setReject(e.target.value)} helperText={t('Refused during the SMTP session')} sx={{ width: 220 }} slotProps={{ htmlInput: { inputMode: 'decimal' } }} />
          <Button variant="contained" disabled={!valid} onClick={() => void run(async () => { await put('/api/spam-filter/thresholds', { reject: numbers[0], add_header: numbers[1] }); await onSaved(); }, t('Thresholds saved'))}>
            {t('Save thresholds')}
          </Button>
        </Stack>
        {!valid && (
          <Typography variant="caption" color="error">
            {t('Enter two scores between 0 and 1000; mail must be marked as spam at a lower score than it is rejected at.')}
          </Typography>
        )}
      </CardContent>
    </Card>
  );
}

function Rules({ overview, onSaved }: { overview: Overview; onSaved: () => Promise<unknown> }) {
  const { feedback, notify } = useAction();
  const saving = useFormAction(routeBy<'score'>([[/score|between/i, 'score']]));
  const [query, setQuery] = useState('');
  const [editing, setEditing] = useState<{ rule: RuleInfo; value: string } | null>(null);
  const rules = useMemo(() => (overview.groups ?? []).flatMap((group) => group.rules.map((rule) => ({ ...rule, group: group.group }))), [overview.groups]);
  const matching = useMemo(() => {
    const needle = query.trim().toLowerCase();
    const found = needle ? rules.filter((rule) => rule.symbol.toLowerCase().includes(needle) || (rule.description ?? '').toLowerCase().includes(needle) || rule.group.toLowerCase().includes(needle)) : rules;
    // Without a search, the rules that matter most (largest scores) come first.
    return [...found].sort((a, b) => Math.abs(b.weight) - Math.abs(a.weight));
  }, [rules, query]);
  const score = editing ? Number(editing.value) : 0;
  const scoreValid = editing !== null && editing.value.trim() !== '' && Number.isFinite(score) && Math.abs(score) <= 1000;
  return (
    <Card variant="outlined">
      <CardContent>
        <Stack direction="row" alignItems="center" spacing={2} sx={{ mb: 1 }} flexWrap="wrap" useFlexGap>
          <Typography variant="h6" sx={{ flex: 1 }}>
            {t('Rule scores')}
          </Typography>
          <TextField label={t('Search rules')} value={query} onChange={(e) => setQuery(e.target.value)} sx={{ minWidth: 260 }} />
        </Stack>
        {feedback}
        <Typography variant="body2" color="text.secondary" sx={{ mb: 1 }}>
          {t('{{matching}} of {{count}} rules', { matching: matching.length, count: rules.length })}{matching.length > MAX_RULES_SHOWN ? t(', showing the {{MAX_RULES_SHOWN}} with the largest scores', { MAX_RULES_SHOWN }) : ''}{t('. Positive scores count towards spam, negative ones against it.')}
        </Typography>
        <Table size="small" aria-label={t('Spam filter rules')}>
          <TableHead>
            <TableRow>
              <TableCell>{t('Rule')}</TableCell>
              <TableCell>{t('Group')}</TableCell>
              <TableCell align="right">{t('Score')}</TableCell>
              <TableCell />
            </TableRow>
          </TableHead>
          <TableBody>
            {matching.slice(0, MAX_RULES_SHOWN).map((rule) => (
              <TableRow key={rule.symbol} hover>
                <TableCell>
                  <Typography variant="body2" sx={{ fontFamily: 'monospace', wordBreak: 'break-all' }}>
                    {rule.symbol}
                  </Typography>
                  <Typography variant="caption" color="text.secondary">
                    {rule.description}
                  </Typography>
                </TableCell>
                <TableCell>{rule.group}</TableCell>
                <TableCell align="right" sx={{ color: rule.weight > 0 ? 'error.main' : rule.weight < 0 ? 'success.main' : undefined, fontWeight: 600 }}>{rule.weight}</TableCell>
                <TableCell align="right">
                  <Tooltip title={t('Edit score')}>
                    <IconButton size="small" aria-label={t('Edit score of {{symbol}}', { symbol: rule.symbol })} onClick={() => setEditing({ rule, value: String(rule.weight) })}>
                      <Edit fontSize="small" />
                    </IconButton>
                  </Tooltip>
                </TableCell>
              </TableRow>
            ))}
          </TableBody>
        </Table>
        {editing && (
          <Dialog open onClose={() => setEditing(null)} fullWidth maxWidth="xs">
            <DialogTitle sx={{ wordBreak: 'break-all' }}>{editing.rule.symbol}</DialogTitle>
            <DialogContent>
              <Typography variant="body2" color="text.secondary" sx={{ mb: 2 }}>
                {editing.rule.description || t('No description.')}
              </Typography>
              {saving.formError}
              <TextField
                label={t('Score')}
                value={editing.value}
                onChange={(e) => { saving.clear(); setEditing({ ...editing, value: e.target.value }); }}
                error={!scoreValid || Boolean(saving.fieldError('score'))}
                helperText={saving.fieldError('score') || t('Between -1000 and 1000')}
                autoFocus
                fullWidth
                slotProps={{ htmlInput: { inputMode: 'decimal' } }}
              />
            </DialogContent>
            <DialogActions>
              <Button onClick={() => setEditing(null)}>{t('Cancel')}</Button>
              <Button
                variant="contained"
                disabled={!scoreValid || saving.busy}
                onClick={async () => {
                  const name = editing.rule.symbol;
                  // The dialog stays open until the filter accepted the score, to show why it did not.
                  if (await saving.run(() => put('/api/spam-filter/rules', { name, value: score }))) {
                    setEditing(null);
                    notify(t('Score saved'));
                    await onSaved();
                  }
                }}
              >
                {t('Save score')}
              </Button>
            </DialogActions>
          </Dialog>
        )}
      </CardContent>
    </Card>
  );
}

function History({ rows }: { rows: Verdict[] }) {
  return (
    <Card variant="outlined">
      <CardContent>
        <Typography variant="h6" sx={{ mb: 1 }}>
          {t('Recent verdicts')}
        </Typography>
        {rows.length === 0 ? (
          <Typography color="text.secondary">{t('Nothing has been scanned yet.')}</Typography>
        ) : (
          <Table size="small" aria-label={t('Recent verdicts')}>
            <TableHead>
              <TableRow>
                <TableCell>{t('Time')}</TableCell>
                <TableCell>{t('From')}</TableCell>
                <TableCell>{t('Subject')}</TableCell>
                <TableCell>{t('Verdict')}</TableCell>
                <TableCell align="right">{t('Score')}</TableCell>
                <TableCell>{t('Main rules')}</TableCell>
              </TableRow>
            </TableHead>
            <TableBody>
              {rows.map((row, index) => (
                <TableRow key={`${row.time}-${index}`}>
                  <TableCell sx={{ whiteSpace: 'nowrap' }}>{row.time ? formatTime(Math.floor(row.time)) : ''}</TableCell>
                  <TableCell sx={{ wordBreak: 'break-all' }}>
                    {row.sender}
                    <Typography variant="caption" color="text.secondary" display="block" sx={{ fontFamily: 'monospace' }}>
                      {row.ip}
                    </Typography>
                  </TableCell>
                  <TableCell sx={{ overflowWrap: 'anywhere', maxWidth: 280 }}>{row.subject}</TableCell>
                  <TableCell>{row.action && <Chip size="small" label={row.action} color={ACTION_COLORS[row.action] ?? 'default'} />}</TableCell>
                  <TableCell align="right" sx={{ whiteSpace: 'nowrap' }}>
                    {typeof row.score === 'number' ? row.score.toFixed(1) : ''}
                    {typeof row.required_score === 'number' ? ` / ${row.required_score}` : ''}
                  </TableCell>
                  <TableCell sx={{ fontFamily: 'monospace', fontSize: 12, wordBreak: 'break-all' }}>{(row.symbols ?? []).map((symbol) => `${symbol.name} (${symbol.score})`).join(', ')}</TableCell>
                </TableRow>
              ))}
            </TableBody>
          </Table>
        )}
      </CardContent>
    </Card>
  );
}

export function SpamFilter() {
  const { data, error, reload } = useLoad(() => get<Overview>('/api/spam-filter'), []);
  // Statistics and verdicts keep moving while the page is open.
  useEffect(() => {
    const timer = setInterval(() => void reload(), 15_000);
    return () => clearInterval(timer);
  }, [reload]);

  if (error) return <Alert severity="error">{error}</Alert>;
  if (!data) return null;
  const actions = data.stat?.actions ?? {};
  return (
    <>
      <PageHeader title={t('Spam filter')}>{data.stat?.version && <Chip label={t('Rspamd {{version}}', { version: data.stat.version })} variant="outlined" />}</PageHeader>
      {!data.configured && (
        <Alert severity="info">
          {t('No spam filter is connected to this server. In the Docker image Rspamd is built in; elsewhere set UNOMAIL_RSPAMD_URL and UNOMAIL_RSPAMD_CONTROLLER_URL.')}
        </Alert>
      )}
      {data.configured && !data.available && <Alert severity="error">{t('The spam filter is configured but not answering: {{error}}', { error: data.error })}</Alert>}
      {data.available && (
        <Stack spacing={3}>
          <Stack direction="row" flexWrap="wrap" gap={1}>
            <Chip label={t('{{count}} scanned', { count: data.stat?.scanned ?? 0 })} />
            <Chip label={t('{{count}} learned', { count: data.stat?.learned ?? 0 })} />
            {Object.entries(actions).map(([action, count]) => (
              <Chip key={action} label={`${count} ${action}`} color={ACTION_COLORS[action] ?? 'default'} variant="outlined" />
            ))}
          </Stack>
          {/* Keyed by the stored values so the fields follow a change made elsewhere. */}
          <Box key={JSON.stringify(data.actions)}>
            <Thresholds overview={data} onSaved={reload} />
          </Box>
          <Rules overview={data} onSaved={reload} />
          <History rows={data.history ?? []} />
        </Stack>
      )}
    </>
  );
}
