// Settings → Filters: server-side mail filters, edited as a list of rules (like Roundcube's
// filter editor) or directly as Sieve. Both edit the same script; see filters/sieveRules.ts.

import Add from '@mui/icons-material/Add';
import ArrowDownward from '@mui/icons-material/ArrowDownward';
import ArrowUpward from '@mui/icons-material/ArrowUpward';
import Close from '@mui/icons-material/Close';
import Delete from '@mui/icons-material/Delete';
import Edit from '@mui/icons-material/Edit';
import {
  Alert, Autocomplete, Box, Button, Card, CardContent, Checkbox, Dialog, DialogContent, DialogTitle, Divider, FormControlLabel, IconButton, List, ListItem, ListItemText,
  MenuItem, Stack, Switch, Tab, Tabs, TextField, Tooltip, Typography, useMediaQuery, useTheme,
} from '@mui/material';
import { useEffect, useMemo, useState } from 'react';
import { del, errorText, get, put } from '../lib/api';
import {
  ACTION_LABELS, ACTIONS, actionTarget, type Action, type Condition, emptyRule, FIELD_LABELS, FIELDS, generate, needsValue, OPERATOR_LABELS, operatorsFor, parseRules, problems, type Rule,
  summary,
} from '../filters/sieveRules';
import { t } from '../i18n';
import { folderName, listMailboxes, type Mailbox, normalizeLabel } from '../mail/jmapClient';
import { DialogButtons } from '../admin/common';

const SIEVE_EXAMPLE = `require ["fileinto", "mailbox", "imap4flags"];

# File newsletters into their own folder
if exists "List-Id" {
    fileinto :create "Newsletters";
    stop;
}

# Flag mail from an important sender
if address :is "from" "boss@example.com" {
    addflag "\\\\Flagged";
}
`;

/** One condition of a rule: what to look at, how to compare and with what. */
function ConditionRow({ condition, onChange, onRemove }: { condition: Condition; onChange: (next: Condition) => void; onRemove?: () => void }) {
  const operators = operatorsFor(condition.field);
  return (
    <Stack direction={{ xs: 'column', sm: 'row' }} spacing={1} alignItems={{ sm: 'center' }} data-testid="condition" sx={(theme) => ({ p: { xs: 1.5, sm: 0 }, border: { xs: `1px solid ${theme.palette.divider}`, sm: 'none' }, borderRadius: 2 })}>
      <TextField
        select
        size="small"
        label={t('Field')}
        value={condition.field}
        onChange={(e) => {
          const field = e.target.value as Condition['field'];
          const allowed = operatorsFor(field);
          onChange({ ...condition, field, op: allowed.includes(condition.op) ? condition.op : allowed[0], value: field === 'size' || condition.field === 'size' ? '' : condition.value });
        }}
        sx={{ minWidth: 170 }}
      >
        {FIELDS.map((field) => (
          <MenuItem key={field} value={field}>{FIELD_LABELS[field]}</MenuItem>
        ))}
      </TextField>
      {condition.field === 'header' && (
        <TextField size="small" label={t('Header name')} placeholder="X-Priority" value={condition.header ?? ''} onChange={(e) => onChange({ ...condition, header: e.target.value })} sx={{ minWidth: 140 }} />
      )}
      <TextField select size="small" label={t('Comparison')} value={condition.op} onChange={(e) => onChange({ ...condition, op: e.target.value as Condition['op'] })} sx={{ minWidth: 190 }}>
        {operators.map((op) => (
          <MenuItem key={op} value={op}>{OPERATOR_LABELS[op]}</MenuItem>
        ))}
      </TextField>
      {needsValue(condition.op) ? (
        <TextField
          size="small"
          label={condition.field === 'size' ? t('Size') : t('Value')}
          placeholder={condition.field === 'size' ? '500K' : undefined}
          value={condition.value}
          onChange={(e) => onChange({ ...condition, value: e.target.value })}
          sx={{ flex: 1, minWidth: 140 }}
        />
      ) : (
        <Box sx={{ flex: 1 }} />
      )}
      {onRemove && (
        <Tooltip title={t('Remove condition')}>
          <IconButton aria-label={t('Remove condition')} onClick={onRemove} sx={{ alignSelf: { xs: 'flex-end', sm: 'center' } }}><Close /></IconButton>
        </Tooltip>
      )}
    </Stack>
  );
}

/** One action of a rule, with the folder, label or address it needs. */
function ActionRow({ action, folders, labels, onChange, onRemove }: { action: Action; folders: Mailbox[]; labels: string[]; onChange: (next: Action) => void; onRemove?: () => void }) {
  const target = actionTarget(action.type);
  return (
    <Stack direction={{ xs: 'column', sm: 'row' }} spacing={1} alignItems={{ sm: 'center' }} data-testid="action" sx={(theme) => ({ p: { xs: 1.5, sm: 0 }, border: { xs: `1px solid ${theme.palette.divider}`, sm: 'none' }, borderRadius: 2 })}>
      <TextField
        select
        size="small"
        label={t('Action')}
        value={action.type}
        onChange={(e) => {
          const type = e.target.value as Action['type'];
          onChange({ type, value: actionTarget(type) === target ? action.value : '' });
        }}
        sx={{ minWidth: 190 }}
      >
        {ACTIONS.map((type) => (
          <MenuItem key={type} value={type}>{ACTION_LABELS[type]}</MenuItem>
        ))}
      </TextField>
      {target === 'folder' && (
        <TextField select size="small" label={t('Folder')} value={folders.some((f) => f.name === action.value) ? action.value : ''} onChange={(e) => onChange({ ...action, value: e.target.value })} sx={{ flex: 1, minWidth: 160 }}>
          {folders.map((folder) => (
            <MenuItem key={folder.id} value={folder.name}>{folderName(folder)}</MenuItem>
          ))}
        </TextField>
      )}
      {target === 'label' && (
        <Autocomplete
          freeSolo
          size="small"
          options={labels}
          value={action.value}
          onInputChange={(_, value) => onChange({ ...action, value })}
          renderInput={(params) => <TextField {...params} label={t('Label')} />}
          sx={{ flex: 1, minWidth: 160 }}
        />
      )}
      {target === 'address' && <TextField size="small" type="email" label={t('Address')} value={action.value} onChange={(e) => onChange({ ...action, value: e.target.value })} sx={{ flex: 1, minWidth: 160 }} />}
      {!target && <Box sx={{ flex: 1 }} />}
      {onRemove && (
        <Tooltip title={t('Remove action')}>
          <IconButton aria-label={t('Remove action')} onClick={onRemove} sx={{ alignSelf: { xs: 'flex-end', sm: 'center' } }}><Close /></IconButton>
        </Tooltip>
      )}
    </Stack>
  );
}

function RuleDialog({ rule: initial, folders, labels, onSave, onClose }: { rule: Rule; folders: Mailbox[]; labels: string[]; onSave: (rule: Rule) => void; onClose: () => void }) {
  const [rule, setRule] = useState(initial);
  const [shown, setShown] = useState<string[]>([]);
  const phone = useMediaQuery(useTheme().breakpoints.down('sm'));
  const set = (changes: Partial<Rule>) => setRule((current) => ({ ...current, ...changes }));
  const setCondition = (index: number, next: Condition) => set({ conditions: rule.conditions.map((c, i) => (i === index ? next : c)) });
  const setAction = (index: number, next: Action) => set({ actions: rule.actions.map((a, i) => (i === index ? next : a)) });

  function save() {
    // Labels are stored the way the rest of the app writes them.
    const actions = rule.actions.map((action) => (action.type === 'label' ? { ...action, value: normalizeLabel(action.value) ?? action.value } : action));
    const cleaned = { ...rule, name: rule.name.trim(), actions };
    const found = problems(cleaned);
    if (actions.some((action) => action.type === 'label' && action.value && !normalizeLabel(action.value))) found.push(t('Labels may contain letters, digits, "-", "_" and "."'));
    if (found.length) {
      setShown(found);
      return;
    }
    onSave(cleaned);
  }

  return (
    <Dialog open onClose={onClose} fullWidth maxWidth="md" fullScreen={phone} aria-labelledby="rule-dialog-title">
      <DialogTitle id="rule-dialog-title">{initial.name ? t('Edit rule') : t('New rule')}</DialogTitle>
      <DialogContent>
        <Stack spacing={2} sx={{ mt: 1 }}>
          {shown.length > 0 && (
            <Alert severity="error" onClose={() => setShown([])}>
              {shown.map((problem) => <div key={problem}>{problem}</div>)}
            </Alert>
          )}
          <TextField label={t('Rule name')} value={rule.name} onChange={(e) => set({ name: e.target.value })} autoFocus={!initial.name} required />
          <TextField select label={t('Apply to')} value={rule.match} onChange={(e) => set({ match: e.target.value as Rule['match'] })}>
            <MenuItem value="all">{t('Messages matching all of these conditions')}</MenuItem>
            <MenuItem value="any">{t('Messages matching any of these conditions')}</MenuItem>
            <MenuItem value="always">{t('Every message')}</MenuItem>
          </TextField>
          {rule.match !== 'always' && (
            <Stack spacing={1.5}>
              {rule.conditions.map((condition, index) => (
                <ConditionRow
                  key={index}
                  condition={condition}
                  onChange={(next) => setCondition(index, next)}
                  onRemove={rule.conditions.length > 1 ? () => set({ conditions: rule.conditions.filter((_, i) => i !== index) }) : undefined}
                />
              ))}
              <Box>
                <Button startIcon={<Add />} onClick={() => set({ conditions: [...rule.conditions, { field: 'subject', op: 'contains', value: '' }] })}>{t('Add condition')}</Button>
              </Box>
            </Stack>
          )}
          <Divider />
          <Typography variant="subtitle2">{t('Then')}</Typography>
          <Stack spacing={1.5}>
            {rule.actions.map((action, index) => (
              <ActionRow
                key={index}
                action={action}
                folders={folders}
                labels={labels}
                onChange={(next) => setAction(index, next)}
                onRemove={rule.actions.length > 1 ? () => set({ actions: rule.actions.filter((_, i) => i !== index) }) : undefined}
              />
            ))}
            <Box>
              <Button startIcon={<Add />} onClick={() => set({ actions: [...rule.actions, { type: 'read', value: '' }] })}>{t('Add action')}</Button>
            </Box>
          </Stack>
          <FormControlLabel control={<Checkbox checked={rule.stop} onChange={(e) => set({ stop: e.target.checked })} />} label={t('Stop here: later rules are not applied to matching messages')} />
        </Stack>
      </DialogContent>
      <DialogButtons onCancel={onClose} onConfirm={save} label={t('Save rule')} />
    </Dialog>
  );
}

/** The rules of a script, or a way out when the script was written by hand. */
function RulesPanel({ script, onChange, onShowScript }: { script: string; onChange: (script: string) => void; onShowScript: () => void }) {
  const rules = useMemo(() => parseRules(script), [script]);
  const [editing, setEditing] = useState<{ index: number; rule: Rule } | null>(null);
  const [folders, setFolders] = useState<Mailbox[]>([]);
  const [labels, setLabels] = useState<string[]>([]);
  useEffect(() => {
    listMailboxes().then((list) => setFolders(list.filter((mailbox) => !mailbox.shareOwner)), () => {});
    get<string[]>('/api/me/labels').then(setLabels, () => {});
  }, []);

  if (rules === null) {
    return (
      <Alert
        severity="info"
        action={
          <Stack direction={{ xs: 'column', sm: 'row' }} spacing={1}>
            <Button color="inherit" size="small" onClick={onShowScript}>{t('Edit the script')}</Button>
            <Button color="inherit" size="small" onClick={() => window.confirm(t('Replace this script with an empty list of rules? What it does now is lost once you save.')) && onChange('')}>
              {t('Start over with rules')}
            </Button>
          </Stack>
        }
      >
        {t('This script was written or changed by hand, so it cannot be shown as rules.')}
      </Alert>
    );
  }

  const label = (name: string) => {
    const folder = folders.find((f) => f.name === name);
    return folder ? folderName(folder) : name;
  };
  const update = (next: Rule[]) => onChange(generate(next));
  const move = (index: number, by: number) => {
    const next = [...rules];
    [next[index], next[index + by]] = [next[index + by], next[index]];
    update(next);
  };

  return (
    <Stack spacing={1}>
      {rules.length === 0 ? (
        <Typography color="text.secondary">{t('No rules yet. Rules are applied from the top to every incoming message.')}</Typography>
      ) : (
        <List disablePadding aria-label={t('Filter rules')} sx={{ border: 1, borderColor: 'divider', borderRadius: 1.5, overflow: 'hidden' }}>
          {rules.map((rule, index) => (
            <ListItem
              key={index}
              divider={index < rules.length - 1}
              data-testid="rule"
              sx={{ pr: 1, gap: 1, opacity: rule.enabled ? 1 : 0.6, flexWrap: { xs: 'wrap', sm: 'nowrap' } }}
            >
              <Switch
                edge="start"
                checked={rule.enabled}
                onChange={(e) => update(rules.map((r, i) => (i === index ? { ...r, enabled: e.target.checked } : r)))}
                slotProps={{ input: { 'aria-label': t('Rule {{name}} enabled', { name: rule.name }) } }}
              />
              <ListItemText primary={rule.name} secondary={summary(rule, label)} sx={{ minWidth: 0, flex: { xs: '1 1 calc(100% - 64px)', sm: 1 } }} secondaryTypographyProps={{ sx: { overflowWrap: 'anywhere' } }} />
              <Stack direction="row" sx={{ flexShrink: 0, ml: { xs: 'auto', sm: 0 } }}>
                <IconButton size="small" aria-label={t('Move {{name}} up', { name: rule.name })} disabled={index === 0} onClick={() => move(index, -1)}><ArrowUpward fontSize="small" /></IconButton>
                <IconButton size="small" aria-label={t('Move {{name}} down', { name: rule.name })} disabled={index === rules.length - 1} onClick={() => move(index, 1)}><ArrowDownward fontSize="small" /></IconButton>
                <IconButton size="small" aria-label={t('Edit rule {{name}}', { name: rule.name })} onClick={() => setEditing({ index, rule })}><Edit fontSize="small" /></IconButton>
                <IconButton
                  size="small"
                  aria-label={t('Delete rule {{name}}', { name: rule.name })}
                  onClick={() => window.confirm(t('Delete the rule "{{name}}"?', { name: rule.name })) && update(rules.filter((_, i) => i !== index))}
                >
                  <Delete fontSize="small" />
                </IconButton>
              </Stack>
            </ListItem>
          ))}
        </List>
      )}
      <Box>
        <Button startIcon={<Add />} onClick={() => setEditing({ index: rules.length, rule: emptyRule() })}>{t('Add rule')}</Button>
      </Box>
      {editing && (
        <RuleDialog
          rule={editing.rule}
          folders={folders}
          labels={labels}
          onClose={() => setEditing(null)}
          onSave={(rule) => {
            const next = [...rules];
            next[editing.index] = rule;
            update(next);
            setEditing(null);
          }}
        />
      )}
    </Stack>
  );
}

export function FiltersCard() {
  const [names, setNames] = useState<{ name: string; active: boolean }[]>([]);
  const [name, setName] = useState('main');
  const [script, setScript] = useState('');
  const [active, setActive] = useState(false);
  const [loaded, setLoaded] = useState(false);
  const [error, setError] = useState('');
  const [saved, setSaved] = useState('');
  const [view, setView] = useState<'rules' | 'script'>('rules');

  const refreshNames = () => get<{ name: string; active: boolean }[]>('/api/me/sieve/scripts').then(setNames).catch(() => {});
  useEffect(() => {
    void refreshNames();
  }, []);
  useEffect(() => {
    get<{ script: string; active: boolean }>(`/api/me/sieve?name=${encodeURIComponent(name)}`)
      .then((data) => {
        setScript(data.script);
        setActive(data.active);
        // A script written by hand opens where it can be edited.
        setView(parseRules(data.script) === null ? 'script' : 'rules');
        setLoaded(true);
        setError('');
      })
      .catch(() => setError(t('Could not load the filter script')));
  }, [name]);
  if (!loaded) return error ? <Alert severity="error">{error}</Alert> : null;

  const change = (next: string) => {
    setScript(next);
    setSaved('');
  };

  async function save() {
    setError('');
    setSaved('');
    try {
      await put('/api/me/sieve', { name, script, active });
      setSaved(t('Filter script saved.'));
      await refreshNames();
    } catch (err) {
      // The server reports the line of the first problem, e.g. "line 3: expected ';'".
      setError(errorText(err, t('Could not save')));
    }
  }

  function addScript() {
    const next = window.prompt(t('Name of the new script (letters, digits, . - _)'))?.trim();
    if (!next) return;
    if (!/^[A-Za-z0-9._-]{1,64}$/.test(next)) {
      setError(t('Script names may contain letters, digits, ".", "-" and "_".'));
      return;
    }
    setSaved('');
    setName(next);
  }

  async function remove() {
    if (!window.confirm(t('Delete the script "{{name}}"?', { name }))) return;
    try {
      await del(`/api/me/sieve?name=${encodeURIComponent(name)}`);
    } catch {
      // A script that was never saved has nothing to delete on the server.
    }
    setSaved(t('Script "{{name}}" deleted.', { name }));
    setName('main');
    await refreshNames();
  }

  const options = names.some((n) => n.name === name) ? names : [...names, { name, active: false }];
  return (
    <Card variant="outlined">
      <CardContent>
        <Typography variant="h6">{t('Mail filters')}</Typography>
        <Typography variant="body2" color="text.secondary" sx={{ mb: 2 }}>
          {t('Rules run on the server for every incoming message: file into folders, label, flag, forward or delete. Build them as rules, or write Sieve yourself. One script is active at a time; it can pull in the others with')}{' '}
          <code>include</code>{t('. Supported extensions: fileinto, mailbox, copy, envelope, body, imap4flags, regex, variables, vacation, include.')}
        </Typography>
        <Stack spacing={2}>
          {error && <Alert severity="error">{error}</Alert>}
          {saved && <Alert severity="success">{saved}</Alert>}
          <Stack direction="row" spacing={1} alignItems="center" flexWrap="wrap" useFlexGap>
            <TextField select label={t('Script')} value={name} onChange={(e) => { setSaved(''); setName(e.target.value); }} sx={{ minWidth: 200 }}>
              {options.map((option) => (
                <MenuItem key={option.name} value={option.name}>
                  {option.name}
                  {option.active ? t(' (active)') : ''}
                </MenuItem>
              ))}
            </TextField>
            <Button onClick={addScript}>{t('New script')}</Button>
            <Button color="error" onClick={() => void remove()} disabled={!names.some((n) => n.name === name)}>
              {t('Delete script')}
            </Button>
          </Stack>
          <FormControlLabel control={<Switch checked={active} onChange={(e) => { setActive(e.target.checked); setSaved(''); }} />} label={t('Filters enabled')} />
          <Box>
            <Tabs value={view} onChange={(_, next: 'rules' | 'script') => setView(next)} aria-label={t('Filter editor')} sx={{ borderBottom: 1, borderColor: 'divider', mb: 2 }}>
              <Tab value="rules" label={t('Rules')} sx={{ textTransform: 'none' }} />
              <Tab value="script" label={t('Sieve script')} sx={{ textTransform: 'none' }} />
            </Tabs>
            {view === 'rules' ? (
              <RulesPanel script={script} onChange={change} onShowScript={() => setView('script')} />
            ) : (
              <TextField
                label={t('Sieve script')}
                value={script}
                onChange={(e) => change(e.target.value)}
                multiline
                minRows={8}
                maxRows={24}
                fullWidth
                slotProps={{ htmlInput: { spellCheck: false, style: { fontFamily: 'monospace', fontSize: 13 } } }}
              />
            )}
          </Box>
          <Stack direction="row" spacing={1}>
            <Button variant="contained" onClick={() => void save()}>
              {t('Save filters')}
            </Button>
            {view === 'script' && !script.trim() && <Button onClick={() => change(SIEVE_EXAMPLE)}>{t('Insert example')}</Button>}
          </Stack>
        </Stack>
      </CardContent>
    </Card>
  );
}
