import Delete from '@mui/icons-material/Delete';
import { Box, Button, Checkbox, IconButton, MenuItem, Stack, TextField, Tooltip, Typography } from '@mui/material';
import { useCallback, useEffect, useState } from 'react';
import { del, get, post, put, errorText } from '../lib/api';
import { COLORS, dayKey, type Calendar, type Task } from './dates';
import {  } from './dialogs';

import { t } from '../i18n';
/** To-dos: the same ones calendar programs keep in these calendars. */
export function TasksView({ calendars, hidden, onNotice }: { calendars: Calendar[]; hidden: number[]; onNotice: (text: string) => void }) {
  const [tasks, setTasks] = useState<Task[]>([]);
  const [summary, setSummary] = useState('');
  const [due, setDue] = useState('');
  const writable = calendars.filter((calendar) => calendar.writable);
  const [target, setTarget] = useState<number | ''>('');
  const calendarId = target || writable[0]?.id;
  const today = dayKey(new Date());

  const load = useCallback(async () => {
    try {
      setTasks(await get<Task[]>('/api/me/calendars/tasks'));
    } catch (err) {
      onNotice(errorText(err, t('The tasks could not be loaded')));
    }
  }, [onNotice]);

  useEffect(() => {
    void load();
    const onFocus = () => void load();
    window.addEventListener('focus', onFocus);
    return () => window.removeEventListener('focus', onFocus);
  }, [load]);

  async function run(action: () => Promise<unknown>) {
    try {
      await action();
    } catch (err) {
      onNotice(errorText(err, t('The task could not be saved')));
    }
    await load();
  }

  async function add() {
    if (!summary.trim() || !calendarId) return;
    const task = { summary, due };
    // Cleared at once, so the next task can be typed while this one is being saved.
    setSummary('');
    setDue('');
    await run(() => post(`/api/me/calendars/${calendarId}/tasks`, task));
  }

  const save = (task: Task, changes: Partial<Task>) => {
    // Shown at once; the list is re-sorted when the server has answered.
    setTasks((current) => current.map((entry) => (entry.id === task.id ? { ...entry, ...changes } : entry)));
    return run(() => put(`/api/me/calendars/${task.calendar_id}/tasks/${task.id}`, { summary: task.summary, description: task.description, due: task.due, completed: task.completed, ...changes }));
  };

  const byId = new Map(calendars.map((calendar) => [calendar.id, calendar]));
  const shown = tasks.filter((task) => !hidden.includes(task.calendar_id));
  return (
    <Box sx={{ flex: 1, minHeight: 0, overflow: 'auto', p: 2 }}>
      <Stack
        component="form"
        direction={{ xs: 'column', sm: 'row' }}
        spacing={1}
        sx={{ mb: 2, maxWidth: 900 }}
        onSubmit={(e) => {
          e.preventDefault();
          void add();
        }}
      >
        <TextField label={t('New task')} size="small" value={summary} onChange={(e) => setSummary(e.target.value)} sx={{ flex: 1 }} slotProps={{
          htmlInput: { maxLength: 300 }
        }} />
        <TextField label={t('Due')} type="date" size="small" value={due} onChange={(e) => setDue(e.target.value)} slotProps={{
          inputLabel: { shrink: true }
        }} />
        {writable.length > 1 && (
          <TextField select label={t('In')} size="small" value={calendarId ?? ''} onChange={(e) => setTarget(Number(e.target.value))} sx={{ minWidth: 150 }}>
            {writable.map((calendar) => (
              <MenuItem key={calendar.id} value={calendar.id}>{calendar.name}</MenuItem>
            ))}
          </TextField>
        )}
        <Button type="submit" variant="contained" disabled={!summary.trim() || !calendarId}>{t('Add')}</Button>
      </Stack>
      {shown.length === 0 && <Typography
        sx={{ color: 'text.secondary', p: 2 }}>{t('No tasks. Tasks added in a calendar program show up here too.')}</Typography>}
      <Box component="ul" aria-label={t('Tasks')} sx={{ listStyle: 'none', m: 0, p: 0, maxWidth: 900 }}>
        {shown.map((task) => {
          const calendar = byId.get(task.calendar_id);
          const editable = calendar?.writable ?? false;
          const overdue = !task.completed && task.due !== '' && task.due < today;
          return (
            <Stack key={task.id} component="li" direction="row" spacing={1} data-testid="task" data-completed={task.completed} sx={{ alignItems: 'center', py: 0.5, borderBottom: 1, borderColor: 'divider' }}>
              <Checkbox
                checked={task.completed}
                disabled={!editable}
                onChange={(e) => void save(task, { completed: e.target.checked })}
                slotProps={{ input: { 'aria-label': task.completed ? t('Reopen {{summary}}', { summary: task.summary }) : t('Complete {{summary}}', { summary: task.summary }) } }}
                sx={{ color: calendar?.color.slice(0, 7) || COLORS[0], '&.Mui-checked': { color: calendar?.color.slice(0, 7) || COLORS[0] } }}
              />
              <Box sx={{ flex: 1, minWidth: 0 }}>
                <Typography noWrap sx={{ textDecoration: task.completed ? 'line-through' : undefined, color: task.completed ? 'text.secondary' : 'text.primary' }}>{task.summary}</Typography>
                {task.description && <Typography variant="body2" noWrap sx={{ color: 'text.secondary' }}>{task.description}</Typography>}
              </Box>
              {overdue && <Typography variant="caption" color="error">{t('overdue')}</Typography>}
              <TextField
                type="date"
                size="small"
                variant="standard"
                value={task.due}
                disabled={!editable}
                onChange={(e) => void save(task, { due: e.target.value })}
                sx={{ width: 140 }}
                slotProps={{
                  htmlInput: { 'aria-label': t('Due date of {{summary}}', { summary: task.summary }) }
                }}
              />
              <Tooltip title={t('Delete')}>
                <span>
                  <IconButton size="small" aria-label={t('Delete {{summary}}', { summary: task.summary })} disabled={!editable} onClick={() => void run(() => del(`/api/me/calendars/${task.calendar_id}/events/${task.id}`))}>
                    <Delete fontSize="small" />
                  </IconButton>
                </span>
              </Tooltip>
            </Stack>
          );
        })}
      </Box>
    </Box>
  );
}
