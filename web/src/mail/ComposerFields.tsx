// The address and subject fields of the composer, with recipient suggestions.

import {
  Box, Chip, InputBase, ListItemText, MenuItem, Paper,
  Stack, Typography,
} from '@mui/material';
import { type ReactNode, useEffect, useState } from 'react';
import { applySuggestion, splitRecipients, suggestRecipients, type Suggestion, suggestionText } from './extra';

import { t } from '../i18n';

/** The inset look of the composer's header fields: a line under each, not reaching the edges. */
export const FIELD_ROW = { borderBottom: 1, borderColor: 'divider', mx: 2, minHeight: 48 } as const;

export function Field({ label, value, onChange, autoFocus }: { label: string; value: string; onChange: (value: string) => void; autoFocus?: boolean }) {
  return (
    <Stack direction="row" alignItems="center" sx={FIELD_ROW}>
      <InputBase fullWidth value={value} placeholder={label} onChange={(e) => onChange(e.target.value)} autoFocus={autoFocus} inputProps={{ 'aria-label': label }} />
    </Stack>
  );
}

/** A recipient field that suggests contacts, groups and directory entries while typing. */
export function RecipientField({ label, placeholder, value, onChange, autoFocus, end }: { label: string; placeholder?: string; value: string; onChange: (value: string) => void; autoFocus?: boolean; end?: ReactNode }) {
  const [options, setOptions] = useState<Suggestion[]>([]);
  const [active, setActive] = useState(0);
  // Suggestions follow what the user types, never a value that was filled in for them.
  const [typed, setTyped] = useState(false);
  const fragment = splitRecipients(value).current;
  const listId = `suggestions-${label.toLowerCase()}`;

  useEffect(() => {
    if (!typed || fragment.length < 2) {
      setOptions([]);
      return;
    }
    let cancelled = false;
    const timer = setTimeout(() => {
      suggestRecipients(fragment)
        .then((found) => {
          if (cancelled) return;
          setOptions(found.slice(0, 8));
          setActive(0);
        })
        .catch(() => !cancelled && setOptions([]));
    }, 180);
    return () => {
      cancelled = true;
      clearTimeout(timer);
    };
  }, [fragment, typed]);

  const choose = (suggestion: Suggestion) => {
    onChange(applySuggestion(value, suggestion));
    setTyped(false);
    setOptions([]);
  };
  const open = options.length > 0;
  return (
    <Box sx={{ position: 'relative' }}>
      <Stack direction="row" alignItems="center" sx={FIELD_ROW}>
        {value && (
          <Typography variant="body2" color="text.secondary" sx={{ mr: 1 }}>
            {label}
          </Typography>
        )}
        <InputBase
          fullWidth
          value={value}
          placeholder={placeholder ?? label}
          autoFocus={autoFocus}
          onChange={(e) => {
            setTyped(true);
            onChange(e.target.value);
          }}
          onBlur={() => setOptions([])}
          onKeyDown={(e) => {
            if (!open) return;
            if (e.key === 'ArrowDown' || e.key === 'ArrowUp') {
              e.preventDefault();
              setActive((index) => (index + (e.key === 'ArrowDown' ? 1 : options.length - 1)) % options.length);
            } else if (e.key === 'Enter' || e.key === 'Tab') {
              e.preventDefault();
              choose(options[active]);
            } else if (e.key === 'Escape') {
              e.stopPropagation();
              setOptions([]);
            }
          }}
          inputProps={{ 'aria-label': label, role: 'combobox', 'aria-expanded': open, 'aria-controls': listId, 'aria-autocomplete': 'list', autoComplete: 'off' }}
        />
        {end}
      </Stack>
      {open && (
        <Paper id={listId} role="listbox" aria-label={t('Suggested recipients')} elevation={6} sx={{ position: 'absolute', left: 16, right: 16, top: '100%', zIndex: 2, borderRadius: 1, py: 0.5, maxHeight: 260, overflow: 'auto' }}>
          {options.map((option, index) => (
            <MenuItem
              key={`${option.source}-${suggestionText(option)}`}
              role="option"
              aria-selected={index === active}
              selected={index === active}
              dense
              // mousedown, not click: the field must not lose focus (and close the list) first.
              onMouseDown={(e) => {
                e.preventDefault();
                choose(option);
              }}
            >
              <ListItemText
                primary={option.source === 'group' ? `${option.name} (${option.members.length === 1 ? '1 person' : t('{{count}} people', { count: option.members.length })})` : option.name || option.email}
                secondary={option.source === 'group' ? t('Group') : option.name ? option.email : undefined}
                primaryTypographyProps={{ noWrap: true }}
                secondaryTypographyProps={{ noWrap: true }}
              />
              {option.source !== 'contact' && option.source !== 'group' && <Chip size="small" label={option.source === 'ldap' ? t('Directory') : t('Colleague')} sx={{ ml: 1 }} />}
            </MenuItem>
          ))}
        </Paper>
      )}
    </Box>
  );
}

