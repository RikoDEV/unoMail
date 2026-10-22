import { Box, Dialog, DialogContent, DialogTitle, Stack, TextField } from '@mui/material';
import { DialogButtons } from '../admin/common';
import { t } from '../i18n';
import { LABEL_COLORS } from './extra';
import { normalizeLabel } from './jmapClient';
import type { LabelDialogState } from './MailSidebar';

/** Creates a label, or changes the colour of one. */
export function LabelDialog({ value, onChange, onClose, onSave }: {
  value: LabelDialogState;
  onChange: (value: LabelDialogState) => void;
  onClose: () => void;
  onSave: (name: string, color: string) => void;
}) {
  return (
    <Dialog open onClose={onClose} fullWidth maxWidth="xs">
      <DialogTitle>{value.existing ? t('Label “{{name}}”', { name: value.name }) : t('New label')}</DialogTitle>
      <DialogContent>
        <Stack spacing={2} sx={{ mt: 1 }}>
          {!value.existing && (
            <TextField
              autoFocus
              label={t('Label name')}
              value={value.name}
              onChange={(e) => onChange({ ...value, name: e.target.value })}
              error={Boolean(value.name) && !normalizeLabel(value.name)}
              helperText={t('Letters, digits, - _ . (spaces become dashes)')}
            />
          )}
          <Stack direction="row" flexWrap="wrap" gap={1} role="radiogroup" aria-label={t('Label colour')}>
            {LABEL_COLORS.map((color) => (
              <Box
                key={color || 'none'}
                component="button"
                role="radio"
                aria-checked={value.color === color}
                aria-label={color ? t('Colour {{color}}', { color }) : t('No colour')}
                onClick={() => onChange({ ...value, color })}
                sx={{ width: 28, height: 28, borderRadius: '50%', cursor: 'pointer', p: 0, bgcolor: color || 'transparent', border: 3, borderColor: value.color === color ? 'text.primary' : color ? 'transparent' : 'divider' }}
              />
            ))}
          </Stack>
        </Stack>
      </DialogContent>
      <DialogButtons
        onCancel={onClose}
        disabled={!normalizeLabel(value.name)}
        label={t('Save label')}
        onConfirm={() => onSave(normalizeLabel(value.name)!, value.color)}
      />
    </Dialog>
  );
}
