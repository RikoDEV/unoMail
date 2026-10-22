// Building blocks shared by the settings cards.

import Delete from '@mui/icons-material/Delete';
import Edit from '@mui/icons-material/Edit';
import {
  Alert, Button, Card, CardContent, IconButton, Stack,
  TableCell, Typography,
} from '@mui/material';
import { type ReactNode } from 'react';


/** A settings card listing things the user adds, edits and deletes. */
export function ListCard({ title, addLabel, onAdd, error, onDismiss, children }: { title: string; addLabel: string; onAdd: () => void; error: string; onDismiss: () => void; children: ReactNode }) {
  return (
    <Card variant="outlined">
      <CardContent>
        <Stack direction="row" alignItems="center" sx={{ mb: 1 }}>
          <Typography variant="h6" sx={{ flex: 1 }}>
            {title}
          </Typography>
          <Button onClick={onAdd}>{addLabel}</Button>
        </Stack>
        {error && <Alert severity="error" onClose={onDismiss} sx={{ mb: 1 }}>{error}</Alert>}
        {children}
      </CardContent>
    </Card>
  );
}

/** The edit and delete buttons at the end of a row; deleting asks first. Without `onDelete` there is no delete button. */
export function RowActions({ editLabel, onEdit, deleteLabel, confirm, onDelete }: { editLabel: string; onEdit: () => void; deleteLabel?: string; confirm?: string; onDelete?: () => void }) {
  return (
    <TableCell align="right" sx={{ whiteSpace: 'nowrap' }}>
      <IconButton size="small" aria-label={editLabel} onClick={onEdit}>
        <Edit fontSize="small" />
      </IconButton>
      {onDelete && (
        <IconButton size="small" aria-label={deleteLabel} onClick={() => (!confirm || window.confirm(confirm)) && onDelete()}>
          <Delete fontSize="small" />
        </IconButton>
      )}
    </TableCell>
  );
}

