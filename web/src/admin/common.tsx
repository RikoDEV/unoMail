import { LinearProgress } from '../ui/progress';
import { Alert, Box, Button, Chip, Dialog, DialogActions, DialogContent, DialogContentText, DialogTitle, Snackbar, Stack, Table, TableBody, TableCell, TableContainer, TableHead, TablePagination, type TableProps, TableRow, TableSortLabel, Typography, useMediaQuery, useTheme } from '@mui/material';
import { Children, cloneElement, Fragment, isValidElement, type ReactElement, type ReactNode, type RefObject, useCallback, useEffect, useRef, useState } from 'react';

import { t, uiLocale } from '../i18n';
import { useTitle } from '../ui/shell';
import { errorText } from '../lib/api';
export { useLoad } from '../lib/useLoad';

/** Wraps mutations: shows failures inline and successes as a toast. */
export function useAction() {
  const [error, setError] = useState('');
  const [message, setMessage] = useState('');
  const run = useCallback(async (action: () => Promise<unknown>, success?: string): Promise<boolean> => {
    setError('');
    try {
      await action();
      if (success) setMessage(success);
      return true;
    } catch (err) {
      setError(errorText(err, t('The operation failed')));
      return false;
    }
  }, []);
  const feedback = (
    <>
      {error && (
        <Alert severity="error" onClose={() => setError('')} sx={{ mb: 2 }}>
          {error}
        </Alert>
      )}
      <Snackbar open={Boolean(message)} autoHideDuration={3500} onClose={() => setMessage('')} message={message} />
    </>
  );
  return { run, feedback, setError, notify: setMessage };
}

/**
 * Submits a form shown in a dialog. A failure is shown in the dialog, under the field it is
 * about (`route` picks it from the server's message) or above the form, never on the page
 * behind the dialog. It disappears once the form is changed.
 */
export function useFormAction<Field extends string>(route: (message: string) => Field | null) {
  const [failure, setFailure] = useState<{ field: Field | null; message: string } | null>(null);
  const [busy, setBusy] = useState(false);
  const run = async (action: () => Promise<unknown>): Promise<boolean> => {
    setFailure(null);
    setBusy(true);
    try {
      await action();
      return true;
    } catch (err) {
      const message = errorText(err, t('The operation failed'));
      // Server messages start in lower case; under a field they read as a sentence.
      setFailure({ field: route(message), message: message.charAt(0).toUpperCase() + message.slice(1) });
      return false;
    } finally {
      setBusy(false);
    }
  };
  return {
    run,
    busy,
    /** The failure to show under `field`, if it is about that field. */
    fieldError: (field: Field) => (failure?.field === field ? failure.message : ''),
    /** A failure that is about no single field, for the top of the form. */
    formError: failure && !failure.field ? <Alert severity="error" sx={{ mb: 2 }}>{failure.message}</Alert> : null,
    clear: () => setFailure(null),
  };
}

/** Picks the field a server message is about: the first whose pattern matches it. */
export const routeBy =
  <Field extends string>(patterns: [RegExp, Field][], fallback: Field | null = null) =>
  (message: string): Field | null =>
    patterns.find(([pattern]) => pattern.test(message))?.[1] ?? fallback;

export function PageHeader({ title, children }: { title: string; children?: ReactNode }) {
  useTitle(title, t('Administration'));
  return (
    <Stack direction="row" spacing={2} useFlexGap sx={{ alignItems: 'center', flexWrap: 'wrap', mb: 2 }}>
      <Typography variant="h5" component="h1" sx={{ flex: 1 }}>
        {title}
      </Typography>
      {children}
    </Stack>
  );
}

const STATUS_COLORS: Record<string, 'success' | 'warning' | 'error' | 'default' | 'info'> = {
  ok: 'success', delivered: 'success', warning: 'warning', deferred: 'warning', junk: 'warning', queued: 'info',
  error: 'error', bounced: 'error', rejected: 'error', unknown: 'default',
};

export function StatusChip({ status }: { status: string }) {
  return <Chip size="small" label={status} color={STATUS_COLORS[status] ?? 'default'} variant={status === 'unknown' ? 'outlined' : 'filled'} />;
}

export function ConfirmDialog({ open, title, text, confirmLabel = t('Delete'), onConfirm, onClose }: { open: boolean; title: string; text: string; confirmLabel?: string; onConfirm: () => void; onClose: () => void }) {
  return (
    <Dialog open={open} onClose={onClose}>
      <DialogTitle>{title}</DialogTitle>
      <DialogContent>
        <DialogContentText>{text}</DialogContentText>
      </DialogContent>
      <DialogActions>
        <Button onClick={onClose}>{t('Cancel')}</Button>
        <Button color="error" variant="contained" onClick={onConfirm}>
          {confirmLabel}
        </Button>
      </DialogActions>
    </Dialog>
  );
}

/** Inline validation helpers shared by the forms. */
export const validators = {
  domain: (v: string) => (/^(?!-)[a-z0-9-]{1,63}(?<!-)(\.(?!-)[a-z0-9-]{1,63}(?<!-))+$/i.test(v.trim()) ? '' : t('Enter a valid domain name, e.g. example.com')),
  // Letters and digits of any script are valid in the local part (internationalized addresses).
  email: (v: string) => (/^[\p{L}\p{N}._+-]+@[\p{L}\p{N}-]+(\.[\p{L}\p{N}-]+)+$/u.test(v.trim()) ? '' : t('Enter a valid e-mail address')),
  password: (v: string) => (v.length >= 10 ? '' : t('Use at least 10 characters')),
};

/** A table that scrolls sideways inside its own box when the screen is too narrow for it. */
type Props = { children?: ReactNode; label?: ReactNode; 'data-sort'?: string | number };

/** Plain text of a rendered cell, used as its sort key unless the cell sets `data-sort`. */
function sortText(node: ReactNode): string {
  if (node == null || typeof node === 'boolean') return '';
  if (typeof node === 'string' || typeof node === 'number') return String(node);
  if (Array.isArray(node)) return node.map(sortText).join(' ');
  if (isValidElement<Props>(node)) return [sortText(node.props.children), sortText(node.props.label)].join(' ').trim();
  return '';
}

/** A row's cells, with those grouped in a fragment counted one by one. */
const cells = (children: ReactNode) => Children.toArray(children).flatMap((cell) => (isValidElement<Props>(cell) && cell.type === Fragment ? Children.toArray(cell.props.children) : [cell]));

function sortKey(row: ReactNode, column: number): string | number {
  if (!isValidElement<Props>(row)) return '';
  // A row with a detail line under it comes as a fragment: sort by its first row.
  if (row.type === Fragment) return sortKey(Children.toArray(row.props.children)[0], column);
  const cell = cells(row.props.children)[column];
  if (!isValidElement<Props>(cell)) return '';
  return cell.props['data-sort'] ?? sortText(cell.props.children);
}

const collator = new Intl.Collator(undefined, { numeric: true, sensitivity: 'base' });

/** Admin table that scrolls sideways on narrow screens; clicking a column title sorts the rows by it. */
export function ScrollTable({ children, ...props }: TableProps) {
  const [sort, setSort] = useState<{ column: number; desc: boolean } | null>(null);
  const parts = Children.map(children, (part) => {
    if (!isValidElement<Props>(part)) return part;
    if (part.type === TableHead) {
      return cloneElement(part, {}, Children.map(part.props.children, (row) => {
        if (!isValidElement<Props>(row) || row.type !== TableRow) return row;
        return cloneElement(row, {}, Children.toArray(row.props.children).map((cell, column) => {
          const element = cell as ReactElement<Props>;
          if (!isValidElement(cell) || cell.type !== TableCell || !sortText(element.props.children)) return cell;
          const active = sort?.column === column;
          return cloneElement(element, { sortDirection: active ? (sort.desc ? 'desc' : 'asc') : false } as Props, (
            <TableSortLabel active={active} direction={active && sort.desc ? 'desc' : 'asc'} onClick={() => setSort(active && sort.desc ? null : { column, desc: active })}>
              {element.props.children}
            </TableSortLabel>
          ));
        }));
      }));
    }
    if (part.type === TableBody && sort) {
      const rows = Children.toArray(part.props.children);
      rows.sort((a, b) => {
        const [x, y] = [sortKey(a, sort.column), sortKey(b, sort.column)];
        if (x === '' || y === '') return x === y ? 0 : x === '' ? 1 : -1;
        const order = typeof x === 'number' && typeof y === 'number' ? x - y : collator.compare(String(x), String(y));
        return sort.desc ? -order : order;
      });
      return cloneElement(part, {}, rows);
    }
    return part;
  });
  return (
    <TableContainer sx={{ maxWidth: '100%', overflowX: 'auto' }}>
      {/* Headings stay on one line; the table scrolls sideways instead. */}
      <Table {...props} sx={[{ '& thead th': { whiteSpace: 'nowrap' } }, ...(Array.isArray(props.sx) ? props.sx : [props.sx])]}>{parts}</Table>
    </TableContainer>
  );
}

/** Whether tables should move long text out of their columns, onto a line under each row. */
export function useCompactTable() {
  const theme = useTheme();
  return useMediaQuery(theme.breakpoints.down('md'));
}

/**
 * A table row whose long text (an error, a log message) is a column on wide screens and a
 * full-width line under the row on narrow ones. `cells` leaves that column out when compact.
 */
export function rowWithDetail(key: string | number, compact: boolean, cells: ReactNode, label: string, detail: string | null | undefined, columns: number) {
  return (
    <Fragment key={key}>
      <TableRow sx={compact && detail ? { '& td': { borderBottom: 0 } } : undefined}>{cells}</TableRow>
      {compact && detail && (
        <TableRow>
          <TableCell colSpan={columns} sx={{ pt: 0 }}>
            {/* Stays in view while the wide table scrolls sideways. */}
            <Box sx={{ position: 'sticky', left: 16, maxWidth: 'calc(100vw - 64px)', overflowWrap: 'anywhere' }}>
              <Typography variant="caption" sx={{ color: 'text.secondary' }}>{label}: </Typography>
              <Typography variant="body2" component="span">{detail}</Typography>
            </Box>
          </TableCell>
        </TableRow>
      )}
    </Fragment>
  );
}

/** How much of an hourly limit has been used, turning orange and then red as it fills. */
export function UsageBar({ label, used, limit }: { label: string; used: number; limit: number }) {
  const share = limit > 0 ? used / limit : 0;
  return (
    <>
      <Typography variant="caption" sx={{ display: 'block' }}>
        {t('{{label}}: {{used}} of {{limit}}', { label, used: used.toLocaleString(uiLocale()), limit: limit.toLocaleString(uiLocale()) })}
      </Typography>
      <LinearProgress variant="determinate" value={Math.min(100, share * 100)} color={share >= 0.9 ? 'error' : share >= 0.7 ? 'warning' : 'primary'} />
    </>
  );
}

/** The width of an element as it resizes (at least 280px), for charts drawn to fit. */
export function useElementWidth(initial: number): [RefObject<HTMLDivElement | null>, number] {
  const holder = useRef<HTMLDivElement>(null);
  const [width, setWidth] = useState(initial);
  useEffect(() => {
    const element = holder.current;
    if (!element) return;
    const observer = new ResizeObserver(([entry]) => setWidth(Math.max(280, Math.floor(entry.contentRect.width))));
    observer.observe(element);
    return () => observer.disconnect();
  }, []);
  return [holder, width];
}

/** The Cancel and confirm buttons at the foot of a dialog (the confirm button submits its form when `submit`). */
export function DialogButtons({ onCancel, onConfirm, label = t('Save'), disabled, cancelDisabled, submit }: {
  onCancel: () => void;
  onConfirm?: () => void;
  label?: ReactNode;
  disabled?: boolean;
  cancelDisabled?: boolean;
  submit?: boolean;
}) {
  return (
    <DialogActions>
      <Button onClick={onCancel} disabled={cancelDisabled}>{t('Cancel')}</Button>
      <Button variant="contained" type={submit ? 'submit' : 'button'} onClick={onConfirm} disabled={disabled}>{label}</Button>
    </DialogActions>
  );
}

/** A long list shown a page at a time: the rows of the current page and the pager below them. */
export function usePaged<T>(items: T[], label: string): { visible: T[]; pager: ReactElement; firstPage: () => void } {
  const [page, setPage] = useState(0);
  const [rowsPerPage, setRowsPerPage] = useState(25);
  // Removing rows can leave the page past the end; show the last one instead.
  const current = Math.min(page, Math.max(0, Math.ceil(items.length / rowsPerPage) - 1));
  const pager = (
    <TablePagination
      component="div"
      count={items.length}
      page={current}
      onPageChange={(_event, next) => setPage(next)}
      rowsPerPage={rowsPerPage}
      onRowsPerPageChange={(event) => { setRowsPerPage(Number(event.target.value)); setPage(0); }}
      rowsPerPageOptions={[25, 50, 100]}
      labelRowsPerPage={label}
    />
  );
  return { visible: items.slice(current * rowsPerPage, (current + 1) * rowsPerPage), pager, firstPage: () => setPage(0) };
}
