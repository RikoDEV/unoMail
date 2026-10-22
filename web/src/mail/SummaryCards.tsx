import ConfirmationNumber from '@mui/icons-material/ConfirmationNumber';
import DirectionsBus from '@mui/icons-material/DirectionsBus';
import DirectionsCar from '@mui/icons-material/DirectionsCar';
import Flight from '@mui/icons-material/Flight';
import Hotel from '@mui/icons-material/Hotel';
import Inventory2 from '@mui/icons-material/Inventory2';
import ReceiptLong from '@mui/icons-material/ReceiptLong';
import Restaurant from '@mui/icons-material/Restaurant';
import Train from '@mui/icons-material/Train';
import { Alert, Box, Button, CircularProgress, Collapse, Link, Stack, Typography } from '@mui/material';
import { useEffect, useState, type ReactElement, type ReactNode } from 'react';
import { Link as RouterLink } from 'react-router-dom';
import { ApiError, errorText, get, patch, post } from '../api';
import { t, uiLocale } from '../i18n';
import { usePrefs } from '../prefs';

type Status = 'ordered' | 'processing' | 'shipped' | 'out_for_delivery' | 'delivered' | 'cancelled' | 'returned' | 'refunded';
const STATUSES: Record<Status, string> = {
  ordered: t('Ordered'), processing: t('Processing'), shipped: t('Shipped'), out_for_delivery: t('Out for delivery'),
  delivered: t('Delivered'), cancelled: t('Cancelled'), returned: t('Returned'), refunded: t('Refunded'),
};
type ReservationKind = 'flight' | 'lodging' | 'train' | 'bus' | 'rental_car' | 'restaurant' | 'event';
const KINDS: Record<ReservationKind, { label: string; icon: ReactElement }> = {
  flight: { label: t('Flight'), icon: <Flight color="action" sx={{ mt: 0.25 }} /> },
  lodging: { label: t('Hotel stay'), icon: <Hotel color="action" sx={{ mt: 0.25 }} /> },
  train: { label: t('Train'), icon: <Train color="action" sx={{ mt: 0.25 }} /> },
  bus: { label: t('Bus'), icon: <DirectionsBus color="action" sx={{ mt: 0.25 }} /> },
  rental_car: { label: t('Car rental'), icon: <DirectionsCar color="action" sx={{ mt: 0.25 }} /> },
  restaurant: { label: t('Table reservation'), icon: <Restaurant color="action" sx={{ mt: 0.25 }} /> },
  event: { label: t('Event'), icon: <ConfirmationNumber color="action" sx={{ mt: 0.25 }} /> },
};
const RESERVATION_STATUSES: Record<string, string> = { confirmed: t('Confirmed'), pending: t('Pending'), cancelled: t('Cancelled') };
const BILL_STATUSES: Record<string, string> = { due: t('Payment due'), overdue: t('Overdue'), paid: t('Paid') };

interface Money { amount: string; currency: string }
interface Shipment {
  tracking_number: string | null; tracking_url: string | null; carrier: string | null;
  delivery_from: string | null; delivery_until: string | null; status: Status;
}
interface Purchase { merchant: string; order_number: string; items: string[]; total: Money | null; status: Status; order_url: string | null; shipments: Shipment[] }
interface Reservation {
  kind: ReservationKind; provider: string; reservation_number: string; status: 'confirmed' | 'pending' | 'cancelled';
  name: string | null; segment: string | null; from: string | null; to: string | null; location: string | null;
  start: string | null; end: string | null; url: string | null;
}
interface Bill { biller: string; reference: string; amount: Money | null; due_date: string | null; status: 'due' | 'overdue' | 'paid'; url: string | null }
interface Source { email_id: string; thread_id: string; subject: string; method: string }
type Card = { id: number; dismissed: boolean; sources: Source[] } & (
  | { kind: 'purchase'; purchase: Purchase }
  | { kind: 'reservation'; reservation: Reservation }
  | { kind: 'bill'; bill: Bill }
);
interface CardsResponse { enabled: boolean; ai_available: boolean; suggest_ai: boolean; cards: Card[]; state: string; error: string | null }

function dateLabel(value: string) {
  // Date-only delivery estimates must not shift a day in the user's timezone.
  const date = new Date(value.length === 10 ? `${value}T12:00:00` : value);
  return date.toLocaleDateString(uiLocale(), { day: 'numeric', month: 'short', year: 'numeric' });
}
/** A date, or a date and time; a time without zone is the local time at the place it describes. */
function whenLabel(value: string) {
  if (value.length === 10) return dateLabel(value);
  return new Date(value).toLocaleString(uiLocale(), { day: 'numeric', month: 'short', year: 'numeric', hour: 'numeric', minute: '2-digit' });
}
function moneyLabel(total: Money) {
  try { return new Intl.NumberFormat(uiLocale(), { style: 'currency', currency: total.currency }).format(Number(total.amount)); }
  catch { return `${total.amount} ${total.currency}`; }
}
const external = { component: 'a', target: '_blank', rel: 'noopener noreferrer', referrerPolicy: 'no-referrer' } as const;

/** The frame every card shares: icon, heading, dismissal and the messages it was built from. */
function CardFrame({ card, icon, label, title, status, subtitle, actions, children, onDismiss }: {
  card: Card; icon: ReactElement; label: string; title: string; status: string; subtitle: string;
  actions?: ReactNode; children?: ReactNode; onDismiss: (id: number, dismissed: boolean) => void;
}) {
  const [expanded, setExpanded] = useState(false);
  if (card.dismissed) return <Button size="small" startIcon={icon} onClick={() => onDismiss(card.id, false)}>{t('Show summary card')}</Button>;
  return (
    <Box component="article" aria-label={label} sx={{ border: 1, borderColor: 'divider', borderRadius: 1, p: 1.5, my: 1.5 }}>
      <Stack direction="row" spacing={1.5} alignItems="flex-start">
        {icon}
        <Box sx={{ flex: 1, minWidth: 0 }}>
          <Typography component="h3" variant="subtitle2" sx={{ overflowWrap: 'anywhere' }}>{title}</Typography>
          <Typography variant="body2" fontWeight={600}>{status}</Typography>
          <Typography variant="caption" color="text.secondary" sx={{ overflowWrap: 'anywhere' }}>{subtitle}</Typography>
        </Box>
        <Button size="small" onClick={() => onDismiss(card.id, true)}>{t('Dismiss')}</Button>
      </Stack>
      {children}
      <Stack direction="row" spacing={1} flexWrap="wrap" useFlexGap sx={{ mt: 1 }}>
        {actions}
        <Button size="small" aria-expanded={expanded} onClick={() => setExpanded((value) => !value)}>{t('Related messages')}</Button>
      </Stack>
      <Collapse in={expanded}>
        <Stack spacing={0.5} sx={{ pt: 1 }}>
          {card.sources.map((source) => <Link key={source.email_id} component={RouterLink} to={`/mail/inbox/${source.thread_id}`} variant="body2" sx={{ overflowWrap: 'anywhere' }}>{source.subject || t('(no subject)')}</Link>)}
          <Typography variant="caption" color="text.secondary">{card.sources.some((s) => s.method === 'ai') ? t('Includes AI-extracted details. See the original messages.') : t('Details from structured email data.')}</Typography>
        </Stack>
      </Collapse>
    </Box>
  );
}

function PurchaseCard({ card, p, onDismiss }: { card: Card; p: Purchase; onDismiss: (id: number, dismissed: boolean) => void }) {
  return (
    <CardFrame card={card} onDismiss={onDismiss} icon={<Inventory2 color="action" sx={{ mt: 0.25 }} />} label={t('Purchase from {{merchant}}', { merchant: p.merchant })}
      title={p.merchant} status={STATUSES[p.status] ?? p.status} subtitle={`${t('Order {{number}}', { number: p.order_number })}${p.total ? ` · ${moneyLabel(p.total)}` : ''}`}
      actions={p.order_url && <Button size="small" {...external} href={p.order_url}>{t('View order')}</Button>}>
      {p.items.length > 0 && <Typography variant="body2" sx={{ mt: 1, overflowWrap: 'anywhere' }}>{p.items.join(' · ')}</Typography>}
      {p.shipments.map((shipment, index) => (
        <Box key={shipment.tracking_number ?? shipment.tracking_url ?? index} sx={{ mt: 1, pt: 1, borderTop: 1, borderColor: 'divider' }}>
          <Typography variant="body2">{[shipment.carrier, STATUSES[shipment.status]].filter(Boolean).join(' · ')}</Typography>
          {(shipment.delivery_from || shipment.delivery_until) && <Typography variant="body2" color="text.secondary">
            {t('Estimated delivery')}: {shipment.delivery_from ? dateLabel(shipment.delivery_from) : dateLabel(shipment.delivery_until!)}{shipment.delivery_from && shipment.delivery_until && shipment.delivery_from !== shipment.delivery_until ? ` – ${dateLabel(shipment.delivery_until)}` : ''}
          </Typography>}
          {shipment.tracking_number && <Typography variant="caption" sx={{ overflowWrap: 'anywhere' }}>{t('Tracking number')}: {shipment.tracking_number}</Typography>}
          {shipment.tracking_url && <Box><Button size="small" {...external} href={shipment.tracking_url}>{t('Track package')}</Button></Box>}
        </Box>
      ))}
    </CardFrame>
  );
}

function ReservationCard({ card, r, onDismiss }: { card: Card; r: Reservation; onDismiss: (id: number, dismissed: boolean) => void }) {
  const kind = KINDS[r.kind] ?? KINDS.event;
  const trip = r.kind === 'flight' || r.kind === 'train' || r.kind === 'bus';
  // Travel reads "From → To"; a stay, table or event leads with what was booked.
  const route = r.from && r.to ? `${r.from} → ${r.to}` : (r.from ?? r.to);
  const booked = trip ? r.segment : r.name !== r.provider ? r.name : null;
  const title = [kind.label, booked].filter(Boolean).join(' · ');
  const period = r.start ? (r.end ? `${whenLabel(r.start)} – ${whenLabel(r.end)}` : whenLabel(r.start)) : null;
  return (
    <CardFrame card={card} onDismiss={onDismiss} icon={kind.icon} label={t('{{kind}} reservation with {{provider}}', { kind: kind.label, provider: r.provider })}
      title={title} status={RESERVATION_STATUSES[r.status] ?? r.status}
      subtitle={`${r.provider} · ${t('Confirmation {{number}}', { number: r.reservation_number })}`}
      actions={r.url && <Button size="small" {...external} href={r.url}>{t('Manage reservation')}</Button>}>
      {(route || period || r.location) && (
        <Box sx={{ mt: 1 }}>
          {route && <Typography variant="body2" sx={{ overflowWrap: 'anywhere' }}>{route}</Typography>}
          {period && <Typography variant="body2" color="text.secondary">{period}</Typography>}
          {r.location && <Typography variant="body2" color="text.secondary" sx={{ overflowWrap: 'anywhere' }}>{r.location}</Typography>}
        </Box>
      )}
    </CardFrame>
  );
}

function BillCard({ card, b, onDismiss }: { card: Card; b: Bill; onDismiss: (id: number, dismissed: boolean) => void }) {
  const status = [b.amount ? moneyLabel(b.amount) : null, BILL_STATUSES[b.status] ?? b.status].filter(Boolean).join(' · ');
  return (
    <CardFrame card={card} onDismiss={onDismiss} icon={<ReceiptLong color="action" sx={{ mt: 0.25 }} />} label={t('Bill from {{biller}}', { biller: b.biller })}
      title={b.biller} status={status}
      subtitle={`${t('Reference {{number}}', { number: b.reference })}${b.due_date && b.status !== 'paid' ? ` · ${t('Due {{date}}', { date: dateLabel(b.due_date) })}` : ''}`}
      actions={b.url && <Button size="small" {...external} href={b.url}>{b.status === 'paid' ? t('View bill') : t('Pay bill')}</Button>} />
  );
}

function SummaryCard({ card, onDismiss }: { card: Card; onDismiss: (id: number, dismissed: boolean) => void }) {
  if (card.kind === 'reservation') return <ReservationCard card={card} r={card.reservation} onDismiss={onDismiss} />;
  if (card.kind === 'bill') return <BillCard card={card} b={card.bill} onDismiss={onDismiss} />;
  return <PurchaseCard card={card} p={card.purchase} onDismiss={onDismiss} />;
}

export function SummaryCards({ emailId }: { emailId: string }) {
  const prefs = usePrefs();
  const [data, setData] = useState<CardsResponse | null>(null);
  const [error, setError] = useState('');
  const [version, setVersion] = useState(0);
  const enabled = prefs.summary_cards !== false;
  useEffect(() => {
    if (!enabled) return;
    let active = true;
    let timer: ReturnType<typeof setTimeout> | undefined;
    let queued = false;
    async function load() {
      try {
        const result = await get<CardsResponse>(`/api/me/summary-cards?email_id=${encodeURIComponent(emailId)}`);
        if (!active) return;
        setData(result);
        setError('');
        if (!result.enabled) return;
        if (result.state === 'unprocessed' && !queued) {
          queued = true;
          await post('/api/me/summary-cards/extract', { email_id: emailId });
          if (!active) return;
          timer = setTimeout(load, 2000);
        } else if (result.state === 'pending' || result.state === 'running' || result.cards.length > 0) {
          timer = setTimeout(load, result.state === 'pending' || result.state === 'running' ? 2000 : 30_000);
        }
      } catch (err) {
        if (active && !(err instanceof ApiError && err.status === 404)) setError(errorText(err, t('Could not load summary cards')));
      }
    }
    void load();
    return () => { active = false; clearTimeout(timer); };
  }, [emailId, enabled, version]);

  async function dismiss(id: number, dismissed: boolean) {
    try {
      await patch(`/api/me/summary-cards/${id}`, { dismissed });
      setData((old) => old && { ...old, cards: old.cards.map((c) => c.id === id ? { ...c, dismissed } : c) });
    } catch (err) { setError(errorText(err, t('Could not update summary card'))); }
  }
  async function extract() {
    try {
      await post('/api/me/summary-cards/extract', { email_id: emailId, use_ai: true });
      setData((old) => old && { ...old, state: 'pending' });
      setVersion((old) => old + 1);
    } catch (err) { setError(errorText(err, t('Could not extract summary card'))); }
  }
  if (!enabled || data?.enabled === false || (!error && !data?.error && !data?.cards.length && !(data?.ai_available && data.suggest_ai))) return null;
  const pending = data?.state === 'pending' || data?.state === 'running';
  return (
    <Box component="section" aria-label={t('Summary cards')}>
      {error && <Alert severity="error" onClose={() => setError('')}>{error}</Alert>}
      {data?.cards.map((card) => <SummaryCard key={card.id} card={card} onDismiss={(id, dismissed) => void dismiss(id, dismissed)} />)}
      {data?.error && <Alert severity="warning">{t('Summary card extraction failed. You can retry.')}</Alert>}
      {data?.ai_available && data.suggest_ai && data.cards.length === 0 && <Button size="small" disabled={pending} onClick={() => void extract()} startIcon={pending ? <CircularProgress size={14} /> : <Inventory2 />}>{t('Extract summary card with AI')}</Button>}
    </Box>
  );
}
