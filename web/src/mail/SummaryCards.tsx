import Inventory2 from '@mui/icons-material/Inventory2';
import { Alert, Box, Button, CircularProgress, Collapse, Link, Stack, Typography } from '@mui/material';
import { useEffect, useState } from 'react';
import { Link as RouterLink } from 'react-router-dom';
import { ApiError, errorText, get, patch, post } from '../api';
import { t, uiLocale } from '../i18n';
import { usePrefs } from '../prefs';

type Status = 'ordered' | 'processing' | 'shipped' | 'out_for_delivery' | 'delivered' | 'cancelled' | 'returned' | 'refunded';
const STATUSES: Record<Status, string> = {
  ordered: t('Ordered'), processing: t('Processing'), shipped: t('Shipped'), out_for_delivery: t('Out for delivery'),
  delivered: t('Delivered'), cancelled: t('Cancelled'), returned: t('Returned'), refunded: t('Refunded'),
};
interface Shipment {
  tracking_number: string | null; tracking_url: string | null; carrier: string | null;
  delivery_from: string | null; delivery_until: string | null; status: Status;
}
interface Card {
  id: number; dismissed: boolean;
  purchase: { merchant: string; order_number: string; items: string[]; total: { amount: string; currency: string } | null; status: Status; order_url: string | null; shipments: Shipment[] };
  sources: { email_id: string; thread_id: string; subject: string; method: string }[];
}
interface CardsResponse { enabled: boolean; ai_available: boolean; suggest_ai: boolean; cards: Card[]; state: string; error: string | null }

function dateLabel(value: string) {
  // Date-only delivery estimates must not shift a day in the user's timezone.
  const date = new Date(value.length === 10 ? `${value}T12:00:00` : value);
  return date.toLocaleDateString(uiLocale(), { day: 'numeric', month: 'short', year: 'numeric' });
}
function totalLabel(total: { amount: string; currency: string }) {
  try { return new Intl.NumberFormat(uiLocale(), { style: 'currency', currency: total.currency }).format(Number(total.amount)); }
  catch { return `${total.amount} ${total.currency}`; }
}

function PurchaseCard({ card, onDismiss }: { card: Card; onDismiss: (id: number, dismissed: boolean) => void }) {
  const [expanded, setExpanded] = useState(false);
  const p = card.purchase;
  if (card.dismissed) return <Button size="small" startIcon={<Inventory2 />} onClick={() => onDismiss(card.id, false)}>{t('Show purchase card')}</Button>;
  return (
    <Box component="article" aria-label={t('Purchase from {{merchant}}', { merchant: p.merchant })} sx={{ border: 1, borderColor: 'divider', borderRadius: 1, p: 1.5, my: 1.5 }}>
      <Stack direction="row" spacing={1.5} alignItems="flex-start">
        <Inventory2 color="action" sx={{ mt: 0.25 }} />
        <Box sx={{ flex: 1, minWidth: 0 }}>
          <Typography component="h3" variant="subtitle2" sx={{ overflowWrap: 'anywhere' }}>{p.merchant}</Typography>
          <Typography variant="body2" fontWeight={600}>{STATUSES[p.status] ?? p.status}</Typography>
          <Typography variant="caption" color="text.secondary" sx={{ overflowWrap: 'anywhere' }}>{t('Order {{number}}', { number: p.order_number })}{p.total ? ` · ${totalLabel(p.total)}` : ''}</Typography>
        </Box>
        <Button size="small" onClick={() => onDismiss(card.id, true)}>{t('Dismiss')}</Button>
      </Stack>
      {p.items.length > 0 && <Typography variant="body2" sx={{ mt: 1, overflowWrap: 'anywhere' }}>{p.items.join(' · ')}</Typography>}
      {p.shipments.map((shipment, index) => (
        <Box key={shipment.tracking_number ?? shipment.tracking_url ?? index} sx={{ mt: 1, pt: 1, borderTop: 1, borderColor: 'divider' }}>
          <Typography variant="body2">{[shipment.carrier, STATUSES[shipment.status]].filter(Boolean).join(' · ')}</Typography>
          {(shipment.delivery_from || shipment.delivery_until) && <Typography variant="body2" color="text.secondary">
            {t('Estimated delivery')}: {shipment.delivery_from ? dateLabel(shipment.delivery_from) : dateLabel(shipment.delivery_until!)}{shipment.delivery_from && shipment.delivery_until && shipment.delivery_from !== shipment.delivery_until ? ` – ${dateLabel(shipment.delivery_until)}` : ''}
          </Typography>}
          {shipment.tracking_number && <Typography variant="caption" sx={{ overflowWrap: 'anywhere' }}>{t('Tracking number')}: {shipment.tracking_number}</Typography>}
          {shipment.tracking_url && <Box><Button size="small" component="a" href={shipment.tracking_url} target="_blank" rel="noopener noreferrer" referrerPolicy="no-referrer">{t('Track package')}</Button></Box>}
        </Box>
      ))}
      <Stack direction="row" spacing={1} flexWrap="wrap" useFlexGap sx={{ mt: 1 }}>
        {p.order_url && <Button size="small" component="a" href={p.order_url} target="_blank" rel="noopener noreferrer" referrerPolicy="no-referrer">{t('View order')}</Button>}
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
        if (active && !(err instanceof ApiError && err.status === 404)) setError(errorText(err, t('Could not load purchase cards')));
      }
    }
    void load();
    return () => { active = false; clearTimeout(timer); };
  }, [emailId, enabled, version]);

  async function dismiss(id: number, dismissed: boolean) {
    try {
      await patch(`/api/me/summary-cards/${id}`, { dismissed });
      setData((old) => old && { ...old, cards: old.cards.map((c) => c.id === id ? { ...c, dismissed } : c) });
    } catch (err) { setError(errorText(err, t('Could not update purchase card'))); }
  }
  async function extract() {
    try {
      await post('/api/me/summary-cards/extract', { email_id: emailId, use_ai: true });
      setData((old) => old && { ...old, state: 'pending' });
      setVersion((old) => old + 1);
    } catch (err) { setError(errorText(err, t('Could not extract purchase card'))); }
  }
  if (!enabled || data?.enabled === false || (!error && !data?.error && !data?.cards.length && !(data?.ai_available && data.suggest_ai))) return null;
  const pending = data?.state === 'pending' || data?.state === 'running';
  return (
    <Box component="section" aria-label={t('Purchase cards')}>
      {error && <Alert severity="error" onClose={() => setError('')}>{error}</Alert>}
      {data?.cards.map((card) => <PurchaseCard key={card.id} card={card} onDismiss={(id, dismissed) => void dismiss(id, dismissed)} />)}
      {data?.error && <Alert severity="warning">{t('Purchase card extraction failed. You can retry.')}</Alert>}
      {data?.ai_available && data.suggest_ai && data.cards.length === 0 && <Button size="small" disabled={pending} onClick={() => void extract()} startIcon={pending ? <CircularProgress size={14} /> : <Inventory2 />}>{t('Extract purchase card with AI')}</Button>}
    </Box>
  );
}
