//! Persisted, account-scoped summary cards: purchases, reservations and bills. Facts retain their source message; user state
//! is separate. Aggregation reads only surviving, non-junk sources, so deletion cannot leave
//! behind facts or action links from a message the account no longer holds.

pub mod extract;
pub mod jobs;

use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use crate::{app::AppState, error::ApiError, util::now};

#[derive(Default, Clone, Deserialize, Serialize)]
#[serde(default, deny_unknown_fields)]
pub struct Config {
    pub model_id: String,
    pub automatic_ai: bool,
}

pub async fn config(state: &AppState) -> Result<Config, ApiError> {
    let value = crate::db::get_setting(&state.db, "summary_cards.config").await?;
    value.map(|s| serde_json::from_str(&s)).transpose().map(|v| v.unwrap_or_default()).map_err(|e| ApiError::Internal(e.into()))
}

pub async fn preferences(state: &AppState, account: i64) -> Result<(bool, bool), ApiError> {
    let value: Option<String> = sqlx::query_scalar("SELECT data FROM preferences WHERE account_id = ?").bind(account).fetch_optional(&state.db).await?;
    let value: Value = value.and_then(|s| serde_json::from_str(&s).ok()).unwrap_or_default();
    Ok((value["summary_cards"] != false, value["summary_cards_ai"] == true))
}

#[derive(Debug, Default, Clone, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum Status { #[default] Ordered, Processing, Shipped, OutForDelivery, Delivered, Cancelled, Returned, Refunded }

#[derive(Debug, Clone, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct Money { pub amount: String, pub currency: String }

#[derive(Debug, Default, Clone, Deserialize, Serialize, PartialEq, Eq)]
#[serde(default, deny_unknown_fields)]
pub struct Shipment {
    pub tracking_number: Option<String>,
    pub tracking_url: Option<String>,
    pub carrier: Option<String>,
    pub delivery_from: Option<String>,
    pub delivery_until: Option<String>,
    pub status: Status,
}

#[derive(Debug, Default, Clone, Deserialize, Serialize, PartialEq, Eq)]
#[serde(default, deny_unknown_fields)]
pub struct Purchase {
    pub merchant: String,
    pub order_number: String,
    pub items: Vec<String>,
    pub total: Option<Money>,
    pub status: Status,
    pub order_url: Option<String>,
    pub shipments: Vec<Shipment>,
}

fn later_status(previous: &Status, next: &Status) -> Status {
    // A routine order/shipping notice must not undo a terminal delivery/cancellation/refund.
    let rank = |s: &Status| match s { Status::Ordered => 0, Status::Processing => 1, Status::Shipped => 2, Status::OutForDelivery => 3,
        Status::Delivered => 4, Status::Cancelled => 5, Status::Returned => 6, Status::Refunded => 7 };
    if rank(next) >= rank(previous) { next.clone() } else { previous.clone() }
}

impl Purchase {
    pub fn merge(&mut self, next: Self) {
        self.status = later_status(&self.status, &next.status);
        if !next.items.is_empty() { self.items = next.items; }
        if next.total.is_some() && (self.total.is_none() || self.total.as_ref().map(|m| &m.currency) == next.total.as_ref().map(|m| &m.currency)) { self.total = next.total; }
        if next.order_url.is_some() { self.order_url = next.order_url; }
        for incoming in next.shipments {
            let found = self.shipments.iter_mut().find(|s| {
                if let Some(number) = &incoming.tracking_number { s.tracking_number.as_ref() == Some(number) }
                else if let Some(url) = &incoming.tracking_url { s.tracking_url.as_ref() == Some(url) }
                else { s.tracking_number.is_none() && s.tracking_url.is_none() }
            });
            if let Some(s) = found {
                s.status = later_status(&s.status, &incoming.status);
                if incoming.carrier.is_some() { s.carrier = incoming.carrier; }
                if incoming.tracking_url.is_some() { s.tracking_url = incoming.tracking_url; }
                if incoming.delivery_from.is_some() { s.delivery_from = incoming.delivery_from; }
                if incoming.delivery_until.is_some() { s.delivery_until = incoming.delivery_until; }
            } else if self.shipments.len() < 20 { self.shipments.push(incoming); }
        }
    }
}

#[derive(Debug, Default, Clone, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum ReservationKind { #[default] Flight, Lodging, Train, Bus, RentalCar, Restaurant, Event }

#[derive(Debug, Default, Clone, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum ReservationStatus { #[default] Confirmed, Pending, Cancelled }

/// A booking: a flight, train or bus leg, a hotel stay, a rental car, a table or an event ticket.
#[derive(Debug, Default, Clone, Deserialize, Serialize, PartialEq, Eq)]
#[serde(default, deny_unknown_fields)]
pub struct Reservation {
    pub kind: ReservationKind,
    /// Who holds the booking: the airline, hotel, rental company, restaurant or ticket seller.
    pub provider: String,
    pub reservation_number: String,
    pub status: ReservationStatus,
    /// The hotel, restaurant, event or car booked, when it differs from the provider.
    pub name: Option<String>,
    /// Flight, train or bus number; tells the legs of one booking apart.
    pub segment: Option<String>,
    pub from: Option<String>,
    pub to: Option<String>,
    pub location: Option<String>,
    /// YYYY-MM-DD, RFC 3339, or a local date-time without zone (YYYY-MM-DDTHH:MM[:SS]).
    pub start: Option<String>,
    pub end: Option<String>,
    pub url: Option<String>,
}

impl Reservation {
    pub fn merge(&mut self, next: Self) {
        // A cancellation is final; a later routine confirmation must not revive the booking.
        let rank = |s: &ReservationStatus| match s { ReservationStatus::Pending => 0, ReservationStatus::Confirmed => 1, ReservationStatus::Cancelled => 2 };
        if rank(&next.status) >= rank(&self.status) { self.status = next.status; }
        for (mine, theirs) in [(&mut self.name, next.name), (&mut self.from, next.from), (&mut self.to, next.to), (&mut self.location, next.location),
            (&mut self.start, next.start), (&mut self.end, next.end), (&mut self.url, next.url)] {
            if theirs.is_some() { *mine = theirs; }
        }
    }
}

#[derive(Debug, Default, Clone, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum BillStatus { #[default] Due, Overdue, Paid }

/// A bill or invoice awaiting, or confirming, payment.
#[derive(Debug, Default, Clone, Deserialize, Serialize, PartialEq, Eq)]
#[serde(default, deny_unknown_fields)]
pub struct Bill {
    pub biller: String,
    /// Invoice, statement or account number.
    pub reference: String,
    pub amount: Option<Money>,
    pub due_date: Option<String>,
    pub status: BillStatus,
    pub url: Option<String>,
}

impl Bill {
    pub fn merge(&mut self, next: Self) {
        let rank = |s: &BillStatus| match s { BillStatus::Due => 0, BillStatus::Overdue => 1, BillStatus::Paid => 2 };
        if rank(&next.status) >= rank(&self.status) { self.status = next.status; }
        if next.amount.is_some() { self.amount = next.amount; }
        if next.due_date.is_some() { self.due_date = next.due_date; }
        if next.url.is_some() { self.url = next.url; }
    }
}

/// One card's facts as read from one message.
#[derive(Debug, Clone, PartialEq)]
pub enum Card { Purchase(Purchase), Reservation(Reservation), Bill(Bill) }

impl Card {
    pub fn kind(&self) -> &'static str {
        match self { Card::Purchase(_) => "purchase", Card::Reservation(_) => "reservation", Card::Bill(_) => "bill" }
    }
    /// What identifies the card across messages from one sender domain.
    fn identity(&self) -> String {
        match self {
            // Unchanged from purchase-only cards, so existing cards keep reconciling.
            Card::Purchase(p) => format!("{}\n{}", p.merchant.to_lowercase(), p.order_number),
            // Legs of one booking share its number; the segment and travel day tell them apart.
            Card::Reservation(r) => {
                let day = if r.segment.is_some() { r.start.as_deref().map(|s| &s[..s.len().min(10)]).unwrap_or_default() } else { "" };
                format!("reservation\n{:?}\n{}\n{}\n{}\n{day}", r.kind, r.provider.to_lowercase(), r.reservation_number, r.segment.as_deref().unwrap_or_default())
            }
            Card::Bill(b) => format!("bill\n{}\n{}\n{}", b.biller.to_lowercase(), b.reference, b.due_date.as_deref().unwrap_or_default()),
        }
    }
    fn details(&self) -> Result<String, ApiError> {
        let text = match self { Card::Purchase(p) => serde_json::to_string(p), Card::Reservation(r) => serde_json::to_string(r), Card::Bill(b) => serde_json::to_string(b) };
        Ok(text.map_err(anyhow::Error::from)?)
    }
    fn parse(kind: &str, details: &str) -> Result<Self, ApiError> {
        let card = match kind {
            "reservation" => serde_json::from_str(details).map(Card::Reservation),
            "bill" => serde_json::from_str(details).map(Card::Bill),
            _ => serde_json::from_str(details).map(Card::Purchase),
        };
        Ok(card.map_err(anyhow::Error::from)?)
    }
    fn merge(&mut self, next: Self) {
        match (self, next) {
            (Card::Purchase(a), Card::Purchase(b)) => a.merge(b),
            (Card::Reservation(a), Card::Reservation(b)) => a.merge(b),
            (Card::Bill(a), Card::Bill(b)) => a.merge(b),
            _ => {}
        }
    }
}

/// Store source facts atomically, idempotent across retries and process restarts.
pub async fn persist(state: &AppState, account: i64, message: i64, sender: &str, cards: Vec<extract::Extracted>, method: &str) -> Result<(), ApiError> {
    let domain = sender.rsplit_once('@').map(|(_, d)| d.to_ascii_lowercase()).ok_or_else(|| ApiError::bad("message has no sender domain"))?;
    let mut tx = state.db.begin().await?;
    for extracted in cards {
        let card = extracted.card;
        // Never reconcile unrelated senders, even if they reuse an order number or a thread.
        let key = crate::util::sha256_hex(format!("{domain}\n{}", card.identity()).as_bytes());
        let id: i64 = sqlx::query_scalar("INSERT INTO purchase_cards (account_id, entity_key, kind, created_at, updated_at) VALUES (?, ?, ?, ?, ?) ON CONFLICT(account_id, entity_key) DO UPDATE SET updated_at = excluded.updated_at RETURNING id")
            .bind(account).bind(key).bind(card.kind()).bind(now()).bind(now()).fetch_one(&mut *tx).await?;
        // Multiple JSON-LD records for the same card in one email are combined before saving.
        let known: Option<String> = sqlx::query_scalar("SELECT details FROM purchase_card_sources WHERE card_id = ? AND message_id = ?").bind(id).bind(message).fetch_optional(&mut *tx).await?;
        let card = if let Some(known) = known { let mut c = Card::parse(card.kind(), &known)?; c.merge(card); c } else { card };
        sqlx::query("INSERT INTO purchase_card_sources (card_id, message_id, details, method, evidence) SELECT ?, id, ?, ?, ? FROM messages WHERE id = ? AND account_id = ? ON CONFLICT(card_id, message_id) DO UPDATE SET details = excluded.details, method = excluded.method, evidence = excluded.evidence")
            .bind(id).bind(card.details()?).bind(method).bind(extracted.evidence).bind(message).bind(account).execute(&mut *tx).await?;
    }
    tx.commit().await?;
    Ok(())
}

pub async fn cards_for(state: &AppState, account: i64, message: i64) -> Result<Vec<Value>, ApiError> {
    let ids: Vec<(i64, bool, String)> = sqlx::query_as("SELECT c.id, c.dismissed, c.kind FROM purchase_cards c JOIN purchase_card_sources s ON s.card_id = c.id WHERE c.account_id = ? AND s.message_id = ? ORDER BY c.id LIMIT 10")
        .bind(account).bind(message).fetch_all(&state.db).await?;
    let mut result = Vec::new();
    for (id, dismissed, kind) in ids {
        let mut sources: Vec<(String, String, i64, i64, String)> = sqlx::query_as("SELECT s.details, s.method, m.id, m.thread_id, m.subject FROM purchase_card_sources s JOIN messages m ON m.id = s.message_id JOIN mailboxes b ON b.id = m.mailbox_id WHERE s.card_id = ? AND m.account_id = ? AND m.deleted = 0 AND m.draft = 0 AND COALESCE(b.role, '') NOT IN ('junk', 'trash') ORDER BY CASE WHEN m.sent_date > 0 THEN m.sent_date ELSE m.internal_date END DESC, m.id DESC LIMIT 100")
            .bind(id).bind(account).fetch_all(&state.db).await?;
        sources.reverse();
        let mut merged: Option<Card> = None;
        let mut evidence = Vec::new();
        for (details, method, message, thread, subject) in sources {
            let next = Card::parse(&kind, &details)?;
            if let Some(c) = &mut merged { c.merge(next); } else { merged = Some(next); }
            evidence.push(json!({ "email_id": format!("m{message}"), "thread_id": format!("t{thread}"), "subject": subject, "method": method }));
        }
        match merged {
            Some(Card::Purchase(mut purchase)) => {
                // One delivered parcel does not imply that every shipment of this order arrived.
                if purchase.shipments.len() > 1 && purchase.status == Status::Delivered && purchase.shipments.iter().any(|s| s.status != Status::Delivered) {
                    purchase.status = Status::Shipped;
                }
                result.push(json!({ "id": id, "kind": "purchase", "dismissed": dismissed, "purchase": purchase, "sources": evidence }));
            }
            Some(Card::Reservation(reservation)) => result.push(json!({ "id": id, "kind": "reservation", "dismissed": dismissed, "reservation": reservation, "sources": evidence })),
            Some(Card::Bill(bill)) => result.push(json!({ "id": id, "kind": "bill", "dismissed": dismissed, "bill": bill, "sources": evidence })),
            None => {}
        }
    }
    Ok(result)
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn updates_keep_order_facts_and_separate_shipments() {
        let mut order = Purchase { merchant: "Shop".into(), order_number: "42".into(), items: vec!["Book".into()], total: Some(Money { amount: "12.50".into(), currency: "EUR".into() }), ..Default::default() };
        order.merge(Purchase { status: Status::Shipped, shipments: vec![Shipment { tracking_number: Some("one".into()), status: Status::Shipped, ..Default::default() }], ..Default::default() });
        order.merge(Purchase { status: Status::Delivered, shipments: vec![Shipment { tracking_number: Some("one".into()), status: Status::Delivered, ..Default::default() }, Shipment { tracking_number: Some("two".into()), status: Status::Shipped, ..Default::default() }], ..Default::default() });
        order.merge(Purchase::default());
        assert_eq!(order.items, ["Book"]);
        assert_eq!(order.total.unwrap().amount, "12.50");
        assert_eq!(order.status, Status::Delivered);
        assert_eq!(order.shipments.len(), 2);
        assert_eq!(order.shipments[0].status, Status::Delivered);
    }
    #[test]
    fn cancellations_and_payments_are_final() {
        let mut flight = Reservation { provider: "Air".into(), reservation_number: "XYZ".into(), start: Some("2027-03-04T08:00:00+01:00".into()), ..Default::default() };
        flight.merge(Reservation { status: ReservationStatus::Cancelled, ..Default::default() });
        flight.merge(Reservation { status: ReservationStatus::Confirmed, ..Default::default() });
        assert_eq!(flight.status, ReservationStatus::Cancelled);
        assert_eq!(flight.start.as_deref(), Some("2027-03-04T08:00:00+01:00"));
        let mut bill = Bill { biller: "Power".into(), reference: "INV-1".into(), status: BillStatus::Paid, ..Default::default() };
        bill.merge(Bill { status: BillStatus::Due, due_date: Some("2027-01-31".into()), ..Default::default() });
        assert_eq!(bill.status, BillStatus::Paid);
        assert_eq!(bill.due_date.as_deref(), Some("2027-01-31"));
    }
}
