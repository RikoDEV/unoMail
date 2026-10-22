mod common;

use common::{Api, TestEnv};
use serde_json::{Value, json};
use unomail::{auth::Account, store::Flags, summary_cards::{self, jobs}};

async fn append(env: &TestEnv, account: &Account, sender: &str, value: Value, day: i32) -> i64 {
    let inbox = env.app.store.mailbox_by_role(account.id, "inbox").await.unwrap().unwrap();
    let raw = format!("From: Shop <{sender}>\r\nTo: {}\r\nSubject: Order update\r\nDate: {day:02} Nov 2026 12:00:00 +0000\r\nContent-Type: text/html; charset=utf-8\r\n\r\n<script type=\"application/ld+json\">{value}</script><p>Purchase update.</p>", account.email);
    env.app.store.append(account.id, inbox.id, raw.as_bytes(), Flags::default(), None).await.unwrap().id
}

async fn drain(env: &TestEnv) {
    for _ in 0..30 { if !jobs::tick(&env.app).await.unwrap() { return; } }
    panic!("queue did not drain");
}

#[tokio::test]
async fn purchases_reconcile_idempotently_and_removed_sources_do_not_leave_stale_facts() {
    let env = TestEnv::start().await;
    env.domain("example.test").await;
    let alice = env.account("alice@example.test").await;
    let bob = env.account("bob@example.test").await;
    let order = json!({"@type":"Order","seller":{"name":"Shop"},"orderNumber":"42","totalPrice":"12.50","priceCurrency":"EUR","orderedItem":{"name":"Book"}});
    let original = append(&env, &alice, "orders@shop.test", order.clone(), 1).await;
    let shipment = |status: &str| json!({"@type":"ParcelDelivery","partOfOrder":{"seller":{"name":"Shop"},"orderNumber":"42"},"trackingNumber":"ABC","trackingUrl":"https://carrier.test/ABC","deliveryStatus":{"eventType":status}});
    let shipped = append(&env, &alice, "shipping@shop.test", shipment("Shipped"), 2).await;
    let delivered = append(&env, &alice, "shipping@shop.test", shipment("Delivered"), 3).await;
    let bobs = append(&env, &bob, "orders@shop.test", order.clone(), 1).await;
    // A different sender domain must never update the first merchant's order.
    append(&env, &alice, "orders@other.test", order, 1).await;
    drain(&env).await;
    let cards = summary_cards::cards_for(&env.app, alice.id, original).await.unwrap();
    assert_eq!(cards.len(), 1);
    assert_eq!(cards[0]["purchase"]["status"], "delivered");
    assert_eq!(cards[0]["purchase"]["total"]["amount"], "12.50");
    assert_eq!(cards[0]["sources"].as_array().unwrap().len(), 3);
    assert_eq!(summary_cards::cards_for(&env.app, bob.id, bobs).await.unwrap()[0]["purchase"]["status"], "ordered");
    jobs::enqueue(&env.app, alice.id, shipped, false).await.unwrap();
    drain(&env).await;
    assert_eq!(summary_cards::cards_for(&env.app, alice.id, original).await.unwrap()[0]["sources"].as_array().unwrap().len(), 3);
    let api = Api::logged_in(&env, "alice@example.test").await;
    assert_eq!(api.get(&format!("/api/me/summary-cards?email_id=m{bobs}")).await.status, 404);
    let card_id = cards[0]["id"].as_i64().unwrap();
    assert_eq!(api.patch(&format!("/api/me/summary-cards/{card_id}"), json!({"dismissed":true})).await.status, 200);
    jobs::enqueue(&env.app, alice.id, original, false).await.unwrap();
    drain(&env).await;
    assert_eq!(summary_cards::cards_for(&env.app, alice.id, original).await.unwrap()[0]["dismissed"], true);
    let bob_api = Api::logged_in(&env, "bob@example.test").await;
    assert_eq!(bob_api.patch(&format!("/api/me/summary-cards/{card_id}"), json!({"dismissed":false})).await.status, 404);
    env.app.store.delete_message(alice.id, delivered).await.unwrap();
    let cards = summary_cards::cards_for(&env.app, alice.id, original).await.unwrap();
    assert_eq!(cards[0]["purchase"]["status"], "shipped");
    assert_eq!(cards[0]["sources"].as_array().unwrap().len(), 2);
    let junk = env.app.store.mailbox_by_role(alice.id, "junk").await.unwrap().unwrap();
    env.app.store.move_message(alice.id, shipped, junk.id).await.unwrap();
    assert_eq!(summary_cards::cards_for(&env.app, alice.id, original).await.unwrap()[0]["purchase"]["status"], "ordered");
}

#[tokio::test]
async fn processing_respects_preferences_and_skips_encrypted_mail() {
    let env = TestEnv::start().await;
    env.domain("example.test").await;
    let alice = env.account("alice@example.test").await;
    let api = Api::logged_in(&env, &alice.email).await;
    api.put("/api/me/preferences", json!({"summary_cards":false})).await;
    let id = append(&env, &alice, "shop@shop.test", json!({"@type":"Order","seller":{"name":"Shop"},"orderNumber":"42"}), 1).await;
    drain(&env).await;
    assert!(summary_cards::cards_for(&env.app, alice.id, id).await.unwrap().is_empty());
    assert_eq!(api.post("/api/me/summary-cards/extract", json!({"email_id":format!("m{id}")})).await.status, 400);
    api.put("/api/me/preferences", json!({"summary_cards":true})).await;
    jobs::enqueue(&env.app, alice.id, id, false).await.unwrap();
    drain(&env).await;
    assert_eq!(summary_cards::cards_for(&env.app, alice.id, id).await.unwrap().len(), 1);
    let inbox = env.app.store.mailbox_by_role(alice.id, "inbox").await.unwrap().unwrap();
    let raw = b"From: shop@shop.test\r\nContent-Type: text/plain\r\n\r\n-----BEGIN PGP MESSAGE-----\r\nencrypted order\r\n-----END PGP MESSAGE-----";
    let encrypted = env.app.store.append(alice.id, inbox.id, raw, Flags::default(), None).await.unwrap().id;
    drain(&env).await;
    assert!(summary_cards::cards_for(&env.app, alice.id, encrypted).await.unwrap().is_empty());
    assert_eq!(api.get("/api/models/summary-cards").await.status, 403);
}

#[tokio::test]
async fn reservations_and_bills_reconcile_per_leg_and_keep_cancellations() {
    let env = TestEnv::start().await;
    env.domain("example.test").await;
    let alice = env.account("alice@example.test").await;
    let leg = |number: &str, day: &str, status: &str| json!({"@type":"FlightReservation","reservationNumber":"RXJ34P","reservationStatus":status,
        "reservationFor":{"@type":"Flight","flightNumber":number,"airline":{"name":"United","iataCode":"UA"},"departureTime":format!("2027-03-{day}T20:15:00-08:00")}});
    // One email confirms both legs of a return trip; a later one cancels the outbound leg only.
    let both = append(&env, &alice, "booking@united.test", json!({"@graph":[leg("110", "04", "ReservationConfirmed"), leg("111", "09", "ReservationConfirmed")]}), 1).await;
    append(&env, &alice, "booking@united.test", leg("110", "04", "ReservationCancelled"), 2).await;
    let bill = append(&env, &alice, "billing@power.test", json!({"@type":"Invoice","accountId":"1234","paymentDueDate":"2027-01-30","provider":{"name":"Power Co"},"totalPaymentDue":{"price":"70.00","priceCurrency":"USD"}}), 3).await;
    drain(&env).await;
    let cards = summary_cards::cards_for(&env.app, alice.id, both).await.unwrap();
    assert_eq!(cards.len(), 2);
    let status = |segment: &str| cards.iter().find(|c| c["reservation"]["segment"] == segment).unwrap()["reservation"]["status"].clone();
    assert_eq!(status("UA 110"), "cancelled");
    assert_eq!(status("UA 111"), "confirmed");
    assert!(cards.iter().all(|c| c["kind"] == "reservation"));
    let bills = summary_cards::cards_for(&env.app, alice.id, bill).await.unwrap();
    assert_eq!((bills[0]["kind"].as_str(), bills[0]["bill"]["amount"]["amount"].as_str()), (Some("bill"), Some("70.00")));
}
