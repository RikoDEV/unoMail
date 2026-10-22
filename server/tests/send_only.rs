//! Send-only mailboxes (noreply@): they keep sending, and mail sent to them is dropped.

mod common;

use axum::http::StatusCode;
use common::{Api, TestEnv};
use serde_json::json;
use unomail::{
    auth::Role,
    db::Direction,
    smtp::delivery::{self, LocalDelivery},
};

#[tokio::test]
async fn mail_for_a_send_only_mailbox_is_discarded() {
    let env = TestEnv::start().await;
    env.domain("example.org").await;
    env.account_with("admin@example.org", Role::SuperAdmin, None).await;
    let noreply = env.account("noreply@example.org").await;
    let admin = Api::logged_in(&env, "admin@example.org").await;

    let raw = "From: someone@remote.example\r\nTo: noreply@example.org\r\nSubject: Re: your order\r\nMessage-ID: <reply@remote.example>\r\n\r\nThanks!\r\n";
    let deliver = || LocalDelivery {
        account_id: noreply.id,
        recipient: "noreply@example.org",
        sender: "someone@remote.example",
        raw: raw.as_bytes(),
        junk: false,
        remote: "203.0.113.9",
        direction: Direction::Inbound,
        author_verified: false,
        sender_verified: true,
    };
    delivery::deliver_local(&env.app, deliver()).await.unwrap();
    assert_eq!(env.inbox(&noreply).await.len(), 1, "an ordinary mailbox keeps its mail");

    let updated = admin.patch(&format!("/api/accounts/{}", noreply.id), json!({ "send_only": true })).await;
    assert_eq!(updated.status, StatusCode::OK, "{}", updated.text);
    assert_eq!(updated.body["send_only"], json!(true));

    delivery::deliver_local(&env.app, deliver()).await.unwrap();
    assert_eq!(env.inbox(&noreply).await.len(), 1, "a send-only mailbox drops new mail");
    let logged: Vec<(String, String)> = sqlx::query_as("SELECT status, detail FROM delivery_log WHERE recipient = 'noreply@example.org' ORDER BY id")
        .fetch_all(&env.app.db)
        .await
        .unwrap();
    assert_eq!(logged.last().unwrap(), &("discarded".to_owned(), "the mailbox is send-only".to_owned()));
}
