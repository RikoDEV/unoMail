//! Mailing lists: distribution, moderation, subscribing by mail and one-click unsubscribe.

mod common;

use axum::http::{Method, StatusCode};
use common::{Api, Client, Sink, TestEnv, message};
use serde_json::json;
use unomail::smtp::queue;

fn link(text: &str, path: &str) -> String {
    let start = text.find(path).unwrap_or_else(|| panic!("{path} not in {text}"));
    text[start..].split_whitespace().next().unwrap().trim_end_matches(['>', ',']).to_owned()
}

/// A delivery-status report saying the copy to friend@remote.example failed.
const REPORT: &str = "From: MAILER-DAEMON@remote.example\r\nTo: team-bounces@example.org\r\nSubject: failure\r\nContent-Type: multipart/report; report-type=delivery-status; boundary=b\r\n\r\n--b\r\nContent-Type: message/delivery-status\r\n\r\nReporting-MTA: dns; remote.example\r\n\r\nFinal-Recipient: rfc822; friend@remote.example\r\nAction: failed\r\nStatus: 5.1.1\r\n\r\n--b--\r\n";

#[tokio::test]
async fn lists_distribute_moderate_and_manage_members() {
    let sink = Sink::start().await;
    let relay = sink.relay();
    let env = TestEnv::start_with(|cfg| cfg.outbound_relay = Some(relay)).await;
    env.domain("example.org").await;
    env.account_with("admin@example.org", unomail::auth::Role::SuperAdmin, None).await;
    let bob = env.account("bob@example.org").await;
    let carol = env.account("carol@example.org").await;
    let admin = Api::logged_in(&env, "admin@example.org").await;

    let created = admin.post("/api/lists", json!({ "address": "team@example.org", "name": "Team", "posting": "members", "subscription": "open", "subject_prefix": "[team]" })).await;
    assert_eq!(created.status, StatusCode::OK, "{}", created.text);
    let id = created.body["id"].as_i64().unwrap();
    assert_eq!(admin.post("/api/lists", json!({ "address": "bob@example.org" })).await.status, StatusCode::CONFLICT, "taken by a mailbox");
    assert_eq!(admin.post("/api/lists", json!({ "address": "x-owner@example.org" })).await.status, StatusCode::BAD_REQUEST);
    let added = admin.post(&format!("/api/lists/{id}/members"), json!({ "addresses": "bob@example.org\nFriend <friend@remote.example>, not an address" })).await;
    assert_eq!(added.body["added"].as_array().unwrap().len(), 2, "{}", added.text);
    assert_eq!(added.body["invalid"], json!(["not an address"]));
    admin.post(&format!("/api/lists/{id}/members"), json!({ "addresses": "carol@example.org", "role": "moderator" })).await;

    // A member posts: everyone gets a copy with the list headers.
    let mut smtp = Client::smtp(env.mx).await;
    assert!(smtp.send_mail("bob@example.org", &["team@example.org"], &message("bob@example.org", "team@example.org", "Lunch?", "At noon")).await.starts_with("250"));
    queue::process_due(&env.app).await;
    let carols = env.inbox(&carol).await;
    assert_eq!(carols.len(), 1);
    let copy = &carols[0];
    assert!(copy.contains("Subject: [team] Lunch?\r\n"), "{copy}");
    assert!(copy.contains("List-Id: \"Team\" <team.example.org>\r\n") && copy.contains("List-Post: <mailto:team@example.org>"));
    assert!(copy.contains("List-Unsubscribe-Post: List-Unsubscribe=One-Click"));
    assert!(copy.starts_with("Return-Path: <team-bounces+"), "each copy has its own return address: {copy}");
    let remote = sink.received();
    assert_eq!(remote.len(), 1);
    assert!(remote[0].from.starts_with("team-bounces+") && remote[0].from.ends_with("@example.org"), "{}", remote[0].from);
    assert_eq!(remote[0].to, "friend@remote.example");
    let friend_bounces = remote[0].from.clone();
    assert_eq!(env.inbox(&bob).await.len(), 1, "the poster gets a copy too");

    // Its own copy coming back is not sent again.
    assert!(smtp.send_mail("x@remote.example", &["team@example.org"], copy).await.starts_with("250"));
    assert_eq!(env.inbox(&carol).await.len(), 1);

    // A stranger's post waits for a moderator, who is told.
    assert!(smtp.send_mail("stranger@remote.example", &["team@example.org"], &message("stranger@remote.example", "team@example.org", "Buy this", "offer")).await.starts_with("250"));
    let carols = env.inbox(&carol).await;
    assert_eq!(carols.len(), 2);
    assert!(carols[1].contains("Approval needed: Buy this"));
    let held = admin.get(&format!("/api/lists/{id}/held")).await.body;
    assert_eq!(held[0]["sender"], "stranger@remote.example");
    let moderate = link(&carols[1], "/lists/moderate/");
    let path = &moderate[moderate.find("/lists/").unwrap()..];
    let api = Api::new(&env);
    assert!(api.send(Method::GET, path, None, &[]).await.text.contains("Buy this"), "a page, nothing decided yet");
    assert_eq!(admin.get(&format!("/api/lists/{id}/held")).await.body.as_array().unwrap().len(), 1);
    let decided = admin.post(&format!("/api/lists/{id}/held/{}", held[0]["token"].as_str().unwrap()), json!({ "action": "discard" })).await;
    assert_eq!(decided.status, StatusCode::OK, "{}", decided.text);
    assert!(api.send(Method::GET, path, None, &[]).await.text.contains("Already handled"));
    assert_eq!(env.inbox(&carol).await.len(), 2, "discarded");

    // Subscribing by mail, confirmed by the link.
    assert!(smtp.send_mail("newbie@remote.example", &["team-request@example.org"], &message("newbie@remote.example", "team-request@example.org", "subscribe", "")).await.starts_with("250"));
    queue::process_due(&env.app).await;
    let confirmation = sink.received().last().unwrap().clone();
    assert_eq!(confirmation.to, "newbie@remote.example");
    let confirm = link(&confirmation.data, "/lists/confirm/");
    let confirm = &confirm[confirm.find("/lists/").unwrap()..];
    assert!(api.send(Method::GET, confirm, None, &[]).await.text.contains("Subscribe newbie@remote.example"));
    assert!(api.send(Method::POST, confirm, None, &[]).await.text.contains("now subscribed"));
    let members = admin.get(&format!("/api/lists/{id}/members")).await.body;
    assert!(members.as_array().unwrap().iter().any(|m| m["email"] == "newbie@remote.example"));

    // One-click unsubscribe from the header of bob's copy.
    let bobs = env.inbox(&bob).await;
    let unsubscribe = link(&bobs[0], "/lists/unsubscribe/");
    let unsubscribe = &unsubscribe[unsubscribe.find("/lists/").unwrap()..];
    let reply = api.raw(Method::POST, unsubscribe, b"List-Unsubscribe=One-Click".to_vec(), "application/x-www-form-urlencoded").await;
    assert_eq!(reply.status, StatusCode::OK);
    let members = admin.get(&format!("/api/lists/{id}/members")).await.body;
    assert!(!members.as_array().unwrap().iter().any(|m| m["email"] == "bob@example.org"));
    assert!(api.send(Method::GET, unsubscribe, None, &[]).await.text.contains("not subscribed"));

    // Reports to the plain bounce address, or to a forged tag, name no member and count for nothing.
    let forged = friend_bounces.replace("team-bounces+", "team-bounces+9").replacen('.', ".0", 1);
    for to in ["team-bounces@example.org", forged.as_str()] {
        for _ in 0..5 {
            assert!(smtp.send_mail("", &[to], REPORT).await.starts_with("250"));
        }
    }
    let members = admin.get(&format!("/api/lists/{id}/members")).await.body;
    assert!(members.as_array().unwrap().iter().any(|m| m["email"] == "friend@remote.example"), "{members}");

    // A member whose copies keep bouncing is removed.
    for _ in 0..5 {
        assert!(smtp.send_mail("", &[friend_bounces.as_str()], REPORT).await.starts_with("250"));
    }
    let members = admin.get(&format!("/api/lists/{id}/members")).await.body;
    assert!(!members.as_array().unwrap().iter().any(|m| m["email"] == "friend@remote.example"), "{members}");
    let _ = bob;
}

#[tokio::test]
async fn only_authenticated_senders_post_as_members() {
    use unomail::lists::{Role, Sender, receive};
    let env = TestEnv::start().await;
    env.domain("example.org").await;
    env.account_with("admin@example.org", unomail::auth::Role::SuperAdmin, None).await;
    let bob = env.account("bob@example.org").await;
    let admin = Api::logged_in(&env, "admin@example.org").await;
    let members = admin.post("/api/lists", json!({ "address": "team@example.org", "name": "Team", "posting": "members" })).await.body["id"].as_i64().unwrap();
    let announce = admin.post("/api/lists", json!({ "address": "news@example.org", "name": "News", "posting": "announce" })).await.body["id"].as_i64().unwrap();
    admin.post(&format!("/api/lists/{members}/members"), json!({ "addresses": "bob@example.org" })).await;
    admin.post(&format!("/api/lists/{announce}/members"), json!({ "addresses": "bob@example.org" })).await;
    admin.post(&format!("/api/lists/{announce}/members"), json!({ "addresses": "boss@example.org", "role": "owner" })).await;

    // From names a member, but nothing vouches for it: held for a moderator.
    let forged = Sender { envelope: "attacker@evil.example", envelope_verified: true, author_verified: false };
    receive(&env.app, members, Role::Post, forged, message("bob@example.org", "team@example.org", "Hi", "x").as_bytes(), false).await.unwrap();
    let held = admin.get(&format!("/api/lists/{members}/held")).await.body;
    assert_eq!(held.as_array().unwrap().len(), 1, "{held}");
    assert_eq!(env.inbox(&bob).await.len(), 0);

    // Posing as an owner does not get past an announcement list either.
    receive(&env.app, announce, Role::Post, forged, message("boss@example.org", "news@example.org", "Raise", "x").as_bytes(), false).await.unwrap();
    assert_eq!(env.inbox(&bob).await.len(), 0);
    assert_eq!(admin.get(&format!("/api/lists/{announce}/held")).await.body.as_array().unwrap().len(), 1);

    // The same From, authenticated, is posted.
    let genuine = Sender { envelope: "bob@example.org", envelope_verified: true, author_verified: true };
    receive(&env.app, members, Role::Post, genuine, message("bob@example.org", "team@example.org", "Hi", "x").as_bytes(), false).await.unwrap();
    unomail::smtp::queue::process_due(&env.app).await;
    assert_eq!(env.inbox(&bob).await.len(), 1);
    assert!(env.inbox(&bob).await[0].contains("From: bob@example.org\r\n"), "a verified author is passed on as is");

    // A member proven by the envelope alone writes someone else of ours into From: the post
    // goes out, but not as a copy signed in that person's name.
    admin.post(&format!("/api/lists/{members}/members"), json!({ "addresses": "partner@remote.example" })).await;
    let member = Sender { envelope: "partner@remote.example", envelope_verified: true, author_verified: false };
    receive(&env.app, members, Role::Post, member, message("boss@example.org", "team@example.org", "Wire the money", "x").as_bytes(), false).await.unwrap();
    unomail::smtp::queue::process_due(&env.app).await;
    let inbox = env.inbox(&bob).await;
    let copy = inbox.iter().find(|m| m.contains("Wire the money")).expect("the member's post is distributed");
    assert!(copy.contains("From: \"boss@example.org via Team\" <team@example.org>\r\n"), "{copy}");
    assert!(copy.contains("X-Original-From: boss@example.org\r\n") && !copy.contains("\nFrom: boss@example.org"), "{copy}");
}
