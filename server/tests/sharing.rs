//! Shared and global folders: access control lists over the web API, JMAP and IMAP, and the
//! import of ready-made messages.

mod common;

use axum::http::{Method, StatusCode};
use common::{Api, Client, PASSWORD, TestEnv};
use serde_json::{Value, json};
use tokio::net::TcpListener;
use unomail::auth::Account;

struct World {
    env: TestEnv,
    bob: Account,
    carol: Account,
    projects: i64,
    bob_api: Api,
    carol_api: Api,
    dave_api: Api,
}

async fn world() -> World {
    let env = TestEnv::start().await;
    env.domain("example.org").await;
    env.domain("other.example").await;
    let bob = env.account("bob@example.org").await;
    let carol = env.account("carol@example.org").await;
    env.account("dave@example.org").await;
    env.account("erin@other.example").await;
    let projects = env.app.store.create_mailbox(bob.id, "Projects").await.unwrap().id;
    for n in 1..=2 {
        let raw = format!("From: ann@remote.example\r\nTo: bob@example.org\r\nSubject: Project {n}\r\nMessage-ID: <p{n}@remote.example>\r\n\r\nplan {n}\r\n");
        env.app.store.append(bob.id, projects, raw.as_bytes(), Default::default(), None).await.unwrap();
    }
    let bob_api = Api::logged_in(&env, "bob@example.org").await;
    let carol_api = Api::logged_in(&env, "carol@example.org").await;
    let dave_api = Api::logged_in(&env, "dave@example.org").await;
    World { env, bob, carol, projects, bob_api, carol_api, dave_api }
}

async fn share(api: &Api, mailbox: i64, identifier: &str, rights: &str) -> common::Reply {
    api.put(&format!("/api/me/mailboxes/{mailbox}/acl"), json!({ "identifier": identifier, "rights": rights })).await
}

async fn mailboxes(api: &Api) -> Vec<Value> {
    let account = api.jmap_account().await;
    api.jmap(json!([["Mailbox/get", { "accountId": account }, "0"]])).await[0][1]["list"].as_array().unwrap().clone()
}

async fn ids_in(api: &Api, mailbox: i64) -> Vec<String> {
    let account = api.jmap_account().await;
    let reply = api.jmap(json!([["Email/query", { "accountId": account, "filter": { "inMailbox": format!("b{mailbox}") } }, "q"]])).await;
    reply[0][1]["ids"].as_array().unwrap().iter().map(|v| v.as_str().unwrap().to_owned()).collect()
}

async fn update(api: &Api, id: &str, patch: Value) -> Value {
    let account = api.jmap_account().await;
    api.jmap(json!([["Email/set", { "accountId": account, "update": { id: patch } }, "u"]])).await[0][1].clone()
}

#[tokio::test]
async fn folders_are_shared_with_specific_rights_over_jmap() {
    let w = world().await;
    let p = w.projects;

    // Only the owner administers the list, and only colleagues of the same domain can be named.
    assert_eq!(share(&w.carol_api, p, "carol@example.org", "lr").await.status, StatusCode::NOT_FOUND, "an unshared folder does not exist for others");
    for (identifier, rights) in [("erin@other.example", "lr"), ("nobody@example.org", "lr"), ("bob@example.org", "lr"), ("carol@example.org", "lrz")] {
        assert_eq!(share(&w.bob_api, p, identifier, rights).await.status, StatusCode::BAD_REQUEST, "{identifier} {rights}");
    }
    let granted = share(&w.bob_api, p, "Carol@Example.org", "srl").await;
    assert_eq!(granted.body, json!([{ "identifier": "carol@example.org", "rights": "lrs" }]), "{}", granted.text);
    assert_eq!(share(&w.carol_api, p, "dave@example.org", "lr").await.status, StatusCode::FORBIDDEN, "reading does not include administering");
    assert_eq!(w.carol_api.get(&format!("/api/me/mailboxes/{p}/acl")).await.status, StatusCode::FORBIDDEN);

    // Carol sees the folder in her own list, under the shared namespace, with her rights.
    let shared: Vec<Value> = mailboxes(&w.carol_api).await.into_iter().filter(|m| !m["shareOwner"].is_null()).collect();
    assert_eq!(shared.len(), 1);
    assert_eq!((shared[0]["name"].as_str(), shared[0]["shareOwner"].as_str(), shared[0]["role"].as_str()), (Some("Shared/bob@example.org/Projects"), Some("bob@example.org"), None));
    let rights = &shared[0]["myRights"];
    assert_eq!((rights["mayReadItems"].as_bool(), rights["maySetSeen"].as_bool(), rights["mayAddItems"].as_bool(), rights["mayRemoveItems"].as_bool(), rights["mayAdmin"].as_bool()), (Some(true), Some(true), Some(false), Some(false), Some(false)));
    assert_eq!(shared[0]["totalEmails"], 2);
    assert!(mailboxes(&w.dave_api).await.iter().all(|m| m["shareOwner"].is_null()));
    let own = mailboxes(&w.bob_api).await.into_iter().find(|m| m["name"] == "Projects").unwrap();
    assert_eq!(own["sharedWith"], 1, "the owner sees that the folder is shared");

    // Reading: list, open, thread view and attachments work for Carol and for nobody else.
    let ids = ids_in(&w.carol_api, p).await;
    assert_eq!(ids.len(), 2);
    let account = w.carol_api.jmap_account().await;
    let fetched = w.carol_api.jmap(json!([["Email/get", { "accountId": account, "ids": ids }, "g"]])).await[0][1].clone();
    assert_eq!(fetched["list"].as_array().unwrap().len(), 2);
    assert!(fetched["list"][0]["bodyValues"].to_string().contains("plan"));
    let thread = fetched["list"][0]["threadId"].as_str().unwrap().to_owned();
    let threads = w.carol_api.jmap(json!([["Thread/get", { "accountId": account, "ids": [thread] }, "t"]])).await[0][1].clone();
    assert_eq!(threads["list"][0]["emailIds"].as_array().unwrap().len(), 1);
    let blob = fetched["list"][0]["blobId"].as_str().unwrap().to_owned();
    assert_eq!(w.carol_api.get(&format!("/jmap/download/{account}/{blob}/message.eml")).await.status, StatusCode::OK);

    let dave_account = w.dave_api.jmap_account().await;
    assert!(ids_in(&w.dave_api, p).await.is_empty());
    let denied = w.dave_api.jmap(json!([["Email/get", { "accountId": dave_account, "ids": ids }, "g"], ["Thread/get", { "accountId": dave_account, "ids": [thread] }, "t"]])).await;
    assert_eq!(denied[0][1]["list"], json!([]));
    assert_eq!(denied[0][1]["notFound"].as_array().unwrap().len(), 2);
    assert_eq!(denied[1][1]["list"], json!([]));
    assert_eq!(w.dave_api.get(&format!("/jmap/download/{dave_account}/{blob}/message.eml")).await.status, StatusCode::NOT_FOUND);

    // Rights are enforced one by one: with "lrs" Carol may mark as read and nothing else.
    let id = &ids[0];
    assert!(update(&w.carol_api, id, json!({ "keywords/$seen": true })).await["updated"].get(id).is_some());
    assert_eq!(update(&w.carol_api, id, json!({ "keywords/$flagged": true })).await["notUpdated"][id]["type"], "forbidden");
    assert_eq!(update(&w.carol_api, id, json!({ "keywords/work": true })).await["notUpdated"][id]["type"], "forbidden");
    let carol_inbox = w.env.app.store.mailbox_by_role(w.carol.id, "inbox").await.unwrap().unwrap().id;
    assert_eq!(update(&w.carol_api, id, json!({ "mailboxIds": { format!("b{carol_inbox}"): true } })).await["notUpdated"][id]["type"], "forbidden");
    let destroyed = w.carol_api.jmap(json!([["Email/set", { "accountId": account, "destroy": [id] }, "d"]])).await[0][1].clone();
    assert_eq!(destroyed["notDestroyed"][id]["type"], "forbidden");
    let created = w.carol_api.jmap(json!([["Email/set", { "accountId": account, "create": { "x": { "mailboxIds": { format!("b{p}"): true }, "subject": "intruder" } } }, "c"]])).await[0][1].clone();
    assert_eq!(created["notCreated"]["x"]["type"], "forbidden");
    assert_eq!(w.env.app.store.messages_in(p).await.unwrap().len(), 2, "nothing was changed or removed");
    assert_eq!(w.carol_api.get(&format!("/api/me/mailboxes/{p}/export")).await.status, StatusCode::OK, "reading includes exporting");
    assert_eq!(w.carol_api.raw(Method::POST, &format!("/api/me/mailboxes/{p}/import"), b"From: x@y.example\r\nSubject: s\r\n\r\nb".to_vec(), "message/rfc822").await.status, StatusCode::FORBIDDEN);

    // Full rights: flag, move out into her own archive (the message becomes hers) and back.
    assert_eq!(share(&w.bob_api, p, "carol@example.org", "lrswite").await.status, StatusCode::OK);
    assert!(update(&w.carol_api, id, json!({ "keywords/$flagged": true, "keywords/work": true })).await["updated"].get(id).is_some());
    let archive = w.env.app.store.mailbox_by_role(w.carol.id, "archive").await.unwrap().unwrap().id;
    assert!(update(&w.carol_api, id, json!({ "mailboxIds": { format!("b{archive}"): true } })).await["updated"].get(id).is_some());
    assert_eq!(w.env.app.store.messages_in(p).await.unwrap().len(), 1);
    let moved = w.env.app.store.messages_in(archive).await.unwrap();
    assert_eq!((moved.len(), moved[0].account_id, moved[0].flagged, moved[0].keywords.as_str()), (1, w.carol.id, true, "[\"work\"]"), "flags and labels travel with the message");
    let (bob_used, carol_used): (i64, i64) = (
        sqlx::query_scalar("SELECT used_bytes FROM accounts WHERE id = ?").bind(w.bob.id).fetch_one(&w.env.app.db).await.unwrap(),
        sqlx::query_scalar("SELECT used_bytes FROM accounts WHERE id = ?").bind(w.carol.id).fetch_one(&w.env.app.db).await.unwrap(),
    );
    assert_eq!(carol_used, moved[0].size, "the quota follows the message to its new owner");
    assert_eq!(bob_used, w.env.app.store.messages_in(p).await.unwrap()[0].size);
    let back = format!("m{}", moved[0].id);
    assert!(update(&w.carol_api, &back, json!({ "mailboxIds": { format!("b{p}"): true } })).await["updated"].get(&back).is_some());
    assert_eq!(ids_in(&w.bob_api, p).await.len(), 2, "the owner sees what colleagues file into the folder");

    // Revoking access takes effect immediately.
    assert_eq!(share(&w.bob_api, p, "carol@example.org", "").await.body, json!([]));
    assert!(mailboxes(&w.carol_api).await.iter().all(|m| m["shareOwner"].is_null()));
    assert!(ids_in(&w.carol_api, p).await.is_empty());
    let after = w.carol_api.jmap(json!([["Email/get", { "accountId": account, "ids": ids_in(&w.bob_api, p).await }, "g"]])).await[0][1].clone();
    assert_eq!(after["list"], json!([]));
}

#[tokio::test]
async fn global_folders_reach_the_whole_domain_and_nobody_else() {
    let w = world().await;
    let news = w.env.app.store.create_mailbox(w.bob.id, "Announcements").await.unwrap().id;
    w.env.app.store.append(w.bob.id, news, b"From: bob@example.org\r\nSubject: Office closed\r\n\r\nOn Friday.\r\n", Default::default(), None).await.unwrap();
    assert_eq!(share(&w.bob_api, news, "anyone", "lr").await.body, json!([{ "identifier": "anyone", "rights": "lr" }]));

    for api in [&w.carol_api, &w.dave_api] {
        let names: Vec<String> = mailboxes(api).await.iter().filter_map(|m| m["name"].as_str().map(str::to_owned)).collect();
        assert!(names.contains(&"Shared/bob@example.org/Announcements".to_owned()), "{names:?}");
        assert_eq!(ids_in(api, news).await.len(), 1);
    }
    let erin = Api::logged_in(&w.env, "erin@other.example").await;
    assert!(mailboxes(&erin).await.iter().all(|m| m["shareOwner"].is_null()), "other domains on the same server are not included");
    assert!(ids_in(&erin, news).await.is_empty());

    // A personal grant adds to the global one.
    share(&w.bob_api, news, "carol@example.org", "si").await;
    let carol_view = mailboxes(&w.carol_api).await.into_iter().find(|m| m["name"] == "Shared/bob@example.org/Announcements").unwrap();
    assert_eq!((carol_view["myRights"]["maySetSeen"].as_bool(), carol_view["myRights"]["mayAddItems"].as_bool()), (Some(true), Some(true)));
    let dave_view = mailboxes(&w.dave_api).await.into_iter().find(|m| m["name"] == "Shared/bob@example.org/Announcements").unwrap();
    assert_eq!(dave_view["myRights"]["maySetSeen"], false);

    // Removing an account removes its grants; the shared namespace cannot be squatted.
    sqlx::query("DELETE FROM accounts WHERE email = 'carol@example.org'").execute(&w.env.app.db).await.unwrap();
    assert_eq!(w.bob_api.get(&format!("/api/me/mailboxes/{news}/acl")).await.body, json!([{ "identifier": "anyone", "rights": "lr" }]));
    let account = w.bob_api.jmap_account().await;
    let squat = w.bob_api.jmap(json!([["Mailbox/set", { "accountId": account, "create": { "x": { "name": "Shared/carol@example.org/INBOX" } } }, "c"]])).await[0][1].clone();
    assert_eq!(squat["notCreated"]["x"]["type"], "invalidProperties");
}

/// Sends one IMAP command and returns every line up to and including the tagged reply.
async fn imap(c: &mut Client, tag: &str, command: &str) -> Vec<String> {
    c.send_raw(format!("{tag} {command}\r\n").as_bytes()).await;
    let mut lines = Vec::new();
    loop {
        let line = c.read_line().await.expect("the connection stays open");
        let done = line.starts_with(&format!("{tag} "));
        lines.push(line);
        if done {
            return lines;
        }
    }
}

async fn imap_login(addr: std::net::SocketAddr, user: &str) -> Client {
    let mut c = Client::connect_tls(addr).await;
    c.read_line().await.unwrap();
    assert!(imap(&mut c, "l", &format!("LOGIN {user} \"{PASSWORD}\"")).await.last().unwrap().starts_with("l OK"));
    c
}

#[tokio::test]
async fn imap_access_control_lists() {
    let w = world().await;
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(unomail::imap::serve(w.env.app.clone(), listener));
    let shared = "\"Shared/bob@example.org/Projects\"";

    let mut bob = imap_login(addr, "bob@example.org").await;
    assert!(imap(&mut bob, "a1", "CAPABILITY").await[0].contains(" ACL "));
    assert_eq!(imap(&mut bob, "a2", "NAMESPACE").await[0], "* NAMESPACE ((\"\" \"/\")) ((\"Shared/\" \"/\")) NIL");
    assert_eq!(imap(&mut bob, "a3", "MYRIGHTS Projects").await[0], "* MYRIGHTS \"Projects\" lrswipkxtea");
    assert_eq!(imap(&mut bob, "a4", "LISTRIGHTS Projects carol@example.org").await[0], "* LISTRIGHTS \"Projects\" \"carol@example.org\" \"\" l r s w i p k x t e a");
    assert!(imap(&mut bob, "a5", "SETACL Projects carol@example.org lr").await[0].starts_with("a5 OK"));
    assert!(imap(&mut bob, "a6", "SETACL Projects carol@example.org +s").await[0].starts_with("a6 OK"));
    assert_eq!(imap(&mut bob, "a7", "GETACL Projects").await[0], "* ACL \"Projects\" \"bob@example.org\" lrswipkxtea \"carol@example.org\" lrs");
    for refused in ["SETACL Projects erin@other.example lr", "SETACL Projects carol@example.org lrq", "SETACL Projects bob@example.org lr", "SETACL Nowhere carol@example.org lr"] {
        assert!(imap(&mut bob, "a8", refused).await[0].starts_with("a8 NO"), "{refused}");
    }

    // Carol: the folder shows up in the shared namespace and honours her rights.
    let mut carol = imap_login(addr, "carol@example.org").await;
    let listed = imap(&mut carol, "b1", "LIST \"\" \"*\"").await;
    assert!(listed.contains(&format!("* LIST (\\HasNoChildren) \"/\" {shared}")), "{listed:?}");
    assert!(imap(&mut carol, "b2", "LIST \"Shared/\" \"*\"").await.len() == 2, "only the shared folder matches");
    assert_eq!(imap(&mut carol, "b3", &format!("MYRIGHTS {shared}")).await[0], format!("* MYRIGHTS {shared} lrs"));
    assert!(imap(&mut carol, "b4", &format!("GETACL {shared}")).await[0].starts_with("b4 NO [NOPERM]"));
    assert!(imap(&mut carol, "b5", &format!("SETACL {shared} dave@example.org lr")).await[0].starts_with("b5 NO [NOPERM]"));
    assert!(imap(&mut carol, "b6", &format!("STATUS {shared} (MESSAGES)")).await[0].contains("(MESSAGES 2)"));
    let selected = imap(&mut carol, "b7", &format!("SELECT {shared}")).await;
    assert!(selected[0] == "* 2 EXISTS" && selected.last().unwrap().starts_with("b7 OK"), "{selected:?}");
    let fetched = imap(&mut carol, "b8", "FETCH 1 (BODY.PEEK[HEADER.FIELDS (SUBJECT)])").await.join("\n");
    assert!(fetched.contains("Subject: Project 1"));
    assert!(imap(&mut carol, "b9", "STORE 1 +FLAGS (\\Seen)").await.last().unwrap().starts_with("b9 OK"));
    for (command, why) in [("STORE 1 +FLAGS (\\Flagged)", "w"), ("STORE 1 +FLAGS (\\Deleted)", "t"), ("STORE 1 FLAGS (\\Seen)", "replacing all flags"), ("EXPUNGE", "e"), ("MOVE 1 INBOX", "t and e")] {
        assert!(imap(&mut carol, "c1", command).await.last().unwrap().starts_with("c1 NO [NOPERM]"), "{command} needs {why}");
    }
    assert!(imap(&mut carol, "c2", "COPY 1 INBOX").await.last().unwrap().starts_with("c2 OK"), "reading allows copying out");
    assert_eq!(w.env.inbox(&w.carol).await.len(), 1);
    c_append_refused(&mut carol, shared).await;
    for refused in [format!("DELETE {shared}"), format!("RENAME {shared} Mine")] {
        assert!(imap(&mut carol, "c4", &refused).await[0].starts_with("c4 NO"), "{refused}");
    }
    assert!(imap(&mut carol, "c5", "CREATE \"Shared/bob@example.org/Fake\"").await[0].starts_with("c5 NO"));
    assert_eq!(w.env.app.store.messages_in(w.projects).await.unwrap().len(), 2);

    // Dave has no access at all: the folder does not exist for him.
    let mut dave = imap_login(addr, "dave@example.org").await;
    assert!(!imap(&mut dave, "d1", "LIST \"\" \"*\"").await.join("\n").contains("Shared/"));
    for command in [format!("SELECT {shared}"), format!("STATUS {shared} (MESSAGES)"), format!("MYRIGHTS {shared}")] {
        assert!(imap(&mut dave, "d2", &command).await[0].starts_with("d2 NO no such mailbox"), "{command}");
    }

    // With insert, delete and expunge rights Carol can file mail in and take mail out.
    assert!(imap(&mut bob, "e1", "SETACL Projects carol@example.org lrswite").await[0].starts_with("e1 OK"));
    let mut carol = imap_login(addr, "carol@example.org").await;
    imap(&mut carol, "f1", &format!("SELECT {shared}")).await;
    assert!(imap(&mut carol, "f2", "MOVE 1 INBOX").await.last().unwrap().starts_with("f2 OK"));
    assert_eq!((w.env.app.store.messages_in(w.projects).await.unwrap().len(), w.env.inbox(&w.carol).await.len()), (1, 2));
    imap(&mut carol, "f3", "SELECT INBOX").await;
    assert!(imap(&mut carol, "f4", &format!("COPY 1 {shared}")).await.last().unwrap().starts_with("f4 OK"));
    assert_eq!(w.env.app.store.messages_in(w.projects).await.unwrap().len(), 2);

    assert!(imap(&mut bob, "g1", "DELETEACL Projects carol@example.org").await[0].starts_with("g1 OK"));
    assert!(imap(&mut carol, "g2", &format!("SELECT {shared}")).await[0].starts_with("g2 NO"));
}

async fn c_append_refused(c: &mut Client, mailbox: &str) {
    let lines = imap(c, "c3", &format!("APPEND {mailbox} {{5+}}\r\nhello")).await;
    assert!(lines.last().unwrap().starts_with("c3 NO [NOPERM]"), "{lines:?}");
}

#[tokio::test]
async fn ready_made_messages_are_imported_and_sent_unchanged() {
    let w = world().await;
    let account = w.bob_api.jmap_account().await;
    let drafts = w.env.app.store.mailbox_by_role(w.bob.id, "drafts").await.unwrap().unwrap().id;
    let sent = w.env.app.store.mailbox_by_role(w.bob.id, "sent").await.unwrap().unwrap().id;
    // A PGP/MIME message as the web client builds it.
    let raw = "From: bob@example.org\r\nTo: carol@example.org\r\nSubject: ...\r\nMIME-Version: 1.0\r\n\
               Content-Type: multipart/encrypted; protocol=\"application/pgp-encrypted\"; boundary=\"b\"\r\n\r\n\
               --b\r\nContent-Type: application/pgp-encrypted\r\n\r\nVersion: 1\r\n\r\n\
               --b\r\nContent-Type: application/octet-stream; name=\"encrypted.asc\"\r\n\r\n-----BEGIN PGP MESSAGE-----\r\n\r\nwV4D\r\n-----END PGP MESSAGE-----\r\n--b--\r\n";
    let upload = w.bob_api.raw(Method::POST, &format!("/jmap/upload/{account}"), raw.as_bytes().to_vec(), "message/rfc822").await;
    assert_eq!(upload.status, StatusCode::CREATED, "{}", upload.text);
    let blob = upload.body["blobId"].as_str().unwrap().to_owned();

    let reply = w
        .bob_api
        .jmap(json!([
            ["Email/import", { "accountId": account, "emails": { "e": { "blobId": blob, "mailboxIds": { format!("b{drafts}"): true }, "keywords": { "$draft": true, "$seen": true } } } }, "i"],
            ["EmailSubmission/set", { "accountId": account, "create": { "s": { "emailId": "#e" } }, "onSuccessUpdateEmail": { "#s": { "mailboxIds": { format!("b{sent}"): true }, "keywords/$draft": null } } }, "s"],
        ]))
        .await;
    assert!(reply[0][1]["created"]["e"]["id"].is_string(), "{reply}");
    assert!(reply[1][1]["created"]["s"].is_object(), "{reply}");
    let delivered = w.env.inbox(&w.carol).await;
    assert!(delivered[0].contains("Content-Type: multipart/encrypted; protocol=\"application/pgp-encrypted\"") && delivered[0].contains("-----BEGIN PGP MESSAGE-----"), "the structure is untouched");
    assert_eq!(w.env.app.store.messages_in(sent).await.unwrap().len(), 1);

    // Imports are limited to the user's own uploads, real messages, and mailboxes they may write to.
    let other_blob = w.env.app.store.messages_in(w.projects).await.unwrap()[0].blob_hash.clone();
    let junk = w.bob_api.raw(Method::POST, &format!("/jmap/upload/{account}"), b"just some text".to_vec(), "text/plain").await.body["blobId"].as_str().unwrap().to_owned();
    let carol_inbox = w.env.app.store.mailbox_by_role(w.carol.id, "inbox").await.unwrap().unwrap().id;
    let bad = w
        .bob_api
        .jmap(json!([["Email/import", { "accountId": account, "emails": {
            "foreign": { "blobId": other_blob, "mailboxIds": { format!("b{drafts}"): true } },
            "missing": { "blobId": format!("u{}", "0".repeat(64)), "mailboxIds": { format!("b{drafts}"): true } },
            "junk": { "blobId": junk, "mailboxIds": { format!("b{drafts}"): true } },
            "elsewhere": { "blobId": blob, "mailboxIds": { format!("b{carol_inbox}"): true } },
        } }, "i"]]))
        .await[0][1]
        .clone();
    assert_eq!(bad["created"], json!({}));
    let kinds: Vec<&str> = ["foreign", "missing", "junk", "elsewhere"].iter().map(|k| bad["notCreated"][k]["type"].as_str().unwrap()).collect();
    assert_eq!(kinds, ["blobNotFound", "blobNotFound", "invalidEmail", "invalidProperties"]);

    // A forged sender is still refused at submission, however the message was created.
    let forged = raw.replace("From: bob@example.org", "From: carol@example.org");
    let blob = w.bob_api.raw(Method::POST, &format!("/jmap/upload/{account}"), forged.into_bytes(), "message/rfc822").await.body["blobId"].as_str().unwrap().to_owned();
    let reply = w
        .bob_api
        .jmap(json!([
            ["Email/import", { "accountId": account, "emails": { "e": { "blobId": blob, "mailboxIds": { format!("b{drafts}"): true } } } }, "i"],
            ["EmailSubmission/set", { "accountId": account, "create": { "s": { "emailId": "#e" } } }, "s"],
        ]))
        .await;
    assert_eq!(reply[1][1]["notCreated"]["s"]["type"], "forbiddenToSend", "{reply}");
}
