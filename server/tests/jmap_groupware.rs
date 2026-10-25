//! JMAP beyond mail: Quota, Sieve scripts, contacts and calendars.

mod common;

use axum::http::Method;
use common::{Api, TestEnv};
use serde_json::{Value, json};
use unomail::auth::Role;

async fn upload(api: &Api, account: &str, data: &str) -> String {
    let reply = api.raw(Method::POST, &format!("/jmap/upload/{account}"), data.as_bytes().to_vec(), "application/sieve").await;
    reply.body["blobId"].as_str().unwrap_or_else(|| panic!("upload failed: {}", reply.text)).to_owned()
}

#[tokio::test]
async fn the_session_announces_the_new_capabilities() {
    let env = TestEnv::start().await;
    env.domain("example.org").await;
    env.account("bob@example.org").await;
    let api = Api::logged_in(&env, "bob@example.org").await;
    let session = api.get("/jmap/session").await.body;
    for capability in ["urn:ietf:params:jmap:quota", "urn:ietf:params:jmap:sieve", "urn:ietf:params:jmap:contacts", "urn:ietf:params:jmap:calendars"] {
        assert!(session["capabilities"].get(capability).is_some(), "{capability}");
        assert!(session["primaryAccounts"].get(capability).is_some(), "{capability}");
    }
    let account = api.jmap_account().await;
    assert_eq!(session["accounts"][&account]["accountCapabilities"]["urn:ietf:params:jmap:sieve"]["implementation"], "unoMail");
}

#[tokio::test]
async fn quotas_follow_the_account() {
    let env = TestEnv::start().await;
    env.domain("example.org").await;
    env.account_with("bob@example.org", Role::User, Some(10 * 1024 * 1024)).await;
    env.account_with("carol@example.org", Role::User, Some(0)).await;
    let bob = Api::logged_in(&env, "bob@example.org").await;
    let account = bob.jmap_account().await;
    let got = bob.jmap(json!([["Quota/get", { "accountId": account, "ids": null }, "0"], ["Quota/query", { "accountId": account, "filter": { "resourceType": "octets" } }, "1"]])).await;
    let quota = &got[0][1]["list"][0];
    assert_eq!((quota["id"].as_str(), quota["resourceType"].as_str(), quota["hardLimit"].as_i64(), quota["scope"].as_str()), (Some("q1"), Some("octets"), Some(10 * 1024 * 1024), Some("account")));
    assert_eq!(got[1][1]["ids"], json!(["q1"]));
    let state = got[0][1]["state"].as_str().unwrap().to_owned();
    let unchanged = bob.jmap(json!([["Quota/changes", { "accountId": account, "sinceState": state }, "0"]])).await;
    assert_eq!(unchanged[0][1]["updated"], json!([]));

    // Without a limit there is no quota to report.
    let carol = Api::logged_in(&env, "carol@example.org").await;
    let carol_account = carol.jmap_account().await;
    let none = carol.jmap(json!([["Quota/get", { "accountId": carol_account, "ids": ["q1"] }, "0"]])).await;
    assert_eq!((none[0][1]["list"].clone(), none[0][1]["notFound"].clone()), (json!([]), json!(["q1"])));
}

#[tokio::test]
async fn sieve_scripts_are_managed_and_activated() {
    let env = TestEnv::start().await;
    env.domain("example.org").await;
    env.account("bob@example.org").await;
    let api = Api::logged_in(&env, "bob@example.org").await;
    let account = api.jmap_account().await;
    let good = upload(&api, &account, "require \"fileinto\";\nif header :contains \"subject\" \"x\" { fileinto \"Archive\"; }\n").await;
    let bad = upload(&api, &account, "if nonsense {").await;

    let validated = api.jmap(json!([["SieveScript/validate", { "accountId": account, "blobId": good }, "0"], ["SieveScript/validate", { "accountId": account, "blobId": bad }, "1"]])).await;
    assert_eq!(validated[0][1]["error"], Value::Null);
    assert_eq!(validated[1][1]["error"]["type"], "invalidScript");

    let set = api
        .jmap(json!([["SieveScript/set", {
            "accountId": account,
            "create": { "a": { "name": "filters", "blobId": good }, "b": { "name": "broken", "blobId": bad } },
            "onSuccessActivateScript": "#a",
        }, "0"]]))
        .await;
    assert!(set[0][1]["created"]["a"]["id"].is_string(), "{}", set[0][1]);
    assert_eq!(set[0][1]["notCreated"]["b"]["type"], "invalidScript");
    // One creation failed, so nothing was activated.
    let id = set[0][1]["created"]["a"]["id"].as_str().unwrap().to_owned();
    let listed = api.jmap(json!([["SieveScript/get", { "accountId": account }, "0"]])).await;
    assert_eq!(listed[0][1]["list"][0]["isActive"], false);

    let activated = api.jmap(json!([["SieveScript/set", { "accountId": account, "onSuccessActivateScript": id }, "0"]])).await;
    assert_eq!(activated[0][1]["updated"][&id]["isActive"], true);
    // The same script ManageSieve and the web client see.
    let stored = unomail::sieve::all(&env.app, api_account_id(&env, "bob@example.org").await).await.unwrap();
    assert!(stored.iter().any(|s| s.name == "filters" && s.active));

    // The script can be downloaded by its blob id and is refused deletion while active.
    let blob = listed[0][1]["list"][0]["blobId"].as_str().unwrap().to_owned();
    let download = api.get(&format!("/jmap/download/{account}/{blob}/filters.siv")).await;
    assert!(download.text.contains("fileinto"));
    let refused = api.jmap(json!([["SieveScript/set", { "accountId": account, "destroy": [id] }, "0"]])).await;
    assert_eq!(refused[0][1]["notDestroyed"][&id]["type"], "scriptIsActive");
    let state = refused[0][1]["newState"].as_str().unwrap().to_owned();
    let off = api.jmap(json!([["SieveScript/set", { "accountId": account, "onSuccessDeactivateScript": true, "destroy": [] }, "0"]])).await;
    assert_eq!(off[0][1]["updated"][&id]["isActive"], false);
    let changes = api.jmap(json!([["SieveScript/changes", { "accountId": account, "sinceState": state }, "0"]])).await;
    assert_eq!(changes[0][1]["updated"], json!([id]));
    let gone = api.jmap(json!([["SieveScript/set", { "accountId": account, "destroy": [id] }, "0"]])).await;
    assert_eq!(gone[0][1]["destroyed"], json!([id]));
}

async fn api_account_id(env: &TestEnv, email: &str) -> i64 {
    sqlx::query_scalar("SELECT id FROM accounts WHERE email = ?").bind(email).fetch_one(&env.app.db).await.unwrap()
}

#[tokio::test]
async fn contact_cards_share_the_address_book() {
    let env = TestEnv::start().await;
    env.domain("example.org").await;
    env.account("bob@example.org").await;
    let api = Api::logged_in(&env, "bob@example.org").await;
    let account = api.jmap_account().await;
    let start = api.jmap(json!([["ContactCard/get", { "accountId": account, "ids": [] }, "0"]])).await[0][1]["state"].as_str().unwrap().to_owned();

    let created = api
        .jmap(json!([["ContactCard/set", { "accountId": account, "create": { "c": {
            "@type": "Card", "version": "1.0", "addressBookIds": { "default": true },
            "name": { "full": "Anna Nowak" }, "emails": { "e": { "address": "anna@example.net" } }, "phones": { "p": { "number": "+48 600 000 000" } },
        } } }, "0"]]))
        .await;
    let id = created[0][1]["created"]["c"]["id"].as_str().unwrap_or_else(|| panic!("{}", created[0][1])).to_owned();
    // The web client's address book shows the card.
    let contacts = api.get("/api/me/contacts").await.body;
    assert!(contacts.as_array().unwrap().iter().any(|c| c["email"] == "anna@example.net" && c["name"] == "Anna Nowak"), "{contacts}");

    let patched = api.jmap(json!([["ContactCard/set", { "accountId": account, "update": { &id: { "name/full": "Anna Kowalska", "organizations": { "o": { "name": "Acme" } } } } }, "0"]])).await;
    assert!(patched[0][1]["updated"].get(&id).is_some(), "{}", patched[0][1]);
    let found = api
        .jmap(json!([
            ["ContactCard/query", { "accountId": account, "filter": { "text": "acme" }, "sort": [{ "property": "name" }] }, "q"],
            ["ContactCard/get", { "accountId": account, "#ids": { "resultOf": "q", "name": "ContactCard/query", "path": "/ids" } }, "g"],
        ]))
        .await;
    assert_eq!(found[0][1]["ids"], json!([id]));
    assert_eq!(found[1][1]["list"][0]["name"]["full"], "Anna Kowalska");
    assert_eq!(found[1][1]["list"][0]["organizations"]["o1"]["name"], "Acme");

    let refused = api.jmap(json!([["ContactCard/set", { "accountId": account, "create": { "x": { "emails": { "e": { "address": "nope" } } } } }, "0"]])).await;
    assert_eq!(refused[0][1]["notCreated"]["x"]["type"], "invalidProperties");

    let destroyed = api.jmap(json!([["ContactCard/set", { "accountId": account, "destroy": [id] }, "0"]])).await;
    assert_eq!(destroyed[0][1]["destroyed"], json!([id]));
    let changes = api.jmap(json!([["ContactCard/changes", { "accountId": account, "sinceState": start }, "0"]])).await;
    // Created and destroyed since then: nothing to tell.
    assert_eq!((changes[0][1]["created"].clone(), changes[0][1]["destroyed"].clone()), (json!([]), json!([])));
    let book = api.jmap(json!([["AddressBook/get", { "accountId": account }, "0"]])).await;
    assert_eq!(book[0][1]["list"][0]["id"], "default");
}

#[tokio::test]
async fn calendars_and_events_round_trip() {
    let env = TestEnv::start().await;
    env.domain("example.org").await;
    env.account("bob@example.org").await;
    let api = Api::logged_in(&env, "bob@example.org").await;
    let account = api.jmap_account().await;

    let calendars = api.jmap(json!([["Calendar/get", { "accountId": account }, "0"]])).await;
    let personal = calendars[0][1]["list"][0]["id"].as_str().unwrap().to_owned();
    assert_eq!(calendars[0][1]["list"][0]["isDefault"], true);
    let event_state = api.jmap(json!([["CalendarEvent/get", { "accountId": account, "ids": [] }, "0"]])).await[0][1]["state"].as_str().unwrap().to_owned();

    let created = api
        .jmap(json!([
            ["Calendar/set", { "accountId": account, "create": { "w": { "name": "Work", "color": "#ff0000" } } }, "c"],
            ["CalendarEvent/set", { "accountId": account, "create": { "e": {
                "@type": "Event", "calendarIds": { "#w": true }, "title": "Planning", "start": "2026-11-02T10:00:00", "duration": "PT1H30M",
                "timeZone": "Europe/Warsaw", "recurrenceRules": [{ "@type": "RecurrenceRule", "frequency": "weekly", "count": 4 }],
                "locations": { "l": { "name": "Room 2" } }, "alerts": { "a": { "trigger": { "@type": "OffsetTrigger", "offset": "-PT15M" } } },
            } } }, "e"],
        ]))
        .await;
    let work = created[0][1]["created"]["w"]["id"].as_str().unwrap_or_else(|| panic!("{}", created[0][1])).to_owned();
    let id = created[1][1]["created"]["e"]["id"].as_str().unwrap_or_else(|| panic!("{}", created[1][1])).to_owned();

    let found = api
        .jmap(json!([
            ["CalendarEvent/query", { "accountId": account, "filter": { "inCalendar": work, "after": "2026-11-01T00:00:00Z", "before": "2026-12-01T00:00:00Z" } }, "q"],
            ["CalendarEvent/get", { "accountId": account, "#ids": { "resultOf": "q", "name": "CalendarEvent/query", "path": "/ids" } }, "g"],
        ]))
        .await;
    assert_eq!(found[0][1]["ids"], json!([id]));
    let event = &found[1][1]["list"][0];
    assert_eq!((event["title"].as_str(), event["start"].as_str(), event["duration"].as_str(), event["timeZone"].as_str()), (Some("Planning"), Some("2026-11-02T10:00:00"), Some("PT1H30M"), Some("Europe/Warsaw")));
    assert_eq!(event["recurrenceRules"][0]["count"], 4);
    assert_eq!(event["locations"]["l1"]["name"], "Room 2");
    assert_eq!(event["alerts"]["a1"]["trigger"]["offset"], "-PT15M");
    // CalDAV sees the same event.
    let stored: String = sqlx::query_scalar("SELECT data FROM calendar_objects WHERE uid = ?").bind(event["uid"].as_str().unwrap()).fetch_one(&env.app.db).await.unwrap();
    assert!(stored.contains("SUMMARY:Planning") && stored.contains("RRULE:FREQ=WEEKLY;COUNT=4"), "{stored}");

    let moved = api.jmap(json!([["CalendarEvent/set", { "accountId": account, "update": { &id: { "title": "Planning (moved)", "start": "2026-11-03T11:00:00", "calendarIds": { &personal: true } } } }, "0"]])).await;
    assert!(moved[0][1]["updated"].get(&id).is_some(), "{}", moved[0][1]);
    let changes = api.jmap(json!([["CalendarEvent/changes", { "accountId": account, "sinceState": event_state }, "0"]])).await;
    assert_eq!(changes[0][1]["created"], json!([id]), "the event keeps its id when it moves");
    let after = api.jmap(json!([["CalendarEvent/get", { "accountId": account, "ids": [id] }, "0"]])).await;
    assert_eq!(after[0][1]["list"][0]["title"], "Planning (moved)");
    assert_eq!(after[0][1]["list"][0]["calendarIds"], json!({ &personal: true }));
    assert!(stored.contains("VALARM") && sqlx::query_scalar::<_, String>("SELECT data FROM calendar_objects WHERE uid = ?").bind(event["uid"].as_str().unwrap()).fetch_one(&env.app.db).await.unwrap().contains("LOCATION:Room 2"), "untouched properties stay");

    let refused = api.jmap(json!([["Calendar/set", { "accountId": account, "destroy": [personal] }, "0"]])).await;
    assert_eq!(refused[0][1]["notDestroyed"][&personal]["type"], "calendarHasEvent");
    let destroyed = api.jmap(json!([["CalendarEvent/set", { "accountId": account, "destroy": [id] }, "0"], ["Calendar/set", { "accountId": account, "destroy": [work] }, "1"]])).await;
    assert_eq!(destroyed[0][1]["destroyed"], json!([id]));
    assert_eq!(destroyed[1][1]["destroyed"], json!([work]));
}

#[tokio::test]
async fn blobs_are_built_read_and_looked_up() {
    let env = TestEnv::start().await;
    env.domain("example.org").await;
    env.account("bob@example.org").await;
    let api = Api::logged_in(&env, "bob@example.org").await;
    let account = api.jmap_account().await;
    let session = api.get("/jmap/session").await.body;
    assert_eq!(session["accounts"][&account]["accountCapabilities"]["urn:ietf:params:jmap:blob"]["supportedTypeNames"], json!(["Email", "Mailbox", "Thread"]));

    let message = "From: ann@example.org\r\nTo: bob@example.org\r\nSubject: Built\r\n\r\nHello there\r\n";
    let (head, body) = message.split_at(20);
    let got = api
        .jmap(json!([
            ["Blob/upload", { "accountId": account, "create": {
                "a": { "data": [{ "data:asText": head }, { "data:asBase64": base64_encode(body) }], "type": "message/rfc822" },
                "b": { "data": [{ "blobId": "#a", "offset": 6, "length": 15 }] },
                "bad": { "data": [{ "blobId": "#a", "offset": 1000, "length": 1 }] },
            } }, "0"],
            ["Blob/get", { "accountId": account, "ids": ["#b", "nope"], "properties": ["data:asText", "digest:sha-256", "size"] }, "1"],
            ["Mailbox/get", { "accountId": account, "ids": null }, "2"],
        ]))
        .await;
    assert_eq!(got[0][1]["created"]["a"]["size"], message.len());
    assert_eq!(got[0][1]["notCreated"]["bad"]["type"], "invalidProperties");
    let piece = &got[1][1]["list"][0];
    assert_eq!((piece["data:asText"].as_str(), piece["size"].as_u64()), (Some("ann@example.org"), Some(15)));
    assert!(piece["digest:sha-256"].as_str().is_some_and(|d| d.len() == 44));
    assert_eq!(got[1][1]["notFound"], json!(["nope"]));

    let inbox = got[2][1]["list"].as_array().unwrap().iter().find(|m| m["role"] == "inbox").unwrap()["id"].as_str().unwrap().to_owned();
    let blob = got[0][1]["created"]["a"]["id"].as_str().unwrap().to_owned();
    let imported = api.jmap(json!([["Email/import", { "accountId": account, "emails": { "e": { "blobId": blob, "mailboxIds": { &inbox: true } } } }, "0"]])).await;
    let email = &imported[0][1]["created"]["e"];
    let found = api.jmap(json!([["Blob/lookup", { "accountId": account, "typeNames": ["Email", "Mailbox"], "ids": [email["blobId"]] }, "0"]])).await;
    assert_eq!(found[0][1]["list"][0]["matchedIds"]["Email"], json!([email["id"]]), "{found} {imported}");
    assert_eq!(found[0][1]["list"][0]["matchedIds"]["Mailbox"], json!([inbox]));
    let wrong = api.jmap(json!([["Blob/lookup", { "accountId": account, "typeNames": ["Calendar"], "ids": [] }, "0"]])).await;
    assert_eq!(wrong[0][1]["type"], "unknownDataType");
}

fn base64_encode(data: &str) -> String {
    use base64::Engine;
    base64::engine::general_purpose::STANDARD.encode(data)
}

#[tokio::test]
async fn principals_list_the_domain() {
    let env = TestEnv::start().await;
    env.domain("example.org").await;
    env.domain("other.example").await;
    env.account("bob@example.org").await;
    env.account("carol@example.org").await;
    env.account("eve@other.example").await;
    let api = Api::logged_in(&env, "bob@example.org").await;
    let account = api.jmap_account().await;
    let session = api.get("/jmap/session").await.body;
    let me = session["accounts"][&account]["accountCapabilities"]["urn:ietf:params:jmap:principals"]["currentUserPrincipalId"].as_str().unwrap().to_owned();
    let got = api
        .jmap(json!([
            ["Principal/query", { "accountId": account, "filter": { "text": "carol" } }, "0"],
            ["Principal/get", { "accountId": account, "ids": null }, "1"],
            ["ShareNotification/query", { "accountId": account }, "2"],
        ]))
        .await;
    assert_eq!(got[0][1]["total"], 1);
    let emails: Vec<&str> = got[1][1]["list"].as_array().unwrap().iter().map(|p| p["email"].as_str().unwrap()).collect();
    assert_eq!(emails, ["bob@example.org", "carol@example.org"], "other domains stay hidden");
    let mine = got[1][1]["list"].as_array().unwrap().iter().find(|p| p["id"] == me.as_str()).unwrap();
    assert!(mine["accounts"][&account].get("urn:ietf:params:jmap:principals:owner").is_some());
    assert_eq!(got[2][1]["ids"], json!([]));
}
