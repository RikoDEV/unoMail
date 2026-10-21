mod common;
use common::{Api,Client,TestEnv};
use serde_json::json;
use unomail::{auth::Role,masked_email::{self as masks,Create,Update},smtp::{delivery::{self,Resolution},submit::{self,Outcome,Submission}},util::{Address,now}};

async fn setup()->(TestEnv,unomail::auth::Account){let env=TestEnv::start().await;env.domain("example.test").await;let a=env.account("alice@example.test").await;(env,a)}

#[tokio::test]
async fn lifecycle_denials_win_over_catchall_and_reservations_survive_deletion(){
    let (env,a)=setup().await;
    sqlx::query("UPDATE domains SET catch_all=? WHERE id=?").bind(&a.email).bind(a.domain_id).execute(&env.app.db).await.unwrap();
    let m=masks::create(&env.app,a.id,Create{prefix:"a".repeat(37),for_domain:"https://shop.example/path".into(),..Default::default()},"test").await.unwrap();
    assert_eq!(m.email.split('@').next().unwrap().len(),64);assert_eq!(m.for_domain,"shop.example");
    masks::destroy(&env.app,a.id,m.id).await.unwrap();
    let m=masks::create(&env.app,a.id,Create{prefix:"shop".into(),..Default::default()},"test").await.unwrap();
    let address=Address::parse(&m.email).unwrap();
    assert!(matches!(delivery::resolve(&env.app,&address).await.unwrap(),Resolution::Deliver(_)));
    assert!(masks::create(&env.app,a.id,Create{domain:Some("other.test".into()),..Default::default()},"test").await.is_err());
    let (disabled,metadata,website)=tokio::join!(
        masks::update(&env.app,a.id,m.id,Update{enabled:Some(false),..Default::default()}),
        masks::update(&env.app,a.id,m.id,Update{description:Some("Updated description".into()),..Default::default()}),
        masks::update(&env.app,a.id,m.id,Update{for_domain:Some("shop.example".into()),..Default::default()})
    );
    disabled.unwrap();metadata.unwrap();website.unwrap();
    assert_eq!(delivery::resolve(&env.app,&address).await.unwrap(),Resolution::NoSuchUser);
    let tagged=Address::parse(&m.email.replace('@',"+tag@")).unwrap();
    assert_eq!(delivery::resolve(&env.app,&tagged).await.unwrap(),Resolution::NoSuchUser);
    masks::update(&env.app,a.id,m.id,Update{enabled:Some(true),..Default::default()}).await.unwrap();
    assert_eq!(masks::owned(&env.app,a.id,&address).await.unwrap(),Some(true));
    masks::destroy(&env.app,a.id,m.id).await.unwrap();
    assert_eq!(delivery::resolve(&env.app,&address).await.unwrap(),Resolution::NoSuchUser);
    assert_eq!(delivery::resolve(&env.app,&tagged).await.unwrap(),Resolution::NoSuchUser);
    assert!(unomail::directory::create_alias(&env.app.db,&m.email,&[a.email.clone()]).await.is_err());
    let api=Api::logged_in(&env,&a.email).await;
    assert_eq!(api.get(&format!("/api/me/masked-addresses/{}",m.id)).await.status,405);
    assert_eq!(api.patch(&format!("/api/me/masked-addresses/{}",m.id),json!({"enabled":true})).await.status,404);
}

#[tokio::test]
async fn expiration_and_concurrent_quota_are_enforced_atomically(){
    let (env,a)=setup().await;
    sqlx::query("INSERT INTO masked_account_policy(account_id,max_masks) VALUES(?,2)").bind(a.id).execute(&env.app.db).await.unwrap();
    let (one,two,three)=tokio::join!(masks::create(&env.app,a.id,Create::default(),"one"),masks::create(&env.app,a.id,Create::default(),"two"),masks::create(&env.app,a.id,Create::default(),"three"));
    assert_eq!([one.is_ok(),two.is_ok(),three.is_ok()].into_iter().filter(|b|*b).count(),2);
    let rows=masks::list(&env.app,a.id).await.unwrap();
    masks::destroy(&env.app,a.id,rows[0].id).await.unwrap();
    let m=masks::create(&env.app,a.id,Create{expires_at:Some(now()+1),..Default::default()},"expires").await.unwrap();
    let api=Api::logged_in(&env,&a.email).await;
    assert_eq!(api.patch(&format!("/api/me/masked-addresses/{}",m.id),json!({"expires_at":now()+1000})).await.status,422);
    tokio::time::sleep(std::time::Duration::from_secs(2)).await;
    assert_eq!(masks::get(&env.app,a.id,m.id).await.unwrap().view()["status"],"expired");
    assert_eq!(masks::owned(&env.app,a.id,&Address::parse(&m.email).unwrap()).await.unwrap(),Some(false));
    assert!(masks::update(&env.app,a.id,m.id,Update{enabled:Some(true),..Default::default()}).await.is_err());
    masks::expire(&env.app).await.unwrap();
    let state:i64=sqlx::query_scalar("SELECT COUNT(*) FROM masked_changes WHERE account_id=? AND item_id=? AND change='updated'").bind(a.id).bind(m.id).fetch_one(&env.app.db).await.unwrap();
    assert_eq!(state,1);
}

#[tokio::test]
async fn delivery_is_trusted_bcc_safe_and_sending_never_substitutes_the_primary(){
    let (env,a)=setup().await;let b=env.account("bob@example.test").await;
    let mask=masks::create(&env.app,a.id,Create::default(),"test").await.unwrap();
    let mut mx=Client::connect(env.mx).await;assert!(mx.read_reply().await.starts_with("220"));mx.cmd("EHLO remote.test").await;
    assert!(mx.send_mail("sender@remote.test",&[&mask.email],"From: sender@remote.test\r\nTo: undisclosed-recipients:;\r\nSubject: Bcc mask\r\nDelivered-To: attacker@elsewhere.test\r\n\r\nHello\r\n").await.starts_with("250"));
    let inbox=env.app.store.mailbox_by_role(a.id,"inbox").await.unwrap().unwrap();let messages=env.app.store.messages_in(inbox.id).await.unwrap();
    assert_eq!(masks::delivery_addresses(&env.app,a.id,messages[0].id).await.unwrap(),[mask.email.clone()]);
    let archive=env.app.store.mailbox_by_role(a.id,"archive").await.unwrap().unwrap();
    let copied=env.app.store.copy_message(a.id,messages[0].id,archive.id).await.unwrap();
    assert_eq!(masks::delivery_addresses(&env.app,a.id,copied.id).await.unwrap(),[mask.email.clone()]);
    let target=env.app.store.mailbox_by_role(b.id,"inbox").await.unwrap().unwrap();
    let copy=env.app.store.copy_across(a.id,messages[0].id,b.id,target.id).await.unwrap();
    assert!(masks::delivery_addresses(&env.app,b.id,copy.id).await.unwrap().is_empty());
    env.app.store.delete_message(b.id,copy.id).await.unwrap();
    let api=Api::logged_in(&env,&a.email).await;
    let message=api.post("/jmap/api",json!({"using":[],"methodCalls":[["Email/get",{"accountId":format!("a{}",a.id),"ids":[format!("m{}",messages[0].id)]},"get"]]})).await;
    assert_eq!(message.body["methodResponses"][0][1]["list"][0]["maskedAddresses"][0],mask.email);
    let address=Address::parse(&mask.email).unwrap();let recipient=Address::parse(&b.email).unwrap();
    let raw=format!("From: <{}>\r\nTo: {}\r\nSubject: Mask reply\r\n\r\nReply from the mask.\r\n",mask.email,b.email);
    let result=submit::submit(&env.app,Submission{account:&a,sender:&address,recipients:std::slice::from_ref(&recipient),raw:raw.as_bytes(),delegate:None,ip:"198.51.100.1".parse().unwrap()}).await;
    assert!(matches!(result,Outcome::Accepted(_)),"{result:?}");
    let received=env.inbox(&b).await.join("\n");assert!(received.contains(&mask.email));assert!(!received.contains(&a.email));
    masks::update(&env.app,a.id,mask.id,Update{enabled:Some(false),..Default::default()}).await.unwrap();
    assert!(!submit::identity_allowed(&env.app,&a,&address).await.unwrap());
    let raw=format!("From: {}\r\nTo: {}\r\n\r\nforged\r\n",mask.email,b.email);
    let mut rt=(*env.app.rt()).clone();rt.strict_from_check=false;env.app.settings.store(std::sync::Arc::new(rt));
    let result=submit::submit(&env.app,Submission{account:&a,sender:&Address::parse(&a.email).unwrap(),recipients:&[recipient],raw:raw.as_bytes(),delegate:None,ip:"198.51.100.1".parse().unwrap()}).await;
    assert!(matches!(result,Outcome::Rejected(_)));
}

#[tokio::test]
async fn scoped_jmap_tokens_only_manage_owned_masks_and_are_revocable(){
    let (env,a)=setup().await;let b=env.account("bob@example.test").await;
    let other=masks::create(&env.app,b.id,Create::default(),"other").await.unwrap();
    let token=masks::token_create(&env.app,a.id,"Password manager",now()+3600).await.unwrap();let bearer=format!("Bearer {}",token["token"].as_str().unwrap());
    let api=Api::new(&env);
    let response=api.send(axum::http::Method::POST,"/api/masked-email/jmap",Some(json!({"using":[masks::CAPABILITY],"methodCalls":[["MaskedEmail/set",{"accountId":format!("a{}",a.id),"create":{"new":{"description":"Shop","forDomain":"https://shop.example"}}},"create"],["Email/get",{"accountId":format!("a{}",a.id),"ids":[]},"forbidden"]]})),&[("authorization",&bearer)]).await;
    assert_eq!(response.status,200,"{}",response.text);
    let created=&response.body["methodResponses"][0][1]["created"]["new"];
    assert_eq!(created["createdBy"],"Password manager");assert!(created["email"].as_str().unwrap().ends_with("@example.test"));
    assert_eq!(response.body["methodResponses"][1][1]["type"],"forbidden");
    let response=api.send(axum::http::Method::POST,"/api/masked-email/jmap",Some(json!({"using":[],"methodCalls":[["MaskedEmail/set",{"accountId":format!("a{}",a.id),"destroy":[format!("x{}",other.id)]},"deny"],["MaskedEmail/changes",{"accountId":format!("a{}",a.id),"sinceState":"0"},"changes"]]})),&[("authorization",&bearer)]).await;
    assert_eq!(response.body["methodResponses"][0][1]["notDestroyed"][format!("x{}",other.id)]["type"],"notFound");
    assert_eq!(response.body["methodResponses"][1][1]["created"].as_array().unwrap().len(),1);
    assert_eq!(api.send(axum::http::Method::GET,"/jmap/session",None,&[("authorization",&bearer)]).await.status,401);
    let user=Api::logged_in(&env,&a.email).await;
    assert_eq!(user.delete(&format!("/api/me/masked-addresses/tokens/{}",token["id"])).await.status,200);
    assert_eq!(api.send(axum::http::Method::GET,"/api/masked-email/session",None,&[("authorization",&bearer)]).await.status,401);
}

#[tokio::test]
async fn administrative_domains_and_policy_do_not_grant_other_tenants_access(){
    let (env,a)=setup().await;let other_domain=env.domain("other.test").await;let b=env.account("bob@other.test").await;
    let admin=env.account_with("admin@example.test",Role::DomainAdmin,None).await;
    sqlx::query("INSERT INTO domain_admins(account_id,domain_id) VALUES(?,?)").bind(admin.id).bind(a.domain_id).execute(&env.app.db).await.unwrap();
    let api=Api::logged_in(&env,&admin.email).await;
    assert_eq!(api.get(&format!("/api/accounts/{}/masked-addresses",b.id)).await.status,404);
    assert_eq!(api.put(&format!("/api/accounts/{}/masked-policy",a.id),json!({"max_masks":2,"extra_domains":["other.test"]})).await.status,404);
    assert_eq!(api.put(&format!("/api/accounts/{}/masked-policy",a.id),json!({"max_masks":0,"extra_domains":[]})).await.status,200);
    assert!(masks::create(&env.app,a.id,Create::default(),"test").await.is_err());
    let _=other_domain;
}

#[tokio::test]
async fn scheduled_sends_revalidate_masks_and_masks_survive_primary_renames(){
    let (env,a)=setup().await;let b=env.account("bob@example.test").await;
    let mask=masks::create(&env.app,a.id,Create::default(),"test").await.unwrap();
    let drafts=env.app.store.mailbox_by_role(a.id,"drafts").await.unwrap().unwrap();
    let raw=format!("From: {}\r\nTo: {}\r\nSubject: Scheduled mask\r\n\r\nA scheduled reply.",mask.email,b.email);
    let draft=env.app.store.append(a.id,drafts.id,raw.as_bytes(),unomail::store::Flags{draft:true,..Default::default()},None).await.unwrap();
    let api=Api::logged_in(&env,&a.email).await;
    let response=api.post("/jmap/api",json!({"using":[],"methodCalls":[["EmailSubmission/set",{"accountId":format!("a{}",a.id),"create":{"send":{"emailId":format!("m{}",draft.id),"envelope":{"mailFrom":{"parameters":{"HOLDFOR":"3600"}}}}}},"schedule"]]})).await;
    assert!(response.body["methodResponses"][0][1]["created"]["send"]["id"].is_string(),"{}",response.text);
    sqlx::query("UPDATE accounts SET email='renamed@example.test',local_part='renamed' WHERE id=?").bind(a.id).execute(&env.app.db).await.unwrap();
    assert_eq!(masks::resolve(&env.app,&Address::parse(&mask.email).unwrap()).await.unwrap(),Some(Some(a.id)));
    masks::update(&env.app,a.id,mask.id,Update{enabled:Some(false),..Default::default()}).await.unwrap();
    sqlx::query("UPDATE email_submissions SET send_at=? WHERE account_id=?").bind(now()-1).bind(a.id).execute(&env.app.db).await.unwrap();
    unomail::jmap::submission::release_due(&env.app).await;
    assert!(env.inbox(&b).await.is_empty());
    let error:Option<String>=sqlx::query_scalar("SELECT error FROM email_submissions WHERE account_id=?").bind(a.id).fetch_one(&env.app.db).await.unwrap();
    assert!(error.unwrap().contains("inactive"));
}

#[tokio::test]
async fn read_receipts_use_the_mask_in_the_body_and_envelope(){
    let (env,a)=setup().await;let b=env.account("bob@example.test").await;
    let mask=masks::create(&env.app,a.id,Create::default(),"test").await.unwrap();
    let mut mx=Client::connect(env.mx).await;mx.read_reply().await;mx.cmd("EHLO remote.test").await;
    let raw=format!("From: {}\r\nTo: {}\r\nDisposition-Notification-To: {}\r\nSubject: Read me privately\r\n\r\nRead me.\r\n",b.email,mask.email,b.email);
    assert!(mx.send_mail(&b.email,&[&mask.email],&raw).await.starts_with("250"));
    let inbox=env.app.store.mailbox_by_role(a.id,"inbox").await.unwrap().unwrap();let msg=env.app.store.messages_in(inbox.id).await.unwrap()[0].id;
    let api=Api::logged_in(&env,&a.email).await;
    let response=api.post("/jmap/api",json!({"using":[],"methodCalls":[["MDN/send",{"accountId":format!("a{}",a.id),"send":{"receipt":{"forEmailId":format!("m{msg}"),"disposition":{"actionMode":"manual-action","sendingMode":"mdn-sent-manually","type":"displayed"}}}},"receipt"]]})).await;
    assert_eq!(response.body["methodResponses"][0][1]["sent"]["receipt"]["finalRecipient"],format!("rfc822; {}",mask.email),"{}",response.text);
    let received=env.inbox(&b).await.join("\n");
    assert!(received.contains(&format!("Return-Path: <{}>",mask.email)));
    assert!(received.contains(&format!("Final-Recipient: rfc822; {}",mask.email)));
    assert!(!received.contains(&a.email));
}
