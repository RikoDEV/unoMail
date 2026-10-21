//! User-owned disposable addresses. All interfaces share these ownership, quota, expiry
//! and domain checks; route reservations are enforced atomically by database triggers.
use std::{collections::HashMap, sync::LazyLock};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use crate::{app::AppState, error::ApiError, util::{now, normalize_domain, random_token, Address}};

pub const CAPABILITY: &str = "urn:unomail:params:jmap:masked-email";
static CREATIONS: LazyLock<parking_lot::Mutex<HashMap<i64,(i64,u32)>>> = LazyLock::new(Default::default);

#[derive(Clone, Deserialize, Serialize)]
#[serde(default, deny_unknown_fields)]
pub struct Config { pub enabled: bool, pub default_limit: i64, pub disabled_domains: Vec<String> }
impl Default for Config { fn default() -> Self { Self { enabled:true, default_limit:100, disabled_domains:vec![] } } }
pub async fn config(app: &AppState) -> Result<Config,ApiError> {
    let raw = crate::db::get_setting(&app.db,"masked_email.config").await?;
    raw.map(|s| serde_json::from_str(&s)).transpose().map(|c| c.unwrap_or_default()).map_err(|e| ApiError::Internal(e.into()))
}
#[derive(Default, Deserialize, Serialize)]
#[serde(default, deny_unknown_fields)]
pub struct Policy { pub max_masks: Option<i64>, pub extra_domains: Vec<String> }
pub async fn policy(app: &AppState, account: i64) -> Result<Policy,ApiError> {
    let row: Option<(Option<i64>,String)> = sqlx::query_as("SELECT max_masks,extra_domains FROM masked_account_policy WHERE account_id=?").bind(account).fetch_optional(&app.db).await?;
    Ok(row.map(|(max_masks,domains)| Policy {max_masks,extra_domains:serde_json::from_str(&domains).unwrap_or_default()}).unwrap_or_default())
}
#[derive(Clone, Serialize, sqlx::FromRow)]
pub struct Mask {
    pub id:i64, pub account_id:i64, pub domain_id:i64, pub email:String, pub description:String,
    pub for_domain:String, pub integration_url:String, pub enabled:bool, pub created_at:i64,
    pub expires_at:Option<i64>, pub created_by:String, pub updated_at:i64,
}
impl Mask {
    pub fn view(&self) -> Value {
        let mut v = serde_json::to_value(self).unwrap();
        v["status"] = json!(if self.expires_at.is_some_and(|t|t<=now()) {"expired"} else if self.enabled {"active"} else {"disabled"});
        v
    }
}
pub async fn list(app:&AppState,account:i64) -> Result<Vec<Mask>,ApiError> {
    Ok(sqlx::query_as("SELECT * FROM masked_addresses WHERE account_id=? ORDER BY id DESC").bind(account).fetch_all(&app.db).await?)
}
pub async fn get(app:&AppState,account:i64,id:i64) -> Result<Mask,ApiError> {
    sqlx::query_as("SELECT * FROM masked_addresses WHERE id=? AND account_id=?").bind(id).bind(account).fetch_optional(&app.db).await?.ok_or(ApiError::NotFound)
}
pub async fn domains(app:&AppState,account:i64) -> Result<Vec<String>,ApiError> {
    let primary: String = sqlx::query_scalar("SELECT d.name FROM accounts a JOIN domains d ON d.id=a.domain_id WHERE a.id=?").bind(account).fetch_optional(&app.db).await?.ok_or(ApiError::NotFound)?;
    let mut permitted = policy(app,account).await?.extra_domains;
    permitted.push(primary);
    let config = config(app).await?;
    let hosted: Vec<String> = sqlx::query_scalar("SELECT name FROM domains WHERE enabled=1 ORDER BY name").fetch_all(&app.db).await?;
    Ok(hosted.into_iter().filter(|d| permitted.contains(d) && !config.disabled_domains.contains(d)).collect())
}
pub async fn info(app:&AppState,account:i64) -> Result<Value,ApiError> {
    let cfg=config(app).await?;
    let limit=policy(app,account).await?.max_masks.unwrap_or(cfg.default_limit);
    let used:i64=sqlx::query_scalar("SELECT COUNT(*) FROM masked_addresses WHERE account_id=?").bind(account).fetch_one(&app.db).await?;
    Ok(json!({"limit":limit,"used":used,"domains":domains(app,account).await?,"creation_enabled":cfg.enabled && limit>0}))
}
#[derive(Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct Create { pub description:String, pub for_domain:String, pub integration_url:String, pub prefix:String, pub domain:Option<String>, pub expires_at:Option<i64>, pub enabled:bool }
impl Default for Create{fn default()->Self{Self{description:String::new(),for_domain:String::new(),integration_url:String::new(),prefix:String::new(),domain:None,expires_at:None,enabled:true}}}
#[derive(Default, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct Update { pub description:Option<String>,pub for_domain:Option<String>,pub integration_url:Option<String>,pub enabled:Option<bool> }

fn clean(s:&str,max:usize) -> Result<String,ApiError> {
    if s.chars().count()>max || s.chars().any(char::is_control) {return Err(ApiError::bad("invalid or overlong mask metadata"));} Ok(s.trim().into())
}
fn website(s:&str) -> Result<String,ApiError> {
    if s.trim().is_empty() {return Ok(String::new());}
    let input=if s.contains("://") {s.trim().to_owned()} else {format!("https://{}",s.trim())};
    let url=reqwest::Url::parse(&input).map_err(|_|ApiError::bad("invalid website domain"))?;
    if !matches!(url.scheme(),"https"|"http") || !url.username().is_empty() || url.password().is_some() {return Err(ApiError::bad("invalid website domain"));}
    url.host_str().and_then(normalize_domain).ok_or_else(||ApiError::bad("invalid website domain"))
}
fn link(s:&str) -> Result<String,ApiError> {
    if s.is_empty() {return Ok(String::new());}
    crate::summary_cards::extract::safe_url(s).filter(|u|u.starts_with("https://")).ok_or_else(||ApiError::bad("integration URL must be HTTPS without credentials"))
}
fn admit(account:i64) -> Result<(),ApiError> {
    let mut entries=CREATIONS.lock(); let t=now();
    entries.retain(|_,(start,_)| t-*start<3600);
    let e=entries.entry(account).or_insert((t,0));
    if e.1>=30 {return Err(ApiError::RateLimited);} e.1+=1; Ok(())
}
pub async fn create(app:&AppState,account:i64,input:Create,by:&str) -> Result<Mask,ApiError> {
    let cfg=config(app).await?;
    if !cfg.enabled {return Err(ApiError::bad("creation of masked addresses is disabled"));}
    if input.prefix.len()>37 || !input.prefix.bytes().all(|b|b.is_ascii_lowercase()||b.is_ascii_digit()||b==b'_') {return Err(ApiError::bad("prefix must be at most 37 lowercase letters, digits or underscores"));}
    if input.expires_at.is_some_and(|t|t<=now() || t>253402300799) {return Err(ApiError::bad("expiration must be a future UTC date"));}
    let description=clean(&input.description,200)?; let for_domain=website(&input.for_domain)?; let url=link(&input.integration_url)?;
    let allowed=domains(app,account).await?;
    let domain=match input.domain {Some(d)=>normalize_domain(&d).ok_or_else(||ApiError::bad("invalid mask domain"))?,None=>allowed.first().cloned().ok_or_else(||ApiError::bad("no domains are available for masks"))?};
    if !allowed.contains(&domain) {return Err(ApiError::bad("mask domain is not allowed for this account"));}
    admit(account)?;
    // Acquire the SQLite write lock before reading quota; concurrent requests cannot exceed it.
    let mut tx=app.db.begin().await?;
    sqlx::query("INSERT INTO masked_account_policy(account_id) VALUES(?) ON CONFLICT(account_id) DO UPDATE SET account_id=excluded.account_id").bind(account).execute(&mut *tx).await?;
    // Recheck mutable administrator policy under the same write lock as allocation.
    let raw:Option<String>=sqlx::query_scalar("SELECT value FROM settings WHERE key='masked_email.config'").fetch_optional(&mut *tx).await?;
    let cfg:Config=raw.map(|s|serde_json::from_str(&s)).transpose().map_err(anyhow::Error::from)?.unwrap_or_default();
    if !cfg.enabled || cfg.disabled_domains.contains(&domain){return Err(ApiError::bad("creation of masked addresses in this domain is disabled"));}
    let limit:Option<i64>=sqlx::query_scalar("SELECT max_masks FROM masked_account_policy WHERE account_id=?").bind(account).fetch_one(&mut *tx).await?;
    let count:i64=sqlx::query_scalar("SELECT COUNT(*) FROM masked_addresses WHERE account_id=?").bind(account).fetch_one(&mut *tx).await?;
    if count>=limit.unwrap_or(cfg.default_limit) {return Err(ApiError::Conflict("masked address quota reached".into()));}
    let domain_id:i64=sqlx::query_scalar("SELECT d.id FROM domains d JOIN accounts a ON a.id=? WHERE d.name=? AND d.enabled=1 AND (d.id=a.domain_id OR d.name IN (SELECT value FROM json_each((SELECT extra_domains FROM masked_account_policy WHERE account_id=a.id))))").bind(account).bind(&domain).fetch_optional(&mut *tx).await?.ok_or_else(||ApiError::bad("mask domain is not allowed for this account"))?;
    let mut email=String::new();
    for _ in 0..5 {
        // 128 random bits encoded as 26 lowercase base32 characters.
        let bytes=crate::util::random_bytes::<16>();
        let token:String=(0..26).map(|group|{let mut v=0;for bit in 0..5{let n=group*5+bit;v=(v<<1)|if n<128{(bytes[n/8]>>(7-n%8))&1}else{0};}b"abcdefghijklmnopqrstuvwxyz234567"[v as usize] as char}).collect();
        email=format!("{}{}{}@{domain}",input.prefix,if input.prefix.is_empty(){""}else{"_"},token);
        if email.split('@').next().unwrap().len()>64 {return Err(ApiError::bad("prefix is too long"));}
        let exists:bool=sqlx::query_scalar("SELECT EXISTS(SELECT 1 FROM address_reservations WHERE email=?)").bind(&email).fetch_one(&mut *tx).await?;
        if !exists {break;} email.clear();
    }
    if email.is_empty() {return Err(ApiError::Conflict("could not allocate a masked address".into()));}
    let id=sqlx::query("INSERT INTO masked_addresses(account_id,domain_id,email,description,for_domain,integration_url,enabled,created_at,expires_at,created_by,updated_at) VALUES(?,?,?,?,?,?,?,?,?,?,?)")
        .bind(account).bind(domain_id).bind(email).bind(description).bind(for_domain).bind(url).bind(input.enabled).bind(now()).bind(input.expires_at).bind(clean(by,100)?).bind(now()).execute(&mut *tx).await?.last_insert_rowid();
    record(&mut tx,account,id,"created").await?;
    tx.commit().await?;
    get(app,account,id).await
}
async fn record(tx:&mut sqlx::Transaction<'_,sqlx::Sqlite>,account:i64,id:i64,change:&str)->Result<(),sqlx::Error>{
    sqlx::query("INSERT INTO masked_changes(account_id,kind,item_id,change) VALUES(?,'masked',?,?)").bind(account).bind(id).bind(change).execute(&mut **tx).await?; Ok(())
}
pub async fn update(app:&AppState,account:i64,id:i64,input:Update)->Result<Mask,ApiError>{
    let current=get(app,account,id).await?;
    if input.enabled==Some(true) && current.expires_at.is_some_and(|t|t<=now()) {return Err(ApiError::bad("an expired mask cannot be re-enabled"));}
    let description=input.description.map(|s|clean(&s,200)).transpose()?;
    let for_domain=input.for_domain.map(|s|website(&s)).transpose()?;
    let url=input.integration_url.map(|s|link(&s)).transpose()?;
    let mut tx=app.db.begin().await?;
    sqlx::query("UPDATE masked_addresses SET description=COALESCE(?,description),for_domain=COALESCE(?,for_domain),integration_url=COALESCE(?,integration_url),enabled=COALESCE(?,enabled),updated_at=? WHERE id=? AND account_id=?")
        .bind(description).bind(for_domain).bind(url).bind(input.enabled).bind(now()).bind(id).bind(account).execute(&mut *tx).await?;
    record(&mut tx,account,id,"updated").await?; tx.commit().await?; get(app,account,id).await
}
pub async fn destroy(app:&AppState,account:i64,id:i64)->Result<(),ApiError>{
    let mut tx=app.db.begin().await?;
    let deleted=sqlx::query("DELETE FROM masked_addresses WHERE id=? AND account_id=?").bind(id).bind(account).execute(&mut *tx).await?.rows_affected();
    if deleted==0 {return Err(ApiError::NotFound);}
    record(&mut tx,account,id,"destroyed").await?; tx.commit().await?; Ok(())
}

/// None: not a mask; Some(None): reserved but inactive/deleted; Some(owner): live mask.
/// Plus tags resolve to the same mask and inherit its denial, never to catch-all.
pub async fn resolve(app:&crate::app::App,address:&Address)->sqlx::Result<Option<Option<i64>>>{
    let email=address.without_tag().to_string();
    let reserved:bool=sqlx::query_scalar("SELECT EXISTS(SELECT 1 FROM address_reservations WHERE email=? AND kind='masked')").bind(&email).fetch_one(&app.db).await?;
    if !reserved {return Ok(None);}
    let owner=sqlx::query_scalar("SELECT m.account_id FROM masked_addresses m JOIN accounts a ON a.id=m.account_id JOIN domains d ON d.id=m.domain_id WHERE m.email=? AND m.enabled=1 AND (m.expires_at IS NULL OR m.expires_at>?) AND a.enabled=1 AND d.enabled=1")
        .bind(email).bind(now()).fetch_optional(&app.db).await?;
    Ok(Some(owner))
}
pub async fn owned(app:&crate::app::App,account:i64,address:&Address)->sqlx::Result<Option<bool>> {
    // Sending from tagged variants is not permitted: a mask's exact address is its identity.
    Ok(resolve(app,address).await?.map(|owner|owner==Some(account) && address.local==address.without_tag().local))
}
pub async fn delivery_addresses(app:&crate::app::App,account:i64,message:i64)->sqlx::Result<Vec<String>>{
    sqlx::query_scalar("SELECT x.email FROM message_mask_delivery x JOIN messages m ON m.id=x.message_id WHERE m.id=? AND m.account_id=? ORDER BY x.email").bind(message).bind(account).fetch_all(&app.db).await
}

pub async fn token_create(app:&AppState,account:i64,name:&str,expires:i64)->Result<Value,ApiError>{
    let name=clean(name,100)?;
    if name.is_empty() || expires<=now() || expires>now()+366*86400 {return Err(ApiError::bad("provide a name and an expiration within one year"));}
    let mut tx=app.db.begin().await?;
    sqlx::query("INSERT INTO masked_account_policy(account_id) VALUES(?) ON CONFLICT(account_id) DO UPDATE SET account_id=excluded.account_id").bind(account).execute(&mut *tx).await?;
    let count:i64=sqlx::query_scalar("SELECT COUNT(*) FROM masked_integration_tokens WHERE account_id=? AND expires_at>?").bind(account).bind(now()).fetch_one(&mut *tx).await?;
    if count>=10 {return Err(ApiError::bad("at most ten active mask integration tokens"));}
    let token=format!("um_mask_{}",random_token());
    let id=sqlx::query("INSERT INTO masked_integration_tokens(account_id,token_hash,name,created_at,expires_at) VALUES(?,?,?,?,?)")
        .bind(account).bind(crate::util::sha256_hex(token.as_bytes())).bind(&name).bind(now()).bind(expires).execute(&mut *tx).await?.last_insert_rowid();
    tx.commit().await?; Ok(json!({"id":id,"name":name,"token":token,"expires_at":expires}))
}

pub async fn expire(app:&AppState)->Result<(),ApiError>{
    let mut tx=app.db.begin().await?;
    let rows:Vec<(i64,i64)>=sqlx::query_as("UPDATE masked_addresses SET enabled=0,updated_at=? WHERE enabled=1 AND expires_at<=? RETURNING id,account_id").bind(now()).bind(now()).fetch_all(&mut *tx).await?;
    for (id,account) in rows{record(&mut tx,account,id,"updated").await?;}
    tx.commit().await?;Ok(())
}
pub async fn run(app:AppState){
    loop{
        let _=expire(&app).await;
        tokio::time::sleep(std::time::Duration::from_secs(30)).await;
    }
}
