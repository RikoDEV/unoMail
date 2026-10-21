use axum::{Json, extract::{Path,State}, http::HeaderMap};
use serde::Deserialize;
use serde_json::{Value,json};
use super::{Session,JsonResult};
use crate::{app::AppState,error::ApiError,masked_email::{self as masks,Create,Update,Policy,Config},util::{now,sha256_hex}};

async fn owner(state:&AppState,session:&Session,account:i64)->Result<(),ApiError>{
    if account==session.account.id {return Ok(());}
    super::accounts::load_managed(state,session,account).await?; Ok(())
}
pub async fn own_list(State(s):State<AppState>,u:Session)->JsonResult<Value>{list_for(&s,u.account.id).await}
pub async fn own_domains(State(s):State<AppState>,u:Session)->JsonResult<Vec<String>>{Ok(Json(masks::domains(&s,u.account.id).await?))}
async fn list_for(s:&AppState,account:i64)->JsonResult<Value>{
    let mut info=masks::info(s,account).await?;
    info["items"]=json!(masks::list(s,account).await?.iter().map(|m|m.view()).collect::<Vec<_>>()); Ok(Json(info))
}
pub async fn own_create(State(s):State<AppState>,u:Session,Json(input):Json<Create>)->JsonResult<Value>{
    let m=masks::create(&s,u.account.id,input,"Webmail").await?;
    u.audit(&s,"mask.created",&m.email,"").await; Ok(Json(m.view()))
}
pub async fn own_update(State(s):State<AppState>,u:Session,Path(id):Path<i64>,Json(input):Json<Update>)->JsonResult<Value>{
    let m=masks::update(&s,u.account.id,id,input).await?;u.audit(&s,"mask.updated",&m.email,"").await;Ok(Json(m.view()))
}
pub async fn own_delete(State(s):State<AppState>,u:Session,Path(id):Path<i64>)->JsonResult<Value>{
    let m=masks::get(&s,u.account.id,id).await?;masks::destroy(&s,u.account.id,id).await?;u.audit(&s,"mask.deleted",&m.email,"").await;Ok(Json(json!({"ok":true})))
}
pub async fn admin_list(State(s):State<AppState>,u:Session,Path(account):Path<i64>)->JsonResult<Value>{owner(&s,&u,account).await?;list_for(&s,account).await}
pub async fn admin_create(State(s):State<AppState>,u:Session,Path(account):Path<i64>,Json(input):Json<Create>)->JsonResult<Value>{
    u.require_admin()?;owner(&s,&u,account).await?;let m=masks::create(&s,account,input,"Administrator").await?;u.audit(&s,"mask.created",&m.email,"").await;Ok(Json(m.view()))
}
pub async fn admin_update(State(s):State<AppState>,u:Session,Path((account,id)):Path<(i64,i64)>,Json(input):Json<Update>)->JsonResult<Value>{
    u.require_admin()?;owner(&s,&u,account).await?;let m=masks::update(&s,account,id,input).await?;u.audit(&s,"mask.updated",&m.email,"").await;Ok(Json(m.view()))
}
pub async fn admin_delete(State(s):State<AppState>,u:Session,Path((account,id)):Path<(i64,i64)>)->JsonResult<Value>{
    u.require_admin()?;owner(&s,&u,account).await?;let m=masks::get(&s,account,id).await?;masks::destroy(&s,account,id).await?;u.audit(&s,"mask.deleted",&m.email,"").await;Ok(Json(json!({"ok":true})))
}
pub async fn policy_get(State(s):State<AppState>,u:Session,Path(account):Path<i64>)->JsonResult<Policy>{u.require_admin()?;owner(&s,&u,account).await?;Ok(Json(masks::policy(&s,account).await?))}
pub async fn policy_put(State(s):State<AppState>,u:Session,Path(account):Path<i64>,Json(mut p):Json<Policy>)->JsonResult<Policy>{
    u.require_admin()?;owner(&s,&u,account).await?;
    if p.max_masks.is_some_and(|n|!(0..=10000).contains(&n))||p.extra_domains.len()>50{return Err(ApiError::bad("invalid masked address quota or domain list"));}
    for d in &mut p.extra_domains{
        *d=crate::util::normalize_domain(d).ok_or_else(||ApiError::bad("invalid additional mask domain"))?;
        let id:Option<i64>=sqlx::query_scalar("SELECT id FROM domains WHERE name=?").bind(&*d).fetch_optional(&s.db).await?;
        u.require_domain(&s.db,id.ok_or(ApiError::NotFound)?).await?;
    }
    sqlx::query("INSERT INTO masked_account_policy(account_id,max_masks,extra_domains) VALUES(?,?,?) ON CONFLICT(account_id) DO UPDATE SET max_masks=excluded.max_masks,extra_domains=excluded.extra_domains")
        .bind(account).bind(p.max_masks).bind(serde_json::to_string(&p.extra_domains).unwrap()).execute(&s.db).await?;
    u.audit(&s,"mask.policy",&account.to_string(),"").await;Ok(Json(p))
}
pub async fn config_get(State(s):State<AppState>,u:Session)->JsonResult<Config>{u.require_super()?;Ok(Json(masks::config(&s).await?))}
pub async fn config_put(State(s):State<AppState>,u:Session,Json(mut c):Json<Config>)->JsonResult<Config>{
    u.require_super()?;
    if !(0..=10000).contains(&c.default_limit)||c.disabled_domains.len()>1000{return Err(ApiError::bad("invalid default mask quota or domain policy"));}
    for d in &mut c.disabled_domains{*d=crate::util::normalize_domain(d).ok_or_else(||ApiError::bad("invalid domain"))?;}
    crate::db::set_setting(&s.db,"masked_email.config",&serde_json::to_string(&c).unwrap()).await?;u.audit(&s,"mask.configured","server","").await;Ok(Json(c))
}
pub async fn tokens(State(s):State<AppState>,u:Session)->JsonResult<Value>{
    let rows:Vec<(i64,String,i64,i64)>=sqlx::query_as("SELECT id,name,created_at,expires_at FROM masked_integration_tokens WHERE account_id=? ORDER BY id DESC").bind(u.account.id).fetch_all(&s.db).await?;
    Ok(Json(json!(rows.into_iter().map(|(id,name,created,expires)|json!({"id":id,"name":name,"created_at":created,"expires_at":expires})).collect::<Vec<_>>())))
}
#[derive(Deserialize)]pub struct TokenInput{ name:String,expires_at:i64 }
pub async fn token_create(State(s):State<AppState>,u:Session,Json(i):Json<TokenInput>)->JsonResult<Value>{
    let value=masks::token_create(&s,u.account.id,&i.name,i.expires_at).await?;u.audit(&s,"mask.token_created",&value["id"].to_string(),"").await;Ok(Json(value))
}
pub async fn token_delete(State(s):State<AppState>,u:Session,Path(id):Path<i64>)->JsonResult<Value>{
    let n=sqlx::query("DELETE FROM masked_integration_tokens WHERE id=? AND account_id=?").bind(id).bind(u.account.id).execute(&s.db).await?.rows_affected();
    if n==0{return Err(ApiError::NotFound);}u.audit(&s,"mask.token_revoked",&id.to_string(),"").await;Ok(Json(json!({"ok":true})))
}
async fn integration(s:&AppState,headers:&HeaderMap)->Result<(crate::auth::Account,String),ApiError>{
    let token=headers.get("authorization").and_then(|v|v.to_str().ok()).and_then(|s|s.strip_prefix("Bearer ")).filter(|s|s.starts_with("um_mask_")&&s.len()<200).ok_or(ApiError::Unauthorized)?;
    let row:Option<(i64,i64,String)>=sqlx::query_as("SELECT id,account_id,name FROM masked_integration_tokens WHERE token_hash=? AND expires_at>?").bind(sha256_hex(token.as_bytes())).bind(now()).fetch_optional(&s.db).await?;
    let (id,account,name)=row.ok_or(ApiError::Unauthorized)?;
    let account=crate::auth::Account::by_id(&s.db,account).await?.filter(|a|a.enabled).ok_or(ApiError::Unauthorized)?;
    let domain:bool=sqlx::query_scalar("SELECT enabled FROM domains WHERE id=?").bind(account.domain_id).fetch_one(&s.db).await?;
    if !domain{return Err(ApiError::Unauthorized);}Ok((account,format!("masked-token:{id}:{name}")))
}
pub async fn integration_session(State(s):State<AppState>,headers:HeaderMap)->JsonResult<Value>{
    let (account,_)=integration(&s,&headers).await?;
    let state:i64=sqlx::query_scalar("SELECT COALESCE(MAX(id),0) FROM masked_changes WHERE account_id=?").bind(account.id).fetch_one(&s.db).await?;
    Ok(Json(json!({"capabilities":{"urn:ietf:params:jmap:core":{"maxSizeRequest":1048576,"maxConcurrentRequests":4,"maxCallsInRequest":32,"maxObjectsInGet":500,"maxObjectsInSet":500},masks::CAPABILITY:{}},"accounts":{format!("a{}",account.id):{"name":"Masked addresses","isPersonal":true,"isReadOnly":false,"accountCapabilities":{masks::CAPABILITY:{}}}},"primaryAccounts":{masks::CAPABILITY:format!("a{}",account.id)},"username":format!("masked:a{}",account.id),"state":state.to_string(),"apiUrl":"/api/masked-email/jmap"})))
}
pub async fn integration_jmap(State(s):State<AppState>,headers:HeaderMap,Json(request):Json<Value>)->JsonResult<Value>{
    let (account,origin)=integration(&s,&headers).await?;
    let result=crate::jmap::process(&s,&account,"0.0.0.0".parse().unwrap(),origin,&request).await.map_err(|(_,m)|ApiError::bad(m))?;
    Ok(Json(result))
}
