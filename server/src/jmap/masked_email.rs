use serde_json::{Map,Value,json};
use super::{Context,MethodResult,MethodError,objects,parse_id,account_id,set_error};
use crate::masked_email::{self as masks,Mask,Create,Update};
use time::{OffsetDateTime,format_description::well_known::Rfc3339};
fn timestamp(t:i64)->Value{OffsetDateTime::from_unix_timestamp(t).ok().and_then(|t|t.format(&Rfc3339).ok()).map_or(Value::Null,Value::String)}
fn view(m:&Mask)->Value{json!({"id":format!("x{}",m.id),"accountId":format!("a{}",m.account_id),"email":m.email,"enabled":m.enabled,"description":m.description,"forDomain":m.for_domain,"url":m.integration_url,"createdBy":m.created_by,"createdAt":timestamp(m.created_at),"expiresAt":m.expires_at.map(timestamp),"status":m.view()["status"]})}
fn err(e:crate::error::ApiError)->Value{
    use crate::error::ApiError;
    match e{ApiError::NotFound=>set_error("notFound","unknown mask"),ApiError::Conflict(s)=>set_error("overQuota",s),ApiError::RateLimited=>set_error("rateLimit","too many mask creations"),ApiError::BadRequest(s)=>set_error("invalidProperties",s),_=>set_error("serverFail","mask operation failed")}
}
pub async fn get(ctx:&Context<'_>,args:&Map<String,Value>)->MethodResult{
    let ids=objects::requested_ids(args)?;let all=masks::list(ctx.app,ctx.account.id).await.map_err(MethodError::server)?;
    if ids.is_none() && all.len()>super::MAX_OBJECTS{return Err(MethodError("requestTooLarge","use query pagination and request explicit ids".into()));}
    let mut list=Vec::new();let mut missing=Vec::new();
    if let Some(ids)=ids{for id in ids{let resolved=ctx.resolve_id(&id);if let Some(m)=all.iter().find(|m|Some(m.id)==parse_id(&resolved,'x')){list.push(objects::select(view(m),args));}else{missing.push(id);}}}
    else{list=all.iter().take(super::MAX_OBJECTS).map(|m|objects::select(view(m),args)).collect();}
    Ok(json!({"accountId":account_id(ctx.account),"state":objects::state(ctx,"masked").await?,"list":list,"notFound":missing}))
}
pub async fn query(ctx:&Context<'_>,args:&Map<String,Value>)->MethodResult{
    if args.get("filter").is_some_and(|f|!f.is_null() && f.as_object().is_none_or(|o|!o.is_empty())){return Err(MethodError("unsupportedFilter","use accountId to scope masked addresses".into()));}
    if args.contains_key("sort"){return Err(MethodError("unsupportedSort","masks are sorted by creation time descending".into()));}
    let all=masks::list(ctx.app,ctx.account.id).await.map_err(MethodError::server)?;
    let position=args.get("position").and_then(Value::as_u64).unwrap_or(0) as usize;
    let limit=args.get("limit").and_then(Value::as_u64).unwrap_or(50).min(super::MAX_OBJECTS as u64) as usize;
    Ok(json!({"accountId":account_id(ctx.account),"queryState":objects::state(ctx,"masked").await?,"canCalculateChanges":false,"position":position,"total":all.len(),"ids":all.iter().skip(position).take(limit).map(|m|format!("x{}",m.id)).collect::<Vec<_>>()}))
}
pub async fn set(ctx:&mut Context<'_>,args:&Map<String,Value>)->MethodResult{
    objects::check_size(args)?;let old=objects::state(ctx,"masked").await?;objects::check_state(args,&old)?;
    let mut result=objects::SetResult::default();
    for (creation,spec) in args.get("create").and_then(Value::as_object).into_iter().flatten(){
        let parsed=(||->Result<Create,Value>{
            let o=spec.as_object().ok_or_else(||set_error("invalidProperties","mask must be an object"))?;
            if o.keys().any(|k|!matches!(k.as_str(),"description"|"forDomain"|"url"|"emailPrefix"|"emailDomain"|"expiresAt"|"enabled")){return Err(set_error("invalidProperties","unknown or read-only mask property"));}
            let text=|k:&str|->Result<String,Value>{match o.get(k){None|Some(Value::Null)=>Ok(String::new()),Some(Value::String(s))=>Ok(s.clone()),_=>Err(set_error("invalidProperties",format!("{k} must be text")))}};
            let enabled=match o.get("enabled"){None=>true,Some(Value::Bool(b))=>*b,_=>return Err(set_error("invalidProperties","enabled must be boolean"))};
            let expires_at=match o.get("expiresAt"){None|Some(Value::Null)=>None,Some(Value::String(s))=>Some(OffsetDateTime::parse(s,&Rfc3339).map_err(|_|set_error("invalidProperties","invalid expiresAt"))?.unix_timestamp()),_=>return Err(set_error("invalidProperties","invalid expiresAt"))};
            let domain=text("emailDomain")?;
            Ok(Create{description:text("description")?,for_domain:text("forDomain")?,integration_url:text("url")?,prefix:text("emailPrefix")?,domain:(!domain.is_empty()).then_some(domain),expires_at,enabled})
        })();
        let by=ctx.origin.strip_prefix("masked-token:").and_then(|s|s.split_once(':').map(|(_,name)|name)).unwrap_or("JMAP client");
        match parsed{Ok(input)=>match masks::create(ctx.app,ctx.account.id,input,by).await{Ok(m)=>{let value=view(&m);ctx.created.insert(creation.clone(),format!("x{}",m.id));result.created.insert(creation.clone(),value);},Err(e)=>{result.not_created.insert(creation.clone(),err(e));}},Err(e)=>{result.not_created.insert(creation.clone(),e);}}
    }
    for (id,spec) in args.get("update").and_then(Value::as_object).into_iter().flatten(){
        let mapped=spec.as_object().filter(|o|o.get("enabled").is_none_or(Value::is_boolean)).map(|o|o.iter().map(|(k,v)|(match k.as_str(){"forDomain"=>"for_domain","url"=>"integration_url",other=>other}.to_owned(),if v.is_null() && matches!(k.as_str(),"description"|"forDomain"|"url"){json!("")}else{v.clone()})).collect::<Map<_,_>>());
        let input=mapped.and_then(|o|serde_json::from_value::<Update>(Value::Object(o)).ok());
        let resolved=ctx.resolve_id(id);
        let value=match (parse_id(&resolved,'x'),input){(Some(n),Some(input))=>match masks::update(ctx.app,ctx.account.id,n,input).await{Ok(_)=>{result.updated.insert(id.clone(),Value::Null);continue;},Err(e)=>err(e)},_=>set_error("invalidProperties","invalid id or read-only mask properties")};
        result.not_updated.insert(id.clone(),value);
    }
    for id in args.get("destroy").and_then(Value::as_array).into_iter().flatten().filter_map(Value::as_str){
        let resolved=ctx.resolve_id(id);
        match parse_id(&resolved,'x'){Some(n)=>match masks::destroy(ctx.app,ctx.account.id,n).await{Ok(())=>result.destroyed.push(id.into()),Err(e)=>{result.not_destroyed.insert(id.into(),err(e));}},None=>{result.not_destroyed.insert(id.into(),set_error("notFound","unknown mask"));}}
    }
    let new=objects::state(ctx,"masked").await?;Ok(result.into_response(ctx,old,new))
}
