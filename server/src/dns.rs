//! Thin, typed wrappers around the DNS resolver.

use std::net::IpAddr;

use mail_auth::{IpLookupStrategy, MX, MessageAuthenticator, RecordSet, common::cache::NoCache};

#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum DnsError {
    #[error("no such record")]
    NotFound,
    #[error("lookup failed: {0}")]
    Temporary(String),
}

fn map_err(err: mail_auth::Error) -> DnsError {
    match err {
        mail_auth::Error::Dns(mail_auth::DnsError::RecordNotFound(_)) => DnsError::NotFound,
        other => DnsError::Temporary(other.to_string()),
    }
}

/// MX hosts ordered by preference. An empty list means the domain publishes no MX records.
pub async fn mx(resolver: &MessageAuthenticator, domain: &str) -> Result<Vec<(u16, String)>, DnsError> {
    Ok(mail_exchangers(resolver, domain).await?.unwrap_or_default())
}

/// [`mx`], telling also whether the domain exists at all: `None` when it does not (NXDOMAIN).
/// Hosts of equal preference come in random order, so that senders spread over them
/// (RFC 5321 5.1).
pub async fn mail_exchangers(resolver: &MessageAuthenticator, domain: &str) -> Result<Option<Vec<(u16, String)>>, DnsError> {
    let records = match resolver.mx_lookup(domain, None::<&NoCache<Box<str>, RecordSet<MX>>>).await {
        Ok(records) => records,
        Err(mail_auth::Error::Dns(mail_auth::DnsError::RecordNotFound(code))) if u16::from(code) == NXDOMAIN => return Ok(None),
        Err(err) => {
            return match map_err(err) {
                DnsError::NotFound => Ok(Some(Vec::new())),
                other => Err(other),
            };
        }
    };
    let mut hosts = Vec::new();
    for record in records.rrset.iter() {
        for exchange in record.exchanges.iter() {
            hosts.push((record.preference, exchange.trim_end_matches('.').to_ascii_lowercase()));
        }
    }
    rand::seq::SliceRandom::shuffle(hosts.as_mut_slice(), &mut rand::thread_rng());
    hosts.sort_by_key(|(preference, _)| *preference);
    Ok(Some(hosts))
}

/// The DNS response code for a name that does not exist.
const NXDOMAIN: u16 = 3;

pub async fn ips(resolver: &MessageAuthenticator, host: &str) -> Result<Vec<IpAddr>, DnsError> {
    resolver
        .ip_lookup(
            host,
            IpLookupStrategy::Ipv4thenIpv6,
            8,
            None::<&NoCache<Box<str>, RecordSet<std::net::Ipv4Addr>>>,
            None::<&NoCache<Box<str>, RecordSet<std::net::Ipv6Addr>>>,
        )
        .await
        .map_err(map_err)
}

pub async fn ptr(resolver: &MessageAuthenticator, ip: IpAddr) -> Result<Vec<String>, DnsError> {
    let records = resolver.ptr_lookup(ip, None::<&NoCache<IpAddr, RecordSet<Box<str>>>>).await.map_err(map_err)?;
    Ok(records.rrset.iter().map(|name| name.trim_end_matches('.').to_ascii_lowercase()).collect())
}

/// All TXT strings published at `name`, each record's character-strings concatenated.
/// TLSA records as `usage selector matching hex`, as they are usually written.
pub async fn tlsa(resolver: &MessageAuthenticator, name: &str) -> Result<Vec<String>, DnsError> {
    let _ = resolver;
    let system = hickory_resolver::TokioResolver::builder_tokio().map_err(|e| DnsError::Temporary(e.to_string()))?.build().map_err(|e| DnsError::Temporary(e.to_string()))?;
    match system.lookup(format!("{}.", name.trim_end_matches('.')), hickory_resolver::proto::rr::RecordType::TLSA).await {
        Ok(lookup) => Ok(lookup
            .answers()
            .iter()
            .filter_map(|record| match &record.data {
                hickory_resolver::proto::rr::RData::TLSA(tlsa) => Some(format!("{} {} {} {}", u8::from(tlsa.cert_usage), u8::from(tlsa.selector), u8::from(tlsa.matching), tlsa.cert_data.iter().map(|b| format!("{b:02x}")).collect::<String>())),
                _ => None,
            })
            .collect()),
        Err(err) if err.to_string().to_ascii_lowercase().contains("no record") => Ok(Vec::new()),
        Err(err) => Err(DnsError::Temporary(err.to_string())),
    }
}

pub async fn txt(resolver: &MessageAuthenticator, name: &str) -> Result<Vec<String>, DnsError> {
    let lookup = resolver
        .resolver()
        .txt_lookup(format!("{}.", name.trim_end_matches('.')))
        .await
        .map_err(|e| if e.is_no_records_found() { DnsError::NotFound } else { DnsError::Temporary(e.to_string()) })?;
    Ok(lookup
        .answers()
        .iter()
        .filter_map(|record| match &record.data {
            hickory_resolver::proto::rr::RData::TXT(txt) => Some(
                txt.txt_data.iter().map(|part| String::from_utf8_lossy(part).into_owned()).collect::<Vec<_>>().concat(),
            ),
            _ => None,
        })
        .collect())
}
