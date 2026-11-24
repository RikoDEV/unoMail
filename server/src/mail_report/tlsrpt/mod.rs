/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: Apache-2.0 OR MIT
 */

use mail_parser::DateTime;
use serde::{Deserialize, Deserializer, Serialize, Serializer};
use serde::de::{SeqAccess, Visitor};
use std::{fmt, marker::PhantomData, net::IpAddr};

pub mod generate;
pub mod parse;

/// Lists in a received report are read with a ceiling: a 10 MB JSON document can otherwise
/// hold hundreds of thousands of entries, and each one costs a database query to store.
const MAX_POLICIES: usize = 500;
const MAX_FAILURE_DETAILS: usize = 2_000;

fn read_bounded<'de, D, T>(deserializer: D, limit: usize) -> Result<Vec<T>, D::Error>
where
    D: Deserializer<'de>,
    T: Deserialize<'de>,
{
    struct Bounded<T> {
        limit: usize,
        marker: PhantomData<T>,
    }
    impl<'de, T: Deserialize<'de>> Visitor<'de> for Bounded<T> {
        type Value = Vec<T>;
        fn expecting(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
            write!(f, "a list of at most {} entries", self.limit)
        }
        fn visit_seq<A: SeqAccess<'de>>(self, mut seq: A) -> Result<Self::Value, A::Error> {
            let mut out = Vec::new();
            while let Some(item) = seq.next_element::<T>()? {
                if out.len() >= self.limit {
                    return Err(serde::de::Error::custom("the report has too many entries"));
                }
                out.push(item);
            }
            Ok(out)
        }
    }
    deserializer.deserialize_seq(Bounded { limit, marker: PhantomData })
}

fn bounded_policies<'de, D>(deserializer: D) -> Result<Vec<Policy>, D::Error>
where
    D: Deserializer<'de>,
{
    read_bounded(deserializer, MAX_POLICIES)
}

fn bounded_details<'de, D>(deserializer: D) -> Result<Vec<FailureDetails>, D::Error>
where
    D: Deserializer<'de>,
{
    read_bounded(deserializer, MAX_FAILURE_DETAILS)
}

#[cfg(test)]
mod tests {
    use super::{MAX_FAILURE_DETAILS, MAX_POLICIES, TlsReport};
    use serde_json::json;

    fn report(policies: usize, details: usize) -> Vec<u8> {
        let details = vec![json!({ "result-type": "other" }); details];
        let policy = json!({
            "policy": { "policy-type": "sts", "policy-string": [], "policy-domain": "example.org", "mx-host": [] },
            "summary": { "total-successful-session-count": 1, "total-failure-session-count": 0 },
            "failure-details": details,
        });
        serde_json::to_vec(&json!({
            "organization-name": "reporter",
            "date-range": { "start-datetime": "2026-01-01T00:00:00Z", "end-datetime": "2026-01-02T00:00:00Z" },
            "report-id": "r",
            "policies": vec![policy; policies],
        }))
        .unwrap()
    }

    #[test]
    fn a_report_larger_than_the_limits_is_refused_while_reading() {
        assert!(TlsReport::parse_json(&report(MAX_POLICIES, 0)).is_ok());
        assert!(TlsReport::parse_json(&report(MAX_POLICIES + 1, 0)).is_err());
        assert!(TlsReport::parse_json(&report(1, MAX_FAILURE_DETAILS + 1)).is_err());
    }
}

#[derive(Debug, PartialEq, Eq, Serialize, Deserialize, Clone)]
pub struct TlsReport {
    #[serde(rename = "organization-name")]
    #[serde(default)]
    pub organization_name: Option<String>,

    #[serde(rename = "date-range")]
    pub date_range: DateRange,

    #[serde(rename = "contact-info")]
    #[serde(default)]
    pub contact_info: Option<String>,

    #[serde(rename = "report-id")]
    #[serde(default)]
    pub report_id: String,

    #[serde(rename = "policies")]
    #[serde(default)]
    #[serde(deserialize_with = "bounded_policies")]
    pub policies: Vec<Policy>,
}

#[derive(Debug, PartialEq, Eq, Serialize, Deserialize, Clone)]
pub struct Policy {
    #[serde(rename = "policy")]
    pub policy: PolicyDetails,

    #[serde(rename = "summary")]
    pub summary: Summary,

    #[serde(rename = "failure-details")]
    #[serde(default)]
    #[serde(deserialize_with = "bounded_details")]
    pub failure_details: Vec<FailureDetails>,
}

#[derive(Debug, Default, PartialEq, Eq, Serialize, Deserialize, Clone)]
pub struct PolicyDetails {
    #[serde(rename = "policy-type")]
    pub policy_type: PolicyType,

    #[serde(rename = "policy-string")]
    #[serde(default)]
    pub policy_string: Vec<String>,

    #[serde(rename = "policy-domain")]
    #[serde(default)]
    pub policy_domain: String,

    #[serde(rename = "mx-host")]
    #[serde(default)]
    pub mx_host: Vec<String>,
}

#[derive(Debug, PartialEq, Eq, Serialize, Deserialize, Clone)]
pub struct Summary {
    #[serde(rename = "total-successful-session-count")]
    #[serde(default)]
    pub total_success: u32,

    #[serde(rename = "total-failure-session-count")]
    #[serde(default)]
    pub total_failure: u32,
}

#[derive(Debug, Default, Hash, PartialEq, Eq, Serialize, Deserialize, Clone)]
pub struct FailureDetails {
    #[serde(rename = "result-type")]
    pub result_type: ResultType,

    #[serde(rename = "sending-mta-ip")]
    pub sending_mta_ip: Option<IpAddr>,

    #[serde(rename = "receiving-mx-hostname")]
    pub receiving_mx_hostname: Option<String>,

    #[serde(rename = "receiving-mx-helo")]
    pub receiving_mx_helo: Option<String>,

    #[serde(rename = "receiving-ip")]
    pub receiving_ip: Option<IpAddr>,

    #[serde(rename = "failed-session-count")]
    #[serde(default)]
    pub failed_session_count: u32,

    #[serde(rename = "additional-information")]
    pub additional_information: Option<String>,

    #[serde(rename = "failure-reason-code")]
    pub failure_reason_code: Option<String>,
}

#[derive(Debug, PartialEq, Eq, Serialize, Deserialize, Clone)]
pub struct DateRange {
    #[serde(rename = "start-datetime")]
    #[serde(serialize_with = "serialize_datetime")]
    #[serde(deserialize_with = "deserialize_datetime")]
    pub start_datetime: DateTime,
    #[serde(rename = "end-datetime")]
    #[serde(serialize_with = "serialize_datetime")]
    #[serde(deserialize_with = "deserialize_datetime")]
    pub end_datetime: DateTime,
}

#[derive(Debug, Default, PartialEq, Eq, Serialize, Deserialize, Clone, Copy)]
pub enum PolicyType {
    #[serde(rename = "tlsa")]
    Tlsa,
    #[serde(rename = "sts")]
    Sts,
    #[serde(rename = "no-policy-found")]
    NoPolicyFound,
    #[serde(other)]
    #[default]
    Other,
}

#[derive(Debug, Default, Clone, Copy, Hash, PartialEq, Eq, Serialize, Deserialize)]
pub enum ResultType {
    #[serde(rename = "starttls-not-supported")]
    StartTlsNotSupported,
    #[serde(rename = "certificate-host-mismatch")]
    CertificateHostMismatch,
    #[serde(rename = "certificate-expired")]
    CertificateExpired,
    #[serde(rename = "certificate-not-trusted")]
    CertificateNotTrusted,
    #[serde(rename = "validation-failure")]
    ValidationFailure,
    #[serde(rename = "tlsa-invalid")]
    TlsaInvalid,
    #[serde(rename = "dnssec-invalid")]
    DnssecInvalid,
    #[serde(rename = "dane-required")]
    DaneRequired,
    #[serde(rename = "sts-policy-fetch-error")]
    StsPolicyFetchError,
    #[serde(rename = "sts-policy-invalid")]
    StsPolicyInvalid,
    #[serde(rename = "sts-webpki-invalid")]
    StsWebpkiInvalid,
    #[serde(other)]
    #[default]
    Other,
}

fn deserialize_datetime<'de, D>(deserializer: D) -> Result<DateTime, D::Error>
where
    D: Deserializer<'de>,
{
    Ok(
        DateTime::parse_rfc3339(Deserialize::deserialize(deserializer)?)
            .unwrap_or_else(|| DateTime::from_timestamp(0)),
    )
}

fn serialize_datetime<S>(datetime: &DateTime, serializer: S) -> Result<S::Ok, S::Error>
where
    S: Serializer,
{
    serializer.serialize_str(&datetime.to_rfc3339())
}

impl PolicyDetails {
    pub fn new(policy_type: PolicyType, policy_domain: impl Into<String>) -> Self {
        Self {
            policy_type,
            policy_string: vec![],
            policy_domain: policy_domain.into(),
            mx_host: vec![],
        }
    }
}

impl FailureDetails {
    pub fn new(result_type: impl Into<ResultType>) -> Self {
        FailureDetails {
            result_type: result_type.into(),
            ..Default::default()
        }
    }

    pub fn with_failure_reason_code(mut self, value: impl Into<String>) -> Self {
        self.failure_reason_code = Some(value.into());
        self
    }

    pub fn with_receiving_mx_hostname(mut self, value: impl Into<String>) -> Self {
        self.receiving_mx_hostname = Some(value.into());
        self
    }

    pub fn with_receiving_ip(mut self, value: IpAddr) -> Self {
        self.receiving_ip = Some(value);
        self
    }
}

impl DateRange {
    pub fn from_timestamps(start_datetime: i64, end_datetime: i64) -> Self {
        Self {
            start_datetime: DateTime::from_timestamp(start_datetime),
            end_datetime: DateTime::from_timestamp(end_datetime),
        }
    }
}
