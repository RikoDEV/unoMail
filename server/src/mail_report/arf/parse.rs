/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: Apache-2.0 OR MIT
 */

use crate::mail_report::{AuthFailureType, DeliveryResult, Error, Feedback, FeedbackType, IdentityAlignment};
use mail_parser::{DateTime, MessageParser, PartKind};
use std::borrow::Cow;

impl<'x> Feedback<'x> {
    pub fn parse_rfc5322(message: &'x [u8]) -> Result<Self, Error> {
        let message = MessageParser::new()
            .parse(message)
            .ok_or(Error::MailParseError)?;
        let mut feedback = None;
        let mut included_message = None;
        let mut included_headers = None;

        for part in message.root().parts() {
            if part.is_content_type("message", "feedback-report") {
                feedback = Feedback::parse_arf(&part.decoded()).map(|f| f.into_owned());
                continue;
            }
            match part.kind() {
                PartKind::Text if part.is_content_type("text", "rfc822-headers") => {
                    included_headers = Some(Cow::<[u8]>::Owned(part.decoded().into_owned()));
                }
                PartKind::Message(message) => {
                    included_message = Some(Cow::<[u8]>::Owned(message.raw().to_vec()));
                }
                _ => {}
            }
        }

        if let Some(mut feedback) = feedback {
            for (feedback, included) in [
                (&mut feedback.message, included_message),
                (&mut feedback.headers, included_headers),
            ] {
                if let Some(included) = included {
                    *feedback = match included {
                        Cow::Borrowed(bytes) => Some(String::from_utf8_lossy(bytes)),
                        Cow::Owned(bytes) => Some(
                            String::from_utf8(bytes)
                                .unwrap_or_else(|err| {
                                    String::from_utf8_lossy(err.as_bytes()).into_owned()
                                })
                                .into(),
                        ),
                    };
                }
            }

            Ok(feedback)
        } else {
            Err(Error::NoReportsFound)
        }
    }

    pub fn parse_arf(arf: &'x [u8]) -> Option<Self> {
        let mut f = Feedback {
            incidents: 1,
            ..Default::default()
        };
        let mut has_ft = false;

        for (key, value) in header_fields(arf) {
            let txt_value = std::str::from_utf8(value).unwrap_or_default().trim();

            hashify::fnc_map_ignore_case!(key,
                b"Arrival-Date" => {
                    if let Some(dt) = std::str::from_utf8(value).ok().and_then(|v| DateTime::parse_rfc822(v.trim())) {
                        f.arrival_date = dt.to_timestamp().into();
                    }
                },
                b"Auth-Failure" => {
                    f.auth_failure = match hashify::map_ignore_case!(txt_value.as_bytes(), AuthFailureType,
                        b"adsp" => AuthFailureType::Adsp,
                        b"bodyhash" => AuthFailureType::BodyHash,
                        b"revoked" => AuthFailureType::Revoked,
                        b"signature" => AuthFailureType::Signature,
                        b"spf" => AuthFailureType::Spf,
                        b"dmarc" => AuthFailureType::Dmarc,
                    ).copied() {
                        Some(auth_failure) => auth_failure,
                        None => continue,
                    };
                },
                b"Authentication-Results" => {
                    f.authentication_results.push(txt_value.into());
                },
                b"DKIM-ADSP-DNS" => {
                    f.dkim_adsp_dns = Some(txt_value.into());
                },
                b"DKIM-Canonicalized-Body" => {
                    f.dkim_canonicalized_body = Some(txt_value.into());
                },
                b"DKIM-Canonicalized-Header" => {
                    f.dkim_canonicalized_header = Some(txt_value.into());
                },
                b"DKIM-Domain" => {
                    f.dkim_domain = Some(txt_value.into());
                },
                b"DKIM-Identity" => {
                    f.dkim_identity = Some(txt_value.into());
                },
                b"DKIM-Selector" => {
                    f.dkim_selector = Some(txt_value.into());
                },
                b"DKIM-Selector-DNS" => {
                    f.dkim_selector_dns = Some(txt_value.into());
                },
                b"Delivery-Result" => {
                    f.delivery_result = match hashify::map_ignore_case!(txt_value.as_bytes(), DeliveryResult,
                        b"delivered" => DeliveryResult::Delivered,
                        b"spam" => DeliveryResult::Spam,
                        b"policy" => DeliveryResult::Policy,
                        b"reject" => DeliveryResult::Reject,
                        b"other" => DeliveryResult::Other,
                    ).copied() {
                        Some(delivery_result) => delivery_result,
                        None => continue,
                    };
                },
                b"Feedback-Type" => {
                    f.feedback_type = match hashify::map_ignore_case!(txt_value.as_bytes(), FeedbackType,
                        b"abuse" => FeedbackType::Abuse,
                        b"auth-failure" => FeedbackType::AuthFailure,
                        b"fraud" => FeedbackType::Fraud,
                        b"not-spam" => FeedbackType::NotSpam,
                        b"other" => FeedbackType::Other,
                        b"virus" => FeedbackType::Virus,
                    ).copied() {
                        Some(feedback_type) => feedback_type,
                        None => continue,
                    };
                    has_ft = true;
                },
                b"Identity-Alignment" => {
                    for id in txt_value.split(',') {
                        let id = id.trim();
                        hashify::fnc_map_ignore_case!(id.as_bytes(),
                            b"dkim" => {
                                f.identity_alignment =
                                    if f.identity_alignment == IdentityAlignment::Spf {
                                        IdentityAlignment::DkimSpf
                                    } else {
                                        IdentityAlignment::Dkim
                                    };
                            },
                            b"spf" => {
                                f.identity_alignment =
                                    if f.identity_alignment == IdentityAlignment::Dkim {
                                        IdentityAlignment::DkimSpf
                                    } else {
                                        IdentityAlignment::Spf
                                    };
                            },
                            b"none" => {
                                f.identity_alignment = IdentityAlignment::None;
                                break;
                            },
                            _ => ()
                        );
                    }
                },
                b"Incidents" => {
                    f.incidents = txt_value.parse().unwrap_or(1);
                },
                b"Original-Envelope-Id" => {
                    f.original_envelope_id = Some(txt_value.into());
                },
                b"Original-Mail-From" => {
                    f.original_mail_from = Some(txt_value.into());
                },
                b"Original-Rcpt-To" => {
                    f.original_rcpt_to = Some(txt_value.into());
                },
                b"Reported-Domain" => {
                    f.reported_domain.push(txt_value.into());
                },
                b"Reported-URI" => {
                    f.reported_uri.push(txt_value.into());
                },
                b"Reporting-MTA" => {
                    f.reporting_mta = Some(if let Some(mta) = txt_value.strip_prefix("dns;") {
                        mta.trim().into()
                    } else {
                        txt_value.into()
                    });
                },
                b"Received-Date" => {
                    if let Some(dt) = std::str::from_utf8(value).ok().and_then(|v| DateTime::parse_rfc822(v.trim())) {
                        f.arrival_date = dt.to_timestamp().into();
                    }
                },
                b"SPF-DNS" => {
                    f.spf_dns = Some(txt_value.into());
                },
                b"Source-IP" => {
                    f.source_ip = if let Some((ip, _)) = txt_value.split_once(' ') {
                        ip.parse().ok()
                    } else {
                        txt_value.parse().ok()
                    };
                },
                b"Source-Port" => {
                    f.source_port = txt_value.parse().unwrap_or(0);
                },
                b"User-Agent" => {
                    f.user_agent = Some(txt_value.into());
                },
                b"Version" => {
                    f.version = txt_value.parse().unwrap_or(0);
                },
                _ => ()
            );
        }

        if has_ft { Some(f) } else { None }
    }
}

/// The fields of an ARF report part: name and value, the value with its folding, up to the first
/// blank line.
fn header_fields(block: &[u8]) -> Vec<(&[u8], &[u8])> {
    let start = block.iter().position(|ch| !ch.is_ascii_whitespace()).unwrap_or(block.len());
    let block = &block[start..];
    let mut fields = Vec::new();
    let mut position = 0;
    let mut field_start = None;
    for line in block.split_inclusive(|ch| *ch == b'\n') {
        let blank = line.trim_ascii().is_empty();
        if !matches!(line.first(), Some(b' ' | b'\t')) || blank {
            if let Some(from) = field_start.take() {
                push_field(&block[from..position], &mut fields);
            }
            if blank {
                return fields;
            }
            field_start = Some(position);
        }
        position += line.len();
    }
    if let Some(from) = field_start {
        push_field(&block[from..position], &mut fields);
    }
    fields
}

fn push_field<'x>(field: &'x [u8], fields: &mut Vec<(&'x [u8], &'x [u8])>) {
    match field.iter().position(|ch| *ch == b':') {
        Some(colon) => fields.push((field[..colon].trim_ascii(), &field[colon + 1..])),
        None => fields.push((field.trim_ascii(), b"")),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn fields_end_at_the_blank_line_and_keep_folding() {
        let fields = header_fields(b"\r\nFeedback-Type: abuse\r\nUser-Agent: a\r\n b\r\nnoise\r\n\r\nIgnored: yes\r\n");
        let names: Vec<&[u8]> = fields.iter().map(|(name, _)| *name).collect();
        assert_eq!(names, [&b"Feedback-Type"[..], b"User-Agent", b"noise"]);
        assert_eq!(fields[1].1, b" a\r\n b\r\n");
    }

    #[test]
    fn a_report_is_found_only_in_the_message_itself() {
        let report = "Feedback-Type: abuse\r\nUser-Agent: test\r\nVersion: 1\r\nArrival-Date: Mon, 05 Oct 2026 10:00:00 +0000\r\n";
        let direct = format!("From: a@example.org\r\nContent-Type: multipart/report; boundary=\"B\"\r\n\r\n--B\r\nContent-Type: message/feedback-report\r\n\r\n{report}\r\n--B--\r\n");
        let feedback = Feedback::parse_rfc5322(direct.as_bytes()).unwrap();
        assert_eq!(feedback.feedback_type(), FeedbackType::Abuse);
        assert!(feedback.arrival_date().is_some());
        // Quoted inside an attached message it is not a report about this mail.
        let forwarded = format!("From: a@example.org\r\nContent-Type: message/rfc822\r\n\r\n{direct}");
        assert!(Feedback::parse_rfc5322(forwarded.as_bytes()).is_err());
    }
}
