/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: Apache-2.0 OR MIT
 */

use crate::mail_report::{
    ActionDisposition, Alignment, AuthResult, DKIMAuthResult, DateRange, Discovery, Disposition,
    DkimResult, DmarcResult, Error, Extension, Identifier, PolicyEvaluated, PolicyOverride,
    PolicyOverrideReason, PolicyPublished, Record, Report, ReportMetadata, Row, SPFAuthResult,
    SPFDomainScope, SpfResult, read_capped,
};
use flate2::read::GzDecoder;
use mail_parser::{MessageParser, PartKind};
use quick_xml::XmlVersion;
use quick_xml::events::{BytesStart, Event};
use quick_xml::reader::Reader;
use std::borrow::Cow;
use std::io::{BufRead, Cursor};
use std::net::IpAddr;
use std::str::FromStr;

impl Report {
    /// Enforced while parsing (not after), so a crafted document cannot allocate first.
    pub const MAX_RECORDS_PARSED: usize = 50_000;

    pub fn parse_rfc5322(report: &[u8], max_size: usize) -> Result<Self, Error> {
        let message = MessageParser::new()
            .parse(report)
            .ok_or(Error::MailParseError)?;
        let mut error = Error::NoReportsFound;

        for part in message.root().parts() {
            match part.kind() {
                PartKind::Text
                    if part
                        .content_type()
                        .and_then(|ct| ct.subtype())
                        .is_some_and(|t| t.eq_ignore_ascii_case("xml"))
                        || part
                            .attachment_name()
                            .and_then(|n| n.rsplit_once('.'))
                            .is_some_and(|(_, e)| e.eq_ignore_ascii_case("xml")) =>
                {
                    match Report::parse_xml(part.text().unwrap_or_default().as_bytes()) {
                        Ok(feedback) => return Ok(feedback),
                        Err(err) => {
                            error = err.into();
                        }
                    }
                }
                PartKind::Binary | PartKind::InlineBinary => {
                    let report = part.decoded();
                    enum ReportType {
                        Xml,
                        Gzip,
                        Zip,
                    }

                    let (_, ext) = part
                        .attachment_name()
                        .unwrap_or("file.none")
                        .rsplit_once('.')
                        .unwrap_or(("file", "none"));
                    let subtype = part
                        .content_type()
                        .and_then(|ct| ct.subtype())
                        .unwrap_or("none");
                    let rt = if subtype.eq_ignore_ascii_case("gzip") {
                        ReportType::Gzip
                    } else if subtype.eq_ignore_ascii_case("zip") {
                        ReportType::Zip
                    } else if subtype.eq_ignore_ascii_case("xml") {
                        ReportType::Xml
                    } else if ext.eq_ignore_ascii_case("gz") {
                        ReportType::Gzip
                    } else if ext.eq_ignore_ascii_case("zip") {
                        ReportType::Zip
                    } else if ext.eq_ignore_ascii_case("xml") {
                        ReportType::Xml
                    } else {
                        continue;
                    };

                    match rt {
                        ReportType::Gzip => {
                            let report: &[u8] = report.as_ref();
                            let buf = read_capped(GzDecoder::new(report), 0, max_size)?;

                            match Report::parse_xml(&buf) {
                                Ok(feedback) => return Ok(feedback),
                                Err(err) => {
                                    error = err.into();
                                }
                            }
                        }
                        ReportType::Zip => {
                            let mut archive = zip::ZipArchive::new(Cursor::new(report))
                                .map_err(|err| Error::UncompressError(err.to_string()))?;
                            // A report archive holds one (sometimes a few) XML files; a zip with
                            // thousands of entries is not one and must not be walked.
                            if archive.len() > 64 {
                                return Err(Error::UncompressError("too many files in the archive".into()));
                            }
                            for i in 0..archive.len() {
                                match archive.by_index(i) {
                                    Ok(mut file) => {
                                        let size_hint = file.size();
                                        let buf = read_capped(&mut file, size_hint, max_size)?;
                                        match Report::parse_xml(&buf) {
                                            Ok(feedback) => return Ok(feedback),
                                            Err(err) => {
                                                error = err.into();
                                            }
                                        }
                                    }
                                    Err(err) => {
                                        error = Error::UncompressError(err.to_string());
                                    }
                                }
                            }
                        }
                        ReportType::Xml => match Report::parse_xml(&report) {
                            Ok(feedback) => return Ok(feedback),
                            Err(err) => {
                                error = err.into();
                            }
                        },
                    }
                }
                _ => (),
            }
        }

        Err(error)
    }

    pub fn parse_xml(report: &[u8]) -> Result<Self, String> {
        let mut version: f32 = 0.0;
        let mut report_metadata = None;
        let mut policy_published = None;
        let mut record = Vec::new();
        let mut extensions = Vec::new();

        let mut reader = Reader::from_reader(report);
        reader.config_mut().trim_text(true);

        let mut buf = Vec::with_capacity(128);
        let mut found_feedback = false;

        while let Some(tag) = reader.next_tag(&mut buf)? {
            let name = tag.name();
            if found_feedback {
                hashify::fnc_map!(name.as_ref().as_bytes(),
                    b"version" => {
                        version = reader.next_value(&mut buf)?.unwrap_or(0.0);
                    },
                    b"report_metadata" => {
                        report_metadata = ReportMetadata::parse(&mut reader, &mut buf)?.into();
                    },
                    b"policy_published" => {
                        policy_published = PolicyPublished::parse(&mut reader, &mut buf)?.into();
                    },
                    b"record" => {
                        // Stop before building a vector the store would refuse anyway: a small
                        // XML document can hold hundreds of thousands of empty records.
                        if record.len() >= Self::MAX_RECORDS_PARSED {
                            return Err(format!("the report has more than {} records", Self::MAX_RECORDS_PARSED));
                        }
                        record.push(Record::parse(&mut reader, &mut buf)?);
                    },
                    b"extensions" => {
                        Extension::parse(&mut reader, &mut buf, &mut extensions)?;
                    },
                    _ => ()
                );
            } else if name.as_ref() == "feedback" {
                found_feedback = true;
            } else if !name.as_ref().is_empty() {
                return Err(format!(
                    "Unexpected tag {} at position {}.",
                    name.as_ref(),
                    reader.buffer_position()
                ));
            }
        }

        Ok(Report {
            version,
            report_metadata: report_metadata.ok_or("Missing feedback/report_metadata tag.")?,
            policy_published: policy_published.ok_or("Missing feedback/policy_published tag.")?,
            record,
            extensions,
        })
    }
}

impl ReportMetadata {
    pub(crate) fn parse<R: BufRead>(
        reader: &mut Reader<R>,
        buf: &mut Vec<u8>,
    ) -> Result<Self, String> {
        let mut rm = ReportMetadata::default();

        while let Some(tag) = reader.next_tag(buf)? {
            let name = tag.name();
            hashify::fnc_map!(name.as_ref().as_bytes(),
                b"org_name" => {
                    rm.org_name = reader.next_value::<String>(buf)?.unwrap_or_default();
                },
                b"email" => {
                    rm.email = reader.next_value::<String>(buf)?.unwrap_or_default();
                },
                b"extra_contact_info" => {
                    rm.extra_contact_info = reader.next_value::<String>(buf)?;
                },
                b"report_id" => {
                    rm.report_id = reader.next_value::<String>(buf)?.unwrap_or_default();
                },
                b"date_range" => {
                    rm.date_range = DateRange::parse(reader, buf)?;
                },
                b"error" => {
                    if let Some(err) = reader.next_value::<String>(buf)? {
                        rm.error.push(err);
                    }
                },
                b"generator" => {
                    rm.generator = reader.next_value::<String>(buf)?;
                },
                b"" => (),
                _ => {
                    reader.skip_tag(buf)?;
                }
            );
        }

        Ok(rm)
    }
}

impl DateRange {
    pub(crate) fn parse<R: BufRead>(
        reader: &mut Reader<R>,
        buf: &mut Vec<u8>,
    ) -> Result<Self, String> {
        let mut dr = DateRange::default();

        while let Some(tag) = reader.next_tag(buf)? {
            let name = tag.name();
            hashify::fnc_map!(name.as_ref().as_bytes(),
                b"begin" => {
                    dr.begin = reader.next_value(buf)?.unwrap_or_default();
                },
                b"end" => {
                    dr.end = reader.next_value(buf)?.unwrap_or_default();
                },
                b"" => (),
                _ => {
                    reader.skip_tag(buf)?;
                }
            );
        }

        Ok(dr)
    }
}

impl PolicyPublished {
    pub(crate) fn parse<R: BufRead>(
        reader: &mut Reader<R>,
        buf: &mut Vec<u8>,
    ) -> Result<Self, String> {
        let mut p = PolicyPublished::default();

        while let Some(tag) = reader.next_tag(buf)? {
            let name = tag.name();
            hashify::fnc_map!(name.as_ref().as_bytes(),
                b"domain" => {
                    p.domain = reader.next_value::<String>(buf)?.unwrap_or_default();
                },
                b"version_published" => {
                    p.version_published = reader.next_value(buf)?;
                },
                b"adkim" => {
                    p.adkim = reader.next_value(buf)?.unwrap_or_default();
                },
                b"aspf" => {
                    p.aspf = reader.next_value(buf)?.unwrap_or_default();
                },
                b"p" => {
                    p.p = reader.next_value(buf)?.unwrap_or_default();
                },
                b"sp" => {
                    p.sp = reader.next_value(buf)?.unwrap_or_default();
                },
                b"np" => {
                    p.np = reader.next_value(buf)?.unwrap_or_default();
                },
                b"discovery_method" => {
                    p.discovery_method = reader.next_value(buf)?.unwrap_or_default();
                },
                b"testing" => {
                    p.testing = reader
                        .next_value::<String>(buf)?
                        .is_some_and(|s| s.eq_ignore_ascii_case("y"));
                },
                b"fo" => {
                    p.fo = reader.next_value::<String>(buf)?;
                },
                b"" => (),
                _ => {
                    reader.skip_tag(buf)?;
                }
            );
        }

        Ok(p)
    }
}

impl Extension {
    pub(crate) fn parse<R: BufRead>(
        reader: &mut Reader<R>,
        buf: &mut Vec<u8>,
        extensions: &mut Vec<Extension>,
    ) -> Result<(), String> {
        while let Some(tag) = reader.next_tag(buf)? {
            let name = tag.name();
            hashify::fnc_map!(name.as_ref().as_bytes(),
                b"extension" => {
                    let mut e = Extension::default();
                    if let Ok(Some(attr)) = tag.try_get_attribute("name")
                        && let Ok(attr) = attr.normalized_value(XmlVersion::Implicit1_0)
                    {
                        e.name = attr.to_string();
                    }
                    if let Ok(Some(attr)) = tag.try_get_attribute("definition")
                        && let Ok(attr) = attr.normalized_value(XmlVersion::Implicit1_0)
                    {
                        e.definition = attr.to_string();
                    }
                    extensions.push(e);
                    reader.skip_tag(buf)?;
                },
                b"" => (),
                _ => {
                    reader.skip_tag(buf)?;
                }
            );
        }

        Ok(())
    }
}

impl Record {
    pub(crate) fn parse<R: BufRead>(
        reader: &mut Reader<R>,
        buf: &mut Vec<u8>,
    ) -> Result<Self, String> {
        let mut r = Record::default();

        while let Some(tag) = reader.next_tag(buf)? {
            let name = tag.name();
            hashify::fnc_map!(name.as_ref().as_bytes(),
                b"row" => {
                    r.row = Row::parse(reader, buf)?;
                },
                b"identifiers" => {
                    r.identifiers = Identifier::parse(reader, buf)?;
                },
                b"auth_results" => {
                    r.auth_results = AuthResult::parse(reader, buf)?;
                },
                b"extensions" => {
                    Extension::parse(reader, buf, &mut r.extensions)?;
                },
                b"" => (),
                _ => {
                    reader.skip_tag(buf)?;
                }
            );
        }

        Ok(r)
    }
}

impl Row {
    pub(crate) fn parse<R: BufRead>(
        reader: &mut Reader<R>,
        buf: &mut Vec<u8>,
    ) -> Result<Self, String> {
        let mut r = Row::default();

        while let Some(tag) = reader.next_tag(buf)? {
            let name = tag.name();
            hashify::fnc_map!(name.as_ref().as_bytes(),
                b"source_ip" => {
                    if let Some(ip) = reader.next_value::<IpAddr>(buf)? {
                        r.source_ip = ip.into();
                    }
                },
                b"count" => {
                    r.count = reader.next_value(buf)?.unwrap_or_default();
                },
                b"policy_evaluated" => {
                    r.policy_evaluated = PolicyEvaluated::parse(reader, buf)?;
                },
                b"" => (),
                _ => {
                    reader.skip_tag(buf)?;
                }
            );
        }

        Ok(r)
    }
}

impl PolicyEvaluated {
    pub(crate) fn parse<R: BufRead>(
        reader: &mut Reader<R>,
        buf: &mut Vec<u8>,
    ) -> Result<Self, String> {
        let mut pe = PolicyEvaluated::default();

        while let Some(tag) = reader.next_tag(buf)? {
            let name = tag.name();
            hashify::fnc_map!(name.as_ref().as_bytes(),
                b"disposition" => {
                    pe.disposition = reader.next_value(buf)?.unwrap_or_default();
                },
                b"dkim" => {
                    pe.dkim = reader.next_value(buf)?.unwrap_or_default();
                },
                b"spf" => {
                    pe.spf = reader.next_value(buf)?.unwrap_or_default();
                },
                b"reason" => {
                    pe.reason.push(PolicyOverrideReason::parse(reader, buf)?);
                },
                b"" => (),
                _ => {
                    reader.skip_tag(buf)?;
                }
            );
        }

        Ok(pe)
    }
}

impl PolicyOverrideReason {
    pub(crate) fn parse<R: BufRead>(
        reader: &mut Reader<R>,
        buf: &mut Vec<u8>,
    ) -> Result<Self, String> {
        let mut por = PolicyOverrideReason::default();

        while let Some(tag) = reader.next_tag(buf)? {
            let name = tag.name();
            hashify::fnc_map!(name.as_ref().as_bytes(),
                b"type" => {
                    por.type_ = reader.next_value(buf)?.unwrap_or_default();
                },
                b"comment" => {
                    por.comment = reader.next_value(buf)?;
                },
                b"" => (),
                _ => {
                    reader.skip_tag(buf)?;
                }
            );
        }

        Ok(por)
    }
}

impl Identifier {
    pub(crate) fn parse<R: BufRead>(
        reader: &mut Reader<R>,
        buf: &mut Vec<u8>,
    ) -> Result<Self, String> {
        let mut i = Identifier::default();

        while let Some(tag) = reader.next_tag(buf)? {
            let name = tag.name();
            hashify::fnc_map!(name.as_ref().as_bytes(),
                b"envelope_to" => {
                    i.envelope_to = reader.next_value(buf)?;
                },
                b"envelope_from" => {
                    i.envelope_from = reader.next_value(buf)?.unwrap_or_default();
                },
                b"header_from" => {
                    i.header_from = reader.next_value(buf)?.unwrap_or_default();
                },
                b"" => (),
                _ => {
                    reader.skip_tag(buf)?;
                }
            );
        }

        Ok(i)
    }
}

impl AuthResult {
    pub(crate) fn parse<R: BufRead>(
        reader: &mut Reader<R>,
        buf: &mut Vec<u8>,
    ) -> Result<Self, String> {
        let mut ar = AuthResult::default();

        while let Some(tag) = reader.next_tag(buf)? {
            let name = tag.name();
            hashify::fnc_map!(name.as_ref().as_bytes(),
                b"dkim" => {
                    ar.dkim.push(DKIMAuthResult::parse(reader, buf)?);
                },
                b"spf" => {
                    ar.spf.push(SPFAuthResult::parse(reader, buf)?);
                },
                b"" => (),
                _ => {
                    reader.skip_tag(buf)?;
                }
            );
        }

        Ok(ar)
    }
}

impl DKIMAuthResult {
    pub(crate) fn parse<R: BufRead>(
        reader: &mut Reader<R>,
        buf: &mut Vec<u8>,
    ) -> Result<Self, String> {
        let mut dar = DKIMAuthResult::default();

        while let Some(tag) = reader.next_tag(buf)? {
            let name = tag.name();
            hashify::fnc_map!(name.as_ref().as_bytes(),
                b"domain" => {
                    dar.domain = reader.next_value(buf)?.unwrap_or_default();
                },
                b"selector" => {
                    dar.selector = reader.next_value(buf)?.unwrap_or_default();
                },
                b"result" => {
                    dar.result = reader.next_value(buf)?.unwrap_or_default();
                },
                b"human_result" => {
                    dar.human_result = reader.next_value(buf)?;
                },
                b"" => (),
                _ => {
                    reader.skip_tag(buf)?;
                }
            );
        }

        Ok(dar)
    }
}

impl SPFAuthResult {
    pub(crate) fn parse<R: BufRead>(
        reader: &mut Reader<R>,
        buf: &mut Vec<u8>,
    ) -> Result<Self, String> {
        let mut sar = SPFAuthResult::default();

        while let Some(tag) = reader.next_tag(buf)? {
            let name = tag.name();
            hashify::fnc_map!(name.as_ref().as_bytes(),
                b"domain" => {
                    sar.domain = reader.next_value(buf)?.unwrap_or_default();
                },
                b"scope" => {
                    sar.scope = reader.next_value(buf)?.unwrap_or_default();
                },
                b"result" => {
                    sar.result = reader.next_value(buf)?.unwrap_or_default();
                },
                b"human_result" => {
                    sar.human_result = reader.next_value(buf)?;
                },
                b"" => (),
                _ => {
                    reader.skip_tag(buf)?;
                }
            );
        }

        Ok(sar)
    }
}

impl FromStr for PolicyOverride {
    type Err = ();

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Ok(hashify::map!(s.as_bytes(), PolicyOverride,
            b"trusted_forwarder" => PolicyOverride::TrustedForwarder,
            b"mailing_list" => PolicyOverride::MailingList,
            b"local_policy" => PolicyOverride::LocalPolicy,
            b"policy_test_mode" => PolicyOverride::PolicyTestMode,
        ).copied()
        .unwrap_or(PolicyOverride::Other))
    }
}

impl FromStr for Discovery {
    type Err = ();

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Ok(hashify::map!(s.as_bytes(), Discovery,
            b"psl" => Discovery::Psl,
            b"treewalk" => Discovery::Treewalk,
        ).copied()
        .unwrap_or(Discovery::Unspecified))
    }
}

impl FromStr for DmarcResult {
    type Err = ();

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Ok(hashify::map!(s.as_bytes(), DmarcResult,
            b"pass" => DmarcResult::Pass,
            b"fail" => DmarcResult::Fail,
        ).copied()
        .unwrap_or(DmarcResult::Unspecified))
    }
}

impl FromStr for DkimResult {
    type Err = ();

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Ok(hashify::map!(s.as_bytes(), DkimResult,
            b"none" => DkimResult::None,
            b"pass" => DkimResult::Pass,
            b"fail" => DkimResult::Fail,
            b"policy" => DkimResult::Policy,
            b"neutral" => DkimResult::Neutral,
            b"temperror" => DkimResult::TempError,
            b"permerror" => DkimResult::PermError,
        ).copied()
        .unwrap_or(DkimResult::None))
    }
}

impl FromStr for SpfResult {
    type Err = ();

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Ok(hashify::map!(s.as_bytes(), SpfResult,
            b"none" => SpfResult::None,
            b"pass" => SpfResult::Pass,
            b"fail" => SpfResult::Fail,
            b"softfail" => SpfResult::SoftFail,
            b"neutral" => SpfResult::Neutral,
            b"temperror" => SpfResult::TempError,
            b"permerror" => SpfResult::PermError,
        ).copied()
        .unwrap_or(SpfResult::None))
    }
}

impl FromStr for SPFDomainScope {
    type Err = ();

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Ok(hashify::map!(s.as_bytes(), SPFDomainScope,
            b"helo" => SPFDomainScope::Helo,
            b"mfrom" => SPFDomainScope::MailFrom,
        ).copied()
        .unwrap_or(SPFDomainScope::Unspecified))
    }
}

impl FromStr for ActionDisposition {
    type Err = ();

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Ok(hashify::map!(s.as_bytes(), ActionDisposition,
            b"none" => ActionDisposition::None,
            b"pass" => ActionDisposition::Pass,
            b"quarantine" => ActionDisposition::Quarantine,
            b"reject" => ActionDisposition::Reject,
        ).copied()
        .unwrap_or(ActionDisposition::Unspecified))
    }
}

impl FromStr for Disposition {
    type Err = ();

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Ok(hashify::map!(s.as_bytes(), Disposition,
            b"none" => Disposition::None,
            b"quarantine" => Disposition::Quarantine,
            b"reject" => Disposition::Reject,
        ).copied()
        .unwrap_or(Disposition::Unspecified))
    }
}

impl FromStr for Alignment {
    type Err = ();

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Ok(match s.as_bytes().first() {
            Some(b'r') => Alignment::Relaxed,
            Some(b's') => Alignment::Strict,
            _ => Alignment::Unspecified,
        })
    }
}

trait ReaderHelper {
    fn next_tag<'x>(&mut self, buf: &'x mut Vec<u8>) -> Result<Option<BytesStart<'x>>, String>;
    fn next_value<T: FromStr>(&mut self, buf: &mut Vec<u8>) -> Result<Option<T>, String>;
    fn skip_tag(&mut self, buf: &mut Vec<u8>) -> Result<(), String>;
}

impl<R: BufRead> ReaderHelper for Reader<R> {
    fn next_tag<'x>(&mut self, buf: &'x mut Vec<u8>) -> Result<Option<BytesStart<'x>>, String> {
        match self.read_event_into(buf) {
            Ok(Event::Start(e)) => Ok(Some(e)),
            Ok(Event::End(_)) | Ok(Event::Eof) => Ok(None),
            Err(e) => Err(format!(
                "Error at position {}: {:?}",
                self.buffer_position(),
                e
            )),
            _ => Ok(Some(BytesStart::new(""))),
        }
    }

    fn next_value<T: FromStr>(&mut self, buf: &mut Vec<u8>) -> Result<Option<T>, String> {
        let mut value: Option<String> = None;

        loop {
            match self.read_event_into(buf) {
                Ok(Event::Text(e)) => {
                    let v = e.xml_content(XmlVersion::Implicit1_0);
                    if let Some(value) = &mut value {
                        value.push_str(&v);
                    } else {
                        value = Some(v.into_owned());
                    }
                }
                Ok(Event::GeneralRef(e)) => {
                    let v = hashify::map!(e.as_bytes(), &'static str,
                        b"lt" => "<",
                        b"gt" => ">",
                        b"amp" => "&",
                        b"apos" => "'",
                        b"quot" => "\"",
                    ).copied()
                    .map(Cow::Borrowed)
                    .or_else(|| {
                        e.resolve_char_ref()
                            .ok()
                            .flatten()
                            .map(|v| Cow::Owned(v.to_string()))
                    })
                    .unwrap_or_else(|| e.xml_content(XmlVersion::Implicit1_0));

                    if let Some(value) = &mut value {
                        value.push_str(&v);
                    } else {
                        value = Some(v.into_owned());
                    }
                }
                Ok(Event::End(_)) => {
                    break;
                }
                Ok(Event::Start(e)) => {
                    return Err(format!(
                        "Expected value, found unexpected tag {} at position {}.",
                        e.name().as_ref(),
                        self.buffer_position()
                    ));
                }
                Ok(Event::Eof) => {
                    return Err(format!(
                        "Expected value, found unexpected EOF at position {}.",
                        self.buffer_position()
                    ));
                }
                _ => (),
            }
        }

        Ok(value.and_then(|v| T::from_str(&v).ok()))
    }

    fn skip_tag(&mut self, buf: &mut Vec<u8>) -> Result<(), String> {
        let mut tag_count = 0;
        loop {
            match self.read_event_into(buf) {
                Ok(Event::End(_)) => {
                    if tag_count == 0 {
                        break;
                    } else {
                        tag_count -= 1;
                    }
                }
                Ok(Event::Start(_)) => {
                    tag_count += 1;
                }
                Ok(Event::Eof) => {
                    return Err(format!(
                        "Expected value, found unexpected EOF at position {}.",
                        self.buffer_position()
                    ));
                }
                _ => (),
            }
        }
        Ok(())
    }
}

