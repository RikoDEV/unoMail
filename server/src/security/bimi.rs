//! BIMI (Brand Indicators for Message Identification): the logo a domain publishes for its
//! mail, and the Verified Mark Certificate that vouches for it.
//!
//! A logo is only ever looked up for a message that passed DMARC, from a domain whose DMARC
//! policy is enforced; that is what makes the logo say something about the message.
//!
//! This module holds the parts that need no network: reading the DNS records, checking a mark
//! certificate against the trusted roots, and vetting the image.

use std::io::Read;

use x509_parser::{pem::Pem, prelude::*};

/// Largest logo accepted (the specification recommends 32 kB).
pub const MAX_LOGO_BYTES: usize = 256 * 1024;
const MAX_CHAIN: usize = 6;
/// id-kp-BrandIndicatorforMessageIdentification
const EKU_BIMI: &str = "1.3.6.1.5.5.7.3.31";
/// id-pe-logotype
const EXT_LOGOTYPE: &str = "1.3.6.1.5.5.7.1.12";
const DIGICERT_ROOT: &str = include_str!("../../assets/bimi-roots/DigiCertVerifiedMarkRootCA.pem");

/// A domain's BIMI assertion record (`default._bimi.<domain>`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Record {
    /// Where the logo (SVG) is published.
    pub logo: Option<String>,
    /// Where the mark certificate (PEM) is published.
    pub authority: Option<String>,
}

fn tags(record: &str) -> Vec<(String, String)> {
    record.split(';').filter_map(|part| part.split_once('=')).map(|(key, value)| (key.trim().to_ascii_lowercase(), value.trim().to_owned())).collect()
}

/// Reads a BIMI record. `None` for anything else, and for a record that declines to
/// participate (empty `l=` and `a=`).
pub fn parse_record(txt: &str) -> Option<Record> {
    let tags = tags(txt);
    if !tags.first().is_some_and(|(key, value)| key == "v" && value.eq_ignore_ascii_case("BIMI1")) {
        return None;
    }
    // Only HTTPS locations are allowed.
    let url = |name: &str| tags.iter().find(|(key, _)| key == name).map(|(_, value)| value.clone()).filter(|value| value.len() <= 2000 && value.to_ascii_lowercase().starts_with("https://"));
    let record = Record { logo: url("l"), authority: url("a") };
    (record.logo.is_some() || record.authority.is_some()).then_some(record)
}

/// Whether a DMARC record enforces its policy for all mail, as BIMI requires: `p=quarantine`
/// or `p=reject`, not limited to a share of the mail by `pct`.
pub fn dmarc_enforced(txt: &str) -> bool {
    let tags = tags(txt);
    let tag = |name: &str| tags.iter().find(|(key, _)| key == name).map(|(_, value)| value.to_ascii_lowercase());
    tags.first().is_some_and(|(key, value)| key == "v" && value.eq_ignore_ascii_case("DMARC1")) && matches!(tag("p").as_deref(), Some("quarantine" | "reject")) && tag("pct").is_none_or(|pct| pct == "100")
}

/// The domain itself and its parents, down to two labels: where records are looked for.
/// (Without a list of public suffixes a parent such as `co.uk` may be asked too; it has no
/// records, so nothing comes of it.)
pub fn candidates(domain: &str) -> Vec<String> {
    let labels: Vec<&str> = domain.split('.').collect();
    (0..labels.len().saturating_sub(1)).take(3).map(|skip| labels[skip..].join(".")).collect()
}

/// Checks that an image is a harmless SVG and returns it as text. Logos may be gzip
/// compressed. Scripts, event handlers, embedded documents and references to anything
/// outside the file are refused: a logo is a picture, nothing else.
pub fn clean_svg(data: &[u8]) -> Option<String> {
    let text = if data.starts_with(&[0x1f, 0x8b]) {
        let mut out = String::new();
        flate2::read::GzDecoder::new(data).take(MAX_LOGO_BYTES as u64 + 1).read_to_string(&mut out).ok()?;
        out
    } else {
        String::from_utf8(data.to_vec()).ok()?
    };
    if text.len() > MAX_LOGO_BYTES {
        return None;
    }
    let lower = text.to_ascii_lowercase();
    if !lower.contains("<svg") || ["<script", "<foreignobject", "<iframe", "<!entity", "javascript:", "<a ", "<image"].iter().any(|bad| lower.contains(bad)) {
        return None;
    }
    // Event handlers (onload=, onclick=, ...) and links leaving the file.
    let bytes = lower.as_bytes();
    let handler = bytes.windows(3).enumerate().any(|(index, window)| {
        (window[0].is_ascii_whitespace() || window[0] == b'"' || window[0] == b'\'') && &window[1..] == b"on" && {
            let rest = &bytes[index + 3..];
            let letters = rest.iter().take_while(|b| b.is_ascii_lowercase()).count();
            letters > 0 && rest[letters..].iter().find(|b| !b.is_ascii_whitespace()) == Some(&b'=')
        }
    });
    let external = ["href=\"http", "href='http", "href=\"//", "href='//", "url(http", "url(\"http", "url('http", "url(//", "href=\"data:", "href='data:"].iter().any(|bad| lower.replace(' ', "").contains(bad));
    (!handler && !external).then_some(text)
}

/// What a valid mark certificate says.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Mark {
    /// The organization the mark belongs to, as the certificate names it.
    pub organization: String,
    /// Who issued the certificate.
    pub issuer: String,
    /// The logo embedded in the certificate.
    pub logo: Option<String>,
}

/// The trusted roots for mark certificates, DER encoded: the one shipped with the server and
/// any PEM files in `extra` (`<data>/bimi-roots`).
pub fn roots(extra: &std::path::Path) -> Vec<Vec<u8>> {
    let mut texts = vec![DIGICERT_ROOT.to_owned()];
    if let Ok(entries) = std::fs::read_dir(extra) {
        texts.extend(entries.flatten().filter(|entry| entry.path().extension().is_some_and(|ext| ext == "pem" || ext == "crt")).filter_map(|entry| std::fs::read_to_string(entry.path()).ok()));
    }
    texts.iter().flat_map(|text| Pem::iter_from_buffer(text.as_bytes()).flatten().filter(|pem| pem.label == "CERTIFICATE").map(|pem| pem.contents).collect::<Vec<_>>()).collect()
}

fn organization(name: &X509Name<'_>) -> String {
    let text = name.iter_organization().next().or_else(|| name.iter_common_name().next()).and_then(|attribute| attribute.as_str().ok()).unwrap_or("");
    text.chars().filter(|c| !c.is_control()).take(200).collect()
}

/// The SVG carried in a certificate's logotype extension (a `data:` URI holding a gzip
/// compressed, base64 encoded image).
fn embedded_logo(certificate: &X509Certificate<'_>) -> Option<String> {
    const MARKER: &[u8] = b"data:image/svg+xml;base64,";
    let extension = certificate.extensions().iter().find(|extension| extension.oid.to_id_string() == EXT_LOGOTYPE)?;
    let start = extension.value.windows(MARKER.len()).position(|window| window == MARKER)? + MARKER.len();
    let encoded: Vec<u8> = extension.value[start..].iter().copied().take_while(|b| b.is_ascii_alphanumeric() || matches!(b, b'+' | b'/' | b'=')).collect();
    let data = base64::Engine::decode(&base64::engine::general_purpose::STANDARD, encoded).ok()?;
    clean_svg(&data)
}

fn name_matches(san: &str, domain: &str) -> bool {
    let san = san.trim_end_matches('.').to_ascii_lowercase();
    // The certificate may name the domain itself, a parent of it, or the BIMI record's own name.
    let san = san.strip_prefix("default._bimi.").unwrap_or(&san);
    domain == san || domain.ends_with(&format!(".{san}"))
}

/// Verifies a mark certificate chain (PEM, leaf first or in any order) for mail from `domain`:
/// issued for that domain, for the purpose of BIMI, valid at `now`, and signed - possibly
/// through intermediates - by one of the trusted `roots`.
///
/// Not checked: revocation and Certificate Transparency.
pub fn verify_mark(pem: &[u8], domain: &str, roots: &[Vec<u8>], now: i64) -> Result<Mark, String> {
    let blocks: Vec<Pem> = Pem::iter_from_buffer(pem).flatten().filter(|block| block.label == "CERTIFICATE").take(MAX_CHAIN).collect();
    let chain: Vec<X509Certificate<'_>> = blocks.iter().filter_map(|block| block.parse_x509().ok()).collect();
    let trusted: Vec<X509Certificate<'_>> = roots.iter().filter_map(|der| X509Certificate::from_der(der).ok().map(|(_, certificate)| certificate)).collect();
    let at = ASN1Time::from_timestamp(now).map_err(|_| "invalid time")?;
    let for_bimi = |certificate: &X509Certificate<'_>| certificate.extended_key_usage().ok().flatten().is_some_and(|usage| usage.value.other.iter().any(|oid| oid.to_id_string() == EKU_BIMI));

    let leaf = chain.iter().find(|certificate| !certificate.is_ca() && for_bimi(certificate)).ok_or("no mark certificate found")?;
    if !leaf.validity().is_valid_at(at) {
        return Err("the mark certificate is expired or not yet valid".into());
    }
    let names = leaf.subject_alternative_name().ok().flatten().map(|san| san.value.general_names.iter().filter_map(|name| if let GeneralName::DNSName(name) = name { Some((*name).to_owned()) } else { None }).collect::<Vec<_>>()).unwrap_or_default();
    if !names.iter().any(|name| name_matches(name, &domain.to_ascii_lowercase())) {
        return Err("the mark certificate was issued for another domain".into());
    }

    let mut current = leaf;
    for _ in 0..MAX_CHAIN {
        if trusted.iter().any(|root| root.subject() == current.issuer() && root.validity().is_valid_at(at) && current.verify_signature(Some(root.public_key())).is_ok()) {
            return Ok(Mark { organization: organization(leaf.subject()), issuer: organization(leaf.issuer()), logo: embedded_logo(leaf) });
        }
        let parent = chain.iter().find(|candidate| {
            !std::ptr::eq(*candidate, current) && candidate.is_ca() && candidate.subject() == current.issuer() && candidate.validity().is_valid_at(at) && current.verify_signature(Some(candidate.public_key())).is_ok()
        });
        match parent {
            Some(parent) => current = parent,
            None => break,
        }
    }
    Err("the mark certificate does not lead to a trusted issuer".into())
}

#[cfg(test)]
mod tests {
    use std::io::Write;

    use rcgen::{BasicConstraints, CertificateParams, CustomExtension, DnType, ExtendedKeyUsagePurpose, IsCa, Issuer, KeyPair};
    use ::time::{Duration, OffsetDateTime};

    use super::*;

    const LOGO: &str = r##"<svg xmlns="http://www.w3.org/2000/svg" version="1.2" baseProfile="tiny-ps" viewBox="0 0 64 64"><title>Example</title><circle cx="32" cy="32" r="30" fill="#1a73e8"/></svg>"##;

    #[test]
    fn records() {
        assert_eq!(parse_record("v=BIMI1; l=https://example.org/logo.svg; a=https://example.org/vmc.pem"), Some(Record { logo: Some("https://example.org/logo.svg".into()), authority: Some("https://example.org/vmc.pem".into()) }));
        assert_eq!(parse_record("v=BIMI1;l=https://example.org/logo.svg;").unwrap().authority, None);
        // Declined, not BIMI at all, or not over HTTPS.
        for bad in ["v=BIMI1; l=; a=;", "v=spf1 -all", "", "l=https://example.org/logo.svg", "v=BIMI1; l=http://example.org/logo.svg", "v=BIMI1; l=javascript:alert(1)"] {
            assert_eq!(parse_record(bad), None, "{bad}");
        }

        assert!(dmarc_enforced("v=DMARC1; p=reject; rua=mailto:d@example.org"));
        assert!(dmarc_enforced("v=DMARC1;p=quarantine;pct=100"));
        for weak in ["v=DMARC1; p=none", "v=DMARC1; p=quarantine; pct=50", "p=reject", "v=spf1 -all", ""] {
            assert!(!dmarc_enforced(weak), "{weak}");
        }
        assert_eq!(candidates("news.mail.example.co.uk"), ["news.mail.example.co.uk", "mail.example.co.uk", "example.co.uk"]);
        assert_eq!(candidates("example.org"), ["example.org"]);
        assert!(candidates("localhost").is_empty());
    }

    #[test]
    fn logos_are_pictures_and_nothing_else() {
        assert_eq!(clean_svg(LOGO.as_bytes()).as_deref(), Some(LOGO));
        let mut gz = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::default());
        gz.write_all(LOGO.as_bytes()).unwrap();
        assert_eq!(clean_svg(&gz.finish().unwrap()).as_deref(), Some(LOGO), "compressed logos are unpacked");
        for bad in [
            "<svg><script>alert(1)</script></svg>",
            "<svg onload=\"alert(1)\"></svg>",
            "<svg><circle ONCLICK = 'x()'/></svg>",
            "<svg><foreignObject><body/></foreignObject></svg>",
            "<svg><image href=\"https://tracker.example/pixel.png\"/></svg>",
            "<svg><rect fill=\"url(https://evil.example/x)\"/></svg>",
            "<svg><a xlink:href=\"javascript:alert(1)\"><circle/></a></svg>",
            "<!DOCTYPE svg [<!ENTITY x SYSTEM \"file:///etc/passwd\">]><svg>&x;</svg>",
            "<html><body>not a picture</body></html>",
            "\u{1f}\u{8b}not really gzip",
        ] {
            assert_eq!(clean_svg(bad.as_bytes()), None, "{bad}");
        }
        assert_eq!(clean_svg(format!("<svg>{}</svg>", "x".repeat(MAX_LOGO_BYTES)).as_bytes()), None);
        // Words that merely contain "on" are fine.
        assert!(clean_svg(b"<svg><title>Position one</title><path d=\"M0 0\" font=\"x\"/></svg>").is_some());
    }

    struct Authority {
        params: CertificateParams,
        key: KeyPair,
        der: Vec<u8>,
        pem: String,
    }

    fn authority(name: &str) -> Authority {
        let key = KeyPair::generate().unwrap();
        let mut params = CertificateParams::new(Vec::new()).unwrap();
        params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
        params.distinguished_name.push(DnType::OrganizationName, name);
        let certificate = params.self_signed(&key).unwrap();
        Authority { der: certificate.der().to_vec(), pem: certificate.pem(), params, key }
    }

    fn mark(issuer: &Authority, names: &[&str], bimi: bool, days_from_now: i64, logo: Option<&str>) -> String {
        let mut params = CertificateParams::new(names.iter().map(|name| (*name).to_owned()).collect::<Vec<_>>()).unwrap();
        params.distinguished_name.push(DnType::OrganizationName, "Example Corp");
        params.not_before = OffsetDateTime::now_utc() + Duration::days(days_from_now - 1);
        params.not_after = OffsetDateTime::now_utc() + Duration::days(days_from_now + 365);
        if bimi {
            params.extended_key_usages = vec![ExtendedKeyUsagePurpose::Other(vec![1, 3, 6, 1, 5, 5, 7, 3, 31])];
        }
        if let Some(svg) = logo {
            let mut gz = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::default());
            gz.write_all(svg.as_bytes()).unwrap();
            let uri = format!("data:image/svg+xml;base64,{}", base64::Engine::encode(&base64::engine::general_purpose::STANDARD, gz.finish().unwrap()));
            // An IA5String holding the URI, as it sits deep inside the real extension.
            let mut content = vec![0x16, 0x82, (uri.len() >> 8) as u8, uri.len() as u8];
            content.extend_from_slice(uri.as_bytes());
            params.custom_extensions = vec![CustomExtension::from_oid_content(&[1, 3, 6, 1, 5, 5, 7, 1, 12], content)];
        }
        params.signed_by(&KeyPair::generate().unwrap(), &Issuer::from_params(&issuer.params, &issuer.key)).unwrap().pem()
    }

    #[test]
    fn mark_certificates() {
        let now = OffsetDateTime::now_utc().unix_timestamp();
        let (trusted, stranger) = (authority("Mark Root"), authority("Some Other CA"));
        let roots = vec![trusted.der.clone()];

        let good = mark(&trusted, &["example.org"], true, 0, Some(LOGO));
        let verified = verify_mark(good.as_bytes(), "example.org", &roots, now).unwrap();
        assert_eq!(verified, Mark { organization: "Example Corp".into(), issuer: "Mark Root".into(), logo: Some(LOGO.into()) });
        // Mail from a subdomain is covered by the organization's certificate; another domain is not.
        assert!(verify_mark(good.as_bytes(), "news.example.org", &roots, now).is_ok());
        assert!(verify_mark(good.as_bytes(), "example.org.evil.test", &roots, now).is_err());
        assert!(verify_mark(good.as_bytes(), "notexample.org", &roots, now).is_err());
        assert!(verify_mark(mark(&trusted, &["default._bimi.example.org"], true, 0, None).as_bytes(), "example.org", &roots, now).unwrap().logo.is_none());

        // An ordinary TLS certificate is no mark certificate, however valid.
        assert_eq!(verify_mark(mark(&trusted, &["example.org"], false, 0, None).as_bytes(), "example.org", &roots, now).unwrap_err(), "no mark certificate found");
        // Not yet valid, or expired.
        assert!(verify_mark(mark(&trusted, &["example.org"], true, 30, None).as_bytes(), "example.org", &roots, now).is_err());
        assert!(verify_mark(mark(&trusted, &["example.org"], true, -400, None).as_bytes(), "example.org", &roots, now).is_err());
        // Signed by somebody the server does not trust - even when that CA is sent along.
        let foreign = format!("{}{}", mark(&stranger, &["example.org"], true, 0, Some(LOGO)), stranger.pem);
        assert_eq!(verify_mark(foreign.as_bytes(), "example.org", &roots, now).unwrap_err(), "the mark certificate does not lead to a trusted issuer");
        assert!(verify_mark(foreign.as_bytes(), "example.org", &[], now).is_err());
        // The same subject name as the trusted root, but another key.
        let impostor = authority("Mark Root");
        assert!(verify_mark(mark(&impostor, &["example.org"], true, 0, None).as_bytes(), "example.org", &roots, now).is_err());
        for junk in ["", "hello", "-----BEGIN CERTIFICATE-----\nAAAA\n-----END CERTIFICATE-----\n"] {
            assert!(verify_mark(junk.as_bytes(), "example.org", &roots, now).is_err());
        }

        // Through an intermediate, in whatever order the file lists the certificates.
        let intermediate_key = KeyPair::generate().unwrap();
        let mut intermediate_params = CertificateParams::new(Vec::new()).unwrap();
        intermediate_params.is_ca = IsCa::Ca(BasicConstraints::Constrained(0));
        intermediate_params.distinguished_name.push(DnType::OrganizationName, "Mark Issuing CA");
        let intermediate_pem = intermediate_params.signed_by(&intermediate_key, &Issuer::from_params(&trusted.params, &trusted.key)).unwrap().pem();
        let issuing = Authority { params: intermediate_params, key: intermediate_key, der: Vec::new(), pem: intermediate_pem };
        let leaf = mark(&issuing, &["example.org"], true, 0, Some(LOGO));
        for chain in [format!("{leaf}{}", issuing.pem), format!("{}{leaf}", issuing.pem)] {
            assert_eq!(verify_mark(chain.as_bytes(), "example.org", &roots, now).unwrap().issuer, "Mark Issuing CA");
        }
        assert!(verify_mark(leaf.as_bytes(), "example.org", &roots, now).is_err(), "the intermediate is missing");
    }

    #[test]
    fn the_shipped_root_is_readable() {
        let roots = roots(std::path::Path::new("/nonexistent"));
        assert_eq!(roots.len(), 1);
        let (_, root) = X509Certificate::from_der(&roots[0]).unwrap();
        assert!(root.is_ca() && organization(root.subject()).contains("DigiCert"));
    }
}
