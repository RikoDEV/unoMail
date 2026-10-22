//! A small S3 client (AWS Signature Version 4): enough to keep message blobs and backups in
//! any S3-compatible object store (AWS, MinIO, Cloudflare R2, Backblaze B2, Wasabi, ...).

use std::time::Duration;

use reqwest::{Method, StatusCode};

use crate::util::{hmac_sha256, sha256_hex};

const EMPTY_SHA256: &str = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855";

#[derive(Debug, Clone)]
pub struct S3Config {
    /// `https://s3.eu-central-1.amazonaws.com`, `http://127.0.0.1:9000`, ...
    pub endpoint: String,
    pub bucket: String,
    pub region: String,
    pub access_key: String,
    pub secret_key: String,
    /// Prepended to every key, e.g. `unomail/`.
    pub prefix: String,
    /// `endpoint/bucket/key` (most self-hosted stores) instead of `bucket.endpoint/key`.
    pub path_style: bool,
}

impl S3Config {
    /// Reads `<prefix>ENDPOINT`, `BUCKET`, `REGION`, `ACCESS_KEY`, `SECRET_KEY`, `PREFIX` and
    /// `PATH_STYLE` from the environment; `None` without a bucket.
    pub fn from_env(prefix: &str) -> anyhow::Result<Option<Self>> {
        let var = |name: &str| std::env::var(format!("{prefix}{name}")).ok().filter(|v| !v.trim().is_empty());
        let Some(bucket) = var("BUCKET") else { return Ok(None) };
        let region = var("REGION").unwrap_or_else(|| "us-east-1".into());
        let custom = var("ENDPOINT");
        let endpoint = custom.clone().unwrap_or_else(|| format!("https://s3.{region}.amazonaws.com")).trim_end_matches('/').to_owned();
        anyhow::ensure!(endpoint.starts_with("https://") || endpoint.starts_with("http://"), "{prefix}ENDPOINT must start with https:// or http://");
        let access_key = var("ACCESS_KEY").ok_or_else(|| anyhow::anyhow!("{prefix}ACCESS_KEY is required with {prefix}BUCKET"))?;
        let secret_key = var("SECRET_KEY").ok_or_else(|| anyhow::anyhow!("{prefix}SECRET_KEY is required with {prefix}BUCKET"))?;
        let mut key_prefix = var("PREFIX").unwrap_or_default().trim_matches('/').to_owned();
        if !key_prefix.is_empty() {
            key_prefix.push('/');
        }
        let path_style = match var("PATH_STYLE").as_deref() {
            Some("1" | "true" | "yes" | "on") => true,
            Some("0" | "false" | "no" | "off") => false,
            Some(other) => anyhow::bail!("invalid {prefix}PATH_STYLE={other:?}"),
            // Self-hosted stores mostly expect path-style requests; AWS wants virtual hosts.
            None => custom.is_some(),
        };
        Ok(Some(S3Config { endpoint, bucket, region, access_key, secret_key, prefix: key_prefix, path_style }))
    }

    /// Where the configuration points, for display (no credentials).
    pub fn describe(&self) -> String {
        format!("s3://{}/{} ({})", self.bucket, self.prefix, self.endpoint)
    }
}

#[derive(Debug, thiserror::Error)]
pub enum S3Error {
    #[error("not found")]
    NotFound,
    #[error("object store request failed: {0}")]
    Request(String),
}

#[derive(Clone)]
pub struct S3 {
    pub cfg: S3Config,
    http: reqwest::Client,
}

fn uri_encode(value: &str, keep_slash: bool) -> String {
    let mut out = String::with_capacity(value.len());
    for byte in value.bytes() {
        match byte {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'.' | b'_' | b'~' => out.push(byte as char),
            b'/' if keep_slash => out.push('/'),
            _ => out.push_str(&format!("%{byte:02X}")),
        }
    }
    out
}

/// One request, signed: the headers to send with it.
#[derive(Debug, PartialEq, Eq)]
struct Signed {
    authorization: String,
    amz_date: String,
    content_sha256: String,
}

/// Signs a request (AWS Signature Version 4, single chunk). `headers` are extra headers to
/// sign (lower-case names), besides `host`, `x-amz-content-sha256` and `x-amz-date`.
#[allow(clippy::too_many_arguments)]
fn sign(cfg: &S3Config, method: &str, host: &str, path: &str, query: &[(String, String)], headers: &[(&str, &str)], payload_sha256: &str, amz_date: &str) -> Signed {
    let date = &amz_date[..8];
    let mut query: Vec<(String, String)> = query.iter().map(|(k, v)| (uri_encode(k, false), uri_encode(v, false))).collect();
    query.sort();
    let canonical_query = query.iter().map(|(k, v)| format!("{k}={v}")).collect::<Vec<_>>().join("&");
    let mut signed_headers: Vec<(String, String)> = vec![("host".into(), host.to_owned()), ("x-amz-content-sha256".into(), payload_sha256.to_owned()), ("x-amz-date".into(), amz_date.to_owned())];
    signed_headers.extend(headers.iter().map(|(k, v)| (k.to_ascii_lowercase(), v.trim().to_owned())));
    signed_headers.sort();
    let canonical_headers: String = signed_headers.iter().map(|(k, v)| format!("{k}:{v}\n")).collect();
    let header_names = signed_headers.iter().map(|(k, _)| k.as_str()).collect::<Vec<_>>().join(";");
    let canonical = format!("{method}\n{path}\n{canonical_query}\n{canonical_headers}\n{header_names}\n{payload_sha256}");
    let scope = format!("{date}/{}/s3/aws4_request", cfg.region);
    let to_sign = format!("AWS4-HMAC-SHA256\n{amz_date}\n{scope}\n{}", sha256_hex(canonical.as_bytes()));
    let key = [date, cfg.region.as_str(), "s3", "aws4_request"].iter().fold(format!("AWS4{}", cfg.secret_key).into_bytes(), |key, part| hmac_sha256(&key, part.as_bytes()));
    let signature = hex::encode(hmac_sha256(&key, to_sign.as_bytes()));
    Signed {
        authorization: format!("AWS4-HMAC-SHA256 Credential={}/{scope}, SignedHeaders={header_names}, Signature={signature}", cfg.access_key),
        amz_date: amz_date.to_owned(),
        content_sha256: payload_sha256.to_owned(),
    }
}

fn amz_now() -> String {
    time::OffsetDateTime::now_utc().format(time::macros::format_description!("[year][month][day]T[hour][minute][second]Z")).unwrap_or_default()
}

impl S3 {
    pub fn new(cfg: S3Config) -> anyhow::Result<Self> {
        let http = crate::outbound::builder()
            .connect_timeout(Duration::from_secs(15))
            .timeout(Duration::from_secs(300))
            .build()?;
        Ok(S3 { cfg, http })
    }

    /// Host and path of an object (or of the bucket for an empty key).
    fn location(&self, key: &str) -> (String, String, String) {
        let (scheme, rest) = self.cfg.endpoint.split_once("://").unwrap_or(("https", &self.cfg.endpoint));
        let (endpoint_host, base_path) = rest.split_once('/').map_or((rest, ""), |(h, p)| (h, p));
        let base_path = if base_path.is_empty() { String::new() } else { format!("/{}", base_path.trim_matches('/')) };
        let object = uri_encode(key, true);
        if self.cfg.path_style {
            let path = if key.is_empty() { format!("{base_path}/{}", uri_encode(&self.cfg.bucket, false)) } else { format!("{base_path}/{}/{object}", uri_encode(&self.cfg.bucket, false)) };
            (scheme.to_owned(), endpoint_host.to_owned(), path)
        } else {
            (scheme.to_owned(), format!("{}.{endpoint_host}", self.cfg.bucket), format!("{base_path}/{object}"))
        }
    }

    async fn request(&self, method: Method, key: &str, query: &[(String, String)], extra: &[(&str, &str)], body: Option<Vec<u8>>) -> Result<reqwest::Response, S3Error> {
        let (scheme, host, path) = self.location(key);
        let payload = body.as_deref().map_or_else(|| EMPTY_SHA256.to_owned(), sha256_hex);
        let signed = sign(&self.cfg, method.as_str(), &host, &path, query, extra, &payload, &amz_now());
        let mut url = format!("{scheme}://{host}{path}");
        if !query.is_empty() {
            let mut pairs: Vec<String> = query.iter().map(|(k, v)| format!("{}={}", uri_encode(k, false), uri_encode(v, false))).collect();
            pairs.sort();
            url.push('?');
            url.push_str(&pairs.join("&"));
        }
        let mut request = self
            .http
            .request(method, url)
            .header("authorization", signed.authorization)
            .header("x-amz-date", signed.amz_date)
            .header("x-amz-content-sha256", signed.content_sha256);
        for (name, value) in extra {
            request = request.header(*name, *value);
        }
        if let Some(body) = body {
            request = request.body(body);
        }
        let response = request.send().await.map_err(|e| S3Error::Request(e.to_string()))?;
        match response.status() {
            status if status.is_success() => Ok(response),
            StatusCode::NOT_FOUND => Err(S3Error::NotFound),
            status => {
                let text = response.text().await.unwrap_or_default();
                let code = text.split("<Code>").nth(1).and_then(|r| r.split("</Code>").next()).unwrap_or("");
                Err(S3Error::Request(format!("{status} {code}").trim().to_owned()))
            }
        }
    }

    fn key(&self, name: &str) -> String {
        format!("{}{name}", self.cfg.prefix)
    }

    pub async fn put(&self, name: &str, data: Vec<u8>) -> Result<(), S3Error> {
        self.request(Method::PUT, &self.key(name), &[], &[], Some(data)).await.map(|_| ())
    }

    pub async fn get(&self, name: &str) -> Result<Vec<u8>, S3Error> {
        let response = self.request(Method::GET, &self.key(name), &[], &[], None).await?;
        response.bytes().await.map(|b| b.to_vec()).map_err(|e| S3Error::Request(e.to_string()))
    }

    /// The first `limit` bytes of an object.
    pub async fn get_head(&self, name: &str, limit: usize) -> Result<Vec<u8>, S3Error> {
        let range = format!("bytes=0-{}", limit.max(1) - 1);
        let response = self.request(Method::GET, &self.key(name), &[], &[("range", &range)], None).await?;
        let mut data = response.bytes().await.map(|b| b.to_vec()).map_err(|e| S3Error::Request(e.to_string()))?;
        data.truncate(limit);
        Ok(data)
    }

    pub async fn exists(&self, name: &str) -> Result<bool, S3Error> {
        match self.request(Method::HEAD, &self.key(name), &[], &[], None).await {
            Ok(_) => Ok(true),
            Err(S3Error::NotFound) => Ok(false),
            Err(err) => Err(err),
        }
    }

    pub async fn delete(&self, name: &str) -> Result<(), S3Error> {
        match self.request(Method::DELETE, &self.key(name), &[], &[], None).await {
            Ok(_) | Err(S3Error::NotFound) => Ok(()),
            Err(err) => Err(err),
        }
    }

    /// Names (without the configured prefix) of the objects under `prefix`.
    pub async fn list(&self, prefix: &str) -> Result<Vec<String>, S3Error> {
        let mut names = Vec::new();
        let mut token: Option<String> = None;
        loop {
            let mut query = vec![("list-type".to_owned(), "2".to_owned()), ("prefix".to_owned(), self.key(prefix))];
            if let Some(token) = &token {
                query.push(("continuation-token".into(), token.clone()));
            }
            let response = self.request(Method::GET, "", &query, &[], None).await?;
            let text = response.text().await.map_err(|e| S3Error::Request(e.to_string()))?;
            for part in text.split("<Key>").skip(1) {
                if let Some(key) = part.split("</Key>").next() {
                    let key = key.replace("&amp;", "&").replace("&lt;", "<").replace("&gt;", ">").replace("&quot;", "\"").replace("&apos;", "'");
                    names.push(key.strip_prefix(&self.cfg.prefix).unwrap_or(&key).to_owned());
                }
            }
            let truncated = text.contains("<IsTruncated>true</IsTruncated>");
            token = text.split("<NextContinuationToken>").nth(1).and_then(|r| r.split("</NextContinuationToken>").next()).map(str::to_owned);
            if !truncated || token.is_none() {
                return Ok(names);
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The example from the AWS documentation ("Signature Calculations for the Authorization
    /// Header: Transferring Payload in a Single Chunk", GET Object).
    #[test]
    fn signature_matches_the_aws_example() {
        let cfg = S3Config {
            endpoint: "https://s3.amazonaws.com".into(),
            bucket: "examplebucket".into(),
            region: "us-east-1".into(),
            access_key: "AKIAIOSFODNN7EXAMPLE".into(),
            secret_key: "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY".into(),
            prefix: String::new(),
            path_style: false,
        };
        let signed = sign(&cfg, "GET", "examplebucket.s3.amazonaws.com", "/test.txt", &[], &[("range", "bytes=0-9")], EMPTY_SHA256, "20130524T000000Z");
        assert_eq!(
            signed.authorization,
            "AWS4-HMAC-SHA256 Credential=AKIAIOSFODNN7EXAMPLE/20130524/us-east-1/s3/aws4_request, SignedHeaders=host;range;x-amz-content-sha256;x-amz-date, Signature=f0e8bdb87c964420e857bd35b5d6ed310bd44f0170aba48dd91039c6036bdb41"
        );
        // ListObjects with a query string (the documentation's GET Bucket example).
        let signed = sign(&cfg, "GET", "examplebucket.s3.amazonaws.com", "/", &[("max-keys".into(), "2".into()), ("prefix".into(), "J".into())], &[], EMPTY_SHA256, "20130524T000000Z");
        assert!(signed.authorization.ends_with("Signature=34b48302e7b5fa45bde8084f4b7868a86f0a534bc59db6670ed5711ef69dc6f7"), "{}", signed.authorization);
    }

    #[test]
    fn locations() {
        let mut cfg = S3Config {
            endpoint: "http://127.0.0.1:9000".into(),
            bucket: "mail".into(),
            region: "us-east-1".into(),
            access_key: "a".into(),
            secret_key: "b".into(),
            prefix: "unomail/".into(),
            path_style: true,
        };
        let s3 = S3::new(cfg.clone()).unwrap();
        assert_eq!(s3.location("unomail/blobs/ab"), ("http".into(), "127.0.0.1:9000".into(), "/mail/unomail/blobs/ab".into()));
        assert_eq!(s3.location(""), ("http".into(), "127.0.0.1:9000".into(), "/mail".into()));
        cfg.path_style = false;
        cfg.endpoint = "https://s3.eu-central-1.amazonaws.com".into();
        let s3 = S3::new(cfg).unwrap();
        assert_eq!(s3.location("a b"), ("https".into(), "mail.s3.eu-central-1.amazonaws.com".into(), "/a%20b".into()));
        assert_eq!(uri_encode("a+b/c~d", true), "a%2Bb/c~d");
    }
}
