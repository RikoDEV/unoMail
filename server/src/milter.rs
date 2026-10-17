//! Milter client (Sendmail milter protocol, version 6): hands incoming mail to external
//! filters such as rspamd's milter, OpenDKIM/OpenDMARC, ClamAV-milter or a custom one,
//! configured with `UNOMAIL_MILTERS=host:port,...`. Each filter may accept, reject, defer or
//! discard the message, add, change or remove headers, replace the body, or quarantine it.

use std::{net::IpAddr, time::Duration};

use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::TcpStream,
};

const TIMEOUT: Duration = Duration::from_secs(30);
const MAX_PACKET: usize = 1024 * 1024 * 64;
const VERSION: u32 = 6;
/// What filters may do: add and change headers, replace the body, quarantine.
const ACTIONS: u32 = 0x01 | 0x02 | 0x10 | 0x20;
/// Steps a filter may ask to skip, and replies it may leave out.
const PROTOCOL: u32 = 0x1F_FFFF & !0x100;

const NO_CONNECT: u32 = 0x1;
const NO_HELO: u32 = 0x2;
const NO_MAIL: u32 = 0x4;
const NO_RCPT: u32 = 0x8;
const NO_BODY: u32 = 0x10;
const NO_HEADERS: u32 = 0x20;
const NO_EOH: u32 = 0x40;
const NR_HEADER: u32 = 0x80;
const NR_CONNECT: u32 = 0x1000;
const NR_HELO: u32 = 0x2000;
const NR_MAIL: u32 = 0x4000;
const NR_RCPT: u32 = 0x8000;
const NR_EOH: u32 = 0x40000;
const NR_BODY: u32 = 0x80000;
const HEADER_LEADING_SPACE: u32 = 0x100000;

/// The connection and envelope a message arrived with.
pub struct Envelope<'a> {
    pub ip: IpAddr,
    pub helo: &'a str,
    pub sender: &'a str,
    pub recipients: &'a [String],
    pub hostname: &'a str,
}

#[derive(Debug, PartialEq, Eq)]
pub enum Verdict {
    /// Deliver `message` (possibly modified); `quarantine` sends it to Junk.
    Deliver { message: Vec<u8>, quarantine: Option<String> },
    Reject(String),
    TempFail(String),
    /// Accept and drop silently.
    Discard,
}

#[derive(Debug, thiserror::Error)]
pub enum MilterError {
    #[error("milter {0}: {1}")]
    Io(String, std::io::Error),
    #[error("milter {0}: protocol error: {1}")]
    Protocol(String, String),
}

/// Parsed parts of a message, edited by the filters.
#[derive(Debug, Clone, PartialEq, Eq)]
struct Parts {
    headers: Vec<(String, String)>,
    body: Vec<u8>,
}

fn split_message(raw: &[u8]) -> Parts {
    let end = crate::security::authn::find_header_end(raw).min(raw.len());
    let head = String::from_utf8_lossy(&raw[..end]);
    let mut headers: Vec<(String, String)> = Vec::new();
    for line in head.split("\r\n").flat_map(|l| l.split('\n')) {
        if line.is_empty() {
            continue;
        }
        if line.starts_with([' ', '\t']) {
            if let Some((_, value)) = headers.last_mut() {
                value.push_str("\r\n");
                value.push_str(line);
            }
        } else if let Some((name, value)) = line.split_once(':') {
            headers.push((name.to_owned(), value.to_owned()));
        }
    }
    let body = &raw[end..];
    let body = body.strip_prefix(b"\r\n").or_else(|| body.strip_prefix(b"\n")).unwrap_or(body);
    Parts { headers, body: body.to_vec() }
}

fn join_message(parts: &Parts) -> Vec<u8> {
    let mut out = Vec::with_capacity(parts.body.len() + 4096);
    for (name, value) in &parts.headers {
        out.extend_from_slice(format!("{name}:{value}\r\n").as_bytes());
    }
    out.extend_from_slice(b"\r\n");
    out.extend_from_slice(&parts.body);
    out
}

struct Connection {
    name: String,
    stream: TcpStream,
}

impl Connection {
    async fn send(&mut self, command: u8, data: &[u8]) -> Result<(), MilterError> {
        let mut packet = Vec::with_capacity(5 + data.len());
        packet.extend_from_slice(&((data.len() + 1) as u32).to_be_bytes());
        packet.push(command);
        packet.extend_from_slice(data);
        tokio::time::timeout(TIMEOUT, self.stream.write_all(&packet))
            .await
            .map_err(|_| MilterError::Io(self.name.clone(), std::io::ErrorKind::TimedOut.into()))?
            .map_err(|e| MilterError::Io(self.name.clone(), e))
    }

    async fn receive(&mut self) -> Result<(u8, Vec<u8>), MilterError> {
        let read = async {
            let mut length = [0u8; 4];
            self.stream.read_exact(&mut length).await?;
            let length = u32::from_be_bytes(length) as usize;
            if length == 0 || length > MAX_PACKET {
                return Err(std::io::Error::new(std::io::ErrorKind::InvalidData, "bad packet length"));
            }
            let mut data = vec![0u8; length];
            self.stream.read_exact(&mut data).await?;
            Ok(data)
        };
        let data = tokio::time::timeout(TIMEOUT, read).await.map_err(|_| MilterError::Io(self.name.clone(), std::io::ErrorKind::TimedOut.into()))?.map_err(|e| MilterError::Io(self.name.clone(), e))?;
        Ok((data[0], data[1..].to_vec()))
    }

    /// Reads replies until a final one (progress notices are skipped).
    async fn reply(&mut self) -> Result<(u8, Vec<u8>), MilterError> {
        loop {
            let (code, data) = self.receive().await?;
            if code != b'p' {
                return Ok((code, data));
            }
        }
    }
}

fn cstrings(values: &[&str]) -> Vec<u8> {
    let mut out = Vec::new();
    for value in values {
        out.extend_from_slice(value.as_bytes());
        out.push(0);
    }
    out
}

fn split_cstrings(data: &[u8]) -> Vec<String> {
    data.split(|b| *b == 0).map(|s| String::from_utf8_lossy(s).into_owned()).collect()
}

/// What a step's reply means for the message.
enum Step {
    Continue,
    Accept,
    Final(Verdict),
}

fn interpret(code: u8, data: &[u8], name: &str) -> Result<Step, MilterError> {
    Ok(match code {
        b'c' => Step::Continue,
        b'a' => Step::Accept,
        // Skip the rest of the body: continue with end of message.
        b's' => Step::Continue,
        b'r' => Step::Final(Verdict::Reject("550 5.7.1 Message rejected by a content filter".into())),
        b't' => Step::Final(Verdict::TempFail("451 4.7.1 Message deferred by a content filter, try again later".into())),
        b'd' => Step::Final(Verdict::Discard),
        b'y' => {
            let text = split_cstrings(data).into_iter().next().unwrap_or_default();
            let text = crate::util::sanitize_line(&text);
            let valid = text.len() >= 3 && text.as_bytes()[..3].iter().all(u8::is_ascii_digit);
            match text.as_bytes().first() {
                Some(b'4') if valid => Step::Final(Verdict::TempFail(text)),
                Some(b'5') if valid => Step::Final(Verdict::Reject(text)),
                _ => Step::Final(Verdict::Reject("550 5.7.1 Message rejected by a content filter".into())),
            }
        }
        other => return Err(MilterError::Protocol(name.to_owned(), format!("unexpected reply {:?}", other as char))),
    })
}

/// Runs the message through one filter.
async fn run_one(address: &str, envelope: &Envelope<'_>, parts: &mut Parts, quarantine: &mut Option<String>) -> Result<Option<Verdict>, MilterError> {
    let name = address.to_owned();
    let stream = tokio::time::timeout(TIMEOUT, TcpStream::connect(address))
        .await
        .map_err(|_| MilterError::Io(name.clone(), std::io::ErrorKind::TimedOut.into()))?
        .map_err(|e| MilterError::Io(name.clone(), e))?;
    let mut c = Connection { name: name.clone(), stream };

    let mut negotiate = Vec::with_capacity(12);
    negotiate.extend_from_slice(&VERSION.to_be_bytes());
    negotiate.extend_from_slice(&ACTIONS.to_be_bytes());
    negotiate.extend_from_slice(&PROTOCOL.to_be_bytes());
    c.send(b'O', &negotiate).await?;
    let (code, data) = c.receive().await?;
    if code != b'O' || data.len() < 12 {
        return Err(MilterError::Protocol(name, "option negotiation failed".into()));
    }
    let actions = u32::from_be_bytes([data[4], data[5], data[6], data[7]]) & ACTIONS;
    let protocol = u32::from_be_bytes([data[8], data[9], data[10], data[11]]);
    let skip = |bit: u32| protocol & bit != 0;

    macro_rules! step {
        ($command:expr, $data:expr, $no:expr, $no_reply:expr) => {
            if !skip($no) {
                c.send($command, $data).await?;
                if !skip($no_reply) {
                    let (code, data) = c.reply().await?;
                    match interpret(code, &data, &name)? {
                        Step::Continue => {}
                        Step::Accept => {
                            let _ = c.send(b'Q', &[]).await;
                            return Ok(None);
                        }
                        Step::Final(verdict) => {
                            let _ = c.send(b'Q', &[]).await;
                            return Ok(Some(verdict));
                        }
                    }
                }
            }
        };
    }

    c.send(b'D', &[&b"C"[..], &cstrings(&["j", envelope.hostname, "{daemon_name}", "unomail", "_", &format!("[{}]", envelope.ip)])].concat()).await?;
    let mut connect = cstrings(&[&format!("[{}]", envelope.ip)]);
    connect.push(if envelope.ip.is_ipv4() { b'4' } else { b'6' });
    connect.extend_from_slice(&25u16.to_be_bytes());
    connect.extend_from_slice(&cstrings(&[&envelope.ip.to_string()]));
    step!(b'C', &connect, NO_CONNECT, NR_CONNECT);
    step!(b'H', &cstrings(&[envelope.helo]), NO_HELO, NR_HELO);
    c.send(b'D', &[&b"M"[..], &cstrings(&["{mail_addr}", envelope.sender])].concat()).await?;
    step!(b'M', &cstrings(&[&format!("<{}>", envelope.sender)]), NO_MAIL, NR_MAIL);
    for recipient in envelope.recipients {
        c.send(b'D', &[&b"R"[..], &cstrings(&["{rcpt_addr}", recipient])].concat()).await?;
        step!(b'R', &cstrings(&[&format!("<{recipient}>")]), NO_RCPT, NR_RCPT);
    }
    for (header, value) in parts.headers.clone() {
        let value = if skip(HEADER_LEADING_SPACE) { value } else { value.strip_prefix(' ').unwrap_or(&value).to_owned() };
        step!(b'L', &cstrings(&[&header, &value]), NO_HEADERS, NR_HEADER);
    }
    step!(b'N', &[], NO_EOH, NR_EOH);
    if !skip(NO_BODY) {
        for chunk in parts.body.chunks(65_535) {
            c.send(b'B', chunk).await?;
            if !skip(NR_BODY) {
                let (code, data) = c.reply().await?;
                if code == b's' {
                    break;
                }
                match interpret(code, &data, &name)? {
                    Step::Continue => {}
                    Step::Accept => {
                        let _ = c.send(b'Q', &[]).await;
                        return Ok(None);
                    }
                    Step::Final(verdict) => {
                        let _ = c.send(b'Q', &[]).await;
                        return Ok(Some(verdict));
                    }
                }
            }
        }
    }

    // End of message: modifications, then the verdict.
    c.send(b'E', &[]).await?;
    let mut new_body: Option<Vec<u8>> = None;
    let verdict = loop {
        let (code, data) = c.receive().await?;
        match code {
            b'p' => continue,
            b'h' if actions & 0x01 != 0 => {
                let fields = split_cstrings(&data);
                if let [name, value, ..] = fields.as_slice() {
                    parts.headers.push((name.clone(), format!(" {value}")));
                }
            }
            b'i' if actions & 0x01 != 0 && data.len() > 4 => {
                let index = u32::from_be_bytes([data[0], data[1], data[2], data[3]]) as usize;
                let fields = split_cstrings(&data[4..]);
                if let [name, value, ..] = fields.as_slice() {
                    let at = index.min(parts.headers.len());
                    parts.headers.insert(at, (name.clone(), format!(" {value}")));
                }
            }
            b'm' if actions & 0x10 != 0 && data.len() > 4 => {
                // The index counts occurrences of that header, from 1.
                let index = u32::from_be_bytes([data[0], data[1], data[2], data[3]]).max(1) as usize;
                let fields = split_cstrings(&data[4..]);
                if let [name, value, ..] = fields.as_slice() {
                    let position = parts.headers.iter().enumerate().filter(|(_, (n, _))| n.eq_ignore_ascii_case(name)).nth(index - 1).map(|(i, _)| i);
                    match (position, value.is_empty()) {
                        (Some(i), true) => {
                            parts.headers.remove(i);
                        }
                        (Some(i), false) => parts.headers[i].1 = format!(" {value}"),
                        (None, false) => parts.headers.push((name.clone(), format!(" {value}"))),
                        (None, true) => {}
                    }
                }
            }
            b'b' if actions & 0x02 != 0 => new_body.get_or_insert_with(Vec::new).extend_from_slice(&data),
            b'q' if actions & 0x20 != 0 => *quarantine = Some(split_cstrings(&data).into_iter().next().unwrap_or_default()),
            // Modifications that were not allowed are ignored.
            b'h' | b'i' | b'm' | b'b' | b'q' | b'+' | b'-' | b'2' => {}
            code => match interpret(code, &data, &name)? {
                Step::Continue | Step::Accept => break None,
                Step::Final(verdict) => break Some(verdict),
            },
        }
    };
    if let Some(body) = new_body {
        parts.body = body;
    }
    let _ = c.send(b'Q', &[]).await;
    Ok(verdict)
}

/// Runs a message through every configured filter, in order.
pub async fn check(milters: &[String], fail_open: bool, envelope: &Envelope<'_>, raw: &[u8]) -> Verdict {
    if milters.is_empty() {
        return Verdict::Deliver { message: raw.to_vec(), quarantine: None };
    }
    let mut parts = split_message(raw);
    let original = parts.clone();
    let mut quarantine = None;
    for address in milters {
        match run_one(address, envelope, &mut parts, &mut quarantine).await {
            Ok(None) => {}
            Ok(Some(verdict)) => return verdict,
            Err(err) => {
                tracing::warn!(%err, "milter unavailable");
                if !fail_open {
                    return Verdict::TempFail("451 4.7.1 Content filter temporarily unavailable, please try again later".into());
                }
            }
        }
    }
    let message = if parts == original { raw.to_vec() } else { join_message(&parts) };
    Verdict::Deliver { message, quarantine }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn hostile_messages_split_without_panicking() {
        for raw in crate::fuzzing::inputs(4, 3000, 16) {
            let parts = split_message(&raw);
            let joined = join_message(&parts);
            // Never more than the input plus the separators it may gain.
            assert!(joined.len() <= raw.len() * 3 + 4);
        }
    }


    #[test]
    fn messages_split_and_join() {
        let raw = b"Subject: hi\r\nX-Long: a\r\n\tb\r\n\r\nbody\r\n";
        let parts = split_message(raw);
        assert_eq!(parts.headers, [("Subject".to_owned(), " hi".to_owned()), ("X-Long".to_owned(), " a\r\n\tb".to_owned())]);
        assert_eq!(parts.body, b"body\r\n");
        assert_eq!(join_message(&parts), raw);
    }
}
