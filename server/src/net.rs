//! Buffered line-oriented connection shared by the SMTP, IMAP and POP3 servers, with support
//! for upgrading a plaintext connection to TLS in place.

use std::{io, sync::Arc, time::Duration};

use bytes::{Buf, BytesMut};
use rustls::ServerConfig;
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::TcpStream,
};
use tokio_rustls::{TlsAcceptor, server::TlsStream};

pub const HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(20);

enum Stream {
    Plain(TcpStream),
    Tls(Box<TlsStream<TcpStream>>),
    /// Transient state while a STARTTLS handshake is in progress or after it failed.
    Closed,
}

#[derive(Debug, thiserror::Error)]
pub enum ReadError {
    #[error("connection closed")]
    Closed,
    #[error("line too long")]
    TooLong,
    #[error("timed out")]
    Timeout,
    #[error(transparent)]
    Io(#[from] io::Error),
}

pub struct Conn {
    stream: Stream,
    buf: BytesMut,
    pub timeout: Duration,
    /// Raw DEFLATE in both directions once negotiated (IMAP COMPRESS, RFC 4978).
    deflate: Option<Box<(flate2::Decompress, flate2::Compress)>>,
}

/// Decompressed data beyond this many bytes per read is a decompression bomb.
const MAX_INFLATE_PER_READ: usize = 16 * 1024 * 1024;

impl Conn {
    pub fn plain(tcp: TcpStream, timeout: Duration) -> Self {
        Conn { stream: Stream::Plain(tcp), buf: BytesMut::with_capacity(4096), timeout, deflate: None }
    }

    /// Performs an implicit-TLS handshake (ports 465, 993, 995).
    pub async fn accept_tls(tcp: TcpStream, config: Arc<ServerConfig>, timeout: Duration) -> io::Result<Self> {
        let tls = tokio::time::timeout(HANDSHAKE_TIMEOUT, TlsAcceptor::from(config).accept(tcp))
            .await
            .map_err(|_| io::Error::new(io::ErrorKind::TimedOut, "TLS handshake timed out"))??;
        Ok(Conn { stream: Stream::Tls(Box::new(tls)), buf: BytesMut::with_capacity(4096), timeout, deflate: None })
    }

    pub fn is_tls(&self) -> bool {
        matches!(self.stream, Stream::Tls(_))
    }

    /// True when the client sent data beyond what has been consumed so far.
    pub fn has_buffered(&self) -> bool {
        !self.buf.is_empty()
    }

    /// Upgrades the connection after a STARTTLS command.
    ///
    /// Any plaintext the client pipelined after the command is a protocol violation and a known
    /// injection vector (CVE-2011-0411): it must never be interpreted inside the TLS session.
    pub async fn start_tls(&mut self, config: Arc<ServerConfig>) -> io::Result<()> {
        if self.has_buffered() {
            self.stream = Stream::Closed;
            return Err(io::Error::new(io::ErrorKind::InvalidData, "plaintext data received after STARTTLS"));
        }
        let Stream::Plain(tcp) = std::mem::replace(&mut self.stream, Stream::Closed) else {
            return Err(io::Error::new(io::ErrorKind::InvalidInput, "connection is not plaintext"));
        };
        let tls = tokio::time::timeout(HANDSHAKE_TIMEOUT, TlsAcceptor::from(config).accept(tcp))
            .await
            .map_err(|_| io::Error::new(io::ErrorKind::TimedOut, "TLS handshake timed out"))??;
        self.stream = Stream::Tls(Box::new(tls));
        Ok(())
    }

    /// Starts compressing both directions. Anything the client sent after the command that
    /// turned compression on is already compressed.
    pub fn start_deflate(&mut self) -> io::Result<()> {
        self.deflate = Some(Box::new((flate2::Decompress::new(false), flate2::Compress::new(flate2::Compression::default(), false))));
        let pending = std::mem::take(&mut self.buf);
        self.inflate(&pending)
    }

    /// Decompresses `raw` onto the read buffer.
    fn inflate(&mut self, raw: &[u8]) -> io::Result<()> {
        let Some(deflate) = &mut self.deflate else { return Ok(()) };
        let inflate = &mut deflate.0;
        let mut input = raw;
        let mut produced = 0;
        let mut out = vec![0u8; 32 * 1024];
        while !input.is_empty() {
            let (before_in, before_out) = (inflate.total_in(), inflate.total_out());
            inflate.decompress(input, &mut out, flate2::FlushDecompress::Sync).map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))?;
            let consumed = (inflate.total_in() - before_in) as usize;
            let written = (inflate.total_out() - before_out) as usize;
            self.buf.extend_from_slice(&out[..written]);
            produced += written;
            input = &input[consumed..];
            if produced > MAX_INFLATE_PER_READ {
                return Err(io::Error::new(io::ErrorKind::InvalidData, "compressed data expands too much"));
            }
            if consumed == 0 && written == 0 {
                break;
            }
        }
        Ok(())
    }

    pub fn is_compressed(&self) -> bool {
        self.deflate.is_some()
    }

    async fn fill(&mut self) -> Result<(), ReadError> {
        let compressed = self.deflate.is_some();
        let mut raw = BytesMut::with_capacity(if compressed { 8192 } else { 0 });
        let target = if compressed { &mut raw } else { &mut self.buf };
        let read = async {
            match &mut self.stream {
                Stream::Plain(s) => s.read_buf(target).await,
                Stream::Tls(s) => s.read_buf(target).await,
                Stream::Closed => Ok(0),
            }
        };
        match tokio::time::timeout(self.timeout, read).await {
            Err(_) => return Err(ReadError::Timeout),
            Ok(Err(e)) => return Err(e.into()),
            Ok(Ok(0)) => return Err(ReadError::Closed),
            Ok(Ok(_)) => {}
        }
        if compressed {
            self.inflate(&raw)?;
        }
        Ok(())
    }

    /// Reads one line including its terminator (`\n`, normally preceded by `\r`). Fails with
    /// [`ReadError::TooLong`] when no terminator appears within `max` bytes.
    pub async fn read_line_raw(&mut self, max: usize) -> Result<Vec<u8>, ReadError> {
        let deadline = tokio::time::Instant::now() + self.timeout;
        let mut scanned = 0;
        loop {
            if let Some(pos) = self.buf[scanned..].iter().position(|b| *b == b'\n') {
                let end = scanned + pos + 1;
                if end > max {
                    return Err(ReadError::TooLong);
                }
                return Ok(self.buf.split_to(end).to_vec());
            }
            scanned = self.buf.len();
            if scanned >= max {
                return Err(ReadError::TooLong);
            }
            tokio::time::timeout_at(deadline, self.fill()).await.map_err(|_| ReadError::Timeout)??;
        }
    }

    /// Reads one line with the trailing CRLF (or bare LF) removed.
    pub async fn read_line(&mut self, max: usize) -> Result<Vec<u8>, ReadError> {
        let mut line = self.read_line_raw(max).await?;
        line.pop();
        if line.last() == Some(&b'\r') {
            line.pop();
        }
        Ok(line)
    }

    /// Reads exactly `n` bytes (IMAP literals).
    pub async fn read_exact(&mut self, n: usize) -> Result<Vec<u8>, ReadError> {
        let deadline = tokio::time::Instant::now() + self.timeout;
        while self.buf.len() < n {
            tokio::time::timeout_at(deadline, self.fill()).await.map_err(|_| ReadError::Timeout)??;
        }
        let out = self.buf[..n].to_vec();
        self.buf.advance(n);
        Ok(out)
    }

    pub async fn write_all(&mut self, data: &[u8]) -> io::Result<()> {
        let compressed;
        let data = match &mut self.deflate {
            Some(deflate) => {
                let compress = &mut deflate.1;
                let mut out = Vec::with_capacity(data.len() / 2 + 64);
                let mut input = data;
                loop {
                    out.reserve(data.len().max(1024));
                    let before = compress.total_in();
                    compress.compress_vec(input, &mut out, flate2::FlushCompress::Sync).map_err(io::Error::other)?;
                    input = &input[(compress.total_in() - before) as usize..];
                    // Done when everything is in and the flush fit in the spare room.
                    if input.is_empty() && out.len() < out.capacity() {
                        break;
                    }
                }
                compressed = out;
                &compressed[..]
            }
            None => data,
        };
        let write = async {
            match &mut self.stream {
                Stream::Plain(s) => {
                    s.write_all(data).await?;
                    s.flush().await
                }
                Stream::Tls(s) => {
                    s.write_all(data).await?;
                    s.flush().await
                }
                Stream::Closed => Err(io::Error::new(io::ErrorKind::NotConnected, "connection closed")),
            }
        };
        tokio::time::timeout(self.timeout, write)
            .await
            .map_err(|_| io::Error::new(io::ErrorKind::TimedOut, "write timed out"))?
    }

    pub async fn shutdown(&mut self) {
        let _ = match &mut self.stream {
            Stream::Plain(s) => s.shutdown().await,
            Stream::Tls(s) => s.shutdown().await,
            Stream::Closed => Ok(()),
        };
    }
}
