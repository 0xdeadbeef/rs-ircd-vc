//! Per-connection driver.
//!
//! The reader parses inbound lines (decompressing frames when negotiated) and
//! dispatches them one at a time, which preserves ordering per client. The
//! writer owns the socket's write half and applies compression after the
//! `COMPRESS` acknowledgement.

use std::io::ErrorKind;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::sync::mpsc;
use tracing::{debug, info};

use crate::net::compress::{
    parse_header, CompressionError, Compressor, Decompressor, HEADER_LEN, MAX_FRAME,
};
use crate::server::{Outbound, Server};

/// Run one accepted connection to completion.
///
/// Returns whether the peer completed registration, which tells a dialler
/// whether the link was ever established and therefore whether to reset its
/// backoff.
///
/// # Errors
///
/// Returns the socket error that terminated the connection, if any.
pub async fn run<S>(
    server: Arc<Server>,
    stream: S,
    peer: SocketAddr,
    secure: bool,
    server_link: bool,
    certificate: Option<Arc<str>>,
    dialing: bool,
) -> std::io::Result<bool>
where
    S: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
    let Some((client, receiver)) = server
        .accept_client(peer, secure, server_link, certificate, dialing)
        .await
    else {
        return Ok(false);
    };

    let config = server.cfg();
    let limits = Limits {
        max_line: config.limits.max_line_len,
        max_decompressed: config.compression.max_decompressed,
        ping_interval: Duration::from_secs(config.limits.ping_interval_secs.max(5)),
        ping_timeout: config
            .limits
            .ping_timeout_secs
            .max(config.limits.ping_interval_secs.max(5)),
        registration_timeout: Duration::from_secs(config.limits.registration_timeout_secs.max(5)),
        compression_level: config.compression.level,
    };
    drop(config);

    let (reader, writer) = tokio::io::split(stream);
    let writer_task = tokio::spawn(writer_loop(writer, receiver, limits.compression_level));

    let reason = reader_loop(&server, &client, reader, &limits).await;
    let reason = match reason {
        Ok(reason) => reason,
        Err(error) => {
            debug!(peer = %peer, %error, "read loop failed");
            "Read error".to_owned()
        }
    };

    let established = client.session(|session| session.registered);
    server.disconnect(&client, &reason);
    client.request_close();

    match tokio::time::timeout(Duration::from_secs(2), writer_task).await {
        Ok(Ok(Ok(()))) => {}
        Ok(Ok(Err(error))) => debug!(peer = %peer, %error, "write loop failed"),
        Ok(Err(error)) => debug!(peer = %peer, %error, "write loop panicked"),
        Err(_) => debug!(peer = %peer, "write loop did not finish in time"),
    }
    info!(peer = %peer, reason = %reason, "connection closed");
    Ok(established)
}

struct Limits {
    max_line: usize,
    max_decompressed: usize,
    ping_interval: Duration,
    ping_timeout: u64,
    registration_timeout: Duration,
    compression_level: u32,
}

async fn reader_loop<R>(
    server: &Arc<Server>,
    client: &Arc<crate::server::ClientHandle>,
    reader: R,
    limits: &Limits,
) -> std::io::Result<String>
where
    R: AsyncRead + Unpin + Send + 'static,
{
    // Tags may use their own budget beyond the line limit; `Message::parse`
    // keeps the message body inside `max_line`.
    let read_limit = limits
        .max_line
        .saturating_add(crate::protocol::message::MAX_CLIENT_TAG_BYTES);
    let mut inbound = Inbound::new(Box::new(reader), read_limit, limits.max_decompressed);
    let max_line = limits.max_line;

    loop {
        if client.closing.load(std::sync::atomic::Ordering::Relaxed) {
            return Ok("Closing link".to_owned());
        }

        let wait = if client.is_registered() {
            limits.ping_interval
        } else {
            limits.registration_timeout
        };

        match tokio::time::timeout(wait, inbound.next_line()).await {
            Ok(Ok(Some(line))) => {
                client.touch();
                if line.is_empty() {
                    continue;
                }
                server.dispatch(client, &line).await;
                if client
                    .compression
                    .load(std::sync::atomic::Ordering::Acquire)
                    && !inbound.is_compressed()
                {
                    inbound.enable_compression();
                }
                if client.closing.load(std::sync::atomic::Ordering::Relaxed) {
                    return Ok("Closing link".to_owned());
                }
            }
            Ok(Ok(None)) => return Ok("Connection closed".to_owned()),
            Ok(Err(error)) => {
                if error.kind() == ErrorKind::InvalidData {
                    // Protocol violation: tell the peer why before dropping.
                    client.send_raw(&format!("ERROR :Closing link: {}", error), max_line);
                    return Ok("Protocol violation".to_owned());
                }
                return Err(error);
            }
            Err(_elapsed) => {
                if !client.is_registered() {
                    client.send_raw("ERROR :Registration timed out", max_line);
                    return Ok("Registration timed out".to_owned());
                }
                if client.idle_seconds() >= limits.ping_timeout {
                    return Ok("Ping timeout".to_owned());
                }
                let token = format!("{}", client.started);
                if !client.send_raw(&format!("PING :{token}"), max_line) {
                    return Ok("Send queue closed".to_owned());
                }
            }
        }
    }
}

async fn writer_loop<W>(
    mut writer: W,
    mut receiver: mpsc::Receiver<Outbound>,
    level: u32,
) -> std::io::Result<()>
where
    W: AsyncWrite + Unpin,
{
    let mut compressor: Option<Compressor> = None;
    while let Some(item) = receiver.recv().await {
        match item {
            Outbound::Line(bytes) => {
                let payload = match &mut compressor {
                    Some(compressor) => compressor
                        .compress_frame(&bytes)
                        .map_err(compression_to_io)?,
                    None => bytes.to_vec(),
                };
                writer.write_all(&payload).await?;
            }
            Outbound::EnableCompression => {
                compressor = Some(Compressor::new(level));
            }
            Outbound::Close => break,
        }
    }
    writer.flush().await?;
    writer.shutdown().await?;
    Ok(())
}

fn compression_to_io(error: CompressionError) -> std::io::Error {
    std::io::Error::new(ErrorKind::InvalidData, error.to_string())
}

/// Inbound line reader supporting both plain and zlib-framed streams.
struct Inbound {
    reader: Box<dyn AsyncRead + Unpin + Send>,
    pending: Vec<u8>,
    decoder: Option<Decompressor>,
    max_line: usize,
    max_decompressed: usize,
}

impl Inbound {
    fn new(
        reader: Box<dyn AsyncRead + Unpin + Send>,
        max_line: usize,
        max_decompressed: usize,
    ) -> Self {
        Self {
            reader,
            pending: Vec::with_capacity(1024),
            decoder: None,
            max_line,
            max_decompressed,
        }
    }

    fn is_compressed(&self) -> bool {
        self.decoder.is_some()
    }

    fn enable_compression(&mut self) {
        // Bytes already buffered are plaintext and are drained first by
        // `next_line`, which checks `pending` before reading another frame.
        self.decoder = Some(Decompressor::new(self.max_decompressed));
    }

    async fn next_line(&mut self) -> std::io::Result<Option<String>> {
        loop {
            if let Some(position) = self.pending.iter().position(|byte| *byte == b'\n') {
                let remainder = self.pending.split_off(position + 1);
                let mut line = std::mem::replace(&mut self.pending, remainder);
                line.pop();
                if line.last() == Some(&b'\r') {
                    line.pop();
                }
                return Ok(Some(String::from_utf8_lossy(&line).into_owned()));
            }
            if self.pending.len() > self.max_line {
                return Err(std::io::Error::new(
                    ErrorKind::InvalidData,
                    format!("line exceeds {} bytes", self.max_line),
                ));
            }
            if self.decoder.is_some() {
                self.read_frame().await?;
            } else if !self.read_plain().await? {
                return Ok(None);
            }
        }
    }

    /// Read more plaintext bytes; `false` signals a clean EOF.
    async fn read_plain(&mut self) -> std::io::Result<bool> {
        let mut chunk = [0u8; 8192];
        let read = self.reader.read(&mut chunk).await?;
        if read == 0 {
            return Ok(false);
        }
        self.pending.extend_from_slice(&chunk[..read]);
        Ok(true)
    }

    async fn read_frame(&mut self) -> std::io::Result<()> {
        let mut header = [0u8; HEADER_LEN];
        self.reader.read_exact(&mut header).await?;
        let (declared, compressed) = parse_header(&header);
        // MARK: security: high: SEC-BOMB-001: frame sizes are checked before allocating.
        if declared > self.max_decompressed || compressed > MAX_FRAME {
            return Err(std::io::Error::new(
                ErrorKind::InvalidData,
                format!("frame header declares {declared}/{compressed} bytes"),
            ));
        }
        let mut payload = vec![0u8; compressed];
        self.reader.read_exact(&mut payload).await?;
        let decoder = self
            .decoder
            .as_mut()
            .ok_or_else(|| std::io::Error::other("decoder missing"))?;
        let frame = decoder
            .decompress_frame(&payload, declared)
            .map_err(compression_to_io)?;
        self.pending.extend_from_slice(&frame);
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::io::AsyncWriteExt;

    #[tokio::test]
    async fn reads_plain_lines_across_chunks() {
        let (mut client, server) = tokio::io::duplex(16);
        let writer = tokio::spawn(async move {
            client
                .write_all(b"PING :a\r\nPING :b\nPING :")
                .await
                .expect("write");
            client.write_all(b"c\r\n").await.expect("write");
        });
        let mut inbound = Inbound::new(Box::new(server), 512, 1 << 20);
        assert_eq!(
            inbound.next_line().await.expect("line"),
            Some("PING :a".to_owned())
        );
        assert_eq!(
            inbound.next_line().await.expect("line"),
            Some("PING :b".to_owned())
        );
        assert_eq!(
            inbound.next_line().await.expect("line"),
            Some("PING :c".to_owned())
        );
        writer.await.expect("writer");
    }

    #[tokio::test]
    async fn rejects_overlong_line() {
        let (mut client, server) = tokio::io::duplex(64);
        tokio::spawn(async move {
            let _ = client.write_all(&[b'x'; 128]).await;
            let _ = client.write_all(b"\n").await;
        });
        let mut inbound = Inbound::new(Box::new(server), 32, 1 << 20);
        let error = inbound.next_line().await.expect_err("must reject");
        assert_eq!(error.kind(), ErrorKind::InvalidData);
    }

    #[tokio::test]
    async fn reads_compressed_frames() {
        let (mut client, server) = tokio::io::duplex(4096);
        tokio::spawn(async move {
            let mut compressor = Compressor::new(6);
            for line in [
                b"PRIVMSG #a :one\r\n".as_slice(),
                b"PRIVMSG #a :two\r\n".as_slice(),
            ] {
                let frame = compressor.compress_frame(line).expect("compress");
                client.write_all(&frame).await.expect("write");
            }
        });
        let mut inbound = Inbound::new(Box::new(server), 512, 1 << 20);
        inbound.enable_compression();
        assert_eq!(
            inbound.next_line().await.expect("line"),
            Some("PRIVMSG #a :one".to_owned())
        );
        assert_eq!(
            inbound.next_line().await.expect("line"),
            Some("PRIVMSG #a :two".to_owned())
        );
    }
}
