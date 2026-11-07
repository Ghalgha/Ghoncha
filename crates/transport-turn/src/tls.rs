//! Nonblocking Rustls client-side TLS record engine.
//!
//! The caller owns the TCP socket and drives readiness. This module never
//! performs socket I/O, waits for a handshake, or calls `complete_io`.
//! Plaintext is exposed only after Rustls has authenticated received records.

extern crate std;

use std::io::{self, Cursor, Read, Write};
use std::sync::Arc;

use rustls::pki_types::ServerName;
use rustls::{ClientConfig, ClientConnection};

use crate::{TurnStreamIoError, TurnStreamSocket};

/// Maximum ciphertext accepted by one readiness callback.
pub const MAX_TLS_CIPHERTEXT_INPUT: usize = 16_384;
/// Maximum plaintext accepted in one write operation (one TLS record).
pub const MAX_TLS_PLAINTEXT_WRITE: usize = 16_384;
/// Rustls plaintext buffering limit for this connection.
pub const MAX_TLS_BUFFERED_PLAINTEXT: usize = 64 * 1024;
/// Hard bound for one batch of pending TLS records (including handshake flights).
pub const MAX_TLS_PENDING_CIPHERTEXT: usize = 256 * 1024;

/// TLS engine construction or I/O error.
#[derive(Debug)]
pub enum TlsEngineError {
    EarlyDataEnabled,
    EmptyCiphertext,
    CiphertextInputTooLarge { maximum: usize, actual: usize },
    PlaintextInputTooLarge { maximum: usize, actual: usize },
    NoCiphertextProgress,
    HandshakeIncomplete,
    PeerClosed,
    OutputBufferLimitReached,
    OutputFailed,
    Rustls(rustls::Error),
    Io(io::Error),
}

impl From<rustls::Error> for TlsEngineError {
    fn from(error: rustls::Error) -> Self {
        Self::Rustls(error)
    }
}

impl From<io::Error> for TlsEngineError {
    fn from(error: io::Error) -> Self {
        Self::Io(error)
    }
}

/// Result of feeding one bounded ciphertext chunk into Rustls.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct TlsReadProgress {
    /// Number of input bytes consumed by Rustls. Retain any remaining suffix.
    pub ciphertext_consumed: usize,
    pub plaintext_available: usize,
    pub ciphertext_pending: usize,
    pub peer_closed: bool,
}

/// Sans-I/O TLS client. The owner must drain ciphertext and plaintext through
/// the explicit methods below as the underlying socket becomes ready.
pub struct TlsClientEngine {
    connection: ClientConnection,
    peer_closed: bool,
    pending_ciphertext: std::vec::Vec<u8>,
    pending_offset: usize,
    output_failed: bool,
}

impl TlsClientEngine {
    /// Creates a TLS client with caller-supplied, fully verified trust policy.
    ///
    /// The supplied configuration must use normal certificate and hostname
    /// verification. Early data is rejected because TURN control and tunnel
    /// records must not be replayable as TLS 1.3 0-RTT data.
    pub fn new(
        config: Arc<ClientConfig>,
        server_name: ServerName<'static>,
    ) -> Result<Self, TlsEngineError> {
        if config.enable_early_data {
            return Err(TlsEngineError::EarlyDataEnabled);
        }

        let mut connection = ClientConnection::new(config, server_name)?;
        connection.set_buffer_limit(Some(MAX_TLS_BUFFERED_PLAINTEXT));

        Ok(Self {
            connection,
            peer_closed: false,
            pending_ciphertext: std::vec::Vec::new(),
            pending_offset: 0,
            output_failed: false,
        })
    }

    /// True until both sides have completed the TLS handshake.
    pub fn is_handshaking(&self) -> bool {
        self.connection.is_handshaking()
    }

    /// Whether the reactor should wait for socket readability.
    pub fn wants_read(&self) -> bool {
        self.connection.wants_read()
    }

    /// Whether TLS ciphertext remains to be written to the TCP socket.
    pub fn wants_write(&self) -> bool {
        self.connection.wants_write() || self.pending_offset < self.pending_ciphertext.len()
    }

    /// Application data is safe to send only after the handshake is complete
    /// and all final handshake bytes have been flushed to the socket.
    pub fn application_data_ready(&self) -> bool {
        !self.output_failed
            && self.pending_offset == self.pending_ciphertext.len()
            && !self.connection.is_handshaking()
            && !self.connection.wants_write()
    }

    pub const fn peer_closed(&self) -> bool {
        self.peer_closed
    }

    /// Feeds ciphertext obtained from the socket. The caller retains any
    /// unconsumed suffix and must call this again before reusing that input.
    pub fn feed_ciphertext(
        &mut self,
        ciphertext: &[u8],
    ) -> Result<TlsReadProgress, TlsEngineError> {
        if self.output_failed {
            return Err(TlsEngineError::OutputFailed);
        }
        if ciphertext.is_empty() {
            return Err(TlsEngineError::EmptyCiphertext);
        }
        if ciphertext.len() > MAX_TLS_CIPHERTEXT_INPUT {
            return Err(TlsEngineError::CiphertextInputTooLarge {
                maximum: MAX_TLS_CIPHERTEXT_INPUT,
                actual: ciphertext.len(),
            });
        }

        let mut input = Cursor::new(ciphertext);
        let consumed = self.connection.read_tls(&mut input)?;
        if consumed == 0 {
            return Err(TlsEngineError::NoCiphertextProgress);
        }

        let state = self.connection.process_new_packets()?;
        self.peer_closed |= state.peer_has_closed();

        Ok(TlsReadProgress {
            ciphertext_consumed: consumed,
            plaintext_available: state.plaintext_bytes_to_read(),
            ciphertext_pending: state.tls_bytes_to_write().saturating_add(
                self.pending_ciphertext
                    .len()
                    .saturating_sub(self.pending_offset),
            ),
            peer_closed: self.peer_closed,
        })
    }

    /// Copies authenticated plaintext into caller-owned storage.
    ///
    /// A zero result means no plaintext is currently available. It does not
    /// mean that the underlying TCP stream reached EOF.
    pub fn read_plaintext(&mut self, output: &mut [u8]) -> Result<usize, TlsEngineError> {
        match self.connection.reader().read(output) {
            Ok(read) => Ok(read),
            Err(error) if error.kind() == io::ErrorKind::WouldBlock => Ok(0),
            Err(error) => Err(TlsEngineError::Io(error)),
        }
    }

    /// Encrypts at most one bounded plaintext chunk. The caller must first
    /// drain any pending handshake or application ciphertext; this prevents
    /// unbounded plaintext accumulation inside the TLS connection.
    pub fn write_plaintext(&mut self, plaintext: &[u8]) -> Result<usize, TlsEngineError> {
        if !self.application_data_ready() {
            return Err(TlsEngineError::HandshakeIncomplete);
        }
        if self.output_failed {
            return Err(TlsEngineError::OutputFailed);
        }
        if self.peer_closed {
            return Err(TlsEngineError::PeerClosed);
        }
        if plaintext.len() > MAX_TLS_PLAINTEXT_WRITE {
            return Err(TlsEngineError::PlaintextInputTooLarge {
                maximum: MAX_TLS_PLAINTEXT_WRITE,
                actual: plaintext.len(),
            });
        }

        match self.connection.writer().write(plaintext) {
            Ok(written) => Ok(written),
            Err(error) if error.kind() == io::ErrorKind::WouldBlock => Ok(0),
            Err(error) => Err(TlsEngineError::Io(error)),
        }
    }

    /// Stages pending TLS records into a bounded buffer, then copies a
    /// caller-sized prefix. This avoids partially writing a TLS record into a
    /// too-small caller buffer and accidentally replaying its prefix.
    pub fn drain_ciphertext(&mut self, output: &mut [u8]) -> Result<usize, TlsEngineError> {
        if self.output_failed {
            return Err(TlsEngineError::OutputFailed);
        }
        if output.is_empty() {
            return Ok(0);
        }

        if self.pending_offset == self.pending_ciphertext.len() {
            self.pending_ciphertext.clear();
            self.pending_offset = 0;
        }

        if self.pending_ciphertext.is_empty() && self.connection.wants_write() {
            let mut sink =
                BoundedVecWriter::new(&mut self.pending_ciphertext, MAX_TLS_PENDING_CIPHERTEXT);
            if self.connection.write_tls(&mut sink).is_err() {
                self.output_failed = true;
                self.pending_ciphertext.clear();
                return Err(TlsEngineError::OutputBufferLimitReached);
            }
            if self.pending_ciphertext.is_empty() && self.connection.wants_write() {
                self.output_failed = true;
                return Err(TlsEngineError::OutputFailed);
            }
        }

        let remaining = self
            .pending_ciphertext
            .len()
            .saturating_sub(self.pending_offset);
        let count = remaining.min(output.len());
        output[..count].copy_from_slice(
            &self.pending_ciphertext[self.pending_offset..self.pending_offset + count],
        );
        self.pending_offset += count;
        Ok(count)
    }
}

struct BoundedVecWriter<'a> {
    output: &'a mut std::vec::Vec<u8>,
    maximum: usize,
}

impl<'a> BoundedVecWriter<'a> {
    fn new(output: &'a mut std::vec::Vec<u8>, maximum: usize) -> Self {
        Self { output, maximum }
    }
}

impl Write for BoundedVecWriter<'_> {
    fn write(&mut self, input: &[u8]) -> io::Result<usize> {
        let next_len = self.output.len().saturating_add(input.len());
        if next_len > self.maximum {
            return Err(io::Error::new(
                io::ErrorKind::WriteZero,
                "TLS ciphertext batch exceeds configured bound",
            ));
        }
        self.output.extend_from_slice(input);
        Ok(input.len())
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

/// A nonblocking TLS stream adapter for an already-connected underlay socket.
///
/// It implements the same byte-stream contract as the raw TURN TCP socket, so
/// it can be supplied directly to `TurnTcpDriver`. Socket ownership remains
/// with this adapter; Android must protect and bind the raw socket before
/// constructing it. The caller drives both read and write readiness.
pub struct TlsStreamSocket<S> {
    socket: S,
    tls: TlsClientEngine,
    ciphertext_input: [u8; MAX_TLS_CIPHERTEXT_INPUT],
    input_len: usize,
    input_offset: usize,
    ciphertext_output: [u8; MAX_TLS_CIPHERTEXT_INPUT],
    output_len: usize,
    output_offset: usize,
    retired: bool,
}

impl<S: TurnStreamSocket> TlsStreamSocket<S> {
    pub fn new(
        socket: S,
        config: Arc<ClientConfig>,
        server_name: ServerName<'static>,
    ) -> Result<Self, TlsEngineError> {
        let tls = TlsClientEngine::new(config, server_name)?;
        Ok(Self {
            socket,
            tls,
            ciphertext_input: [0; MAX_TLS_CIPHERTEXT_INPUT],
            input_len: 0,
            input_offset: 0,
            ciphertext_output: [0; MAX_TLS_CIPHERTEXT_INPUT],
            output_len: 0,
            output_offset: 0,
            retired: false,
        })
    }

    pub fn tls(&self) -> &TlsClientEngine {
        &self.tls
    }

    pub fn socket(&self) -> &S {
        &self.socket
    }

    pub fn into_inner(self) -> S {
        self.socket
    }

    /// Flushes one bounded ciphertext chunk on a writable socket.
    /// Returns false while more output or socket writability is required.
    pub fn flush_pending_ciphertext(&mut self) -> Result<bool, TurnStreamIoError> {
        self.flush_ciphertext_once()
    }

    fn flush_ciphertext_once(&mut self) -> Result<bool, TurnStreamIoError> {
        if self.retired {
            return Err(TurnStreamIoError::Failed);
        }

        if self.output_offset == self.output_len {
            self.output_offset = 0;
            self.output_len = 0;
            match self.tls.drain_ciphertext(&mut self.ciphertext_output) {
                Ok(written) => self.output_len = written,
                Err(_) => {
                    self.retired = true;
                    return Err(TurnStreamIoError::Failed);
                }
            }
        }

        if self.output_len == 0 {
            return Ok(!self.tls.wants_write());
        }

        let pending = &self.ciphertext_output[self.output_offset..self.output_len];
        let offered = pending.len();
        match self.socket.write(pending) {
            Ok(0) => {
                self.retired = true;
                Err(TurnStreamIoError::Failed)
            }
            Ok(written) if written > offered => {
                self.retired = true;
                Err(TurnStreamIoError::Failed)
            }
            Ok(written) => {
                self.output_offset += written;
                if self.output_offset == self.output_len {
                    self.output_offset = 0;
                    self.output_len = 0;
                }
                Ok(self.output_len == 0 && !self.tls.wants_write())
            }
            Err(TurnStreamIoError::WouldBlock) => Ok(false),
            Err(TurnStreamIoError::Failed) => {
                self.retired = true;
                Err(TurnStreamIoError::Failed)
            }
        }
    }

    fn read_decrypted(&mut self, output: &mut [u8]) -> Result<usize, TurnStreamIoError> {
        match self.tls.read_plaintext(output) {
            Ok(read) => Ok(read),
            Err(_) => {
                self.retired = true;
                Err(TurnStreamIoError::Failed)
            }
        }
    }
}

impl<S: TurnStreamSocket> TurnStreamSocket for TlsStreamSocket<S> {
    fn local_addr(&self) -> core::net::SocketAddr {
        self.socket.local_addr()
    }

    fn peer_addr(&self) -> core::net::SocketAddr {
        self.socket.peer_addr()
    }

    fn read(&mut self, buffer: &mut [u8]) -> Result<usize, TurnStreamIoError> {
        if self.retired {
            return Err(TurnStreamIoError::Failed);
        }
        if buffer.is_empty() {
            return Ok(0);
        }
        if !self.flush_ciphertext_once()? {
            return Err(TurnStreamIoError::WouldBlock);
        }

        let plaintext = self.read_decrypted(buffer)?;
        if plaintext > 0 {
            return Ok(plaintext);
        }
        if self.tls.peer_closed() {
            return Ok(0);
        }

        if self.input_offset == self.input_len {
            self.input_offset = 0;
            self.input_len = match self.socket.read(&mut self.ciphertext_input) {
                // A raw TCP EOF without an authenticated TLS close_notify is
                // truncation, not a clean end of the TLS stream.
                Ok(0) => {
                    self.retired = true;
                    return Err(TurnStreamIoError::Failed);
                }
                Ok(read) if read <= self.ciphertext_input.len() => read,
                Ok(_) => {
                    self.retired = true;
                    return Err(TurnStreamIoError::Failed);
                }
                Err(error) => return Err(error),
            };
        }

        let progress = match self
            .tls
            .feed_ciphertext(&self.ciphertext_input[self.input_offset..self.input_len])
        {
            Ok(progress) => progress,
            Err(_) => {
                self.retired = true;
                return Err(TurnStreamIoError::Failed);
            }
        };
        self.input_offset += progress.ciphertext_consumed;
        if self.input_offset == self.input_len {
            self.input_offset = 0;
            self.input_len = 0;
        }

        let plaintext = self.read_decrypted(buffer)?;
        if plaintext > 0 {
            return Ok(plaintext);
        }
        if self.tls.peer_closed() {
            return Ok(0);
        }
        if !self.flush_ciphertext_once()? {
            return Err(TurnStreamIoError::WouldBlock);
        }
        Err(TurnStreamIoError::WouldBlock)
    }

    fn write(&mut self, bytes: &[u8]) -> Result<usize, TurnStreamIoError> {
        if self.retired {
            return Err(TurnStreamIoError::Failed);
        }
        if bytes.is_empty() {
            return Ok(0);
        }
        if !self.flush_ciphertext_once()? {
            return Err(TurnStreamIoError::WouldBlock);
        }
        if !self.tls.application_data_ready() {
            return Err(TurnStreamIoError::WouldBlock);
        }

        let accepted = match self.tls.write_plaintext(bytes) {
            Ok(accepted) => accepted,
            Err(_) => {
                self.retired = true;
                return Err(TurnStreamIoError::Failed);
            }
        };
        if accepted == 0 {
            return Err(TurnStreamIoError::WouldBlock);
        }

        // Once Rustls accepts plaintext, the TURN queue may advance. Any
        // unwritten ciphertext remains in this adapter's bounded output buffer.
        self.flush_ciphertext_once()?;
        Ok(accepted)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use rustls::RootCertStore;
    // Test-only P-256 CA (valid to 2046) and example.com server identity (valid to 2036).
    const TEST_CA_CERT_DER: &[u8] = &[
        0x30, 0x82, 0x01, 0x9d, 0x30, 0x82, 0x01, 0x43, 0xa0, 0x03, 0x02, 0x01, 0x02, 0x02, 0x14,
        0x69, 0x9d, 0xc9, 0x98, 0xda, 0x15, 0x40, 0x2e, 0xcd, 0x48, 0x97, 0x8d, 0x6e, 0xa9, 0xc1,
        0x08, 0x85, 0x0e, 0x0b, 0x26, 0x30, 0x0a, 0x06, 0x08, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x04,
        0x03, 0x02, 0x30, 0x1c, 0x31, 0x1a, 0x30, 0x18, 0x06, 0x03, 0x55, 0x04, 0x03, 0x0c, 0x11,
        0x47, 0x48, 0x4f, 0x4e, 0x43, 0x48, 0x41, 0x20, 0x54, 0x65, 0x73, 0x74, 0x20, 0x52, 0x6f,
        0x6f, 0x74, 0x30, 0x1e, 0x17, 0x0d, 0x32, 0x36, 0x31, 0x31, 0x30, 0x37, 0x30, 0x30, 0x35,
        0x32, 0x30, 0x37, 0x5a, 0x17, 0x0d, 0x34, 0x36, 0x31, 0x31, 0x30, 0x32, 0x30, 0x30, 0x35,
        0x32, 0x30, 0x37, 0x5a, 0x30, 0x1c, 0x31, 0x1a, 0x30, 0x18, 0x06, 0x03, 0x55, 0x04, 0x03,
        0x0c, 0x11, 0x47, 0x48, 0x4f, 0x4e, 0x43, 0x48, 0x41, 0x20, 0x54, 0x65, 0x73, 0x74, 0x20,
        0x52, 0x6f, 0x6f, 0x74, 0x30, 0x59, 0x30, 0x13, 0x06, 0x07, 0x2a, 0x86, 0x48, 0xce, 0x3d,
        0x02, 0x01, 0x06, 0x08, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x03, 0x01, 0x07, 0x03, 0x42, 0x00,
        0x04, 0xeb, 0xd3, 0x9e, 0xb4, 0x2e, 0x03, 0x5f, 0x98, 0xe5, 0xa4, 0x86, 0x7c, 0x0b, 0x55,
        0x6d, 0x53, 0x2c, 0xce, 0x4b, 0xe7, 0xd9, 0x07, 0x51, 0x74, 0x82, 0x15, 0x4d, 0x4d, 0xd0,
        0x84, 0x22, 0x11, 0x25, 0xd5, 0x6f, 0x65, 0x0b, 0x01, 0x1a, 0x99, 0xbf, 0xb5, 0x39, 0xc6,
        0x64, 0x96, 0xdd, 0xd4, 0x96, 0x28, 0x39, 0xa8, 0xc7, 0x55, 0xeb, 0x15, 0xb9, 0x33, 0x6e,
        0xcc, 0x01, 0x46, 0x35, 0x28, 0xa3, 0x63, 0x30, 0x61, 0x30, 0x1d, 0x06, 0x03, 0x55, 0x1d,
        0x0e, 0x04, 0x16, 0x04, 0x14, 0x6b, 0xc9, 0xe8, 0xd3, 0xf7, 0x7a, 0xd3, 0xd7, 0x54, 0x9f,
        0x76, 0x11, 0x8d, 0x98, 0x55, 0xe3, 0x02, 0xe2, 0xd9, 0x10, 0x30, 0x1f, 0x06, 0x03, 0x55,
        0x1d, 0x23, 0x04, 0x18, 0x30, 0x16, 0x80, 0x14, 0x6b, 0xc9, 0xe8, 0xd3, 0xf7, 0x7a, 0xd3,
        0xd7, 0x54, 0x9f, 0x76, 0x11, 0x8d, 0x98, 0x55, 0xe3, 0x02, 0xe2, 0xd9, 0x10, 0x30, 0x0f,
        0x06, 0x03, 0x55, 0x1d, 0x13, 0x01, 0x01, 0xff, 0x04, 0x05, 0x30, 0x03, 0x01, 0x01, 0xff,
        0x30, 0x0e, 0x06, 0x03, 0x55, 0x1d, 0x0f, 0x01, 0x01, 0xff, 0x04, 0x04, 0x03, 0x02, 0x01,
        0x06, 0x30, 0x0a, 0x06, 0x08, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x04, 0x03, 0x02, 0x03, 0x48,
        0x00, 0x30, 0x45, 0x02, 0x21, 0x00, 0xc3, 0xf3, 0xd0, 0x80, 0x4e, 0x4b, 0x53, 0x9a, 0x2a,
        0xe2, 0xed, 0x4e, 0xa6, 0x9d, 0x77, 0xb2, 0x89, 0xdb, 0xf5, 0x75, 0x5a, 0x38, 0x2b, 0x61,
        0x86, 0x99, 0xbc, 0xd9, 0xa3, 0x57, 0x64, 0x2e, 0x02, 0x20, 0x67, 0x48, 0xe8, 0xc8, 0x82,
        0x19, 0x1a, 0xeb, 0xc0, 0x5a, 0xb2, 0x41, 0xf8, 0xfb, 0x34, 0x23, 0x7d, 0xfe, 0xc2, 0x5f,
        0x30, 0x23, 0xe2, 0x33, 0x61, 0x22, 0x98, 0x5a, 0x94, 0x59, 0x01, 0x6a,
    ];

    const TEST_SERVER_CERT_DER: &[u8] = &[
        0x30, 0x82, 0x01, 0xc4, 0x30, 0x82, 0x01, 0x69, 0xa0, 0x03, 0x02, 0x01, 0x02, 0x02, 0x14,
        0x50, 0x18, 0x52, 0xc2, 0x7f, 0x57, 0xed, 0xc6, 0x9c, 0x99, 0xd5, 0xcc, 0xe0, 0x60, 0x6e,
        0xa7, 0xef, 0xe8, 0xd6, 0x0b, 0x30, 0x0a, 0x06, 0x08, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x04,
        0x03, 0x02, 0x30, 0x1c, 0x31, 0x1a, 0x30, 0x18, 0x06, 0x03, 0x55, 0x04, 0x03, 0x0c, 0x11,
        0x47, 0x48, 0x4f, 0x4e, 0x43, 0x48, 0x41, 0x20, 0x54, 0x65, 0x73, 0x74, 0x20, 0x52, 0x6f,
        0x6f, 0x74, 0x30, 0x1e, 0x17, 0x0d, 0x32, 0x36, 0x31, 0x31, 0x30, 0x37, 0x30, 0x30, 0x35,
        0x32, 0x30, 0x37, 0x5a, 0x17, 0x0d, 0x33, 0x36, 0x31, 0x31, 0x30, 0x34, 0x30, 0x30, 0x35,
        0x32, 0x30, 0x37, 0x5a, 0x30, 0x16, 0x31, 0x14, 0x30, 0x12, 0x06, 0x03, 0x55, 0x04, 0x03,
        0x0c, 0x0b, 0x65, 0x78, 0x61, 0x6d, 0x70, 0x6c, 0x65, 0x2e, 0x63, 0x6f, 0x6d, 0x30, 0x59,
        0x30, 0x13, 0x06, 0x07, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x02, 0x01, 0x06, 0x08, 0x2a, 0x86,
        0x48, 0xce, 0x3d, 0x03, 0x01, 0x07, 0x03, 0x42, 0x00, 0x04, 0x0f, 0xef, 0xfa, 0x4b, 0x9e,
        0x03, 0xfc, 0xbf, 0x47, 0x23, 0xaa, 0x12, 0xa6, 0x89, 0x49, 0x7c, 0xbc, 0x96, 0x23, 0x54,
        0xf7, 0xc7, 0x0a, 0x4e, 0xc1, 0x6b, 0x66, 0x61, 0x5a, 0xdd, 0xb7, 0x9f, 0x4e, 0xba, 0x76,
        0xeb, 0xb6, 0x7e, 0x1d, 0x54, 0xc4, 0x44, 0xe0, 0x40, 0xb5, 0x50, 0xbd, 0xc2, 0xe4, 0x0a,
        0x5b, 0x34, 0x95, 0xb7, 0xc0, 0x1d, 0x2b, 0x59, 0x2a, 0x70, 0x1b, 0x6f, 0xd5, 0x04, 0xa3,
        0x81, 0x8e, 0x30, 0x81, 0x8b, 0x30, 0x0c, 0x06, 0x03, 0x55, 0x1d, 0x13, 0x01, 0x01, 0xff,
        0x04, 0x02, 0x30, 0x00, 0x30, 0x0e, 0x06, 0x03, 0x55, 0x1d, 0x0f, 0x01, 0x01, 0xff, 0x04,
        0x04, 0x03, 0x02, 0x07, 0x80, 0x30, 0x13, 0x06, 0x03, 0x55, 0x1d, 0x25, 0x04, 0x0c, 0x30,
        0x0a, 0x06, 0x08, 0x2b, 0x06, 0x01, 0x05, 0x05, 0x07, 0x03, 0x01, 0x30, 0x16, 0x06, 0x03,
        0x55, 0x1d, 0x11, 0x04, 0x0f, 0x30, 0x0d, 0x82, 0x0b, 0x65, 0x78, 0x61, 0x6d, 0x70, 0x6c,
        0x65, 0x2e, 0x63, 0x6f, 0x6d, 0x30, 0x1d, 0x06, 0x03, 0x55, 0x1d, 0x0e, 0x04, 0x16, 0x04,
        0x14, 0x05, 0xdd, 0xf4, 0xd7, 0xfe, 0x0f, 0x08, 0x98, 0xf4, 0x87, 0x42, 0xf6, 0x68, 0x1b,
        0x58, 0x0b, 0xff, 0x01, 0x86, 0xf0, 0x30, 0x1f, 0x06, 0x03, 0x55, 0x1d, 0x23, 0x04, 0x18,
        0x30, 0x16, 0x80, 0x14, 0x6b, 0xc9, 0xe8, 0xd3, 0xf7, 0x7a, 0xd3, 0xd7, 0x54, 0x9f, 0x76,
        0x11, 0x8d, 0x98, 0x55, 0xe3, 0x02, 0xe2, 0xd9, 0x10, 0x30, 0x0a, 0x06, 0x08, 0x2a, 0x86,
        0x48, 0xce, 0x3d, 0x04, 0x03, 0x02, 0x03, 0x49, 0x00, 0x30, 0x46, 0x02, 0x21, 0x00, 0xea,
        0x44, 0xbb, 0x8e, 0x3b, 0x56, 0x79, 0x65, 0x53, 0x6e, 0xa0, 0x05, 0xfa, 0x44, 0xd9, 0xed,
        0x1c, 0x7a, 0xa0, 0xbb, 0x52, 0xf5, 0xac, 0x74, 0x86, 0x7e, 0x6c, 0xd4, 0xef, 0x91, 0x2d,
        0xf4, 0x02, 0x21, 0x00, 0x93, 0xe6, 0xd9, 0xe0, 0x6e, 0x16, 0x84, 0xaf, 0xb3, 0x35, 0x16,
        0x6b, 0xd0, 0x27, 0xc3, 0x1c, 0xcf, 0x96, 0x8b, 0xdd, 0xbe, 0x2e, 0x07, 0x95, 0x6a, 0x80,
        0x15, 0x0a, 0x21, 0x20, 0x42, 0x71,
    ];

    const TEST_SERVER_KEY_DER: &[u8] = &[
        0x30, 0x81, 0x87, 0x02, 0x01, 0x00, 0x30, 0x13, 0x06, 0x07, 0x2a, 0x86, 0x48, 0xce, 0x3d,
        0x02, 0x01, 0x06, 0x08, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x03, 0x01, 0x07, 0x04, 0x6d, 0x30,
        0x6b, 0x02, 0x01, 0x01, 0x04, 0x20, 0x33, 0x7e, 0x64, 0xd1, 0x39, 0xcc, 0x45, 0x17, 0xd9,
        0xd3, 0xeb, 0x0c, 0x67, 0xe9, 0x15, 0x6a, 0xe3, 0xc2, 0xd9, 0xf0, 0x32, 0x54, 0xec, 0x22,
        0xb4, 0xfa, 0x48, 0x01, 0x23, 0xd1, 0x5f, 0x37, 0xa1, 0x44, 0x03, 0x42, 0x00, 0x04, 0x0f,
        0xef, 0xfa, 0x4b, 0x9e, 0x03, 0xfc, 0xbf, 0x47, 0x23, 0xaa, 0x12, 0xa6, 0x89, 0x49, 0x7c,
        0xbc, 0x96, 0x23, 0x54, 0xf7, 0xc7, 0x0a, 0x4e, 0xc1, 0x6b, 0x66, 0x61, 0x5a, 0xdd, 0xb7,
        0x9f, 0x4e, 0xba, 0x76, 0xeb, 0xb6, 0x7e, 0x1d, 0x54, 0xc4, 0x44, 0xe0, 0x40, 0xb5, 0x50,
        0xbd, 0xc2, 0xe4, 0x0a, 0x5b, 0x34, 0x95, 0xb7, 0xc0, 0x1d, 0x2b, 0x59, 0x2a, 0x70, 0x1b,
        0x6f, 0xd5, 0x04,
    ];

    fn test_server_certificate() -> rustls::pki_types::CertificateDer<'static> {
        rustls::pki_types::CertificateDer::from(TEST_SERVER_CERT_DER.to_vec())
    }

    fn test_root_certificate() -> rustls::pki_types::CertificateDer<'static> {
        rustls::pki_types::CertificateDer::from(TEST_CA_CERT_DER.to_vec())
    }

    fn test_server_config() -> Arc<rustls::ServerConfig> {
        let key = rustls::pki_types::PrivateKeyDer::Pkcs8(
            rustls::pki_types::PrivatePkcs8KeyDer::from(TEST_SERVER_KEY_DER.to_vec()),
        );
        Arc::new(
            rustls::ServerConfig::builder()
                .with_no_client_auth()
                .with_single_cert(std::vec![test_server_certificate()], key)
                .unwrap(),
        )
    }

    fn trusted_test_client_config() -> Arc<ClientConfig> {
        let mut roots = RootCertStore::empty();
        roots.add(test_root_certificate()).unwrap();
        Arc::new(
            ClientConfig::builder()
                .with_root_certificates(roots)
                .with_no_client_auth(),
        )
    }

    fn pump_client_to_server(
        client: &mut TlsClientEngine,
        server: &mut rustls::ServerConnection,
    ) -> bool {
        if !client.wants_write() {
            return false;
        }
        let mut output = [0_u8; 4096];
        let written = client.drain_ciphertext(&mut output).unwrap();
        if written == 0 {
            return false;
        }
        let mut input = std::io::Cursor::new(&output[..written]);
        assert_eq!(server.read_tls(&mut input).unwrap(), written);
        server.process_new_packets().unwrap();
        true
    }

    fn pump_server_to_client(
        server: &mut rustls::ServerConnection,
        client: &mut TlsClientEngine,
    ) -> bool {
        if !server.wants_write() {
            return false;
        }
        let mut output = std::vec::Vec::new();
        let written = server.write_tls(&mut output).unwrap();
        if written == 0 {
            return false;
        }
        for chunk in output.chunks(MAX_TLS_CIPHERTEXT_INPUT) {
            client.feed_ciphertext(chunk).unwrap();
        }
        true
    }

    fn server_initial_flight(
        client: &mut TlsClientEngine,
        server: &mut rustls::ServerConnection,
    ) -> std::vec::Vec<u8> {
        let mut client_hello = [0_u8; 4096];
        let hello_len = client.drain_ciphertext(&mut client_hello).unwrap();
        assert!(hello_len > 0);
        let mut input = std::io::Cursor::new(&client_hello[..hello_len]);
        assert_eq!(server.read_tls(&mut input).unwrap(), hello_len);
        server.process_new_packets().unwrap();

        let mut server_flight = std::vec::Vec::new();
        server.write_tls(&mut server_flight).unwrap();
        assert!(!server_flight.is_empty());
        server_flight
    }

    #[test]
    fn untrusted_tls_certificate_authority_is_rejected() {
        let mut client = TlsClientEngine::new(
            client_config(),
            ServerName::try_from("example.com").unwrap(),
        )
        .unwrap();
        let mut server = rustls::ServerConnection::new(test_server_config()).unwrap();
        let server_flight = server_initial_flight(&mut client, &mut server);

        assert!(matches!(
            client.feed_ciphertext(&server_flight),
            Err(TlsEngineError::Rustls(_))
        ));
        assert!(!client.application_data_ready());
    }

    #[test]
    fn tls_server_name_mismatch_is_rejected() {
        let mut client = TlsClientEngine::new(
            trusted_test_client_config(),
            ServerName::try_from("wrong.example.com").unwrap(),
        )
        .unwrap();
        let mut server = rustls::ServerConnection::new(test_server_config()).unwrap();
        let server_flight = server_initial_flight(&mut client, &mut server);

        assert!(matches!(
            client.feed_ciphertext(&server_flight),
            Err(TlsEngineError::Rustls(_))
        ));
        assert!(!client.application_data_ready());
    }

    #[test]
    fn verified_tls_handshake_carries_turn_stream_bytes_both_directions() {
        use std::io::{Read, Write};

        let mut client = TlsClientEngine::new(
            trusted_test_client_config(),
            ServerName::try_from("example.com").unwrap(),
        )
        .unwrap();
        let mut server = rustls::ServerConnection::new(test_server_config()).unwrap();

        for _ in 0..16 {
            let client_progress = pump_client_to_server(&mut client, &mut server);
            let server_progress = pump_server_to_client(&mut server, &mut client);
            if !client.is_handshaking()
                && !server.is_handshaking()
                && !client.wants_write()
                && !server.wants_write()
            {
                break;
            }
            assert!(client_progress || server_progress, "TLS handshake stalled");
        }

        assert!(!client.is_handshaking());
        assert!(!server.is_handshaking());
        assert!(client.application_data_ready());

        let request = b"TURN Allocate";
        assert_eq!(client.write_plaintext(request).unwrap(), request.len());
        let mut encrypted = [0_u8; 4096];
        let encrypted_len = client.drain_ciphertext(&mut encrypted).unwrap();
        assert!(encrypted_len > 0);
        let mut cursor = std::io::Cursor::new(&encrypted[..encrypted_len]);
        assert_eq!(server.read_tls(&mut cursor).unwrap(), encrypted_len);
        server.process_new_packets().unwrap();

        let mut received = [0_u8; 64];
        let received_len = server.reader().read(&mut received).unwrap();
        assert_eq!(&received[..received_len], request);

        let response = b"TURN Allocate Success";
        assert_eq!(server.writer().write(response).unwrap(), response.len());
        let mut response_ciphertext = std::vec::Vec::new();
        server.write_tls(&mut response_ciphertext).unwrap();
        for chunk in response_ciphertext.chunks(MAX_TLS_CIPHERTEXT_INPUT) {
            client.feed_ciphertext(chunk).unwrap();
        }

        let mut response_plaintext = [0_u8; 64];
        let response_len = client.read_plaintext(&mut response_plaintext).unwrap();
        assert_eq!(&response_plaintext[..response_len], response);
    }

    #[test]
    fn authenticated_tls_close_notify_is_reported_as_clean_eof() {
        let mut client = TlsClientEngine::new(
            trusted_test_client_config(),
            ServerName::try_from("example.com").unwrap(),
        )
        .unwrap();
        let mut server = rustls::ServerConnection::new(test_server_config()).unwrap();

        for _ in 0..16 {
            let client_progress = pump_client_to_server(&mut client, &mut server);
            let server_progress = pump_server_to_client(&mut server, &mut client);
            if !client.is_handshaking()
                && !server.is_handshaking()
                && !client.wants_write()
                && !server.wants_write()
            {
                break;
            }
            assert!(client_progress || server_progress, "TLS handshake stalled");
        }
        assert!(client.application_data_ready());

        server.send_close_notify();
        let mut close_notify = std::vec::Vec::new();
        server.write_tls(&mut close_notify).unwrap();
        assert!(!close_notify.is_empty());

        let progress = client.feed_ciphertext(&close_notify).unwrap();
        assert!(progress.peer_closed);
        assert!(client.peer_closed());

        let mut plaintext = [0_u8; 64];
        assert_eq!(client.read_plaintext(&mut plaintext).unwrap(), 0);
        assert!(matches!(
            client.write_plaintext(b"TURN Allocate"),
            Err(TlsEngineError::PeerClosed)
        ));
    }

    fn client_config() -> Arc<ClientConfig> {
        Arc::new(
            ClientConfig::builder()
                .with_root_certificates(RootCertStore::empty())
                .with_no_client_auth(),
        )
    }

    fn server_name() -> ServerName<'static> {
        ServerName::try_from("turn.example.test").expect("valid DNS server name")
    }

    #[test]
    fn client_hello_is_emitted_without_blocking_io() {
        let mut engine = TlsClientEngine::new(client_config(), server_name()).unwrap();

        assert!(engine.is_handshaking());
        assert!(engine.wants_write());
        assert!(!engine.application_data_ready());

        let mut output = [0_u8; 4096];
        let written = engine.drain_ciphertext(&mut output).unwrap();

        assert!(written > 0);
        assert!(!engine.wants_write());
        assert!(engine.is_handshaking());
        assert!(!engine.application_data_ready());
    }

    #[test]
    fn partial_ciphertext_drain_remains_writable_until_fully_taken() {
        let mut engine = TlsClientEngine::new(client_config(), server_name()).unwrap();
        let mut first = [0_u8; 1];

        assert_eq!(engine.drain_ciphertext(&mut first).unwrap(), 1);
        assert!(engine.wants_write());

        let mut remainder = [0_u8; 4096];
        assert!(engine.drain_ciphertext(&mut remainder).unwrap() > 0);
        assert!(!engine.wants_write());
    }

    #[test]
    fn application_data_is_rejected_before_handshake_completion() {
        let mut engine = TlsClientEngine::new(client_config(), server_name()).unwrap();

        assert!(matches!(
            engine.write_plaintext(b"TURN Allocate"),
            Err(TlsEngineError::HandshakeIncomplete)
        ));
    }

    #[test]
    fn oversized_ciphertext_chunk_is_rejected() {
        let mut engine = TlsClientEngine::new(client_config(), server_name()).unwrap();
        let input = std::vec![0_u8; MAX_TLS_CIPHERTEXT_INPUT + 1];

        assert!(matches!(
            engine.feed_ciphertext(&input),
            Err(TlsEngineError::CiphertextInputTooLarge { .. })
        ));
    }

    #[derive(Debug)]
    struct MockStream {
        local: core::net::SocketAddr,
        peer: core::net::SocketAddr,
        writes: std::vec::Vec<u8>,
        read_data: std::vec::Vec<u8>,
        write_limit: usize,
        eof: bool,
    }

    impl TurnStreamSocket for MockStream {
        fn local_addr(&self) -> core::net::SocketAddr {
            self.local
        }

        fn peer_addr(&self) -> core::net::SocketAddr {
            self.peer
        }

        fn read(&mut self, buffer: &mut [u8]) -> Result<usize, TurnStreamIoError> {
            if !self.read_data.is_empty() {
                let read = buffer.len().min(self.read_data.len());
                buffer[..read].copy_from_slice(&self.read_data[..read]);
                self.read_data.drain(..read);
                Ok(read)
            } else if self.eof {
                Ok(0)
            } else {
                Err(TurnStreamIoError::WouldBlock)
            }
        }

        fn write(&mut self, bytes: &[u8]) -> Result<usize, TurnStreamIoError> {
            let written = bytes.len().min(self.write_limit);
            self.writes.extend_from_slice(&bytes[..written]);
            Ok(written)
        }
    }

    fn mock_stream(write_limit: usize) -> MockStream {
        MockStream {
            local: "192.0.2.10:40000".parse().unwrap(),
            peer: "198.51.100.1:443".parse().unwrap(),
            writes: std::vec::Vec::new(),
            read_data: std::vec::Vec::new(),
            write_limit,
            eof: false,
        }
    }

    #[test]
    fn unexpected_tcp_eof_without_tls_close_notify_fails_closed() {
        let mut stream = mock_stream(usize::MAX);
        stream.eof = true;
        let mut socket = TlsStreamSocket::new(stream, client_config(), server_name()).unwrap();

        assert_eq!(socket.read(&mut [0_u8; 64]), Err(TurnStreamIoError::Failed));
        assert_eq!(socket.read(&mut [0_u8; 64]), Err(TurnStreamIoError::Failed));
    }

    #[test]
    fn tls_stream_socket_completes_verified_handshake_and_exchanges_plaintext() {
        let mut socket = TlsStreamSocket::new(
            mock_stream(usize::MAX),
            trusted_test_client_config(),
            ServerName::try_from("example.com").unwrap(),
        )
        .unwrap();
        let mut server = rustls::ServerConnection::new(test_server_config()).unwrap();

        // The adapter emits ClientHello through the underlying byte stream.
        assert_eq!(
            socket.read(&mut [0_u8; 64]),
            Err(TurnStreamIoError::WouldBlock)
        );
        let client_hello = std::mem::take(&mut socket.socket.writes);
        assert!(!client_hello.is_empty());
        let mut input = std::io::Cursor::new(&client_hello);
        assert_eq!(server.read_tls(&mut input).unwrap(), client_hello.len());
        server.process_new_packets().unwrap();

        // Feed the authenticated server flight into the adapter's TCP input.
        let mut server_flight = std::vec::Vec::new();
        server.write_tls(&mut server_flight).unwrap();
        assert!(!server_flight.is_empty());
        socket.socket.read_data.extend_from_slice(&server_flight);
        assert_eq!(
            socket.read(&mut [0_u8; 64]),
            Err(TurnStreamIoError::WouldBlock)
        );

        // The adapter must flush the client's Finished before application data.
        let client_finished = std::mem::take(&mut socket.socket.writes);
        assert!(!client_finished.is_empty());
        let mut input = std::io::Cursor::new(&client_finished);
        assert_eq!(server.read_tls(&mut input).unwrap(), client_finished.len());
        server.process_new_packets().unwrap();
        assert!(!server.is_handshaking());
        assert!(socket.tls().application_data_ready());

        let request = b"TURN Allocate";
        assert_eq!(socket.write(request).unwrap(), request.len());
        let request_ciphertext = std::mem::take(&mut socket.socket.writes);
        assert!(!request_ciphertext.is_empty());
        let mut input = std::io::Cursor::new(&request_ciphertext);
        assert_eq!(
            server.read_tls(&mut input).unwrap(),
            request_ciphertext.len()
        );
        server.process_new_packets().unwrap();

        let mut received = [0_u8; 64];
        let received_len = server.reader().read(&mut received).unwrap();
        assert_eq!(&received[..received_len], request);

        let response = b"TURN Allocate Success";
        assert_eq!(server.writer().write(response).unwrap(), response.len());
        let mut response_ciphertext = std::vec::Vec::new();
        server.write_tls(&mut response_ciphertext).unwrap();
        assert!(!response_ciphertext.is_empty());
        socket
            .socket
            .read_data
            .extend_from_slice(&response_ciphertext);

        let mut plaintext = [0_u8; 64];
        let plaintext_len = socket.read(&mut plaintext).unwrap();
        assert_eq!(&plaintext[..plaintext_len], response);
    }

    #[test]
    fn tls_socket_sends_client_hello_before_accepting_turn_plaintext() {
        let mut socket =
            TlsStreamSocket::new(mock_stream(usize::MAX), client_config(), server_name()).unwrap();

        assert_eq!(
            socket.write(b"TURN Allocate"),
            Err(TurnStreamIoError::WouldBlock)
        );
        let wire = &socket.socket().writes;
        assert!(!wire.is_empty());
        assert!(
            !wire
                .windows(b"TURN Allocate".len())
                .any(|part| part == b"TURN Allocate")
        );
        assert!(socket.tls().is_handshaking());
    }

    #[test]
    fn turn_tcp_driver_uses_tls_underlay_without_sending_cleartext() {
        let socket =
            TlsStreamSocket::new(mock_stream(usize::MAX), client_config(), server_name()).unwrap();
        let server = "198.51.100.1:443".parse().unwrap();
        let mut driver = crate::TurnTcpDriver::<_, 2, 4096, 8192>::new(
            socket,
            server,
            "test-user",
            "test-password",
        )
        .unwrap();

        let poll = driver
            .poll_control_with_deadline(crate::MonotonicTime(1))
            .unwrap();
        assert!(poll.queued_control);
        assert_eq!(
            driver.flush_one().unwrap(),
            crate::TurnTcpFlushResult::WouldBlock
        );

        let wire = &driver.socket().socket().writes;
        assert!(!wire.is_empty());
        assert!(
            !wire
                .windows(b"TURN Allocate".len())
                .any(|part| part == b"TURN Allocate")
        );
        assert!(driver.queued_bytes() > 0);
    }

    #[test]
    fn tls_socket_retains_partial_handshake_ciphertext() {
        let mut socket =
            TlsStreamSocket::new(mock_stream(1), client_config(), server_name()).unwrap();

        assert_eq!(
            socket.write(b"TURN Allocate"),
            Err(TurnStreamIoError::WouldBlock)
        );
        assert_eq!(socket.socket().writes.len(), 1);

        let mut attempts = 0;
        while !socket.flush_pending_ciphertext().unwrap() {
            attempts += 1;
            assert!(attempts < 4096);
        }
        assert!(socket.socket().writes.len() > 1);
    }

    #[test]
    fn early_data_configuration_is_rejected() {
        let mut config = ClientConfig::builder()
            .with_root_certificates(RootCertStore::empty())
            .with_no_client_auth();
        config.enable_early_data = true;

        assert!(matches!(
            TlsClientEngine::new(Arc::new(config), server_name()),
            Err(TlsEngineError::EarlyDataEnabled)
        ));
    }
}
