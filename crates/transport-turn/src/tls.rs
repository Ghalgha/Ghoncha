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
                Ok(0) => {
                    self.retired = true;
                    return Ok(0);
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
        write_limit: usize,
    }

    impl TurnStreamSocket for MockStream {
        fn local_addr(&self) -> core::net::SocketAddr {
            self.local
        }

        fn peer_addr(&self) -> core::net::SocketAddr {
            self.peer
        }

        fn read(&mut self, _buffer: &mut [u8]) -> Result<usize, TurnStreamIoError> {
            Err(TurnStreamIoError::WouldBlock)
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
            write_limit,
        }
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
