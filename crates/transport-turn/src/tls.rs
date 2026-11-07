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

/// Maximum ciphertext accepted by one readiness callback.
pub const MAX_TLS_CIPHERTEXT_INPUT: usize = 16_384;
/// Maximum plaintext accepted in one write operation (one TLS record).
pub const MAX_TLS_PLAINTEXT_WRITE: usize = 16_384;
/// Rustls plaintext buffering limit for this connection.
pub const MAX_TLS_BUFFERED_PLAINTEXT: usize = 64 * 1024;

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
        self.connection.wants_write()
    }

    /// Application data is safe to send only after the handshake is complete
    /// and all final handshake bytes have been flushed to the socket.
    pub fn application_data_ready(&self) -> bool {
        !self.connection.is_handshaking() && !self.connection.wants_write()
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
            ciphertext_pending: state.tls_bytes_to_write(),
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

    /// Writes as much pending TLS ciphertext as fits in the supplied buffer.
    /// Repeatedly call while `wants_write()` is true; no socket I/O occurs here.
    pub fn drain_ciphertext(
        &mut self,
        output: &mut [u8],
    ) -> Result<usize, TlsEngineError> {
        if output.is_empty() || !self.connection.wants_write() {
            return Ok(0);
        }

        let mut sink = SliceWriter::new(output);
        self.connection.write_tls(&mut sink)?;
        Ok(sink.written())
    }
}

struct SliceWriter<'a> {
    output: &'a mut [u8],
    written: usize,
}

impl<'a> SliceWriter<'a> {
    fn new(output: &'a mut [u8]) -> Self {
        Self { output, written: 0 }
    }

    const fn written(&self) -> usize {
        self.written
    }
}

impl Write for SliceWriter<'_> {
    fn write(&mut self, input: &[u8]) -> io::Result<usize> {
        let available = self.output.len().saturating_sub(self.written);
        let count = available.min(input.len());
        self.output[self.written..self.written + count].copy_from_slice(&input[..count]);
        self.written += count;
        Ok(count)
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}
