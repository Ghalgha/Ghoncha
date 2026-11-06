//! Peer identity pins used by authenticated transport handshakes.
//!
//! This module parses and compares SHA-256 certificate fingerprints. It does not
//! hash certificates or perform certificate validation; the selected DTLS
//! implementation must hash the verified peer certificate and compare the
//! result against this pin before accepting tunnel traffic.

/// A SHA-256 certificate fingerprint.
#[derive(Clone, Copy, Debug)]
pub struct Sha256Fingerprint([u8; 32]);

/// Errors returned while parsing a colon-separated SHA-256 fingerprint.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum FingerprintParseError {
    InvalidLength,
    InvalidSeparator,
    InvalidHexDigit,
}

impl Sha256Fingerprint {
    /// Creates a fingerprint from its 32 raw digest bytes.
    pub const fn from_bytes(bytes: [u8; 32]) -> Self {
        Self(bytes)
    }

    /// Parses the 95-character form `AA:BB:...` (upper- or lowercase hex).
    pub fn parse_colon_hex(input: &str) -> Result<Self, FingerprintParseError> {
        let bytes = input.as_bytes();
        if bytes.len() != 95 {
            return Err(FingerprintParseError::InvalidLength);
        }

        let mut digest = [0u8; 32];
        let mut index = 0;
        while index < 32 {
            let offset = index * 3;
            if index != 31 && bytes[offset + 2] != b':' {
                return Err(FingerprintParseError::InvalidSeparator);
            }
            let high = hex_nibble(bytes[offset]).ok_or(FingerprintParseError::InvalidHexDigit)?;
            let low =
                hex_nibble(bytes[offset + 1]).ok_or(FingerprintParseError::InvalidHexDigit)?;
            digest[index] = (high << 4) | low;
            index += 1;
        }

        Ok(Self(digest))
    }

    /// Returns the raw 32-byte digest.
    pub const fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }

    /// Compares a candidate SHA-256 digest without data-dependent early exit.
    pub fn matches(&self, candidate: &[u8; 32]) -> bool {
        let mut difference = 0u8;
        let mut index = 0;
        while index < 32 {
            difference |= self.0[index] ^ candidate[index];
            index += 1;
        }
        difference == 0
    }
}

fn hex_nibble(value: u8) -> Option<u8> {
    match value {
        b'0'..=b'9' => Some(value - b'0'),
        b'a'..=b'f' => Some(value - b'a' + 10),
        b'A'..=b'F' => Some(value - b'A' + 10),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const FINGERPRINT: &str = "00:01:02:03:04:05:06:07:08:09:0A:0B:0C:0D:0E:0F:10:11:12:13:14:15:16:17:18:19:1A:1B:1C:1D:1E:1F";

    #[test]
    fn parses_uppercase_and_lowercase_fingerprints() {
        let upper = Sha256Fingerprint::parse_colon_hex(FINGERPRINT).unwrap();
        let lower = Sha256Fingerprint::parse_colon_hex(&FINGERPRINT.to_ascii_lowercase()).unwrap();
        assert_eq!(upper.as_bytes(), lower.as_bytes());
        assert_eq!(upper.as_bytes()[0], 0);
        assert_eq!(upper.as_bytes()[31], 31);
    }

    #[test]
    fn compares_candidate_digest() {
        let fingerprint = Sha256Fingerprint::parse_colon_hex(FINGERPRINT).unwrap();
        let mut candidate = *fingerprint.as_bytes();
        assert!(fingerprint.matches(&candidate));
        candidate[31] ^= 1;
        assert!(!fingerprint.matches(&candidate));
    }

    #[test]
    fn rejects_invalid_lengths_separators_and_hex() {
        assert!(matches!(
            Sha256Fingerprint::parse_colon_hex("00"),
            Err(FingerprintParseError::InvalidLength)
        ));
        let invalid_separator = FINGERPRINT.replacen(':', "-", 1);
        assert!(matches!(
            Sha256Fingerprint::parse_colon_hex(&invalid_separator),
            Err(FingerprintParseError::InvalidSeparator)
        ));
        let invalid_hex = FINGERPRINT.replacen("00", "GG", 1);
        assert!(matches!(
            Sha256Fingerprint::parse_colon_hex(&invalid_hex),
            Err(FingerprintParseError::InvalidHexDigit)
        ));
    }
}
