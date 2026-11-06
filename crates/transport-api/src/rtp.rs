//! Minimal, allocation-free RTP record framing for the GHONCHA private payload profile.
//!
//! This profile deliberately uses a fixed RTP header: version 2, no CSRC list,
//! no header extensions, no RTP padding, and dynamic payload type 127. The
//! payload is one complete opaque GHONCHA record (normally a WireGuard
//! datagram). It is not an Opus, VP8, or other standard media payload.

/// Size of the fixed RTP header used by the GHONCHA profile.
pub const RTP_HEADER_LEN: usize = 12;

/// Dynamic RTP payload type reserved by the GHONCHA private profile.
pub const GHONCHA_RTP_PAYLOAD_TYPE: u8 = 127;

/// Errors produced while encoding or decoding the GHONCHA RTP profile.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RtpRecordError {
    BufferTooSmall,
    TruncatedHeader,
    UnsupportedVersion,
    PaddingNotSupported,
    HeaderExtensionsNotSupported,
    ContributingSourcesNotSupported,
    MarkerNotSupported,
    UnexpectedPayloadType,
    EmptyPayload,
}

/// The fixed RTP header fields used by the GHONCHA profile.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct RtpRecordHeader {
    pub sequence_number: u16,
    pub timestamp: u32,
    pub ssrc: u32,
}

impl RtpRecordHeader {
    /// Writes the 12-byte RTP header into caller-owned storage.
    pub fn write_to(self, output: &mut [u8]) -> Result<(), RtpRecordError> {
        if output.len() < RTP_HEADER_LEN {
            return Err(RtpRecordError::BufferTooSmall);
        }

        output[0] = 0x80; // RTP version 2; no padding, extension, or CSRCs.
        output[1] = GHONCHA_RTP_PAYLOAD_TYPE;
        output[2..4].copy_from_slice(&self.sequence_number.to_be_bytes());
        output[4..8].copy_from_slice(&self.timestamp.to_be_bytes());
        output[8..12].copy_from_slice(&self.ssrc.to_be_bytes());

        Ok(())
    }
}

/// A parsed GHONCHA RTP record borrowing its payload from the input datagram.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct RtpRecord<'a> {
    pub header: RtpRecordHeader,
    pub payload: &'a [u8],
}

impl<'a> RtpRecord<'a> {
    /// Parses one complete RTP datagram in the fixed GHONCHA profile.
    ///
    /// No memory is allocated and the payload is returned as a borrowed slice.
    pub fn parse(datagram: &'a [u8]) -> Result<Self, RtpRecordError> {
        if datagram.len() < RTP_HEADER_LEN {
            return Err(RtpRecordError::TruncatedHeader);
        }

        let first = datagram[0];
        if first >> 6 != 2 {
            return Err(RtpRecordError::UnsupportedVersion);
        }
        if first & 0x20 != 0 {
            return Err(RtpRecordError::PaddingNotSupported);
        }
        if first & 0x10 != 0 {
            return Err(RtpRecordError::HeaderExtensionsNotSupported);
        }
        if first & 0x0f != 0 {
            return Err(RtpRecordError::ContributingSourcesNotSupported);
        }

        let second = datagram[1];
        if second & 0x80 != 0 {
            return Err(RtpRecordError::MarkerNotSupported);
        }
        if second != GHONCHA_RTP_PAYLOAD_TYPE {
            return Err(RtpRecordError::UnexpectedPayloadType);
        }

        let payload = &datagram[RTP_HEADER_LEN..];
        if payload.is_empty() {
            return Err(RtpRecordError::EmptyPayload);
        }

        Ok(Self {
            header: RtpRecordHeader {
                sequence_number: u16::from_be_bytes([datagram[2], datagram[3]]),
                timestamp: u32::from_be_bytes([datagram[4], datagram[5], datagram[6], datagram[7]]),
                ssrc: u32::from_be_bytes([datagram[8], datagram[9], datagram[10], datagram[11]]),
            },
            payload,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn writes_and_parses_a_record_without_copying_payload() {
        let header = RtpRecordHeader {
            sequence_number: 0x1234,
            timestamp: 0x1020_3040,
            ssrc: 0xa1b2_c3d4,
        };
        let payload = b"wireguard-datagram";
        let mut datagram = [0u8; RTP_HEADER_LEN + 18];

        header.write_to(&mut datagram).unwrap();
        datagram[RTP_HEADER_LEN..].copy_from_slice(payload);

        let parsed = RtpRecord::parse(&datagram).unwrap();
        assert_eq!(parsed.header, header);
        assert_eq!(parsed.payload, payload);
        assert_eq!(parsed.payload.as_ptr(), datagram[RTP_HEADER_LEN..].as_ptr());
    }

    #[test]
    fn rejects_a_short_header() {
        assert_eq!(
            RtpRecord::parse(&[0x80; RTP_HEADER_LEN - 1]),
            Err(RtpRecordError::TruncatedHeader)
        );
    }

    #[test]
    fn rejects_unsupported_rtp_features() {
        let mut datagram = [0u8; RTP_HEADER_LEN + 1];
        datagram[0] = 0x80 | 0x20;
        datagram[1] = GHONCHA_RTP_PAYLOAD_TYPE;
        assert_eq!(
            RtpRecord::parse(&datagram),
            Err(RtpRecordError::PaddingNotSupported)
        );

        datagram[0] = 0x80 | 0x10;
        assert_eq!(
            RtpRecord::parse(&datagram),
            Err(RtpRecordError::HeaderExtensionsNotSupported)
        );

        datagram[0] = 0x81;
        assert_eq!(
            RtpRecord::parse(&datagram),
            Err(RtpRecordError::ContributingSourcesNotSupported)
        );

        datagram[0] = 0x80;
        datagram[1] = 0x80 | GHONCHA_RTP_PAYLOAD_TYPE;
        assert_eq!(
            RtpRecord::parse(&datagram),
            Err(RtpRecordError::MarkerNotSupported)
        );
    }

    #[test]
    fn rejects_wrong_version_payload_type_and_empty_payload() {
        let mut datagram = [0u8; RTP_HEADER_LEN + 1];
        datagram[0] = 0x40;
        datagram[1] = GHONCHA_RTP_PAYLOAD_TYPE;
        assert_eq!(
            RtpRecord::parse(&datagram),
            Err(RtpRecordError::UnsupportedVersion)
        );

        datagram[0] = 0x80;
        datagram[1] = 96;
        assert_eq!(
            RtpRecord::parse(&datagram),
            Err(RtpRecordError::UnexpectedPayloadType)
        );

        datagram[1] = GHONCHA_RTP_PAYLOAD_TYPE;
        assert_eq!(
            RtpRecord::parse(&datagram[..RTP_HEADER_LEN]),
            Err(RtpRecordError::EmptyPayload)
        );
    }

    #[test]
    fn reports_insufficient_output_storage() {
        let header = RtpRecordHeader {
            sequence_number: 1,
            timestamp: 2,
            ssrc: 3,
        };
        let mut output = [0u8; RTP_HEADER_LEN - 1];
        assert_eq!(
            header.write_to(&mut output),
            Err(RtpRecordError::BufferTooSmall)
        );
    }
}
