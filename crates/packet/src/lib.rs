#![no_std]

pub mod flow;

//! Allocation-free validation and views over IPv4 and IPv6 packets.
//!
//! The parser borrows the input buffer and never copies packet contents.

/// Minimum IPv4 header size, in bytes.
pub const IPV4_MIN_HEADER_LEN: usize = 20;

/// Fixed IPv6 header size, in bytes.
pub const IPV6_HEADER_LEN: usize = 40;

/// IP protocol version.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum IpVersion {
    V4,
    V6,
}

/// An IP address copied from a packet header.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum IpAddress {
    V4([u8; 4]),
    V6([u8; 16]),
}

/// Errors returned when an IP packet is malformed or unsupported.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum PacketError {
    Empty,
    TruncatedHeader,
    UnsupportedVersion(u8),
    InvalidIpv4HeaderLength,
    InvalidIpv4TotalLength,
    InvalidIpv6PayloadLength,
    Ipv6JumbogramUnsupported,
}

/// A validated, zero-copy view over one complete IP packet.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct IpPacket<'a> {
    bytes: &'a [u8],
    version: IpVersion,
    header_len: usize,
}

impl<'a> IpPacket<'a> {
    /// Parses one complete IP packet without allocating or copying.
    ///
    /// The input must contain exactly one packet. Trailing bytes are rejected
    /// rather than silently treated as padding or a second packet.
    pub fn parse(bytes: &'a [u8]) -> Result<Self, PacketError> {
        let first = *bytes.first().ok_or(PacketError::Empty)?;
        let version = first >> 4;

        match version {
            4 => Self::parse_v4(bytes),
            6 => Self::parse_v6(bytes),
            other => Err(PacketError::UnsupportedVersion(other)),
        }
    }

    fn parse_v4(bytes: &'a [u8]) -> Result<Self, PacketError> {
        if bytes.len() < IPV4_MIN_HEADER_LEN {
            return Err(PacketError::TruncatedHeader);
        }

        let header_len = usize::from(bytes[0] & 0x0f) * 4;
        if header_len < IPV4_MIN_HEADER_LEN {
            return Err(PacketError::InvalidIpv4HeaderLength);
        }
        if header_len > bytes.len() {
            return Err(PacketError::TruncatedHeader);
        }

        let total_len = usize::from(u16::from_be_bytes([bytes[2], bytes[3]]));
        if total_len < header_len || total_len != bytes.len() {
            return Err(PacketError::InvalidIpv4TotalLength);
        }

        Ok(Self {
            bytes,
            version: IpVersion::V4,
            header_len,
        })
    }

    fn parse_v6(bytes: &'a [u8]) -> Result<Self, PacketError> {
        if bytes.len() < IPV6_HEADER_LEN {
            return Err(PacketError::TruncatedHeader);
        }

        let payload_len = usize::from(u16::from_be_bytes([bytes[4], bytes[5]]));

        // A zero payload length is valid for a 40-byte IPv6 packet. Longer
        // packets with a zero length require the Jumbo Payload option.
        if payload_len == 0 && bytes.len() > IPV6_HEADER_LEN {
            return Err(PacketError::Ipv6JumbogramUnsupported);
        }

        if IPV6_HEADER_LEN + payload_len != bytes.len() {
            return Err(PacketError::InvalidIpv6PayloadLength);
        }

        Ok(Self {
            bytes,
            version: IpVersion::V6,
            header_len: IPV6_HEADER_LEN,
        })
    }

    /// Returns the IP version.
    #[inline]
    pub const fn version(&self) -> IpVersion {
        self.version
    }

    /// Returns the complete packet bytes.
    #[inline]
    pub const fn as_bytes(&self) -> &'a [u8] {
        self.bytes
    }

    /// Returns the bytes following the fixed or declared IP header.
    ///
    /// For IPv6, extension headers remain part of this slice.
    #[inline]
    pub fn payload(&self) -> &'a [u8] {
        &self.bytes[self.header_len..]
    }

    /// Returns the IP header length in bytes.
    #[inline]
    pub const fn header_len(&self) -> usize {
        self.header_len
    }

    /// Returns the packet length in bytes.
    #[inline]
    pub const fn packet_len(&self) -> usize {
        self.bytes.len()
    }

    /// Returns the IPv4 Protocol or IPv6 Next Header field.
    #[inline]
    pub fn next_header(&self) -> u8 {
        match self.version {
            IpVersion::V4 => self.bytes[9],
            IpVersion::V6 => self.bytes[6],
        }
    }

    /// Returns the IPv4 TTL or IPv6 Hop Limit.
    #[inline]
    pub fn hop_limit(&self) -> u8 {
        match self.version {
            IpVersion::V4 => self.bytes[8],
            IpVersion::V6 => self.bytes[7],
        }
    }

    /// Returns the source IP address.
    #[inline]
    pub fn source(&self) -> IpAddress {
        match self.version {
            IpVersion::V4 => IpAddress::V4([
                self.bytes[12],
                self.bytes[13],
                self.bytes[14],
                self.bytes[15],
            ]),
            IpVersion::V6 => {
                let mut address = [0; 16];
                address.copy_from_slice(&self.bytes[8..24]);
                IpAddress::V6(address)
            }
        }
    }

    /// Returns the destination IP address.
    #[inline]
    pub fn destination(&self) -> IpAddress {
        match self.version {
            IpVersion::V4 => IpAddress::V4([
                self.bytes[16],
                self.bytes[17],
                self.bytes[18],
                self.bytes[19],
            ]),
            IpVersion::V6 => {
                let mut address = [0; 16];
                address.copy_from_slice(&self.bytes[24..40]);
                IpAddress::V6(address)
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_ipv4_without_copying_payload() {
        let mut bytes = [0_u8; 23];
        bytes[0] = 0x45;
        bytes[2..4].copy_from_slice(&23_u16.to_be_bytes());
        bytes[8] = 64;
        bytes[9] = 17;
        bytes[12..16].copy_from_slice(&[192, 0, 2, 1]);
        bytes[16..20].copy_from_slice(&[198, 51, 100, 2]);
        bytes[20..].copy_from_slice(&[1, 2, 3]);

        let packet = IpPacket::parse(&bytes).unwrap();

        assert_eq!(packet.version(), IpVersion::V4);
        assert_eq!(packet.header_len(), 20);
        assert_eq!(packet.packet_len(), 23);
        assert_eq!(packet.payload(), &[1, 2, 3]);
        assert_eq!(packet.next_header(), 17);
        assert_eq!(packet.hop_limit(), 64);
        assert_eq!(packet.source(), IpAddress::V4([192, 0, 2, 1]));
        assert_eq!(packet.destination(), IpAddress::V4([198, 51, 100, 2]));
    }

    #[test]
    fn accepts_ipv4_options() {
        let mut bytes = [0_u8; 24];
        bytes[0] = 0x46;
        bytes[2..4].copy_from_slice(&24_u16.to_be_bytes());

        let packet = IpPacket::parse(&bytes).unwrap();
        assert_eq!(packet.header_len(), 24);
        assert!(packet.payload().is_empty());
    }

    #[test]
    fn rejects_invalid_ipv4_lengths() {
        let mut bytes = [0_u8; 20];
        bytes[0] = 0x45;
        bytes[2..4].copy_from_slice(&19_u16.to_be_bytes());
        assert_eq!(
            IpPacket::parse(&bytes),
            Err(PacketError::InvalidIpv4TotalLength)
        );

        bytes[2..4].copy_from_slice(&21_u16.to_be_bytes());
        assert_eq!(
            IpPacket::parse(&bytes),
            Err(PacketError::InvalidIpv4TotalLength)
        );
    }

    #[test]
    fn parses_empty_ipv6_payload() {
        let mut bytes = [0_u8; IPV6_HEADER_LEN];
        bytes[0] = 0x60;
        bytes[7] = 32;
        bytes[6] = 59;

        let packet = IpPacket::parse(&bytes).unwrap();
        assert_eq!(packet.version(), IpVersion::V6);
        assert_eq!(packet.header_len(), IPV6_HEADER_LEN);
        assert!(packet.payload().is_empty());
        assert_eq!(packet.next_header(), 59);
        assert_eq!(packet.hop_limit(), 32);
    }

    #[test]
    fn parses_ipv6_payload_and_addresses() {
        let mut bytes = [0_u8; IPV6_HEADER_LEN + 1];
        bytes[0] = 0x60;
        bytes[4..6].copy_from_slice(&1_u16.to_be_bytes());
        bytes[8..24].copy_from_slice(&[1; 16]);
        bytes[24..40].copy_from_slice(&[2; 16]);
        bytes[40] = 0xaa;

        let packet = IpPacket::parse(&bytes).unwrap();
        assert_eq!(packet.payload(), &[0xaa]);
        assert_eq!(packet.source(), IpAddress::V6([1; 16]));
        assert_eq!(packet.destination(), IpAddress::V6([2; 16]));
    }

    #[test]
    fn rejects_ipv6_jumbograms_until_explicitly_supported() {
        let mut bytes = [0_u8; IPV6_HEADER_LEN + 1];
        bytes[0] = 0x60;

        assert_eq!(
            IpPacket::parse(&bytes),
            Err(PacketError::Ipv6JumbogramUnsupported)
        );
    }

    #[test]
    fn rejects_truncated_and_unknown_packets() {
        assert_eq!(IpPacket::parse(&[]), Err(PacketError::Empty));
        assert_eq!(IpPacket::parse(&[0x45]), Err(PacketError::TruncatedHeader));
        assert_eq!(
            IpPacket::parse(&[0x70]),
            Err(PacketError::UnsupportedVersion(7))
        );
    }
}
