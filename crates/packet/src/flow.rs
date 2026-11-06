//! Canonical inner-IP flow identity for packet-affinity scheduling.
//!
//! This module is allocation-free. IPv6 extension headers are walked with strict
//! header-count and byte limits; unsupported opaque protocols use network-level
//! affinity.

#[cfg(test)]
extern crate std;

use crate::{IpAddress, IpPacket, IpVersion};

/// Stable identity for packets that must remain on the same transport path.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct FlowKey {
    pub source: IpAddress,
    pub destination: IpAddress,
    pub protocol: u8,
    pub discriminator: FlowDiscriminator,
}

/// Transport-specific or fragmentation-specific part of a flow identity.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum FlowDiscriminator {
    /// TCP/UDP ports identify the directional transport tuple.
    Ports { source: u16, destination: u16 },
    /// All fragments of one IP datagram share this identifier.
    Fragment(u32),
    /// Fallback for protocols without safely parsed port identifiers.
    Network,
}

const IPV6_MAX_EXTENSION_HEADERS: usize = 8;
const IPV6_MAX_EXTENSION_BYTES: usize = 256;

/// Why a packet could not be assigned a fully parsed flow key.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum FlowKeyError {
    UnsupportedIpv6Extension(u8),
    InvalidIpv6FragmentHeader,
    Ipv6ExtensionLimit,
    InvalidIpv6ExtensionLength,
    TruncatedHeader,
}

impl FlowKey {
    /// Builds a directional key without allocating or copying packet payload.
    /// Fragmented packets use the fragment identifier rather than ports.
    pub fn from_packet(packet: &IpPacket<'_>) -> Result<Self, FlowKeyError> {
        let bytes = packet.as_bytes();
        let mut protocol = packet.next_header();
        let mut payload_offset = packet.header_len();
        let mut fragment = None;

        match packet.version() {
            IpVersion::V4 => {
                let flags_offset = u16::from_be_bytes([bytes[6], bytes[7]]);
                if flags_offset & 0x3fff != 0 {
                    fragment = Some(u32::from(u16::from_be_bytes([bytes[4], bytes[5]])));
                }
            }
            IpVersion::V6 => {
                let mut extension_count = 0;
                let mut extension_bytes = 0;

                while is_ipv6_extension(protocol) {
                    if extension_count >= IPV6_MAX_EXTENSION_HEADERS {
                        return Err(FlowKeyError::Ipv6ExtensionLimit);
                    }
                    extension_count += 1;

                    let remaining = bytes.len().saturating_sub(payload_offset);
                    let header_len = match protocol {
                        44 => {
                            if remaining < 8 {
                                return Err(FlowKeyError::TruncatedHeader);
                            }
                            let header = &bytes[payload_offset..payload_offset + 8];
                            let offset_flags = u16::from_be_bytes([header[2], header[3]]);
                            // RFC 8200 reserves the second octet and bits 1-2.
                            if header[1] != 0 || offset_flags & 0x0006 != 0 {
                                return Err(FlowKeyError::InvalidIpv6FragmentHeader);
                            }
                            protocol = header[0];
                            let fragment_offset = (offset_flags & 0xfff8) >> 3;
                            if fragment_offset != 0 || offset_flags & 1 != 0 {
                                fragment = Some(u32::from_be_bytes([
                                    header[4], header[5], header[6], header[7],
                                ]));
                                payload_offset += 8;
                                break;
                            }
                            8
                        }
                        51 => {
                            if remaining < 2 {
                                return Err(FlowKeyError::TruncatedHeader);
                            }
                            let header = &bytes[payload_offset..];
                            protocol = header[0];
                            let length = (usize::from(header[1]) + 2) * 4;
                            if length < 12 {
                                return Err(FlowKeyError::InvalidIpv6ExtensionLength);
                            }
                            length
                        }
                        _ => {
                            if remaining < 2 {
                                return Err(FlowKeyError::TruncatedHeader);
                            }
                            let header = &bytes[payload_offset..];
                            protocol = header[0];
                            (usize::from(header[1]) + 1) * 8
                        }
                    };

                    if header_len > remaining {
                        return Err(FlowKeyError::TruncatedHeader);
                    }
                    extension_bytes += header_len;
                    if extension_bytes > IPV6_MAX_EXTENSION_BYTES {
                        return Err(FlowKeyError::Ipv6ExtensionLimit);
                    }
                    payload_offset += header_len;
                }
            }
        }

        let discriminator = if let Some(id) = fragment {
            FlowDiscriminator::Fragment(id)
        } else if protocol == 6 || protocol == 17 {
            if bytes.len() < payload_offset + 4 {
                return Err(FlowKeyError::TruncatedHeader);
            }
            FlowDiscriminator::Ports {
                source: u16::from_be_bytes([bytes[payload_offset], bytes[payload_offset + 1]]),
                destination: u16::from_be_bytes([
                    bytes[payload_offset + 2],
                    bytes[payload_offset + 3],
                ]),
            }
        } else {
            FlowDiscriminator::Network
        };

        Ok(Self {
            source: packet.source(),
            destination: packet.destination(),
            protocol,
            discriminator,
        })
    }

    /// Builds a flow key, falling back to coarse network affinity when the
    /// bounded IPv6 extension walk reaches its configured limit.
    ///
    /// Malformed or truncated headers remain errors; only a valid packet whose
    /// extension chain exceeds the parser budget receives the conservative key.
    pub fn from_packet_with_conservative_fallback(
        packet: &IpPacket<'_>,
    ) -> Result<Self, FlowKeyError> {
        match Self::from_packet(packet) {
            Ok(key) => Ok(key),
            Err(FlowKeyError::Ipv6ExtensionLimit)
            | Err(FlowKeyError::UnsupportedIpv6Extension(_)) => Ok(Self {
                source: packet.source(),
                destination: packet.destination(),
                protocol: packet.next_header(),
                discriminator: FlowDiscriminator::Network,
            }),
            Err(error) => Err(error),
        }
    }

    /// Deterministic placement hash. This is not a cryptographic primitive.
    pub fn stable_hash(self) -> u64 {
        let mut hash = 0xcbf2_9ce4_8422_2325_u64;
        hash_byte(&mut hash, self.protocol);
        hash_address(&mut hash, self.source);
        hash_address(&mut hash, self.destination);
        match self.discriminator {
            FlowDiscriminator::Ports {
                source,
                destination,
            } => {
                hash_byte(&mut hash, 1);
                for byte in source.to_be_bytes() {
                    hash_byte(&mut hash, byte);
                }
                for byte in destination.to_be_bytes() {
                    hash_byte(&mut hash, byte);
                }
            }
            FlowDiscriminator::Fragment(id) => {
                hash_byte(&mut hash, 2);
                for byte in id.to_be_bytes() {
                    hash_byte(&mut hash, byte);
                }
            }
            FlowDiscriminator::Network => hash_byte(&mut hash, 3),
        }
        hash
    }
}

fn hash_address(hash: &mut u64, address: IpAddress) {
    match address {
        IpAddress::V4(bytes) => {
            hash_byte(hash, 4);
            for byte in bytes {
                hash_byte(hash, byte);
            }
        }
        IpAddress::V6(bytes) => {
            hash_byte(hash, 6);
            for byte in bytes {
                hash_byte(hash, byte);
            }
        }
    }
}

fn hash_byte(hash: &mut u64, byte: u8) {
    *hash ^= u64::from(byte);
    *hash = hash.wrapping_mul(0x0000_0100_0000_01b3);
}

fn is_ipv6_extension(next_header: u8) -> bool {
    // ESP (50) is intentionally opaque: it receives network-level affinity.
    matches!(next_header, 0 | 43 | 44 | 51 | 60 | 135 | 139 | 140)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ipv4(protocol: u8, fragment: u16, payload: &[u8]) -> std::vec::Vec<u8> {
        let mut bytes = std::vec![0_u8; 20 + payload.len()];
        bytes[0] = 0x45;
        let len = bytes.len() as u16;
        bytes[2..4].copy_from_slice(&len.to_be_bytes());
        bytes[4..6].copy_from_slice(&0x1234_u16.to_be_bytes());
        bytes[6..8].copy_from_slice(&fragment.to_be_bytes());
        bytes[8] = 64;
        bytes[9] = protocol;
        bytes[12..16].copy_from_slice(&[192, 0, 2, 1]);
        bytes[16..20].copy_from_slice(&[198, 51, 100, 2]);
        bytes[20..].copy_from_slice(payload);
        bytes
    }

    #[test]
    fn tcp_and_udp_keys_include_directional_ports() {
        let bytes = ipv4(6, 0, &[0x12, 0x34, 0, 80]);
        let packet = IpPacket::parse(&bytes).unwrap();
        assert_eq!(
            FlowKey::from_packet(&packet).unwrap().discriminator,
            FlowDiscriminator::Ports {
                source: 0x1234,
                destination: 80
            }
        );
    }

    #[test]
    fn all_ipv4_fragments_share_the_datagram_key() {
        let first = ipv4(17, 0x2000, &[0x12, 0x34, 0, 53]);
        let later = ipv4(17, 1, &[1, 2, 3, 4]);
        let first_key = FlowKey::from_packet(&IpPacket::parse(&first).unwrap()).unwrap();
        let later_key = FlowKey::from_packet(&IpPacket::parse(&later).unwrap()).unwrap();
        assert_eq!(first_key, later_key);
        assert_eq!(first_key.discriminator, FlowDiscriminator::Fragment(0x1234));
    }

    #[test]
    fn non_transport_protocols_use_network_affinity() {
        let bytes = ipv4(1, 0, &[8, 0, 0, 0]);
        let key = FlowKey::from_packet(&IpPacket::parse(&bytes).unwrap()).unwrap();
        assert_eq!(key.discriminator, FlowDiscriminator::Network);
    }

    #[test]
    fn rejects_truncated_transport_header() {
        let bytes = ipv4(6, 0, &[1, 2, 3]);
        assert_eq!(
            FlowKey::from_packet(&IpPacket::parse(&bytes).unwrap()),
            Err(FlowKeyError::TruncatedHeader)
        );
    }

    #[test]
    fn uses_conservative_affinity_when_ipv6_extension_budget_is_exceeded() {
        let mut bytes = std::vec![0_u8; 40 + 9 * 8];
        bytes[0] = 0x60;
        bytes[4..6].copy_from_slice(&72_u16.to_be_bytes());
        bytes[6] = 0;
        for index in 0..9 {
            let offset = 40 + index * 8;
            bytes[offset] = if index == 8 { 17 } else { 0 };
            bytes[offset + 1] = 0;
        }
        let packet = IpPacket::parse(&bytes).unwrap();

        assert_eq!(
            FlowKey::from_packet(&packet),
            Err(FlowKeyError::Ipv6ExtensionLimit)
        );
        let fallback = FlowKey::from_packet_with_conservative_fallback(&packet).unwrap();
        assert_eq!(fallback.protocol, 0);
        assert_eq!(fallback.discriminator, FlowDiscriminator::Network);
    }

    #[test]
    fn treats_ipv6_esp_as_opaque_network_affinity() {
        let mut bytes = std::vec![0_u8; 41];
        bytes[0] = 0x60;
        bytes[4..6].copy_from_slice(&1_u16.to_be_bytes());
        bytes[6] = 50; // ESP payload is encrypted and cannot expose TCP/UDP ports.

        let key = FlowKey::from_packet(&IpPacket::parse(&bytes).unwrap()).unwrap();
        assert_eq!(key.protocol, 50);
        assert_eq!(key.discriminator, FlowDiscriminator::Network);
    }

    fn ipv6_fragment(reserved: u8, offset_flags: u16, id: u32) -> std::vec::Vec<u8> {
        let mut bytes = std::vec![0_u8; 48];
        bytes[0] = 0x60;
        bytes[4..6].copy_from_slice(&8_u16.to_be_bytes());
        bytes[6] = 44;
        bytes[8..24].copy_from_slice(&[1; 16]);
        bytes[24..40].copy_from_slice(&[2; 16]);
        bytes[40] = 17;
        bytes[41] = reserved;
        bytes[42..44].copy_from_slice(&offset_flags.to_be_bytes());
        bytes[44..48].copy_from_slice(&id.to_be_bytes());
        bytes
    }

    #[test]
    fn rejects_nonzero_reserved_fields_in_ipv6_fragment_header() {
        for (reserved, offset_flags) in [(1, 0), (0, 0x0002), (0, 0x0004)] {
            let bytes = ipv6_fragment(reserved, offset_flags, 7);
            assert_eq!(
                FlowKey::from_packet(&IpPacket::parse(&bytes).unwrap()),
                Err(FlowKeyError::InvalidIpv6FragmentHeader)
            );
        }
    }

    #[test]
    fn valid_ipv6_fragments_share_the_datagram_key() {
        let first = ipv6_fragment(0, 0x0001, 0x1234_5678);
        let later = ipv6_fragment(0, 0x0008, 0x1234_5678);
        let first_key = FlowKey::from_packet(&IpPacket::parse(&first).unwrap()).unwrap();
        let later_key = FlowKey::from_packet(&IpPacket::parse(&later).unwrap()).unwrap();
        assert_eq!(first_key, later_key);
        assert_eq!(
            first_key.discriminator,
            FlowDiscriminator::Fragment(0x1234_5678)
        );
    }

    #[test]
    fn walks_ipv6_hop_by_hop_and_destination_options_before_udp() {
        let mut bytes = std::vec![0_u8; 40 + 8 + 8 + 8];
        bytes[0] = 0x60;
        bytes[4..6].copy_from_slice(&24_u16.to_be_bytes());
        bytes[6] = 0; // Hop-by-Hop Options
        bytes[40] = 60; // Destination Options
        bytes[41] = 0; // 8-byte header
        bytes[48] = 17; // UDP
        bytes[49] = 0;
        bytes[56..58].copy_from_slice(&1234_u16.to_be_bytes());
        bytes[58..60].copy_from_slice(&443_u16.to_be_bytes());

        let key = FlowKey::from_packet(&IpPacket::parse(&bytes).unwrap()).unwrap();
        assert_eq!(
            key.discriminator,
            FlowDiscriminator::Ports {
                source: 1234,
                destination: 443
            }
        );
        assert_eq!(key.protocol, 17);
    }

    #[test]
    fn walks_ipv6_authentication_header_before_tcp() {
        let mut bytes = std::vec![0_u8; 40 + 12 + 4];
        bytes[0] = 0x60;
        bytes[4..6].copy_from_slice(&16_u16.to_be_bytes());
        bytes[6] = 51; // Authentication Header
        bytes[40] = 6; // TCP
        bytes[41] = 1; // (1 + 2) * 4 = 12 bytes
        bytes[52..54].copy_from_slice(&3210_u16.to_be_bytes());
        bytes[54..56].copy_from_slice(&443_u16.to_be_bytes());

        let key = FlowKey::from_packet(&IpPacket::parse(&bytes).unwrap()).unwrap();
        assert_eq!(
            key.discriminator,
            FlowDiscriminator::Ports {
                source: 3210,
                destination: 443
            }
        );
    }

    #[test]
    fn rejects_too_short_ipv6_authentication_header() {
        let mut bytes = std::vec![0_u8; 40 + 8];
        bytes[0] = 0x60;
        bytes[4..6].copy_from_slice(&8_u16.to_be_bytes());
        bytes[6] = 51;
        bytes[40] = 17;
        bytes[41] = 0;
        assert_eq!(
            FlowKey::from_packet(&IpPacket::parse(&bytes).unwrap()),
            Err(FlowKeyError::InvalidIpv6ExtensionLength)
        );
    }

    #[test]
    fn bounds_ipv6_extension_header_walk() {
        let mut bytes = std::vec![0_u8; 40 + 9 * 8];
        bytes[0] = 0x60;
        bytes[4..6].copy_from_slice(&72_u16.to_be_bytes());
        bytes[6] = 0;
        for index in 0..9 {
            let offset = 40 + index * 8;
            bytes[offset] = if index == 8 { 17 } else { 0 };
            bytes[offset + 1] = 0;
        }
        assert_eq!(
            FlowKey::from_packet(&IpPacket::parse(&bytes).unwrap()),
            Err(FlowKeyError::Ipv6ExtensionLimit)
        );
    }

    #[test]
    fn rejects_truncated_ipv6_extension_header() {
        let mut bytes = std::vec![0_u8; 44];
        bytes[0] = 0x60;
        bytes[4..6].copy_from_slice(&4_u16.to_be_bytes());
        bytes[6] = 0;
        assert_eq!(
            FlowKey::from_packet(&IpPacket::parse(&bytes).unwrap()),
            Err(FlowKeyError::TruncatedHeader)
        );
    }

    #[test]
    fn stable_hash_is_repeatable_and_directional() {
        let a = ipv4(17, 0, &[0x12, 0x34, 0, 53]);
        let b = ipv4(17, 0, &[0, 53, 0x12, 0x34]);
        let a = FlowKey::from_packet(&IpPacket::parse(&a).unwrap()).unwrap();
        let b = FlowKey::from_packet(&IpPacket::parse(&b).unwrap()).unwrap();
        assert_eq!(a.stable_hash(), a.stable_hash());
        assert_ne!(a.stable_hash(), b.stable_hash());
    }
}
