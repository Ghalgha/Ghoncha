//! Canonical inner-IP flow identity for packet-affinity scheduling.
//!
//! This module is allocation-free. IPv6 extension-header chains other than a
//! directly visible Fragment header are rejected until a bounded extension
//! walker is implemented; callers must use a conservative fallback.

use core::hash::Hash;

use crate::{IpAddress, IpPacket, IpVersion};

/// Stable identity for packets that must remain on the same transport path.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub struct FlowKey {
    pub source: IpAddress,
    pub destination: IpAddress,
    pub protocol: u8,
    pub discriminator: FlowDiscriminator,
}

/// Transport-specific or fragmentation-specific part of a flow identity.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub enum FlowDiscriminator {
    /// TCP/UDP ports identify the bidirectional transport tuple directionally.
    Ports { source: u16, destination: u16 },
    /// All fragments of one IP datagram share this identifier.
    Fragment(u32),
    /// Fallback for protocols without safely parsed port identifiers.
    Network,
}

/// Why a packet could not be assigned a fully parsed flow key.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum FlowKeyError {
    /// The packet uses an IPv6 extension chain not yet supported here.
    UnsupportedIpv6Extension(u8),
    /// The IPv6 Fragment header or transport header is truncated.
    TruncatedHeader,
}

impl FlowKey {
    /// Builds a canonical directional key without allocating or copying payload.
    ///
    /// Fragmented packets use the fragment identifier rather than transport
    /// ports so the first and subsequent fragments receive the same key.
    pub fn from_packet(packet: &IpPacket<'_>) -> Result<Self, FlowKeyError> {
        let bytes = packet.as_bytes();
        let mut protocol = packet.next_header();
        let mut payload_offset = packet.header_len();
        let mut fragment = None;

        match packet.version() {
            IpVersion::V4 => {
                let flags_offset = u16::from_be_bytes([bytes[6], bytes[7]]);
                let offset = flags_offset & 0x1fff;
                let more_fragments = flags_offset & 0x2000 != 0;
                if offset != 0 || more_fragments {
                    fragment = Some(u32::from(u16::from_be_bytes([bytes[4], bytes[5]])));
                }
            }
            IpVersion::V6 => {
                if is_ipv6_extension(protocol) {
                    if protocol != 44 {
                        return Err(FlowKeyError::UnsupportedIpv6Extension(protocol));
                    }
                    if bytes.len() < payload_offset + 8 {
                        return Err(FlowKeyError::TruncatedHeader);
                    }
                    let fragment_header = &bytes[payload_offset..payload_offset + 8];
                    protocol = fragment_header[0];
                    let offset_flags =
                        u16::from_be_bytes([fragment_header[2], fragment_header[3]]);
                    let fragment_offset = (offset_flags & 0xfff8) >> 3;
                    let more_fragments = offset_flags & 1 != 0;
                    let identification = u32::from_be_bytes([
                        fragment_header[4],
                        fragment_header[5],
                        fragment_header[6],
                        fragment_header[7],
                    ]);
                    payload_offset += 8;
                    if fragment_offset != 0 || more_fragments {
                        fragment = Some(identification);
                    }
                    if is_ipv6_extension(protocol) {
                        return Err(FlowKeyError::UnsupportedIpv6Extension(protocol));
                    }
                }
            }
        }

        let discriminator = if let Some(identification) = fragment {
            FlowDiscriminator::Fragment(identification)
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

    /// Deterministic 64-bit hash for bounded, fixed-capacity flow tables.
    ///
    /// This is a placement hash, not a cryptographic primitive. Implementations
    /// handling hostile input should combine it with keyed hashing at the
    /// scheduling boundary when collision attacks are in scope.
    pub fn stable_hash(self) -> u64 {
        let mut hash = 0xcbf2_9ce4_8422_2325_u64;
        hash_byte(&mut hash, self.protocol);
        match self.source {
            IpAddress::V4(address) => {
                hash_byte(&mut hash, 4);
                for byte in address {
                    hash_byte(&mut hash, byte);
                }
            }
            IpAddress::V6(address) => {
                hash_byte(&mut hash, 6);
                for byte in address {
                    hash_byte(&mut hash, byte);
                }
            }
        }
        match self.destination {
            IpAddress::V4(address) => {
                hash_byte(&mut hash, 4);
                for byte in address {
                    hash_byte(&mut hash, byte);
                }
            }
            IpAddress::V6(address) => {
                hash_byte(&mut hash, 6);
                for byte in address {
                    hash_byte(&mut hash, byte);
                }
            }
        }
        match self.discriminator {
            FlowDiscriminator::Ports { source, destination } => {
                hash_byte(&mut hash, 1);
                for byte in source.to_be_bytes().into_iter().chain(destination.to_be_bytes()) {
                    hash_byte(&mut hash, byte);
                }
            }
            FlowDiscriminator::Fragment(identifier) => {
                hash_byte(&mut hash, 2);
                for byte in identifier.to_be_bytes() {
                    hash_byte(&mut hash, byte);
                }
            }
            FlowDiscriminator::Network => hash_byte(&mut hash, 3),
        }
        hash
    }
}

fn hash_byte(hash: &mut u64, byte: u8) {
    *hash ^= u64::from(byte);
    *hash = hash.wrapping_mul(0x0000_0100_0000_01b3);
}

fn is_ipv6_extension(next_header: u8) -> bool {
    matches!(next_header, 0 | 43 | 44 | 50 | 51 | 60 | 135 | 139 | 140)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ipv4(protocol: u8, fragment: u16, payload: &[u8]) -> std::vec::Vec<u8> {
        let mut bytes = std::vec![0_u8; 20 + payload.len()];
        bytes[0] = 0x45;
        bytes[2..4].copy_from_slice(&(bytes.len() as u16).to_be_bytes());
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
        let tcp = ipv4(6, 0, &[0x12, 0x34, 0x00, 0x50]);
        let packet = IpPacket::parse(&tcp).unwrap();
        assert_eq!(
            FlowKey::from_packet(&packet).unwrap().discriminator,
            FlowDiscriminator::Ports { source: 0x1234, destination: 80 }
        );
    }

    #[test]
    fn all_ipv4_fragments_share_the_datagram_key() {
        let first = ipv4(17, 0x2000, &[0x12, 0x34, 0x00, 0x35]);
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
    fn rejects_unsupported_ipv6_extension_chain() {
        let mut bytes = std::vec![0_u8; 41];
        bytes[0] = 0x60;
        bytes[4..6].copy_from_slice(&1_u16.to_be_bytes());
        bytes[6] = 0;
        assert_eq!(
            FlowKey::from_packet(&IpPacket::parse(&bytes).unwrap()),
            Err(FlowKeyError::UnsupportedIpv6Extension(0))
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
