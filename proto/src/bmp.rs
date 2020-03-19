use byteorder::{NetworkEndian, ReadBytesExt};
use std::io::{Cursor, Read};
use std::net::{IpAddr, Ipv4Addr};
use std::convert::From;
use std::time::Duration;
use failure::Error;
use super::bgp::{Message, ParseParam};

#[derive(Debug)]
pub struct CommonHeader {
    version: u8,
    message_length: u32,
    message_type: u8,
}

impl CommonHeader {
    fn from_bytes(c: &mut Cursor<&[u8]>) -> Result<CommonHeader, Error> {
        let version: u8 = c.read_u8()?;
        let msg_length: u32 = c.read_u32::<NetworkEndian>()?;
        let msg_type = c.read_u8()?;
        Ok(CommonHeader{
            version: version,
            message_length: msg_length,
            message_type: msg_type,
        })
    }
}

#[derive(Debug)]
pub struct PerPeerHeader {
    peer_type: u8,
    peer_flags: u8,
    peer_distinguisher: u64,
    peer_address: IpAddr,
    peer_as: u32,
    peer_bgp_id: Ipv4Addr,
    timestamp: Duration,
}

impl PerPeerHeader {
    const PEER_FLAG_IPV6: u8  = 1 << 7;
    const PEER_FLAG_POST_POLICY: u8  = 1 << 6;
    const PEER_FLAG_2BYTE_AS_PATH_FORMAT: u8  = 1 << 5;

    fn from_bytes(c: &mut Cursor<&[u8]>) -> Result<PerPeerHeader, Error> {
        let peer_type: u8 = c.read_u8()?;
        let peer_flags: u8 = c.read_u8()?;
        let peer_distinguisher: u64 = c.read_u64::<NetworkEndian>()?;

        let peer_address: IpAddr;
        if peer_flags & PerPeerHeader::PEER_FLAG_IPV6 != 0 {
            let mut buf = [0; 16];
            c.read_exact(&mut buf)?;
            peer_address = IpAddr::from(buf);
        } else {
            c.set_position(c.position() + 12);
            let mut buf = [0; 4];
            c.read_exact(&mut buf)?;
            peer_address = IpAddr::from(buf);
        }
        let peer_as = c.read_u32::<NetworkEndian>()?;
        let peer_bgp_id: Ipv4Addr = From::from(c.read_u32::<NetworkEndian>()?);
        let timestamp_seconds = c.read_u32::<NetworkEndian>()?;
        let timestamp_microseconds = c.read_u32::<NetworkEndian>()?;
        let timestamp = Duration::new(timestamp_seconds.into(), timestamp_microseconds.into());
        Ok(PerPeerHeader{
            peer_type: peer_type,
            peer_flags: peer_flags,
            peer_distinguisher: peer_distinguisher,
            peer_address: peer_address,
            peer_as: peer_as,
            peer_bgp_id: peer_bgp_id,
            timestamp: timestamp,
        })
    }
}

#[derive(Debug)]
pub enum BmpPacket {
    RouteMonitoring {
        common_header: CommonHeader,
        per_peer_header: PerPeerHeader,
        payload: Message,
    },
    StatisticsReport {
        common_header: CommonHeader,
        per_peer_header: PerPeerHeader,
        payload: Vec<u8>,
    },
    PeerDownNotification {
        common_header: CommonHeader,
        per_peer_header: PerPeerHeader,
        payload: Vec<u8>,
    },
    PeerUpNotification {
        common_header: CommonHeader,
        per_peer_header: PerPeerHeader,
        payload: Vec<u8>,
    },
    InitiationMessage {
        common_header: CommonHeader,
        payload: Vec<u8>,
    },
    TerminationMessage {
        common_header: CommonHeader,
        payload: Vec<u8>,
    },
    RouteMirroringMessage {
        common_header: CommonHeader,
        per_peer_header: PerPeerHeader,
        payload: Vec<u8>,
    },
    Undefined {
        common_header: CommonHeader,
        payload: Vec<u8>,
    },
}

impl BmpPacket {
    const COMMON_HEADER_SIZE: u64 = 6;
    const HEADER_SIZE: u64 = 48;

    const ROUTE_MONITORING: u8 = 0;
    const STATISTICS_REPORT: u8 = 1;
    const PEER_DOWN_NOTIFICATION: u8 = 2;
    const PEER_UP_NOTIFICATION: u8 = 3;
    const INITIATION_MESSAGE: u8 = 4;
    const TERMINATION_MESSAGE: u8 = 5;
    const ROUTE_MIRRORING_MESSAGE: u8 = 6;

    pub fn from_bytes(buf: &[u8]) -> Result<BmpPacket, Error> {
        let buflen = buf.len();
        let mut c = Cursor::new(buf);

        let common_header = CommonHeader::from_bytes(&mut c);
        match common_header {
            Ok(ch) => {
                if buflen < ch.message_length as usize {
                    return Err(format_err!("buffer is too short"));
                }

                let mut c = Cursor::new(&buf[BmpPacket::COMMON_HEADER_SIZE as usize..ch.message_length as usize]);
                match ch.message_type {
                    BmpPacket::ROUTE_MONITORING => {
                        let pph = PerPeerHeader::from_bytes(&mut c)?;
                        c.set_position(BmpPacket::HEADER_SIZE);
                        let p = ParseParam { local_as: 0 };
                        let payload = Message::from_bytes(&p, &buf[BmpPacket::HEADER_SIZE as usize..ch.message_length as usize])?;
                        return Ok(BmpPacket::RouteMonitoring{
                            common_header: ch,
                            per_peer_header: pph,
                            payload: payload,
                        })
                    },
                    BmpPacket::STATISTICS_REPORT => {
                        let pph = PerPeerHeader::from_bytes(&mut c)?;
                        // FIXME:
                        let mut payload = Vec::new();
                        let pos = BmpPacket::HEADER_SIZE;
                        for _ in pos as u32..ch.message_length {
                            payload.push(c.read_u8()?);
                        }
                        return Ok(BmpPacket::StatisticsReport{
                            common_header: ch,
                            per_peer_header: pph,
                            payload: payload,
                        })
                    },
                    BmpPacket::PEER_DOWN_NOTIFICATION => {
                        let pph = PerPeerHeader::from_bytes(&mut c)?;
                        // FIXME:
                        let mut payload = Vec::new();
                        let pos = BmpPacket::HEADER_SIZE;
                        for _ in pos as u32..ch.message_length {
                            payload.push(c.read_u8()?);
                        }
                        return Ok(BmpPacket::PeerDownNotification{
                            common_header: ch,
                            per_peer_header: pph,
                            payload: payload,
                        })
                    },
                    BmpPacket::PEER_UP_NOTIFICATION => {
                        let pph = PerPeerHeader::from_bytes(&mut c)?;
                        // FIXME:
                        let mut payload = Vec::new();
                        let pos = BmpPacket::HEADER_SIZE;
                        for _ in pos as u32..ch.message_length {
                            payload.push(c.read_u8()?);
                        }
                        return Ok(BmpPacket::PeerUpNotification{
                            common_header: ch,
                            per_peer_header: pph,
                            payload: payload,
                        })
                    },
                    BmpPacket::INITIATION_MESSAGE => {
                        // FIXME:
                        let mut payload = Vec::new();
                        let pos = BmpPacket::HEADER_SIZE;
                        for _ in pos as u32..ch.message_length {
                            payload.push(c.read_u8()?);
                        }
                        return Ok(BmpPacket::InitiationMessage{
                            common_header: ch,
                            payload: payload,
                        })
                    },
                    BmpPacket::TERMINATION_MESSAGE => {
                        // FIXME:
                        let mut payload = Vec::new();
                        let pos = BmpPacket::HEADER_SIZE;
                        for _ in pos as u32..ch.message_length {
                            payload.push(c.read_u8()?);
                        }
                        return Ok(BmpPacket::TerminationMessage{
                            common_header: ch,
                            payload: payload,
                        })
                    },
                    BmpPacket::ROUTE_MIRRORING_MESSAGE => {
                        let pph = PerPeerHeader::from_bytes(&mut c)?;
                        // FIXME:
                        let mut payload = Vec::new();
                        let pos = BmpPacket::HEADER_SIZE;
                        for _ in pos as u32..ch.message_length {
                            payload.push(c.read_u8()?);
                        }
                        return Ok(BmpPacket::RouteMirroringMessage{
                            common_header: ch,
                            per_peer_header: pph,
                            payload: payload,
                        })
                    },
                    _ => {
                        let mut payload = Vec::new();
                        let pos = BmpPacket::HEADER_SIZE;
                        for _ in pos as u32..ch.message_length {
                            payload.push(c.read_u8()?);
                        }
                        return Ok(BmpPacket::Undefined{
                            common_header: ch,
                            payload: payload,
                        })
                    },
                }
            },
            Err(e) => {
                return Err(e);
            },
        }
    }
}
