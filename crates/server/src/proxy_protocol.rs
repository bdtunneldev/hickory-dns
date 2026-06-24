// Copyright 2026 RAHMAT AL ZAMI
//
// Licensed under the Apache License, Version 2.0, <LICENSE-APACHE or
// https://apache.org/licenses/LICENSE-2.0> or the MIT license <LICENSE-MIT or
// https://opensource.org/licenses/MIT>, at your option.

//! HAProxy PROXY protocol v2 parsing with RouteDNS tenant TLV support.

use std::{
    io,
    net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr},
};

use tokio::io::{AsyncRead, AsyncReadExt};

/// Custom PPv2 TLV type used by RouteDNS for tenant identification.
pub const TENANT_TLV_TYPE: u16 = 0xE1;

const PP2_SIGNATURE: &[u8] = b"\r\n\r\n\0\r\nQUIT\n";

/// Parsed PROXY protocol header from a TCP connection.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProxyHeader {
    /// Real client socket address.
    pub src: SocketAddr,
    /// Optional tenant identifier from TLV 0xE1.
    pub tenant_id: Option<String>,
}

/// Read and parse a PROXY protocol v2 header from the start of a TCP stream.
///
/// If the stream does not begin with a PROXY signature, returns `Ok(None)` and
/// leaves the stream unread so the caller can treat it as a plain DNS connection.
pub async fn read_proxy_header<R: AsyncRead + Unpin>(
    stream: &mut R,
) -> io::Result<Option<ProxyHeader>> {
    let mut sig = [0u8; 12];
    stream.read_exact(&mut sig).await?;

    if &sig != PP2_SIGNATURE {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "stream does not start with PROXY protocol signature",
        ));
    }

    let mut ver_cmd = [0u8; 1];
    stream.read_exact(&mut ver_cmd).await?;
    let version = ver_cmd[0] >> 4;
    if version != 2 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            format!("unsupported PROXY protocol version: {version}"),
        ));
    }

    let mut fam = [0u8; 1];
    stream.read_exact(&mut fam).await?;

    let mut len_buf = [0u8; 2];
    stream.read_exact(&mut len_buf).await?;
    let len = u16::from_be_bytes(len_buf) as usize;

    let mut payload = vec![0u8; len];
    if len > 0 {
        stream.read_exact(&mut payload).await?;
    }

    let cmd = ver_cmd[0] & 0x0F;
    // LOCAL (0x00) or PROXY (0x01)
    if cmd == 0x00 {
        return Ok(Some(ProxyHeader {
            src: SocketAddr::new(IpAddr::V4(Ipv4Addr::UNSPECIFIED), 0),
            tenant_id: parse_tlvs(&payload, address_len(fam[0])),
        }));
    }

    let addr_len = address_len(fam[0]);
    if payload.len() < addr_len {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "PROXY header address block truncated",
        ));
    }

    let src = parse_addresses(fam[0], &payload[..addr_len])?;
    let tenant_id = parse_tlvs(&payload, addr_len);

    Ok(Some(ProxyHeader { src, tenant_id }))
}

fn address_len(fam: u8) -> usize {
    match fam {
        0x11 | 0x12 => 12,  // TCP4 / UDP4
        0x21 | 0x22 => 36,  // TCP6 / UDP6
        0x31 | 0x32 => 216, // UNIX stream / dgram
        0x00 => 0,          // UNSPEC / LOCAL
        _ => 0,
    }
}

fn parse_addresses(fam: u8, data: &[u8]) -> io::Result<SocketAddr> {
    match fam {
        0x11 | 0x12 => {
            if data.len() < 12 {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "IPv4 PROXY address block too short",
                ));
            }
            let src_ip = Ipv4Addr::new(data[0], data[1], data[2], data[3]);
            let src_port = u16::from_be_bytes([data[8], data[9]]);
            Ok(SocketAddr::new(IpAddr::V4(src_ip), src_port))
        }
        0x21 | 0x22 => {
            if data.len() < 36 {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "IPv6 PROXY address block too short",
                ));
            }
            let mut octets = [0u8; 16];
            octets.copy_from_slice(&data[0..16]);
            let src_ip = Ipv6Addr::from(octets);
            let src_port = u16::from_be_bytes([data[32], data[33]]);
            Ok(SocketAddr::new(IpAddr::V6(src_ip), src_port))
        }
        _ => Err(io::Error::new(
            io::ErrorKind::InvalidData,
            format!("unsupported PROXY address family: 0x{fam:02x}"),
        )),
    }
}

fn parse_tlvs(payload: &[u8], offset: usize) -> Option<String> {
    let mut pos = offset;
    while pos + 3 <= payload.len() {
        let tlv_type = u16::from_be_bytes([payload[pos], payload[pos + 1]]);
        let tlv_len = payload[pos + 2] as usize;
        pos += 3;
        if pos + tlv_len > payload.len() {
            break;
        }
        if tlv_type == TENANT_TLV_TYPE {
            return String::from_utf8(payload[pos..pos + tlv_len].to_vec()).ok();
        }
        pos += tlv_len;
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_ipv4_proxy_with_tenant_tlv() {
        let mut payload = Vec::new();
        // src 203.0.113.1:12345 dst 10.0.0.1:5301
        payload.extend_from_slice(&[203, 0, 113, 1, 10, 0, 0, 1]);
        payload.extend_from_slice(&49u16.to_be_bytes()); // src port
        payload.extend_from_slice(&5301u16.to_be_bytes()); // dst port
        // tenant TLV
        payload.extend_from_slice(&TENANT_TLV_TYPE.to_be_bytes());
        payload.push(6);
        payload.extend_from_slice(b"tenant");

        let src = parse_addresses(0x11, &payload[..12]).unwrap();
        assert_eq!(src, "203.0.113.1:12345".parse().unwrap());
        assert_eq!(parse_tlvs(&payload, 12), Some("tenant".to_string()));
    }
}
