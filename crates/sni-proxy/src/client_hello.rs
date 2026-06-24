//! Parse TLS ClientHello records and extract the SNI hostname without terminating TLS.

use crate::error::{Result, SniProxyError};

const TLS_HANDSHAKE: u8 = 0x16;
const HANDSHAKE_CLIENT_HELLO: u8 = 0x01;
const EXT_SERVER_NAME: u16 = 0;
const NAME_TYPE_HOST: u8 = 0;

/// Maximum bytes buffered while waiting for a complete ClientHello.
pub const MAX_CLIENT_HELLO_BYTES: usize = 16 * 1024;

/// Extract the first host_name SNI value from buffered TLS data.
///
/// Handles TLS record fragmentation by scanning all complete handshake messages
/// in the buffer. Returns the SNI string when found.
pub fn extract_sni_from_buffer(buffer: &[u8]) -> Result<Option<String>> {
    let mut offset = 0;
    while offset + 5 <= buffer.len() {
        let record_type = buffer[offset];
        if record_type != TLS_HANDSHAKE {
            return Err(SniProxyError::ClientHello(format!(
                "expected TLS handshake record (0x16), got 0x{record_type:02x}"
            )));
        }

        let record_len = u16::from_be_bytes([buffer[offset + 3], buffer[offset + 4]]) as usize;
        let record_end = offset + 5 + record_len;
        if record_end > buffer.len() {
            return Ok(None);
        }

        let payload = &buffer[offset + 5..record_end];
        if let Some(sni) = scan_handshake_payload(payload)? {
            return Ok(Some(sni));
        }

        offset = record_end;
    }

    if offset < buffer.len() {
        return Err(SniProxyError::ClientHello(
            "truncated TLS record header".into(),
        ));
    }

    Ok(None)
}

fn scan_handshake_payload(payload: &[u8]) -> Result<Option<String>> {
    let mut pos = 0;
    while pos + 4 <= payload.len() {
        let msg_type = payload[pos];
        let msg_len = u24(&payload[pos + 1..pos + 4])?;
        let msg_end = pos + 4 + msg_len;
        if msg_end > payload.len() {
            return Ok(None);
        }

        if msg_type == HANDSHAKE_CLIENT_HELLO {
            if let Some(sni) = parse_client_hello(&payload[pos + 4..msg_end])? {
                return Ok(Some(sni));
            }
        }

        pos = msg_end;
    }
    Ok(None)
}

fn parse_client_hello(body: &[u8]) -> Result<Option<String>> {
    if body.len() < 34 {
        return Ok(None);
    }

    let mut pos = 2 + 32;
    if pos >= body.len() {
        return Ok(None);
    }

    let session_id_len = body[pos] as usize;
    pos += 1 + session_id_len;
    if pos + 2 > body.len() {
        return Ok(None);
    }

    let cipher_len = u16::from_be_bytes([body[pos], body[pos + 1]]) as usize;
    pos += 2 + cipher_len;
    if pos >= body.len() {
        return Ok(None);
    }

    let comp_len = body[pos] as usize;
    pos += 1 + comp_len;
    if pos + 2 > body.len() {
        return Ok(None);
    }

    let ext_len = u16::from_be_bytes([body[pos], body[pos + 1]]) as usize;
    pos += 2;
    if pos + ext_len > body.len() {
        return Ok(None);
    }

    parse_extensions(&body[pos..pos + ext_len])
}

fn parse_extensions(extensions: &[u8]) -> Result<Option<String>> {
    let mut pos = 0;
    while pos + 4 <= extensions.len() {
        let ext_type = u16::from_be_bytes([extensions[pos], extensions[pos + 1]]);
        let ext_len = u16::from_be_bytes([extensions[pos + 2], extensions[pos + 3]]) as usize;
        pos += 4;
        if pos + ext_len > extensions.len() {
            return Ok(None);
        }

        if ext_type == EXT_SERVER_NAME {
            return parse_server_name_list(&extensions[pos..pos + ext_len]);
        }

        pos += ext_len;
    }
    Ok(None)
}

fn parse_server_name_list(data: &[u8]) -> Result<Option<String>> {
    if data.len() < 2 {
        return Ok(None);
    }
    let list_len = u16::from_be_bytes([data[0], data[1]]) as usize;
    let mut pos = 2;
    let list_end = 2 + list_len;
    if list_end > data.len() {
        return Ok(None);
    }

    while pos + 3 <= list_end {
        let name_type = data[pos];
        let name_len = u16::from_be_bytes([data[pos + 1], data[pos + 2]]) as usize;
        pos += 3;
        if pos + name_len > list_end {
            return Ok(None);
        }
        if name_type == NAME_TYPE_HOST {
            let hostname = std::str::from_utf8(&data[pos..pos + name_len])
                .map_err(|e| SniProxyError::ClientHello(format!("invalid SNI UTF-8: {e}")))?;
            return Ok(Some(hostname.to_ascii_lowercase()));
        }
        pos += name_len;
    }
    Ok(None)
}

fn u24(bytes: &[u8]) -> Result<usize> {
    if bytes.len() < 3 {
        return Err(SniProxyError::ClientHello(
            "handshake length underflow".into(),
        ));
    }
    Ok(((bytes[0] as usize) << 16) | ((bytes[1] as usize) << 8) | bytes[2] as usize)
}

/// Build a minimal TLS ClientHello with the given SNI (for tests).
#[cfg(test)]
pub(crate) fn build_test_client_hello(sni: &str) -> Vec<u8> {
    let mut name = Vec::new();
    name.push(NAME_TYPE_HOST);
    name.extend_from_slice(&(sni.len() as u16).to_be_bytes());
    name.extend_from_slice(sni.as_bytes());

    let mut sni_list = Vec::new();
    sni_list.extend_from_slice(&(name.len() as u16).to_be_bytes());
    sni_list.extend_from_slice(&name);

    let mut extensions = Vec::new();
    extensions.extend_from_slice(&EXT_SERVER_NAME.to_be_bytes());
    extensions.extend_from_slice(&(sni_list.len() as u16).to_be_bytes());
    extensions.extend_from_slice(&sni_list);

    let mut body = Vec::new();
    body.extend_from_slice(&[0x03, 0x03]);
    body.extend(vec![0u8; 32]);
    body.push(0);
    body.extend_from_slice(&[0x00, 0x02, 0x00, 0xff]);
    body.push(1);
    body.push(0);
    body.extend_from_slice(&(extensions.len() as u16).to_be_bytes());
    body.extend_from_slice(&extensions);

    let mut handshake = Vec::new();
    handshake.push(HANDSHAKE_CLIENT_HELLO);
    handshake.push((body.len() >> 16) as u8);
    handshake.push((body.len() >> 8) as u8);
    handshake.push(body.len() as u8);
    handshake.extend_from_slice(&body);

    let mut record = Vec::new();
    record.push(TLS_HANDSHAKE);
    record.extend_from_slice(&[0x03, 0x01]);
    record.extend_from_slice(&(handshake.len() as u16).to_be_bytes());
    record.extend_from_slice(&handshake);
    record
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn extracts_sni_from_client_hello() {
        let buf = build_test_client_hello("api.example.com");
        let sni = extract_sni_from_buffer(&buf).unwrap().unwrap();
        assert_eq!(sni, "api.example.com");
    }

    #[test]
    fn returns_none_when_buffer_incomplete() {
        let buf = build_test_client_hello("login.example.com");
        let partial = &buf[..buf.len() - 4];
        assert!(extract_sni_from_buffer(partial).unwrap().is_none());
    }

    #[test]
    fn normalizes_sni_to_lowercase() {
        let buf = build_test_client_hello("API.Example.COM");
        let sni = extract_sni_from_buffer(&buf).unwrap().unwrap();
        assert_eq!(sni, "api.example.com");
    }
}
