use std::io;
use std::net::{SocketAddr, UdpSocket};
use std::time::Duration;

const IO_TIMEOUT: Duration = Duration::from_secs(2);

pub fn tftp_request(peer: &str, filename: &str) -> io::Result<(String, String)> {
    let peer: std::net::IpAddr = peer
        .parse()
        .map_err(|error| io::Error::new(io::ErrorKind::InvalidInput, error))?;
    let socket = UdpSocket::bind("0.0.0.0:0")?;
    socket.set_read_timeout(Some(IO_TIMEOUT))?;
    socket.set_write_timeout(Some(IO_TIMEOUT))?;
    let mut request = vec![0, 1];
    request.extend_from_slice(filename.as_bytes());
    request.extend_from_slice(b"\0octet\0");
    socket.send_to(&request, SocketAddr::new(peer, 69))?;

    let mut contents = Vec::new();
    let mut expected_block = 1_u16;
    let mut server = None;
    loop {
        let mut packet = [0_u8; 516];
        let (length, source) = socket.recv_from(&mut packet)?;
        if let Some(server) = server {
            if source != server {
                continue;
            }
        } else {
            server = Some(source);
        }
        if length < 4 {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "truncated TFTP packet",
            ));
        }
        let opcode = u16::from_be_bytes([packet[0], packet[1]]);
        if opcode == 5 {
            return Err(io::Error::new(
                io::ErrorKind::NotFound,
                "TFTP server returned an error",
            ));
        }
        let block = u16::from_be_bytes([packet[2], packet[3]]);
        if opcode != 3 || block != expected_block {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "unexpected TFTP packet",
            ));
        }
        contents.extend_from_slice(&packet[4..length]);
        if contents.len() > crate::protocol::MAX_REQUEST_DATA_LENGTH {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "TFTP response exceeds protocol limit",
            ));
        }
        socket.send_to(&[0, 4, packet[2], packet[3]], source)?;
        if length < packet.len() {
            break;
        }
        expected_block = expected_block
            .checked_add(1)
            .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "TFTP block overflow"))?;
    }
    parse_fixture_response(&contents)
}

fn parse_fixture_response(contents: &[u8]) -> io::Result<(String, String)> {
    let text = std::str::from_utf8(contents)
        .map_err(|error| io::Error::new(io::ErrorKind::InvalidData, error))?;
    let mut lines = text.lines();
    let request_id = lines
        .next()
        .and_then(|line| line.strip_prefix("request_id="))
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "missing fixture request_id"))?;
    let payload = lines
        .next()
        .and_then(|line| line.strip_prefix("payload="))
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "missing fixture payload"))?;
    if lines.next().is_some() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "extra fixture response fields",
        ));
    }
    if format!("request_id={request_id}\npayload={payload}\n").as_bytes() != contents {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "fixture response is not canonically encoded",
        ));
    }
    Ok((request_id.into(), payload.into()))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn canonical_fixture_response_is_strictly_parsed() {
        assert_eq!(
            parse_fixture_response(b"request_id=request-1\npayload=opaque\n").unwrap(),
            ("request-1".into(), "opaque".into())
        );
        assert!(parse_fixture_response(b"request_id=request-1\nwrong=opaque\n").is_err());
        assert!(parse_fixture_response(b"request_id=request-1\r\npayload=opaque\r\n").is_err());
        assert!(parse_fixture_response(b"request_id=request-1\npayload=opaque").is_err());
    }
}
