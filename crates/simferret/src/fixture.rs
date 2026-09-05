use std::io;
use std::net::{SocketAddr, TcpListener, TcpStream};
use std::time::Duration;

use serde::{Deserialize, Serialize};

use crate::protocol::{read_frame, write_frame};

const IO_TIMEOUT: Duration = Duration::from_secs(2);
pub const SERVER_READY: &[u8] = b"SIMFERRET_SERVER_READY_V1\n";

#[derive(Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct EchoMessage {
    request_id: String,
    payload: String,
}

pub fn serve(address: &str, corrupt_responses: bool) -> io::Result<()> {
    let listener = bind(address)?;
    serve_listener(listener, corrupt_responses)
}

pub fn bind(address: &str) -> io::Result<TcpListener> {
    TcpListener::bind(address)
}

pub fn serve_listener(listener: TcpListener, corrupt_responses: bool) -> io::Result<()> {
    for connection in listener.incoming() {
        let mut stream = connection?;
        stream.set_read_timeout(Some(IO_TIMEOUT))?;
        stream.set_write_timeout(Some(IO_TIMEOUT))?;
        let Some(mut message) = read_frame::<EchoMessage>(&mut stream)? else {
            continue;
        };
        if corrupt_responses {
            message.payload.push_str("-corrupted");
        }
        write_frame(&mut stream, &message)?;
    }
    Ok(())
}

pub fn request(address: &str, request_id: &str, payload: &str) -> io::Result<(String, String)> {
    let address: SocketAddr = address
        .parse()
        .map_err(|error| io::Error::new(io::ErrorKind::InvalidInput, error))?;
    let mut stream = TcpStream::connect_timeout(&address, IO_TIMEOUT)?;
    stream.set_read_timeout(Some(IO_TIMEOUT))?;
    stream.set_write_timeout(Some(IO_TIMEOUT))?;
    write_frame(
        &mut stream,
        &EchoMessage {
            request_id: request_id.into(),
            payload: payload.into(),
        },
    )?;
    let response: EchoMessage = read_frame(&mut stream)?
        .ok_or_else(|| io::Error::new(io::ErrorKind::UnexpectedEof, "server closed connection"))?;
    Ok((response.request_id, response.payload))
}

#[cfg(test)]
mod tests {
    use std::thread;

    use super::*;

    #[test]
    fn echo_server_returns_input_and_can_intentionally_corrupt_payload() {
        for corrupt in [false, true] {
            let listener = TcpListener::bind("127.0.0.1:0").unwrap();
            let address = listener.local_addr().unwrap().to_string();
            thread::spawn(move || serve_listener(listener, corrupt).unwrap());
            let response = request(&address, "request-1", "opaque").unwrap();
            assert_eq!(response.0, "request-1");
            if corrupt {
                assert_ne!(response.1, "opaque");
            } else {
                assert_eq!(response.1, "opaque");
            }
        }
    }
}
