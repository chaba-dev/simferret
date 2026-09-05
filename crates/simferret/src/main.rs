use std::env;
use std::io::{self, Read, Write};
use std::process::ExitCode;
use std::thread;

fn main() -> ExitCode {
    match run() {
        Ok(code) => ExitCode::from(code),
        Err(error) => {
            eprintln!("simferret: {error}");
            ExitCode::FAILURE
        }
    }
}

fn run() -> io::Result<u8> {
    let mut arguments = env::args_os();
    let _program = arguments.next();
    match arguments.next().and_then(|value| value.into_string().ok()) {
        Some(command) if command == "guest-agent" => {
            if arguments.next().is_some() {
                return Err(usage());
            }
            let executable = env::current_exe()?;
            let status = simferret::agent::run(
                &mut io::stdin().lock(),
                &mut io::stdout().lock(),
                &executable,
            )?;
            Ok(status as u8)
        }
        Some(command) if command == "fixture-server" => {
            let address = arguments
                .next()
                .and_then(|value| value.into_string().ok())
                .ok_or_else(usage)?;
            let mode = arguments
                .next()
                .and_then(|value| value.into_string().ok())
                .ok_or_else(usage)?;
            if arguments.next().is_some() || !matches!(mode.as_str(), "echo" | "corrupt") {
                return Err(usage());
            }
            let listener = simferret::fixture::bind(&address)?;
            thread::Builder::new()
                .name("agent-watchdog".into())
                .spawn(|| {
                    let mut input = io::stdin().lock();
                    let mut byte = [0_u8; 1];
                    loop {
                        match input.read(&mut byte) {
                            Ok(0) => std::process::exit(2),
                            Ok(_) => {}
                            Err(error) if error.kind() == io::ErrorKind::Interrupted => {}
                            Err(_) => std::process::exit(2),
                        }
                    }
                })
                .map_err(io::Error::other)?;
            io::stdout().write_all(simferret::fixture::SERVER_READY)?;
            io::stdout().flush()?;
            simferret::fixture::serve_listener(listener, mode == "corrupt")?;
            Ok(0)
        }
        _ => Err(usage()),
    }
}

fn usage() -> io::Error {
    io::Error::new(
        io::ErrorKind::InvalidInput,
        "usage: simferret guest-agent | simferret fixture-server ADDRESS echo|corrupt",
    )
}
