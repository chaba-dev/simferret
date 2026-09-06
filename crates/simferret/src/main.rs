use std::env;
use std::io::{self, Read, Write};
use std::path::PathBuf;
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
    let command = arguments.next().and_then(|value| value.into_string().ok());
    if command.is_none() && std::process::id() == 1 {
        return Ok(simferret::guest::init()? as u8);
    }
    match command {
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
        Some(command) if command == "guest-init" => {
            if arguments.next().is_some() {
                return Err(usage());
            }
            Ok(simferret::guest::init()? as u8)
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
        Some(command) if command == "run" => {
            let mut scenario = None;
            let mut seed = None;
            let mut runs_directory = PathBuf::from("runs");
            while let Some(option) = arguments.next() {
                let value = arguments.next().ok_or_else(usage)?;
                match option.to_str() {
                    Some("--scenario") if scenario.is_none() => {
                        scenario = Some(PathBuf::from(value));
                    }
                    Some("--seed") if seed.is_none() => {
                        seed = Some(
                            value
                                .to_str()
                                .ok_or_else(usage)?
                                .parse()
                                .map_err(|_| usage())?,
                        );
                    }
                    Some("--runs-dir") => runs_directory = PathBuf::from(value),
                    _ => return Err(usage()),
                }
            }
            let kernel = env::var_os("SIMFERRET_KERNEL")
                .map(PathBuf::from)
                .ok_or_else(|| {
                    io::Error::new(io::ErrorKind::NotFound, "SIMFERRET_KERNEL is not set")
                })?;
            let result = simferret::run::record(&simferret::run::RunOptions {
                scenario: scenario.ok_or_else(usage)?,
                seed: seed.ok_or_else(usage)?,
                runs_directory,
                kernel,
                executable: env::current_exe()?,
            })?;
            println!("run: {}", result.run_id);
            println!(
                "assertions: {}",
                if result.assertions.passed {
                    "passed"
                } else {
                    "failed"
                }
            );
            println!("artifacts: {}", result.directory.display());
            println!("replay: simferret replay {}", result.directory.display());
            Ok(result.assertions.exit_code() as u8)
        }
        _ => Err(usage()),
    }
}

fn usage() -> io::Error {
    io::Error::new(
        io::ErrorKind::InvalidInput,
        "usage: simferret run --scenario PATH --seed N [--runs-dir PATH] | simferret guest-agent | simferret guest-init | simferret fixture-server ADDRESS echo|corrupt",
    )
}
