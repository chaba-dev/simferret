use std::env;
use std::io;
use std::path::PathBuf;
use std::process::ExitCode;

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
        Some(command) if command == "run" => {
            let mut scenario = None;
            let mut seed = None;
            let mut workload = None;
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
                    Some("--workload") if workload.is_none() => {
                        workload = Some(PathBuf::from(value));
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
                workload,
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
            println!(
                "replay: simferret replay {}",
                shell_quote(&result.directory.canonicalize()?)?
            );
            Ok(result.exit_code() as u8)
        }
        Some(command) if command == "workload" => {
            let subcommand = arguments
                .next()
                .and_then(|value| value.into_string().ok())
                .ok_or_else(usage)?;
            match subcommand.as_str() {
                "assemble" => {
                    let mut specification = None;
                    let mut store = None;
                    while let Some(option) = arguments.next() {
                        let value = arguments.next().ok_or_else(usage)?;
                        match option.to_str() {
                            Some("--specification") if specification.is_none() => {
                                specification = Some(PathBuf::from(value));
                            }
                            Some("--store") if store.is_none() => {
                                store = Some(PathBuf::from(value));
                            }
                            _ => return Err(usage()),
                        }
                    }
                    let result = simferret::workload::assemble(
                        &specification.ok_or_else(usage)?,
                        &store.ok_or_else(usage)?,
                    )?;
                    println!("source: {}", result.source_kind.name());
                    println!("canonical: {}", result.canonical_digest);
                    println!("closure: {}", result.closure_sha256);
                    println!("tree: {}", result.tree_sha256);
                    println!("template: {}", result.template_sha256);
                    println!("executable: {}", result.launch.executable);
                    println!("entries: {}", result.entries);
                    println!("expanded bytes: {}", result.expanded_bytes);
                    println!("raw objects: {}", result.raw_objects);
                    Ok(0)
                }
                "verify" => {
                    let store = arguments.next().ok_or_else(usage)?;
                    if arguments.next().is_some() {
                        return Err(usage());
                    }
                    let result = simferret::workload::load(&PathBuf::from(store))?;
                    println!("source: {}", result.source_kind.name());
                    println!("canonical: {}", result.canonical_digest);
                    println!("closure: {}", result.closure_sha256);
                    println!("executable: {}", result.launch.executable);
                    println!("entries: {}", result.tree.len());
                    println!("template bytes: {}", result.template.len());
                    Ok(0)
                }
                _ => Err(usage()),
            }
        }
        Some(command) if command == "replay" => {
            let directory = arguments.next().ok_or_else(usage)?;
            if arguments.next().is_some() {
                return Err(usage());
            }
            let kernel = env::var_os("SIMFERRET_KERNEL")
                .map(PathBuf::from)
                .ok_or_else(|| {
                    io::Error::new(io::ErrorKind::NotFound, "SIMFERRET_KERNEL is not set")
                })?;
            let result = simferret::run::replay(&simferret::run::ReplayOptions {
                directory: PathBuf::from(directory),
                kernel,
                executable: env::current_exe()?,
            })?;
            println!("replay: verified");
            println!("run: {}", result.run_id);
            println!("events: {} byte-identical", result.event_count);
            println!("semantic outcome: {}", result.semantic_outcome_sha256);
            println!(
                "assertions: {}",
                if result.assertions.passed {
                    "passed"
                } else {
                    "failed"
                }
            );
            Ok(result.exit_code() as u8)
        }
        _ => Err(usage()),
    }
}

fn shell_quote(path: &std::path::Path) -> io::Result<String> {
    let path = path
        .to_str()
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidInput, "replay path is not UTF-8"))?;
    Ok(format!("'{}'", path.replace('\'', "'\"'\"'")))
}

fn usage() -> io::Error {
    io::Error::new(
        io::ErrorKind::InvalidInput,
        "usage: simferret run --scenario PATH --seed N [--workload SPECIFICATION] [--runs-dir PATH] | simferret replay RUN_DIRECTORY | simferret workload assemble --specification PATH --store PATH | simferret workload verify STORE | simferret guest-agent",
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn replay_path_is_shell_quoted() {
        assert_eq!(
            shell_quote(std::path::Path::new("run dir/it's;safe")).unwrap(),
            "'run dir/it'\"'\"'s;safe'"
        );
    }
}
