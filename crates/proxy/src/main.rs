use std::process::ExitCode;

const USAGE: &str = "\
usage: proxelo-proxy <command>

commands:
  check <file>   validate a serialized snapshot
  version        print the version";

fn main() -> ExitCode {
    let args: Vec<String> = std::env::args().skip(1).collect();
    match args
        .iter()
        .map(String::as_str)
        .collect::<Vec<_>>()
        .as_slice()
    {
        ["version"] => {
            println!("proxelo-proxy {}", env!("CARGO_PKG_VERSION"));
            ExitCode::SUCCESS
        }
        ["check", path] => check(path),
        _ => {
            eprintln!("{USAGE}");
            ExitCode::from(2)
        }
    }
}

fn check(path: &str) -> ExitCode {
    let bytes = match std::fs::read(path) {
        Ok(b) => b,
        Err(e) => {
            eprintln!("{path}: {e}");
            return ExitCode::FAILURE;
        }
    };
    match proxelo_snapshot::load(&bytes) {
        Ok(snap) => {
            println!(
                "ok: revision {}, {} listeners, {} sites, {} upstreams",
                snap.revision,
                snap.listeners.len(),
                snap.sites.len(),
                snap.upstreams.len()
            );
            ExitCode::SUCCESS
        }
        Err(e) => {
            eprintln!("{path}: {e}");
            ExitCode::FAILURE
        }
    }
}
