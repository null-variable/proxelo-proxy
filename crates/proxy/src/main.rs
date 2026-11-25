use std::process::ExitCode;
use std::sync::Arc;

use proxelo_server::Server;
use proxelo_snapshot::Runtime;

#[cfg(feature = "jemalloc")]
#[global_allocator]
static ALLOC: tikv_jemallocator::Jemalloc = tikv_jemallocator::Jemalloc;

#[cfg(feature = "mimalloc")]
#[global_allocator]
static ALLOC: mimalloc::MiMalloc = mimalloc::MiMalloc;

const USAGE: &str = "\
usage: proxelo-proxy <command>

commands:
  check <file>                validate a serialized snapshot
  serve <file> [options]      serve traffic from a serialized snapshot
  version                     print the version

serve options:
  --workers <n>       worker threads (default: number of CPUs)
  --runtime <kind>    shared: one multi-threaded runtime (default)
                      per-core: one single-threaded runtime per worker";

#[derive(Clone, Copy, PartialEq)]
enum RuntimeKind {
    Shared,
    PerCore,
}

fn main() -> ExitCode {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let args: Vec<&str> = args.iter().map(String::as_str).collect();
    match args.as_slice() {
        ["version"] => {
            println!("proxelo-proxy {}", env!("CARGO_PKG_VERSION"));
            ExitCode::SUCCESS
        }
        ["check", path] => match load(path) {
            Ok((snap, _)) => {
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
                eprintln!("{e}");
                ExitCode::FAILURE
            }
        },
        ["serve", path, opts @ ..] => match parse_serve(opts) {
            Some((workers, kind)) => serve(path, workers, kind),
            None => usage(),
        },
        _ => usage(),
    }
}

fn usage() -> ExitCode {
    eprintln!("{USAGE}");
    ExitCode::from(2)
}

fn parse_serve(mut opts: &[&str]) -> Option<(usize, RuntimeKind)> {
    let mut workers = std::thread::available_parallelism().map_or(1, |n| n.get());
    let mut kind = RuntimeKind::Shared;
    while let [flag, value, rest @ ..] = opts {
        match *flag {
            "--workers" => workers = value.parse().ok().filter(|&n| n > 0)?,
            "--runtime" => {
                kind = match *value {
                    "shared" => RuntimeKind::Shared,
                    "per-core" => RuntimeKind::PerCore,
                    _ => return None,
                }
            }
            _ => return None,
        }
        opts = rest;
    }
    opts.is_empty().then_some((workers, kind))
}

/// Reads, validates and builds a snapshot. Checking a snapshot builds it too,
/// so `check` rejects what `serve` would reject.
fn load(path: &str) -> Result<(proxelo_api::snapshot::v1::Snapshot, Runtime), String> {
    let bytes = std::fs::read(path).map_err(|e| format!("{path}: {e}"))?;
    let snap = proxelo_snapshot::load(&bytes).map_err(|e| format!("{path}: {e}"))?;
    let rt = Runtime::build(&snap).map_err(|e| format!("{path}: {e}"))?;
    Ok((snap, rt))
}

fn serve(path: &str, workers: usize, kind: RuntimeKind) -> ExitCode {
    let rt = match load(path) {
        Ok((_, rt)) => rt,
        Err(e) => {
            eprintln!("{e}");
            return ExitCode::FAILURE;
        }
    };
    // Shared runtime: one socket per address, spread by the scheduler.
    // Per-core: one SO_REUSEPORT socket per address and worker, so the kernel
    // spreads connections and each stays on the thread that accepted it.
    let per_worker = kind == RuntimeKind::PerCore;
    let mut sockets: Vec<Vec<(usize, std::net::TcpListener)>> =
        (0..if per_worker { workers } else { 1 })
            .map(|_| Vec::new())
            .collect();
    for (i, l) in rt.listeners.iter().enumerate() {
        for &addr in &l.addrs {
            for slot in &mut sockets {
                match proxelo_server::bind(addr, l.reuse_port || per_worker, l.backlog) {
                    Ok(s) => slot.push((i, s)),
                    Err(e) => {
                        eprintln!("listeners[{i}]: bind {addr}: {e}");
                        return ExitCode::FAILURE;
                    }
                }
            }
        }
    }
    eprintln!(
        "serving revision {} with {workers} workers ({})",
        rt.revision,
        if per_worker { "per-core" } else { "shared" }
    );
    let server = Server::new(rt, workers);

    let result = if per_worker {
        run_per_core(server, sockets)
    } else {
        run_shared(server, workers, sockets.pop().unwrap_or_default())
    };
    match result {
        Ok(()) => ExitCode::SUCCESS,
        Err(e) => {
            eprintln!("{e}");
            ExitCode::FAILURE
        }
    }
}

fn run_shared(
    server: Arc<Server>,
    workers: usize,
    sockets: Vec<(usize, std::net::TcpListener)>,
) -> std::io::Result<()> {
    let next = std::sync::atomic::AtomicUsize::new(0);
    let rt = tokio::runtime::Builder::new_multi_thread()
        .worker_threads(workers)
        .on_thread_start(move || {
            proxelo_server::set_worker_id(next.fetch_add(1, std::sync::atomic::Ordering::Relaxed));
        })
        .enable_all()
        .build()?;
    rt.block_on(async move {
        for (i, s) in sockets {
            tokio::spawn(server.clone().accept(i, s));
        }
        shutdown_signal().await
    })
}

fn run_per_core(
    server: Arc<Server>,
    sockets: Vec<Vec<(usize, std::net::TcpListener)>>,
) -> std::io::Result<()> {
    let mut threads = Vec::new();
    for (id, mine) in sockets.into_iter().enumerate() {
        let server = server.clone();
        let rt = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()?;
        threads.push(
            std::thread::Builder::new()
                .name(format!("worker-{id}"))
                .spawn(move || {
                    proxelo_server::set_worker_id(id);
                    rt.block_on(async move {
                        let mut tasks = Vec::new();
                        for (i, s) in mine {
                            tasks.push(tokio::spawn(server.clone().accept(i, s)));
                        }
                        for t in tasks {
                            let _ = t.await;
                        }
                    });
                })?,
        );
    }
    let main = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()?;
    // Worker threads run until the process exits.
    main.block_on(shutdown_signal())
}

async fn shutdown_signal() -> std::io::Result<()> {
    use tokio::signal::unix::{SignalKind, signal};
    let mut term = signal(SignalKind::terminate())?;
    tokio::select! {
        r = tokio::signal::ctrl_c() => r,
        _ = term.recv() => Ok(()),
    }
}
