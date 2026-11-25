use std::path::{Path, PathBuf};
use std::process::ExitCode;
use std::sync::Arc;

use proxelo_api::snapshot::v1::Snapshot;
use proxelo_server::{Listeners, Server};
use proxelo_snapshot::Runtime;
use proxelo_sync::{Apply, Client};

#[cfg(feature = "jemalloc")]
#[global_allocator]
static ALLOC: tikv_jemallocator::Jemalloc = tikv_jemallocator::Jemalloc;

#[cfg(feature = "mimalloc")]
#[global_allocator]
static ALLOC: mimalloc::MiMalloc = mimalloc::MiMalloc;

const USAGE: &str = "\
usage: proxelo-proxy <command>

commands:
  run [options]               serve snapshots pushed by the control plane
  serve <file> [options]      serve traffic from a serialized snapshot
  check <file>                validate a serialized snapshot
  sim                         dry-load helper for the control plane: reads
                              length-delimited proxelo.sim.v1.SimRequest
                              messages on stdin, answers SimResponse on stdout
  version                     print the version

run options:
  --data <dir>        data directory; the last-known-good snapshot is kept
                      in <dir>/proxy/lkg.snap (default /var/lib/proxelo)
  --socket <path>     control plane socket (default /run/proxelo/control.sock)
  --node-id <id>      name reported to the control plane (default: host name)

run and serve options:
  --workers <n>       worker threads (default: number of CPUs)
  --runtime <kind>    shared: one multi-threaded runtime (default)
                      per-core: one single-threaded runtime per worker";

#[derive(Clone, Copy, PartialEq)]
enum RuntimeKind {
    Shared,
    PerCore,
}

struct Options {
    workers: usize,
    kind: RuntimeKind,
    data: PathBuf,
    socket: PathBuf,
    node_id: Option<String>,
}

fn main() -> ExitCode {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let args: Vec<&str> = args.iter().map(String::as_str).collect();
    match args.as_slice() {
        ["version"] => {
            println!("proxelo-proxy {}", env!("CARGO_PKG_VERSION"));
            ExitCode::SUCCESS
        }
        ["check", path] => match load(Path::new(path)) {
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
            Err(e) => fail(&e),
        },
        ["serve", path, opts @ ..] => match parse_options(opts, false) {
            Some(o) => exit(serve(Path::new(path), &o)),
            None => usage(),
        },
        ["sim"] => exit(sim()),
        ["run", opts @ ..] => match parse_options(opts, true) {
            Some(o) => exit(run(o)),
            None => usage(),
        },
        _ => usage(),
    }
}

fn usage() -> ExitCode {
    eprintln!("{USAGE}");
    ExitCode::from(2)
}

fn fail(e: &str) -> ExitCode {
    eprintln!("{e}");
    ExitCode::FAILURE
}

fn exit(r: Result<(), String>) -> ExitCode {
    match r {
        Ok(()) => ExitCode::SUCCESS,
        Err(e) => fail(&e),
    }
}

fn parse_options(mut opts: &[&str], run: bool) -> Option<Options> {
    let mut o = Options {
        workers: std::thread::available_parallelism().map_or(1, |n| n.get()),
        kind: RuntimeKind::Shared,
        data: PathBuf::from("/var/lib/proxelo"),
        socket: PathBuf::from("/run/proxelo/control.sock"),
        node_id: None,
    };
    while let [flag, value, rest @ ..] = opts {
        match *flag {
            "--workers" => o.workers = value.parse().ok().filter(|&n| n > 0)?,
            "--runtime" => {
                o.kind = match *value {
                    "shared" => RuntimeKind::Shared,
                    "per-core" => RuntimeKind::PerCore,
                    _ => return None,
                }
            }
            "--data" if run => o.data = PathBuf::from(value),
            "--socket" if run => o.socket = PathBuf::from(value),
            "--node-id" if run && !value.is_empty() => o.node_id = Some((*value).to_owned()),
            _ => return None,
        }
        opts = rest;
    }
    opts.is_empty().then_some(o)
}

/// Reads, validates and builds a snapshot. Checking a snapshot builds it too,
/// so `check` rejects what `serve` would reject.
fn load(path: &Path) -> Result<(Snapshot, Runtime), String> {
    let bytes = std::fs::read(path).map_err(|e| format!("{}: {e}", path.display()))?;
    build(&bytes).map_err(|e| format!("{}: {e}", path.display()))
}

fn build(bytes: &[u8]) -> Result<(Snapshot, Runtime), String> {
    let snap = proxelo_snapshot::load(bytes).map_err(|e| e.to_string())?;
    let rt = Runtime::build(&snap).map_err(|e| e.to_string())?;
    Ok((snap, rt))
}

/// Runtimes the simulator keeps, by snapshot bytes: the active revision and
/// a draft are compared back and forth without rebuilding either.
const SIM_CACHE: usize = 4;

/// The dry-load helper: loads snapshots exactly as `run` does
/// and runs requests through the serving phases. One response per request
/// message, until stdin closes.
fn sim() -> Result<(), String> {
    use std::io::Write;

    use prost::Message;
    use proxelo_api::sim::v1::{SimRequest, SimResponse};

    let mut input = std::io::stdin().lock();
    let mut output = std::io::stdout().lock();
    // Snapshots are small; equal bytes are what makes a cached build reusable.
    let mut cache: Vec<(Vec<u8>, Runtime)> = Vec::new();
    while let Some(msg) = read_frame(&mut input).map_err(|e| e.to_string())? {
        let req = SimRequest::decode(msg.as_slice()).map_err(|e| e.to_string())?;
        let mut resp = SimResponse::default();
        if let Some(i) = cache.iter().position(|(b, _)| *b == req.snapshot) {
            let entry = cache.remove(i);
            cache.push(entry);
        } else {
            match build(&req.snapshot) {
                Ok((_, rt)) => {
                    if cache.len() == SIM_CACHE {
                        cache.remove(0);
                    }
                    cache.push((req.snapshot, rt));
                }
                Err(e) => resp.error = e,
            }
        }
        if resp.error.is_empty()
            && let Some((_, rt)) = cache.last()
        {
            resp.results = req
                .requests
                .iter()
                .map(|r| proxelo_server::simulate(rt, r))
                .collect();
        }
        output
            .write_all(&resp.encode_length_delimited_to_vec())
            .and_then(|()| output.flush())
            .map_err(|e| e.to_string())?;
    }
    Ok(())
}

/// Largest simulator message accepted, a bound on what a bad length prefix
/// can make the helper allocate.
const MAX_FRAME: u64 = 64 << 20;

/// Reads one varint length-prefixed message; `None` at end of input.
fn read_frame(r: &mut impl std::io::Read) -> std::io::Result<Option<Vec<u8>>> {
    let mut len = 0u64;
    for shift in (0..64).step_by(7) {
        let mut b = [0u8];
        if r.read(&mut b)? == 0 {
            if shift == 0 {
                return Ok(None);
            }
            return Err(std::io::ErrorKind::UnexpectedEof.into());
        }
        len |= u64::from(b[0] & 0x7f) << shift;
        if b[0] & 0x80 == 0 {
            if len > MAX_FRAME {
                return Err(std::io::Error::other("message too large"));
            }
            let mut msg = vec![0; len as usize];
            r.read_exact(&mut msg)?;
            return Ok(Some(msg));
        }
    }
    Err(std::io::Error::other("bad length prefix"))
}

/// Worker runtimes. Shared: one multi-threaded runtime, sockets accepted on
/// it and connections spread by its scheduler. Per-core: one single-threaded
/// runtime per worker thread, each with its own SO_REUSEPORT sockets, so the
/// kernel spreads connections and each stays on the thread that accepted it.
struct Workers {
    handles: Vec<tokio::runtime::Handle>,
    // Kept alive for the life of the process.
    _shared: Option<tokio::runtime::Runtime>,
}

fn start_workers(n: usize, kind: RuntimeKind) -> std::io::Result<Workers> {
    if kind == RuntimeKind::Shared {
        let next = std::sync::atomic::AtomicUsize::new(0);
        let rt = tokio::runtime::Builder::new_multi_thread()
            .worker_threads(n)
            .on_thread_start(move || {
                proxelo_server::set_worker_id(
                    next.fetch_add(1, std::sync::atomic::Ordering::Relaxed),
                );
            })
            .enable_all()
            .build()?;
        return Ok(Workers {
            handles: vec![rt.handle().clone()],
            _shared: Some(rt),
        });
    }
    let mut handles = Vec::with_capacity(n);
    for id in 0..n {
        let rt = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()?;
        handles.push(rt.handle().clone());
        std::thread::Builder::new()
            .name(format!("worker-{id}"))
            .spawn(move || {
                proxelo_server::set_worker_id(id);
                // Runs the tasks spawned onto this worker until exit.
                rt.block_on(std::future::pending::<()>());
            })?;
    }
    Ok(Workers {
        handles,
        _shared: None,
    })
}

fn describe(o: &Options) -> String {
    format!(
        "{} workers ({})",
        o.workers,
        if o.kind == RuntimeKind::PerCore {
            "per-core"
        } else {
            "shared"
        }
    )
}

/// Serves one snapshot file until terminated.
fn serve(path: &Path, o: &Options) -> Result<(), String> {
    let (_, rt) = load(path)?;
    let workers = start_workers(o.workers, o.kind).map_err(|e| e.to_string())?;
    let revision = rt.revision;
    let server = Server::new(Runtime::empty(), o.workers);
    let mut listeners = Listeners::new(workers.handles, o.kind == RuntimeKind::PerCore);
    listeners.apply(&server, rt).map_err(|e| e.to_string())?;
    eprintln!("serving revision {revision} with {}", describe(o));
    main_runtime()?
        .block_on(shutdown_signal())
        .map_err(|e| e.to_string())
}

/// Serves snapshots pushed by the control plane until terminated. Starts from
/// the last-known-good snapshot when there is one, so traffic is served even
/// while the control plane is down.
fn run(o: Options) -> Result<(), String> {
    let lkg = o.data.join("proxy").join("lkg.snap");
    let workers = start_workers(o.workers, o.kind).map_err(|e| e.to_string())?;
    let server = Server::new(Runtime::empty(), o.workers);
    let mut node = Node {
        server,
        listeners: Listeners::new(workers.handles, o.kind == RuntimeKind::PerCore),
        lkg,
        revision: 0,
        hash: Vec::new(),
    };

    match std::fs::read(&node.lkg) {
        Ok(bytes) => match build(&bytes) {
            Ok((snap, rt)) => match node.listeners.apply(&node.server, rt) {
                Ok(()) => {
                    node.revision = snap.revision;
                    node.hash = snap.hash;
                    eprintln!(
                        "serving last-known-good revision {} from {}",
                        node.revision,
                        node.lkg.display()
                    );
                }
                Err(e) => eprintln!("{}: {e}; waiting for the control plane", node.lkg.display()),
            },
            Err(e) => eprintln!("{}: {e}; waiting for the control plane", node.lkg.display()),
        },
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
            eprintln!("no last-known-good snapshot; waiting for the control plane");
        }
        Err(e) => eprintln!("{}: {e}; waiting for the control plane", node.lkg.display()),
    }
    eprintln!("running with {}", describe(&o));

    let client = Client {
        socket: o.socket,
        node_id: o.node_id.unwrap_or_else(hostname),
        version: env!("CARGO_PKG_VERSION").to_owned(),
    };
    main_runtime()?.block_on(async move {
        tokio::select! {
            () = client.run(&mut node, |line| eprintln!("{line}")) => Ok(()),
            r = shutdown_signal() => r.map_err(|e| e.to_string()),
        }
    })
}

/// The snapshot state of a running proxy.
struct Node {
    server: Arc<Server>,
    listeners: Listeners,
    lkg: PathBuf,
    revision: u64,
    hash: Vec<u8>,
}

impl Apply for Node {
    fn active_revision(&self) -> u64 {
        self.revision
    }

    fn active_hash(&self) -> &[u8] {
        &self.hash
    }

    fn apply(&mut self, snap: Snapshot, bytes: &[u8]) -> Result<(), String> {
        proxelo_snapshot::validate(&snap).map_err(|e| e.to_string())?;
        let rt = Runtime::build(&snap).map_err(|e| e.to_string())?;
        self.listeners
            .apply(&self.server, rt)
            .map_err(|e| e.to_string())?;
        self.revision = snap.revision;
        self.hash = snap.hash;
        // The snapshot is live either way; a failed write only means a
        // restart without the control plane comes up on an older one.
        if let Err(e) = write_atomic(&self.lkg, bytes) {
            eprintln!("{}: {e}", self.lkg.display());
        }
        Ok(())
    }
}

/// Writes `bytes` to `path` so that a crash leaves either the old file or the
/// new one, never a torn file.
fn write_atomic(path: &Path, bytes: &[u8]) -> std::io::Result<()> {
    use std::io::Write;
    let dir = path.parent().unwrap_or(Path::new("."));
    std::fs::create_dir_all(dir)?;
    let tmp = path.with_extension("tmp");
    let mut f = std::fs::File::create(&tmp)?;
    f.write_all(bytes)?;
    f.sync_all()?;
    std::fs::rename(&tmp, path)?;
    std::fs::File::open(dir)?.sync_all()
}

fn hostname() -> String {
    std::fs::read_to_string("/etc/hostname")
        .ok()
        .map(|s| s.trim().to_owned())
        .filter(|s| !s.is_empty())
        .or_else(|| std::env::var("HOSTNAME").ok().filter(|s| !s.is_empty()))
        .unwrap_or_else(|| "proxy".to_owned())
}

fn main_runtime() -> Result<tokio::runtime::Runtime, String> {
    tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .map_err(|e| e.to_string())
}

async fn shutdown_signal() -> std::io::Result<()> {
    use tokio::signal::unix::{SignalKind, signal};
    let mut term = signal(SignalKind::terminate())?;
    tokio::select! {
        r = tokio::signal::ctrl_c() => r,
        _ = term.recv() => Ok(()),
    }
}
