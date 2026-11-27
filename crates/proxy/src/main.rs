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
  --drain <seconds>   how long open connections may finish after a graceful
                      stop or binary upgrade (default 60)

signals (run):
  SIGTERM, SIGINT     stop now
  SIGQUIT             stop accepting, let open connections finish, stop
  SIGUSR1             reopen access log files
  SIGUSR2             binary upgrade: start the binary at this path again;
                      it takes over the listening sockets, then this process
                      stops accepting and finishes its connections. A process
                      started by hand on the same --data does the same.

run and serve options:
  --metrics <addr>    serve Prometheus metrics at http://<addr>/metrics
                      (default 127.0.0.1:9145; \"off\" disables)
  --workers <n>       worker threads (default: number of CPUs)
  --runtime <kind>    shared: one multi-threaded runtime (default)
                      per-core: one single-threaded runtime per worker";

#[derive(Clone, Copy, PartialEq)]
enum RuntimeKind {
    Shared,
    PerCore,
}

struct Options {
    metrics: Option<std::net::SocketAddr>,
    workers: usize,
    kind: RuntimeKind,
    data: PathBuf,
    socket: PathBuf,
    node_id: Option<String>,
    drain: std::time::Duration,
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
        metrics: Some(std::net::SocketAddr::from(([127, 0, 0, 1], 9145))),
        workers: std::thread::available_parallelism().map_or(1, |n| n.get()),
        kind: RuntimeKind::Shared,
        data: PathBuf::from("/var/lib/proxelo"),
        socket: PathBuf::from("/run/proxelo/control.sock"),
        node_id: None,
        drain: std::time::Duration::from_secs(60),
    };
    while let [flag, value, rest @ ..] = opts {
        match *flag {
            "--metrics" if *value == "off" => o.metrics = None,
            "--metrics" => o.metrics = Some(value.parse().ok()?),
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
            "--drain" if run => o.drain = std::time::Duration::from_secs(value.parse().ok()?),
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
    // TLS contexts are built here too, so what OpenSSL rejects fails a
    // check or dry-load and not only a live swap.
    proxelo_server::check_tls(&rt)?;
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
    server.set_background(listeners.background());
    listeners.apply(&server, rt).map_err(|e| e.to_string())?;
    eprintln!("serving revision {revision} with {}", describe(o));
    let main = main_runtime()?;
    main.block_on(async {
        let _metrics = start_metrics(&server, o.metrics)?;
        shutdown_signal().await.map_err(|e| e.to_string())
    })
}

/// Serves snapshots pushed by the control plane until terminated. Starts from
/// the last-known-good snapshot when there is one, so traffic is served even
/// while the control plane is down.
fn run(o: Options) -> Result<(), String> {
    let lkg = o.data.join("proxy").join("lkg.snap");
    proxelo_server::set_cache_dir(o.data.join("proxy").join("cache"));
    let upgrade = o.data.join("proxy").join("upgrade.sock");
    // A proxy already running on this data directory hands over its
    // listening sockets: this is a binary upgrade.
    let taken = proxelo_server::take_over(&upgrade)
        .map_err(|e| format!("binary upgrade from {}: {e}", upgrade.display()))?;
    let workers = start_workers(o.workers, o.kind).map_err(|e| e.to_string())?;
    let server = Server::new(Runtime::empty(), o.workers);
    let mut node = Node {
        server,
        listeners: Listeners::new(workers.handles, o.kind == RuntimeKind::PerCore),
        lkg,
        revision: 0,
        hash: Vec::new(),
        snap: None,
        resolved: proxelo_snapshot::Resolved::new(),
        names: Vec::new(),
    };
    node.server.set_background(node.listeners.background());
    let predecessor = taken.map(|(p, sockets)| {
        eprintln!("binary upgrade: took over {} sockets", sockets.len());
        node.listeners.inherit(sockets);
        p
    });

    let restored = match std::fs::read(&node.lkg) {
        Ok(bytes) => match proxelo_snapshot::load(&bytes)
            .map_err(|e| e.to_string())
            .and_then(|snap| node.install(snap))
        {
            Ok(()) => {
                eprintln!(
                    "serving last-known-good revision {} from {}",
                    node.revision,
                    node.lkg.display()
                );
                Ok(())
            }
            Err(e) => Err(format!("{}: {e}", node.lkg.display())),
        },
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
            Err("no last-known-good snapshot".to_owned())
        }
        Err(e) => Err(format!("{}: {e}", node.lkg.display())),
    };
    match restored {
        Ok(()) => {}
        // The old process keeps serving when this one cannot take over what
        // it serves; dropping the predecessor tells it so.
        Err(e) if predecessor.is_some() => return Err(format!("binary upgrade: {e}")),
        Err(e) => eprintln!("{e}; waiting for the control plane"),
    }
    eprintln!("running with {}", describe(&o));

    let client = Client {
        socket: o.socket,
        node_id: o.node_id.unwrap_or_else(hostname),
        version: env!("CARGO_PKG_VERSION").to_owned(),
    };
    let metrics = o.metrics;
    let drain = o.drain;
    main_runtime()?.block_on(async move {
        if let Some(p) = predecessor {
            // Both processes accept until the old one confirms it stopped.
            match tokio::task::spawn_blocking(move || p.ready()).await {
                Ok(Ok(())) => eprintln!("binary upgrade: previous process stopped accepting"),
                Ok(Err(e)) => eprintln!("binary upgrade: previous process: {e}"),
                Err(e) => eprintln!("binary upgrade: {e}"),
            }
        }
        let listener = proxelo_server::listen_upgrade(&upgrade)
            .map_err(|e| format!("{}: {e}", upgrade.display()))?;
        let metrics = start_metrics(&node.server, metrics)?;
        systemd_notify(&format!("READY=1\nMAINPID={}", std::process::id()));
        let handoff = node.listeners.handoff();
        let stop = tokio::select! {
            () = client.run(&mut node, |line| eprintln!("{line}")) => return Ok(()),
            r = signals() => r.map_err(|e| e.to_string())?,
            r = listener.successor(&handoff) => {
                Stop::Upgraded(r.map_err(|e| format!("{}: {e}", upgrade.display()))?)
            }
        };
        let successor = match stop {
            Stop::Upgraded(s) => Some(s),
            // After an upgrade the socket file is the successor's.
            Stop::Now => {
                let _ = std::fs::remove_file(&upgrade);
                return Ok(());
            }
            Stop::Graceful => {
                let _ = std::fs::remove_file(&upgrade);
                None
            }
        };
        systemd_notify("STOPPING=1");
        node.listeners.close();
        if let Some(m) = metrics {
            m.abort();
            let _ = m.await;
        }
        if let Some(s) = successor {
            s.done();
            eprintln!("binary upgrade: the new process serves; finishing connections");
        }
        proxelo_server::drain::start();
        match proxelo_server::drain::wait(drain).await {
            0 => eprintln!("all connections finished"),
            n => eprintln!("closing {n} connections still open"),
        }
        Ok(())
    })
}

/// Why `run` stops.
enum Stop {
    /// SIGINT or SIGTERM.
    Now,
    /// SIGQUIT: stop accepting, let connections finish.
    Graceful,
    /// A new process serves the sockets; finish connections as for SIGQUIT.
    Upgraded(proxelo_server::Successor),
}

/// Waits for a signal that stops `run`. SIGUSR1 reopens access log files;
/// SIGUSR2 starts the binary again for an upgrade.
async fn signals() -> std::io::Result<Stop> {
    use tokio::signal::unix::{SignalKind, signal};
    let mut term = signal(SignalKind::terminate())?;
    let mut quit = signal(SignalKind::quit())?;
    let mut usr1 = signal(SignalKind::user_defined1())?;
    let mut usr2 = signal(SignalKind::user_defined2())?;
    loop {
        tokio::select! {
            r = tokio::signal::ctrl_c() => return r.map(|()| Stop::Now),
            _ = term.recv() => return Ok(Stop::Now),
            _ = quit.recv() => return Ok(Stop::Graceful),
            _ = usr1.recv() => proxelo_server::reopen_logs(),
            _ = usr2.recv() => start_successor(),
        }
    }
}

/// Starts the binary at this process's path with its arguments, as nginx
/// does on USR2. The new process connects to the upgrade socket itself; if
/// it fails, this one carries on.
fn start_successor() {
    let exe = match std::env::current_exe() {
        Ok(p) => p,
        Err(e) => {
            eprintln!("binary upgrade: {e}");
            return;
        }
    };
    match std::process::Command::new(&exe)
        .args(std::env::args_os().skip(1))
        .spawn()
    {
        Ok(mut child) => {
            eprintln!(
                "binary upgrade: started {} (pid {})",
                exe.display(),
                child.id()
            );
            // Reaped here if it exits while this process still runs.
            std::thread::spawn(move || {
                if let Ok(status) = child.wait()
                    && !status.success()
                {
                    eprintln!("binary upgrade: new process exited with {status}");
                }
            });
        }
        Err(e) => eprintln!("binary upgrade: {}: {e}", exe.display()),
    }
}

/// Sends a state to systemd when started as a `Type=notify` unit. After a
/// binary upgrade the new process reports itself as the main process, which
/// needs `NotifyAccess=all`.
fn systemd_notify(state: &str) {
    let Some(path) = std::env::var_os("NOTIFY_SOCKET") else {
        return;
    };
    let Ok(socket) = std::os::unix::net::UnixDatagram::unbound() else {
        return;
    };
    let bytes = path.as_encoded_bytes();
    #[cfg(target_os = "linux")]
    if let Some(name) = bytes.strip_prefix(b"@") {
        use std::os::linux::net::SocketAddrExt;
        if let Ok(addr) = std::os::unix::net::SocketAddr::from_abstract_name(name) {
            let _ = socket.send_to_addr(state.as_bytes(), &addr);
        }
        return;
    }
    let _ = bytes;
    let _ = socket.send_to(state.as_bytes(), &path);
}

/// The snapshot state of a running proxy.
struct Node {
    server: Arc<Server>,
    listeners: Listeners,
    lkg: PathBuf,
    revision: u64,
    hash: Vec<u8>,
    /// The active snapshot, kept to rebuild it when a re-resolved host name
    /// of a `resolve` target changes addresses.
    snap: Option<Snapshot>,
    resolved: proxelo_snapshot::Resolved,
    /// Names to re-resolve, their interval and when they are next due.
    names: Vec<(String, std::time::Duration, std::time::Instant)>,
}

impl Node {
    /// Serves `snap`, resolving its `resolve` names now.
    fn install(&mut self, snap: Snapshot) -> Result<(), String> {
        let names = proxelo_server::resolve_names(&snap);
        let resolved = if names.is_empty() {
            proxelo_snapshot::Resolved::new()
        } else {
            block_in_place(proxelo_server::resolve_all(&names))
        };
        let rt = Runtime::build_with(&snap, &resolved).map_err(|e| e.to_string())?;
        self.listeners
            .apply(&self.server, rt)
            .map_err(|e| e.to_string())?;
        let now = std::time::Instant::now();
        self.names = names.into_iter().map(|(n, d)| (n, d, now + d)).collect();
        self.resolved = resolved;
        self.revision = snap.revision;
        self.hash = snap.hash.clone();
        self.snap = Some(snap);
        Ok(())
    }
}

/// Runs `f` to completion from synchronous code that may itself run inside
/// the single-threaded main runtime.
fn block_in_place<F: std::future::Future + Send>(f: F) -> F::Output
where
    F::Output: Send,
{
    std::thread::scope(|s| {
        s.spawn(|| {
            tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()
                .expect("runtime")
                .block_on(f)
        })
        .join()
        .expect("resolver thread")
    })
}

impl Apply for Node {
    fn active_revision(&self) -> u64 {
        self.revision
    }

    fn active_hash(&self) -> &[u8] {
        &self.hash
    }

    fn tap(&mut self, f: proxelo_sync::TapFilter) {
        proxelo_server::set_tap_filter(f);
    }

    async fn purge(&self, p: proxelo_sync::Purge) -> proxelo_sync::PurgeDone {
        let server = self.server.clone();
        let id = p.id.clone();
        match tokio::task::spawn_blocking(move || server.purge(&p)).await {
            Ok(done) => done,
            Err(e) => proxelo_sync::PurgeDone {
                id,
                removed: 0,
                error: e.to_string(),
            },
        }
    }

    fn tap_events(&mut self) -> Option<proxelo_sync::TapEvents> {
        proxelo_server::take_tap_events()
    }

    fn challenges(&mut self, c: proxelo_sync::Challenges) {
        proxelo_server::set_http_challenges(
            &c.http01
                .into_iter()
                .map(|h| (h.token, h.key_authorization))
                .collect::<Vec<_>>(),
        );
        let errors = proxelo_server::set_tls_challenges(
            &c.tls_alpn01
                .into_iter()
                .map(|t| (t.name, t.chain_pem, t.key_pem))
                .collect::<Vec<_>>(),
        );
        for e in errors {
            eprintln!("{e}");
        }
    }

    /// Re-resolves the `resolve` names that are due; a changed answer
    /// rebuilds the snapshot with the new addresses (nginx resolve).
    async fn tick(&mut self) {
        let now = std::time::Instant::now();
        let due: Vec<(String, std::time::Duration)> = self
            .names
            .iter()
            .filter(|(_, _, at)| *at <= now)
            .map(|(n, d, _)| (n.clone(), *d))
            .collect();
        if due.is_empty() {
            return;
        }
        for (_, d, at) in &mut self.names {
            if *at <= now {
                *at = now + *d;
            }
        }
        let fresh = proxelo_server::resolve_all(&due).await;
        let mut changed = false;
        for (name, _) in &due {
            // A failed lookup keeps the last addresses, as nginx does.
            if let Some(a) = fresh.get(name)
                && self.resolved.get(name) != Some(a)
            {
                self.resolved.insert(name.clone(), a.clone());
                changed = true;
            }
        }
        let Some(snap) = &self.snap else {
            return;
        };
        if !changed {
            return;
        }
        match Runtime::build_with(snap, &self.resolved) {
            Ok(rt) => {
                if let Err(e) = self.listeners.apply(&self.server, rt) {
                    eprintln!("re-resolved targets: {e}");
                }
            }
            Err(e) => eprintln!("re-resolved targets: {e}"),
        }
    }

    fn stats(&self) -> proxelo_sync::Stats {
        let t = proxelo_server::metrics::totals();
        let per = proxelo_server::metrics::per_resource(&self.server);
        proxelo_sync::Stats {
            revision: self.revision,
            requests: t.requests,
            server_errors: t.server_errors,
            upstream_attempts: t.upstream_attempts,
            upstream_failures: t.upstream_failures,
            sites: per
                .sites
                .into_iter()
                .map(|(id, c)| proxelo_sync::SiteStats {
                    id,
                    requests: c.requests,
                    server_errors: c.server_errors,
                })
                .collect(),
            routes: per
                .routes
                .into_iter()
                .map(|(site_id, id, c)| proxelo_sync::RouteStats {
                    site_id,
                    id,
                    requests: c.requests,
                    server_errors: c.server_errors,
                })
                .collect(),
            targets: per
                .targets
                .into_iter()
                .map(|t| proxelo_sync::TargetStats {
                    upstream_id: t.upstream,
                    address: t.address,
                    attempts: t.attempts,
                    failures: t.failures,
                    healthy: t.healthy,
                    check_error: t.check_error,
                })
                .collect(),
        }
    }

    fn apply(&mut self, snap: Snapshot, bytes: &[u8]) -> Result<(), String> {
        self.install(snap)?;
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

/// Waits for SIGINT or SIGTERM, for `serve`. SIGUSR1 reopens access log
/// files, for rotation, as in nginx.
async fn shutdown_signal() -> std::io::Result<()> {
    use tokio::signal::unix::{SignalKind, signal};
    let mut term = signal(SignalKind::terminate())?;
    let mut usr1 = signal(SignalKind::user_defined1())?;
    loop {
        tokio::select! {
            r = tokio::signal::ctrl_c() => return r,
            _ = term.recv() => return Ok(()),
            _ = usr1.recv() => proxelo_server::reopen_logs(),
        }
    }
}

/// Serves `GET /metrics` on `addr`, apart from traffic listeners
/// (a separate port, localhost by default).
fn start_metrics(
    server: &Arc<Server>,
    addr: Option<std::net::SocketAddr>,
) -> Result<Option<tokio::task::JoinHandle<()>>, String> {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    let Some(addr) = addr else {
        return Ok(None);
    };
    let std = std::net::TcpListener::bind(addr).map_err(|e| format!("metrics {addr}: {e}"))?;
    std.set_nonblocking(true).map_err(|e| e.to_string())?;
    let listener = tokio::net::TcpListener::from_std(std).map_err(|e| e.to_string())?;
    let server = server.clone();
    let task = tokio::spawn(async move {
        loop {
            let Ok((mut s, _)) = listener.accept().await else {
                continue;
            };
            let server = server.clone();
            tokio::spawn(async move {
                let mut buf = [0u8; 2048];
                let mut n = 0;
                while !buf[..n].windows(4).any(|w| w == b"\r\n\r\n") && n < buf.len() {
                    match s.read(&mut buf[n..]).await {
                        Ok(0) | Err(_) => return,
                        Ok(k) => n += k,
                    }
                }
                let line = buf[..n].split(|&c| c == b'\r').next().unwrap_or_default();
                let (status, body) = if line.starts_with(b"GET /metrics ") {
                    ("200 OK", proxelo_server::metrics::render(&server))
                } else {
                    ("404 Not Found", String::new())
                };
                let head = format!(
                    "HTTP/1.1 {status}\r\nContent-Type: text/plain; version=0.0.4\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
                    body.len()
                );
                let _ = s.write_all(head.as_bytes()).await;
                let _ = s.write_all(body.as_bytes()).await;
            });
        }
    });
    eprintln!("metrics on http://{addr}/metrics");
    Ok(Some(task))
}
