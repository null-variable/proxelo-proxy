//! proxy-wasm host (ABI 0.2) on wasmtime: route filters and the WAF.
//!
//! Modules arrive from the control plane by hash and are stored under the
//! data directory; compiled code is cached there too, so a restart does not
//! compile again. Each filter keeps a pool of instances that have run
//! `_start`, `proxy_on_vm_start` and `proxy_on_configure`; a request takes
//! one, creates a stream context in it and returns it when done. A trap or
//! an exhausted limit discards the instance.
//!
//! The host offers what HTTP filters use: header maps, request and response
//! bodies, properties, local responses, logs and metrics, plus the WASI
//! preview1 calls a TinyGo or Rust build needs (clocks, randomness, args,
//! environment, stdout and stderr). There is no file system and no network.

use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU32, Ordering};
use std::sync::{Arc, LazyLock, Mutex, OnceLock};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use proxelo_http1::{Body, ChunkedDecoder, HeaderKind, Version, push_hex};
use proxelo_snapshot::{WasmFilter, WasmModule, hex};
use wasmtime::{
    Caller, Config, Engine, Extern, Instance, Linker, Memory, Module, Store, StoreLimits,
    StoreLimitsBuilder, TypedFunc,
};

use crate::conn::{BodyLeft, Conn, Fail, SEND_TIMEOUT, Sink};
use crate::exchange::Exchange;
use crate::io::write_timeout;

/// Epoch ticks per second; callback timeouts are counted in them.
const TICK: Duration = Duration::from_millis(10);
/// Idle instances kept per filter.
const POOL: usize = 8;
/// Context ID of the plugin; streams count up from it.
const ROOT: u32 = 1;
/// Plugin logs below error are dropped; the WAF logs matched rules at
/// critical and its own diagnostics at warn.
const LOG_LEVEL: i32 = 4;

// proxy_status_t
const OK: i32 = 0;
const NOT_FOUND: i32 = 1;
const BAD_ARGUMENT: i32 = 2;
const INVALID_MEMORY_ACCESS: i32 = 6;
const UNIMPLEMENTED: i32 = 12;

// map and buffer types
const REQUEST_HEADERS: i32 = 0;
const RESPONSE_HEADERS: i32 = 2;
const REQUEST_BODY: i32 = 0;
const RESPONSE_BODY: i32 = 1;
const VM_CONFIGURATION: i32 = 6;
const PLUGIN_CONFIGURATION: i32 = 7;

// WASI errno
const ESUCCESS: i32 = 0;
const EBADF: i32 = 8;
const EFAULT: i32 = 21;
const EINVAL: i32 = 28;
const ENOTSUP: i32 = 58;

static ENGINE: OnceLock<Result<Engine, String>> = OnceLock::new();
static DIR: OnceLock<PathBuf> = OnceLock::new();

/// Where modules and compiled code are kept; set once at start.
pub fn set_dir(dir: PathBuf) {
    let _ = DIR.set(dir);
}

fn dir() -> Option<&'static Path> {
    DIR.get().map(PathBuf::as_path)
}

fn engine() -> Result<&'static Engine, String> {
    ENGINE
        .get_or_init(|| {
            let mut c = Config::new();
            c.epoch_interruption(true);
            if let Some(d) = dir() {
                let mut cc = wasmtime::CacheConfig::new();
                cc.with_directory(d.join("compiled"));
                let cache = wasmtime::Cache::new(cc).map_err(|e| e.to_string())?;
                c.cache(Some(cache));
            }
            let e = Engine::new(&c).map_err(|e| e.to_string())?;
            let ticker = e.clone();
            std::thread::Builder::new()
                .name("wasm-epoch".into())
                .spawn(move || {
                    loop {
                        std::thread::sleep(TICK);
                        ticker.increment_epoch();
                    }
                })
                .map_err(|e| e.to_string())?;
            Ok(e)
        })
        .as_ref()
        .map_err(Clone::clone)
}

/// Compiled modules by hash, shared by snapshots.
static MODULES: LazyLock<Mutex<HashMap<[u8; 32], Module>>> =
    LazyLock::new(|| Mutex::new(HashMap::new()));

fn module_path(sha: &[u8; 32]) -> Option<PathBuf> {
    dir().map(|d| d.join("modules").join(format!("{}.wasm", hex(sha))))
}

/// The hashes of the modules stored on disk.
pub fn stored_modules() -> Vec<String> {
    let Some(d) = dir() else {
        return Vec::new();
    };
    let Ok(rd) = std::fs::read_dir(d.join("modules")) else {
        return Vec::new();
    };
    rd.filter_map(|e| {
        let name = e.ok()?.file_name().into_string().ok()?;
        let h = name.strip_suffix(".wasm")?;
        (h.len() == 64 && h.bytes().all(|c| c.is_ascii_hexdigit())).then(|| h.to_owned())
    })
    .collect()
}

/// Stores a module received from the control plane once its bytes hash to
/// `sha256` (lowercase hex).
pub fn store_module(sha256: &str, bytes: &[u8]) -> Result<(), String> {
    let got = hex(&openssl::sha::sha256(bytes));
    if got != sha256 {
        return Err(format!("wasm module {sha256}: bytes hash to {got}"));
    }
    let Some(d) = dir() else {
        return Err("no data directory for wasm modules".into());
    };
    let d = d.join("modules");
    std::fs::create_dir_all(&d).map_err(|e| e.to_string())?;
    let tmp = d.join(format!("{sha256}.tmp"));
    std::fs::write(&tmp, bytes).map_err(|e| e.to_string())?;
    std::fs::rename(&tmp, d.join(format!("{sha256}.wasm"))).map_err(|e| e.to_string())
}

/// The compiled module for `m`, compiling it (or loading the cached code)
/// on first use.
fn compiled(m: &WasmModule) -> Result<Module, String> {
    if let Some(module) = MODULES
        .lock()
        .unwrap_or_else(|e| e.into_inner())
        .get(&m.sha256)
    {
        return Ok(module.clone());
    }
    let path = module_path(&m.sha256).ok_or("no data directory for wasm modules")?;
    let bytes = std::fs::read(&path).map_err(|e| format!("wasm module {}: {e}", m.hex()))?;
    if openssl::sha::sha256(&bytes) != m.sha256 {
        return Err(format!(
            "wasm module {}: stored bytes do not match",
            m.hex()
        ));
    }
    let module =
        Module::new(engine()?, &bytes).map_err(|e| format!("wasm module {}: {e}", m.hex()))?;
    MODULES
        .lock()
        .unwrap_or_else(|e| e.into_inner())
        .insert(m.sha256, module.clone());
    Ok(module)
}

/// A header map as proxy-wasm passes it.
pub(crate) type Pairs = Vec<(Vec<u8>, Vec<u8>)>;

/// The request as a stream context sees it.
#[derive(Default)]
pub(crate) struct Stream {
    pub request_headers: Vec<(Vec<u8>, Vec<u8>)>,
    pub response_headers: Vec<(Vec<u8>, Vec<u8>)>,
    pub request_body: Vec<u8>,
    pub response_body: Vec<u8>,
    /// ("request","path") and the like, joined with NUL.
    pub properties: HashMap<Vec<u8>, Vec<u8>>,
    /// A response the plugin asked to send instead.
    pub local: Option<Local>,
    /// Lines the plugin logged at [`LOG_LEVEL`] or above.
    pub logs: Vec<String>,
    /// Rule IDs in those lines, `[id "N"]` as ModSecurity writes them.
    pub rules: Vec<u32>,
}

pub(crate) struct Local {
    pub status: u16,
    pub headers: Vec<(Vec<u8>, Vec<u8>)>,
    pub body: Vec<u8>,
}

struct Host {
    name: Arc<str>,
    vm_config: Arc<[u8]>,
    plugin_config: Arc<[u8]>,
    stream: Stream,
    limits: StoreLimits,
    /// The plugin exited through proc_exit.
    exited: Option<i32>,
}

struct Exports {
    context_create: TypedFunc<(i32, i32), ()>,
    request_headers: TypedFunc<(i32, i32, i32), i32>,
    request_body: TypedFunc<(i32, i32, i32), i32>,
    response_headers: TypedFunc<(i32, i32, i32), i32>,
    done: Option<TypedFunc<i32, i32>>,
    log: Option<TypedFunc<i32, ()>>,
    delete: Option<TypedFunc<i32, ()>>,
}

struct Vm {
    store: Store<Host>,
    ex: Exports,
    next_context: u32,
}

/// Instances of one filter.
pub(crate) struct Plugin {
    /// What it was built from: the module's hash and the filter with its
    /// module index cleared, to reuse it in the next snapshot.
    sha256: [u8; 32],
    filter: WasmFilter,
    module: Module,
    linker: Arc<Linker<Host>>,
    name: Arc<str>,
    vm_config: Arc<[u8]>,
    plugin_config: Arc<[u8]>,
    max_memory: usize,
    timeout_ticks: u64,
    pub fail_open: bool,
    pub request_body: Option<u64>,
    idle: Mutex<Vec<Vm>>,
}

/// Plugins indexed like the filters of a route's access settings.
pub(crate) type Plugins = Box<[Arc<Plugin>]>;

/// Why a filter did not run to the end.
#[derive(Debug)]
pub(crate) struct Failed(pub String);

/// What a filter decided at one step.
pub(crate) enum Step {
    Continue,
    /// The plugin answered itself; the response is in the stream.
    Respond,
}

impl Plugin {
    /// Prepares a filter: its module compiled, one instance started to
    /// check the configuration.
    pub(crate) fn new(f: &WasmFilter, m: &WasmModule) -> Result<Arc<Self>, String> {
        let module = compiled(m)?;
        let mut linker = Linker::new(module.engine());
        add_host(&mut linker).map_err(|e| e.to_string())?;
        linker
            .define_unknown_imports_as_traps(&module)
            .map_err(|e| e.to_string())?;
        let p = Arc::new(Self {
            sha256: m.sha256,
            filter: WasmFilter {
                module: 0,
                ..f.clone()
            },
            module,
            linker: Arc::new(linker),
            name: f.name.as_ref().into(),
            vm_config: f.vm_configuration.as_ref().into(),
            plugin_config: f.configuration.as_ref().into(),
            max_memory: usize::try_from(f.max_memory).unwrap_or(usize::MAX),
            timeout_ticks: (u64::from(f.timeout_ms) / TICK.as_millis() as u64).max(1),
            fail_open: f.fail_open,
            request_body: f.request_body,
            idle: Mutex::new(Vec::new()),
        });
        let vm = p.start()?;
        p.put(vm);
        Ok(p)
    }

    fn start(&self) -> Result<Vm, String> {
        let host = Host {
            name: self.name.clone(),
            vm_config: self.vm_config.clone(),
            plugin_config: self.plugin_config.clone(),
            stream: Stream::default(),
            limits: StoreLimitsBuilder::new()
                .memory_size(self.max_memory)
                .trap_on_grow_failure(true)
                .build(),
            exited: None,
        };
        let mut store = Store::new(self.module.engine(), host);
        store.limiter(|h| &mut h.limits);
        // Start-up runs Go's runtime and parses rule sets: it gets more time
        // than a request callback.
        store.set_epoch_deadline(self.timeout_ticks.max(30_000 / TICK.as_millis() as u64));
        store.epoch_deadline_trap();
        let inst = self
            .linker
            .instantiate(&mut store, &self.module)
            .map_err(|e| format!("wasm {}: {e}", self.name))?;
        let ex = exports(&inst, &mut store).map_err(|e| format!("wasm {}: {e}", self.name))?;
        let err = |e: wasmtime::Error| format!("wasm {}: {e}", self.name);
        if let Some(Extern::Func(f)) = inst.get_export(&mut store, "_initialize") {
            f.typed::<(), ()>(&store)
                .map_err(err)?
                .call(&mut store, ())
                .map_err(err)?;
        } else if let Some(Extern::Func(f)) = inst.get_export(&mut store, "_start") {
            let r = f.typed::<(), ()>(&store).map_err(err)?.call(&mut store, ());
            // TinyGo's _start returns; a proc_exit(0) is a normal end too.
            if let Err(e) = r
                && store.data().exited != Some(0)
            {
                return Err(err(e));
            }
        }
        let vm_start = inst
            .get_typed_func::<(i32, i32), i32>(&mut store, "proxy_on_vm_start")
            .map_err(err)?;
        let configure = inst
            .get_typed_func::<(i32, i32), i32>(&mut store, "proxy_on_configure")
            .map_err(err)?;
        ex.context_create
            .call(&mut store, (ROOT as i32, 0))
            .map_err(err)?;
        let n = self.vm_config.len() as i32;
        if vm_start.call(&mut store, (ROOT as i32, n)).map_err(err)? == 0 {
            return Err(format!("wasm {}: proxy_on_vm_start failed", self.name));
        }
        let n = self.plugin_config.len() as i32;
        if configure.call(&mut store, (ROOT as i32, n)).map_err(err)? == 0 {
            let logs = store.data().stream.logs.join("; ");
            return Err(format!("wasm {}: configuration refused: {logs}", self.name));
        }
        store.data_mut().stream.logs.clear();
        Ok(Vm {
            store,
            ex,
            next_context: ROOT + 1,
        })
    }

    fn take(&self) -> Result<Vm, Failed> {
        let vm = self.idle.lock().unwrap_or_else(|e| e.into_inner()).pop();
        match vm {
            Some(vm) => Ok(vm),
            None => self.start().map_err(Failed),
        }
    }

    fn put(&self, vm: Vm) {
        let mut idle = self.idle.lock().unwrap_or_else(|e| e.into_inner());
        if idle.len() < POOL {
            idle.push(vm);
        }
    }

    /// Opens a stream context for one request.
    pub(crate) fn open(self: &Arc<Self>, stream: Stream) -> Result<Session, Failed> {
        let mut vm = self.take()?;
        let id = vm.next_context;
        vm.next_context = vm.next_context.wrapping_add(1).max(ROOT + 1);
        vm.store.data_mut().stream = stream;
        let mut s = Session {
            plugin: self.clone(),
            vm: Some(vm),
            id,
        };
        s.call(|vm, id| {
            vm.ex
                .context_create
                .call(&mut vm.store, (id as i32, ROOT as i32))
                .map(|_| 0)
        })?;
        Ok(s)
    }
}

/// One request's stream context in an instance.
pub(crate) struct Session {
    plugin: Arc<Plugin>,
    vm: Option<Vm>,
    id: u32,
}

impl Session {
    pub(crate) fn fail_open(&self) -> bool {
        self.plugin.fail_open
    }

    pub(crate) fn stream(&mut self) -> &mut Stream {
        &mut self
            .vm
            .as_mut()
            .expect("session is open")
            .store
            .data_mut()
            .stream
    }

    fn call(
        &mut self,
        f: impl FnOnce(&mut Vm, u32) -> wasmtime::Result<i32>,
    ) -> Result<i32, Failed> {
        let id = self.id;
        let vm = self
            .vm
            .as_mut()
            .ok_or_else(|| Failed("instance lost".into()))?;
        vm.store.set_epoch_deadline(self.plugin.timeout_ticks);
        match f(vm, id) {
            Ok(r) => Ok(r),
            Err(e) => {
                // A trapped instance is in an unknown state.
                self.vm = None;
                Err(Failed(format!("wasm {}: {e}", self.plugin.name)))
            }
        }
    }

    fn step(&mut self, r: Result<i32, Failed>) -> Result<Step, Failed> {
        r?;
        Ok(if self.stream().local.is_some() {
            Step::Respond
        } else {
            Step::Continue
        })
    }

    pub(crate) fn request_headers(&mut self, end: bool) -> Result<Step, Failed> {
        let n = self.stream().request_headers.len() as i32;
        let r = self.call(|vm, id| {
            vm.ex
                .request_headers
                .call(&mut vm.store, (id as i32, n, i32::from(end)))
        });
        self.step(r)
    }

    pub(crate) fn request_body(&mut self) -> Result<Step, Failed> {
        let n = self.stream().request_body.len() as i32;
        let r = self.call(|vm, id| vm.ex.request_body.call(&mut vm.store, (id as i32, n, 1)));
        self.step(r)
    }

    pub(crate) fn response_headers(&mut self) -> Result<Step, Failed> {
        let n = self.stream().response_headers.len() as i32;
        let r = self.call(|vm, id| {
            vm.ex
                .response_headers
                .call(&mut vm.store, (id as i32, n, 0))
        });
        self.step(r)
    }

    /// Ends the stream (log, done, delete) and returns the instance.
    pub(crate) fn close(mut self) {
        let ex = self
            .vm
            .as_ref()
            .map(|vm| (vm.ex.log.clone(), vm.ex.done.clone(), vm.ex.delete.clone()));
        if let Some((log, done, delete)) = ex {
            if let Some(f) = log {
                let _ = self.call(|vm, id| f.call(&mut vm.store, id as i32).map(|_| 0));
            }
            if let Some(f) = done {
                let _ = self.call(|vm, id| f.call(&mut vm.store, id as i32));
            }
            if let Some(f) = delete {
                let _ = self.call(|vm, id| f.call(&mut vm.store, id as i32).map(|_| 0));
            }
        }
        if let Some(mut vm) = self.vm.take() {
            vm.store.data_mut().stream = Stream::default();
            self.plugin.put(vm);
        }
    }
}

fn exports(inst: &Instance, store: &mut Store<Host>) -> wasmtime::Result<Exports> {
    if inst.get_memory(&mut *store, "memory").is_none() {
        return Err(wasmtime::format_err!("no exported memory"));
    }
    if inst
        .get_func(&mut *store, "proxy_on_memory_allocate")
        .is_none()
        && inst.get_func(&mut *store, "malloc").is_none()
    {
        return Err(wasmtime::format_err!("no proxy_on_memory_allocate export"));
    }
    Ok(Exports {
        context_create: inst.get_typed_func(&mut *store, "proxy_on_context_create")?,
        request_headers: inst.get_typed_func(&mut *store, "proxy_on_request_headers")?,
        request_body: inst.get_typed_func(&mut *store, "proxy_on_request_body")?,
        response_headers: inst.get_typed_func(&mut *store, "proxy_on_response_headers")?,
        done: inst.get_typed_func(&mut *store, "proxy_on_done").ok(),
        log: inst.get_typed_func(&mut *store, "proxy_on_log").ok(),
        delete: inst.get_typed_func(&mut *store, "proxy_on_delete").ok(),
    })
}

type C<'a> = Caller<'a, Host>;

fn memory(c: &mut C<'_>) -> Option<Memory> {
    match c.get_export("memory") {
        Some(Extern::Memory(m)) => Some(m),
        _ => None,
    }
}

fn read(c: &mut C<'_>, ptr: i32, len: i32) -> Option<Vec<u8>> {
    let m = memory(c)?;
    let (ptr, len) = (usize::try_from(ptr).ok()?, usize::try_from(len).ok()?);
    m.data(&*c)
        .get(ptr..ptr.checked_add(len)?)
        .map(<[u8]>::to_vec)
}

fn write(c: &mut C<'_>, ptr: i32, bytes: &[u8]) -> bool {
    let Some(m) = memory(c) else { return false };
    let Ok(ptr) = usize::try_from(ptr) else {
        return false;
    };
    m.write(&mut *c, ptr, bytes).is_ok()
}

fn write_u32(c: &mut C<'_>, ptr: i32, v: u32) -> bool {
    write(c, ptr, &v.to_le_bytes())
}

/// Copies `bytes` into memory the plugin allocates and stores the pointer
/// and length at `ret_ptr` and `ret_len`.
fn give(c: &mut C<'_>, bytes: &[u8], ret_ptr: i32, ret_len: i32) -> wasmtime::Result<i32> {
    let malloc = match c
        .get_export("proxy_on_memory_allocate")
        .or_else(|| c.get_export("malloc"))
    {
        Some(Extern::Func(f)) => f.typed::<i32, i32>(&*c)?,
        _ => return Ok(UNIMPLEMENTED),
    };
    let p = if bytes.is_empty() {
        0
    } else {
        let p = malloc.call(&mut *c, bytes.len() as i32)?;
        if p == 0 || !write(c, p, bytes) {
            return Ok(INVALID_MEMORY_ACCESS);
        }
        p
    };
    if !write_u32(c, ret_ptr, p as u32) || !write_u32(c, ret_len, bytes.len() as u32) {
        return Ok(INVALID_MEMORY_ACCESS);
    }
    Ok(OK)
}

/// proxy-wasm map serialization: count, then each key and value size,
/// then the NUL-terminated keys and values.
fn serialize_map(pairs: &[(Vec<u8>, Vec<u8>)]) -> Vec<u8> {
    let mut out = Vec::new();
    out.extend_from_slice(&(pairs.len() as u32).to_le_bytes());
    for (k, v) in pairs {
        out.extend_from_slice(&(k.len() as u32).to_le_bytes());
        out.extend_from_slice(&(v.len() as u32).to_le_bytes());
    }
    for (k, v) in pairs {
        out.extend_from_slice(k);
        out.push(0);
        out.extend_from_slice(v);
        out.push(0);
    }
    out
}

fn deserialize_map(b: &[u8]) -> Option<Vec<(Vec<u8>, Vec<u8>)>> {
    let u32_at = |i: usize| -> Option<usize> {
        Some(u32::from_le_bytes(b.get(i..i + 4)?.try_into().ok()?) as usize)
    };
    if b.is_empty() {
        return Some(Vec::new());
    }
    let n = u32_at(0)?;
    let mut sizes = Vec::with_capacity(n.min(1024));
    for i in 0..n {
        sizes.push((u32_at(4 + i * 8)?, u32_at(8 + i * 8)?));
    }
    let mut at = 4 + n * 8;
    let mut out = Vec::with_capacity(sizes.len());
    for (k, v) in sizes {
        let key = b.get(at..at + k)?.to_vec();
        at += k + 1;
        let val = b.get(at..at + v)?.to_vec();
        at += v + 1;
        out.push((key, val));
    }
    Some(out)
}

fn map(s: &mut Stream, id: i32) -> Option<&mut Vec<(Vec<u8>, Vec<u8>)>> {
    match id {
        REQUEST_HEADERS => Some(&mut s.request_headers),
        RESPONSE_HEADERS => Some(&mut s.response_headers),
        _ => None,
    }
}

/// The numbers of `[id "N"]` in a log line.
fn rule_ids(line: &[u8]) -> impl Iterator<Item = u32> + '_ {
    line.windows(5)
        .enumerate()
        .filter(|(_, w)| *w == b"[id \"")
        .filter_map(|(i, _)| {
            let rest = &line[i + 5..];
            let end = rest.iter().position(|&c| c == b'"')?;
            std::str::from_utf8(&rest[..end]).ok()?.parse().ok()
        })
}

fn level_name(level: i32) -> &'static str {
    match level {
        0 => "trace",
        1 => "debug",
        2 => "info",
        3 => "warn",
        4 => "error",
        _ => "critical",
    }
}

static METRICS: LazyLock<Mutex<Vec<(String, i64)>>> = LazyLock::new(|| Mutex::new(Vec::new()));
static METRIC_IDS: AtomicU32 = AtomicU32::new(0);

fn add_host(l: &mut Linker<Host>) -> wasmtime::Result<()> {
    let env = "env";
    l.func_wrap(
        env,
        "proxy_log",
        |mut c: C<'_>, level: i32, p: i32, n: i32| -> i32 {
            let Some(msg) = read(&mut c, p, n) else {
                return INVALID_MEMORY_ACCESS;
            };
            if level >= LOG_LEVEL {
                let line = format!(
                    "wasm {} {}: {}",
                    c.data().name,
                    level_name(level),
                    String::from_utf8_lossy(&msg)
                );
                eprintln!("{line}");
                let st = &mut c.data_mut().stream;
                for id in rule_ids(&msg) {
                    if st.rules.len() < 64 && !st.rules.contains(&id) {
                        st.rules.push(id);
                    }
                }
                if st.logs.len() < 64 {
                    st.logs.push(line);
                }
            }
            OK
        },
    )?;
    l.func_wrap(
        env,
        "proxy_get_log_level",
        |mut c: C<'_>, ret: i32| -> i32 {
            if write_u32(&mut c, ret, LOG_LEVEL as u32) {
                OK
            } else {
                INVALID_MEMORY_ACCESS
            }
        },
    )?;
    l.func_wrap(
        env,
        "proxy_set_effective_context",
        |_: C<'_>, _id: i32| -> i32 { OK },
    )?;
    l.func_wrap(env, "proxy_done", |_: C<'_>| -> i32 { OK })?;
    l.func_wrap(
        env,
        "proxy_set_tick_period_milliseconds",
        |_: C<'_>, _ms: i32| -> i32 { OK },
    )?;
    l.func_wrap(
        env,
        "proxy_get_current_time_nanoseconds",
        |mut c: C<'_>, ret: i32| -> i32 {
            let now = SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .map_or(0, |d| d.as_nanos() as u64);
            if write(&mut c, ret, &now.to_le_bytes()) {
                OK
            } else {
                INVALID_MEMORY_ACCESS
            }
        },
    )?;
    l.func_wrap(
        env,
        "proxy_get_buffer_bytes",
        |mut c: C<'_>, id: i32, start: i32, max: i32, rp: i32, rl: i32| -> wasmtime::Result<i32> {
            let h = c.data();
            let buf: Vec<u8> = match id {
                REQUEST_BODY => h.stream.request_body.clone(),
                RESPONSE_BODY => h.stream.response_body.clone(),
                VM_CONFIGURATION => h.vm_config.to_vec(),
                PLUGIN_CONFIGURATION => h.plugin_config.to_vec(),
                _ => return Ok(NOT_FOUND),
            };
            let (Ok(start), Ok(max)) = (usize::try_from(start), usize::try_from(max)) else {
                return Ok(BAD_ARGUMENT);
            };
            if start > buf.len() {
                return Ok(BAD_ARGUMENT);
            }
            let end = start.saturating_add(max).min(buf.len());
            give(&mut c, &buf[start..end], rp, rl)
        },
    )?;
    l.func_wrap(
        env,
        "proxy_get_buffer_status",
        |mut c: C<'_>, id: i32, rl: i32, rf: i32| -> i32 {
            let h = c.data();
            let n = match id {
                REQUEST_BODY => h.stream.request_body.len(),
                RESPONSE_BODY => h.stream.response_body.len(),
                VM_CONFIGURATION => h.vm_config.len(),
                PLUGIN_CONFIGURATION => h.plugin_config.len(),
                _ => return NOT_FOUND,
            };
            if write_u32(&mut c, rl, n as u32) && write_u32(&mut c, rf, 0) {
                OK
            } else {
                INVALID_MEMORY_ACCESS
            }
        },
    )?;
    l.func_wrap(
        env,
        "proxy_set_buffer_bytes",
        |mut c: C<'_>, id: i32, start: i32, size: i32, p: i32, n: i32| -> i32 {
            let Some(v) = read(&mut c, p, n) else {
                return INVALID_MEMORY_ACCESS;
            };
            let s = &mut c.data_mut().stream;
            let buf = match id {
                REQUEST_BODY => &mut s.request_body,
                RESPONSE_BODY => &mut s.response_body,
                _ => return NOT_FOUND,
            };
            let start = usize::try_from(start).unwrap_or(usize::MAX).min(buf.len());
            let end = start
                .saturating_add(usize::try_from(size).unwrap_or(0))
                .min(buf.len());
            buf.splice(start..end, v);
            OK
        },
    )?;
    l.func_wrap(
        env,
        "proxy_get_header_map_pairs",
        |mut c: C<'_>, id: i32, rp: i32, rl: i32| -> wasmtime::Result<i32> {
            let Some(m) = map(&mut c.data_mut().stream, id) else {
                return Ok(BAD_ARGUMENT);
            };
            let b = serialize_map(m);
            give(&mut c, &b, rp, rl)
        },
    )?;
    l.func_wrap(
        env,
        "proxy_get_header_map_size",
        |mut c: C<'_>, id: i32, ret: i32| -> i32 {
            let Some(m) = map(&mut c.data_mut().stream, id) else {
                return BAD_ARGUMENT;
            };
            let n = serialize_map(m).len() as u32;
            if write_u32(&mut c, ret, n) {
                OK
            } else {
                INVALID_MEMORY_ACCESS
            }
        },
    )?;
    l.func_wrap(
        env,
        "proxy_set_header_map_pairs",
        |mut c: C<'_>, id: i32, p: i32, n: i32| -> i32 {
            let Some(pairs) = read(&mut c, p, n).and_then(|b| deserialize_map(&b)) else {
                return INVALID_MEMORY_ACCESS;
            };
            match map(&mut c.data_mut().stream, id) {
                Some(m) => {
                    *m = pairs;
                    OK
                }
                None => BAD_ARGUMENT,
            }
        },
    )?;
    l.func_wrap(
        env,
        "proxy_get_header_map_value",
        |mut c: C<'_>, id: i32, kp: i32, kn: i32, rp: i32, rl: i32| -> wasmtime::Result<i32> {
            let Some(key) = read(&mut c, kp, kn) else {
                return Ok(INVALID_MEMORY_ACCESS);
            };
            let Some(m) = map(&mut c.data_mut().stream, id) else {
                return Ok(BAD_ARGUMENT);
            };
            let v = m
                .iter()
                .find(|(k, _)| k.eq_ignore_ascii_case(&key))
                .map(|(_, v)| v.clone());
            match v {
                Some(v) => give(&mut c, &v, rp, rl),
                None => Ok(NOT_FOUND),
            }
        },
    )?;
    l.func_wrap(
        env,
        "proxy_add_header_map_value",
        |mut c: C<'_>, id: i32, kp: i32, kn: i32, vp: i32, vn: i32| -> i32 {
            let (Some(k), Some(v)) = (read(&mut c, kp, kn), read(&mut c, vp, vn)) else {
                return INVALID_MEMORY_ACCESS;
            };
            match map(&mut c.data_mut().stream, id) {
                Some(m) => {
                    m.push((k, v));
                    OK
                }
                None => BAD_ARGUMENT,
            }
        },
    )?;
    l.func_wrap(
        env,
        "proxy_replace_header_map_value",
        |mut c: C<'_>, id: i32, kp: i32, kn: i32, vp: i32, vn: i32| -> i32 {
            let (Some(k), Some(v)) = (read(&mut c, kp, kn), read(&mut c, vp, vn)) else {
                return INVALID_MEMORY_ACCESS;
            };
            match map(&mut c.data_mut().stream, id) {
                Some(m) => {
                    m.retain(|(n, _)| !n.eq_ignore_ascii_case(&k));
                    m.push((k, v));
                    OK
                }
                None => BAD_ARGUMENT,
            }
        },
    )?;
    l.func_wrap(
        env,
        "proxy_remove_header_map_value",
        |mut c: C<'_>, id: i32, kp: i32, kn: i32| -> i32 {
            let Some(k) = read(&mut c, kp, kn) else {
                return INVALID_MEMORY_ACCESS;
            };
            match map(&mut c.data_mut().stream, id) {
                Some(m) => {
                    m.retain(|(n, _)| !n.eq_ignore_ascii_case(&k));
                    OK
                }
                None => BAD_ARGUMENT,
            }
        },
    )?;
    l.func_wrap(
        env,
        "proxy_get_property",
        |mut c: C<'_>, p: i32, n: i32, rp: i32, rl: i32| -> wasmtime::Result<i32> {
            let Some(mut path) = read(&mut c, p, n) else {
                return Ok(INVALID_MEMORY_ACCESS);
            };
            while path.last() == Some(&0) {
                path.pop();
            }
            if path == b"plugin_name" {
                let name = c.data().name.as_bytes().to_vec();
                return give(&mut c, &name, rp, rl);
            }
            match c.data().stream.properties.get(&path).cloned() {
                Some(v) => give(&mut c, &v, rp, rl),
                None => Ok(NOT_FOUND),
            }
        },
    )?;
    l.func_wrap(
        env,
        "proxy_set_property",
        |_: C<'_>, _a: i32, _b: i32, _c: i32, _d: i32| -> i32 { UNIMPLEMENTED },
    )?;
    l.func_wrap(
        env,
        "proxy_send_local_response",
        |mut c: C<'_>,
         status: i32,
         _dp: i32,
         _dn: i32,
         bp: i32,
         bn: i32,
         hp: i32,
         hn: i32,
         _grpc: i32|
         -> i32 {
            let (Some(body), Some(headers)) = (
                read(&mut c, bp, bn),
                read(&mut c, hp, hn).and_then(|b| deserialize_map(&b)),
            ) else {
                return INVALID_MEMORY_ACCESS;
            };
            let status = u16::try_from(status)
                .ok()
                .filter(|s| (200..600).contains(s))
                .unwrap_or(403);
            c.data_mut().stream.local = Some(Local {
                status,
                headers,
                body,
            });
            OK
        },
    )?;
    l.func_wrap(env, "proxy_continue_stream", |_: C<'_>, _t: i32| -> i32 {
        OK
    })?;
    l.func_wrap(env, "proxy_close_stream", |_: C<'_>, _t: i32| -> i32 { OK })?;
    l.func_wrap(
        env,
        "proxy_define_metric",
        |mut c: C<'_>, _kind: i32, p: i32, n: i32, ret: i32| -> i32 {
            let Some(name) = read(&mut c, p, n) else {
                return INVALID_MEMORY_ACCESS;
            };
            let name = String::from_utf8_lossy(&name).into_owned();
            let mut m = METRICS.lock().unwrap_or_else(|e| e.into_inner());
            let id = match m.iter().position(|(n, _)| *n == name) {
                Some(i) => i as u32,
                None => {
                    m.push((name, 0));
                    METRIC_IDS.fetch_add(1, Ordering::Relaxed)
                }
            };
            drop(m);
            if write_u32(&mut c, ret, id) {
                OK
            } else {
                INVALID_MEMORY_ACCESS
            }
        },
    )?;
    l.func_wrap(
        env,
        "proxy_increment_metric",
        |_: C<'_>, id: i32, delta: i64| -> i32 {
            let mut m = METRICS.lock().unwrap_or_else(|e| e.into_inner());
            match usize::try_from(id).ok().and_then(|i| m.get_mut(i)) {
                Some((_, v)) => {
                    *v = v.saturating_add(delta);
                    OK
                }
                None => NOT_FOUND,
            }
        },
    )?;
    l.func_wrap(
        env,
        "proxy_record_metric",
        |_: C<'_>, id: i32, value: i64| -> i32 {
            let mut m = METRICS.lock().unwrap_or_else(|e| e.into_inner());
            match usize::try_from(id).ok().and_then(|i| m.get_mut(i)) {
                Some((_, v)) => {
                    *v = value;
                    OK
                }
                None => NOT_FOUND,
            }
        },
    )?;
    l.func_wrap(
        env,
        "proxy_get_metric",
        |mut c: C<'_>, id: i32, ret: i32| -> i32 {
            let v = {
                let m = METRICS.lock().unwrap_or_else(|e| e.into_inner());
                match usize::try_from(id).ok().and_then(|i| m.get(i)) {
                    Some((_, v)) => *v,
                    None => return NOT_FOUND,
                }
            };
            if write(&mut c, ret, &v.to_le_bytes()) {
                OK
            } else {
                INVALID_MEMORY_ACCESS
            }
        },
    )?;
    add_wasi(l)
}

/// WASI preview1, as far as a plugin without files or sockets needs it.
fn add_wasi(l: &mut Linker<Host>) -> wasmtime::Result<()> {
    let w = "wasi_snapshot_preview1";
    // No arguments and no environment.
    for name in ["args_sizes_get", "environ_sizes_get"] {
        l.func_wrap(w, name, |mut c: C<'_>, count: i32, size: i32| -> i32 {
            if write_u32(&mut c, count, 0) && write_u32(&mut c, size, 0) {
                ESUCCESS
            } else {
                EFAULT
            }
        })?;
    }
    for name in ["args_get", "environ_get"] {
        l.func_wrap(w, name, |_: C<'_>, _a: i32, _b: i32| -> i32 { ESUCCESS })?;
    }
    l.func_wrap(
        w,
        "clock_time_get",
        |mut c: C<'_>, id: i32, _precision: i64, ret: i32| -> i32 {
            let ns = match id {
                0 => SystemTime::now()
                    .duration_since(UNIX_EPOCH)
                    .map_or(0, |d| d.as_nanos() as u64),
                1..=3 => monotonic_ns(),
                _ => return EINVAL,
            };
            if write(&mut c, ret, &ns.to_le_bytes()) {
                ESUCCESS
            } else {
                EFAULT
            }
        },
    )?;
    l.func_wrap(
        w,
        "clock_res_get",
        |mut c: C<'_>, _id: i32, ret: i32| -> i32 {
            if write(&mut c, ret, &1u64.to_le_bytes()) {
                ESUCCESS
            } else {
                EFAULT
            }
        },
    )?;
    l.func_wrap(w, "random_get", |mut c: C<'_>, p: i32, n: i32| -> i32 {
        let Ok(n) = usize::try_from(n) else {
            return EINVAL;
        };
        let mut b = vec![0u8; n];
        if openssl::rand::rand_bytes(&mut b).is_err() {
            return EINVAL;
        }
        if write(&mut c, p, &b) {
            ESUCCESS
        } else {
            EFAULT
        }
    })?;
    l.func_wrap(
        w,
        "fd_write",
        |mut c: C<'_>, fd: i32, iovs: i32, n: i32, ret: i32| -> i32 {
            if fd != 1 && fd != 2 {
                return EBADF;
            }
            let mut total = 0u32;
            let mut text = Vec::new();
            for i in 0..n.max(0) {
                let Some(iov) = read(&mut c, iovs + i * 8, 8) else {
                    return EFAULT;
                };
                let p = u32::from_le_bytes([iov[0], iov[1], iov[2], iov[3]]) as i32;
                let len = u32::from_le_bytes([iov[4], iov[5], iov[6], iov[7]]) as i32;
                let Some(b) = read(&mut c, p, len) else {
                    return EFAULT;
                };
                total += b.len() as u32;
                text.extend_from_slice(&b);
            }
            // Plugins write their own diagnostics here; stderr goes to the
            // log, stdout is dropped.
            if fd == 2 && !text.trim_ascii().is_empty() {
                eprintln!(
                    "wasm {}: {}",
                    c.data().name,
                    String::from_utf8_lossy(text.trim_ascii_end())
                );
            }
            if write_u32(&mut c, ret, total) {
                ESUCCESS
            } else {
                EFAULT
            }
        },
    )?;
    l.func_wrap(
        w,
        "fd_fdstat_get",
        |mut c: C<'_>, fd: i32, ret: i32| -> i32 {
            if !(0..=2).contains(&fd) {
                return EBADF;
            }
            // Character device, no flags, no rights restrictions.
            let mut st = [0u8; 24];
            st[0] = 2;
            st[8..16].copy_from_slice(&u64::MAX.to_le_bytes());
            st[16..24].copy_from_slice(&u64::MAX.to_le_bytes());
            if write(&mut c, ret, &st) {
                ESUCCESS
            } else {
                EFAULT
            }
        },
    )?;
    // No preopened directories: the plugin sees an empty file system.
    l.func_wrap(
        w,
        "fd_prestat_get",
        |_: C<'_>, _fd: i32, _ret: i32| -> i32 { EBADF },
    )?;
    l.func_wrap(
        w,
        "fd_prestat_dir_name",
        |_: C<'_>, _fd: i32, _p: i32, _n: i32| -> i32 { EBADF },
    )?;
    l.func_wrap(w, "fd_close", |_: C<'_>, _fd: i32| -> i32 { EBADF })?;
    l.func_wrap(
        w,
        "fd_read",
        |_: C<'_>, _fd: i32, _iovs: i32, _n: i32, _ret: i32| -> i32 { EBADF },
    )?;
    l.func_wrap(
        w,
        "fd_seek",
        |_: C<'_>, _fd: i32, _off: i64, _whence: i32, _ret: i32| -> i32 { EBADF },
    )?;
    l.func_wrap(
        w,
        "path_open",
        |_: C<'_>,
         _fd: i32,
         _flags: i32,
         _p: i32,
         _n: i32,
         _oflags: i32,
         _base: i64,
         _inherit: i64,
         _fdflags: i32,
         _ret: i32|
         -> i32 { ENOTSUP },
    )?;
    l.func_wrap(w, "sched_yield", |_: C<'_>| -> i32 { ESUCCESS })?;
    l.func_wrap(
        w,
        "proc_exit",
        |mut c: C<'_>, code: i32| -> wasmtime::Result<()> {
            c.data_mut().exited = Some(code);
            Err(wasmtime::format_err!("proc_exit({code})"))
        },
    )?;
    Ok(())
}

fn monotonic_ns() -> u64 {
    static START: LazyLock<std::time::Instant> = LazyLock::new(std::time::Instant::now);
    START.elapsed().as_nanos() as u64
}

/// Plugins by site, then route.
pub(crate) type Table = Box<[Box<[Plugins]>]>;

/// Builds the plugins of every route filter of `rt`, sharing one per
/// identical filter and taking over those of `old` that did not change, so
/// their started instances carry over.
pub(crate) fn build(rt: &proxelo_snapshot::Runtime, old: Option<&Table>) -> Result<Table, String> {
    let mut made: Vec<Arc<Plugin>> = old
        .into_iter()
        .flat_map(|t| {
            t.iter()
                .flat_map(|s| s.iter().flat_map(|r| r.iter().cloned()))
        })
        .collect();
    let mut out = Vec::with_capacity(rt.sites.len());
    for (si, s) in rt.sites.iter().enumerate() {
        let mut routes = Vec::with_capacity(s.routes.len());
        for (ri, r) in s.routes.iter().enumerate() {
            let mut ps = Vec::with_capacity(r.access.wasm.len());
            for (fi, f) in r.access.wasm.iter().enumerate() {
                let m = &rt.wasm_modules[f.module as usize];
                let key = WasmFilter {
                    module: 0,
                    ..f.clone()
                };
                let p = match made
                    .iter()
                    .find(|p| p.sha256 == m.sha256 && p.filter == key)
                {
                    Some(p) => p.clone(),
                    None => {
                        let p = Plugin::new(f, m).map_err(|e| {
                            format!("sites[{si}].routes[{ri}].access.wasm[{fi}]: {e}")
                        })?;
                        made.push(p.clone());
                        p
                    }
                };
                ps.push(p);
            }
            routes.push(ps.into_boxed_slice());
        }
        out.push(routes.into_boxed_slice());
    }
    Ok(out.into_boxed_slice())
}

/// Header lines of `pairs` that `from` lacks, compared with
/// case-insensitive names; pseudo-headers are left out.
fn added<'a>(pairs: &'a Pairs, from: &'a Pairs) -> impl Iterator<Item = &'a (Vec<u8>, Vec<u8>)> {
    pairs
        .iter()
        .filter(move |p| !p.0.starts_with(b":") && !has(from, &p.0, &p.1))
}

pub(crate) fn has(pairs: &Pairs, name: &[u8], value: &[u8]) -> bool {
    pairs
        .iter()
        .any(|(n, v)| n.eq_ignore_ascii_case(name) && v == value)
}

/// Appends the lines a plugin added to `pairs`, compared with `from`.
pub(crate) fn push_added(out: &mut Vec<u8>, pairs: &Pairs, from: &Pairs) {
    for (n, v) in added(pairs, from) {
        out.extend_from_slice(n);
        out.extend_from_slice(b": ");
        crate::reply::push_header_value(out, v);
        out.extend_from_slice(b"\r\n");
    }
}

fn u64_le(v: u64) -> Vec<u8> {
    v.to_le_bytes().to_vec()
}

/// The properties of the request in `x`, as Envoy names them.
fn properties(x: &mut Exchange) -> HashMap<Vec<u8>, Vec<u8>> {
    let mut p = HashMap::new();
    let mut put = |k: &[u8], v: Vec<u8>| {
        p.insert(k.to_vec(), v);
    };
    let target = x.req.target.get(&x.head).to_vec();
    let path_end = target
        .iter()
        .position(|&c| c == b'?')
        .unwrap_or(target.len());
    put(b"request\0path", target.clone());
    put(b"request\0url_path", target[..path_end].to_vec());
    put(
        b"request\0query",
        target.get(path_end + 1..).unwrap_or_default().to_vec(),
    );
    put(b"request\0host", x.host.clone());
    put(b"request\0method", x.req.method_span.get(&x.head).to_vec());
    put(
        b"request\0scheme",
        if x.https() {
            b"https".to_vec()
        } else {
            b"http".to_vec()
        },
    );
    let protocol: &[u8] = if x.h3 {
        b"HTTP/3"
    } else if x.h2 {
        b"HTTP/2"
    } else if x.req.version == Version::Http10 {
        b"HTTP/1.0"
    } else {
        b"HTTP/1.1"
    };
    put(b"request\0protocol", protocol.to_vec());
    put(b"request\0id", x.request_id().to_vec());
    put(b"source\0address", x.peer.to_string().into_bytes());
    put(b"source\0port", u64_le(x.peer.port().into()));
    put(b"destination\0address", x.local.to_string().into_bytes());
    put(b"destination\0port", u64_le(x.local.port().into()));
    p
}

/// The request headers with the pseudo-headers proxy-wasm filters expect.
fn request_pairs(x: &Exchange) -> Pairs {
    let mut out = Vec::with_capacity(x.req.headers.iter().count() + 4);
    let authority = x
        .request_header(b"host")
        .map_or_else(|| x.host.clone(), <[u8]>::to_vec);
    out.push((b":authority".to_vec(), authority));
    out.push((b":path".to_vec(), x.req.target.get(&x.head).to_vec()));
    out.push((b":method".to_vec(), x.req.method_span.get(&x.head).to_vec()));
    out.push((
        b":scheme".to_vec(),
        if x.https() {
            b"https".to_vec()
        } else {
            b"http".to_vec()
        },
    ));
    for h in x.req.headers.iter() {
        if h.kind == HeaderKind::Host || h.kind.is_hop_by_hop() {
            continue;
        }
        out.push((h.name.get(&x.head).to_vec(), h.value.get(&x.head).to_vec()));
    }
    out
}

impl Conn {
    /// Runs the route's proxy-wasm filters on the request head and, when a
    /// filter asks for it, the buffered body. `Err` is the status to answer;
    /// a filter's own response is kept in `wasm_local`.
    pub(crate) async fn wasm_request(&mut self, plugins: &Plugins) -> Result<(), u16> {
        if plugins.is_empty() || !self.wasm.is_empty() {
            return Ok(());
        }
        self.wasm_req = None;
        let max = plugins.iter().filter_map(|p| p.request_body).max();
        let body = match max {
            Some(max) => self.peek_body(max).await?,
            None => None,
        };
        let headers = request_pairs(&self.x);
        let props = properties(&mut self.x);
        let mut current = headers.clone();
        for p in plugins.iter() {
            let stream = Stream {
                request_headers: current.clone(),
                request_body: body.clone().unwrap_or_default(),
                properties: props.clone(),
                ..Stream::default()
            };
            let given = body
                .as_ref()
                .filter(|b| p.request_body.is_some_and(|m| b.len() as u64 <= m));
            let r = match p.open(stream) {
                Ok(mut s) => {
                    let r = s
                        .request_headers(given.is_none())
                        .and_then(|step| match step {
                            Step::Continue if given.is_some() => s.request_body(),
                            step => Ok(step),
                        });
                    match r {
                        Ok(step) => {
                            let st = s.stream();
                            current = std::mem::take(&mut st.request_headers);
                            let local = st.local.take();
                            self.wasm.push(s);
                            Ok(matches!(step, Step::Respond).then_some(local).flatten())
                        }
                        Err(e) => Err(e),
                    }
                }
                Err(e) => Err(e),
            };
            match r {
                Ok(None) => {}
                Ok(Some(local)) => {
                    let status = local.status;
                    self.wasm_local = Some(local);
                    return Err(status);
                }
                Err(Failed(e)) => {
                    eprintln!("{e}");
                    if !p.fail_open {
                        return Err(500);
                    }
                }
            }
        }
        if current != headers {
            self.wasm_req = Some((headers, current));
        }
        Ok(())
    }

    /// Reads the request body for the filters or a mirror and puts it back
    /// in front of what follows on the connection, framed as it came, so the
    /// request goes on as if unread. `None` without a body or past `max`.
    pub(crate) async fn peek_body(&mut self, max: u64) -> Result<Option<Vec<u8>>, u16> {
        if matches!(self.body, BodyLeft::None) {
            return Ok(None);
        }
        if let Body::Length(n) = self.x.req.body
            && n > max
        {
            return Ok(None);
        }
        if self.x.req.expect_continue && self.buf.end == 0 {
            if write_timeout(
                &mut self.client,
                b"HTTP/1.1 100 Continue\r\n\r\n",
                SEND_TIMEOUT,
            )
            .await
            .is_err()
            {
                self.x.req.keep_alive = false;
                return Err(400);
            }
            self.x.req.expect_continue = false;
        }
        let chunked = matches!(self.body, BodyLeft::Chunked(..));
        let mut body = Vec::new();
        match self.pump_body(Sink::Collect(&mut body)).await {
            Ok(()) => {}
            Err(Fail::TooLarge) => {
                self.x.req.keep_alive = false;
                return Err(413);
            }
            Err(_) => {
                self.x.req.keep_alive = false;
                return Err(400);
            }
        }
        let mut data = Vec::with_capacity(body.len() + 32 + self.buf.end);
        if chunked {
            if !body.is_empty() {
                push_hex(&mut data, body.len() as u64);
                data.extend_from_slice(b"\r\n");
                data.extend_from_slice(&body);
                data.extend_from_slice(b"\r\n");
            }
            data.extend_from_slice(b"0\r\n\r\n");
            self.body = BodyLeft::Chunked(ChunkedDecoder::new(), 0);
        } else if !body.is_empty() {
            data.extend_from_slice(&body);
            self.body = BodyLeft::Length(body.len() as u64);
        }
        data.extend_from_slice(self.buf.filled());
        self.buf.end = data.len();
        self.buf.data = data;
        Ok((body.len() as u64 <= max).then_some(body))
    }

    /// Runs the filters on the upstream response head in `resp`. Returns
    /// the headers as the filters left them when they changed them, paired
    /// with the original ones. `Err` is the status to answer instead.
    pub(crate) fn wasm_response(&mut self, status: u16) -> Result<Option<(Pairs, Pairs)>, u16> {
        if self.wasm.is_empty() {
            return Ok(None);
        }
        let mut headers: Pairs = Vec::with_capacity(self.resp.headers.iter().count() + 1);
        headers.push((b":status".to_vec(), status.to_string().into_bytes()));
        for h in self.resp.headers.iter() {
            if h.kind.is_hop_by_hop() {
                continue;
            }
            headers.push((
                h.name.get(&self.ubuf.data).to_vec(),
                h.value.get(&self.ubuf.data).to_vec(),
            ));
        }
        let mut current = headers.clone();
        let mut i = 0;
        while i < self.wasm.len() {
            let s = &mut self.wasm[i];
            let st = s.stream();
            st.response_headers = std::mem::take(&mut current);
            st.properties
                .insert(b"response\0code".to_vec(), u64_le(status.into()));
            match s.response_headers() {
                Ok(step) => {
                    let st = s.stream();
                    current = std::mem::take(&mut st.response_headers);
                    if let (Step::Respond, Some(local)) = (step, st.local.take()) {
                        let status = local.status;
                        self.wasm_local = Some(local);
                        return Err(status);
                    }
                    i += 1;
                }
                Err(Failed(e)) => {
                    eprintln!("{e}");
                    let s = self.wasm.remove(i);
                    let fail_open = s.fail_open();
                    s.close();
                    if !fail_open {
                        return Err(502);
                    }
                    current = headers.clone();
                }
            }
        }
        Ok((current != headers).then_some((headers, current)))
    }

    /// A filter's own response for `status`, if one asked for it: its
    /// header lines go to `out`, its body is returned.
    pub(crate) fn wasm_local_head(&mut self, status: u16) -> Option<Vec<u8>> {
        let local = self.wasm_local.take().filter(|l| l.status == status)?;
        const FRAMING: &[&[u8]] = &[
            b"content-length",
            b"transfer-encoding",
            b"connection",
            b"keep-alive",
            b"date",
            b"server",
        ];
        for (n, v) in &local.headers {
            if n.starts_with(b":") || FRAMING.iter().any(|f| n.eq_ignore_ascii_case(f)) {
                continue;
            }
            self.out.extend_from_slice(n);
            self.out.extend_from_slice(b": ");
            crate::reply::push_header_value(&mut self.out, v);
            self.out.extend_from_slice(b"\r\n");
        }
        Some(local.body)
    }

    /// The log phase of the filters; their instances go back to the pool.
    pub(crate) fn wasm_done(&mut self) {
        self.wasm_req = None;
        self.wasm_local = None;
        let status = self.x.sent.status;
        for mut s in self.wasm.drain(..) {
            let st = s.stream();
            st.properties
                .insert(b"response\0code".to_vec(), u64_le(status.into()));
            for &id in &st.rules {
                if !self.x.waf_rules.contains(&id) {
                    self.x.waf_rules.push(id);
                }
            }
            s.close();
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rule_ids_from_logs() {
        let line = br#"Coraza: Access denied [file "x"] [id "949110"] [msg ""] [id "1"] [id "x"]"#;
        assert_eq!(rule_ids(line).collect::<Vec<_>>(), [949110, 1]);
    }

    #[test]
    fn map_serialization_round_trips() {
        let pairs = vec![
            (b":path".to_vec(), b"/x".to_vec()),
            (b"a".to_vec(), Vec::new()),
        ];
        let b = serialize_map(&pairs);
        assert_eq!(deserialize_map(&b).unwrap(), pairs);
        assert_eq!(deserialize_map(&[]).unwrap(), vec![]);
        assert!(deserialize_map(&[1, 0, 0, 0, 9, 0, 0, 0]).is_none());
    }
}
