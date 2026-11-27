//! Runtime form of proxy-wasm filters and the modules they run.

use proxelo_api::snapshot::v1 as ir;

type Invalid = (String, String);

/// A WebAssembly module, named by the SHA-256 of its bytes.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WasmModule {
    pub sha256: [u8; 32],
}

impl WasmModule {
    /// Lowercase hex, the file name modules are stored under.
    pub fn hex(&self) -> String {
        hex(&self.sha256)
    }
}

pub fn hex(b: &[u8]) -> String {
    let mut s = String::with_capacity(b.len() * 2);
    for c in b {
        s.push(char::from(b"0123456789abcdef"[usize::from(c >> 4)]));
        s.push(char::from(b"0123456789abcdef"[usize::from(c & 15)]));
    }
    s
}

/// A proxy-wasm plugin on a route.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WasmFilter {
    /// Index into `Runtime::wasm_modules`.
    pub module: u32,
    pub name: Box<str>,
    pub configuration: Box<[u8]>,
    pub vm_configuration: Box<[u8]>,
    pub fail_open: bool,
    /// Buffer the request body up to this size for the plugin; `None`
    /// passes it through unseen.
    pub request_body: Option<u64>,
    pub max_memory: u64,
    pub timeout_ms: u32,
}

pub(crate) fn module(m: &ir::WasmModule) -> Result<WasmModule, String> {
    let s = m.sha256.as_bytes();
    if s.len() != 64 {
        return Err("must be 64 hex digits".into());
    }
    let digit = |c: u8| match c {
        b'0'..=b'9' => Some(c - b'0'),
        b'a'..=b'f' => Some(c - b'a' + 10),
        _ => None,
    };
    let mut out = [0u8; 32];
    for (i, pair) in s.chunks(2).enumerate() {
        let (Some(h), Some(l)) = (digit(pair[0]), digit(pair[1])) else {
            return Err("must be lowercase hex".into());
        };
        out[i] = h << 4 | l;
    }
    Ok(WasmModule { sha256: out })
}

pub(crate) fn filter(f: &ir::WasmFilter, modules: usize) -> Result<WasmFilter, Invalid> {
    if f.module as usize >= modules {
        return Err(("module".into(), "no such wasm module".into()));
    }
    Ok(WasmFilter {
        module: f.module,
        name: f.name.as_str().into(),
        configuration: f.configuration.as_slice().into(),
        vm_configuration: f.vm_configuration.as_slice().into(),
        fail_open: f.fail_open,
        request_body: f.request_body.then_some(if f.max_body == 0 {
            1024 * 1024
        } else {
            f.max_body
        }),
        max_memory: if f.max_memory == 0 {
            256 << 20
        } else {
            f.max_memory
        },
        timeout_ms: if f.timeout_ms == 0 {
            1000
        } else {
            f.timeout_ms
        },
    })
}
