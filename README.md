# proxelo-proxy

The data plane of Proxelo: the process that accepts client connections and
serves traffic. It is written in Rust and is configured only by snapshots
pushed from the control plane ([`proxelo`](https://github.com/null-variable/proxelo)).

The wire format between the two lives in
[`proxelo-api`](https://github.com/null-variable/proxelo-api).

## Status

Early development. `proxelo-proxy run` receives snapshots from the control
plane and serves them; `proxelo-proxy serve` serves a single snapshot file.
Both serve HTTP/1.1:

- Sites by nginx `server_name` order: exact name, longest `*.name` or
  `.name`, longest `name.*`, first PCRE2 regex, then the default site.
- Routes by nginx `location` order: `=`, then the longest prefix (`^~` stops
  here), then the first `~`/`~*` PCRE2 regex, then that longest prefix.
  Regexes run with JIT and a match limit; a match that hits it answers 500.
- Nested routes (locations inside a prefix location), searched like nginx.
- nginx `rewrite` (site and route level, `last`/`break`/`redirect`/
  `permanent`, captures `$1`..`$9`), `return`, `error_page` (internal
  redirect, named route or redirect, once per request) and `try_files`, with
  nginx variables such as `$uri`, `$args`, `$host` and `$arg_name`.
- Static files (`root`, `index`) and reverse proxying with smooth weighted
  round robin and keepalive upstream connections.

TLS, HTTP/2 and the `--sim` dry-load mode are not built yet.

Behaviour follows nginx defaults where the snapshot has no setting yet:
timeouts (`client_header_timeout 60s`, `keepalive_timeout 75s`,
`proxy_read_timeout 60s`, ...), `client_max_body_size 1m`, error pages,
the 301 for directories without a trailing slash, `proxy_next_upstream error
timeout` and the response headers nginx hides from upstreams.

## Layout

| Crate | Purpose |
|---|---|
| `crates/proxy` | `proxelo-proxy` binary |
| `crates/snapshot` | Validates snapshots and builds the runtime form (host and route lookup with PCRE2, resolved upstream targets) |
| `crates/http1` | HTTP/1.1 codec: in-place parsing, strict framing, chunked decoding, path normalization |
| `crates/server` | Accept loop, request handling, static files, proxying, upstream pools, snapshot swap, listening sockets that follow the snapshot |
| `crates/sync` | Control plane client: receives snapshots over the control socket and acks them |
| `fuzz` | `cargo fuzz` targets for the codec (separate workspace, nightly) |

## Build

```sh
cargo build --release      # builds the bundled PCRE2 with a C compiler
./target/release/proxelo-proxy version
./target/release/proxelo-proxy check snapshot.bin
./target/release/proxelo-proxy serve snapshot.bin --workers 4 --runtime per-core
./target/release/proxelo-proxy run --data /var/lib/proxelo --socket /run/proxelo/control.sock
```

`run` starts from the last-known-good snapshot in `<data>/proxy/lkg.snap` if
there is one, connects to the control plane socket and reconnects with backoff
whenever the stream ends. Each pushed snapshot is validated, built and swapped
in, then written to the LKG file; a snapshot that fails (for example a
listener address already in use) is acked as rejected and the previous one
keeps serving. Listening sockets follow the snapshot: added addresses are
bound before the swap, removed ones closed after it, unchanged ones stay open.
Connections accepted on a removed address close at their next request.

`check` builds the runtime form too, so it rejects anything `serve` would,
including listener and target addresses that do not resolve.

### Runtime and allocator candidates

The runtime and allocator are still being chosen by benchmark. Both candidates of each are built in:

| Choice | How |
|---|---|
| Multi-threaded Tokio, one socket per address | `--runtime shared` (default) |
| One single-threaded runtime per worker, one `SO_REUSEPORT` socket per worker | `--runtime per-core` |
| jemalloc | `cargo build --release --features jemalloc` |
| mimalloc | `cargo build --release --features mimalloc` |

## Development rules

- No `unsafe` outside crates created specifically for FFI. The workspace sets `unsafe_code = "forbid"`.
- `cargo fmt`, `cargo clippy -- -D warnings` and `cargo test` must pass.
- The request path must not allocate per request once a connection is warm.
  `crates/server/tests/alloc.rs` serves static and proxied requests on a warm
  keepalive connection under a counting allocator and fails on any allocation.

### Fuzzing

Needs a nightly toolchain and `cargo install cargo-fuzz`:

```sh
cd fuzz
cargo +nightly fuzz run request -- -max_total_time=3600
```

Targets: `request`, `response`, `chunked`, `path`. CI runs each for two minutes.

## License

Licensed under the [Apache License, Version 2.0](LICENSE). See [NOTICE](NOTICE).
