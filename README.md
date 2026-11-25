# proxelo-proxy

The data plane of Proxelo: the process that accepts client connections and
serves traffic. It is written in Rust and is configured only by snapshots
pushed from the control plane ([`proxelo`](https://github.com/null-variable/proxelo)).

The wire format between the two lives in
[`proxelo-api`](https://github.com/null-variable/proxelo-api).

## Status

Early development. `proxelo-proxy serve` serves HTTP/1.1 from a snapshot
file: exact-host sites, exact and prefix routes with nginx `location` order,
static files (`root`, `index`) and reverse proxying with smooth weighted round
robin and keepalive upstream connections. TLS, HTTP/2, regex routes and
snapshot delivery from the control plane are not built yet.

Behaviour follows nginx defaults where the snapshot has no setting yet:
timeouts (`client_header_timeout 60s`, `keepalive_timeout 75s`,
`proxy_read_timeout 60s`, ...), `client_max_body_size 1m`, error pages,
the 301 for directories without a trailing slash, `proxy_next_upstream error
timeout` and the response headers nginx hides from upstreams.

## Layout

| Crate | Purpose |
|---|---|
| `crates/proxy` | `proxelo-proxy` binary |
| `crates/snapshot` | Validates snapshots and builds the runtime form (host and route lookup, resolved upstream targets) |
| `crates/http1` | HTTP/1.1 codec: in-place parsing, strict framing, chunked decoding, path normalization |
| `crates/server` | Accept loop, request handling, static files, proxying, upstream pools, snapshot swap |
| `fuzz` | `cargo fuzz` targets for the codec (separate workspace, nightly) |

## Build

```sh
cargo build --release
./target/release/proxelo-proxy version
./target/release/proxelo-proxy check snapshot.bin
./target/release/proxelo-proxy serve snapshot.bin --workers 4 --runtime per-core
```

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
