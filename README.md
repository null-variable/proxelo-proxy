# proxelo-proxy

The data plane of Proxelo: the process that accepts client connections and
serves traffic. It is written in Rust and is configured only by snapshots
pushed from the control plane ([`proxelo`](https://github.com/null-variable/proxelo)).

The wire format between the two lives in
[`proxelo-api`](https://github.com/null-variable/proxelo-api).
How the control plane, the snapshot and the proxy fit together is described
in [proxelo's architecture overview](https://github.com/null-variable/proxelo/blob/main/docs/architecture.md).

## Status

Early development. `proxelo-proxy run` receives snapshots from the control
plane and serves them; `proxelo-proxy serve` serves a single snapshot file.
Both serve HTTP/1.1, and HTTP/2 and TLS on TLS listeners:

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
- Route conditions after the path match: methods, headers, query arguments
  and a CEL expression (standard library and network extension); routes with
  the same path are tried in order, then the one without conditions.
- `proxelo-proxy sim`: the dry-load helper the control plane uses to validate
  snapshots and simulate requests with this engine (same parser, site lookup
  and phases; proxying reports the upstream instead of connecting).
- Static files (`root`, `index`) and reverse proxying with smooth weighted
  round robin or least_conn, backup targets, passive health (`max_fails`,
  `fail_timeout`), `proxy_next_upstream` retries on errors, timeouts and
  listed statuses, per-route timeouts and keepalive upstream connections
  with an idle timeout and a request limit.
- TLS with OpenSSL 3: minimum version and cipher list per listener, one
  certificate per site chosen by SNI with the same lookup as `Host`, a
  default certificate for handshakes without a matching name. Certificates
  and keys are checked when a snapshot is loaded, and the TLS contexts are
  built before a swap, so a snapshot OpenSSL rejects is refused whole.
- HTTP/2 through ALPN (the `h2` crate) on TLS listeners. Each stream runs
  through the same phases, proxying, logs and metrics as HTTP/1.1.
- Response and upstream request headers set, added or removed per route
  (nginx `add_header` with `always`, `proxy_set_header`,
  `proxy_hide_header`), with variables such as `$request_id` and `$scheme`.
- Redirect to https per site, and ACME HTTP-01 and TLS-ALPN-01 challenges
  handed down by the control plane.
- Access logs per route in nginx `log_format` syntax with `escape=json`,
  to stdout, stderr or files, written by a background thread; lines are
  dropped and counted when it falls behind. SIGUSR1 reopens files.
- Prometheus metrics on `--metrics` (default `127.0.0.1:9145/metrics`):
  requests and latency per site and route, upstream responses, failures,
  latency and health per target, connections, TLS handshake errors and
  snapshot swaps. Counters survive swaps.

Snapshots arrive as bytes and are checked against their SHA-256 hash
before they are applied or written as the last-known-good snapshot. A
replaced snapshot is freed on a separate thread.

Behaviour follows nginx defaults where the snapshot has no setting yet:
timeouts (`client_header_timeout 60s`, `keepalive_timeout 75s`,
`proxy_read_timeout 60s`, ...), `client_max_body_size 1m`, error pages,
the 301 for directories without a trailing slash, `proxy_next_upstream error
timeout` and the response headers nginx hides from upstreams.

## Layout

| Crate | Purpose |
|---|---|
| `crates/proxy` | `proxelo-proxy` binary |
| `crates/snapshot` | Validates snapshots and builds the runtime form (host and route lookup with PCRE2, route conditions with CEL, templates, resolved upstream targets) |
| `crates/http1` | HTTP/1.1 codec: in-place parsing, strict framing, chunked decoding, path normalization |
| `crates/server` | Accept loop, TLS (`tls.rs`) and HTTP/2 (`h2.rs`), request phases (shared with the simulator), variables, static files, proxying, upstream state, header changes, access logs, metrics, snapshot swap, listening sockets that follow the snapshot |
| `crates/sync` | Control plane client: receives snapshots over the control socket, acks them and reports traffic counters every 5 s for the commit-confirm guard |
| `fuzz` | `cargo fuzz` targets for the codec (separate workspace, nightly) |

## Build

```sh
cargo build --release      # builds the bundled PCRE2; links OpenSSL 3 found by
                           # pkg-config or Homebrew (or set OPENSSL_DIR)
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
