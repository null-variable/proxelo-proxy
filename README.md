# proxelo-proxy

The data plane of Proxelo: the process that accepts client connections and
serves traffic. It is written in Rust and is configured only by snapshots
pushed from the control plane ([`proxelo`](https://github.com/null-variable/proxelo)).

The wire format between the two lives in
[`proxelo-api`](https://github.com/null-variable/proxelo-api).

## Status

Early development. The current build validates snapshots; the serving path is
being built next.

## Layout

| Crate | Purpose |
|---|---|
| `crates/proxy` | `proxelo-proxy` binary |
| `crates/snapshot` | Decodes and validates snapshots before they are swapped in |

## Build

```sh
cargo build --release
./target/release/proxelo-proxy version
./target/release/proxelo-proxy check snapshot.bin
```

## Development rules

- No `unsafe` outside crates created specifically for FFI. The workspace sets `unsafe_code = "forbid"`.
- `cargo fmt`, `cargo clippy -- -D warnings` and `cargo test` must pass.
- The request path must not allocate per request once a connection is warm. Benchmarks enforce this as the serving path lands.

## License

Licensed under the [Apache License, Version 2.0](LICENSE). See [NOTICE](NOTICE).
