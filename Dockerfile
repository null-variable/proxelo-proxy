# syntax=docker/dockerfile:1
# proxelo-proxy image. FEATURES picks an allocator: "", jemalloc or mimalloc.
#   docker build -t proxelo-proxy .
#   docker build -t proxelo-proxy:jemalloc --build-arg FEATURES=jemalloc .
FROM rust:1.98-slim-trixie AS build
RUN apt-get update \
 && apt-get install -y --no-install-recommends make git pkg-config libssl-dev \
 && rm -rf /var/lib/apt/lists/*
ARG FEATURES=""
WORKDIR /src
COPY . .
RUN --mount=type=cache,target=/usr/local/cargo/registry \
    --mount=type=cache,target=/usr/local/cargo/git \
    --mount=type=cache,target=/src/target \
    cargo build --release --locked -p proxelo-proxy ${FEATURES:+--features "$FEATURES"} \
 && cp target/release/proxelo-proxy /proxelo-proxy

FROM debian:trixie-slim
RUN apt-get update \
 && apt-get install -y --no-install-recommends ca-certificates libssl3t64 \
 && rm -rf /var/lib/apt/lists/* \
 && groupadd --system --gid 10001 proxelo \
 && useradd --system --uid 10001 --gid proxelo --home-dir /var/lib/proxelo proxelo \
 && install -d -o proxelo -g proxelo -m 0750 /var/lib/proxelo /run/proxelo
COPY --from=build /proxelo-proxy /usr/local/bin/proxelo-proxy
USER proxelo
# The last-known-good snapshot lives here; the control socket directory is
# shared with the control plane container.
VOLUME ["/var/lib/proxelo"]
# SIGQUIT lets open connections finish (up to --drain seconds).
STOPSIGNAL SIGQUIT
ENTRYPOINT ["proxelo-proxy"]
CMD ["run", "--data", "/var/lib/proxelo", "--socket", "/run/proxelo/control.sock"]
