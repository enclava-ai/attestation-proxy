FROM rust:1.92-bookworm AS builder

RUN apt-get update && \
    apt-get install -y --no-install-recommends musl-tools pkg-config libssl-dev ca-certificates && \
    rm -rf /var/lib/apt/lists/*

WORKDIR /src
COPY Cargo.toml Cargo.lock ./
COPY src ./src

RUN rustup target add x86_64-unknown-linux-musl && \
    cargo build --release --target x86_64-unknown-linux-musl

FROM debian:bookworm-slim AS certs
RUN apt-get update && \
    apt-get install -y --no-install-recommends ca-certificates && \
    rm -rf /var/lib/apt/lists/*

FROM scratch
COPY --from=builder /src/target/x86_64-unknown-linux-musl/release/attestation-proxy /attestation-proxy
COPY --from=certs /etc/ssl/certs/ca-certificates.crt /etc/ssl/certs/ca-certificates.crt

ENTRYPOINT ["/attestation-proxy"]
