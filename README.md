# attestation-proxy

Small Rust HTTP sidecar for confidential workloads.

It serves guest attestation data, proxies KBS/CDH resource reads, and manages
storage ownership flows such as unlock, password change, recovery, and
auto-unlock.

## Main endpoints

- `GET /health`
- `GET /status`
- `GET /v1/attestation`
- `GET /v1/attestation/info`
- `GET /cdh/resource/<path>`
- `POST /unlock`
- `POST /change-password`
- `POST /recover`
- `POST /enable-auto-unlock`
- `POST /disable-auto-unlock`

The full cross-repo runtime contract lives in
[`enclava-tenant-manifests/docs/ATTESTATION-PROXY-CONTRACT.md`](../enclava-tenant-manifests/docs/ATTESTATION-PROXY-CONTRACT.md).

## Local development

Run tests:

```bash
cargo test
```

Run locally:

```bash
cargo run
```

By default the server listens on `0.0.0.0:8081`.

## Container image

Build the container image:

```bash
docker build -t attestation-proxy .
```

The Dockerfile builds a statically linked `x86_64-unknown-linux-musl` binary and
copies it into a minimal runtime image with CA certificates.
