# attestation-proxy

Small Rust HTTP sidecar for confidential workloads.

It serves guest attestation data, proxies KBS/CDH resource reads, and manages
storage ownership flows such as unlock, password change, recovery, and
auto-unlock.

## Main endpoints

- `GET /health`
- `GET /status`
- `GET /v1/attestation?nonce=<base64-32B>&domain=<host>&leaf_spki_sha256=<hex-or-base64-32B>`
- `GET /v1/attestation/info`
- `GET /cdh/resource/<path>`
- `POST /unlock`
- `POST /change-password`
- `POST /recover`
- `POST /enable-auto-unlock`
- `POST /disable-auto-unlock`
- `POST /receipts/sign`

The full cross-repo runtime contract lives in
[`enclava-tenant-manifests/docs/ATTESTATION-PROXY-CONTRACT.md`](../enclava-tenant-manifests/docs/ATTESTATION-PROXY-CONTRACT.md).

## Attestation REPORT_DATA binding

`GET /v1/attestation` rejects caller-supplied `runtime_data`. Because this
proxy runs plain HTTP behind Caddy and cannot extract the TLS leaf certificate
itself, callers must provide `nonce`, `domain`, and `leaf_spki_sha256`.

The proxy computes SNP `REPORT_DATA` locally:

- bytes `0..32`: CE-v1 SHA-256 transcript hash over
  `purpose=enclava-tee-tls-v1`, `domain`, 32-byte `nonce`, and
  `leaf_spki_sha256`
- bytes `32..64`: `SHA256(raw 32-byte Ed25519 receipt public key)`

Only those 64 computed bytes are base64-encoded and forwarded to AA as
`runtime_data`.

## Receipt signing

`POST /receipts/sign` signs workload lifecycle receipts with an Ed25519 key
created inside the running pod. Requests use:

```json
{
  "receipt_type": "rekey",
  "app_id": "app-id",
  "resource_path": "default/app-id-owner/workload-secret-seed",
  "new_value_sha256": "64 lowercase or uppercase hex chars"
}
```

Supported `receipt_type` values are `rekey`, `teardown`, and
`unlock_mode_transition`. The response includes `receipt.pubkey`,
`receipt.pubkey_sha256`, `receipt.payload_canonical_bytes`, and
`receipt.signature`; `payload_canonical_bytes` is CE-v1 TLV and is the exact
message signed by Ed25519.

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
