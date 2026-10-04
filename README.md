# rfc9421-signing-demo

Sign and verify HTTP messages per [RFC 9421](https://www.rfc-editor.org/rfc/rfc9421.html)
(HTTP Message Signatures), with [RFC 9530](https://www.rfc-editor.org/rfc/rfc9530.html)
`Content-Digest` body binding. TypeScript, zero runtime dependencies (only `node:crypto`).

Built as a working building block of the **Tokenta API-verification research**
(baseline B1: signature verification cost/latency). It is a demo, not a
certified implementation — see [Limitations](#limitations).

## Install

Requires Node.js ≥ 20.

```bash
npm install
npm run build
npm test   # 18 tests, all local, no network
```

## Quickstart

```ts
import {
  generateEd25519KeyPair,
  signRequest,
  verifyRequest,
} from "./dist/index.js";

const { publicKey, privateKey } = generateEd25519KeyPair();

const signed = signRequest(
  {
    method: "POST",
    url: "https://api.example.com/v1/payments",
    headers: { "content-type": "application/json" },
    body: JSON.stringify({ amount: 100 }),
  },
  { keyId: "my-key", alg: "ed25519", key: privateKey },
);

console.log(signed.headers["signature-input"]);
// sig1=("@method" "@authority" "@path" "content-digest");created=...;keyid="my-key";alg="ed25519"
console.log(signed.headers["signature"]);
// sig1=:base64...:

const result = verifyRequest(signed, { key: publicKey });
console.log(result); // { ok: true, label: "sig1", keyId: "my-key", alg: "ed25519" }
```

Tamper with the body, a covered header, the path, or the key — verification
fails with a specific `reason` (`"body does not match content-digest"`,
`"signature mismatch"`, `"signature expired"`, …).

HMAC variant:

```ts
import { secretKey } from "./dist/index.js";
const secret = secretKey("shared-secret");
const signed = signRequest(req, { keyId: "k", alg: "hmac-sha256", key: secret });
const result = verifyRequest(signed, { key: secret });
```

## What it implements

- **Signature base** (§2.5): `"id": value` lines for each covered component,
  then the `"@signature-params"` line. Covered components: `@method`,
  `@scheme`, `@authority`, `@path`, `@target-uri`, `@created`, `@expires`,
  plus any HTTP header field (case-insensitive, multi-values joined).
- **Algorithms**: `ed25519` and `hmac-sha256` (constant-time compare).
- **Body binding**: `Content-Digest: sha-512=:…:` is computed when the body
  is covered, and the verifier recomputes it — a swapped body fails even if
  the signature itself is valid.
- **Freshness**: `created` enforced with a configurable clock-skew
  tolerance (`clockSkewToleranceSec`, default 60s); `expires` enforced
  strictly by default, with an optional grace period
  (`expiredToleranceSec`, default 0s).
- Minimal `Signature-Input` / `Signature` field parsing for verification.

## Limitations (honest)

- **Subset of RFC 9421.** Not implemented: `ecdsa-p256-sha256`, `rsa-pss-sha512`,
  `hmac-sha512`, `@query`, `@status`, `@request-response`, trailers, `bs`,
  `keyid` resolution / key discovery, `nonce` replay tracking. The verifier
  checks one signature label per call.
- **Authority normalization** uses WHATWG `URL` semantics (lowercased, default
  ports elided). Both sides of this library agree with each other, but a
  foreign implementation with different normalization would disagree.
- **Body binding only understands `sha-512`** digests.
- **No replay cache.** Freshness (`created`/`expires`) bounds the window, but
  deduplicating signatures within that window is the caller's job (see the
  planned `replay-cache-go` companion).
- **Demo-grade key management.** Keys are passed in directly; there is no
  keystore, rotation, or `keyid`→key lookup.

## Benchmarks

`npm run bench` measures locally-observed sign/verify throughput per
algorithm (3000 timed iterations per op after 200 warmup, printing the Node
version and CPU). One real run on 2026-10-03:

| alg | op | throughput |
|-----|--------|------------|
| ed25519 | sign | ~16,300 ops/sec (~61 µs/op) |
| ed25519 | verify | ~4,500 ops/sec (~223 µs/op) |
| hmac-sha256 | sign | ~37,600 ops/sec (~27 µs/op) |
| hmac-sha256 | verify | ~40,500 ops/sec (~25 µs/op) |

Environment: Node v24.20.0, linux/x64, AMD EPYC 9D25 (virtualized; shared
host, so numbers vary run to run). Request fixture: POST with a 31-byte JSON
body, covered components `@method @authority @path content-digest`.
Machine-local measurements for capacity planning, not guaranteed
throughput — run `npm run bench` on your own hardware.

## Reproducibility

`npm test` runs 18 tests including a golden signature-base vector and a
golden `Content-Digest` vector (the latter cross-checked against `openssl`).
No network access, no randomness in assertions (keys are generated per-test
but only round-trip properties are asserted).

## License

MIT
