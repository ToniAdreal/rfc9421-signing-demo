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

Optional `keyid` pinning (key-confusion defense): pass `expectedKeyId` and
the verifier asserts the signature's `keyid` equals it *after* the
cryptographic check — a signature from a different key with a different
`keyid` fails with `KEYID_MISMATCH` even when the crypto key itself verifies.

```ts
const ok = verifyRequest(signed, { key: publicKey, expectedKeyId: "my-key" });
// mismatch -> { ok: false, code: "KEYID_MISMATCH", reason: 'keyid mismatch: ...' }
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
- **Nonce (RFC 9421 §2.3)**: pass `nonce` to `signRequest` and it is
  emitted as a `nonce` signature-input parameter — part of the signed
  `@signature-params` line, so a forged nonce fails with
  `SIGNATURE_MISMATCH`. `verifyRequest` returns it as `result.nonce`
  (the wire-seen value, reported before authenticity is established).
  Tracking seen nonces to detect replays is the caller's job.
- Minimal `Signature-Input` / `Signature` field parsing for verification.
- **Multi-signature verification**: `verifyAllLabels(req, { key, keys })`
  parses every label from the `Signature-Input` header and verifies each
  one with `verifyRequest`, returning one `VerifyResult` per label in wire
  order. A failing label never blocks the remaining labels — built for
  multi-party flows (e.g. a merchant signature plus a payment-gateway
  signature on the same request). Pass per-label keys via the optional
  `keys` map; labels missing from it fall back to `key`. Duplicate labels
  are verified once (first occurrence); a request with no `Signature-Input`
  header yields an empty array.

```ts
import { verifyAllLabels } from "./dist/index.js";

const results = verifyAllLabels(signed, {
  key: merchantPublicKey,
  keys: { gateway: gatewayPublicKey },
});
for (const r of results) {
  console.log(r.label, r.ok ? "OK" : `FAILED (${r.code})`);
}
```

## Limitations (honest)

- **Subset of RFC 9421.** Not implemented: `ecdsa-p256-sha256`, `rsa-pss-sha512`,
  `hmac-sha512`, `@query`, `@status`, `@request-response`, trailers, `bs`,
  `keyid` resolution / key discovery. The verifier
  checks one signature label per call; `verifyAllLabels` verifies every
  label in the request (one `VerifyResult` per label).
- **Authority normalization** uses WHATWG `URL` semantics (lowercased, default
  ports elided). Both sides of this library agree with each other, but a
  foreign implementation with different normalization would disagree.
- **Body binding only understands `sha-512`** digests.
- **No replay cache.** The `nonce` parameter is emitted, signed, and
  returned so callers can track seen nonces, but this library keeps no
  cache itself — detecting a nonce reuse within the freshness window is
  the caller's job (see the planned `replay-cache-go` companion).
- **Demo-grade key management.** Keys are passed in directly; there is no
  keystore, rotation, or `keyid`→key lookup.

## Interoperability

Honest status: **this library has only been tested against itself.** No
third-party RFC 9421 implementation has been exercised against it yet, so
cross-implementation compatibility is untested. Interop reports and issues
are welcome.

What *has* been verified beyond the sign→verify round-trip tests:

- The signature-base construction follows RFC 9421 §2.5. The golden vector
  in `test/golden.test.ts` is asserted against a hand-written expectation
  derived from the spec's format rules — that checks internal consistency
  with the spec as implemented here, not independent agreement.
- The `Content-Digest: sha-512` value is plain SHA-512; the golden vector
  was cross-checked against `openssl dgst -sha512` output for the same
  input.

Known interop hazards (things a foreign implementation may do differently;
most also appear in [Limitations](#limitations)):

- **Key delivery is out of band.** `keyid` is carried but never resolved —
  no key discovery, JWKS, or keystore. Both sides must agree on keys and
  `keyid` values manually.
- **Authority normalization.** `@authority` is normalized with WHATWG `URL`
  semantics (lowercased, default ports elided). A peer that normalizes
  differently will build a different signature base.
- **Covered component selection.** Signer and verifier must agree on the
  exact covered components, in the exact order. Defaults here are
  `@method @authority @path`, plus `content-digest` when a body exists.
- **Digest algorithm.** Body binding only understands `sha-512`. A peer
  sending `sha-256` digests fails with "no sha-512 content-digest present".
- **Signature algorithms.** Only `ed25519` and `hmac-sha256` are
  implemented. Not supported: `ecdsa-p256-sha256`, `rsa-pss-sha512`,
  `hmac-sha512`, or anything else.
- **Components.** Not supported: `@query`, `@status`, `@request-response`,
  trailers, `bs`, and other derived components beyond the list under
  "What it implements".
- **Single signature.** The verifier checks one signature label per call;
  messages carrying multiple signatures are not handled.
- **Freshness is not replay protection.** `created`/`expires` bound the
  acceptance window, but there is no nonce or replay cache.

In short: a spec-conformant *subset* that is self-consistent and locally
well-tested, but wire compatibility with any third-party RFC 9421
implementation has **not** been demonstrated. Do not assume it without
testing.

Security notes (scope, replay, key management, why not production):
see [SECURITY.md](SECURITY.md).

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

## Error codes

`verifyRequest` never throws: every failure returns `{ ok: false, code, reason, label, ... }`.
`verifyRequestOrThrow` is the throwing twin — it raises a `VerifyError`
(an `Error` subclass, so existing generic `catch (e)` handlers keep working)
carrying the same machine-readable `.code`, plus `.label`, `.keyId`, `.alg`.

Codes are stable across versions; the human-readable `reason` strings are not.

| `code` | meaning |
|--------|---------|
| `MISSING_SIGNATURE_INPUT` | `signature-input` header absent |
| `MISSING_SIGNATURE` | `signature` header absent |
| `MALFORMED_SIGNATURE_INPUT` | `signature-input` present but unparseable |
| `SIGNATURE_BASE_BUILD_FAILED` | covered components could not be rebuilt from the request |
| `MALFORMED_SIGNATURE` | `signature` present but unparseable |
| `UNSUPPORTED_ALG` | `alg` parameter names an unsupported algorithm |
| `VERIFICATION_ERROR` | the crypto layer itself threw (e.g. malformed key material) |
| `SIGNATURE_MISMATCH` | cryptographic signature does not verify (wrong key or tampering) |
| `KEYID_MISMATCH` | signature's `keyid` does not match the verifier's `expectedKeyId` (or no `keyid` present) |
| `MISSING_CONTENT_DIGEST` | body present but no `sha-512` entry in `content-digest` |
| `BODY_DIGEST_MISMATCH` | body bytes do not match the signed `sha-512` digest |
| `EXPIRED` | `expires` timestamp is in the past (beyond tolerance) |
| `CREATED_IN_FUTURE` | `created` timestamp is in the future (beyond clock-skew tolerance) |

```ts
import { verifyRequestOrThrow, isVerifyError } from "rfc9421-signing-demo";

try {
  const { label, keyId, alg } = verifyRequestOrThrow(req, { key: publicKey });
  // ...
} catch (e) {
  if (isVerifyError(e)) {
    if (e.code === "EXPIRED") { /* ask the client to re-sign */ }
    // e.reason carries the human-readable detail; e is still an Error.
  }
  throw e;
}
```

## Reproducibility

`npm test` runs 57 tests including a golden signature-base vector and a
golden `Content-Digest` vector (the latter cross-checked against `openssl`).
No network access, no randomness in assertions (keys are generated per-test
but only round-trip properties are asserted).

## License

MIT
