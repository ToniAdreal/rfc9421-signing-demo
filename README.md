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
npm test   # 261 tests, all local, no network
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
// HMAC secrets must be ≥ 32 bytes (RFC 2104: key ≥ hash output length).
const secret = secretKey("a-shared-hmac-secret-of-32-bytes!!");
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

Optional `keyid`→key resolution (key discovery / rotation): pass `keyResolver`
and the verifier looks up the signing key from the `keyid` claimed in the
signature-input, instead of using a fixed `key`. Mutually exclusive with
`key` (passing both throws a configuration error).

```ts
const store = new Map([["my-key", publicKey], ["old-key", oldPublicKey]]);
const result = verifyRequest(signed, {
  keyResolver: (keyId) => store.get(keyId), // unknown keyid -> KEY_RESOLUTION_FAILED
});
```

JWK public-key distribution (webhook / gateway deployments, where PEM is
awkward to ship): export the ed25519 public key as a plain RFC 8037 object,
send it as JSON, and import it on the verifier side. Private JWKs (`"d"`
present) are refused — this helper is public-key distribution only, so
private keys stay in PEM on the signer side.

```ts
import { exportPublicKeyJwk, importPublicKeyJwk } from "./dist/index.js";
const jwk = exportPublicKeyJwk(publicKey); // { kty: "OKP", crv: "Ed25519", x: "..." }
const wireKey = JSON.parse(JSON.stringify(jwk)); // what the verifier receives
verifyRequest(signed, { key: importPublicKeyJwk(wireKey) }); // { ok: true, ... }
// Malformed JWKs (missing kty/crv/x, wrong curve, corrupt x) throw a clear
// "invalid JWK: ..." Error; never a verification failure.
```

P-256 gateways get the same treatment: `exportPublicKeyJwkP256` /
`importPublicKeyJwkP256` handle the RFC 7518 EC shape
(`{ kty: "EC", crv: "P-256", x, y }`) for `ecdsa-p256-sha256` verifiers,
with the same refusal of private (`"d"`) material.

Receiving signed webhooks with Node's `http` server — the receive→verify
chain via `fromNodeRequest`:

```ts
import { createServer } from "node:http";
import { fromNodeRequest, verifyRequest } from "./dist/index.js";

const server = createServer((req, res) => {
  const chunks: Buffer[] = [];
  req.on("data", (c) => chunks.push(c));
  req.on("end", () => {
    // IncomingMessage is a stream: the body must be buffered first and
    // passed in — the adapter never reads it. Pass the raw bytes, never a
    // re-serialized object, so the Content-Digest check sees exact bytes.
    const body = Buffer.concat(chunks);
    const result = verifyRequest(fromNodeRequest(req, body), {
      key: gatewayPublicKey, // or keyResolver for keyid-based lookup
    });
    if (!result.ok) {
      res.writeHead(401).end(`bad signature: ${result.code}`);
      return;
    }
    res.writeHead(200).end("ok"); // result.nonce / result.keyId available here
  });
});
```

What `fromNodeRequest` does: rebuilds the absolute URL as
`<scheme>://<host><path>` (the `host` header, port included, is preserved
verbatim), lowercases header names, and joins multi-value headers with
`", "` — the same convention `signRequest`/`getHeader` use. The scheme
defaults to `https` on a TLS socket, `http` otherwise; behind a
TLS-terminating proxy pass `{ scheme: "https" }` explicitly, because signer
and verifier must agree on the exact URL (`@scheme`/`@authority`/`@path`
are covered components). Missing `method`/`url`/`host` throws a
configuration `Error` instead of silently defaulting.

## What it implements

- **Signature base** (§2.5): `"id": value` lines for each covered component,
  then the `"@signature-params"` line. Covered components: `@method`,
  `@scheme`, `@authority`, `@path`, `@query`, `@target-uri`, `@created`,
  `@expires`, plus any HTTP header field (case-insensitive, multi-values joined).
- **Sign-side input guards**: `signRequest` fails fast with a descriptive
  configuration error instead of minting a broken signature — `expires`
  earlier than `created` (a signature that is expired at birth), an empty
  `coveredComponents` list (would sign nothing), and non-integer
  `created`/`expires` (the verifier's `signature-input` parser only
  recognizes integer seconds, so a fractional value would silently diverge
  between signer and verifier). `expires === created` is allowed.
- **Optional `keyid`**: RFC 9421 leaves `keyid` optional — `signRequest`'s
  `keyId` is too, and omitting it emits no `keyid` parameter on the wire.
  The verifier reports `keyId: undefined`, and pinning/resolution flows
  treat it as a missing claim (e.g. `keyResolver` → `KEY_RESOLUTION_FAILED`,
  `expectedKeyId` → `KEYID_MISMATCH`).
- **Algorithms**: `ed25519`, `ecdsa-p256-sha256` (NIST P-256; DER-encoded
  ECDSA signatures per RFC 9421 §3.3.4), `rsa-pss-sha512` (RSASSA-PSS with
  SHA-512, MGF1 with SHA-512, 64-byte salt per RFC 9421 §3.3.1),
  `hmac-sha256` (≥ 32-byte secrets) and `hmac-sha512` (≥ 64-byte secrets;
  constant-time compare; floors paired with the algorithm per RFC 2104
  §3).
- **Body binding**: `Content-Digest: sha-512=:…:` is computed when the body
  is covered, and the verifier recomputes it — a swapped body fails even if
  the signature itself is valid. The verifier prefers `sha-512` but falls
  back to `sha-256` when the header carries no `sha-512` entry (for foreign
  signers that only send `sha-256`); signing always emits `sha-512`.
- **Freshness**: `created` enforced with a configurable clock-skew
  tolerance (`clockSkewToleranceSec`, default 60s); `expires` enforced
  strictly by default, with an optional grace period
  (`expiredToleranceSec`, default 0s). A verifier can also demand the
  timestamps exist at all: `requireCreated` / `requireExpires` reject
  signatures that omit them (`MISSING_CREATED` / `MISSING_EXPIRES`) —
  for signers you control, `signRequest` always sends `created`.
- **Nonce (RFC 9421 §2.3)**: pass `nonce` to `signRequest` and it is
  emitted as a `nonce` signature-input parameter — part of the signed
  `@signature-params` line, so a forged nonce fails with
  `SIGNATURE_MISMATCH`. `verifyRequest` returns it as `result.nonce`
  (the wire-seen value, reported before authenticity is established).
  For replay detection, pass a `ReplayCache` via
  `verifyRequest(req, { key, replayCache })`: a nonce already seen within
  the cache TTL fails with `NONCE_REPLAY` (fresh nonces are recorded only
  *after* the signature fully verifies, so forgeries can't pollute the
  cache). The cache is in-memory, bounded (LRU + TTL), and per-process —
  multi-verifier deployments still need a shared nonce store (see the
  Limitations and SECURITY.md). Call `cache.stats()` for observability:
  it returns a `{ size, hits, misses, evictions }` snapshot (expired-entry
  reclamation and LRU eviction both count as evictions); `cache.clear()`
  also resets the counters.
- Minimal `Signature-Input` / `Signature` field parsing for verification.
- **Node http server adapter**: `fromNodeRequest(req, body, opts?)`
  normalizes an `http.IncomingMessage` into a `RequestLike` (absolute URL
  rebuilt from the `host` header, lowercased header names, multi-value
  headers joined with `", "`), so `verifyRequest` plugs straight into a
  webhook receiver — see the Quickstart receive→verify example.
- **Multi-signature verification**: `verifyAllLabels(req, { key, keys })`
  parses every label from the `Signature-Input` header and verifies each
  one with `verifyRequest`, returning one `VerifyResult` per label in wire
  order. A failing label never blocks the remaining labels — built for
  multi-party flows (e.g. a merchant signature plus a payment-gateway
  signature on the same request). Pass per-label keys via the optional
  `keys` map; labels missing from it fall back to `key`. When each party
  signs with a different key id, pin them per label via the optional
  `expectedKeyIds` map (label→keyid); labels missing from it fall back to
  the global `expectedKeyId`. Duplicate labels are verified once (first
  occurrence); a request with no `Signature-Input` header yields an empty
  array.

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

- **Multi-party signing**: `addSignature(signedReq, opts)` appends a second
  party's signature to an already-signed request, producing a genuine
  multi-label RFC 9421 §2.4 dictionary — the sign-side twin of
  `verifyAllLabels`. Both parties sign the same original request content
  (the existing `Signature-Input` / `Signature` headers are stripped
  before the second base is built, so dictionaries are never re-signed).
  Duplicate or empty labels fail fast with a clear error; appending to an
  unsigned request fails fast too. The input request is never mutated.

```ts
import { addSignature, signRequest } from "./dist/index.js";

// merchant signs first with its own key
const merchantSigned = signRequest(req, {
  keyId: "merchant-key-1",
  alg: "ed25519",
  key: merchantPrivateKey,
  label: "merchant",
});
// payment gateway appends its own label without touching the merchant's
const dual = addSignature(merchantSigned, {
  keyId: "gateway-key-7",
  alg: "hmac-sha256",
  key: gatewaySecret,
  label: "gateway",
});
```

## Limitations (honest)

- **Subset of RFC 9421.** Not implemented: `rsa-v1_5-sha256`, `@status`, `@request-response`, trailers, `bs`,
  and network key discovery (JWKS / keystores over HTTP). `keyid`→key
  resolution *is* supported opt-in: pass `VerifyOptions.keyResolver` and the
  verifier maps the claimed `keyid` to a `KeyObject` (unknown `keyid` fails
  with `KEY_RESOLUTION_FAILED`); the resolver itself is caller-provided and
  runs in-process. The verifier
  checks one signature label per call; `verifyAllLabels` verifies every
  label in the request (one `VerifyResult` per label).
- **Authority normalization** uses WHATWG `URL` semantics (lowercased, default
  ports elided). Both sides of this library agree with each other, but a
  foreign implementation with different normalization would disagree.
- **Body binding digest algorithms.** The verifier understands `sha-512`
  (preferred when present) and `sha-256` (fallback when no `sha-512` entry
  exists); signing emits `sha-512` only. Other `content-digest` algorithms
  are rejected with `MISSING_CONTENT_DIGEST`.
- **In-memory replay cache only.** The optional `ReplayCache` is a
  per-process helper with a configurable TTL and LRU capacity cap — it
  does not survive restarts and is not shared between verifier instances.
  If you run multiple verifiers, deduplicate nonces in a shared store
  (e.g. Redis) instead of (or in addition to) this cache.
- **Demo-grade key management.** Keys are passed in directly or resolved via a
  caller-provided `keyResolver`; there is no built-in keystore, key
  rotation schedule, JWKS fetching, or `keyid`→key lookup over the network.

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

- **Key delivery is out of band.** `keyid` is carried and can be resolved
  opt-in via `VerifyOptions.keyResolver` (a caller-provided in-process
  lookup; unknown `keyid` fails with `KEY_RESOLUTION_FAILED`) — there is
  still no key discovery, JWKS, or keystore over the network. Both sides
  must agree on keys and `keyid` values manually.
- **Authority normalization.** `@authority` is normalized with WHATWG `URL`
  semantics (lowercased, default ports elided). A peer that normalizes
  differently will build a different signature base.
- **Covered component selection.** Signer and verifier must agree on the
  exact covered components, in the exact order. Defaults here are
  `@method @authority @path`, plus `content-digest` when a body exists.
- **Digest algorithm.** Body binding understands `sha-512` (preferred) and
  `sha-256` (fallback when no `sha-512` entry is present). A peer sending
  only other digest algorithms fails with "no sha-512 or sha-256
  content-digest present".
- **Signature algorithms.** Implemented: `ed25519`, `ecdsa-p256-sha256`
  (DER-encoded, RFC 9421 §3.3.4), `rsa-pss-sha512` (RSASSA-PSS with
  SHA-512, MGF1 with SHA-512, and a 64-byte salt per RFC 9421 §3.3.1 —
  signatures are probabilistic, so verifiers re-verify rather than
  re-sign-and-compare), `hmac-sha256`, `hmac-sha512` (constant-time
  compare; ≥ 64-byte secrets per RFC 2104 §3). Not supported:
  `rsa-v1_5-sha256` or anything else.
- **Missing `alg` parameter.** `alg` is optional per RFC 9421 §2.3
  (Appendix B.2.5's hmac-sha256 vector omits it), but this library
  historically defaults a missing `alg` to `"ed25519"`, so a foreign
  signature without `alg` could not be verified end-to-end. Opt-in
  fallback: `VerifyOptions.algFallback: "infer"` infers the algorithm
  from the resolved key's shape (`secret` → `hmac-sha256`, ed25519 key
  → `ed25519`, P-256 EC key → `ecdsa-p256-sha256`, RSA key →
  `rsa-pss-sha512`) and throws a caller
  configuration `Error` when a wire-carried `alg` contradicts the key's
  shape. Automatic detection is opt-in only — without it, a missing
  `alg` keeps meaning `"ed25519"`, exactly as before.
- **HMAC secret length.** `secretKey()` refuses secrets shorter than 32
  bytes (the `hmac-sha256` floor), and the sign/verify paths pair the
  floor with the chosen algorithm: `hmac-sha256` → ≥ 32 bytes,
  `hmac-sha512` → ≥ 64 bytes (RFC 2104 §3: the key SHOULD be at least as
  long as the hash output). A short key is a caller configuration error
  and throws on both sides — a signer can never mint signatures that the
  verifier would also (correctly) refuse to check, and a secret adequate
  only for `hmac-sha256` is never silently accepted for `hmac-sha512`.
- **Components.** Not supported: `@status`, `@request-response`,
  trailers, `bs`, and other derived components beyond the list under
  "What it implements".
- **Multiple signatures.** `verifyRequest` checks one label per call; for
  multi-party flows, `verifyAllLabels` verifies every label in the request
  (one `VerifyResult` per label, and a failing label never blocks the
  remaining labels). Per-label key material is still caller-supplied via
  the optional `keys` map — a peer that expects automatic per-label key
  discovery will need keys wired up manually.
- **Freshness is not automatic replay protection.** `created`/`expires`
  only bound the acceptance window. RFC 9421 `nonce` is supported
  (`signRequest` accepts a `nonce` option; `verifyRequest` echoes it back
  as `result.nonce`), and an opt-in per-process in-memory `ReplayCache`
  (LRU + TTL) rejects a replayed nonce with `NONCE_REPLAY`. There is no
  shared or distributed nonce store — multi-verifier deployments still
  need one (see Limitations).

In short: a spec-conformant *subset* that is self-consistent and locally
well-tested, but wire compatibility with any third-party RFC 9421
implementation has **not** been demonstrated. Do not assume it without
testing.

Security notes (scope, replay, key management, why not production):
see [SECURITY.md](SECURITY.md).

## Benchmarks

`npm run bench` measures locally-observed sign/verify throughput per
algorithm (3000 timed iterations per op after 200 warmup, printing the Node
version and CPU). One real run on 2026-10-07:

| alg | op | throughput |
|-----|--------|------------|
| ed25519 | sign | ~8,100 ops/sec (~124 µs/op) |
| ed25519 | verify | ~4,200 ops/sec (~238 µs/op) |
| hmac-sha256 | sign | ~41,800 ops/sec (~24 µs/op) |
| hmac-sha256 | verify | ~28,700 ops/sec (~35 µs/op) |
| hmac-sha512 | sign | ~24,700 ops/sec (~41 µs/op) |
| hmac-sha512 | verify | ~28,100 ops/sec (~36 µs/op) |
| ecdsa-p256-sha256 | sign | ~10,900 ops/sec (~91 µs/op) |
| ecdsa-p256-sha256 | verify | ~4,200 ops/sec (~240 µs/op) |

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
| `KEY_RESOLUTION_FAILED` | `keyResolver` could not map the signature's `keyid` to a key (missing or unknown `keyid`) |
| `MISSING_CONTENT_DIGEST` | body present but no `sha-512` or `sha-256` entry in `content-digest` |
| `BODY_DIGEST_MISMATCH` | body bytes do not match the signed `sha-512` (or `sha-256` fallback) digest |
| `EXPIRED` | `expires` timestamp is in the past (beyond tolerance) |
| `CREATED_IN_FUTURE` | `created` timestamp is in the future (beyond clock-skew tolerance) |
| `MISSING_CREATED` | `requireCreated` is set but the signature carries no `created` |
| `MISSING_EXPIRES` | `requireExpires` is set but the signature carries no `expires` |
| `NONCE_REPLAY` | nonce already seen within the replay-cache TTL (`VerifyOptions.replayCache`) |

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

`npm test` runs 261 tests including the RFC 9421 Appendix B.2.5 independent interop vector, a golden signature-base vector and a
golden `Content-Digest` vector (the latter cross-checked against `openssl`).
No network access, no randomness in assertions (keys are generated per-test
but only round-trip properties are asserted).

## License

MIT
