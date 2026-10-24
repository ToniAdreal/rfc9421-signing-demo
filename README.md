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
npm test   # 825 tests, all local, no external network (JWKS tests use a loopback-only server)
```

Or run the bundled demo — one command generates a fresh ed25519 key
pair, signs a fixed payment request (with `Content-Digest` and a
`nonce`), prints the `Signature-Input` / `Signature` headers, and
verifies it. It then prints the signature-base segment: the
RFC 9421 §2.5 signature base of the main signature — the exact
string that was signed — rebuilt with `buildSignatureBase` over
its covered components, followed by a line mapping each base line
to its covered component. It then tampers the body by one byte and
shows the verifier rejecting it with `BODY_DIGEST_MISMATCH`. The demo then
continues with the multi-party flow: a payment gateway appends a
second signature with `addSignature` (hmac-sha256, label `gateway`),
the merged headers are printed, `listSignatureLabels` enumerates
the two labels in wire order (`sig1`, `gateway`), `verifyAllLabels`
verifies both
labels, and tampering `content-type` — covered only by the gateway
signature — fails only the gateway label. The demo then runs the
replay segment: the same signed request is verified twice against an
opt-in `ReplayCache` — the first presentation passes, the second is
rejected with `NONCE_REPLAY` — and a request carrying a different
nonce still verifies. The demo then re-signs the same request with
`contentDigestAlg: "sha-256"` for a peer that only accepts sha-256
digests, prints the sha-512 and sha-256 `Content-Digest` headers
side by side, verifies the sha-256 line, and shows the same
one-byte body tamper rejected with `BODY_DIGEST_MISMATCH`. The demo
then runs the inbound segment: a mock Node `IncomingMessage`-shaped
object (mixed-case headers, a multi-value header, a host with a
port) is normalized with `fromNodeRequest` and verifies, while
rebuilding it with the wrong scheme is rejected with
`SIGNATURE_MISMATCH` because the inbound signature covers `@scheme`.
The demo then runs the JWKS segment: a
`JwksKeyStore` is restored offline from a v1 snapshot of the demo
public key, the demo request verifies through its key resolver, and
a request signed under an unknown `keyid` is rejected with
`KEY_RESOLUTION_FAILED`. The demo closes with the thumbprint
segment: the demo public key is exported as a JWK, its RFC 7638
`jwkThumbprint` is printed, and a request signed with that
thumbprint as its `keyid` verifies with `expectedKeyId` pinned to
the same thumbprint. The demo closes with a structured-field
canonicalization segment: three fixed field values (a Dictionary
with a Decimal member, an Integer Item with leading zeros, a
Dictionary Byte Sequence member) are run through
`canonicalizeStructuredFieldValue` and printed as raw -> canonical
pairs — the canonical form is what a verifier actually compares
for a `;sf` covered component. The demo closes with a
dictionary-member extraction segment: one fixed multi-member
Dictionary value is run through `serializeDictionaryMemberValue`
once per fixed key (an Integer member, a member with parameters, a
Decimal member, a Byte Sequence member, an Inner List member and
a bare key) and printed as key -> serialized-value pairs — the
member value without its Dictionary key, which is what a `;key`
covered component contributes — and a missing key is shown
rejected with its `not present` error. The demo closes with a
signature-params serialization segment: five fixed (covered
components, parameters) cases — an empty component list, the
shared four components with created + keyid + alg, the same four
with all six parameters set, four parameterized component ids,
and a nonce whose quote and backslash must serialize escaped —
are run through `serializeSignatureParams` and printed as
name -> serialized pairs, showing how the inner list and the
parameters in fixed order (created, expires, keyid, alg, nonce,
tag) assemble into the `@signature-params` line a verifier
rebuilds byte-for-byte. The demo closes with a PEM key round-trip
segment: the main ed25519 key pair is exported with
`exportPublicKeyPem` / `exportPrivateKeyPem` (only the first line
of each PEM — its type header — is printed), imported back with
`importPublicKey` / `importPrivateKey`, and the imported keys
complete a fresh sign -> verify round-trip, showing the PEM
export -> import -> verify path a gateway or ops tool performs
when keys are distributed as PEM files rather than JWKs. The demo
closes with a throwing-verification segment: the main signed
request is verified with `verifyRequestOrThrow`, which returns
the verified identity (label, keyid, alg, nonce) instead of a
result object, and the same request with the body tampered by
one byte throws a `VerifyError` whose stable code
(`BODY_DIGEST_MISMATCH`, asserted against the `isVerifyError`
guard outside the printed lines) is printed. The demo closes
with a nonce-generation segment: `generateNonce()` (default
16 bytes) and `generateNonce(32)` draw fresh replay-protection
nonces from the CSPRNG, both are printed with their shapes
(22 / 43 base64url characters, decoding to 16 / 32 bytes), and
the short one signs a fresh request whose verification parses
exactly that nonce back out — outside the printed lines the
demo asserts both shapes, that the two draws differ, and the
sign -> verify nonce round-trip. The demo closes with a JWK
public-key import segment: the main ed25519 public key is
exported with `exportPublicKeyJwk`, carried through a JSON
stringify/parse round-trip as it would cross the wire, and read
back with `importPublicKeyJwk`, and the main signed request
verifies with the imported key — the inbound half of JWK key
distribution (the PEM segment covers the same round-trip for
PEM files). A detached copy whose `x` coordinate has its first
character flipped imports as a different well-formed key, and
verification against it is printed rejected with
`SIGNATURE_MISMATCH`; only the exported JWK's shape
(`kty`/`crv`/43-character `x` length) is printed, never the key
bytes. The demo closes with a key-resolver memoization
segment: a counting resolver over a fixed two-key store is
wrapped with `memoizeKeyResolver` (TTL at the 300-second
default, injected clock pinned to the demo's fixed verify
instant) and passed as `keyResolver` — the main request
verifies twice under the same keyid while the underlying
resolver is called only once, then a request signed under a
second keyid verifies and the printed count advances to two.
The demo closes with an HMAC secret-length guard segment:
fixed secrets (only their byte lengths matter) are run
through `assertHmacSecretLength` — a 32-byte secret passes
for `hmac-sha256` and a 64-byte secret passes for
`hmac-sha512`, while a secret one byte below each floor
(31 / 63 bytes) is printed rejected with the guard's exact
message, asserted outside the printed lines against
hand-pinned expectations; only algorithm names and byte
lengths are printed, never key bytes. The demo closes with an
RSA modulus-length guard segment: fixed-shape keys are run
through `assertRsaModulusLength` under a fixed caller context
— an RSA public key exactly at the 2048-bit floor passes,
while a 1024-bit RSA public key and the main line's ed25519
public key (not an RSA key at all) are printed rejected with
the guard's exact messages, asserted outside the printed
lines against hand-pinned expectations; only key types and
modulus lengths are printed, never key bytes. The demo closes
with an ECDSA P-256 signing segment: the same fixed payment
request is signed under `ecdsa-p256-sha256` with a P-256 key
pair from `generateP256KeyPair`, its `Signature-Input` is
printed (algorithm and keyid, never key bytes), verification
is printed passing with its label / keyid / alg / nonce
identity — asserted outside the printed lines against
hand-pinned expectations — and the same request with its
body tampered by one byte is printed rejected with
`BODY_DIGEST_MISMATCH`. The demo closes with a
Content-Digest algorithm guard segment: fixed values are
run through `assertContentDigestAlg` — the two emittable
algorithms (`sha-512`, `sha-256`) pass, while a fixed
rejected corpus (unknown algorithms `sha-1` / `md5`, the
empty string, wrong-case spellings, a trailing-space
spelling, and the non-string values `undefined` / `null`)
is printed rejected with the guard's exact messages,
asserted outside the printed lines against hand-pinned
expectations; each rejected value is printed only as a
fixed printable label. The demo closes with a ReplayCache
snapshot persistence segment: a request signed with a
fixed nonce verifies against a `ReplayCache` on the
demo's fixed clock, the cache is exported with
`exportSnapshot()` (the printed line carries the entry
count, the fixed nonce and its first-seen instant), a
new cache is rebuilt with `ReplayCache.restore()`, and
the same request verified against the restored cache is
printed rejected with `NONCE_REPLAY` — the restart does
not reopen the replay window — while a fresh-nonce
request verifies against the restored cache and is
recorded only there; outside the printed lines the demo
asserts the restored rejection code and the exported
snapshot against hand-pinned expectations and that the
original cache still holds only the exported entry:

```bash
npm run demo
```

The request data (method, URL, body, `created` timestamp, key id, and
nonce) is fixed in `src/demo.ts` — no network, no wall clock — so every
line except the freshly generated signature itself, the
thumbprint derived from the fresh key, and the nonce-generation
segment's two fresh nonces (only their shapes are stable) is
identical between runs.

## Quickstart

```ts
import {
  generateEd25519KeyPair,
  signRequest,
  verifyRequest,
} from "./dist/src/index.js";

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
import { secretKey } from "./dist/src/index.js";
// HMAC secrets must be ≥ 32 bytes (RFC 2104: key ≥ hash output length).
const secret = secretKey("a-shared-hmac-secret-of-32-bytes!!");
const signed = signRequest(req, { keyId: "k", alg: "hmac-sha256", key: secret });
const result = verifyRequest(signed, { key: secret });
```

Nonce for replay detection (CSPRNG-backed base64url, default 128 bits — never hand-roll with `Math.random`):

```ts
import { generateNonce } from "./dist/src/index.js";
const signed = signRequest(req, { keyId: "k", alg: "ed25519", key: privateKey, nonce: generateNonce() });
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
`key` and `candidateKeys` (passing more than one of the three throws a configuration error).

```ts
const store = new Map([["my-key", publicKey], ["old-key", oldPublicKey]]);
const result = verifyRequest(signed, {
  keyResolver: (keyId) => store.get(keyId), // unknown keyid -> KEY_RESOLUTION_FAILED
});
```

Slow keystore? Wrap the resolver with `memoizeKeyResolver` — successful
`keyid`→key resolutions are cached in-memory for `ttlSec` (default 300s),
so high-rate verification stops hitting the keystore once per signature.
Unknown keyids (`undefined`) and thrown errors are deliberately never
cached, so rotated-in keys are discoverable on the next verify and outages
still converge to `VERIFICATION_ERROR`. The cache is bounded by
`maxEntries` (default 10_000, matching `ReplayCache`): inserting into a
full cache first reclaims expired entries, then evicts the least
recently used one, so a stream of one-off `keyid`s cannot grow it
without bound. A hit refreshes recency but never extends the entry's
TTL.

```ts
import { memoizeKeyResolver } from "./dist/src/index.js";
const keyResolver = memoizeKeyResolver((keyId) => store.get(keyId), {
  ttlSec: 300,
  maxEntries: 10_000, // the default
});
// pass `keyResolver` to every verifyRequest call
```

Key rotation without `keyid` (Stripe-style webhook secret rollover): pass
`candidateKeys` — an ordered list of keys — and the verifier tries each in
turn, returning the first full pass. Only `SIGNATURE_MISMATCH` advances to
the next candidate; policy verdicts (`EXPIRED`, `NONCE_REPLAY`,
`MISSING_*`, ...) are about the signature itself, not the key, so they
return immediately instead of widening the walk. When every candidate
mismatches, the last candidate's `SIGNATURE_MISMATCH` is returned. Mutually
exclusive with `key` and `keyResolver` (an empty list or a non-KeyObject
entry throws a configuration error).

```ts
const result = verifyRequest(signed, {
  candidateKeys: [newSecret, oldSecret], // in-flight webhooks still use the old one
});
```

Multi-party rotation without `keyid` (merchant and gateway rolling their
webhook secrets on independent schedules): `verifyAllLabels` accepts a
per-label `candidateKeysByLabel` map. Each label's list is tried in
order with the same first-full-pass semantics as the global
`candidateKeys`; a label missing from the map falls back to the global
`candidateKeys`, and a per-label list is never tried against another
label — the merchant's candidates cannot widen the gateway's rotation
surface. Mutually exclusive with that label's `key`/`keys` and
`keyResolver`/`keyResolvers`.

```ts
const results = verifyAllLabels(dualSigned, {
  candidateKeysByLabel: {
    merchant: [merchantPublicKey], // fixed key
    gateway: [gatewayNewSecret, gatewayOldSecret], // mid-rollover
  },
});
```

Timing honesty: the *number* of candidates tried is observable through
verification latency — an observer can learn which secret (old vs new) a
request used. If that must stay hidden, wrap the call so it always runs all
candidates (or pad the latency) in your own layer. Failed attempts never
touch `replayCache` (it is consulted only after a full pass), so rotation
cannot pollute replay state.

JWK public-key distribution (webhook / gateway deployments, where PEM is
awkward to ship): export the ed25519 public key as a plain RFC 8037 object,
send it as JSON, and import it on the verifier side. Private JWKs (`"d"`
present) are refused — this helper is public-key distribution only, so
private keys stay in PEM on the signer side.

```ts
import { exportPublicKeyJwk, importPublicKeyJwk } from "./dist/src/index.js";
const jwk = exportPublicKeyJwk(publicKey); // { kty: "OKP", crv: "Ed25519", x: "..." }
const wireKey = JSON.parse(JSON.stringify(jwk)); // what the verifier receives
verifyRequest(signed, { key: importPublicKeyJwk(wireKey) }); // { ok: true, ... }
// Malformed JWKs (missing kty/crv/x, wrong curve, corrupt x) throw a clear
// "invalid JWK: ..." Error; never a verification failure.
```

P-256 gateways get the same treatment: `exportPublicKeyJwkP256` /
`importPublicKeyJwkP256` handle the RFC 7518 EC shape
(`{ kty: "EC", crv: "P-256", x, y }`) for `ecdsa-p256-sha256` verifiers,
with the same refusal of private (`"d"`) material. P-384 gateways
likewise: `exportPublicKeyJwkP384` / `importPublicKeyJwkP384` handle
`{ kty: "EC", crv: "P-384", x, y }` for `ecdsa-p384-sha384` verifiers —
the two curves' helpers are deliberately separate, so a P-256 JWK is
refused by the P-384 importer and vice versa. P-521 gateways
likewise: `exportPublicKeyJwkP521` / `importPublicKeyJwkP521` handle
`{ kty: "EC", crv: "P-521", x, y }` for `ecdsa-p521-sha512` verifiers —
the three curves' helpers are deliberately separate, so a JWK from one
curve is refused by the other curves' importers.

RSA gateways too: `exportPublicKeyJwkRsa` / `importPublicKeyJwkRsa` handle
the RFC 7518 RSA shape (`{ kty: "RSA", n, e }`) for RSA verifiers, with
the same refusal of private (`"d"`) material. One JWK serves both RSA
algorithms (`rsa-pss-sha512` and `rsa-v1_5-sha256`): the JWK carries no
`alg`, so the distinction lives only in each signature's `alg` parameter. One honest
caveat documented in code: node:crypto's RSA JWK importer is lenient, so a
structurally-valid but degenerate modulus (e.g. all-zero `n`) is accepted
at import time and fails only at the crypto layer when used — verification
still fails closed, never silently accepts.

Stable `keyid` derivation for those JWKs: `jwkThumbprint(jwk)` computes
the RFC 7638 thumbprint (required members only, lexicographic canonical
JSON, SHA-256, base64url) of any of the three public JWK shapes above, so
both sides of a distribution derive the same `kid` for the same key
instead of inventing local names. Extra members (`kid`, `alg`, `use`) do
not affect the result; JWKs carrying private material (`"d"`), missing a
required member, or with an unsupported `kty` throw. One honest limit: a
thumbprint is an identifier derived from public material — it is not a
proof of key possession and not a signature, and anyone who has the
public key can compute it.

Network key discovery (JWKS): when a signer's keys live behind a JWKS
endpoint — the gateway/webhook standard for public-key distribution and
rotation — `JwksKeyStore` fetches the document, imports every key by
`kid` (ed25519 / P-256 / P-384 / P-521 / RSA, the five JWK shapes above), and exposes a
synchronous `resolve` that drops straight into `keyResolver`:

```ts
import { JwksKeyStore } from "./dist/src/index.js";
const store = new JwksKeyStore("https://gateway.example.com/.well-known/jwks.json");
await store.refresh(); // the async fetch stays in your layer; verifyRequest stays synchronous
const result = verifyRequest(signed, { keyResolver: store.resolve }); // unknown kid -> KEY_RESOLUTION_FAILED
await store.refreshIfStale(); // rotation = re-fetch when stale; returns false (and fetches nothing) while fresh
```

`refreshIfStale()` is the one-call form of the `if (store.isStale()) await store.refresh()`
check: a fresh snapshot returns `false` without touching the network, a stale
one (or a store that has never refreshed) delegates to `refresh()` with all of
its atomic semantics and returns `true`. Refreshes are single-flight:
concurrent `refresh()` calls — and stale `refreshIfStale()` calls — share one
in-flight fetch and its single atomic snapshot replacement (on failure every
waiter receives the same error), so a burst of verifiers hitting a stale
window together cannot thundering-herd the endpoint. Only overlapping calls
merge: once a refresh settles, the next call fetches again, and a failure is
never cached.

Observability: `store.stats()` returns a detached `{ refreshes,
refreshFailures, hits, misses }` snapshot (mirroring `ReplayCache.stats()`).
Refresh counts are once per actual fetch — a single-flight refresh shared by
many waiters counts once, as a success or as a failure — and every `resolve()`
call counts as exactly one hit (returned a key) or miss (returned `undefined`:
an unknown keyid, any keyid before the first successful refresh, or an invalid
keyid), so `hits + misses` is the total number of resolutions. The counters
run for the store's lifetime and are not part of a snapshot: exporting or
restoring one does not reset them.

Fetch timeout (opt-in): `new JwksKeyStore(url, { fetchTimeoutMs: 10_000 })`
bounds each fetch of the default fetch implementation — a hung JWKS endpoint
would otherwise leave `refresh()` unsettled forever (and stall every waiter
merged by the single-flight mechanism). On expiry `refresh()` throws
`JwksKeyStore: JWKS fetch timed out after 10000ms`, the previous snapshot and
`lastRefreshedAt` are untouched (fail-closed, counted as a refresh failure).
The option takes a positive integer (milliseconds) and is unset by default, so
no configuration change is zero behavior change; it applies to the default
fetch only — a custom `fetchImpl` never receives an abort signal and must
implement its own timeout if it needs one.

A failed `refresh()` (HTTP error, non-JSON body, a malformed JWKS
document, or an entry carrying private `"d"` material) throws and leaves
the previous snapshot untouched, so a JWKS outage degrades to staleness
instead of becoming a verification outage; entries without a `kid` are
skipped. The fetch is injectable (`fetchImpl`) and the staleness clock
is injectable (`now`, `ttlSec` default 300s). Trusting the endpoint is
the caller's responsibility — whatever it serves becomes a verification
key, with no TLS pinning or response-signature check here (see
SECURITY.md).

Snapshot export/restore: a single process can carry its fetched keys
across its own restart — `store.exportSnapshot()` returns a detached,
JSON-serializable `{ v: 1, fetchedAtSec, keys }` of public-key JWKs
(each tagged with its `kid`), and `JwksKeyStore.restore(snapshot, url)`
(or `store.restoreSnapshot(snapshot)`) rebuilds a store that resolves
offline, with no fetch:

```ts
const persisted = JSON.parse(fs.readFileSync("jwks-snapshot.json", "utf8"));
const store = JwksKeyStore.restore(persisted, "https://gateway.example.com/.well-known/jwks.json");
const result = verifyRequest(signed, { keyResolver: store.resolve }); // works before any refresh()
```

Staleness counts from the snapshot's original `fetchedAtSec` —
restoring never renews freshness, so the caller's refresh loop should
still run. Restore is fail-closed, deliberately stricter than
`refresh()`: a malformed snapshot, an entry carrying private `"d"`
material, an unsupported `kty`, or a kid-less entry (skipped by
`refresh()`, fatal here — a snapshot is this store's own export format,
so a kid-less entry means corrupt data) throws and leaves any existing
snapshot untouched. Honest caveats: the snapshot is **not signed** —
treat the persisted form as trusted configuration, since whoever can
rewrite it can substitute their own verification keys — and it covers
one process across its own restart only; two processes restoring the
same snapshot diverge immediately afterwards. Exporting before any
successful `refresh()` throws rather than persisting a keyless
placeholder.

Receiving signed webhooks with Node's `http` server — the receive→verify
chain via `fromNodeRequest`:

```ts
import { createServer } from "node:http";
import { fromNodeRequest, verifyRequest } from "./dist/src/index.js";

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
configuration `Error` instead of silently defaulting. The adapter also
carries the message's trailers into `RequestLike.trailers` (from
`req.rawTrailers` when present, else `req.trailers`; names lowercased,
multi-values joined with `", "` — the header conventions), so covered
`;tr` components verify on a real server; note trailers only exist on
chunked messages and are complete only after the request's `end`
event, which is when the example above calls the adapter. A message
with no trailers produces no `trailers` field at all.

Verifying signed *responses* with a Node `http` client — the
receive→verify chain via `fromNodeResponse`:

```ts
import { get } from "node:http";
import { fromNodeResponse, verifyRequest } from "./dist/src/index.js";

// The request the client actually sent — the response signature can be
// bound to it (see ";req" below), so keep it around.
const request = { method: "GET", url, headers: { host } };

get(url, (res) => {
  const chunks: Buffer[] = [];
  res.on("data", (c) => chunks.push(c));
  res.on("end", () => {
    // A response has no method/url of its own: they describe the request
    // it answers, so they come from `opts.request` (attached as
    // RequestLike.request, enabling covered ";req" components such as
    // "@method";req) or from an explicit `opts.method` + `opts.url` pair.
    const result = verifyRequest(fromNodeResponse(res, Buffer.concat(chunks), { request }), {
      key: gatewayPublicKey,
      requiredComponents: ["@status"], // insist the signer bound the status
    });
    if (!result.ok) {
      throw new Error(`bad gateway signature: ${result.code}`);
    }
  });
});
```

What `fromNodeResponse` does: takes the response `statusCode` (a covered
`@status` binds it; a missing `statusCode` throws a configuration `Error`
instead of silently defaulting), lowercases header names and joins
multi-value headers with `", "` (the same convention as
`fromNodeRequest`), passes the buffered body through untouched, and
carries trailers into `RequestLike.trailers` (from `res.rawTrailers`
when present, else `res.trailers`). On a real client the trailers are
complete only after the response's `end` event — which is when the
example above calls the adapter.

## What it implements

- **Signature base** (§2.5): `"id": value` lines for each covered component,
  then the `"@signature-params"` line. Covered components: `@method`,
  `@scheme`, `@authority`, `@path`, `@query`, `@query-param`, `@status`, `@target-uri`, `@request-target`, `@created`,
  `@expires`, plus any HTTP header field (case-insensitive, multi-values joined).
  `@status` (response verification, e.g. webhook callbacks or signed API
  responses) binds the response status code: set `RequestLike.status` on
  both `signRequest` and `verifyRequest` — a covered `@status` with no status
  is a caller configuration error (fail-fast on the sign side,
  `SIGNATURE_BASE_BUILD_FAILED` on the verify side).
- **Request target (§2.2.5 `@request-target`)**: `"@request-target"` binds
  the request target in its origin form — the path plus, when present,
  `?` and the query, exactly as it appears in an HTTP/1.1 request line
  (no trailing `?` when there is no query). That is the component a
  legacy gateway that signed the request line needs: unlike
  `@target-uri` it contains no scheme or authority, and unlike `@path`
  it does not drop the query, so any path or query change breaks the
  signature while a scheme/authority change alone does not. The value
  is reconstructed from `RequestLike.url`, so the absolute-form,
  authority-form, and asterisk-form request targets cannot be
  represented and are not produced, and a URL fragment never
  participates. It combines with `;req` like the other derived
  components.
- **Single query parameters (§2.2.8 `@query-param`)**: `"@query-param";name="amount"`
  binds one named query parameter instead of the whole query string —
  the payment-callback shape where only `amount` must be tamper-proof
  while unrelated parameters may be added, removed, or reordered by
  intermediaries. The `;name` parameter is required and holds the
  parameter's name in percent-encoded form. The query is parsed as
  `application/x-www-form-urlencoded`; the bound value is the decoded
  value re-encoded with the RFC's percent-encode-after-encoding rules
  (UTF-8, only unreserved bytes left literal), so `%20` and `+`
  spellings of a space canonicalize identically on both sides. A
  parameter present with an empty value binds the empty string; a
  parameter that does not occur is an error on both sides (fail-fast
  when signing, `SIGNATURE_BASE_BUILD_FAILED` when verifying), and a
  name that occurs more than once must not be covered this way — the
  RFC directs that case to `@query`, and this library throws instead
  of picking a winner. `;name` combines with `;req` (canonical wire
  form `;req;name="…"`); combining it with `;bs`/`;sf`/`;key`/`;tr`
  is rejected.
- **Request binding for response signatures (§2.4 `;req`)**: any covered
  component may carry the `;req` component parameter — `"@method";req`,
  `"@authority";req`, `"content-digest";req`, … — which resolves that
  component against the *associated request* (`RequestLike.request`)
  instead of the response carrying the signature. That is what binds a
  signed response (e.g. a payment gateway's settlement callback) to the
  request that triggered it: transplanting the response onto a different
  request fails verification. Set `request` on both `signRequest` and
  `verifyRequest` (the signed object carries it through); using `;req`
  with no associated request fails fast on the sign side and with
  `SIGNATURE_BASE_BUILD_FAILED` on the verify side. A plain component and
  its `;req` twin may coexist in one signature (`"@method"` and
  `"@method";req` are distinct lines).
- **Byte-sequence header values (§2.1.2 `;bs`)**: a header field
  component may carry `;bs` — `"x-charge-ref";bs` — in which case the
  field value enters the signature base as its raw bytes serialized
  `:base64:`, with no whitespace trimming or normalization. That binds
  bytes a plain string component would erase: a value and the same
  value with its trailing space stripped verify identically without
  `;bs`, but are different signatures with it. `;bs` combines with
  `;req` (either order; canonical wire form `;req;bs`), is rejected on
  derived components (`"@method";bs` fails fast on the sign side and
  with `SIGNATURE_BASE_BUILD_FAILED` on the verify side), and other
  component parameters still fail closed. For a
  multi-value field, `;bs` joins the raw (untrimmed) elements with
  ", " before encoding.
- **Strict Structured Field serialization (§2.1.1 `;sf`)**: a header
  field component may carry `;sf` — `"x-quota";sf` — in which case the
  field value is parsed as an HTTP Structured Field (RFC 8941) and
  re-serialized with the strict rules of RFC 8941 §4 before entering
  the signature base: separator whitespace collapses to the canonical
  form and decimals gain their three-digit fraction, so a value and
  its re-spaced wire twin verify identically under `;sf` (without it
  they are different signatures). Honest scope: the RFC 8941 core
  types are supported (Dictionary, List, Item and Inner List;
  Integer, Decimal, String, Token, Byte Sequence, Boolean, and
  parameters); the RFC 9651 extensions (Date, Display String) are
  not, and a value that parses as no supported type fails closed on
  both sides. RFC 9421 expects the application to know the field's
  type; this library keeps no per-field type registry — the parser
  tries Dictionary, then List, then Item and takes the first type
  that consumes the whole value, which yields the RFC's strict bytes
  for every well-typed value (ambiguous shapes such as a lone token
  serialize identically under each candidate type). `;sf` combines
  with `;req` (canonical wire form `;req;sf`), is rejected on derived
  components like `;bs`, and is incompatible with `;bs` (raw bytes
  vs. parsed value — the pair fails closed). The strict serializer
  is also exported as `canonicalizeStructuredFieldValue`.
- **Dictionary member selection (§2.1.1 `;key`)**: a header field
  component may carry `;key="<name>"` — `"x-dict";key="b"` — in which
  case the field value is parsed as a Dictionary Structured Field and
  only the named member enters the signature base, serialized
  strictly as an Item or Inner List *without* the key itself
  (RFC 8941 §4.1.2; a bare key serializes as `?1`). The other members
  are deliberately not bound: editing an unselected member leaves
  the signature valid, while editing, re-parameterizing, or deleting
  the selected member fails verification — the fine-grained binding
  gateways use for structured fields such as `content-digest`
  (`"content-digest";key="sha-512"`). A member that does not exist
  fails fast on the sign side and with
  `SIGNATURE_BASE_BUILD_FAILED` on the verify side — never an
  empty-string component value. The parameter value must be a quoted
  string naming a valid Dictionary key (missing, unquoted, or
  non-key values fail closed). `;key` combines with `;req`
  (canonical wire form `;req;key="…"`), is rejected on derived
  components, and is incompatible with both `;bs` and `;sf` (raw
  bytes / whole-field serialization vs. one strictly serialized
  member — the pairs fail closed). The member extractor is also
  exported as `serializeDictionaryMemberValue`.
- **Trailer fields (§2.1.4 `;tr`)**: a header field component may
  carry `;tr` — `"x-checksum";tr` — in which case the field value is
  taken from the message's trailers (`RequestLike.trailers`, same
  shape as `headers`) instead of its headers, with the same
  multi-value join and normalization. Without `;tr`, trailers never
  participate: a header and a trailer sharing a field name are
  independent, and a plain component and its `;tr` twin may coexist
  in one signature. Set `trailers` on both `signRequest` and
  `verifyRequest` (the signed object carries it through). A covered
  `;tr` field with no matching trailer fails fast on the sign side
  and with `SIGNATURE_BASE_BUILD_FAILED` on the verify side — never
  an empty-string component value. `;tr` is orthogonal to the value
  transforms: it combines with `;req` (the trailer is then read from
  the associated request; canonical wire form `;req;tr`), with
  `;bs`, with `;sf`, and with `;key` (each still subject to its own
  incompatibilities — `;bs` with `;sf`/`;key` still fails closed),
  and is rejected on derived components like the other field-only
  parameters.
- **Sign-side input guards**: `signRequest` fails fast with a descriptive
  configuration error instead of minting a broken signature — `expires`
  earlier than `created` (a signature that is expired at birth), an empty
  `coveredComponents` list (would sign nothing), and non-integer
  `created`/`expires` (the verifier's `signature-input` parser only
  recognizes integer seconds, so a fractional value would silently diverge
  between signer and verifier), and a non-token `label` (commas/spaces
  would corrupt the `signature-input` dictionary; the label is the member
  key `verifyAllLabels` splits on). `expires === created` is allowed.
- **Optional `keyid`**: RFC 9421 leaves `keyid` optional — `signRequest`'s
  `keyId` is too, and omitting it emits no `keyid` parameter on the wire.
  The verifier reports `keyId: undefined`, and pinning/resolution flows
  treat it as a missing claim (e.g. `keyResolver` → `KEY_RESOLUTION_FAILED`,
  `expectedKeyId` → `KEYID_MISMATCH`).
- **Algorithms**: `ed25519`, `ecdsa-p256-sha256` (NIST P-256; ECDSA
  signature values are the raw concatenation of the two integers r and
  s, each padded to 32 octets — 64 octets total — exactly as RFC 9421
  §3.3.4 defines; see [Interoperability](#interoperability)),
  `ecdsa-p384-sha384` (NIST P-384; the same raw r‖s form with each
  integer padded to 48 octets — 96 octets total — per RFC 9421 §3.3.5),
  `ecdsa-p521-sha512` (NIST P-521; the same raw r‖s form with each
  integer padded to 66 octets — 132 octets total — per RFC 9421 §3.3.6),
  `rsa-pss-sha512` (RSASSA-PSS with
  SHA-512, MGF1 with SHA-512, 64-byte salt per RFC 9421 §3.3.1),
  `rsa-v1_5-sha256` (RSASSA-PKCS1-v1_5 with SHA-256 per RFC 9421 §3.3.2 —
  deterministic signatures, same RSA key material as PSS, ≥ 2048-bit
  modulus enforced on both sides; included for legacy gateway/webhook
  interoperability, PSS or ed25519 preferred for new deployments),
  `hmac-sha256` (≥ 32-byte secrets) and `hmac-sha512` (≥ 64-byte secrets;
  constant-time compare; floors paired with the algorithm per RFC 2104
  §3).
- **Body binding**: `Content-Digest: sha-512=:…:` is computed when the body
  is covered, and the verifier recomputes it — a swapped body fails even if
  the signature itself is valid. The verifier prefers `sha-512` but falls
  back to `sha-256` when the header carries no `sha-512` entry (for foreign
  signers that only send `sha-256`); signing emits `sha-512` by default and
  `sha-256` when `SignOptions.contentDigestAlg` is set to `"sha-256"` (for
  peers that only accept sha-256 digests).
- **Freshness**: `created` enforced with a configurable clock-skew
  tolerance (`clockSkewToleranceSec`, default 60s); `expires` enforced
  strictly by default, with an optional grace period
  (`expiredToleranceSec`, default 0s). A verifier can also demand the
  timestamps exist at all: `requireCreated` / `requireExpires` reject
  signatures that omit them (`MISSING_CREATED` / `MISSING_EXPIRES`) —
  for signers you control, `signRequest` always sends `created`. And an
  opt-in maximum age (`maxSignatureAgeSec`, unset by default) rejects a
  signature whose `created` is older than the window with
  `SIGNATURE_TOO_OLD` — the webhook-timestamp-window analog (cf.
  Stripe's few-minutes tolerance), bounding replayability of long-lived
  signed messages without a nonce replay cache. The age check fires
  only when `created` is present (orthogonal to `requireCreated`).
- **Required components**: `verifyRequest` can demand the signature
  cover specific components (`VerifyOptions.requiredComponents`) — a
  signature covering only `"@method"` is cryptographically valid but
  protects nothing, so a payment-gateway verifier typically requires
  `content-digest` (body cannot be swapped) and/or `@path` (request
  target cannot be changed). The check is opt-in, case-insensitive,
  and fails fast *before* any crypto work with
  `MISSING_REQUIRED_COMPONENT`; it composes with `verifyAllLabels`
  (checked per label).
- **Nonce (RFC 9421 §2.3)**: pass `nonce` to `signRequest` and it is
  emitted as a `nonce` signature-input parameter — part of the signed
  `@signature-params` line, so a forged nonce fails with
  `SIGNATURE_MISMATCH`. Generate the value with `generateNonce()`
  (CSPRNG-backed base64url, default 128 bits): a hand-rolled
  `Math.random()` nonce is predictable and makes the replay-cache
  defense below meaningless. `verifyRequest` returns it as `result.nonce`
  (the wire-seen value, reported before authenticity is established).
  For replay detection, pass a `ReplayCache` via
  `verifyRequest(req, { key, replayCache })`: a nonce already seen within
  the cache TTL fails with `NONCE_REPLAY` (fresh nonces are recorded only
  *after* the signature fully verifies, so forgeries can't pollute the
  cache). The cache is only consulted when a signature actually carries
  a nonce, so a nonce-less signature bypasses it silently — set
  `requireNonce: true` alongside it when such signatures must be
  rejected instead: they then fail with `MISSING_NONCE` (an empty-string
  nonce counts as missing), checked after the cryptographic check and
  before the cache query. The cache itself is shared across
  `verifyAllLabels` labels, while `requireNonce` is judged per label. The
  store is keyed by the bare nonce string with no per-label partitioning,
  so callers have a hard contract: **one nonce per label** — if two labels
  on the same request carry the *same* nonce (e.g. a gateway reusing the
  merchant's nonce while appending its own signature), the first label
  records it and every later label is rejected with `NONCE_REPLAY`, even
  though both signatures are cryptographically valid. This is the
  intentional fail-closed semantic (pinned by
  `test/replay.test.ts`), not a bug: changing the store key format would
  silently break every existing custom `NonceStore` implementation.
  Generate a fresh `generateNonce()` value for each label you sign.
  Multi-verifier deployments still need a shared nonce store (see the
  Limitations and SECURITY.md). Call `cache.stats()` for observability:
  it returns a `{ size, hits, misses, evictions }` snapshot (expired-entry
  reclamation and LRU eviction both count as evictions); `cache.clear()`
  also resets the counters. A single process can carry the cache across
  its own restart: `cache.exportSnapshot()` returns a detached,
  JSON-serializable `{ v: 1, entries }` snapshot of the live nonces with
  their original first-seen timestamps, and
  `ReplayCache.restore(snapshot, opts)` reloads it after strictly
  validating the shape (a corrupt snapshot throws a configuration error
  at startup instead of silently disabling replay protection). Expired
  entries are dropped at load, an over-capacity snapshot keeps the
  newest entries, TTLs keep counting from first sight rather than from
  the restore, and the observability counters restart at zero.
- **Application tag (RFC 9421 §2.3)**: pass `tag` to `signRequest` and it
  is emitted as a `tag` signature-input parameter — part of the signed
  `@signature-params` line, so a forged tag fails with
  `SIGNATURE_MISMATCH`. The tag binds the signature to one application
  protocol (e.g. `"payment-webhook-v1"`), which is the cross-protocol
  replay defense: protocols that share a key (a payment webhook and an
  admin API signed with the same gateway key, say) cannot replay each
  other's signatures when the verifier pins its protocol with
  `verifyRequest(req, { key, expectedTag: "payment-webhook-v1" })` —
  a different tag, or no tag at all, then fails with `TAG_MISMATCH`,
  checked after the cryptographic check so forgeries still report
  `SIGNATURE_MISMATCH`. `verifyRequest` returns the wire tag as
  `result.tag`; in `verifyAllLabels` the same expectation is judged
  per label, and each label can pin its own protocol via the optional
  `expectedTags` map (label→tag) — a label missing from it falls back
  to the global `expectedTag` (unset means no check for it). An
  empty-string tag is rejected by `signRequest` as a
  configuration error (it would bind nothing).
- Minimal `Signature-Input` / `Signature` field parsing for verification.
- **Node http server adapter**: `fromNodeRequest(req, body, opts?)`
  normalizes an `http.IncomingMessage` into a `RequestLike` (absolute URL
  rebuilt from the `host` header, lowercased header names, multi-value
  headers joined with `", "`), so `verifyRequest` plugs straight into a
  webhook receiver — see the Quickstart receive→verify example.
- **Node http client adapter**: `fromNodeResponse(res, body, opts?)`
  normalizes a client's received `http.IncomingMessage` into a
  `RequestLike` (response `statusCode` bound via `@status`, same header
  and trailer conventions), so `verifyRequest` plugs straight into
  verifying gateway-signed responses — pass `opts.request` (the request
  you sent) to enable covered `;req` request-binding components. See
  the Quickstart response receive→verify example.
- **Multi-signature verification**: `verifyAllLabels(req, { key, keys })`
  parses every label from the `Signature-Input` header and verifies each
  one with `verifyRequest`, returning one `VerifyResult` per label in wire
  order. A failing label never blocks the remaining labels — built for
  multi-party flows (e.g. a merchant signature plus a payment-gateway
  signature on the same request). Pass per-label keys via the optional
  `keys` map; labels missing from it fall back to `key`. When each party
  signs with a different key id, pin them per label via the optional
  `expectedKeyIds` map (label→keyid); labels missing from it fall back to
  the global `expectedKeyId`. When each party signs for a different
  application protocol, pin the tags per label via the optional
  `expectedTags` map (label→tag); labels missing from it fall back to
  the global `expectedTag`. For resolver-based verification, pass
  per-label resolvers via the optional `keyResolvers` map
  (label→`(keyId) => KeyObject | undefined`) — handy when the parties'
  key ids live in separate keystores (merchant store vs gateway store);
  labels missing from it fall back to the global `keyResolver`.
  When each party rotates its own HMAC secret independently (merchant
  fixed ed25519 key, gateway mid-rollover with old and new secrets), pass
  per-label rotation lists via the optional `candidateKeysByLabel` map
  (label→`KeyObject[]`) — each label's list is tried in order with
  first-full-pass semantics, exactly like the global `candidateKeys`,
  and labels missing from it fall back to the global `candidateKeys`.
  A per-label list is never tried against another label, so a stale
  merchant candidate cannot widen the gateway's rotation surface.
  `keys`/`key` cannot be combined with either resolver or with any
  candidate list (configuration error). Duplicate labels are verified once (first occurrence); a
  request with no `Signature-Input` header yields an empty array.
  A repeated signature-input parameter (e.g. two `created=` values, case
  variants included) is ambiguous authenticated input and is rejected as
  `MALFORMED_SIGNATURE_INPUT` before any crypto runs — the parser never
  silently lets the later value win.

```ts
import { verifyAllLabels } from "./dist/src/index.js";

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
  A signed response's `status` is preserved on the returned object and
  passed through to the appended signature, so multi-party signing also
  works when `@status` is covered (merchant signs a response, gateway
  appends its own label over the same status).

```ts
import { addSignature, signRequest } from "./dist/src/index.js";

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

## FAQ (honest)

- **Can I use this in production?**
  No — not as-is. This is a demo / learning implementation of a subset
  of RFC 9421, not a hardened, audited security library: no security
  audit has been performed, cross-implementation compatibility is
  untested (see the next answers), replay protection is opt-in only,
  and there is no key lifecycle story beyond JWKS fetching. If you
  need production message signatures, use a maintained, audited
  implementation of the full RFC 9421 instead — see "Why not use this
  directly in production" in [SECURITY.md](SECURITY.md).

- **How much of RFC 9421 does this implement? What is missing?**
  A self-consistent subset. Eight signature algorithms are implemented
  (`ed25519`, `ecdsa-p256-sha256`, `ecdsa-p384-sha384`,
  `ecdsa-p521-sha512`, `rsa-pss-sha512`,
  `rsa-v1_5-sha256`, `hmac-sha256`, `hmac-sha512`), plus the
  `;req`/`;bs`/`;sf`/`;key`/`;tr` component parameters for header
  fields and `;name` for `@query-param`. Not implemented: component
  parameters besides those, and generic keystores over HTTP (JWKS
  fetching via `JwksKeyStore` *is* implemented — see below).
  Narrower limits also apply inside what is implemented — `;sf`
  covers the RFC 8941 core types only, `;tr` reads caller-supplied
  `RequestLike.trailers` rather than parsing raw trailer sections
  off the wire, and `@request-target` is reconstructed in origin
  form only. The full list is in [Limitations](#limitations-honest).

- **Has this been tested against other RFC 9421 implementations?**
  No. No third-party RFC 9421 implementation has been exercised
  against this library yet, so cross-implementation compatibility
  is still untested — do not assume wire compatibility without
  testing it yourself. What *has* been checked are the RFC's own
  published example vectors: the Appendix B.2.1, B.2.2, B.2.3, B.2.4,
  B.2.5 and B.2.6 vectors verify end-to-end through `verifyRequest` with
  signature bases matching byte-for-byte, and the `Content-Digest`
  values were cross-checked against `openssl` output. That is a
  narrower claim than third-party interop; see
  [Interoperability](#interoperability) for exactly what was verified.

- **Which `Content-Digest` algorithms are accepted, and in what order?**
  The verifier understands `sha-512` and `sha-256`, in that order:
  when the header carries both, only the `sha-512` entry is honored;
  a `sha-256` entry is accepted as a fallback only when no `sha-512`
  entry is present. Any other digest algorithm is rejected with
  `MISSING_CONTENT_DIGEST`. Signing mirrors this: it emits `sha-512`
  by default, or `sha-256` when `SignOptions.contentDigestAlg` is
  set to `"sha-256"` (for a peer that only accepts sha-256 digests).
  Note the scope limit: body binding only applies when a
  `content-digest` header is present at all — a request without one
  verifies against headers alone.

- **Does verifying a signature ever make network requests?**
  `signRequest` / `verifyRequest` themselves do no network I/O — key
  resolution is a synchronous, in-process lookup. The one network
  path is opt-in: if you use `JwksKeyStore`, its `refresh()` fetches
  the JWKS document from the URL you configured (via the global
  `fetch`), and `resolve()` then answers from that fetched snapshot.
  Nothing calls `refresh()` for you. Trusting that endpoint is your
  responsibility: the store performs no TLS pinning and no
  response-signature verification, so point it only at trusted
  origins, over HTTPS (see [SECURITY.md](SECURITY.md)). The test
  suite and benchmark stay offline — JWKS tests use a loopback-only
  server and the benchmark resolves against a restored snapshot.

- **Does a valid signature stop replay attacks?**
  Not by itself. `created` / `expires` only bound the acceptance
  window — a signature captured inside its window can be replayed
  unless you opt into nonce checking: pass a `ReplayCache` via
  `VerifyOptions.replayCache` to reject an already-seen `nonce`
  with `NONCE_REPLAY`, and `requireNonce` to reject nonce-less
  signatures with `MISSING_NONCE` instead of letting them bypass
  the cache. The built-in cache is per-process and in-memory only
  (TTL + LRU cap; a snapshot survives its *own* process's restart
  but is never shared), so a multi-verifier deployment still needs
  a shared nonce store (e.g. Redis) — see
  [Limitations](#limitations-honest) and [SECURITY.md](SECURITY.md).

- **Who manages keys and rotation?**
  You do. Keys are passed in directly, resolved per call via a
  caller-provided `keyResolver`, or fetched from a JWKS endpoint
  via `JwksKeyStore`. There is no built-in persistent keystore and
  no automatic rotation schedule: a `JwksKeyStore` snapshot can be
  exported and restored across a single process's restart, but the
  library never writes it anywhere itself, its persisted form is
  unsigned (treat it as trusted configuration only), and deciding
  *when* to re-fetch is your loop — `refreshIfStale()` performs the
  staleness check and the re-fetch in one call, but nothing calls
  it for you. Until a successful `refresh()` replaces the snapshot,
  a revoked key keeps verifying; a failed refresh never replaces
  the last good snapshot.

## Limitations (honest)

- **Subset of RFC 9421.** Not implemented: component
  parameters besides `;req`/`;bs`/`;sf`/`;key`/`;tr`/`;name`, and generic
  keystores over HTTP. The `bs`, `sf`, `key`, and `tr` component parameters
  *are* implemented for header fields, and `;name` *is* implemented for
  the `@query-param` derived component (see "What it implements"; `;sf`
  covers the RFC 8941 core types only, with no per-field type
  registry, and `;key` selects Dictionary members of those same core
  types; `;tr` reads the field value from caller-supplied
  `RequestLike.trailers` — this library does not parse raw HTTP
  trailer sections off the wire). `@request-target` *is* implemented
  (§2.2.5), reconstructed from the absolute `RequestLike.url` in
  origin form only (path + query): the absolute-form, authority-form,
  and asterisk-form request targets cannot be expressed through that
  URL and are not produced. Network key
  discovery *is* implemented for JWKS endpoints: `JwksKeyStore` fetches a
  JWKS document and resolves `keyid`s against the fetched snapshot.
  Response-to-request binding *is* implemented, via the §2.4 `;req`
  component parameter (there is no `@request-response` derived component
  in RFC 9421 — earlier versions of this README listed it in error). `keyid`→key
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
  exists); signing emits `sha-512` by default, `sha-256` with
  `contentDigestAlg: "sha-256"`. Other `content-digest` algorithms
  are rejected with `MISSING_CONTENT_DIGEST`.
- **In-memory replay cache only.** The optional `ReplayCache` is a
  per-process helper with a configurable TTL and LRU capacity cap. It
  can survive its *own* process's restart — export a snapshot before
  shutdown and restore it at startup — but it is not shared between
  verifier instances, and two processes restoring the same snapshot
  diverge immediately afterwards. If you run multiple verifiers,
  deduplicate nonces in a shared store
  (e.g. Redis) instead of (or in addition to) this cache.
- **Demo-grade key management.** Keys are passed in directly, resolved via a
  caller-provided `keyResolver`, or fetched from a JWKS endpoint via
  `JwksKeyStore`; there is still no built-in persistent keystore and no
  automatic rotation schedule — a `JwksKeyStore` snapshot can be exported
  and restored across a single process's restart, but the library never
  writes it anywhere itself, its persisted form is unsigned (trusted
  configuration only), and deciding *when* to re-fetch remains the
  caller's loop (`refreshIfStale()` performs the `isStale()` check and
  the re-fetch in one call, but nothing calls it for you). Trusting
  the JWKS endpoint is the caller's responsibility (see SECURITY.md).

## Interoperability

Honest status: **no third-party RFC 9421 implementation has been
exercised against this library yet**, so cross-implementation
compatibility is still untested. What has been checked are the RFC's
own published example vectors (below) — a narrower claim than
third-party interop. Interop reports and issues are welcome.

What *has* been verified beyond the sign→verify round-trip tests:

- The signature-base construction follows RFC 9421 §2.5. The golden vector
  in `test/golden.test.ts` is asserted against a hand-written expectation
  derived from the spec's format rules — that checks internal consistency
  with the spec as implemented here, not independent agreement.
- The `Content-Digest: sha-512` value is plain SHA-512; the golden vector
  was cross-checked against `openssl dgst -sha512` output for the same
  input.
- The `Content-Digest: sha-256` value is plain SHA-256, independently
  cross-checked the same way: `test/contentDigestSha256Openssl.test.ts`
  pins openssl-derived expectations (OpenSSL 3.0.13, run locally) for
  empty, ASCII, multi-byte UTF-8, and binary bodies, plus the sample
  value RFC 9530 Appendix D publishes for `{"hello": "world"}`. That
  file also re-runs `openssl dgst -sha256` live when an `openssl`
  binary is available; when none is, the live re-check is explicitly
  skipped (never silently passed) and only the hardcoded
  openssl-derived vectors run — the live cross-check itself was done
  locally.
- RFC 9421 Appendix B.2.5 (hmac-sha256 — the only Appendix B vector
  whose signature-input omits `alg`, so it verifies end-to-end through
  `verifyRequest` with the `algFallback: "infer"` opt-in; without the
  opt-in the historical ed25519 default fails as `VERIFICATION_ERROR`),
  B.2.6 (ed25519), B.2.4
  (ecdsa-p256-sha256), B.2.3 (rsa-pss-sha512, full coverage),
  B.2.2 (rsa-pss-sha512, selective coverage — `@authority`,
  `content-digest`, and a single named query parameter via
  `@query-param;name="Pet"`, with a `tag` parameter; the test pins
  the selective boundary: changing a covered component fails, while
  changing uncovered components — method, date, content-type, an
  unrelated query parameter — still verifies), and
  B.2.1 (rsa-pss-sha512, minimal coverage — empty covered-components
  list, authenticated by its created/keyid/nonce parameters alone) vectors in
  `test/rfc9421AppendixB.test.ts`: the
  signature base matches the published bytes exactly and the published
  signature value verifies end-to-end through `verifyRequest`. For
  B.2.4 that includes the encoding RFC 9421 §3.3.4 defines — the raw
  concatenation of the two ECDSA integers, 64 octets — which the
  library's sign side now also emits (earlier versions emitted and
  expected DER instead; DER signatures from those versions are
  rejected, with no compatibility fallback).

Known interop hazards (things a foreign implementation may do differently;
most also appear in [Limitations](#limitations)):

- **Key delivery is mostly out of band.** `keyid` is carried and can be resolved
  opt-in via `VerifyOptions.keyResolver` (a caller-provided in-process
  lookup; unknown `keyid` fails with `KEY_RESOLUTION_FAILED`), and
  `JwksKeyStore` adds opt-in JWKS fetching over HTTP for signers that
  publish a JWKS endpoint. There is still no generic keystore protocol
  support, and both sides must agree on `keyid` values.
- **Authority normalization.** `@authority` is normalized with WHATWG `URL`
  semantics (lowercased, default ports elided). A peer that normalizes
  differently will build a different signature base.
- **Covered component selection.** Signer and verifier must agree on the
  exact covered components, in the exact order. Defaults here are
  `@method @authority @path`, plus `content-digest` when a body exists.
- **Digest algorithm.** Body binding understands `sha-512` (preferred) and
  `sha-256` (fallback when no `sha-512` entry is present). Signing defaults
  to `sha-512`; set `SignOptions.contentDigestAlg: "sha-256"` for a peer
  that only accepts sha-256 digests. A peer sending
  only other digest algorithms fails with "no sha-512 or sha-256
  content-digest present".
- **Signature algorithms.** Implemented: `ed25519`, `ecdsa-p256-sha256`
  (raw r‖s encoding per RFC 9421 §3.3.4, so the official B.2.4 vector
  verifies end-to-end; see the verified list above — note the breaking
  change from earlier versions of this library, which used DER: their
  ECDSA signatures no longer verify here), `ecdsa-p384-sha384`
  (raw r‖s encoding per RFC 9421 §3.3.5, each integer padded to
  48 octets; the P-256 and P-384 widths are pinned separately, so a
  signature from one curve never verifies as the other),
  `ecdsa-p521-sha512` (raw r‖s encoding per RFC 9421 §3.3.6, each integer
  padded to 66 octets; its width is pinned separately from the P-256 and
  P-384 widths for the same reason),
  `rsa-pss-sha512` (RSASSA-PSS with
  SHA-512, MGF1 with SHA-512, and a 64-byte salt per RFC 9421 §3.3.1 —
  signatures are probabilistic, so verifiers re-verify rather than
  re-sign-and-compare), `rsa-v1_5-sha256` (RSASSA-PKCS1-v1_5 with
  SHA-256 per RFC 9421 §3.3.2 — deterministic; the verifier dispatches
  on the declared `alg`, never on the key's shape, so a PSS signature
  never verifies as v1.5 or vice versa), `hmac-sha256`, `hmac-sha512`
  (constant-time compare; ≥ 64-byte secrets per RFC 2104 §3). Anything
  else is not supported.
- **Missing `alg` parameter.** `alg` is optional per RFC 9421 §2.3
  (Appendix B.2.5's hmac-sha256 vector omits it), but this library
  historically defaults a missing `alg` to `"ed25519"`, so a foreign
  signature without `alg` could not be verified end-to-end. Opt-in
  fallback: `VerifyOptions.algFallback: "infer"` infers the algorithm
  from the resolved key's shape (`secret` → `hmac-sha256`, ed25519 key
  → `ed25519`, P-256 EC key → `ecdsa-p256-sha256`, P-384 EC key →
  `ecdsa-p384-sha384`, P-521 EC key → `ecdsa-p521-sha512`, RSA key →
  `rsa-pss-sha512` — never `rsa-v1_5-sha256`, since key shape cannot
  distinguish the two RSA paddings) and throws a caller
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
- **Components.** Binding a response signature to the request that caused
  it is supported via the `;req` component parameter (§2.4) — there is no
  `@request-response` derived component in RFC 9421 (earlier versions of
  this README named one in error). Trailer fields *are* supported via
  the `;tr` component parameter (§2.1.4), reading caller-supplied
  `RequestLike.trailers`. Not supported: component
  parameters besides `;req`/`;bs`/`;sf`/`;key`/`;tr`, and other derived components beyond
  the list under "What it implements".
- **Multiple signatures.** `verifyRequest` checks one label per call; for
  multi-party flows, `verifyAllLabels` verifies every label in the request
  (one `VerifyResult` per label, and a failing label never blocks the
  remaining labels). Per-label key material is still caller-supplied via
  the optional `keys` map or the optional `keyResolvers`/`keyResolver`
  keyid→key lookup — a peer that expects automatic per-label key
  discovery will need keys wired up manually.
- **Freshness is not automatic replay protection.** `created`/`expires`
  only bound the acceptance window. RFC 9421 `nonce` is supported
  (`signRequest` accepts a `nonce` option; `verifyRequest` echoes it back
  as `result.nonce`), and an opt-in per-process in-memory `ReplayCache`
  (LRU + TTL) rejects a replayed nonce with `NONCE_REPLAY`; the opt-in
  `requireNonce` rejects nonce-less signatures with `MISSING_NONCE`
  instead of letting them bypass the cache. There is no
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
algorithm plus the key-resolution, JWKS snapshot-export, JWKS snapshot-restore, resolver-based verification, maximum-signature-age verification, expiry-presence verification, created-presence verification, clock-skew verification, expiry-grace verification, key-id binding verification, per-label key-id binding verification, per-label key-resolution verification, algorithm-inference verification, application-tag-pinning verification, component-coverage verification, replay-cache verification, nonce-presence verification, JWKS refresh, JWKS concurrent single-flight refresh, thumbprint-derivation, replay-check, replay snapshot-export, replay stats, replay snapshot-restore,
malformed-input rejection, standalone content-digest,
inbound-normalization, per-curve JWK round-trip, ed25519 JWK round-trip, PEM round-trip,
signature-base-building, end-to-end signing, standalone signature-parser,
structured-field canonicalization, dictionary-member extraction, signature-parameter serialization, nonce generation, throwing-verify-wrapper, header-lookup, header-value combination, digest-algorithm identification, HMAC secret-length guard, RSA modulus-length guard, signature-input value building, content-digest algorithm guard and component-resolution paths below
(3000 timed iterations per op after 200 warmup, printing the Node
version and CPU).
All rows below are from one real run on 2026-10-23:

| alg | op | throughput |
|-----|--------|------------|
| ed25519 | sign | ~8,427 ops/sec (118.66 µs/op) |
| ed25519 | verify | ~3,942 ops/sec (253.68 µs/op) |
| hmac-sha256 | sign | ~35,445 ops/sec (28.21 µs/op) |
| hmac-sha256 | verify | ~24,812 ops/sec (40.30 µs/op) |
| hmac-sha512 | sign | ~34,144 ops/sec (29.29 µs/op) |
| hmac-sha512 | verify | ~26,705 ops/sec (37.45 µs/op) |
| ecdsa-p256-sha256 | sign | ~12,751 ops/sec (78.42 µs/op) |
| ecdsa-p256-sha256 | verify | ~5,466 ops/sec (182.95 µs/op) |
| ecdsa-p384-sha384 | sign | ~453.3 ops/sec (2206.07 µs/op) |
| ecdsa-p384-sha384 | verify | ~653.8 ops/sec (1529.56 µs/op) |
| ecdsa-p521-sha512 | sign | ~194.0 ops/sec (5153.63 µs/op) |
| ecdsa-p521-sha512 | verify | ~254.3 ops/sec (3932.23 µs/op) |
| rsa-pss-sha512 | sign | ~1,007 ops/sec (993.40 µs/op) |
| rsa-pss-sha512 | verify | ~5,042 ops/sec (198.35 µs/op) |
| rsa-v1_5-sha256 | sign | ~1,018 ops/sec (982.18 µs/op) |
| rsa-v1_5-sha256 | verify | ~9,561 ops/sec (104.59 µs/op) |
| verifyAllLabels (2 labels) | verify | ~3,367 ops/sec (297.04 µs/op) |
| JwksKeyStore.resolve (hit) | resolve | ~4,020,483 ops/sec (0.25 µs/op) |
| memoizeKeyResolver (hit) | resolve | ~3,852,832 ops/sec (0.26 µs/op) |
| memoizeKeyResolver (miss) | resolve | ~4,349,251 ops/sec (0.23 µs/op) |
| JwksKeyStore.exportSnapshot (3 keys) | export | ~20,099 ops/sec (49.75 µs/op) |
| JwksKeyStore.restoreSnapshot (3 keys) | restore | ~16,399 ops/sec (60.98 µs/op) |
| verifyRequest keyResolver (2 keyids) | verify | ~1,506 ops/sec (664.06 µs/op) |
| verifyRequest requireExpires | verify | ~3,214 ops/sec (311.10 µs/op) |
| verifyRequest requireCreated | verify | ~4,973 ops/sec (201.09 µs/op) |
| verifyRequest expectedTag | verify | ~3,396 ops/sec (294.46 µs/op) |
| verifyRequest replayCache | verify | ~2,318 ops/sec (431.42 µs/op) |
| verifyRequest requireNonce | verify | ~4,355 ops/sec (229.62 µs/op) |
| verifyRequest expectedKeyId | verify | ~4,884 ops/sec (204.75 µs/op) |
| verifyRequest algFallback (infer) | verify | ~38,945 ops/sec (25.68 µs/op) |
| verifyRequest requiredComponents | verify | ~4,321 ops/sec (231.40 µs/op) |
| JwksKeyStore.refreshIfStale (stale) | refresh | ~54,058 ops/sec (18.50 µs/op) |
| jwkThumbprint (3 JWK shapes) | derive | ~43,218 ops/sec (23.14 µs/op) |
| ReplayCache.check (hit, 1k) | check | ~1,325,325 ops/sec (0.75 µs/op) |
| ReplayCache.exportSnapshot (3 live) | export | ~1,244,051 ops/sec (0.80 µs/op) |
| ReplayCache.stats (5 live) | stats | ~1,239,644 ops/sec (0.81 µs/op) |
| ReplayCache.fromSnapshot (4 live) | restore | ~191,041 ops/sec (5.23 µs/op) |
| verifyRequest (malformed, 566 cases) | reject | ~10,432 ops/sec (95.86 µs/op) |
| contentDigest sha-512 (31-byte body) | digest | ~286,772 ops/sec (3.49 µs/op) |
| contentDigest sha-256 (31-byte body) | digest | ~400,826 ops/sec (2.49 µs/op) |
| fromNodeRequest (inbound, trailers) | normalize | ~55,746 ops/sec (17.94 µs/op) |
| JWK round-trip P-256 | roundtrip | ~13,776 ops/sec (72.59 µs/op) |
| JWK round-trip P-384 | roundtrip | ~11,706 ops/sec (85.42 µs/op) |
| JWK round-trip P-521 | roundtrip | ~12,901 ops/sec (77.51 µs/op) |
| JWK round-trip RSA-2048 | roundtrip | ~5,459 ops/sec (183.17 µs/op) |
| JWK round-trip ed25519 | roundtrip | ~97,423 ops/sec (10.26 µs/op) |
| PEM round-trip ed25519 | roundtrip | ~3,080 ops/sec (324.65 µs/op) |
| buildSignatureBase (4 components) | build | ~43,538 ops/sec (22.97 µs/op) |
| signRequest (ed25519, end-to-end) | sign | ~6,294 ops/sec (158.87 µs/op) |
| listSignatureLabels (2 labels) | parse | ~188,808 ops/sec (5.30 µs/op) |
| parseSignatureInput (merchant) | parse | ~135,513 ops/sec (7.38 µs/op) |
| parseSignatureField (merchant) | parse | ~248,547 ops/sec (4.02 µs/op) |
| serializeSignatureParams (5 cases) | serialize | ~15,487 ops/sec (64.57 µs/op) |
| generateNonce (16 + 32 bytes) | generate | ~18,754 ops/sec (53.32 µs/op) |
| verifyRequestOrThrow (valid) | verify | ~2,301 ops/sec (434.54 µs/op) |
| verifyRequestOrThrow (tampered) | throw | ~2,840 ops/sec (352.15 µs/op) |
| getHeader/getHeaderRaw (9 names ×2) | lookup | ~92,826 ops/sec (10.77 µs/op) |
| joinHeaderValues (9 cases) | join | ~252,625 ops/sec (3.96 µs/op) |
| contentDigestAlgOf (10 cases) | identify | ~603,295 ops/sec (1.66 µs/op) |
| assertHmacSecretLength (10 cases) | guard | ~21,745 ops/sec (45.99 µs/op) |
| assertRsaModulusLength (7 cases) | guard | ~27,440 ops/sec (36.44 µs/op) |
| signatureInputValue (4 cases) | serialize | ~96,903 ops/sec (10.32 µs/op) |
| assertContentDigestAlg (10 cases) | guard | ~20,110 ops/sec (49.73 µs/op) |
| resolveComponent (18 cases) | resolve | ~18,947 ops/sec (52.78 µs/op) |

Load note for this run: it was taken on a shared host, so the
absolute throughputs above vary from quieter runs of the same
bench, and rows measured at different moments in the run were
not all hit equally by contention. Treat the table as one real
run — most useful for same-run relative comparison — and re-run
the bench on a quiet machine for capacity numbers.

The `ecdsa-p384-sha384` rows: the P-384 path uses the same fixture
caliber as P-256 (one fresh key pair per scenario, outside the timed
loops), and in this run it measured markedly more expensive than
P-256 — about 2,206 µs/op to sign versus about 78.42 µs/op, and about
1,530 µs/op to verify versus about 182.95 µs/op.

The `ecdsa-p521-sha512` rows: the P-521 path uses the same fixture
caliber as P-256 / P-384 (one fresh key pair per scenario, outside
the timed loops; signatures are the raw r‖s form, 132 bytes total),
and it is the most expensive EC tier in this run — about 2.3× the
per-op sign cost and about 2.6× the verify cost of P-384.

The `verifyAllLabels` row covers the multi-party scenario: the merchant signs
with ed25519 and the payment gateway appends its own hmac-sha256 signature
(`addSignature`) — both labels are verified independently on every call.

The `verifyRequest requiredComponents` row covers the coverage-policy
form a receiver runs before any cryptography: every measured call
verifies a pinned ed25519 fixture signed outside timing covering
exactly `@method`, `@path` and `content-digest` with those three
components required — the pre-cryptographic coverage check the
plain verify rows never pay, because they pass no requirement —
and re-pins that the result is ok. The rejecting and boundary
halves (one missing component's pinned `MISSING_REQUIRED_COMPONENT`
code and singular-form reason, two missing components' plural-form
reason, case-insensitive requirement matching, the opt-in default
and the malformed-entry configuration error) are asserted outside
timing, not in the numbers.

The `resolve` rows cover the keyid→key hot path: the `JwksKeyStore` is
restored offline from a snapshot (the bench performs zero network I/O), a
hit is a plain Map lookup, a `memoizeKeyResolver` hit is served from its
TTL cache, and a miss uses an unknown keyid, which is never cached and so
penetrates to the store on every call. In this run the raw
store hit landed at ~0.25 µs/op, the memoized hit at ~0.26 µs/op
and the miss at ~0.23 µs/op — all three are plain Map/cache
operations whose relative ordering is contention noise on this
offline fixture: memoizing pays off when the underlying
resolver is slow or remote, which this offline fixture
deliberately is not.

The `export` row is new: it measures
`JwksKeyStore.exportSnapshot` — the snapshot export a gateway
runs to persist its key store before a restart, so a cold start
can restore the last fetched keys instead of being unable to
verify until its first successful refresh — isolated from the
`resolve` rows above, which read the store, and from the
snapshot-persistence CLI demo segment, which walks the same
path once for readability. One measured op is one export of a
fixed three-key store (ed25519, P-256 and RSA — the historical
fixture predates P-384/P-521 JWKS support; the store now imports
all five shapes), generated once outside timing and restored
offline under hand-pinned kids at a pinned `fetchedAtSec` of
1700000000 — the bench performs zero network I/O). Every
measured pass re-pins the whole exported envelope against
hand-written expectations: version 1, the pinned fetch time,
exactly the three pinned kids in restore order, the per-shape
`kty` dispatch (OKP / EC / RSA, the EC entry naming P-256),
and public-only JWK material — no entry may carry a private
`"d"` member. Outside timing the bench also asserts that a
never-refreshed store's export is refused with the pinned
full message (there is no meaningful `fetchedAtSec` for keys
that were never fetched). In this run it measured ~17,200
ops/sec (~58.14 µs/op for the three-key pass, roughly
19.4 µs per key) — about 188× the same run's raw resolve hit
(~0.31 µs/op), which is the expected shape: a resolve is a
Map lookup, while an export re-derives every key's JWK
through node:crypto and assembles a fresh detached envelope
on every call. The bench makes no wall-clock assertions.

The `restore` row is new: it measures
`JwksKeyStore.restoreSnapshot` — the snapshot restore a
gateway runs at cold start to rebuild its key store from the
persisted envelope in an existing store object, isolated
from the `export` row above, which serializes the store,
from the static `JwksKeyStore.restore` construction behind
the `resolve` rows, which was never itself a measured op,
and from the snapshot-persistence CLI demo segment, which
walks the same restore once for readability. One measured
op is one restore of a pinned three-key envelope (ed25519, P-256
and RSA — the historical fixture predates P-384/P-521 JWKS
support; the store now imports all five shapes), generated once
outside timing and exported outside timing from a source
store refreshed once through a counting fake fetch at a
pinned `fetchedAtSec` of 1700000000 under a 120-second TTL)
into a target store primed through its own counting fake
fetch with a different single key at the instant exactly
one TTL after the source fetch. Every measured pass
re-pins the restore contract: the pinned kid resolves
afterwards, `stats()` is identical before and after the
restore (the target's primed counters — one refresh, one
hit, one miss — keep running across it, because counters
are not part of a snapshot and restoring resets none of
them), the freshness timestamp is the envelope's original
fetch time, and `isStale()` counts from that time, so at
the target clock's boundary instant the just-restored
store is already stale — restoring never renews freshness.
Outside timing the bench also pins the exhaustive half
(all three kids resolve, the target's primed kid no longer
does, and the restored store re-exports the identical
envelope) and that corrupt envelopes fail closed: an
unsupported version and an empty kid each throw the pinned
full message and leave the store's keys, freshness and
counters exactly as they were. In this run it measured
~2,065 ops/sec (~484.20 µs/op for the three-key
restore-plus-recheck pass) — about 2x the same run's
three-key export (~235.30 µs/op), which is the expected
shape: a restore strictly validates the untrusted envelope
and re-imports every key through node:crypto, while an
export only re-derives JWKs from keys already imported,
and both dwarf a resolve hit (~0.32 µs/op), which is a
plain Map lookup. The bench performs zero network I/O
(both stores fetch only through counting fake fetches,
and a restore performs no fetch at all) and makes no
wall-clock assertions.

The `verifyRequest keyResolver` row is new: it measures
`verifyRequest` in its keyid→key resolution form — the
verify shape a gateway runs while its keys rotate by
keyid, isolated from the static-`key` verify rows above,
which never pay resolution as a separate step, and from
the `memoizeKeyResolver` rows, which time the resolver
cache itself rather than a full verification through a
resolver. One measured op verifies two pinned ed25519
fixtures (one per keyid, both signed outside timing over
the shared fixture with `created` pinned at 1700000000,
the verifier's injected `now` at the same instant)
through a plain Map resolver holding the two pinned
public keys, and re-pins both results on every pass:
each must be ok and each returned `keyId` must equal the
kid its fixture was signed under. Outside timing the
bench also pins the fail-closed half: a fixture signed
under an unknown kid returns exactly
`KEY_RESOLUTION_FAILED` carrying that kid and the pinned
reason, and passing a static `key` together with the
resolver throws the pinned mutual-exclusion
configuration error. In this run it measured ~3,147
ops/sec (~317.73 µs/op for the two-verification pass,
roughly 159 µs per verification) — the same order as the
same run's static-key ed25519 verify (~173.16 µs/op),
which is the expected shape: this offline resolver is a
plain Map lookup, so resolution adds no measurable cost
of its own here; the row exists so the resolver form has
a checked steady-state number of its own, and so a
future resolver regression (or a slower real keystore
behind the same seam) has a baseline to compare against.
The bench performs zero network I/O and makes no
wall-clock assertions (the verifier clock is injected).

The `verifyRequest maxSignatureAgeSec` row is new: it
measures `verifyRequest` with the opt-in
`maxSignatureAgeSec` age cap — the verify form a
receiver uses to bound how long a signed message stays
replayable when it carries `created` but no `expires`,
isolated from the plain verify rows above, which pass
no cap and so never pay the age computation
(`now - created`) or the strict `>` boundary check.
One measured op verifies one pinned ed25519 fixture
(signed outside timing over the shared fixture with
`created` pinned at 1700000000 and no `expires`) at an
injected `now` 60 seconds later, inside the
300-second cap, and re-pins on every pass that the
result is ok. Outside timing the bench also pins the
other two halves of the contract: the same fixture at
one second past the cap returns exactly
`SIGNATURE_TOO_OLD` with the pinned reason, and a
hand-built signature carrying no `created` at all
still verifies at that past-cap instant, because an
undated signature bypasses the age check entirely. In
this run it measured ~1,234 ops/sec (~810.14 µs/op) —
slower per op than the same run's static-key ed25519
verify (~341.24 µs/op), which is contention noise on
this heavily loaded host rather than the cost of one
subtraction and comparison: the row exists so the
age-capped form has a checked steady-state number of
its own. The bench performs zero network I/O and makes
no wall-clock assertions (every verify instant is
injected).

The `verifyRequest requireExpires` row is new: it
measures `verifyRequest` with the opt-in
`requireExpires` requirement — the verify form a
receiver uses to refuse a signature that carries no
`expires` and so has no bounded lifetime, isolated
from the plain verify rows above, which pass no
requirement and so never pay the post-cryptographic
presence check. One measured op verifies one pinned
ed25519 fixture (signed outside timing over the shared
fixture with `created` pinned at 1700000000 and
`expires` 600 seconds later) at an injected `now`
equal to `created`, and re-pins on every pass that the
result is ok. Outside timing the bench also pins the
other two halves of the contract: a hand-built
signature carrying `created` but no `expires` returns
exactly `MISSING_EXPIRES` with the pinned reason under
`requireExpires: true`, and the same signature still
verifies with the option unset, because the
requirement is opt-in. In this run it measured ~6,478
ops/sec (~154.38 µs/op) — the same order as the same
run's static-key ed25519 verify (~200.52 µs/op), the
difference being contention noise on this shared host
rather than the cost of one presence check: the row
exists so the expiry-demanding form has a checked
steady-state number of its own. The bench performs
zero network I/O and makes no wall-clock assertions
(every verify instant is injected).

The `verifyRequest clockSkewToleranceSec (120s)` row is new: it
measures `verifyRequest` with a caller-pinned
`clockSkewToleranceSec` — the verify form a receiver
uses to tolerate a signer whose clock runs ahead,
isolated from the plain verify rows above, which rely
on the 60-second default against fixtures that are not
dated in the future and so never exercise a custom
future-`created` window. One measured op verifies one
pinned ed25519 fixture (signed outside timing over the
shared fixture with `created` pinned 30 seconds ahead
of the verifier's injected `now` at 1700000000) under a
120-second tolerance, and re-pins on every pass that
the result is ok. Outside timing the bench also pins
the other three halves of the contract: the same
fixture under a 10-second tolerance returns exactly
`CREATED_IN_FUTURE` with the pinned reason, exactly at
the boundary (`created` equal to `now + skew`) the same
fixture still verifies because the comparison is a
strict `>`, and with no option passed the same fixture
verifies because the 60-second default covers the
30-second skew. In this run it measured ~6,132
ops/sec (~163.07 µs/op) — the same order as the same
run's static-key ed25519 verify (~167.37 µs/op), the
difference being contention noise on this shared host
rather than the cost of one comparison: the row exists
so the clock-skew-tolerant form has a checked
steady-state number of its own. The bench performs
zero network I/O and makes no wall-clock assertions
(every verify instant is injected).

The `verifyRequest expiredToleranceSec (120s grace)` row is new: it
measures `verifyRequest` with a caller-pinned
`expiredToleranceSec` — the verify form a receiver
uses to accept a signature that expired moments ago
(in-flight requests, signer/receiver clock drift),
isolated from the plain verify rows above, which rely
on the default zero grace against fixtures that have
not expired and so never exercise a custom expiry
window. One measured op verifies one pinned ed25519
fixture (signed outside timing over the shared fixture
with `created` pinned at 1699996400 and `expires` 30
seconds before the verifier's injected `now` at
1700000000) under a 120-second grace, and re-pins on
every pass that the result is ok. Outside timing the
bench also pins the other four halves of the contract:
the same fixture under a 10-second grace returns
exactly `EXPIRED` with the pinned reason, exactly at
the boundary (`now` equal to `expires + tolerance`)
the same fixture still verifies because the comparison
is a strict `>`, with no option passed the same
fixture is rejected because the default grace is zero,
and a hand-built signature whose `expires` precedes
its `created` returns exactly `INVALID_TIME_WINDOW`
with the pinned reason even inside the wide grace —
the grace can extend a lifetime, it cannot resurrect a
signature that was expired at birth. In this run it
measured ~6,428 ops/sec (~155.58 µs/op) — the same
order as the same run's static-key ed25519 verify
(~172.17 µs/op), the difference being contention noise
on this shared host rather than the cost of one
addition and comparison: the row exists so the
grace-tolerant form has a checked steady-state number
of its own. The bench performs zero network I/O and
makes no wall-clock assertions (every verify instant
is injected).

The `verifyRequest expectedKeyId` row is new: it
measures `verifyRequest` with the opt-in
`expectedKeyId` pin — the verify form a receiver
uses to bind verification to the expected signer
key (key-confusion defense), isolated from the
plain verify rows above, which pass no pin and so
never pay the post-cryptographic keyid comparison.
One measured op verifies one pinned ed25519 fixture
(signed outside timing over the shared fixture with
`created` pinned at 1700000000 under the pinned
keyid) with a matching `expectedKeyId`, and re-pins
on every pass that the result is ok and its returned
`keyId` equals the pinned value. Outside timing the
bench also pins the other halves of the contract: a
mismatched pin returns exactly `KEYID_MISMATCH`
with the pinned reason, a hand-built signature
carrying no `keyid` returns the same code with the
`got no keyid` reason shape, and that same no-keyid
signature still verifies with the option unset,
because the pin is opt-in. In this run it measured
~6,212 ops/sec (~160.98 µs/op) — the same order as
the same run's static-key ed25519 verify (~231.97
µs/op), the difference being contention noise on
this shared host rather than the cost of one string
comparison: the row exists so the key-bound form
has a checked steady-state number of its own. The
bench performs zero network I/O and makes no
wall-clock assertions (every verify instant is
injected).

The `verifyAllLabels expectedKeyIds (2 labels)` row is new: it
measures `verifyAllLabels` with the opt-in per-label
`expectedKeyIds` pins — the verify form a multi-party
receiver uses to bind each signer's label to its own
expected key (key-confusion defense when the merchant
and the gateway use different key ids), isolated from
the plain `verifyAllLabels` row above, which passes no
pins and so never pays the per-label pin resolution or
the post-cryptographic keyid comparisons, and from the
single-label `verifyRequest expectedKeyId` row, which
pins only one label. One measured op verifies one
pinned dual-label ed25519 fixture (both labels signed
outside timing over the shared fixture with `created`
pinned at 1700000000 under their pinned keyids) with a
fully matching `expectedKeyIds` map at an injected
`now` equal to `created`, and re-pins on every pass
that both results are ok, in wire order, and that each
returned `keyId` equals its label's pinned value.
Outside timing the bench also pins the other halves of
the contract: a wrong pin on the gateway label returns
exactly `KEYID_MISMATCH` with the pinned reason while
the merchant label still verifies, a label missing
from the map falls back to the global `expectedKeyId`
(a matching fallback verifies both labels, and an
empty map makes the gateway label fail against the
merchant global pin with the pinned code and reason),
and an empty-string map value throws the pinned
configuration error. In this run it measured ~2,359
ops/sec (~423.95 µs/op for the two-label pass, roughly
212 µs per label) — slower per pass than the same
run's unpinned `verifyAllLabels` row (~303.41 µs/op),
which is the expected shape: this pass verifies two
ed25519 signatures and pays two keyid comparisons,
while the unpinned row's gateway label is a cheaper
HMAC verification. The bench performs zero network I/O
and makes no wall-clock assertions (every verify
instant is injected).

The `verifyAllLabels keyResolvers (2 labels)` row is new: it
measures `verifyAllLabels` with the opt-in per-label
`keyResolvers` map — the verify form a multi-party
receiver uses when the merchant's and the gateway's
keyids live in separate keystores, isolated from the
plain `verifyAllLabels` row above, which passes static
keys and so never pays a resolver lookup, and from the
single-label `verifyRequest keyResolver` row, which
resolves only one label. One measured op verifies one
pinned dual-label ed25519 fixture (both labels signed
outside timing over the shared fixture with `created`
pinned at 1700000000 under their pinned keyids, each
keyid belonging to its own resolver's keystore) with a
fully resolving `keyResolvers` map at an injected
`now` equal to `created`, and re-pins on every pass
that both results are ok, in wire order, and that each
returned `keyId` equals its label's pinned value.
Outside timing the bench also pins the other halves of
the contract: the gateway resolver returning
`undefined` gives the gateway label exactly
`KEY_RESOLUTION_FAILED` with the pinned reason while
the merchant label still verifies, a label missing
from the map falls back to the global `keyResolver`,
a non-function map value throws the pinned
configuration error, and `keyResolvers` combined with
`keys` throws the pinned mutual-exclusion
configuration error. In this run it measured ~1,584
ops/sec (~631.16 µs/op for the two-label pass, roughly
316 µs per label) — slower per pass than the same
run's plain `verifyAllLabels` row (~346.36 µs/op),
which is the expected shape: this pass verifies two
ed25519 signatures through two resolver lookups,
while the plain row's gateway label is a cheaper HMAC
verification. The bench performs zero network I/O
and makes no wall-clock assertions (every verify
instant is injected).

The `verifyRequest algFallback (infer)` row is new: it
measures `verifyRequest` with the opt-in
`algFallback: "infer"` — the algorithm-inference form a
receiver uses for foreign signers that omit the optional
`alg` parameter (RFC 9421 §2.3), which the existing
verify rows never timed (their fixtures always carry
`alg` on the wire, so the key-shape inference was never
a measured cost). One measured op verifies the RFC 9421
Appendix B.2.5 wire value verbatim — its
signature-input carries `created` and `keyid` but no
`alg` — against the §B.1.5 pinned shared secret with
`algFallback: "infer"` at an injected `now` equal to
the vector's `created` instant, and re-pins on every
pass that the result is ok and that the inferred `alg`
(`hmac-sha256`) and the returned `keyId` equal their
pinned values. Outside timing the bench also pins the
other halves of the contract: the same wire with no
opt-in returns exactly `VERIFICATION_ERROR` (the legacy
`ed25519` default is tried against the secret key and
the crypto layer rejects the shape — only the code is
pinned, as in the CLI demo, because the reason carries
the crypto layer's own message), a wire
`alg="ed25519"` verified under the opt-in against a
secret key throws the pinned incompatible-key
configuration error, and the same no-`alg` wire
verified under the opt-in against a secp256k1 key — a
shape with no supported mapping — throws the pinned
cannot-infer configuration error. In this run it
measured ~54,107 ops/sec (~18.48 µs/op) — faster per
op than the same run's `hmac-sha256` verify row
(~40.16 µs/op), which is the expected shape: the B.2.5
fixture covers three components and carries no body to
digest, while the scenario row covers four components
including `content-digest` over the shared body; the
inference itself is one key-shape branch before the
same HMAC check. The bench performs zero network I/O
and makes no wall-clock assertions (every verify
instant is injected).

The `refresh` row is new: it measures
`JwksKeyStore.refreshIfStale` on a stale snapshot — the
refresh direction a gateway pays when its key snapshot ages
out and rotation must be picked up, isolated from the
`resolve` rows above, which only read the store, and from
the `export` row, which serializes it. One measured op is
one stale refresh of a one-key store: the injected clock is
advanced by exactly the 120-second TTL before every call
(`isStale()` uses `>=` semantics, so the snapshot is stale
at the boundary), and the call must fetch the pinned JWKS
document from a counting fake fetch (zero network), import
the ed25519 JWK and rebuild the kid index. Every measured
pass self-checks that the call reported a refresh (returned
true), that the fetch count advanced by exactly one, that
the store is fresh again at the advanced instant, and that
the pinned kid resolves; after the run, the total fetch
count must equal priming + warmup + timed calls exactly.
Outside timing the bench also pins the not-stale case: a
fresh snapshot's `refreshIfStale()` returns false and the
fetch count does not move — the "no fetch while fresh"
half of the contract costs nothing and fetches nothing.
In this run it measured ~15,833 ops/sec (~63.16 µs/op) —
the same order as the same run's three-key export
(~58.14 µs/op), which is the expected shape: both rebuild
key material through node:crypto on every call, while a
resolve is a Map lookup. The bench makes no wall-clock
assertions (the store's clock is injected).

The second `refresh` row is new: it measures
`JwksKeyStore.refresh` single-flight merging — the
concurrent direction the serial `refreshIfStale` row above
never pays, when a gateway cold-starts or a rotation lands
and many waiters refresh at once instead of stampeding the
JWKS endpoint. One measured op is one batch of eight
concurrent `refresh()` calls over a one-key store that was
primed once and then made stale by advancing its injected
clock exactly to the 120-second TTL boundary; the counting
fake fetch serves one pinned JWKS document and resolves on
a microtask tick (zero network). Every measured batch
self-checks that the fetch count advanced by exactly one,
that `stats().refreshes` advanced by exactly one, and that
the pinned kid resolves afterwards; after the run, the
total fetch count must equal priming + warmup + timed
batches exactly. Outside timing the bench also pins the
shared-failure half of the contract on a separate store:
one batch of eight waiters all receive the same rejection
object from exactly one fetch (counted once in
`stats().refreshFailures`), and the next `refresh()` after
that failure fetches again and succeeds — a failure is
never cached. In this run it measured ~24,330 ops/sec
(~41.10 µs/op for the eight-call batch, roughly 5.1 µs per
concurrent caller) — close to the same run's serial stale
refresh (~26,837 ops/sec, ~37.26 µs/op), which is the
expected shape: a batch pays one fetch and one JWK import
plus the promise bookkeeping for eight waiters, so seven
of the eight callers ride on the single flight instead of
paying a fetch of their own. The bench makes no wall-clock
assertions (the store's clock is injected and the fake
fetch resolves on a microtask tick).

The `jwkThumbprint` row covers the key-management derivation a JWKS
publisher runs for every key at publish/rotation time: one measured
call derives the RFC 7638 thumbprint of each of the three public JWK
shapes this library exports (ed25519, P-256, RSA — so the per-op cost
covers 3 derivations). The fixture keys have sources independent of
this implementation (the RFC 8032 §7.1 ed25519 test key, the P-256
generator point, and the RFC 7638 §3.1 example RSA key), and the bench
self-checks outside timing that every shape reproduces its pinned
expected thumbprint — the RSA expectation is the value published in
RFC 7638 §3.1 itself.

The `ReplayCache.check` row covers the replay-detection hot path: the
cache is prefilled with 1,000 nonces under a fixed fake clock
(`ReplayCacheOptions.now`, so the cache itself sees no wall clock), and
every measured call rotates over the prefilled set and must report a
replay. The bench self-checks that an unseen nonce reports false on its
first check and true on its second, and that the final `stats()`
counters match the exact number of check calls made.

The `ReplayCache.exportSnapshot` row is new: it measures the
snapshot export a single-process verifier runs to persist its
tracked nonces before a restart, so the restart does not reopen
the replay window — isolated from the `check` row above, which
records and looks up nonces, and from the
snapshot-persistence demo segments, which walk the same path
once for readability. One measured op is one export of a
fixed-clock cache (injected `now`, frozen at the export
instant) whose map holds four recorded nonces: one recorded
7,200 seconds before the export instant and already expired
under the 3,600-second TTL, and three live nonces at pinned
`seenAt` values 30, 20 and 10 seconds before it. Every
measured pass re-pins the whole exported snapshot against
hand-written expectations: version 1, exactly the three live
entries, every entry item by item (nonce and `seenAt`, first
and last included), and the expired nonce absent. Outside
timing the bench also asserts the detached-copy semantics
(mutating an exported snapshot — an entry's nonce, its
`seenAt`, an injected entry, the version — leaves a
re-export unchanged) and that an empty cache exports
`{ v: 1, entries: [] }`. In this run it measured ~428,054
ops/sec (~2.34 µs/op for the three-live-entry pass) — close
to the same run's `ReplayCache.check` hit (~1.89 µs/op):
both are small-map operations at this size (a check is one
Map hit; an export scans a four-entry map, filters expired
entries against the injected clock and assembles a fresh
detached envelope), so their relative ordering at this
scale is contention-sensitive. The bench performs zero
network I/O and makes no wall-clock assertions.

The `ReplayCache.stats` row is new: it measures the
observability snapshot a verifier's monitoring polls on
every tick — isolated from the `check` row above, which
records and looks up nonces, and from the `exportSnapshot`
row, which serializes them. One measured op is one
`stats()` reading of a fixed-clock cache (injected `now`,
frozen at the stats instant) whose construction is pinned
end to end: capacity 6 and a 100-second TTL; two nonces
recorded at the base instant, four live nonces and one hit
90 seconds later, and one further recording whose insertion
LRU-evicts the oldest entry (one eviction); at the stats
instant — exactly one TTL after the base — the second
base-instant nonce is exactly at its TTL boundary (expired
under the `>=` rule but still in the map, since no check
has run to prune it) and the five later nonces are live.
Every measured pass re-pins the whole snapshot against the
hand-written expectation `{ size: 5, hits: 1, misses: 7,
evictions: 1 }` — `size` counts only the live entries —
with the `size` getter agreeing. Outside timing the bench
also asserts the detached-copy semantics (a returned
snapshot overwritten with 999s leaves a re-read unchanged)
and that an empty cache reports all-zero stats. In this
run it measured ~1,495,004 ops/sec (~0.67 µs/op) — faster
than the same run's `ReplayCache.check` hit (~0.84 µs/op),
which is the expected shape: a stats reading is a pure
scan of a six-entry map plus a fresh counter copy, while a
check hit also deletes and re-inserts its entry to refresh
LRU recency. The bench performs zero network I/O and makes
no wall-clock assertions.

The `ReplayCache.fromSnapshot` row is new: it measures the
snapshot restore a single-process verifier runs at startup to
rebuild its replay cache from the persisted snapshot —
isolated from the `exportSnapshot` row above, which serializes
the cache, and from the snapshot-persistence demo segments,
which walk the same restore once for readability. One
measured op is one `ReplayCache.fromSnapshot(snapshot, opts)`
restore of a pinned envelope (exported outside timing from a
fixed-clock source cache, injected `now` frozen at the export
instant) holding four live nonces at pinned `seenAt` values
3,500, 30, 20 and 10 seconds before it, under a 3,600-second
TTL. Every measured pass re-pins the rebuilt cache against
hand-written expectations — the `size` getter and the whole
`stats()` reading `{ size: 4, hits: 0, misses: 0, evictions: 0 }`
(a snapshot carries no counters, and load-time work is not an
eviction) — then checks every restored nonce: each must still
report a replay, so the restart does not reopen the replay
window, and the hit counter must advance by exactly the entry
count. Outside timing the bench also asserts the
expired-at-restore drop (a restore under a clock advanced 200
seconds past the export instant drops exactly the oldest
entry — by then 3,700 seconds old — whose nonce records as
fresh again, while a surviving nonce still replays) and that
corrupt envelopes fail loudly (an unsupported version and a
malformed entry each throw the pinned configuration error
instead of silently disabling replay protection). In this
run it measured ~291,089 ops/sec (~3.44 µs/op for the
four-entry restore-plus-recheck pass) — slower than the same
run's `ReplayCache.stats` reading (~1.18 µs/op) and
`ReplayCache.exportSnapshot` pass (~1.33 µs/op), which is the
expected shape: a restore strictly validates the untrusted
envelope entry by entry and rebuilds the map, and this pass
additionally re-checks all four restored nonces, while a
stats reading is a pure scan and an export only assembles
the envelope. The bench performs zero network I/O and makes
no wall-clock assertions.

The `reject` row covers the malformed-input path a verification gateway
faces from adversarial or broken senders: measured calls rotate over a
fixed corpus of 566 malformed requests, generated deterministically
with the same fixed-seed approach as the parser fuzz test (mulberry32,
seed 20261005) — truncations, byte-level mutations, hand-built shapes
and printable soup over the `signature-input` header of a valid signed
request, malformed and mutated `signature` values, and missing
headers. Pathological-size inputs are excluded (the fuzz test already
pins their per-call latency). The bench self-checks, before and during
timing, that every corpus case returns `{ ok: false, code }` and never
throws, that the missing-header cases carry their exact codes, and
that `MALFORMED_SIGNATURE_INPUT` is the largest error-code bucket, as
the corpus construction implies. The bench performs zero network I/O
and makes no wall-clock assertions; the number is this parser's own
rejection throughput on this machine, not a comparison against any
other implementation.

The `digest` rows measure the standalone RFC 9530 body
hash, `contentDigest(body, alg)`, over the shared fixture body (the
31-byte JSON body named in the bench header), isolated from the
sign/verify paths that normally bundle hashing with an asymmetric
signature — so a reader can see what hashing a body costs on its own
and how the two algorithms compare at this size. In this run
sha-256 landed ahead (~686,048 versus ~557,195 ops/sec) — at this
size the call is mostly fixed overhead, so the ordering (and the
size of the gap) is shared-host noise, not bulk-hashing
performance. The
bench self-checks outside timing that the fixture body reproduces
pinned wire values for both algorithms — the sha-256 value is the
OpenSSL-derived vector in the test suite, the sha-512 value was
computed with `openssl dgst -sha512` and cross-checked with Python
hashlib, and the sha-512 path must also reproduce the test suite's
golden `contentDigest("hello")` value — never values derived from
the implementation at bench time.

The `fromNodeRequest` row measures the inbound
normalization a gateway runs on every received request before
`verifyRequest` — rebuilding the absolute URL
(`https://gateway.example.com:8443/v1/payments?event=charge.succeeded`,
from a TLS socket flag, a verbatim host header with port, and an
origin-form path), lowercasing and folding seven header entries
(one multi-value `x-forwarded-for` whose elements are trimmed and
joined with ", ", one `undefined` entry dropped), and carrying
trailers over from the raw wire form (a duplicated trailer name
merged into one field). The bench fixture is a fixed mock
`IncomingRequestLike` — no real server is started and the bench
performs zero network I/O. Self-checks outside timing pin the
normalized result field by field against a hand-written expected
`RequestLike`, check that the parsed-trailers-object form produces
the identical result, that `rawTrailers` wins over a disagreeing
parsed object, and that a trailer-less message gains no `trailers`
field. In this run it measured ~133,836 ops/sec (~7.47 µs/op) —
the work is a handful of object allocations and string folds, so
run-to-run swings here are host contention (see the load note),
not code changes.

The `roundtrip` rows measure the per-curve JWK
export/import round trip a JWKS publisher pays when serializing a
key set and a verifier pays when loading one, for the shapes the
generic ed25519-only `exportPublicKeyJwk` does not cover. One
measured call exports a fixed public key with `exportPublicKeyJwk*`,
pushes the JWK through a JSON stringify/parse round trip (the wire
form a JWKS document travels in), and re-imports it with
`importPublicKeyJwk*`. The fixture caliber is fixed: one fresh key
pair per shape, generated once outside timing with the library's own
generators — P-256 / P-384 / P-521 via the `generateP*KeyPair`
helpers, RSA via `generateRsaPssKeyPair` (2048-bit modulus, the
library default; the RSA JWK carries no `alg`, so the one RSA row
serves both `rsa-pss-sha512` and `rsa-v1_5-sha256`). Self-checks
outside timing require the re-imported key's SPKI DER — produced by
node:crypto directly, independently of the JWK helpers — to equal
the original's byte-for-byte, for every shape. In this run the EC
rows landed at ~5,274 (P-256), ~3,078 (P-384) and ~4,045 (P-521)
ops/sec and RSA at ~5,288 ops/sec. No ordering across curves is
claimed from this one run — the per-call cost is
dominated by node:crypto's JWK import validation, whose relative
cost per curve should be re-measured on a quiet machine before
drawing conclusions.

The `JWK round-trip ed25519` row is new: it measures the same
round trip for the library's default algorithm, through the
generic `exportPublicKeyJwk` / `importPublicKeyJwk` pair — the
OKP JWK shape a JWKS document actually distributes for ed25519,
which the rows above (per-curve helpers) and the PEM row (the
other encoding of the same key) never timed. One measured call
exports one fixed ed25519 public key (pair generated once
outside timing), re-pins the exported JWK's shape item by item
(`kty` OKP, `crv` Ed25519, a non-empty `x`, and no private `d`
field) on every pass, pushes it through the JSON wire form and
re-imports it; outside timing, the re-imported public key must
verify a signature made with the original private key. In this
run it measured ~24,943 ops/sec (~40.09 µs/op) — cheaper per op
than the same run's PEM ed25519 row (~140.98 µs/op), which is
the expected shape: the PEM pass exports and re-imports both
keys and re-derives a thumbprint on every call, while this row
moves one public key in JSON form. The bench performs zero
network I/O and makes no wall-clock assertions.

The `buildSignatureBase` row is new: it measures the pure
string-building step every sign and verify pays before any
cryptography runs — resolving the covered components of the
shared fixture request and serializing the `@signature-params`
line — isolated so the base-building share of a sign/verify
number is visible apart from the algorithm cost it is normally
bundled into. The covered set is the fixed four components named
in the bench header (`@method @authority @path content-digest`),
the request is the shared fixture (with its `content-digest`
header carrying the pinned sha-512 wire value of the fixture
body), and the parameters are fixed (`created=1700000000`,
`keyid="bench-key"`, `alg="ed25519"` — no wall clock). The bench
self-checks outside timing that the built base equals a
hand-written expected base text byte-for-byte, written out
literally from the RFC 9421 §2.5 rules in the same hand-pinned
style as the test suite's golden vector — never derived from
`buildSignatureBase` at bench time — and re-pins the full text on
every measured call. In this run it measured ~32,858 ops/sec
(~30.43 µs/op) — about 51% of the same run's hmac-sha256 sign
per-op time (~59.90 µs/op) and about 13% of an ed25519 sign
(~230.14 µs/op). The two rows were measured at different moments
under shared-host contention (see the load note), so no precise
share is claimed from this run; the expected shape is that base
building is a real minority share of an asymmetric sign, while
for a cheap MAC sign it is a comparable fixed cost. The bench
performs zero network I/O and makes no
wall-clock assertions.

The `signRequest (ed25519, end-to-end)` row is new: it measures
one complete `signRequest` call over the shared fixture — base
building, the ed25519 cryptography and the `signature-input` /
`signature` header serialization together — the total a signer
pays per request, as its own checked row. The per-algorithm
scenario rows at the top of the table also time `signRequest`,
but they discard the output unchecked; this row's fixture is
fixed (`created=1700000000`, `keyid="bench-key"`,
`alg="ed25519"`, one ed25519 key pair generated once outside
timing — no wall clock) and every measured pass re-pins the
output shape: both signature headers present, the full
`signature-input` value and the single label `sig1` equal to
hand-written expectations, the `content-digest` header equal
to the pinned fixture digest, and the signature a single
member decoding to 64 bytes. Outside timing the bench asserts
exhaustively that the signed request verifies with the pinned
identity (label / keyid / alg) and that the same request with
its body tampered by one byte (amount 100 -> 101) is rejected
with `BODY_DIGEST_MISMATCH`. In this run it measured ~11,851
ops/sec (~84.38 µs/op) — faster per op than the same run's
scenario `ed25519` sign row (~207.45 µs/op), which is not an
ordering claim: the two rows were measured at different
moments under shared-host contention (see the load note), and
the scenario row's loop is the older unchecked shape. No key
or signature bytes are printed. The bench performs zero
network I/O and makes no wall-clock assertions.

The `parse` rows are new: they measure the three standalone
parsers a gateway pre-screen calls directly, isolated from the
end-to-end `verifyRequest` paths that bundle them with base
building and cryptography — `listSignatureLabels` (splitting the
member labels), `parseSignatureInput` (one member's covered
components and parameters) and `parseSignatureField` (one
member's raw signature bytes), each reported as its own row over
a fixed dual-label fixture written out literally in the bench:
a `merchant` member covering
`@method @authority @path content-digest` (created, keyid, alg and
nonce parameters) and a `gateway` member covering
`@method @authority content-type` (created, expires, keyid and
alg), with signature members carrying 16 sequential bytes and
the 11 ASCII bytes `hello-world` respectively (fixture values
only — the parsers decode, they never verify). The bench
self-checks outside timing that both members parse to the
hand-pinned shapes — label list, component lists, every
parameter, both decoded byte strings — and that a hand-pinned
malformed set (empty/trailing-empty label lists, an unknown
label, an unterminated or missing inner list, and signature
members with no `:base64:` shape) all throw; every measured call
re-pins the core of its result. In this run
`parseSignatureInput` was the most expensive of the three
(~63,011 ops/sec, ~15.87 µs/op), `listSignatureLabels` landed at
~141,770 ops/sec (~7.05 µs/op) and `parseSignatureField` at
~337,496 ops/sec (~2.96 µs/op) — together the whole
pre-screen parse of one member costs roughly 26 µs, about 7% of
an ed25519 verify in the same run (~397.48 µs/op), so for a gateway
the parsing itself is not the bottleneck; the cryptography is.
The bench performs zero network I/O and makes no wall-clock
assertions.

The `canon` row is new: it measures
`canonicalizeStructuredFieldValue` — the parse-then-strictly-
reserialize step every `;sf` covered component pays on the signer
and the verifier — isolated from the end-to-end `;sf` verify path
that bundles it with base building and cryptography. One measured
op is one pass over a fixed six-value corpus (6 canonicalizations
per op) covering the three shapes the function tries: a Dictionary
with a Decimal member (`1.5` reserializes as `1.500`, the
three-fraction-digit rule), a Dictionary with member parameters
and an Inner List under sloppy wire spacing, a List of two
Strings, a lone Decimal Item, a lone Integer Item with leading
zeros (`007` reserializes as `7`), and a Dictionary member holding
a Byte Sequence with a Boolean parameter (base64 re-encoded
canonically). Every expected serialization is hand-pinned in the
bench from the RFC 8941 §4 rules (matching the values pinned
independently in the `;sf` test suite) — never derived from the
implementation at bench time — and every measured pass re-pins
every entry's result. In this run it measured ~6,195 ops/sec
(~161.42 µs/op for the six-value pass, roughly 27 µs per value):
among the most expensive pure-string passes in this table, which
is the honest cost of parsing a value as up to three Structured
Field types and reserializing it strictly. The bench performs
zero network I/O and makes no wall-clock assertions.

The `extract` row is new: it measures
`serializeDictionaryMemberValue` — the single-member extraction
every `;key` covered component pays on the signer and the
verifier — isolated from the end-to-end `;key` verify path and
from the whole-value `canon` path above. One measured op is one
pass over a fixed six-key set against one fixed multi-member
Dictionary value (6 extractions per op), and every extraction
re-parses the whole Dictionary — the function has no incremental
API, so that re-parse is the honest per-member cost a gateway
pays per `;key` component. The key set covers an Integer member,
a member carrying parameters (`2;x=1;y=2` — parameters stay
attached to the extracted value), a Decimal member (`1.500`),
a Byte Sequence member with a Boolean parameter
(`:aGVsbG8=:;x=?0`), an Inner List member (`(a b c)`) and a bare
key (`?1` — a Boolean-true member serializes without its key,
per RFC 9421 §2.1.2.1.2). Every expected serialization is
hand-pinned in the bench from the RFC 8941 §4.1.2 rules
(matching the values pinned independently in the `;key` and
`;sf` test suites) — never derived from the implementation at
bench time — every measured pass re-pins every entry's result,
and a missing key must throw "not present", asserted outside
timing. In this run it measured ~9,782 ops/sec (~102.22 µs/op
for the six-key pass, roughly 17 µs per extraction): in this
run its pass landed below the whole-value canonicalization
pass in the same run (~161.42 µs/op), even though it reserializes
only one member — it still parses them all, and the two rows
were measured at different moments, so no per-pass ordering
between them is claimed from this run. The bench performs zero
network I/O and makes no wall-clock assertions.

The `serialize` row is new: it measures
`serializeSignatureParams` — the inner-list-plus-parameters
serialization every sign and verify pays before any
cryptography runs — isolated from the `buildSignatureBase`
row above, whose cost bundles it with resolving every covered
component's value. One measured op is one pass over a fixed
five-case corpus (5 serializations per op) spanning zero to
four covered components: an empty component list carrying
exactly the RFC 9421 §B.2.1 parameters, the shared four
components with created + keyid + alg, the same four with all
six parameters set (created, expires, keyid, alg, nonce, tag),
four parameterized component ids (`;req`, `;tr`, `;name=`,
`;key=`), and a nonce whose quote and backslash characters
must serialize escaped. Every expected string is hand-pinned
in the bench from the serializer's contract (matching values
pinned independently in the Appendix B, golden, parameterized-
component and nonce test suites) — never derived from the
implementation at bench time — and every measured pass
re-pins every case's result. In this run it measured
~20,483 ops/sec (~48.82 µs/op for the five-case pass, roughly
10 µs per case): the five-case pass landed well above one
`buildSignatureBase` call in the same run (~30.43 µs/op) —
the two rows were measured at different moments under
shared-host contention (see the load note), so no per-case
versus per-base ordering is claimed from this run. The bench
performs zero network I/O and makes no wall-clock assertions.

The `generate` row is new: it measures `generateNonce` — the
nonce generation an anti-replay signer pays on every request
before signing — as one pass over the two fixed byte tiers
(one generation per tier per measured op): the default 16
bytes (128 bits, exercised through the no-argument default)
and 32 bytes (256 bits). The random source is the system
CSPRNG (`node:crypto` `randomBytes`), so the numbers include
entropy-source cost, not just the base64url encoding. The
bench self-checks morphology only, on every measured call —
exact length (22 characters for 16 bytes, 43 for 32, the
lengths pinned in the generateNonce test) and the
base64url-only character set — and never a specific value:
the output is random by design, and that randomness comes
only from the function under test itself. In this run it
measured ~44,894 ops/sec (~22.27 µs/op for the two-generation
pass, roughly 11 µs per generation) — the CSPRNG draw plus
the base64url encoding, at this run's shared-host contention
level (see the load note). The bench performs
zero network I/O and makes no wall-clock assertions.

The `verify` / `throw` rows for `verifyRequestOrThrow` are new:
they measure the throwing wrapper a middleware-style caller
actually uses, reported as two separate rows over a fixed
ed25519 fixture (one key pair generated outside timing,
`created` pinned, verified at a fixed `now` — no wall clock).
The valid row is the success path: the same `verifyRequest`
work plus result unwrapping, self-checked on every measured
call to return label `sig1`, keyid `bench-key` and alg
`ed25519`. The tampered row is the failure path over the same
request with the first signature byte flipped (the tamper
construction pinned in the verify-errors test): every measured
call must catch a `VerifyError` — asserted via `isVerifyError` —
carrying the pinned code `SIGNATURE_MISMATCH` written as a
literal in the bench, and the throw count afterwards must equal
warmup + timed iterations exactly, so the row prices exception
construction and carrying the machine-readable code, not just
the failed cryptography. In this run the valid row measured
~2,240 ops/sec (~446.42 µs/op) and the tampered row ~2,661 ops/sec
(~375.78 µs/op): the two rows landed in the same range in this
run, the tampered row faster in this run despite — or rather
including — the extra exception construction (the two rows
were measured at different moments under shared-host
contention), and both landed
close to the result-style ed25519 verify row (~397.48 µs/op)
in the same run — the wrapper adds no cryptography, so no
cross-row ordering beyond that is claimed.
The bench performs zero network I/O and makes no
wall-clock assertions.

The `lookup` row is new: it measures `getHeader` and
`getHeaderRaw` — the case-insensitive header lookup every
covered-component resolution pays on the signer and the
verifier — isolated from the end-to-end paths and from the
`buildSignatureBase` row above, whose cost bundles one such
lookup per covered component with the base serialization.
One measured op is one pass over a fixed nine-name lookup set
against one fixed multi-header fixture (9 names × both
helpers = 18 lookups per op): mixed-case single strings, a
duplicated header name under two casings (`Host` first, a
shadowed lowercase `host` second — the first match in
insertion order must win), and two multi-value fields whose
elements carry padding whitespace, on which the two helpers
must differ — `getHeader` trims each element and joins with
", " (the canonical form), `getHeaderRaw` joins the raw
elements untrimmed (the form a `;bs` component binds) — while
a padded single string passes through verbatim in both forms.
Every expected value is hand-pinned in the bench from the two
helpers' documented contracts — never derived from the
helpers at bench time — every measured pass re-pins every
lookup's result for both helpers, and the missing /
undefined-valued names (three absent names plus one present
with an `undefined` value, all returning `undefined` from
both helpers) are asserted outside timing. In this run it
measured ~76,753 ops/sec (~13.03 µs/op for the 18-lookup pass,
roughly 0.72 µs per lookup) — in this run the pass landed
below the same run's `buildSignatureBase` row (~30.43 µs/op
for four components): the two rows were measured at different
moments under shared-host contention (see the load note), so
no ordering between the scan-and-fold and base building is
claimed from this run. The bench performs zero network I/O and makes no
wall-clock assertions.

The `join` row is new: it measures `joinHeaderValues` — the
multi-value header combination every canonical lookup,
signer-side fold and Node-adapter fold pays for a repeated
header field — isolated from the `lookup` row above, whose
cost bundles it with the case-insensitive scan. One measured
op is one pass over a fixed nine-case corpus (9 combinations
per op) spanning an empty array, a single padded value, plain
and whitespace-padded multi-value arrays (spaces and tabs),
and empty-element cases: a lone empty string, two
whitespace-only elements, an empty element in the middle of
real values, and an empty first element. Empty elements are
not dropped — each element is trimmed and the results are
joined with ", ", so an empty element still contributes its
separator (["a", "", "b"] combines to "a, , b"), because
dropping it would canonicalize two different wire shapes onto
one signature base. Every expected combination is hand-pinned
in the bench from the helper's documented contract (the
non-empty pins match the values pinned independently in the
multi-value-header test suite) — never derived from
`joinHeaderValues` at bench time — and every measured pass
re-pins every case's result. In this run it measured
~212,430 ops/sec (~4.71 µs/op for the nine-case pass, roughly
0.52 µs per combination) — a trim and a join per element,
with no scan and no parsing; its per-pass cost landed below
the `lookup` pass in this run, and no ordering
between the two header rows is claimed from it. The bench
performs zero network I/O and makes no wall-clock assertions.

The `identify` row is new: it measures `contentDigestAlgOf`
— the digest-algorithm identification a signer appending a
second signature pays to pin itself to the existing wire
Content-Digest value — isolated from the `digest` rows
above, whose cost is hashing, and from the end-to-end
`addSignature` path that bundles it. One measured op is one
pass over a fixed ten-case corpus (10 identifications per
op): both emittable algorithms alone (the pinned wire values
of the shared fixture body), mixed two-algorithm values in
both orders, unknown algorithms (sha-1, sha-384), and
malformed shapes (an uppercase prefix, a leading space, a
bare algorithm name with no `=`, and the empty string). The
helper reads only the prefix before the first `=`, so a
mixed value resolves to its first entry — sha-512-first to
`sha-512`, sha-256-first to `sha-256` — which is the
signer-side pinning contract, not the verifier's body check
(that scans the whole value and prefers sha-512 when both
are present). Every unknown or malformed case must return
`undefined`, the fail-closed shape a caller turns into an
explicit rejection. Every expected result is hand-pinned in
the bench from the helper's documented contract (the sha-1
pin matches the rejection the contentDigestAlg test suite
pins for a header this library cannot emit) — never derived
from `contentDigestAlgOf` at bench time — the corpus is
self-checked outside timing first, and every measured pass
re-pins every case's result. In this run it measured
~494,055 ops/sec (~2.02 µs/op for the ten-case pass,
roughly 0.20 µs per identification) — a prefix scan and a
pair of string comparisons, far cheaper than the hashing it
precedes, which is the expected shape. The bench performs
zero network I/O and makes no wall-clock assertions.

The first `guard` row is new: it measures `assertHmacSecretLength`
— the per-algorithm HMAC secret-length guard every HMAC
sign/verify pays before any MAC runs (RFC 2104: the key
SHOULD be at least as long as the hash output, so
hmac-sha256 requires at least 32 bytes and hmac-sha512 at
least 64) — isolated from the HMAC sign/verify rows above,
whose cost bundles it with the MAC itself. One measured op
is one pass over a fixed ten-case corpus (10 guard checks
per op): for each algorithm an empty secret, one byte below
its floor (31 / 63 bytes), exactly at its floor (32 / 64
bytes), and far above it (128 bytes), plus the
cross-algorithm contrast — a 63-byte secret passes for
hmac-sha256, and a 32-byte secret that passes for
hmac-sha256 is rejected for hmac-sha512, because the floor
is paired with the algorithm, never shared. Six of the ten
cases throw and are caught inside the measured pass, so the
fail-closed rejection (including exception construction) is
part of the steady state a caller pays. Every expected
pass/throw outcome, including the exact floor and byte
count in each throw message, is hand-pinned in the bench
from the guard's documented contract (matching the messages
the keyLength and hmacSha512 test suites pin independently)
— never derived from `assertHmacSecretLength` at bench
time — the corpus is self-checked exhaustively outside
timing first, and every measured pass re-pins every case's
outcome. The secrets are built once at bench start from a
fixed fill; only their lengths matter. In this run it
measured ~7,745 ops/sec (~129.12 µs/op for the ten-case pass,
roughly 12.9 µs per check) — a per-check cost dominated by
the six throwing cases' exception construction, not the
length comparison itself, which is the expected shape for a
fail-closed guard whose passing path is a single integer
comparison. The bench performs zero network I/O and makes
no wall-clock assertions.

The second `guard` row is new: it measures
`assertRsaModulusLength` — the RSA modulus-length guard
every `rsa-v1_5-sha256` sign/verify pays before any RSA
operation runs (the modulus must be at least
`MIN_RSA_MODULUS_BITS` = 2048 bits, and the key must be an
RSA key at all) — isolated from the RSA sign/verify rows
above, whose cost bundles it with the RSA operation itself.
One measured op is one pass over a fixed seven-case corpus
(7 guard checks per op): a 2048-bit RSA public and private
key at exactly the floor (both pass), a 1024-bit RSA public
and private key below the floor (both throw the pinned
"must be at least 2048 bits, got 1024 bits" message the
rsaV15 suite pins for the same weak pair on both sides),
and three wrong-shape keys — an ed25519 public key, a
P-256 public key and a symmetric secret — each throwing
the pinned expected-an-RSA-key message for its shape.
Five of the seven cases throw and are caught inside the
measured pass, so the fail-closed rejection (including
exception construction) is part of the steady state a
caller pays. Every expected pass/throw outcome, including
the exact full throw message under the bench's fixed
caller context, is hand-pinned in the bench from the
guard's documented contract — never derived from
`assertRsaModulusLength` at bench time — the corpus is
self-checked exhaustively outside timing first, and every
measured pass re-pins every case's outcome. All keys are
generated once at bench start; the timed region generates
no keys. In this run it measured ~7,174 ops/sec
(~139.38 µs/op for the seven-case pass, roughly 19.9 µs per
check) — a per-check cost dominated by the five throwing
cases' exception construction, not the type and modulus
comparisons themselves, which is the expected shape for a
fail-closed guard whose passing path is a key-type check
plus a single integer comparison. The bench performs zero
network I/O and makes no wall-clock assertions.

The third `guard` row is new: it measures
`assertContentDigestAlg` — the content-digest algorithm
guard every sign/verify that selects a digest algorithm
pays before any hashing runs (only `sha-512` and
`sha-256` can be emitted; anything else is a caller
configuration error, never a verification failure) —
isolated from the `digest` rows above, whose cost is
hashing, and from the sign/verify rows that bundle it.
One measured op is one pass over a fixed ten-case corpus
(10 guard checks per op): the two emittable algorithms
(both pass), unknown algorithms (`sha-1` and `md5`, both
throw), the empty string (throws), two wrong-case
spellings (`SHA-512` and `Sha-256`, both throw — the
comparison is exact and case-sensitive), a trailing-space
spelling (`sha-512 `, throws — no trimming), and the
non-string values `undefined` and `null` (both throw).
Eight of the ten cases throw and are caught inside the
measured pass, so the fail-closed rejection (including
exception construction) is part of the steady state a
caller pays. Every expected pass/throw outcome, including
the exact full throw message for each case, is
hand-pinned in the bench from the guard's documented
contract (matching the rejections the contentDigestAlg
test suite pins for `sha-1`, `md5` and the empty string)
— never derived from `assertContentDigestAlg` at bench
time — the corpus is self-checked exhaustively outside
timing first, and every measured pass re-pins every
case's outcome. In this run it measured ~15,196 ops/sec
(~65.81 µs/op for the ten-case pass, roughly 6.6 µs per
check) — a per-check cost dominated by the eight throwing
cases' exception construction, not the two string
comparisons themselves, which is the expected shape for
a fail-closed guard whose passing path is two exact
comparisons. The bench performs zero network I/O and
makes no wall-clock assertions.

The second `serialize` row is new: it measures
`signatureInputValue` — the full `Signature-Input` field
value a signer builds once per label (`label=` plus the
serialized inner list and parameters) — isolated from the
`serializeSignatureParams` row above, which measures the
same serialization without the label prefix, and from the
sign rows that bundle it with base building and
cryptography. One measured op is one pass over a fixed
four-case corpus (4 value builds per op): a bare
single-component value with an empty parameter set (the
value renders as the bare inner list — this function
builds a value, it does not look one up, so there is no
missing-label / undefined outcome to pin), the shared
four components under the label `sig1` with created +
keyid + alg, a second label, `merchant`, over the same
four components with all six parameters set, and a
`gateway` value with parameterized component ids
(`;req`, `;key="b"`) and a nonce whose quote and backslash
must serialize escaped. Every expected string is
hand-pinned in the bench from the function's contract
(matching values pinned independently in the golden,
multi-label and nonce test suites) — never derived from
`signatureInputValue` at bench time — every measured pass
re-pins every case's result, and the dual-label join of
the golden and merchant values (joined with ", ", the
merge the multi-label tests build from two such outputs)
is asserted outside timing against a hand-pinned full
header literal. In this run it measured ~32,736 ops/sec
(~30.55 µs/op for the four-case pass, roughly 7.6 µs per
case) — its per-case cost landed below the
`serializeSignatureParams` per-case cost in the same run
(~10 µs), but the two corpora differ in composition (this
one includes the bare minimal case), so no ordering
between the two `serialize` rows is claimed from this
run. The bench performs zero network I/O and makes no
wall-clock assertions.

The second `resolve` row is new: it measures
`resolveComponent` — the per-component resolution every
sign and verify pays once per covered component, turning
one component identifier into the exact value its
signature-base line carries — isolated from the
`buildSignatureBase` row above, which bundles it with
the `@signature-params` serialization, and from the
`JwksKeyStore.resolve` row, which is key resolution, not
component resolution. One measured op is one pass over a
fixed eighteen-case corpus (18 resolutions per op): ten
derived components (`@method`, `@scheme`, `@authority`,
`@path`, `@query`, `@request-target`, `@target-uri`,
`@query-param;name="amount"`, `@created` and `@status`),
two plain header fields (`content-type` and the pinned
`content-digest` — the shape the CLI demo's resolution
segment presents, widened here with the forms the demo
does not cover), and six parameterized forms
(`x-charge-ref;bs` binding the raw bytes including a
trailing space, `example-dict;sf` strictly re-serializing
a sloppily-spaced dictionary, `x-dict;key="b"` extracting
one member, `x-checksum;tr` resolving from the trailers
rather than the same-named header, and `@method;req` /
`x-charge-id;req` resolving against the associated
request). Every expected value is hand-pinned in the
bench from the resolver's contract, cross-checked
against the values the demo segment and the bs / sf /
key / tr / req / query-param test suites pin
independently — never derived from `resolveComponent`
at bench time — the corpus is self-checked exhaustively
outside timing first, every measured pass re-pins every
case's value, and the unsupported-parameter rejection
(the demo's pinned `;zz` shape, exact message) is
asserted outside timing, so the measured steady state
is successful resolutions only. In this run it measured
~11,556 ops/sec (~86.54 µs/op for the eighteen-case
pass, roughly 4.8 µs per resolution) — a per-resolution
cost dominated by the parameterized forms' parsing and
re-serialization, not the derived components' string
reads, which is the expected shape for a resolver whose
plain path is a URL parse plus a header lookup. The
bench performs zero network I/O and makes no
wall-clock assertions.

The `verifyRequest requireCreated` row is new: it measures
`verifyRequest` with the opt-in `requireCreated` — the
created-presence form a receiver uses to refuse signatures
with no bounded age, which the existing verify rows never
timed (they set no requirement, so the post-cryptographic
`created === undefined` presence check was never a measured
cost). One measured op verifies a hand-built no-`created`
ed25519 signature (minted outside timing with
`buildSignatureBase` + `signatureInputValue` + a raw
ed25519 sign, because `signRequest` always emits `created`)
with `requireCreated: true` at an injected `now`, and
re-pins on every pass that the result is exactly
`MISSING_CREATED` with the pinned reason — the measured
steady state is the rejecting path, unlike the
accepting-path verify rows. Outside timing the bench also
pins the other halves of the contract: the same
no-`created` signature still verifies with the option
unset (the requirement is opt-in), a dated `signRequest`
fixture verifies under `requireCreated: true`, and a
forged (tampered signature bytes) no-`created` signature
returns `SIGNATURE_MISMATCH`, because the cryptographic
check runs before the presence check — so a forgery is
never mistaken for a policy violation. In this run it
measured ~4,915 ops/sec (~203.48 µs/op) — the same order
as an ed25519 verify on this host class, which is the
expected shape: the row exists so the created-presence
form has a checked steady-state number of its own, not
because one presence comparison moves the needle. The
bench performs zero network I/O and makes no
wall-clock assertions (every verify instant is
injected).

The `verifyRequest expectedTag` row is new: it measures
`verifyRequest` with the opt-in `expectedTag` — the
application-tag-pinning form a receiver uses for
cross-protocol replay protection (RFC 9421 §2.3), which
the existing verify rows never timed (they set no
expectation, so the post-cryptographic tag comparison
was never a measured cost). One measured op verifies one
pinned ed25519 fixture (signed outside timing over the
shared fixture with `created` pinned at 1700000000 and
`tag` pinned to `"payment-webhook-v1"`) with the matching
`expectedTag` at an injected `now` equal to `created`,
and re-pins on every pass that the result is ok and the
returned `tag` equals the pinned value. Outside timing
the bench also pins the other halves of the contract:
the same signature under a different `expectedTag`
returns exactly `TAG_MISMATCH` with the pinned reason
`tag mismatch: expected "refund-webhook-v1", got
"payment-webhook-v1"`, a fixture signed with no `tag` at
all returns `TAG_MISMATCH` with the pinned `got no tag`
reason shape, and the same tagged signature still
verifies with the option unset, because the requirement
is opt-in. In this run it measured ~4,977 ops/sec
(~200.94 µs/op) — the same order as the same run's
static-key ed25519 verify (~205.72 µs/op), which is the
expected shape: the row exists so the tag-pinning form
has a checked steady-state number of its own, not
because one string comparison moves the needle. The
bench performs zero network I/O and makes no
wall-clock assertions (every verify instant is
injected).

The `verifyRequest replayCache` row is new: it measures
`verifyRequest` with the opt-in `replayCache` — the
replay-defense form a receiver uses to refuse an
already-seen request (RFC 9421 nonce replay protection),
which the existing verify rows never timed (they pass
no cache, so the post-cryptographic cache consultation
was never a measured cost). One measured op verifies
one pinned ed25519 fixture (signed outside timing over
the shared fixture with `created` pinned at 1700000000
and `nonce` pinned to `"bench-replay-nonce-1"`) twice
against a fresh `ReplayCache` sharing the injected
`now` of 1700000000: the first verify records the
nonce and is ok, the second is rejected with exactly
the pinned `NONCE_REPLAY` code and reason
`nonce replay detected: "bench-replay-nonce-1" was
already seen`. Outside timing the bench also pins the
other halves of the contract: without a cache the
same fixture verifies twice (replay defense is
opt-in), a nonce-less signature verifies twice under
a cache (nonce-less signatures bypass the cache
entirely), and a forged signature (signature bytes
tampered) returns `SIGNATURE_MISMATCH` without
polluting the cache — the cryptographic check runs
before the cache consultation, so the unmodified
fixture still verifies (and is then replay-rejected)
afterwards. In this run it measured ~1,780 ops/sec
(~561.89 µs/op) — slower than the same run's plain
ed25519 verify row, which is the expected shape: one
measured op performs two full verifications plus a
cache allocation, and the row exists so the
replay-defense form has a checked steady-state number
of its own. The bench performs zero network I/O and
makes no wall-clock assertions (every verify instant
is injected).

The `verifyRequest requireNonce` row is new: it measures
`verifyRequest` with the opt-in `requireNonce` — the
nonce-presence form a receiver runs to refuse nonce-less
signatures before they ever reach the replay store,
which the existing verify rows never timed (they pass
no such requirement, so the post-cryptographic
presence check was never a measured cost). One
measured op verifies one pinned ed25519 fixture
(signed outside timing over the shared fixture with
`created` pinned at 1700000000 and `nonce` pinned to
`"bench-require-nonce-1"`) with `requireNonce: true`,
self-checking that the result is ok and the returned
`nonce` equals the pinned value. Outside timing the
bench also pins the rejecting half of the contract: a
nonce-less signature under the option returns exactly
`MISSING_NONCE` with the pinned reason (so the measured
path cannot be an empty one), and the same nonce-less
signature still verifies with the option unset —
the requirement is opt-in. In this run it measured
~4,355 ops/sec (~229.62 µs/op), in the expected band
just above the plain ed25519 verify row (one presence
check on top of a full verification). The bench
performs zero network I/O and makes no wall-clock
assertions (every verify instant is injected).

Environment: Node v24.22.1, linux/x64, AMD EPYC 9D25 (virtualized; shared
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
| `TAG_MISMATCH` | signature's `tag` does not match the verifier's `expectedTag` (or no `tag` present) |
| `KEY_RESOLUTION_FAILED` | `keyResolver` could not map the signature's `keyid` to a key (missing or unknown `keyid`) |
| `MISSING_CONTENT_DIGEST` | body present but no `sha-512` (preferred) or `sha-256` (fallback) entry in `content-digest` |
| `BODY_DIGEST_MISMATCH` | body bytes do not match the signed `sha-512` (or `sha-256` fallback) digest |
| `EXPIRED` | `expires` timestamp is in the past (beyond tolerance) |
| `CREATED_IN_FUTURE` | `created` timestamp is in the future (beyond clock-skew tolerance) |
| `SIGNATURE_TOO_OLD` | `created` is older than the opt-in `VerifyOptions.maxSignatureAgeSec` window |
| `MISSING_CREATED` | `requireCreated` is set but the signature carries no `created` |
| `MISSING_EXPIRES` | `requireExpires` is set but the signature carries no `expires` |
| `INVALID_TIME_WINDOW` | both timestamps present but `expires` is earlier than `created` (signature already expired at birth; `expires === created` is allowed) |
| `NONCE_REPLAY` | nonce already seen within the replay-cache TTL (`VerifyOptions.replayCache`) |
| `MISSING_NONCE` | `requireNonce` is set but the signature carries no `nonce` (or an empty-string one) |
| `MISSING_REQUIRED_COMPONENT` | the signature omits a component required by `VerifyOptions.requiredComponents` |

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

`npm test` runs 825 tests including the RFC 9421 Appendix B.2.1, B.2.2, B.2.3, B.2.4, B.2.5 and B.2.6 independent interop vectors (all six verify end-to-end;
every vector's base also matches byte-for-byte — see Interoperability), a golden signature-base vector and a golden
`Content-Digest` vector (the latter cross-checked against `openssl`).
No external network access (the JWKS tests serve their key documents from
a loopback-only `http` server on an ephemeral port), no randomness in
assertions (keys are generated per-test but only round-trip properties
are asserted).

## License

MIT

See [CHANGELOG.md](CHANGELOG.md) for the release history.
