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
npm test   # 541 tests, all local, no external network (JWKS tests use a loopback-only server)
```

Or run the bundled demo — one command generates a fresh ed25519 key
pair, signs a fixed payment request (with `Content-Digest` and a
`nonce`), prints the `Signature-Input` / `Signature` headers, and
verifies it; then it tampers the body by one byte and shows the
verifier rejecting it with `BODY_DIGEST_MISMATCH`:

```bash
npm run demo
```

The request data (method, URL, body, `created` timestamp, key id, and
nonce) is fixed in `src/demo.ts` — no network, no wall clock — so every
line except the freshly generated signature itself is identical
between runs.

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
`key` (passing both throws a configuration error).

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
with the same refusal of private (`"d"`) material.

RSA gateways too: `exportPublicKeyJwkRsa` / `importPublicKeyJwkRsa` handle
the RFC 7518 RSA shape (`{ kty: "RSA", n, e }`) for RSA verifiers, with
the same refusal of private (`"d"`) material. One JWK serves both RSA
algorithms (`rsa-pss-sha512` and `rsa-v1_5-sha256`): the JWK carries no
`alg`, so the distinction lives only in each signature's `alg` parameter. One honest
caveat documented in code: node:crypto's RSA JWK importer is lenient, so a
structurally-valid but degenerate modulus (e.g. all-zero `n`) is accepted
at import time and fails only at the crypto layer when used — verification
still fails closed, never silently accepts.

Network key discovery (JWKS): when a signer's keys live behind a JWKS
endpoint — the gateway/webhook standard for public-key distribution and
rotation — `JwksKeyStore` fetches the document, imports every key by
`kid` (ed25519 / P-256 / RSA, the three JWK shapes above), and exposes a
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
its atomic semantics and returns `true`. Concurrent calls are deliberately not
deduplicated — two overlapping calls may each fetch; serialize them yourself
if you need single-flight behaviour.

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
configuration `Error` instead of silently defaulting.

## What it implements

- **Signature base** (§2.5): `"id": value` lines for each covered component,
  then the `"@signature-params"` line. Covered components: `@method`,
  `@scheme`, `@authority`, `@path`, `@query`, `@query-param`, `@status`, `@target-uri`, `@created`,
  `@expires`, plus any HTTP header field (case-insensitive, multi-values joined).
  `@status` (response verification, e.g. webhook callbacks or signed API
  responses) binds the response status code: set `RequestLike.status` on
  both `signRequest` and `verifyRequest` — a covered `@status` with no status
  is a caller configuration error (fail-fast on the sign side,
  `SIGNATURE_BASE_BUILD_FAILED` on the verify side).
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
- **Algorithms**: `ed25519`, `ecdsa-p256-sha256` (NIST P-256; DER-encoded
  ECDSA signatures per RFC 9421 §3.3.4), `rsa-pss-sha512` (RSASSA-PSS with
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
  `verifyAllLabels` labels, while `requireNonce` is judged per label. The cache is in-memory, bounded (LRU + TTL), and per-process —
  multi-verifier deployments still need a shared nonce store (see the
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
  per label. An empty-string tag is rejected by `signRequest` as a
  configuration error (it would bind nothing).
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
  the global `expectedKeyId`. For resolver-based verification, pass
  per-label resolvers via the optional `keyResolvers` map
  (label→`(keyId) => KeyObject | undefined`) — handy when the parties'
  key ids live in separate keystores (merchant store vs gateway store);
  labels missing from it fall back to the global `keyResolver`.
  `keys`/`key` cannot be combined with either resolver (configuration
  error). Duplicate labels are verified once (first occurrence); a
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
  trailer sections off the wire). Network key
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
  (DER-encoded, RFC 9421 §3.3.4), `rsa-pss-sha512` (RSASSA-PSS with
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
  → `ed25519`, P-256 EC key → `ecdsa-p256-sha256`, RSA key →
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
algorithm (3000 timed iterations per op after 200 warmup, printing the Node
version and CPU). One real run on 2026-10-10:

| alg | op | throughput |
|-----|--------|------------|
| ed25519 | sign | ~3,500 ops/sec (~284 µs/op) |
| ed25519 | verify | ~4,100 ops/sec (~241 µs/op) |
| hmac-sha256 | sign | ~45,300 ops/sec (~22 µs/op) |
| hmac-sha256 | verify | ~33,400 ops/sec (~30 µs/op) |
| hmac-sha512 | sign | ~45,900 ops/sec (~22 µs/op) |
| hmac-sha512 | verify | ~37,600 ops/sec (~27 µs/op) |
| ecdsa-p256-sha256 | sign | ~18,400 ops/sec (~54 µs/op) |
| ecdsa-p256-sha256 | verify | ~7,500 ops/sec (~133 µs/op) |
| rsa-pss-sha512 | sign | ~1,600 ops/sec (~618 µs/op) |
| rsa-pss-sha512 | verify | ~11,700 ops/sec (~86 µs/op) |
| rsa-v1_5-sha256 | sign | ~1,600 ops/sec (~607 µs/op) |
| rsa-v1_5-sha256 | verify | ~9,000 ops/sec (~111 µs/op) |
| verifyAllLabels (2 labels) | verify | ~5,100 ops/sec (~196 µs/op) |

The `verifyAllLabels` row covers the multi-party scenario: the merchant signs
with ed25519 and the payment gateway appends its own hmac-sha256 signature
(`addSignature`) — both labels are verified independently on every call.

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

`npm test` runs 541 tests including the RFC 9421 Appendix B.2.5 independent interop vector, a golden signature-base vector and a
golden `Content-Digest` vector (the latter cross-checked against `openssl`).
No external network access (the JWKS tests serve their key documents from
a loopback-only `http` server on an ephemeral port), no randomness in
assertions (keys are generated per-test but only round-trip properties
are asserted).

## License

MIT
