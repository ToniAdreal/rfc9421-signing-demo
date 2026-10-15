# Changelog

All notable changes to this project are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and the version below is the version declared in `package.json`. Every entry
summarizes one or more commits in this repository's `git log`, grouped by
change type; no entry describes a feature that is not in the history.

## [Unreleased]

### Added

- The benchmark (`npm run bench`) now also measures
  `serializeDictionaryMemberValue` — the single-member extraction
  every `;key` covered component pays on the signer and the
  verifier — as one pass over a fixed six-key set against one
  fixed multi-member Dictionary value (an Integer member, a
  member with parameters, a Decimal member, a Byte Sequence
  member, an Inner List member and a bare key) per measured
  call. Every expected serialization is hand-pinned in the bench
  from the RFC 8941 §4.1.2 rules, a missing key's throw is
  asserted outside timing, and every measured pass re-pins
  every entry's result. The README Benchmarks table was
  refreshed wholesale from one real run and now carries the
  `extract` row. The bench performs zero network I/O and makes
  no wall-clock assertions.
- The CLI demo (`npm run demo`) now also prints a signature-base
  segment right after the main line's verification: the RFC 9421
  §2.5 signature base of the main `sig1` signature — the exact
  string that was signed — rebuilt with `buildSignatureBase` over
  the request's actual covered components (`@method`, `@authority`,
  `@path`, `content-digest`), followed by a line mapping each base
  line to its covered component. The base carries no key or
  signature bytes and every input is a fixed demo constant, so the
  segment is byte-identical between runs; it performs zero
  network I/O.
- The benchmark (`npm run bench`) now also measures
  `verifyRequestOrThrow` — the throwing verify wrapper a
  middleware-style caller uses — as two separate rows over a
  fixed ed25519 fixture: the success path (result unwrapping
  over one valid request) and the failure path over the same
  request with one signature byte flipped, where every measured
  call catches a `VerifyError` asserted via `isVerifyError` to
  carry the pinned `SIGNATURE_MISMATCH` code, so the exception-
  construction cost is priced separately. Self-checks run
  outside timing and on every measured call. The README
  Benchmarks table was refreshed wholesale from one real run
  and now carries the `verify` / `throw` rows. The bench
  performs zero network I/O and makes no wall-clock assertions.
- The CLI demo (`npm run demo`) now also closes with a JWK
  thumbprint segment: the demo public key is exported as a JWK, its
  RFC 7638 `jwkThumbprint` is printed, and a request signed with
  that thumbprint as its `keyid` verifies with `expectedKeyId`
  pinned to the same thumbprint, showing the fingerprint-as-keyid
  binding. The segment performs zero network I/O; the thumbprint
  is derived from the demo's fresh key, so it differs between runs
  like the signature itself.
- The benchmark (`npm run bench`) now also measures
  `canonicalizeStructuredFieldValue` — the parse-then-strictly-
  reserialize step every `;sf` covered component pays on the
  signer and the verifier — as one pass over a fixed six-value
  corpus (Dictionary / List / Item shapes, a Decimal member, a
  leading-zero Integer, and a Byte Sequence member) per measured
  call. Every expected serialization is hand-pinned in the bench
  from the RFC 8941 §4 rules and re-pinned on every measured
  pass. The README Benchmarks table was refreshed wholesale from
  one real run and now carries the `canon` row. The bench
  performs zero network I/O and makes no wall-clock assertions.
- The benchmark (`npm run bench`) now also measures the three
  standalone signature parsers a gateway pre-screen calls
  directly — `listSignatureLabels`, `parseSignatureInput` and
  `parseSignatureField` — each as its own row over a fixed
  hand-written dual-label fixture (`merchant` / `gateway`
  members, written out literally in the bench, not produced by
  `signRequest`). Self-checks outside timing pin both members'
  label list, component lists, every parameter and both decoded
  byte strings, plus a hand-pinned malformed set that must all
  throw; every measured call re-pins the core of its result.
  The README Benchmarks table was refreshed wholesale from one
  real run and now carries the three `parse` rows. The bench
  performs zero network I/O and makes no wall-clock assertions.
- The CLI demo (`npm run demo`) now also shows an inbound
  normalization segment: a request signed against a host-with-port
  URL (with `@scheme` and a multi-value `x-trace-hops` header
  covered) is rebuilt from a mock Node `IncomingMessage`-shaped
  object — mixed-case header names, the multi-value header still an
  array, an encrypted socket — through `fromNodeRequest`, the
  normalized method/URL/headers are printed, and the result
  verifies; rebuilding the same wire request with the wrong scheme
  (`http`) is rejected with `SIGNATURE_MISMATCH`. The segment starts
  no server and performs zero network I/O.
- The CLI demo (`npm run demo`) now also shows a sha-256
  Content-Digest segment: the same fixed demo request is re-signed
  with `contentDigestAlg: "sha-256"` for a peer that only accepts
  sha-256 digests, the main line's sha-512 and the peer line's
  sha-256 `Content-Digest` headers are printed side by side on the
  same body, the sha-256 signature verifies, and the same one-byte
  body tamper as the main line is rejected with
  `BODY_DIGEST_MISMATCH`. The segment performs zero network I/O and
  uses the demo's fixed key id, `created` and nonce.
- The benchmark (`npm run bench`) now also measures the per-curve
  JWK export/import round trip: for each of P-256, P-384, P-521 and
  RSA (2048-bit, the library default; its JWK is shared by both RSA
  algorithms), one freshly generated public key (generated outside
  timing) is exported with `exportPublicKeyJwk*`, pushed through a
  JSON stringify/parse round trip, and re-imported with
  `importPublicKeyJwk*` on every measured call. Self-checks outside
  timing require the re-imported key's SPKI DER — produced by
  node:crypto directly, independently of the JWK helpers — to equal
  the original's byte-for-byte. The bench performs zero network I/O.
  The README Benchmarks table was refreshed wholesale from one real
  run and now carries the four `roundtrip` rows.
- The CLI demo (`npm run demo`) now closes with a JWKS key-resolution
  segment: a `JwksKeyStore` is restored offline from a v1 snapshot
  carrying only the demo key's public JWK (`fetchedAtSec` and the
  store clock are pinned to the demo's fixed instants, and the
  configured `fetchImpl` throws if it is ever called, so the segment
  performs zero network I/O), the demo's signed request verifies
  through `keyResolver: (kid) => store.resolve(kid)`, and a request
  signed under an unknown `keyid` is rejected with
  `KEY_RESOLUTION_FAILED`, showing the production gateway
  key-discovery path the earlier segments bypassed by passing a key
  directly.

- The benchmark (`npm run bench`) now also measures the
  `fromNodeRequest` inbound-normalization path: a fixed mock
  `IncomingRequestLike` (seven header entries including a multi-value
  header and an `undefined` entry, trailers in both Node forms, the
  shared 31-byte body) is normalized on every measured call, with
  self-checks outside timing pinning the result field by field
  against a hand-written expected `RequestLike`, the
  parsed-trailers-object form, `rawTrailers` precedence, and the
  no-trailers shape. No real server is started; the bench performs
  zero network I/O. The README Benchmarks table was refreshed
  wholesale from one real run and now carries the `normalize` row.
- The CLI demo (`npm run demo`) now closes with a replay-protection
  segment: the demo's signed request is verified twice against an
  opt-in `ReplayCache` (fixed injected clock, capacity 100, TTL
  3600s) — the first presentation passes, the identical second
  presentation is rejected with `NONCE_REPLAY` — and a request
  signed with a different nonce still verifies, showing that the
  cache rejects repeats, not new nonces.
- The benchmark (`npm run bench`) now also measures the
  `ecdsa-p521-sha512` sign/verify path: the algorithm loop gains the
  P-521 member with the same fixture caliber as the existing
  P-256 / P-384 paths (one fresh `generateP521KeyPair()` pair per
  scenario, outside the timed loops; signatures are the raw r‖s
  form, 132 bytes total), closing the drift left when the algorithm
  itself landed. The README Benchmarks table was refreshed
  wholesale from one real run and now carries the two P-521 rows.
- The benchmark (`npm run bench`) now also measures the
  `ecdsa-p384-sha384` sign/verify path: the algorithm loop gains the
  P-384 member with the same fixture caliber as the existing P-256
  path (one fresh `generateP384KeyPair()` pair per scenario, outside
  the timed loops), closing the drift between the implemented
  algorithm list and the benchmark loop. The README Benchmarks table
  was refreshed wholesale from one real run and now carries the two
  P-384 rows.
- `ecdsa-p521-sha512` signature algorithm (RFC 9421 §3.3.6): NIST
  P-521 with SHA-512, signatures in the raw r‖s form with each integer
  padded to 66 octets (132 octets total) — the highest-strength tier of
  the existing ECDSA support, with the three EC limb widths (32 / 48 /
  66 octets) pinned separately on both sides so a signature from one
  curve never verifies as another's. Includes `generateP521KeyPair()`,
  the `exportPublicKeyJwkP521` / `importPublicKeyJwkP521` JWK helpers
  (`crv: "P-521"`, private material refused, P-256 / P-384 JWKs
  refused), and a `secp521r1` → `ecdsa-p521-sha512` mapping under
  `algFallback: "infer"`. With this, every signature algorithm RFC 9421
  registers is implemented; the unsupported-algorithm tests now pin
  `ed448` (not registered in RFC 9421) instead.
- The benchmark (`npm run bench`) now also measures the
  `jwkThumbprint` key-derivation path: one measured call derives the
  RFC 7638 thumbprint of each of the three exported public JWK shapes
  (ed25519 / P-256 / RSA) over a fixed fixture whose keys come from
  RFC 8032 §7.1, the P-256 generator point, and the RFC 7638 §3.1
  example. Self-checks outside timing pin every shape to an
  independently computed expected thumbprint — the RSA one is the
  value published in RFC 7638 §3.1.
- The CLI demo (`npm run demo`) now also shows the multi-party
  payments flow: after the single-signature script, a payment gateway
  appends a second signature with `addSignature` (label `gateway`,
  hmac-sha256 under a labelled demo-only secret, additionally covering
  `content-type`), the merged `Signature-Input` / `Signature` headers
  are printed, and `verifyAllLabels` verifies both labels. Tampering
  `content-type` then fails only the gateway label
  (`SIGNATURE_MISMATCH`) while the merchant `sig1` label still
  verifies.
- `ecdsa-p384-sha384` signature algorithm (RFC 9421 §3.3.5): NIST
  P-384 with SHA-384, signatures in the raw r‖s form with each integer
  padded to 48 octets (96 octets total) — the P-384 twin of the
  existing `ecdsa-p256-sha256` support, with the two limb widths pinned
  separately on both sides so a signature from one curve never verifies
  as the other. Includes `generateP384KeyPair()`, the
  `exportPublicKeyJwkP384` / `importPublicKeyJwkP384` JWK helpers
  (`crv: "P-384"`, private material refused, P-256 JWKs refused), and a
  `secp384r1` → `ecdsa-p384-sha384` mapping under
  `algFallback: "infer"`.
- `jwkThumbprint(jwk)`: the RFC 7638 JWK Thumbprint (SHA-256 over the
  lexicographic canonical JSON of the required members only, base64url)
  for the three public JWK shapes this library exports (OKP, EC, RSA),
  so both sides of a JWKS distribution derive the same stable `keyid`
  for the same key. Extra members (`kid`/`alg`/`use`) are ignored;
  private JWKs (`"d"` present), missing/empty required members, and
  unsupported `kty` values throw. Verified against the RFC 7638 §3.1
  official example, whose published thumbprint is reproduced exactly.
- RFC 9421 Appendix B.2.2 official test vector (rsa-pss-sha512,
  selective coverage): the published signature base — covering only
  `@authority`, `content-digest`, and `@query-param;name="Pet"`,
  with `created`/`keyid`/`tag` parameters — matches byte-for-byte,
  the published 256-octet signature verifies with node:crypto alone
  under RSASSA-PSS (SHA-512, MGF1-SHA-512, 64-byte salt), and it
  verifies end-to-end through `verifyRequest` (via
  `algFallback: "infer"`, since the vector carries no `alg`
  parameter), returning the tag. The selective-coverage boundary is
  pinned: tampering a covered component fails, changing uncovered
  components still verifies.
- RFC 9421 Appendix B.2.1 official test vector (rsa-pss-sha512,
  minimal coverage): the published signature base — a single
  `@signature-params` line over an empty covered-components list with
  `created`/`keyid`/`nonce` — matches byte-for-byte, the published
  256-octet signature verifies with node:crypto alone under
  RSASSA-PSS (SHA-512, MGF1-SHA-512, 64-byte salt), and it verifies
  end-to-end through `verifyRequest` (via `algFallback: "infer"`,
  since the vector carries no `alg` parameter), returning the nonce.
- RFC 9421 Appendix B.2.3 official test vector (rsa-pss-sha512, full
  coverage): the published signature base matches byte-for-byte, the
  published 256-octet signature verifies with node:crypto alone under
  RSASSA-PSS (SHA-512, MGF1-SHA-512, 64-byte salt), and it verifies
  end-to-end through `verifyRequest` (via `algFallback: "infer"`,
  since the vector carries no `alg` parameter).
- `JwksKeyStore.stats()` observability: detached `{ refreshes,
  refreshFailures, hits, misses }` counters for the store's lifetime —
  refreshes counted once per actual fetch (single-flight merges count
  once), every `resolve()` counted as one hit or miss, and snapshot
  export/restore does not reset the counts.
- The benchmark now also measures the key-resolution hot path:
  `JwksKeyStore.resolve` hits on an offline-restored store (zero
  network), and `memoizeKeyResolver` cache hits and misses (unknown
  keyids, which are never cached), with self-checks on the underlying
  resolver call counts.
- The benchmark now also measures the malformed-input rejection path:
  `verifyRequest` rotating over a 566-case corpus of malformed
  `signature-input` / `signature` values, generated deterministically
  with the parser fuzz test's fixed-seed approach and self-checked to
  always return `{ ok: false, code }` and never throw.
- `fromNodeRequest` now populates `RequestLike.trailers` from a Node
  `IncomingMessage` (`rawTrailers` when present, else `trailers`;
  names lowercased, multi-values joined like headers), so RFC 9421
  `;tr` covered components verify on a real server. Messages without
  trailers produce no `trailers` field, as before.
- The `@request-target` derived component (RFC 9421 §2.2.5): the
  request target in origin form — the path plus, when present, `?`
  and the query — reconstructed from `RequestLike.url` as
  `pathname + search`, so it never contains the scheme or authority
  and a URL fragment never participates. Because `RequestLike` only
  carries an absolute URL, the absolute-form, authority-form, and
  asterisk-form request targets of §2.2.5 cannot be represented and
  are not produced.
- A `package.json` `exports` map for the package root, pointing at
  the built `dist/src` entry with `types`, `import`, and `default`
  conditions (alongside the existing `main` field).
- The benchmark now also measures the replay-detection hot path:
  `ReplayCache.check` hits against a cache prefilled with 1,000
  nonces under a deterministic fake clock (zero network), rotating
  over the whole prefilled set so the LRU recency refresh is
  exercised across entries, with self-checks on the stats counters.

### Changed

- **Breaking:** `ecdsa-p256-sha256` now uses the signature encoding
  RFC 9421 §3.3.4 actually defines — the raw concatenation of r and s,
  each padded to 32 octets (64 octets total, via node:crypto's
  `dsaEncoding: "ieee-p1363"`) — instead of DER. Signatures this
  library mints are now interoperable with spec-conformant peers, and
  the official Appendix B.2.4 vector verifies end-to-end. DER-encoded
  ECDSA signatures minted by earlier versions of this library are no
  longer accepted, and there is deliberately no DER fallback: this is
  a demo, and silently accepting two encodings would hide exactly the
  interop bug this fix removes.
- `JwksKeyStore` refreshes are now single-flight: concurrent
  `refresh()` / stale `refreshIfStale()` calls share one in-flight
  fetch and its atomic snapshot replacement instead of each fetching;
  a settled refresh is never reused and a failure is never cached.

### Tests

- Independent RFC 9421 Appendix vectors added: B.2.6 (ed25519) and
  B.2.4 (ecdsa-p256-sha256) both verify end-to-end (B.2.4 after the
  §3.3.4 encoding fix below; its signature base also reproduces
  byte-for-byte).
- The sha-256 `Content-Digest` path is cross-checked against values
  produced outside this library: hardcoded vectors derived with
  OpenSSL (`openssl dgst -sha256`) plus the published RFC 9530
  Appendix D value for `{"hello": "world"}`. A live OpenSSL
  re-check runs when an `openssl` binary is available and is
  explicitly skipped — never silently passed — when it is not.
- A test executes the README Quickstart's first TypeScript block
  against the built entry point, so a renamed export, a changed
  sign/verify signature, or a stale import path in the first code a
  new reader runs fails the suite. The later Quickstart fragments
  are illustrative snippets and are not executed.
- The parser fuzz timing assertions are de-flaked: the per-call
  50ms wall-clock budget (which failed once at 52.2ms under a
  parallel full-suite run for sub-millisecond work) is now asserted
  on the corpus median against the same 50ms budget, plus a 1000ms
  catastrophic single-case bound, so a systematic slowdown still
  fails while scheduler/GC pauses no longer do.

### Documentation

- `CONTRIBUTING.md`: setup, the honesty hard rules contributions
  are held to, and the pre-submit checks.
- Corrected the `SECURITY.md` content-digest signing claim: body
  binding signs with `sha-512` by default, or `sha-256` when
  `SignOptions.contentDigestAlg` is set to `"sha-256"` (the earlier
  text said signing emitted `sha-512` only).
- Corrected the `package.json` description and keywords to match
  the supported algorithms: the description now lists all six
  (`ed25519`, `hmac-sha256`, `hmac-sha512`, `ecdsa-p256-sha256`,
  `rsa-pss-sha512`, `rsa-v1_5-sha256`) instead of only the first
  two.
- A README "FAQ (honest)" section collecting the positioning
  answers previously scattered across Limitations,
  Interoperability, and SECURITY.md: production use, subset scope,
  third-party interop status, Content-Digest algorithm preference,
  JWKS network behavior, replay limits, and key management. It
  restates existing documented facts only and adds no new claims.

## [0.1.0]

The only version declared in `package.json`. Entries cover the commit
history from the initial commit (2026-10-02) through 2026-10-11.

### Added

- RFC 9421 HTTP message signing and verification demo (ed25519 and
  hmac-sha256), with RFC 9530 `Content-Digest` body binding.
- Typed verification errors with stable failure codes, a configurable
  expiry grace period (`expiredToleranceSec`), and `requireCreated` /
  `requireExpires` / `maxSignatureAgeSec` verification options.
- Replay protection: `nonce` signature parameter support, a secure
  `generateNonce()` helper, `VerifyOptions.requireNonce`, a pluggable
  `NonceStore` interface with an in-memory `ReplayCache` implementation
  (including observability counters and snapshot export/restore for
  restart persistence).
- Multi-signature support: `addSignature` for appending a second party's
  signature, and `verifyAllLabels` batch verification returning per-label
  results (with per-label key resolvers and per-label keyid pinning) so
  one bad label does not block the others.
- Key handling: `expectedKeyId` keyid pinning, a keyid-to-key resolver,
  `memoizeKeyResolver` with TTL caching and an LRU `maxEntries` bound,
  JWK public-key import/export (ed25519, P-256, and RSA per RFC 7518
  §6.3), and a `JwksKeyStore` for JWKS network key discovery with
  `refreshIfStale()` and snapshot export/restore.
- Additional signature algorithms: ecdsa-p256-sha256, rsa-pss-sha512,
  hmac-sha512, and rsa-v1_5-sha256, plus an opt-in `algFallback: "infer"`
  mode for a missing `alg` parameter, and enforcement of a minimum
  32-byte HMAC secret length.
- RFC 9421 component coverage: `@query`, `@status`, and `@query-param`
  (with `;name`) derived components, and the `;req`, `;sf`, `;bs`,
  `;key`, and `;tr` component parameters; `requiredComponents`
  enforcement of covered components; the `tag` signature parameter with
  `expectedTag` pinning; optional `keyId` in `signRequest`.
- Content-Digest options: `SignOptions.contentDigestAlg` emitting a
  sha-256 digest, and accepting sha-256 as a fallback when no sha-512
  digest is present.
- A Node `http` request adapter for webhook receivers, a benchmark
  script (`npm run bench`) measuring real sign/verify throughput, and
  a CLI demo (`npm run demo`) showing a sign/verify round-trip with
  tamper rejection.

### Fixed

- Reject signatures whose `expires` precedes `created`, duplicate
  signature-input parameters, empty-string nonces, and signature labels
  that are not valid RFC 9421 tokens.
- Unify multi-value header whitespace normalization, and preserve the
  response status through `addSignature`.
- Fail fast on invalid `signRequest` configuration instead of producing
  an unverifiable signature.
- Correct the package entry points and README quickstart imports, which
  pointed at a nonexistent `dist/index.js`.

### Tests

- Negative verification cases (clock skew, missing covered header, wrong
  HMAC key, unsupported algorithm, sha-512 body binding) and
  content-digest edge cases (multiple digest algorithms, tampered
  digest header, digest/body mismatch).
- An independent RFC 9421 Appendix B.2.5 interop golden vector, and a
  parser fuzz suite for the signature-input/signature parsers.

### Documentation

- An honest interoperability status section and `SECURITY.md` describing
  the demo scope and which assumptions do not carry to production.
- Corrections to stale README and `SECURITY.md` claims (algorithm
  coverage, `verifyAllLabels`, key resolver, parser fuzz, test counts,
  and the `MISSING_CONTENT_DIGEST` error description).

### CI and packaging

- GitHub Actions workflows running the test suite on push and pull
  requests (Node 20/22), and publishing to GitHub Packages as
  `@toniadreal/rfc9421-signing-demo` on Node 22.
- An MIT `LICENSE` file.
