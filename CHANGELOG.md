# Changelog

All notable changes to this project are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and the version below is the version declared in `package.json`. Every entry
summarizes one or more commits in this repository's `git log`, grouped by
change type; no entry describes a feature that is not in the history.

## [Unreleased]

### Added

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
- `fromNodeRequest` now populates `RequestLike.trailers` from a Node
  `IncomingMessage` (`rawTrailers` when present, else `trailers`;
  names lowercased, multi-values joined like headers), so RFC 9421
  `;tr` covered components verify on a real server. Messages without
  trailers produce no `trailers` field, as before.

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
