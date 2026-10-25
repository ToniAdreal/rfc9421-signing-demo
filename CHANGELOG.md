# Changelog

All notable changes to this project are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and the version below is the version declared in `package.json`. Every entry
summarizes one or more commits in this repository's `git log`, grouped by
change type; no entry describes a feature that is not in the history.

## [Unreleased]

### Added

- The CLI demo (`npm run demo`) gains a per-label nonce
  requirement segment: a dual-label request carries a merchant
  signature that must carry a nonce and a gateway signature that
  historically carries none, verified with
  `requireNonceByLabel: { merchant: true }` and the global
  `requireNonce` unset — the nonce-less merchant label is
  rejected with `MISSING_NONCE`, the unmapped gateway label
  falls back to the unset global and verifies, and the same
  merchant signature re-signed with a nonce verifies alongside
  it. The segment asserts every outcome, label, code, reason and
  reported nonce against hand-pinned expectations, so a broken
  fixture fails the demo with a non-zero exit.
- The CLI demo (`npm run demo`) gains a JWKS requireHttps segment:
  a real loopback `http` server serves the scripted key's JWKS
  document, and a `JwksKeyStore` built over that plaintext endpoint
  with `requireHttps: true` is rejected at construction with the
  pinned configuration error before any fetch is attempted (the
  loopback server records zero requests). A store over an `https:`
  endpoint URL with the same option constructs cleanly — the
  construction check passes for `https:`, and no fetch is attempted
  at construction, so no local TLS fixture is faked. A store over
  the same loopback endpoint with the option off refreshes, resolves
  the scripted keyid, and records exactly one fetch. The segment
  asserts every outcome against hand-pinned expectations, so a
  broken fixture fails the demo with a non-zero exit.
- The CLI demo (`npm run demo`) gains a required-tag segment: the
  same request signed with no tag is rejected with `MISSING_TAG`
  under `requireTag: true` and verifies with the option unset, and
  the same request signed with a tag verifies under the option —
  the presence counterpart to the application-tag segment's
  `expectedTag` value pin, with `requireTagByLabel` as the
  per-label form. The segment asserts every outcome, code,
  reason and reported tag against hand-pinned expectations, so a
  broken fixture fails the demo with a non-zero exit.
- `verifyAllLabels` accepts a `requireTagByLabel` map: a label in the
  map is checked against its own `requireTag` boolean, any other label
  falls back to the global `requireTag` (unset means no existence
  check for it). A missing tag reuses the global `MISSING_TAG` code —
  no new code is introduced — and the check position is the same as
  the global one (after the cryptographic check, before the window
  checks), so forgeries still report `SIGNATURE_MISMATCH`. A
  non-boolean map value is a caller configuration error (throw), and
  the map never joins the key-selection mutual-exclusion rules. It is
  orthogonal to `requireNonceByLabel`: each map drives only its own
  existence check, so a merchant signature that must carry a tag and
  a gateway signature that historically carries none can be verified
  in one call with independent per-label verdicts.
- The benchmark (`npm run bench`) now also measures
  `fromNodeResponse` + `verifyRequest` over a loopback-signed
  gateway settlement response: a real `http` server on loopback
  (no external network) signs a 200 response covering `@status`,
  the bound request's `@method` (`;req`), and a settlement
  trailer (`;tr`), and the measured op adapts that live response
  and verifies it with `@status` required, re-pinning the
  adapted status (200), the carried-over trailer, and a
  successful verification on every pass. The timed loop
  re-measures only the client-side adapt + verify work over the
  one captured response — re-measuring the network per
  iteration would time TCP loopback, not the adapter. Outside
  timing, a missing `statusCode` fails fast with the adapter's
  pinned message and transplanting the response onto a request
  with a different method breaks the `;req` binding with a pinned
  `SIGNATURE_MISMATCH`. On this run the new row measured
  ~3,590 ops/sec (278.58 µs/op). The README Benchmarks table
  was refreshed in full from this run (73 rows, 2026-10-25).

- `verifyAllLabels` accepts a per-label nonce-existence map
  `requireNonceByLabel`: a label in the map is checked against its
  own boolean, any other label falls back to the global `requireNonce`
  (unset means no existence check for it), and a mapped value overrides
  the global flag in both directions. A missing nonce reuses the global
  error code (`MISSING_NONCE`); no new code, and the check position
  matches the global one (after the cryptographic check, before the
  replay cache), so forgeries still report `SIGNATURE_MISMATCH` and a
  nonce-less label never reaches the cache. A non-boolean map value is
  a caller configuration error naming the label, and like the freshness
  requirements an existence requirement never joins the key-selection
  mutual-exclusion rules. The map only overrides the existence
  requirement: the replay cache stays shared across labels (one nonce
  per label). 12 new tests in `test/requireNonceByLabel.test.ts`.

- `SignedHttpRequest` echoes `coveredComponents`: exactly the list
  `signRequest` wrote into `signature-input` (the explicit option, or
  the default set when omitted), in signature order, as a detached
  copy — the sign-side mirror of `VerifyResult.coveredComponents`, so
  the two sides compare item for item without a second header parse.
  `addSignature` echoes the appended signature's own list, not a merge
  with the first signature's. 11 new tests in
  `test/signedCoveredComponents.test.ts`.

- The CLI demo gains a JWKS fetch retries segment: a `JwksKeyStore`
  with `fetchRetries: 2` over a counting fake fetch scripted 500, 500,
  200 succeeds on the third attempt with two recorded sleeps and a
  one-key snapshot, while a second store with the same retry budget
  pointed at a 404 endpoint fails with the pinned HTTP 404 message
  after exactly one fetch and zero sleeps — a 4xx response is
  terminal, never retried. 2 new tests in `test/demo.test.ts`.

- `verifyAllLabels` accepts per-label freshness-existence maps
  `requireCreatedByLabel` and `requireExpiresByLabel`: a label in a map
  is checked against its own boolean, any other label falls back to
  the global `requireCreated` / `requireExpires` (unset means no
  existence check for it), and a mapped value overrides the global
  flag in both directions. Missing parameters reuse the global error
  codes (`MISSING_CREATED` / `MISSING_EXPIRES`); no new codes, and the
  check position matches the global one (after the cryptographic
  check, before the window checks), so forgeries still report
  `SIGNATURE_MISMATCH`. A non-boolean map value is a caller
  configuration error naming the label, and like the freshness window
  an existence requirement never joins the key-selection
  mutual-exclusion rules. 12 new tests in
  `test/requireFreshnessByLabel.test.ts`.

- `VerifyOptions.requireTag` (default `false`, backwards compatible):
  a signature carrying no `tag` — or an empty-string one, treated as
  missing since `signRequest` refuses to mint one — fails with the new
  error code `MISSING_TAG`. Checked alongside
  `requireCreated`/`requireExpires`, after the cryptographic check and
  before the window checks, so forgeries still report
  `SIGNATURE_MISMATCH`; in `verifyAllLabels` it applies independently
  per label, and a signature that also fails a pinned `expectedTag`
  still reports `TAG_MISMATCH`. 10 new tests in
  `test/requireTag.test.ts`.

- `VerifyResult` now carries `coveredComponents`: the covered component
  identifiers parsed from `signature-input`, in signature-input order,
  as seen on the wire — reported on every `verifyRequest` /
  `verifyWithKey` return point that already carries the wire fields
  (success and failure alike), so a webhook receiver can audit exactly
  which components a signature claimed to cover without re-parsing the
  header. Absent (`undefined`) only when the component list could not
  be parsed at all (missing or malformed `signature-input`); never
  fabricated, and always a detached copy. `verifyRequestOrThrow`
  returns the same field on success; `verifyAllLabels` reports each
  label's own list. 11 new tests in
  `test/verifyResultCoveredComponents.test.ts` (plus the updated
  `demo.test.ts` shape assertion for the throwing-verification
  segment).

- `JwksKeyStore` accepts opt-in fetch retries: `fetchRetries`
  (default `0`, single attempt as before), `fetchBackoffMs` (default
  `1000`, fixed delay between attempts), and `sleepImpl` (default
  `setTimeout`-based, injectable so tests can record delays without
  waiting). Only transient failures are retried — network errors and
  HTTP 5xx; a 4xx response, a malformed JWKS document, and a
  `fetchTimeoutMs` abort are terminal, and on exhaustion `refresh()`
  throws the last attempt's error unchanged. The previous snapshot
  and `lastRefreshedAt` stay untouched until an attempt fully
  succeeds, and `stats()` counts one `refresh()` call once however
  many attempts it made. 9 new tests in
  `test/jwksFetchRetry.test.ts`.

- `verifyAllLabels` accepts a per-label freshness-window map
  `maxSignatureAgeSecByLabel`: a label in the map is checked against
  its own window, any other label falls back to the global
  `maxSignatureAgeSec` (unset means no age check for it) — so a
  merchant signature with a short window and a gateway signature with
  a long one can share one request. Each value is validated per label
  with the global window's rules (non-negative finite number, else a
  configuration error naming the label); a window is not key
  selection, so it never joins the `keys`/`keyResolver`/`candidateKeys`
  mutual-exclusion rules. 9 new tests in
  `test/maxSignatureAgeSecByLabel.test.ts`.

- `VerifyResult` now carries the wire timestamps `created` / `expires`
  (Unix seconds, `undefined` when the signer omitted them), in the same
  "as seen on the wire" spirit as `nonce` / `tag`: every `verifyRequest`
  and `verifyWithKey` return point (success and failure alike) reports
  the parsed values, so a webhook receiver can log the claimed signing
  instant or run a custom age window without re-parsing
  `signature-input`. A tampered timestamp is reported as tampered
  (`SIGNATURE_MISMATCH` with the tampered value), because the failure is
  about authenticity, not about what was sent. `verifyRequestOrThrow`
  returns the same two fields on success and carries them on the thrown
  `VerifyError`; `verifyAllLabels` reports each label's own pair.
  12 new tests in `test/verifyResultTimestamps.test.ts` (plus the
  updated `demo.test.ts` shape assertion for the throwing-verification
  segment).

- `JwksKeyStore` accepts an opt-in `requireHttps: true`: a plaintext `http:`
  endpoint URL is then rejected at construction with
  `JwksKeyStore: \`requireHttps\` requires https: for the JWKS endpoint,
  got "http:"` — before any fetch is attempted (proved by a counting
  `fetchImpl` that sees zero calls). Whatever the endpoint serves becomes
  a verification key, and over plaintext a path attacker could substitute
  the entire key set, so this is the production posture when the endpoint
  is on the public internet. Non-boolean values throw a configuration
  error; `http:` stays allowed by default (loopback development, tests),
  and the check is construction-time only — it does not intercept a fetch
  that is later redirected from https to http (documented honestly on the
  option, in the README JWKS section and in SECURITY.md). Check order is
  URL validity → protocol whitelist → https enforcement. 8 new tests in
  `test/jwksHttps.test.ts`.

- CLI demo closes with a signed-response segment: a real loopback `http`
  server plays the payment gateway, signing its settlement response's
  `@status` with a gateway ed25519 key, and the client's `http.get`
  callback buffers the body, normalizes the response with
  `fromNodeResponse(res, body, { request })` and verifies with
  `requiredComponents: ["@status"]` — the client-side mirror of the
  inbound `fromNodeRequest` demo. A second pass flips the adapted status
  200 -> 500 (the way a downgraded settlement would look on the wire)
  and is rejected with `SIGNATURE_MISMATCH`. All outcomes are asserted
  outside the printed lines against hand-pinned constants; only the
  loopback port (never printed) and the key pair are fresh per run, so
  the segment's printed lines are byte-identical between runs.

- `JwksKeyStore` accepts an opt-in `fetchTimeoutMs` (positive integer,
  milliseconds): the default fetch is performed as
  `globalThis.fetch(url, { signal })` with an `AbortController` that
  aborts at the deadline, so a hung JWKS endpoint can no longer leave
  `refresh()` unsettled forever (and stall every waiter merged by the
  single-flight mechanism — key rotation is the path that must keep
  working during an outage). On expiry `refresh()` throws
  `JwksKeyStore: JWKS fetch timed out after Nms`; the previous snapshot
  and `lastRefreshedAt` are untouched (fail-closed) and the failure is
  counted in `stats().refreshFailures`. Non-integer/zero/negative/NaN
  values throw at construction. The timeout applies to the default
  fetch only — a custom `fetchImpl` never receives an abort signal and
  must implement its own timeout if it needs one (documented honestly
  on the option and in the README JWKS section). Unset by default, so
  no configuration change is zero behavior change.

- `JwksKeyStore` now imports NIST P-384 and P-521 JWKs: the EC branch of
  JWKS/snapshot import dispatches by `crv` (`P-256` / `P-384` / `P-521`,
  via the pre-existing `importPublicKeyJwkP384` / `importPublicKeyJwkP521`
  helpers), so a gateway publishing `ecdsa-p384-sha384` /
  `ecdsa-p521-sha512` keys no longer makes `refresh()` throw. Unsupported
  or missing `crv` values fail `refresh()` with an explicit
  `unsupported EC crv ...` error and leave the previous snapshot
  untouched. `exportSnapshot()` likewise dispatches EC keys by their
  node:crypto named curve (`prime256v1` / `secp384r1` / `secp521r1`), so
  fetched P-384/P-521 keys survive a snapshot round-trip (previously
  export of a store holding them threw); snapshots carrying them restore
  back onto the right importers. The class JSDoc and README JWKS
  sections now document the five supported JWK shapes.

- `verifyAllLabels` now accepts a per-label `candidateKeysByLabel` map
  (label→`KeyObject[]`) for multi-party key rotation: the merchant and
  the payment gateway rotate their webhook HMAC secrets on independent
  schedules, so each label gets its own ordered rotation list, tried in
  order with the same first-full-pass semantics as the global
  `candidateKeys`. A label missing from the map falls back to the global
  `candidateKeys`; a per-label list is never tried against another
  label, so a merchant candidate cannot widen the gateway's rotation
  surface. Each list is validated per label with the same rules as the
  global option (non-empty array of KeyObjects; a malformed map or list
  throws a configuration error naming the label), and it is mutually
  exclusive with that label's `key`/`keys` and
  `keyResolver`/`keyResolvers` — combining them throws. The README
  multi-label and key-rotation sections document the pattern with a
  merchant-fixed-key + gateway-mid-rollover example.

- The benchmark (`npm run bench`) now also measures
  `verifyRequest` with `requiredComponents` — the
  component-coverage policy form a receiver runs to refuse a
  cryptographically valid signature that covers none of the
  components it needs (a payment-gateway verifier typically
  wants `content-digest` and `@path` covered), which the
  existing verify rows never timed (they pass no requirement,
  so the pre-cryptographic coverage check was never a
  measured cost). One measured op verifies a pinned ed25519
  fixture (signed outside timing with `coveredComponents`
  `@method`, `@path`, `content-digest`) with exactly those
  three components required and re-pins that the result is
  ok — the measured steady state is the accepting path.
  Outside timing the rejecting and boundary halves are
  asserted once: one missing required component returns
  exactly the pinned `MISSING_REQUIRED_COMPONENT` code with
  the pinned singular-form reason, two missing give the
  pinned plural-form reason, case-mismatched requirement
  names (`Content-Digest`, `@PATH`) still match, the same
  fixture verifies with the option unset (the check is
  opt-in and the default is unchanged), and an empty-string
  entry throws the pinned configuration error. The README
  Benchmarks table was refreshed wholesale from one real
  run and now carries the `verifyRequest requiredComponents`
  row (~4,321 ops/sec on this run).

- The benchmark (`npm run bench`) now also measures
  `verifyRequest` with `replayCache` — the replay-defense
  verify form a receiver uses to refuse an already-seen
  request (nonce replay protection), which the existing
  verify rows never timed (they pass no cache, so the
  post-cryptographic cache consultation was never a
  measured cost). One measured op verifies a pinned
  ed25519 fixture (signed outside timing with `created`
  and `nonce` pinned) twice against a fresh
  `ReplayCache` sharing the verifier's injected clock:
  the first verify records the nonce and is ok, the
  second is rejected with exactly the pinned
  `NONCE_REPLAY` code and reason — the measured steady
  state is the replay-rejecting path. Outside timing
  the bypassing and non-polluting halves are asserted:
  the same fixture verifies twice without a cache, a
  nonce-less signature verifies twice under a cache
  (nonce-less signatures bypass the cache entirely),
  and a forged signature (tampered bytes) returns
  `SIGNATURE_MISMATCH` without polluting the cache —
  the cryptographic check runs before the cache
  consultation. The README Benchmarks table was
  refreshed wholesale from one real run and now carries
  the `verifyRequest replayCache` row.
- The benchmark (`npm run bench`) now also measures
  `verifyRequest` with `requireCreated` — the
  created-presence verify form a receiver uses to refuse
  signatures with no bounded age, which the existing
  verify rows never timed (they set no requirement, so
  the post-cryptographic `created === undefined`
  presence check was never a measured cost). The fixture
  is a hand-built no-`created` ed25519 signature minted
  outside timing with `buildSignatureBase` +
  `signatureInputValue` + a raw ed25519 sign (the shape
  `test/requireFreshness.test.ts` uses, because
  `signRequest` always emits `created`); every measured
  pass re-pins that the result is exactly
  `MISSING_CREATED` with the pinned reason — the
  measured steady state is the rejecting path. The
  same signature's acceptance without the option, a
  dated fixture's acceptance under the requirement,
  and a forged (tampered signature bytes) no-`created`
  signature's `SIGNATURE_MISMATCH` result (the
  cryptographic check runs before the presence check)
  are asserted outside timing. The README Benchmarks
  table was refreshed wholesale from one real run and
  now carries the `verifyRequest requireCreated` row.
- The benchmark (`npm run bench`) now also measures
  `verifyRequest` with `expectedTag` — the
  application-tag-pinning verify form a receiver uses
  for cross-protocol replay protection (RFC 9421
  §2.3), which the existing verify rows never timed
  (they set no expectation, so the post-cryptographic
  `tag === expectedTag` comparison was never a
  measured cost). The fixture is one ed25519 signature
  minted outside timing with `created` pinned and
  `tag` pinned to `"payment-webhook-v1"`, verified
  with the matching `expectedTag` at an injected
  `now` equal to `created`; every measured pass
  re-pins that the result is ok and the returned
  `tag` equals the pinned value. The same signature
  under a different `expectedTag`, a fixture signed
  with no `tag` at all (`got no tag` reason shape),
  and the unchanged default behaviour without the
  option are asserted outside timing with pinned
  `TAG_MISMATCH` codes and reasons. The README
  Benchmarks table was refreshed wholesale from one
  real run and now carries the `verifyRequest
  expectedTag` row.
- The CLI demo (`npm run demo`) now closes with a
  per-label key resolver segment: two fresh ed25519
  key pairs mint a dual-label fixture (`merchant` via
  `signRequest`, `gateway` appended via
  `addSignature`), showing `verifyAllLabels`'
  `keyResolvers` option — both labels verify through
  their own keystore resolvers, the gateway label
  alone is rejected with `KEY_RESOLUTION_FAILED` and
  its pinned reason when its resolver returns
  `undefined` (its key id rotated out of the gateway
  keystore) while the merchant label still verifies,
  a label missing from the map falls back to the
  global `keyResolver`, and a non-function map value
  throws the pinned configuration error before any
  verification runs. `DemoResult` gains the segment's
  dual-signed request, three per-label result arrays
  and the thrown configuration error, and the demo
  tests gain two cases pinning the segment
  end-to-end (750 tests in total). Every fixture is
  fixed — injected clock, no network, no randomness
  in the printed lines.
- The CLI demo (`npm run demo`) now closes with a
  per-label keyid pinning segment: two fresh ed25519
  key pairs mint a dual-label fixture (`merchant` via
  `signRequest`, `gateway` appended via
  `addSignature`), showing `verifyAllLabels`'
  `expectedKeyIds` option — both labels verify under
  a fully matching map, the gateway label alone is
  rejected with `KEYID_MISMATCH` and its pinned
  reason under a wrong per-label pin while the
  merchant label still verifies, a label missing
  from the map falls back to the global
  `expectedKeyId` (the matching fallback verifying
  both labels, the empty-map fallback failing the
  gateway label against the merchant global pin),
  and an empty-string map value throws the pinned
  configuration error before any verification runs.
  `DemoResult` gains the segment's dual-signed
  request, four per-label result arrays and the
  thrown configuration error, and the demo tests
  gain two cases pinning the segment end-to-end
  (748 tests in total). Every fixture is fixed —
  injected clock, no network, no randomness in the
  printed lines.
- The benchmark (`npm run bench`) now also measures
  `verifyRequest` with `algFallback: "infer"` — the
  algorithm-inference verify form a receiver uses for
  foreign signers that omit the optional `alg`
  parameter, which the existing verify rows never
  timed (their fixtures always carry `alg` on the
  wire). The fixture is the RFC 9421 Appendix B.2.5
  wire value verbatim (no `alg` parameter) verified
  against its pinned shared secret at an injected
  `now` equal to the vector's `created` instant.
  Every measured pass re-pins that the result is ok
  and that the inferred `alg` and the returned
  `keyId` equal their pinned values. The same wire's
  `VERIFICATION_ERROR` result without the opt-in, a
  wire `alg` contradicting the key's shape throwing
  the pinned configuration error, and a secp256k1 key
  shape with no supported mapping throwing the
  pinned cannot-infer configuration error are
  asserted outside timing. The README Benchmarks
  table was refreshed wholesale from one real run
  and now carries the `verifyRequest algFallback
  (infer)` row.
- The benchmark (`npm run bench`) now also measures
  `verifyRequest` with `expiredToleranceSec` — the
  expiry-grace verify form a receiver uses to accept a
  signature that expired moments ago, which the
  existing verify rows never timed (they rely on the
  default zero grace against fixtures that have not
  expired). The fixture is an ed25519 request signed
  outside timing with `created` pinned one hour before
  and `expires` pinned 30 seconds before the
  verifier's injected `now`, verified under a
  120-second grace. Every measured pass re-pins that
  the result is ok. The narrow-grace `EXPIRED` result
  (pinned code and reason), the acceptance exactly at
  the grace boundary, the rejection under the default
  zero grace and a hand-built born-expired signature's
  `INVALID_TIME_WINDOW` result inside a wide grace are
  asserted outside timing. The README Benchmarks table
  was refreshed wholesale from one real run and now
  carries the `verifyRequest expiredToleranceSec
  (120s grace)` row.
- The benchmark (`npm run bench`) now also measures
  `verifyAllLabels` with `keyResolvers` — the
  per-label key-resolution verify form a multi-party
  receiver uses when each signer's keyids live in a
  separate keystore (the merchant's and the gateway's
  own resolvers), which the existing multi-label
  verify row never timed (it passes static keys, so
  the per-label resolver lookups were never a
  measured cost). The fixture is a dual-label
  ed25519 request signed outside timing with
  `created` pinned under two pinned keyids, each
  belonging to its own resolver, verified with a
  fully resolving `keyResolvers` map. Every measured
  pass re-pins that both results are ok, in wire
  order, and that each returned `keyId` equals its
  label's pinned value. The one-label unresolved
  result (exactly `KEY_RESOLUTION_FAILED` with the
  pinned reason, the other label still verifying),
  the global-`keyResolver` fallback for a label
  missing from the map, the non-function map value's
  pinned configuration error and the
  `keyResolvers`-with-`keys` mutual-exclusion
  configuration error are asserted outside timing.
  The README Benchmarks table was refreshed
  wholesale from one real run and now carries the
  `verifyAllLabels keyResolvers (2 labels)` row.
- The benchmark (`npm run bench`) now also measures
  `verifyAllLabels` with `expectedKeyIds` — the
  per-label key-id binding verify form a multi-party
  receiver uses to pin each signer's key
  independently (key-confusion defense), which the
  existing multi-label verify row never timed (it
  passes no pins, so the per-label pin resolution
  and keyid comparisons were never a measured
  cost). The fixture is a dual-label ed25519
  request signed outside timing with `created`
  pinned under two pinned keyids, verified with a
  fully matching `expectedKeyIds` map. Every
  measured pass re-pins that both results are ok,
  in wire order, and that each returned `keyId`
  equals its label's pinned value. The one-label
  mismatched-pin result (exactly `KEYID_MISMATCH`
  with the pinned reason, the other label still
  verifying), the global-`expectedKeyId` fallback
  for a label missing from the map (both the
  matching and the mismatching halves) and the
  empty-string map value's pinned configuration
  error are asserted outside timing. The README
  Benchmarks table was refreshed wholesale from
  one real run and now carries the
  `verifyAllLabels expectedKeyIds (2 labels)` row.
- The CLI demo (`npm run demo`) now closes with a
  required-nonce segment: one key pair mints a
  nonce-carrying signature via `signRequest` and two
  hand-built signatures via the public signature-base
  primitives (no nonce at all, and an empty-string
  nonce — the wire shapes a foreign signer sends),
  showing `verifyRequest`'s `requireNonce` option —
  the nonce-carrying signature verifies, both
  hand-built ones are rejected after the
  cryptographic check with `MISSING_NONCE` and its
  pinned reason (an empty-string nonce counts as
  missing), and the same nonce-less signature
  verified with no option set shows the default (no
  check is made, so the replay-cache bypass the
  option closes stays visible). `DemoResult` gains
  the segment's three signed requests and four
  verification results, and the demo tests gain two
  cases pinning the segment end-to-end (746 tests
  in total). Every fixture is fixed — no network,
  no wall clock.
- The benchmark (`npm run bench`) now also measures
  `verifyRequest` with `expectedKeyId` — the key-id
  binding verify form a receiver uses to pin the
  expected signer key (key-confusion defense), which
  the existing verify rows never timed (they pass no
  pin, so the post-cryptographic keyid comparison was
  never a measured cost). The fixture is one ed25519
  request signed outside timing with `created` pinned
  under a pinned keyid, verified with a matching
  `expectedKeyId`. Every measured pass re-pins that
  the result is ok and its returned `keyId` equals
  the pinned value. The mismatched-pin result
  (exactly `KEYID_MISMATCH` with the pinned reason),
  the hand-built no-`keyid` result (the same code
  with the `got no keyid` reason shape) and that same
  signature's acceptance without the option are
  asserted outside timing. The README Benchmarks
  table was refreshed wholesale from one real run and
  now carries the `verifyRequest expectedKeyId` row.
- The benchmark (`npm run bench`) now also measures
  `verifyRequest` with `clockSkewToleranceSec` — the
  clock-skew verify form a receiver uses to tolerate a
  signer whose clock runs ahead, which the existing
  verify rows never timed (they rely on the 60-second
  default against fixtures that are not dated in the
  future, so a caller-pinned future-`created` window
  was never a measured cost). The fixture is one
  ed25519 request signed outside timing with `created`
  pinned 30 seconds ahead of the verifier's injected
  `now`, verified under a 120-second tolerance. Every
  measured pass re-pins that the result is ok. The
  narrow-tolerance result (exactly
  `CREATED_IN_FUTURE` with the pinned reason), the
  exact-boundary acceptance (the comparison is a
  strict `>`) and the no-option acceptance (the
  60-second default covers the 30-second skew) are
  asserted outside timing. The README Benchmarks
  table was refreshed wholesale from one real run and
  now carries the
  `verifyRequest clockSkewToleranceSec (120s)` row.
- The CLI demo (`npm run demo`) now closes with a
  required-components segment: one key pair signs the
  same fixed payment request fully covered
  (`@method`, `@path`, `content-digest`) and covering
  only `@method`, showing `verifyRequest`'s
  `requiredComponents` coverage policy — the fully
  covered signature verifies, the narrow one is
  rejected before any cryptographic work with
  `MISSING_REQUIRED_COMPONENT` and its pinned reason,
  differently-cased required names still pass, a
  malformed list containing an empty string throws
  the pinned configuration error verbatim, and the
  narrow signature verified with no option set shows
  the default (no check is made). `DemoResult` gains
  the segment's two signed requests, four verification
  results and the thrown message, and the demo tests
  gain two cases pinning the segment end-to-end (744
  tests in total). Every fixture is fixed — no
  network, no wall clock.
- The CLI demo (`npm run demo`) now closes with an
  alg-fallback segment: the RFC 9421 Appendix B.2.5
  hmac-sha256 wire value — whose signature-input carries
  no `alg` parameter — is verified against its pinned
  shared secret with `algFallback: "infer"` (the
  algorithm is inferred from the secret key's shape and
  reported as `hmac-sha256`) and without the opt-in
  (the legacy `ed25519` default fails with
  `VERIFICATION_ERROR`), and the two caller
  configuration errors print verbatim: a wire
  `alg="ed25519"` paired with a secret key, and the
  no-`alg` wire paired with a secp256k1 key whose shape
  has no supported mapping. `DemoResult` gains the
  segment's wire request, two verification results and
  the two thrown messages, and the demo tests gain two
  cases pinning the segment end-to-end (742 tests in
  total). Every fixture is fixed — no network, no wall
  clock.
- The benchmark (`npm run bench`) now also measures
  `verifyRequest` with `requireExpires` — the
  expiry-presence verify form a receiver uses to
  refuse a signature that carries no `expires` and so
  has no bounded lifetime, which the existing verify
  rows never timed (they pass no requirement, so the
  post-cryptographic presence check was never a
  measured cost). The fixture is one ed25519 request
  signed outside timing with `created` and `expires`
  both pinned, verified at an injected `now` equal to
  `created`. Every measured pass re-pins that the
  result is ok. The hand-built no-`expires` result
  (exactly `MISSING_EXPIRES` with the pinned reason)
  and that same signature's acceptance without the
  option are asserted outside timing. The README
  Benchmarks table was refreshed wholesale from one
  real run and now carries the
  `verifyRequest requireExpires` row.
- The CLI demo (`npm run demo`) now closes with an
  application-tag segment: one key pair signs the same
  fixed request with the pinned tag
  (`payment-webhook-v1`), with another protocol's tag
  (`admin-api-v1`) and with no tag, showing
  `verifyRequest`'s `expectedTag` pin — the matching
  tag verifies, the other tag and the missing tag are
  each rejected with `TAG_MISMATCH` and its pinned
  reason, and the same tagged signature verified with
  no `expectedTag` pinned shows the default (no check
  is made). `DemoResult` gains the segment's three
  signed requests and four verification results, and
  the demo tests gain two cases pinning the segment
  end-to-end (740 tests in total). Every fixture is
  fixed — no network, no wall clock.
- The CLI demo (`npm run demo`) now closes with a Node
  trailers segment: three fixed mock
  `IncomingMessage`-shaped objects show
  `fromNodeRequest`'s trailer normalization — a parsed
  `trailers` object normalized to lowercase keys with
  multi-value fields trimmed and joined, a non-empty
  `rawTrailers` winning over a stale parsed object
  (duplicate raw names merged), and a message with no
  trailers gaining no `trailers` field at all — and a
  request whose `x-checksum` trailer is bound via a
  `;tr` covered component completes a sign ->
  `fromNodeRequest` -> verify round-trip.
  `DemoResult` gains the segment's three normalized
  requests, its signed request and its verification
  result, and the demo tests gain two cases pinning
  the segment end-to-end (738 tests in total). Every
  fixture is fixed — no network, no wall clock.
- The benchmark (`npm run bench`) now also measures
  `verifyRequest` with `maxSignatureAgeSec` — the
  age-capped verify form a receiver uses to bound how
  long a signed message stays replayable when it
  carries `created` but no `expires`, which the
  existing verify rows never timed (they pass no cap,
  so the age computation and its strict `>` boundary
  check were never a measured cost). The fixture is
  one ed25519 request signed outside timing with
  `created` pinned, verified at an injected `now`
  60 seconds later under a 300-second cap. Every
  measured pass re-pins that the result is ok. The
  past-cap result (exactly `SIGNATURE_TOO_OLD` with
  the pinned reason) and the no-`created` bypass (a
  hand-built undated signature still verifies at the
  past-cap instant) are asserted outside timing. The
  README Benchmarks table was refreshed wholesale
  from one real run and now carries the
  `verifyRequest maxSignatureAgeSec (300s cap)` row.
  The bench performs zero network I/O and no
  wall-clock assertions.
- The benchmark (`npm run bench`) now also measures
  `verifyRequest` through a `keyResolver` — the
  keyid→key resolution verify form a gateway runs while
  its keys rotate by keyid, which the existing verify rows
  never timed (they all pass a static `key`, and the
  `memoizeKeyResolver` rows time the resolver cache itself
  rather than a full verification through a resolver). The
  fixture is a plain Map keystore holding two pinned
  ed25519 public keys (generated once outside timing)
  under two pinned kids, with one signed fixture request
  per kid signed outside timing with `created` pinned and
  the verifier's `now` injected at the same instant.
  Every measured pass verifies both fixtures through the
  resolver and re-pins that each result is ok and each
  returned `keyId` equals its pinned kid. The
  unknown-keyid result (exactly `KEY_RESOLUTION_FAILED`
  carrying the unknown kid and the pinned reason) and the
  `key` + `keyResolver` mutual-exclusion configuration
  error are asserted outside timing. The README
  Benchmarks table was refreshed wholesale from one real
  run and now carries the `verifyRequest keyResolver
  (2 keyids)` row. The bench performs zero network I/O
  and no wall-clock assertions.
- The benchmark (`npm run bench`) now also measures
  `JwksKeyStore.restoreSnapshot` — the snapshot-restore
  path a gateway runs at cold start to rebuild its key
  store from the persisted envelope in an existing store
  object, which the existing `exportSnapshot` row never
  timed (it measures only the serialize direction, and
  the static `restore` construction behind the `resolve`
  rows was never itself a measured op). The fixture
  envelope is a pinned three-key set (ed25519 / P-256 /
  RSA, generated once outside timing) exported outside
  timing from a source store refreshed once through a
  counting fake fetch at a pinned fetch time under a
  120-second TTL; the target store is primed through its
  own counting fake fetch with a different single key at
  the instant exactly one TTL later. Every measured pass
  restores the envelope and re-pins that the pinned kid
  resolves, that `stats()` is identical before and after
  the restore (restoring resets no counters), and that
  `isStale()` counts from the envelope's original fetch
  time — so the just-restored store is already stale at
  the boundary instant. The corrupt-envelope rejections
  (an unsupported version and an empty kid, each with its
  pinned full message) and the fail-closed
  unchanged-store assertions are asserted outside timing.
  The README Benchmarks table was refreshed wholesale
  from one real run and now carries the `restore` row.
  The bench performs zero network I/O and no wall-clock
  assertions.
- The CLI demo (`npm run demo`) now closes with a clock
  tolerance segment: a signature created 120 seconds in
  the future verifies under a wide
  `clockSkewToleranceSec` (180 seconds) and is rejected
  with `CREATED_IN_FUTURE` under a narrow one (90), while
  the no-option defaults are pinned by a 30-second-future
  signature verifying and the 120-second-future one
  failing (default skew 60); a signature 30 seconds past
  its `expires` verifies under a wide
  `expiredToleranceSec` grace (60 seconds) and is
  rejected with `EXPIRED` under a narrow grace (20),
  while a signature just 1 second past `expires` fails
  with no option passed (default grace 0 — strict).
  `DemoResult` gains the segment's three signed requests
  and seven verification results, the demo tests gain two
  cases pinning the segment end-to-end (736 tests in
  total), and every clock in the segment is injected —
  no network, no wall clock, no randomness in the
  printed lines.
- The CLI demo (`npm run demo`) now closes with a maximum
  signature age segment: one ed25519 signature pinned at
  the demo's fixed `created` instant with no `expires` is
  verified under the opt-in `maxSignatureAgeSec` cap
  (300 seconds) at three injected instants — inside the
  cap (verifies), exactly at the cap (verifies: the age
  check is a strict `>`), and one second past it
  (rejected with `SIGNATURE_TOO_OLD`) — and a hand-built
  signature carrying no `created` at all (only `expires`,
  `keyid` and `alg`) still verifies at the past-cap
  instant, because a signature with no `created` bypasses
  the age check entirely (orthogonal to
  `requireCreated`). `DemoResult` gains the segment's
  signed requests and four verification results, the demo
  tests gain two cases pinning the segment end-to-end
  (734 tests in total), and every clock in the segment is
  injected — no network, no wall clock, no randomness in
  the printed lines.
- The benchmark (`npm run bench`) now also measures
  `ReplayCache.fromSnapshot` — the snapshot-restore path a
  single-process verifier runs at startup to rebuild its
  replay cache from the persisted snapshot, which the
  existing `exportSnapshot` row never timed (it measures
  only the serialize direction). The fixture is a pinned
  envelope exported outside timing from a fixed-clock
  source cache holding four live nonces under a
  3,600-second TTL. Every measured pass restores the
  envelope, re-pins the rebuilt cache's `size` and zeroed
  `stats()` counters, and re-checks every restored nonce —
  each must still report a replay. The expired-at-restore
  drop (a clock advanced past the oldest entry's TTL drops
  exactly that entry) and the corrupt-envelope rejections
  (unsupported version, malformed entry) are asserted
  outside timing. The README Benchmarks table was
  refreshed wholesale from one real run and now carries
  the `restore` row. The bench performs zero network I/O
  and no wall-clock assertions.
- The benchmark (`npm run bench`) now also measures
  `JwksKeyStore.refresh` single-flight merging — the
  concurrent refresh path a gateway hits at cold start /
  rotation time, which the existing serial
  `refreshIfStale` row never timed. The fixture is a
  one-key store (ed25519, generated once outside timing)
  primed once and made stale by advancing its injected
  clock exactly to the 120-second TTL boundary; a counting
  fake fetch serves one pinned JWKS document and resolves
  on a microtask tick. Every measured batch launches
  eight concurrent `refresh()` calls and re-pins that the
  fetch count and `stats().refreshes` each advanced by
  exactly one and that the pinned kid resolves; a
  shared-failure batch (all eight waiters receiving the
  same rejection from exactly one fetch) and the
  failure-not-cached retry are asserted outside timing.
  The README Benchmarks table was refreshed wholesale
  from one real run and now carries the second `refresh`
  row. The bench performs zero network I/O and no
  wall-clock assertions.
- The benchmark (`npm run bench`) now also measures
  `resolveComponent` — the per-component resolution every
  sign and verify pays once per covered component — which
  the existing `buildSignatureBase` row only ever timed
  bundled with the `@signature-params` serialization.
  The fixture is a fixed eighteen-case corpus over one
  pinned request (query string, status, trailers and an
  associated request attached): ten derived components,
  two plain header fields and six parameterized forms
  (`;bs`, `;sf`, `;key="…"`, `;tr`, and `;req` on both a
  derived component and a header field). Every measured
  pass re-pins each case's resolved value against the
  hand-written expectation, and the unsupported-parameter
  rejection is asserted outside timing. The README
  Benchmarks table was refreshed wholesale from one real
  run and now carries the `resolve` row. The bench
  performs zero network I/O and no wall-clock assertions.
- The benchmark (`npm run bench`) now also measures
  `ReplayCache.stats()` — the observability snapshot a
  verifier's monitoring polls on every tick (live entries
  counted against the injected clock, plus the detached
  hits / misses / evictions counters) — which the existing
  `check` and `exportSnapshot` rows never timed (the check
  row reads `stats()` only once, as a post-run self-check).
  The fixture is a fixed-clock cache (capacity 6, TTL 100
  seconds) whose construction is pinned end to end: one
  entry LRU-evicted during construction and one entry
  exactly at its TTL boundary at the stats instant
  (expired but still in the map), with five live entries.
  Every measured pass re-pins the snapshot against the
  hand-written expectation `{ size: 5, hits: 1, misses: 7,
  evictions: 1 }`, where `size` counts only the live
  entries; the detached-copy semantics and the empty-cache
  all-zero reading are asserted outside timing. The README
  Benchmarks table was refreshed wholesale from one real
  run and now carries the `stats` row. The bench performs
  zero network I/O and no wall-clock assertions.
- The benchmark (`npm run bench`) now also measures the
  ed25519 JWK round trip — the generic `exportPublicKeyJwk` →
  JSON stringify/parse → `importPublicKeyJwk` path for the
  library's default algorithm, in the OKP JWK shape a JWKS
  document actually distributes for ed25519 — which the
  existing per-curve JWK rows (P-256 / P-384 / P-521 /
  RSA-2048) and the ed25519 PEM row never timed. The row
  reuses the shared JWK round-trip helper (extended with an
  optional per-export shape check): every measured pass
  re-pins the exported JWK item by item (`kty` OKP, `crv`
  Ed25519, a non-empty `x`, and no private `d` field), and
  outside timing the re-imported public key must verify a
  signature made with the original private key. The README
  Benchmarks table was refreshed wholesale from one real
  run and now carries the `roundtrip` row. The bench
  performs zero network I/O and no wall-clock assertions.
- The benchmark (`npm run bench`) now also measures
  `JwksKeyStore.refreshIfStale` on a stale snapshot — the
  refresh direction a gateway pays when its key snapshot
  ages out (stale check against the injected clock, one
  fetch, JWK import and kid-index rebuild), which the
  existing `resolve` and `exportSnapshot` rows never
  timed. The store's injected clock is advanced by
  exactly its 120-second TTL before every measured call
  (stale under the `>=` rule), a counting fake fetch
  serves one pinned JWKS document (zero network), and
  every measured pass self-checks that the call reported
  a refresh, that the fetch count advanced by exactly
  one, and that the pinned kid resolves afterwards; the
  not-stale case (returns false, fetch count unmoved) is
  asserted outside timing. An async measurement helper
  (`measureAsync`) was added for promise-returning paths.
  The README Benchmarks table was refreshed wholesale
  from one real run and now carries the `refresh` row.
- The CLI demo (`npm run demo`) now closes with a
  ReplayCache clear segment: a fresh `ReplayCache` under
  the demo's fixed clock records one pinned nonce (a
  miss) and reports its repeat as a replay (a hit), then
  `clear()` is called and the emptied state is printed —
  `size` 0 and `stats()` all zero — after which the same
  nonce checks in as fresh again and the counters
  re-accumulate from zero. Earlier replay demo segments
  showed the cache recording, snapshotting and reporting
  its counters, but never the explicit reset a gateway
  runs at key rotation or for test isolation instead of
  waiting for TTL expiry. `DemoResult` carries the three
  check outcomes, the pre-clear stats, the post-clear
  size and stats, and the post-recheck stats, and the
  demo tests pin the fields and the printed lines. The
  clock is injected; the segment performs zero network
  I/O.
- The benchmark (`npm run bench`) now also measures
  `ReplayCache.exportSnapshot` — the snapshot export a
  single-process verifier runs to persist its tracked
  nonces before a restart (live entries filtered against
  the injected clock and assembled into the detached
  `{ v: 1, entries }` envelope) — over a fixed-clock cache
  whose map holds four recorded nonces: one already
  expired under the TTL and three live nonces at pinned
  `seenAt` values. Every measured pass re-pins the whole
  exported snapshot: version 1, exactly the live-entry
  count, every entry item by item (nonce and `seenAt`,
  first and last included), and the expired nonce absent;
  the detached-copy semantics and the empty-cache export
  (`{ v: 1, entries: [] }`) are asserted outside timing.
  The README Benchmarks table was refreshed wholesale
  from one real run and now carries the `export` row.
  The bench performs zero network I/O and no wall-clock
  assertions.
- The CLI demo (`npm run demo`) now closes with a
  ReplayCache observability segment: a small
  `ReplayCache` (capacity 3, 100-second TTL) under an
  injected clock is driven through a pinned script — two
  fresh nonces (misses), a repeat of the first (a hit),
  a third fresh nonce filling the cache, a fourth whose
  insertion evicts the least recently seen entry, and,
  after the clock advances past the TTL, a fifth whose
  insertion reclaims one expired entry — and `stats()`
  (`{ size, hits, misses, evictions }`) is printed after
  every step with each reading hand-pinned. A returned
  snapshot overwritten with 999s is shown to leave the
  cache unchanged: `stats()` hands out a detached copy,
  never a view. Earlier replay demo segments used a
  cache without ever presenting its observability
  counters, the health view a gateway operator watches.
  `DemoResult` carries the six check outcomes, the
  per-step stats and the post-mutation stats, and the
  demo tests pin the fields and the printed lines.
  Every clock is injected; the segment performs zero
  network I/O.
- The CLI demo (`npm run demo`) now closes with a JWKS
  observability segment: a `JwksKeyStore` is driven
  through one `refresh()` over a counting fake fetch
  (zero network) under an injected clock, and its
  observability surface is printed at three pinned
  instants — before any refresh (`lastRefreshedAt`
  `null`, `isStale()` `true`), at the fetch instant
  (`lastRefreshedAt` pinned, `isStale()` `false` inside
  the 120-second TTL), and at exactly the TTL boundary
  (`isStale()` `true` under the `>=` rule). At the
  boundary a request signed under the pinned keyid
  still verifies through the stale snapshot, a direct
  resolve of the pinned keyid is a hit and a direct
  resolve of an unknown keyid is a miss, and the final
  `stats()` is printed with every field pinned
  (`{ refreshes: 1, refreshFailures: 0, hits: 2,
  misses: 1 }` — the boundary verification contributes
  the first hit). Earlier JWKS demo segments each read
  one slice of store state, so the combined health view
  an operator watches was invisible to demo readers.
  `DemoResult` carries the before/after/boundary reads,
  the fetch count, the signed request and its
  verification, both resolve outcomes and the final
  stats, and the demo tests pin the fields and the
  printed lines. Every clock is injected and no key
  material is printed.
- The benchmark (`npm run bench`) now also measures
  `JwksKeyStore.exportSnapshot` — the snapshot export a
  gateway runs to persist its key store before a restart
  (each key re-exported through the JWK exporter for its
  type and assembled into the `{ v: 1, fetchedAtSec, keys }`
  envelope) — over an offline-restored store holding the
  three supported key shapes (ed25519, P-256 and RSA, one
  freshly generated key pair per shape, generated once
  outside timing) under hand-pinned kids at a pinned
  `fetchedAtSec`. Every measured pass re-pins the whole
  exported envelope: version, fetch time, exactly the
  three pinned kids in restore order, the per-shape `kty`
  dispatch (the EC entry naming P-256), and public-only
  JWK material with no `"d"` member; a never-refreshed
  store's export refusal is asserted outside timing with
  the pinned full message. The README Benchmarks table
  was refreshed wholesale from one real run and now
  carries the `export` row. The bench performs zero
  network I/O and no wall-clock assertions.
- The CLI demo (`npm run demo`) now closes with a JWKS
  snapshot persistence segment: a `JwksKeyStore` is
  refreshed once through a counting fake fetch (zero
  network) under an injected clock, its snapshot is
  exported with `exportSnapshot()` (only the version,
  the original `fetchedAtSec` and the key count are
  printed — never JWK material), the snapshot crosses a
  JSON text round-trip, and `JwksKeyStore.restore()`
  cold-starts a new store from it with the fetch count
  unchanged, its freshness still counting from the
  original fetch. A detached copy of the snapshot with
  private `"d"` material mixed into its key is fed to
  the restored store's `restoreSnapshot()` and printed
  rejected with the full fail-closed message; a request
  signed under the snapshotted keyid is verified through
  the restored store only after that rejection, so the
  passing verification proves the failed restore left
  the good snapshot untouched. A never-refreshed store's
  `exportSnapshot()` is printed refused outright.
  Earlier JWKS demo segments restored a hand-built
  snapshot or fetched live, so the persisted cold-start
  path — and both of its refusal surfaces — was
  invisible to demo readers. `DemoResult` carries the
  exported snapshot, both fetch counts, the restored
  store's size and freshness timestamp, the signed
  request, its verification and both error messages,
  and the demo tests pin the fields and the printed
  lines. Every clock is injected and no key material is
  printed, so the segment's printed lines are identical
  between runs.
- The CLI demo (`npm run demo`) now closes with an RSA
  v1_5 signing segment: the same fixed payment request
  is signed under `rsa-v1_5-sha256` (RSASSA-PKCS1-v1_5,
  RFC 9421 §3.3.2 — the legacy-interop algorithm) with
  an RSA key pair from `generateRsaV15KeyPair`, generated
  once per process, and its `Signature-Input` is printed
  (algorithm and keyid, never key bytes). The same
  request is signed a second time with the same key and
  the two signatures are shown byte-identical — v1_5 is
  deterministic, unlike RSA-PSS — verification is
  printed passing with its label / keyid / alg / nonce
  identity, and the same request with its body tampered
  by one byte is printed rejected with
  `BODY_DIGEST_MISMATCH`. Every earlier RSA demo segment
  signed with RSA-PSS or only guarded RSA keys, so an
  actual v1_5 signing — and its determinism — was
  invisible to demo readers. Outside the printed lines
  the demo asserts the verified identity, the
  byte-identity of the two signatures and the tamper
  rejection code against hand-pinned expectations.
  `DemoResult` carries both signed requests, the
  determinism verdict and both verification results,
  and the demo tests pin the fields and the printed
  lines. Only the determinism verdict is printed, never
  the signature bytes, so the segment's printed lines
  are identical between runs.
- The CLI demo (`npm run demo`) now closes with a
  signature-input value construction segment: the main
  line's covered components and fixed parameters are run
  through `signatureInputValue` — the low-level builder
  `signRequest` uses for one label's `Signature-Input`
  member (`label=` plus the serialized inner list and
  parameters) — and the built value is printed and
  asserted, outside the printed lines, to equal both a
  hand-pinned expectation and the main signed request's
  actual `signature-input` header byte for byte. A second
  call under a different label, over a shorter covered
  set and with all six parameter slots set (expires,
  nonce and tag included), is printed as well, its
  parameters serializing in the fixed
  created/expires/keyid/alg/nonce/tag order. Every
  earlier demo segment consumed the finished header, so
  how one label's member is built was invisible to demo
  readers. `DemoResult` carries both built values, and
  the demo tests pin the fields and the printed lines.
  Every input is a fixed constant, so the segment's
  printed lines are identical between runs.
- The CLI demo (`npm run demo`) now closes with a
  normalized header lookup segment: a fixed header record
  — one field stored under a mixed-case key as a padded
  two-element array, one single string field — is read
  with `getHeader`, the normalized lookup the verifier
  itself uses (the lookup name's case need not match the
  stored key, a multi-value field comes back trimmed and
  joined with ", ", a single string value comes back
  exactly as stored, and a missing field comes back
  `undefined`), and the same record is read with
  `getHeaderRaw` so the two results print side by side:
  the raw read preserves every element's padding, which
  is exactly the difference that makes the two reads easy
  to confuse and exactly why only the raw read may feed a
  `;bs` component. Every earlier demo segment read
  headers only through a full sign/verify path (the
  parsing segments used `getHeaderRaw` alone), so the
  normalized lookup — and its contrast with the raw read
  — was invisible to demo readers. Outside the printed
  lines the demo asserts every lookup result equals the
  hand-pinned expectations. `DemoResult` carries the
  fixture record and all five lookup results, and the
  demo tests pin the fields and the printed lines. Every
  input is a fixed constant, so the segment's printed
  lines are identical between runs.
- The CLI demo (`npm run demo`) now closes with a JWKS
  refresh and rotation segment: a `JwksKeyStore` over a
  counting fake JWKS fetch (zero network) and an injected
  clock is driven through `refreshIfStale()` — the first
  call loads the pre-rotation key (fetch count 1) and a
  request signed under the old keyid verifies through the
  store; a second call 60 seconds into the 120-second TTL
  returns `false` and fetches nothing; past the TTL, with
  the fake endpoint serving only the rotated key, a third
  call returns `true` (fetch count 2), a request signed
  under the rotated keyid verifies, and the retired
  keyid's still-valid signature is rejected with
  `KEY_RESOLUTION_FAILED` because its keyid no longer
  resolves. Every earlier JWKS demo segment restored a
  snapshot and never fetched, so the stale-refresh /
  rotation pick-up — the moment a verifier starts
  trusting a new key and stops trusting the retired one —
  was invisible to demo readers. Outside the printed
  lines the demo asserts every return value, fetch count
  and verified identity equal the hand-pinned
  expectations. `DemoResult` carries the three
  return values, the fetch counts after each probe, both
  signed requests and all three verifications, and the
  demo tests pin the fields and the printed lines.
  Because `refreshIfStale()` is asynchronous, `runDemo()`
  is now `async` (returning `Promise<DemoResult>`) and
  the demo's entry point awaits it; every demo test
  awaits it in turn. Both segment key pairs are fresh
  ed25519 pairs and the clock is injected, so the
  segment's printed lines are identical between runs.
- The CLI demo (`npm run demo`) now closes with an RSA
  JWK key distribution segment: the RSA public key is
  exported with `exportPublicKeyJwkRsa` (only the JWK's
  `kty` and the `n`/`e` lengths are printed — never the
  full modulus), read back through a JSON wire
  round-trip with `importPublicKeyJwkRsa`, and
  completes an `rsa-pss-sha512` sign -> verify
  round-trip, printed passing. Every earlier JWK
  segment covered only the ed25519 (`kty: "OKP"`) and
  EC (`kty: "EC"`) forms, so the RSA form
  (`kty: "RSA"` + `n`/`e`) — the member shape JWKS
  documents carry most often — was invisible to demo
  readers on its own. The EC segment's P-256 JWK fed
  to the RSA importer is printed rejected with the
  importer's exact kty-mismatch error. Outside the
  printed lines the demo asserts the JWK's shape
  (kty, the 342-character `n` length of a 2048-bit
  modulus and the `AQAB` exponent) and the verified
  identity equal the hand-pinned expectations.
  `DemoResult` carries the exported JWK, the signed
  request, the verification and the mismatch message,
  and the demo tests pin the fields and the printed
  lines. The RSA key pair is generated once per
  process (like the RSA guard segment's keys); only
  the JWK shape and the round-trip semantics are
  asserted, so the segment's printed lines are
  identical between runs.
- The CLI demo (`npm run demo`) now closes with an EC
  JWK key distribution segment: one fresh key pair is
  generated per NIST curve (P-256, P-384, P-521), each
  public key is exported with its curve's
  `exportPublicKeyJwkP*` helper (only the JWK's
  `kty`/`crv` and `x` length are printed), read back
  through a JSON wire round-trip with the matching
  `importPublicKeyJwkP*` helper, and completes a
  sign -> verify round-trip under its curve's RFC 9421
  algorithm, printed passing. Every earlier JWK segment
  covered only the ed25519 (`kty: "OKP"`) form, so the
  EC form (`kty: "EC"` + `crv` + `x`/`y`) — the key
  shape gateways and webhook verifiers distribute most
  often — was invisible to demo readers. A P-256 JWK
  fed to the P-384 importer is printed rejected with
  the importer's exact crv-mismatch error. Outside the
  printed lines the demo asserts every JWK's shape
  (kty, crv and both coordinate lengths: 43 / 64 / 88
  base64url chars) and every verified identity equal
  the hand-pinned expectations. `DemoResult` carries
  the exported JWKs, the signed requests, the
  verifications and the mismatch message, and the demo
  tests pin the fields and the printed lines. The key
  pairs are fresh on every run; only the JWK shapes
  and the round-trip semantics are asserted, so the
  segment's printed lines are identical between runs.
- The CLI demo (`npm run demo`) now closes with a
  Signature field parsing segment: the main signed
  request's `signature` value is parsed with
  `parseSignatureField` for the main label, and the
  extracted bytes' length (64 bytes, the ed25519 length)
  and a short hexadecimal prefix are printed — never the
  full signature. The same field is then parsed for a
  hand-pinned unknown label, which is printed rejected
  with the parser's exact `not present in Signature
  field` error. Every earlier segment showed the
  Signature-Input parse layer or consumed the signature
  bytes only inside verification, so how a verifier gets
  the raw bytes it feeds to the cryptographic check was
  invisible to demo readers. Outside the printed lines
  the demo asserts the extracted bytes equal, byte for
  byte, the bytes the signer emitted (decoded
  independently from the header's base64 member), that
  their length equals the pinned ed25519 length, and
  that the unknown-label rejection equals the pinned
  message (the same message shape the parser suites pin
  for their own absent labels). `DemoResult` carries the
  extracted bytes, their hex prefix and the rejection
  message, and the demo tests pin the fields and the
  printed lines. The main key pair is fresh on every
  run, so the printed prefix differs between runs while
  its shape and the rejection line are identical; every
  other input is a fixed demo constant.
- The CLI demo (`npm run demo`) now closes with a
  multi-value header combination segment: a fixed request
  carrying one field twice (a padded two-element array) is
  combined with `joinHeaderValues` and the combination is
  printed — each element trimmed, the elements joined with
  ", " per RFC 9421 §2.5, which is also the wire value the
  signer emits for the field. A request signed over the
  repeated field is printed verifying, and the same request
  with the field replaced by the wrong combination (a bare
  comma join, the space after the comma dropped) is printed
  rejected with `SIGNATURE_MISMATCH`, because the verifier
  rebuilds a different signature base from the wrongly
  joined value. Every earlier segment consumed the
  combination only inside sign/verify or the Node adapter,
  so the combination rule itself — the multi-value
  interop pitfall — was invisible to demo readers. Outside
  the printed lines the demo asserts the combination
  character for character, the signer's emitted wire
  value, the verified identity and the rejection code
  equal the hand-pinned expectations (the same combination
  shape and code
  `test/multiValueHeaderWhitespace.test.ts` pins for its
  own padded fixture). `DemoResult` carries the
  combination, the signed request and both verification
  results, and the demo tests pin the fields and the
  printed lines. Every input is a fixed demo constant, so
  the segment is byte-identical between runs.
- The CLI demo (`npm run demo`) now closes with a
  component-resolution segment: each covered component of
  the main signed request is run through `resolveComponent`
  — the per-component resolver `buildSignatureBase` applies
  — and printed as component -> resolved value (`@method`
  uppercased and `@authority` lowercased from the request
  target, `@path` from the URL, and the `content-digest`
  field's normalized value), and a detached illegal
  component id (`content-digest` carrying the unsupported
  `;zz` parameter) is printed rejected with the resolver's
  exact unsupported-parameter error. Every earlier segment
  showed the finished signature base or consumed resolution
  only inside sign/verify, so how one covered component
  becomes one base line — quoted-field, `;sf` / `;bs` /
  `;tr` and the other parameter semantics included — was
  invisible to demo readers. Outside the printed lines the
  demo asserts every resolved value and the rejection
  message equal the hand-pinned expectations (the same
  values the signature-base segment's printed lines carry,
  and the same `;zz` rejection shape
  `test/reqComponent.test.ts` pins on the sign side).
  `DemoResult` carries the resolved pairs and the rejection
  message, and the demo tests pin the fields and the
  printed lines. To make the segment possible,
  `resolveComponent` is now also exported from the package
  entry point (it was previously reachable only inside
  `src/components.ts`). Every input is a fixed demo
  constant, so the segment is byte-identical between runs.
- The benchmark (`npm run bench`) now also measures
  `signRequest` end to end — one complete signing of the
  shared fixture (signature-base construction, the ed25519
  cryptography and the `signature-input` / `signature`
  header serialization) as a standalone
  `signRequest (ed25519, end-to-end)` row. The fixture is
  fixed (`created=1700000000`, `keyid="bench-key"`,
  `alg="ed25519"`, one ed25519 key pair generated once
  outside timing), and every measured pass re-pins the
  output shape — both signature headers present, the full
  `signature-input` value and the single label `sig1`
  equal to hand-written expectations, the `content-digest`
  header equal to the pinned fixture digest, and the
  signature a single member decoding to 64 bytes — while
  outside timing the signed request is asserted to verify
  with the pinned identity (label / keyid / alg) and the
  same request with its body tampered by one byte
  (amount 100 -> 101) is rejected with
  `BODY_DIGEST_MISMATCH`. The per-algorithm scenario rows
  also time `signRequest`, but they discard the output
  unchecked, so this is the first checked total for the
  sign side. The README Benchmarks table was refreshed
  wholesale from one real run and now carries the new
  `sign` row. The bench performs zero network I/O and no
  wall-clock assertions, and never prints key or
  signature bytes.
- The CLI demo (`npm run demo`) now closes with an ECDSA
  P-521 signing segment: the same fixed payment request is
  signed under `ecdsa-p521-sha512` with a P-521 key pair
  from `generateP521KeyPair` — the generator the library's
  ecdsa tests and bench corpus use — its `Signature-Input`
  is printed, verification passes, and the same request
  with its body tampered by one byte (amount 100 -> 101)
  is rejected with `BODY_DIGEST_MISMATCH`, because the
  covered `content-digest` no longer matches the body.
  The demo's earlier segments show the ed25519 main line,
  the hmac-sha256 gateway line and the P-256 / P-384
  curves, so the widest NIST curve — whose signatures are
  the 132-octet raw r‖s form of RFC 9421 §3.3.6 (66 octets
  per limb), completing the ladder against the P-256
  segment's 64-octet form and the P-384 segment's 96-octet
  form — was invisible to demo readers. Outside the
  printed lines the demo asserts the verified identity
  (label, keyid, alg, nonce) and the tamper rejection
  code equal the hand-pinned expectations (the same
  identity and code `test/ecdsaP521.test.ts` pins for its
  round-trip and tampered-body cases). `DemoResult`
  carries the signed request and both verifications, and
  the demo tests pin the fields, the 132-octet wire
  length and the printed lines. The P-521 key pair is
  fresh on every run, so the signature bytes differ
  between runs while every printed line is identical.

- The CLI demo (`npm run demo`) now closes with a
  Signature-Input parsing segment: the main signed
  request's `signature-input` value is read back raw with
  `getHeaderRaw` and printed truncated to a pinned
  72-character preview, then parsed with
  `parseSignatureInput` for the main label — the parsed
  label, keyid, alg, created and covered components are
  printed. Every earlier demo segment consumed the parsed
  parameters only inside `verifyRequest`, so the parse
  layer a receiver debugs first on an inbound request was
  invisible to demo readers. Outside the printed lines
  the demo asserts the raw value and every parsed field
  equal the hand-pinned expectations (the same parse
  shape the bench parser fixture pins for its own
  inputs), and a detached copy of the raw value with its
  closing parenthesis removed is asserted to throw the
  pinned `malformed Signature-Input: unterminated inner
  list` error — the fail-closed shape a receiver sees on
  a truncated header — whose rejection is printed.
  `DemoResult` carries the raw value, the parse result
  and the tamper error, and the demo tests pin the
  fields and the printed lines. The segment performs
  zero network I/O, and its printed lines are identical
  between runs.

- The CLI demo (`npm run demo`) now closes with an ECDSA
  P-384 signing segment: the same fixed payment request is
  signed under `ecdsa-p384-sha384` with a P-384 key pair
  from `generateP384KeyPair` — the generator the library's
  ecdsa tests and bench corpus use — its `Signature-Input`
  is printed, verification passes, and the same request
  with its body tampered by one byte (amount 100 -> 101)
  is rejected with `BODY_DIGEST_MISMATCH`, because the
  covered `content-digest` no longer matches the body.
  The demo's earlier segments show the ed25519 main line,
  the hmac-sha256 gateway line and the narrower P-256
  curve, so the wider NIST curve — whose signatures are
  the 96-octet raw r‖s form of RFC 9421 §3.3.5 (48 octets
  per limb), against the P-256 segment's 64-octet form —
  was invisible to demo readers. Outside the printed
  lines the demo asserts the verified identity (label,
  keyid, alg, nonce) and the tamper rejection code equal
  the hand-pinned expectations (the same identity and
  code `test/ecdsaP384.test.ts` pins for its round-trip
  and tampered-body cases). `DemoResult` carries the
  signed request and both verifications, and the demo
  tests pin the fields, the 96-octet wire length and the
  printed lines. No key bytes are printed, the segment
  performs zero network I/O, and its printed lines are
  identical between runs.

- The CLI demo (`npm run demo`) now closes with a
  ReplayCache snapshot persistence segment: a request
  signed with a fixed nonce verifies against a
  `ReplayCache` on the demo's fixed clock, the cache is
  exported with `exportSnapshot()`, and a new cache is
  rebuilt with `ReplayCache.restore()` — the restart.
  The same request verified against the restored cache
  is rejected with `NONCE_REPLAY`, and a fresh-nonce
  request verifies against the restored cache and is
  recorded only there. The demo's earlier replay segment
  shows the cache rejecting a second presentation inside
  one process, and its JWKS segment restores a *key*
  store from a snapshot, but the replay cache's own
  cross-restart persistence — the only way its seen
  nonces survive a restart — was invisible to demo
  readers. Outside the printed lines the demo asserts
  the exported snapshot equals the hand-pinned v1 entry
  (the segment nonce at the fixed verify instant), the
  restored rejection code equals the hand-pinned
  `NONCE_REPLAY` expectation (the same snapshot shape
  and code `test/replaySnapshot.test.ts` pins for its
  round-trip case), and the original cache still holds
  only the exported entry after the restored cache
  records the fresh nonce. `DemoResult` carries the
  signed request, both caches' verifications, the
  exported snapshot and both entry counts, and the demo
  tests pin the fields and the printed lines. Only the
  entry count, the fixed nonces and the first-seen
  instant are printed, the segment performs zero network
  I/O, and its printed lines are identical between runs.

- The CLI demo (`npm run demo`) now closes with a
  Content-Digest algorithm guard segment: fixed values are
  run through `assertContentDigestAlg` — the two emittable
  algorithms (`sha-512`, the default, and `sha-256`) pass,
  while a fixed rejected corpus (unknown algorithms
  `sha-1` / `md5`, the empty string, wrong-case spellings
  `SHA-512` / `Sha-256`, a trailing-space spelling
  `sha-512 `, and the non-string values `undefined` /
  `null`) is rejected. The demo's earlier segments emit
  sha-512 / sha-256 `Content-Digest` headers and identify
  their algorithms on the read side with
  `contentDigestAlgOf`, but never showed this write-side
  fail-closed guard, so an unsupported digest algorithm
  being blocked before any hashing was invisible to demo
  readers. Outside the printed lines the demo asserts the
  accepted group all passed and every rejection message
  equals the hand-pinned expectations (the same messages
  `src/digest.ts` builds and the bench corpus /
  contentDigestAlg suite pin). `DemoResult` carries the
  accepted cases and the rejections, and the demo tests
  pin the fields and the printed lines. Each rejected
  value is printed only as a fixed printable label, the
  segment performs zero network I/O, and its printed
  lines are identical between runs.

- The CLI demo (`npm run demo`) now closes with an ECDSA
  P-256 signing segment: the same fixed payment request is
  signed under `ecdsa-p256-sha256` with a P-256 key pair
  from `generateP256KeyPair` — the generator the library's
  ecdsa tests and bench corpus use — its `Signature-Input`
  is printed, verification passes, and the same request
  with its body tampered by one byte (amount 100 -> 101)
  is rejected with `BODY_DIGEST_MISMATCH`, because the
  covered `content-digest` no longer matches the body.
  The demo's earlier segments sign and verify with
  ed25519 and hmac-sha256 only, so the NIST-curve
  algorithm line — supported since the ecdsa-p256-sha256
  work and measured in the bench — was invisible to demo
  readers. Outside the printed lines the demo asserts
  the verified identity (label `sig1`, the segment's
  keyid, alg and nonce) and the tamper rejection code
  equal the hand-pinned expectations (the same identity
  and code `test/ecdsaP256.test.ts` pins for its
  round-trip and tampered-body cases). `DemoResult`
  carries the signed request and both verification
  results, and the demo tests pin the fields, the raw
  64-octet r||s wire form, and the printed lines. The
  segment prints only the `Signature-Input` (algorithm
  and keyid), never key or signature bytes, performs
  zero network I/O, and its printed lines are identical
  between runs even though the P-256 key pair itself is
  fresh per run.

- The CLI demo (`npm run demo`) now closes with an RSA
  modulus-length guard segment: fixed-shape keys are run
  through `assertRsaModulusLength` under a fixed caller
  context (`assertRsaModulusLength demo`) — an RSA public
  key exactly at the 2048-bit floor passes, while a
  1024-bit RSA public key (below the floor) and the main
  line's ed25519 public key (not an RSA key at all) are
  rejected. The demo's earlier segments sign and verify
  with RSA keys but never showed this setup-time guard, so
  a weak or wrong-type RSA key being blocked at the
  boundary was invisible to readers. Outside the printed
  lines the demo asserts the accepted case passed and
  both rejection messages equal the hand-pinned
  expectations (the same messages `src/keys.ts` builds
  from `MIN_RSA_MODULUS_BITS` and the bench corpus /
  rsaV15 suite pin). `DemoResult` carries the accepted
  case and the rejections, and the demo tests pin the
  fields and the printed lines. The RSA key pairs are
  generated once per process (only their types and
  modulus lengths matter), the segment prints only key
  types and modulus lengths, never key bytes, performs
  zero network I/O, and its printed lines are identical
  between runs.

- The CLI demo (`npm run demo`) now closes with an HMAC
  secret-length guard segment: fixed secrets built from a
  fixed fill byte (only their lengths matter) are run through
  `assertHmacSecretLength` — a 32-byte secret passes for
  `hmac-sha256` and a 64-byte secret passes for
  `hmac-sha512` (exactly each algorithm's RFC 2104 floor),
  while a secret one byte below each floor (31 bytes for
  sha256, 63 bytes for sha512) is rejected. The demo's
  earlier segments sign and verify with HMAC keys but never
  showed this setup-time guard, so a weak gateway secret
  being blocked at the boundary was invisible to readers.
  Outside the printed lines the demo asserts the accepted
  group all passed and both rejection messages equal the
  hand-pinned expectations (the same messages `src/keys.ts`
  builds from `MIN_HMAC_SECRET_BYTES` /
  `MIN_HMAC_SHA512_SECRET_BYTES` and the keyLength /
  hmacSha512 suites pin). `DemoResult` carries the accepted
  cases and the rejections, and the demo tests pin the
  fields and the printed lines. The segment prints only
  algorithm names and byte lengths, never key bytes,
  performs zero network I/O, and its printed lines are
  identical between runs.

- The CLI demo (`npm run demo`) now closes with a key-resolver
  memoization segment: a counting resolver over a fixed two-key
  store (the main demo key plus a fresh second keypair) is
  wrapped with `memoizeKeyResolver` — TTL at the library
  default of 300 seconds, the wrapper's injected clock pinned
  to the demo's fixed verify instant so no entry can expire
  mid-segment — and passed as `keyResolver` to
  `verifyRequest`. The main signed request verifies twice
  under the same keyid while the underlying resolver is
  called only once (the second verification is served from
  the cache), and a request signed under a second keyid then
  verifies and advances the underlying call count to two —
  the per-keyid cache shape a gateway in front of a remote
  keystore relies on, which the demo's earlier resolver
  segments (JWKS store, thumbprint pinning) never showed for
  a plain resolver. Outside the printed lines the demo
  asserts all three verifications passed and both call
  counts equal the hand-pinned expectations (1 after the
  repeat, 2 after the second keyid — the same counts
  `test/memoizeKeyResolver.test.ts` pins for its counting
  store). `DemoResult` carries the three verifications and
  both counts, and the demo tests pin the fields and the
  printed lines. The segment prints only keyids and counts,
  never key bytes, performs zero network I/O, and its
  printed lines are identical between runs.

- The CLI demo (`npm run demo`) now closes with a JWK
  public-key import segment: the main line's ed25519 public
  key is exported with `exportPublicKeyJwk`, carried through
  a JSON stringify/parse round-trip exactly as it would
  cross the wire to a gateway, and read back with
  `importPublicKeyJwk` — the inbound half of JWK key
  distribution, which the demo's thumbprint segment (export
  only) never showed and its PEM round-trip segment covers
  only for the PEM format. The main signed request verifies
  with the imported key, and a detached copy of the JWK
  whose `x` coordinate has its first character flipped —
  still a well-formed 32-byte value, so the import succeeds
  — is rejected at verification with `SIGNATURE_MISMATCH`.
  Outside the printed lines the demo asserts the
  imported-key verification, the tampered copy's rejection
  against the hand-pinned code (the rejection shape
  `test/jwk.test.ts` pins for an imported key), and that
  the tamper copy left the exported JWK untouched.
  `DemoResult` carries the exported JWK and both
  verifications, and the demo tests pin the fields and the
  printed lines. Only the exported JWK's shape is printed
  (never the key bytes), the segment performs zero network
  I/O, and no assertion depends on the fresh key's value.
- The CLI demo (`npm run demo`) now closes with a
  nonce-generation segment: `generateNonce()` (the default
  16-byte draw) and `generateNonce(32)` produce fresh
  replay-protection nonces, both printed with their shapes
  (22 / 43 base64url characters, decoding to 16 / 32 bytes),
  and the short nonce signs a fresh request whose verification
  prints the nonce parsed back out. Every earlier segment
  signs with a hand-written nonce constant; this segment
  shows the standard CSPRNG entry point a real signer uses
  instead, since a predictable nonce makes the replay cache
  meaningless. Outside the printed lines the demo asserts
  both shapes against hand-pinned expectations (character
  lengths, decoded byte lengths, base64url alphabet — the
  same shapes `test/generateNonce.test.ts` pins), that the
  two draws differ, and that the parsed-back nonce equals
  the signed one character for character. `DemoResult`
  carries the two nonces, the signed request and its
  verification, and the demo tests pin the fields and the
  printed lines. The segment performs zero network I/O; the
  nonce values are random per run (like the key pair), so
  no assertion depends on their values — only their shapes
  and the sign → verify round-trip are pinned.
- The benchmark (`npm run bench`) now also measures the
  PEM round trip — `exportPublicKeyPem` +
  `exportPrivateKeyPem` on one fixed ed25519 key pair (the
  same shape the CLI demo's PEM segment round-trips,
  generated once outside timing), re-imported with
  `importPublicKey` / `importPrivateKey` — the
  serialization-plus-reparse cost of handing keys over as
  PEM files (SPKI public / PKCS#8 private), the standard
  encoding for gateways, KMS tooling and peer verifiers,
  which the per-curve JWK round-trip rows do not cover.
  Every measured pass asserts both PEM first lines equal
  the hand-pinned type headers and that the re-imported
  public key's JWK thumbprint equals the original's;
  outside timing, the re-imported keys must additionally
  complete a sign → verify over the shared fixture. The
  README Benchmarks table was refreshed wholesale from
  one real run (on a heavily loaded shared host, so the
  absolute numbers are depressed versus earlier tables —
  they remain machine-local measurements, not
  guarantees) and now carries the `PEM round-trip
  ed25519` row. The bench performs zero network I/O and
  no wall-clock assertions; the key pair is random per
  run but no assertion depends on its value.
- The CLI demo (`npm run demo`) now identifies the digest
  algorithm of its already-emitted `Content-Digest` headers
  with `contentDigestAlgOf`, right after the sha-256 segment:
  the main line's header is identified as `sha-512` and the
  sha-256 peer line's as `sha-256`, while a pinned
  sha-1-shaped value (`sha-1=:abc=:`) comes back `undefined`
  — the fail-closed shape a caller must reject, since this
  library cannot emit sha-1. Outside the printed lines the
  demo asserts all three identifications equal the
  hand-pinned expectations. `DemoResult` carries the three
  identification results, and the demo tests pin the fields
  and the printed lines. The segment performs zero network
  I/O and its printed lines are identical between runs.
- The CLI demo (`npm run demo`) now enumerates the dual-signed
  request's signature labels right after the multi-party signing
  segment: `listSignatureLabels` is called over the merged
  `Signature-Input` value and the labels are printed in wire
  order (`sig1`, `gateway` — 2 labels), the enumerate-first
  entry point a receiver uses before verifying each label.
  Outside the printed lines the demo asserts the enumerated
  labels equal the hand-pinned expectation in set and order
  (the same two-label wire-order shape the benchmark pins as
  `PARSER_EXPECTED_LABELS`). `DemoResult` carries the
  enumerated labels, and the demo tests pin the field and the
  printed lines. The segment performs zero network I/O and
  its printed lines are identical between runs.
- The CLI demo (`npm run demo`) now closes with a
  throwing-verification segment: the main signed request is
  verified with `verifyRequestOrThrow`, which returns the
  verified identity (label `sig1`, the demo keyid, `ed25519`,
  the demo nonce) instead of a result object, and the same
  request with the body tampered by one byte (amount 100 ->
  101) is verified again — the call throws a `VerifyError`
  whose stable code is printed. Outside the printed lines the
  demo asserts the returned identity and the thrown code equal
  the hand-pinned expectations (`BODY_DIGEST_MISMATCH`, the
  same code the returning `verifyRequest` reports for that
  tamper) and that the caught error passes the `isVerifyError`
  guard. `DemoResult` carries the returned identity, the
  caught error and the guard result, and the demo tests pin
  all three. The segment performs zero network I/O and its
  printed lines are identical between runs.
- The CLI demo (`npm run demo`) now closes with a PEM key
  round-trip segment: the main line's ed25519 key pair is
  exported with `exportPublicKeyPem` / `exportPrivateKeyPem`,
  only the first line of each PEM (its type header — SPKI
  `-----BEGIN PUBLIC KEY-----` for the public key, PKCS#8
  `-----BEGIN PRIVATE KEY-----` for the private key, both
  hand-pinned) is printed, the PEM texts are imported back
  with `importPublicKey` / `importPrivateKey`, and the
  imported keys complete a fresh sign -> verify round-trip
  over the same fixed request. Outside the printed lines the
  demo asserts the round-trip verification passed and that
  both PEM headers equal the pinned expectations. The segment
  performs zero network I/O; its printed lines are identical
  between runs even though the key pair itself is fresh.
- The benchmark (`npm run bench`) now also measures
  `assertContentDigestAlg` — the content-digest algorithm
  guard every sign/verify that selects a digest algorithm
  pays before any hashing runs (only `sha-512` and
  `sha-256` can be emitted; anything else is a caller
  configuration error) — as one pass over a fixed ten-case
  corpus per measured call: the two emittable algorithms
  (both pass), unknown algorithms (`sha-1` and `md5`),
  the empty string, two wrong-case spellings, a
  trailing-space spelling, and the non-string values
  `undefined` and `null` (all eight illegal shapes throw
  the pinned full configuration-error message). Eight of
  the ten cases throw and are caught inside the measured
  pass — the fail-closed rejection is part of the steady
  state a caller pays. Every expected pass/throw outcome
  is hand-pinned in the bench from the guard's documented
  contract (matching the rejections the contentDigestAlg
  test suite pins independently), never derived from the
  implementation at bench time, self-checked exhaustively
  outside timing, and re-pinned on every measured pass.
  The README Benchmarks table was refreshed wholesale
  from one real run and now carries the third `guard`
  row. The bench performs zero network I/O, zero
  randomness, and no wall-clock assertions.
- The benchmark (`npm run bench`) now also measures
  `signatureInputValue` — the full `Signature-Input` field
  value a signer builds once per label (`label=` plus the
  serialized inner list and parameters) — as one pass over
  a fixed four-case corpus per measured call: a bare
  single-component value with an empty parameter set (the
  value renders as the bare inner list — the function
  builds a value, it does not look one up, so there is no
  missing-label / undefined outcome), the shared four
  components under the label `sig1` with created + keyid +
  alg, a second label, `merchant`, over the same four
  components with all six parameters set, and a `gateway`
  value with parameterized component ids and an escaped
  nonce. Every expected string is hand-pinned in the bench
  from the function's contract (matching values pinned
  independently in the golden, multi-label and nonce test
  suites), never derived from the implementation at bench
  time, self-checked exhaustively outside timing —
  including the dual-label join of the golden and merchant
  values (joined with ", ", the merge the multi-label
  tests build) against a hand-pinned full header literal —
  and re-pinned on every measured pass. The README
  Benchmarks table was refreshed wholesale from one real
  run and now carries the second `serialize` row. The
  bench performs zero network I/O, zero randomness, and
  no wall-clock assertions.
- The benchmark (`npm run bench`) now also measures
  `assertRsaModulusLength` — the RSA modulus-length guard
  every `rsa-v1_5-sha256` sign/verify pays before any RSA
  operation runs (the modulus must be at least
  `MIN_RSA_MODULUS_BITS` = 2048 bits, and the key must be
  an RSA key at all) — as one pass over a fixed seven-case
  corpus per measured call: a 2048-bit RSA public and
  private key at exactly the floor (both pass), a 1024-bit
  RSA public and private key below the floor (both throw
  the pinned modulus message the rsaV15 suite pins for the
  same weak pair on both sides), and three wrong-shape
  keys (an ed25519 public key, a P-256 public key and a
  symmetric secret, each throwing the pinned
  expected-an-RSA-key message for its shape). Five of the
  seven cases throw and are caught inside the measured
  pass — the fail-closed rejection is part of the steady
  state a caller pays. Every expected pass/throw
  outcome, including the exact full throw message under
  the bench's fixed caller context, is hand-pinned in
  the bench from the guard's documented contract, never
  derived from the implementation at bench time,
  self-checked exhaustively outside timing, and
  re-pinned on every measured pass. All keys are
  generated once at bench start; the timed region
  generates no keys. The README Benchmarks table was
  refreshed wholesale from one real run and now carries
  the second `guard` row. The bench performs zero
  network I/O, zero key generation inside timing, and
  no wall-clock assertions.
- The benchmark (`npm run bench`) now also measures
  `assertHmacSecretLength` — the per-algorithm HMAC
  secret-length guard every HMAC sign/verify pays before any
  MAC runs (RFC 2104: the key SHOULD be at least as long as
  the hash output, so hmac-sha256 requires at least 32 bytes
  and hmac-sha512 at least 64) — as one pass over a fixed
  ten-case corpus per measured call: for each algorithm an
  empty secret, one byte below its floor, exactly at its
  floor, and far above it, plus the cross-algorithm pair a
  63-byte secret that passes for hmac-sha256 and a 32-byte
  secret that passes for hmac-sha256 but is rejected for
  hmac-sha512. Six of the ten cases throw and are caught
  inside the measured pass — the fail-closed rejection is
  part of the steady state a caller pays. Every expected
  pass/throw outcome, including the exact floor and byte
  count in each throw message, is hand-pinned in the bench
  from the guard's documented contract (matching the
  messages the keyLength and hmacSha512 suites pin
  independently), never derived from the implementation at
  bench time, self-checked exhaustively outside timing, and
  re-pinned on every measured pass. The secrets are built
  once at bench start from a fixed fill — only their lengths
  matter. The README Benchmarks table was refreshed
  wholesale from one real run and now carries the `guard`
  row. The bench performs zero network I/O, zero randomness
  and no wall-clock assertions.
- The benchmark (`npm run bench`) now also measures
  `contentDigestAlgOf` — the digest-algorithm identification
  a signer appending a second signature pays to pin itself
  to the existing wire Content-Digest value — as one pass
  over a fixed ten-case corpus per measured call: both
  emittable algorithms alone (the pinned wire values of the
  shared fixture body), mixed two-algorithm values in both
  orders (the helper reads only the prefix before the first
  `=`, so a mixed value resolves to its first entry — the
  signer-side pinning contract, not the verifier's
  whole-value sha-512-preferring body check), unknown
  algorithms (sha-1, sha-384), and malformed shapes (an
  uppercase prefix, a leading space, a bare algorithm name
  with no `=`, and the empty string), whose expected result
  is `undefined` — the fail-closed shape a caller turns
  into an explicit rejection. Every expected result is
  hand-pinned in the bench from the helper's documented
  contract, never derived from the implementation at bench
  time, self-checked outside timing, and re-pinned on every
  measured pass. `contentDigestAlgOf` is now also exported
  from the package entry point (it was previously internal
  to the signing path). The README Benchmarks table was
  refreshed wholesale from one real run and now carries
  the `identify` row. The bench performs zero network I/O,
  zero randomness and no wall-clock assertions.
- The benchmark (`npm run bench`) now also measures
  `joinHeaderValues` — the multi-value header combination
  every canonical lookup, signer-side fold and Node-adapter
  fold pays for a repeated header field (RFC 9421 §2.5:
  trim each element, join with ", ") — as one pass over a
  fixed nine-case corpus per measured call: an empty array,
  a single padded value, plain and whitespace-padded
  multi-value arrays (spaces and tabs), and empty-element
  cases (a lone empty string, two whitespace-only elements,
  an empty element in the middle of real values, and an
  empty first element). Empty elements are not dropped —
  they still contribute their separator — and every
  expected combination is hand-pinned in the bench from
  the helper's documented contract (the non-empty pins
  match the multi-value-header test suite), never derived
  from the implementation at bench time, and re-pinned on
  every measured pass. The README Benchmarks table was
  refreshed wholesale from one real run and now carries
  the `join` row. The bench performs zero network I/O,
  zero randomness and no wall-clock assertions.
- The CLI demo (`npm run demo`) now closes with a
  signature-params serialization segment: five fixed (covered
  components, parameters) cases — an empty component list
  carrying the RFC 9421 §B.2.1 parameters, the shared four
  covered components with created + keyid + alg, the same four
  with all six parameters set, four parameterized component ids
  (`;req` / `;tr` / `;name=` / `;key=`), and a nonce whose quote
  and backslash characters must serialize escaped — are run
  through `serializeSignatureParams` and printed as name ->
  serialized pairs, showing how the inner list and the parameters
  in fixed order (created, expires, keyid, alg, nonce, tag)
  assemble into the `@signature-params` line a verifier rebuilds
  byte-for-byte. Every expectation is hand-pinned from the
  serializer's contract, matching the bench corpus and the
  values pinned in the Appendix B, golden,
  parameterized-component and nonce test suites; the segment
  performs zero network I/O and is byte-identical between runs.
- The benchmark (`npm run bench`) now also measures
  `getHeader` / `getHeaderRaw` — the case-insensitive header
  lookup every covered-component resolution pays on the
  signer and the verifier — as one pass over a fixed
  nine-name lookup set against one fixed multi-header
  fixture per measured call (9 names × both helpers = 18
  lookups): mixed-case single strings, a duplicated header
  name under two casings (the first match in insertion order
  must win), and multi-value fields with padded elements, on
  which the canonical form (trimmed, joined with ", ") and
  the raw form (joined untrimmed, the form a `;bs` component
  binds) must differ. Every expected value is hand-pinned in
  the bench from the two helpers' documented contracts and
  re-pinned on every measured pass; missing and
  undefined-valued headers returning `undefined` from both
  helpers are asserted outside timing. The README Benchmarks
  table was refreshed wholesale from one real run and now
  carries the `lookup` row. The bench performs zero network
  I/O, zero randomness and no wall-clock assertions.
- The benchmark (`npm run bench`) now also measures
  `generateNonce` — the nonce generation an anti-replay
  signer pays on every request — as one pass over the two
  fixed byte tiers per measured call: the default 16 bytes
  (128 bits, exercised through the no-argument default) and
  32 bytes (256 bits). The random source is the system
  CSPRNG (`node:crypto` `randomBytes`), so the numbers
  include entropy-source cost. Self-checks assert morphology
  only, on every measured call — exact length (22 base64url
  characters for 16 bytes, 43 for 32, the lengths pinned in
  the generateNonce test suite) and the base64url-only
  character set — and never a specific value. The README
  Benchmarks table was refreshed wholesale from one real
  run and now carries the `generate` row. The bench
  performs zero network I/O and makes no wall-clock
  assertions; the only randomness is the function under
  test itself.
- The CLI demo (`npm run demo`) now closes with a
  dictionary-member extraction segment: one fixed multi-member
  Dictionary value is run through
  `serializeDictionaryMemberValue` once per fixed key (an Integer
  member, a member with parameters, a Decimal member, a Byte
  Sequence member, an Inner List member and a bare key) and each
  extraction is printed as a key -> serialized-value pair, showing
  the member value without its Dictionary key (parameters still
  attached) that a `;key` covered component contributes to the
  signature base. A missing key's `not present` rejection is
  printed as one line. Every expectation is hand-pinned from the
  RFC 8941 §4.1.2 rules, matching the values pinned in the
  `;key` / `;sf` component tests and the bench corpus; the
  segment performs zero network I/O and is byte-identical
  between runs.
- The benchmark (`npm run bench`) now also measures
  `serializeSignatureParams` — the inner-list-plus-parameters
  serialization every sign and verify pays before any
  cryptography runs — as one pass over a fixed five-case corpus
  per measured call: an empty component list carrying the
  RFC 9421 §B.2.1 parameters, the shared four covered
  components with created + keyid + alg, the same four with all
  six parameters set, four parameterized component ids
  (`;req` / `;tr` / `;name=` / `;key=`), and a nonce whose quote
  and backslash characters must serialize escaped. Every
  expected string is hand-pinned in the bench from the
  serializer's contract, matching values pinned independently
  in the Appendix B, golden, parameterized-component and nonce
  test suites, and every measured pass re-pins every case's
  result. `serializeSignatureParams` is also now re-exported
  from the package entry point alongside `signatureInputValue`
  (it was previously only reachable through the components
  module). The README Benchmarks table was refreshed wholesale
  from one real run and now carries the `serialize` row. The
  bench performs zero network I/O and makes no wall-clock
  assertions.
- The CLI demo (`npm run demo`) now closes with a structured-field
  canonicalization segment: three fixed field values (a Dictionary
  with a Decimal member, an Integer Item with leading zeros, a
  Dictionary Byte Sequence member) are run through
  `canonicalizeStructuredFieldValue` and printed as raw ->
  canonical pairs, showing the form a verifier actually compares
  for a `;sf` covered component (Decimals gain three fractional
  digits, leading-zero Integers collapse, Byte Sequences are
  re-encoded). Every expectation is hand-pinned from the RFC 8941
  §4 rules, matching the values pinned in the `;sf` component
  tests and the bench corpus; the segment performs zero network
  I/O and is byte-identical between runs.
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
- The Appendix B.2.5 (hmac-sha256) vector is now verified end-to-end
  through `verifyRequest` — the last Appendix B vector without a
  published-signature end-to-end case. The test assembles the
  published request, `signature-input`, and signature wire values
  and verifies them with `algFallback: "infer"` (B.2.5 is the only
  Appendix B vector whose signature-input omits `alg`, which is the
  case that opt-in exists for), asserting `ok` and the inferred
  `hmac-sha256` algorithm; a tampered `@authority` fails with
  `SIGNATURE_MISMATCH`; and the same vector without the opt-in
  fails with `VERIFICATION_ERROR` (the historical ed25519 default),
  pinning why the fallback stays opt-in.

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
