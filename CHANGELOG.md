# Changelog

All notable changes to this project are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and the version below is the version declared in `package.json`. Every entry
summarizes one or more commits in this repository's `git log`, grouped by
change type; no entry describes a feature that is not in the history.

## [Unreleased]

### Added

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
