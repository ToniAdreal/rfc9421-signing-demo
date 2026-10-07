# Security policy

This is a **learning/demo implementation of a subset of RFC 9421**
(HTTP Message Signatures). It is not a hardened, audited security library.
Read this before using it anywhere that matters.

## Demo scope

- Only an RFC 9421 *subset* is implemented: signature algorithms
  `ed25519`, `ecdsa-p256-sha256` (NIST P-256, DER-encoded per
  RFC 9421 §3.3.4), `rsa-pss-sha512` (RSASSA-PSS per RFC 9421 §3.3.1),
  `hmac-sha256`, and `hmac-sha512` (≥ 64-byte secrets, RFC 2104 §3); `verifyRequest` checks one
  signature label per call, while `verifyAllLabels` verifies every label
  in the request (a failing label never blocks the remaining labels);
  and body binding signs via `Content-Digest: sha-512` only (the
  verifier additionally accepts a `sha-256` fallback when no `sha-512`
  entry is present). See
  `README.md` → "Limitations (honest)" for the full list of what is not
  supported.
- The implementation has only been tested against itself (see
  `README.md` → "Interoperability"). Wire compatibility with any
  third-party RFC 9421 implementation is untested.
- **No security audit has been performed.** The signature-input parser
  has been fuzz-tested against a fixed-seed corpus of 1000+ malformed
  inputs (`test/parserFuzz.test.ts`): `verifyRequest` and
  `verifyAllLabels` never let a parser exception escape — they return
  `{ok:false, code}` instead — and each case completes in well under
  50 ms (no catastrophic backtracking). That covers robustness against
  malformed headers, not a systematic adversarial analysis: treat the
  parser as hardening-in-progress rather than proven, it runs
  entirely in-process on untrusted headers with no network or
  filesystem access.

## Assumptions that do not hold in production

- **Replay protection is opt-in and single-process.** `created`/`expires`
  only bound the acceptance window; a signature captured inside its
  validity window can be replayed unless the caller opts into the
  in-memory `ReplayCache` (`VerifyOptions.replayCache`), which tracks
  seen nonces with a TTL and an LRU capacity cap. The cache does not
  survive restarts and is not shared across verifier instances, so a
  multi-instance deployment must still deduplicate nonces in a shared
  store — that part remains the caller's job.
- **Fixed, configurable tolerance windows.** `verifyRequest` accepts
  `created` timestamps up to `clockSkewToleranceSec` seconds in the future
  (default 60 — generous, shrink it if your clocks are trustworthy) and
  `expires` timestamps up to `expiredToleranceSec` seconds in the past
  (default 0, strictly enforced). Widening these windows lengthens the
  replay window above; keep both as small as your deployment allows.
- **Demo-grade key management.** Keys are passed in directly as
  `KeyObject`s, or resolved per-call via the opt-in `keyResolver`
  (`VerifyOptions.keyResolver`: `(keyId) => KeyObject | undefined`,
  mutually exclusive with the static `key`; an unknown or missing
  `keyid` fails with `KEY_RESOLUTION_FAILED`, and a resolver that
  throws is contained to `VERIFICATION_ERROR` — never a silent
  fallback to another key). There is still no built-in keystore, no
  key rotation, and no key discovery (JWKS etc.): how keys are
  generated, stored, rotated, and mapped to `keyid` values is entirely
  on the caller.
- **`hmac-sha256` / `hmac-sha512` are symmetric.** The "verifier" holds the same secret as
  the signer, so verification proves integrity but not origin — the
  verifying party could itself have forged the signature. Use `ed25519`
  when the verifier must not be able to mint signatures.
- **Short HMAC secrets are rejected.** RFC 2104 §3 advises the key be at
  least as long as the hash output — 32 bytes for sha-256, 64 bytes for
  sha-512 — and this library pairs the floor with the algorithm:
  `hmac-sha256` secrets must be ≥ 32 bytes, `hmac-sha512` secrets must be
  ≥ 64 bytes. `secretKey()`, `signRequest`, and `verifyRequest` all
  enforce this and throw a configuration error on anything shorter, on
  both the sign and verify sides, so a weak key fails loudly at setup
  time instead of minting low-entropy signatures — and a secret that is
  only adequate for `hmac-sha256` is never silently accepted for
  `hmac-sha512`.
- **Timing.** HMAC comparison uses `timingSafeEqual` after a length check,
  and Ed25519 verification goes through `node:crypto`. No additional
  side-channel analysis has been done.

## What verification does *not* guarantee

- It does not check authorization, tenant identity, or transport security.
  A valid signature on a request that arrived over plain HTTP (or with a
  swapped body whose digest header was also swapped) tells you only that
  whoever held the key signed *that* content.
- Body binding only applies when a `content-digest` header is present, and
  only the `sha-512` entry is honored when present, with `sha-256` accepted
  as a fallback. Requests without a digest header
  verify against headers alone.

## Why not use this directly in production

In short: untested cross-implementation compatibility, no replay
protection out of the box (opt-in, single-process cache only), no key
lifecycle story, unaudited parser, and a deliberately
narrow feature subset. If you need production message signatures, use a
maintained, audited implementation of the full RFC 9421 with replay
handling and key management, and validate it against independent
implementations first.

## Reporting a security issue

If you find a security problem in this demo, please open an issue on this
repository describing it. Do not include private keys, secrets, or any
credentials in the report.
