# Security policy

This is a **learning/demo implementation of a subset of RFC 9421**
(HTTP Message Signatures). It is not a hardened, audited security library.
Read this before using it anywhere that matters.

## Demo scope

- Only an RFC 9421 *subset* is implemented: signature algorithms
  `ed25519` and `hmac-sha256`, a single signature label per verification
  call, and body binding via `Content-Digest: sha-512` only. See
  `README.md` → "Limitations (honest)" for the full list of what is not
  supported.
- The implementation has only been tested against itself (see
  `README.md` → "Interoperability"). Wire compatibility with any
  third-party RFC 9421 implementation is untested.
- **No security audit has been performed.** The signature-input parser has
  not been fuzz-tested. Treat the parser as adversarial-input-adjacent:
  it runs entirely in-process on untrusted headers, and while it performs
  no network or filesystem access, robustness under hostile input has not
  been systematically established.

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
  `KeyObject`s. There is no keystore, no key rotation, no `keyid`→key
  lookup, and no key discovery (JWKS etc.). `keyid` is an opaque hint;
  it is carried but never resolved. How keys are generated, stored,
  rotated, and mapped to `keyid` values is entirely on the caller.
- **`hmac-sha256` is symmetric.** The "verifier" holds the same secret as
  the signer, so verification proves integrity but not origin — the
  verifying party could itself have forged the signature. Use `ed25519`
  when the verifier must not be able to mint signatures.
- **Timing.** HMAC comparison uses `timingSafeEqual` after a length check,
  and Ed25519 verification goes through `node:crypto`. No additional
  side-channel analysis has been done.

## What verification does *not* guarantee

- It does not check authorization, tenant identity, or transport security.
  A valid signature on a request that arrived over plain HTTP (or with a
  swapped body whose digest header was also swapped) tells you only that
  whoever held the key signed *that* content.
- Body binding only applies when a `content-digest` header is present, and
  only the `sha-512` entry is honored. Requests without a digest header
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
