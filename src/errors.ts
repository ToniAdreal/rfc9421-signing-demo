/**
 * Machine-readable verification failure codes.
 *
 * `verifyRequest` never throws; every failure result carries one of these
 * codes in `VerifyResult.code`. `verifyRequestOrThrow` throws a
 * `VerifyError` (an `Error` subclass) carrying the same code.
 */
export type VerifyFailureCode =
  /** `signature-input` header absent. */
  | "MISSING_SIGNATURE_INPUT"
  /** `signature` header absent. */
  | "MISSING_SIGNATURE"
  /** `signature-input` header present but unparseable. */
  | "MALFORMED_SIGNATURE_INPUT"
  /** Covered components could not be rebuilt from the request. */
  | "SIGNATURE_BASE_BUILD_FAILED"
  /** `signature` header present but unparseable. */
  | "MALFORMED_SIGNATURE"
  /**
   * The `signature-input` header is longer than the configured
   * `VerifyOptions.maxSignatureInputLength` byte limit (default
   * 65,536 bytes). Checked *before* any parsing: an oversized header
   * is rejected without the parser ever running over it, so a hostile
   * peer cannot make the verifier chew through megabytes of header
   * before failing. Length is measured in UTF-8 bytes on the joined
   * header value (the value the parser would see), not in characters.
   */
  | "SIGNATURE_INPUT_TOO_LARGE"
  /**
   * The `signature` header is longer than the configured
   * `VerifyOptions.maxSignatureLength` byte limit (default 65,536
   * bytes). Checked *before* any parsing, in the same position as
   * `SIGNATURE_INPUT_TOO_LARGE`.
   */
  | "SIGNATURE_TOO_LARGE"
  /** `alg` parameter names an unsupported algorithm. */
  | "UNSUPPORTED_ALG"
  /**
   * The signature's algorithm (the wire `alg`, or the effective
   * algorithm when `alg` is absent: the legacy `"ed25519"` default, or
   * the key-shape inference under `algFallback: "infer"`) is not in
   * the verifier's `VerifyOptions.allowedAlgs` whitelist. Only
   * possible when the caller opted in. Checked *before* any
   * cryptographic work: a disallowed algorithm is a policy violation,
   * not an authenticity verdict, so a forged signature carrying a
   * disallowed `alg` reports this code rather than
   * `SIGNATURE_MISMATCH`.
   */
  | "ALG_NOT_ALLOWED"
  /** The crypto layer itself threw (e.g. malformed key material). */
  | "VERIFICATION_ERROR"
  /** Cryptographic signature does not verify (wrong key or tampering). */
  | "SIGNATURE_MISMATCH"
  /**
   * `keyid` in the signature-input does not match the verifier's
   * `expectedKeyId` (key-confusion / wrong-key binding). Includes a
   * signature that carries no `keyid` at all.
   */
  | "KEYID_MISMATCH"
  /**
   * The `tag` signature parameter (RFC 9421 §2.3) does not match the
   * verifier's `expectedTag`: the signature was minted for a different
   * application protocol than the one this verifier serves. Includes a
   * signature that carries no `tag` at all. Only possible when the
   * caller opted in with `expectedTag`. Checked only *after* the
   * cryptographic check, so forgeries still report
   * `SIGNATURE_MISMATCH`.
   */
  | "TAG_MISMATCH"
  /**
   * The `VerifyOptions.keyResolver` lookup could not produce a key: the
   * signature carried no `keyid`, or the resolver returned `undefined`
   * for the claimed `keyid`. Only possible when a resolver is configured.
   */
  | "KEY_RESOLUTION_FAILED"
  /** Body present but no `sha-512` (preferred) or `sha-256` (fallback) entry in `content-digest`. */
  | "MISSING_CONTENT_DIGEST"
  /** Body bytes do not match the signed `sha-512` digest. */
  | "BODY_DIGEST_MISMATCH"
  /** `expires` timestamp is in the past (beyond tolerance). */
  | "EXPIRED"
  /** `created` timestamp is in the future (beyond clock-skew tolerance). */
  | "CREATED_IN_FUTURE"
  /**
   * `created` timestamp is older than `VerifyOptions.maxSignatureAgeSec`
   * seconds in the past. Only possible when the caller opted in. A
   * signature that carries no `created` parameter never triggers this —
   * the check is orthogonal to `requireCreated`.
   */
  | "SIGNATURE_TOO_OLD"
  /**
   * `VerifyOptions.requireCreated` is set but the signature carries no
   * `created` parameter. Only possible when the caller opted in.
   */
  | "MISSING_CREATED"
  /**
   * `VerifyOptions.requireExpires` is set but the signature carries no
   * `expires` parameter. Only possible when the caller opted in.
   */
  | "MISSING_EXPIRES"
  /**
   * Both `created` and `expires` are present but `expires` is earlier
   * than `created`: the signature was already expired at birth. The
   * signing side rejects this (`signRequest`); this code covers
   * third-party / hand-built signatures. `expires === created` is
   * allowed, mirroring the signing side. Checked only *after* the
   * cryptographic check, so forgeries still report
   * `SIGNATURE_MISMATCH`.
   */
  | "INVALID_TIME_WINDOW"
  /**
   * Nonce already seen within the TTL of `VerifyOptions.replayCache`
   * (replayed signature). Only possible when a cache is configured and
   * the signature carries a `nonce`.
   */
  | "NONCE_REPLAY"
  /**
   * `VerifyOptions.requireNonce` is set but the signature carries no
   * `nonce` parameter, or carries an empty-string one (treated as
   * missing: the signing side rejects empty nonces, so one on the wire
   * can only come from a third party). Only possible when the caller
   * opted in. Checked only *after* the cryptographic check and *before*
   * the nonce replay store, so forgeries still report
   * `SIGNATURE_MISMATCH`.
   */
  | "MISSING_NONCE"
  /**
   * `VerifyOptions.requireTag` is set but the signature carries no
   * `tag` parameter, or carries an empty-string one (treated as
   * missing: the signing side rejects empty tags, so one on the wire
   * can only come from a third party). Only possible when the caller
   * opted in. Checked only *after* the cryptographic check and
   * alongside `requireCreated`/`requireExpires` (before the window
   * checks), so forgeries still report `SIGNATURE_MISMATCH`. A
   * signature that also fails a pinned `expectedTag` still reports
   * `TAG_MISMATCH`: the pinning check runs first.
   */
  | "MISSING_TAG"
  /**
   * The signature did not cover one or more components demanded by
   * `VerifyOptions.requiredComponents` (e.g. a payment-gateway verifier
   * requiring `content-digest` or `@path`). Only possible when the
   * caller opted in. Checked *before* the cryptographic check: a missing
   * component is a policy violation, not an authenticity verdict.
   */
  | "MISSING_REQUIRED_COMPONENT"
  /**
   * A signature label demanded by `VerifyAllOptions.requiredLabels`
   * is absent from the request entirely (no entry for it in the
   * `signature-input` header, or no `signature-input` header at all).
   * Only possible when the caller opted in. Reported as a synthetic
   * per-label failure appended after the labels actually present on
   * the wire, so a label-stripping downgrade can never pass a bare
   * `results.every((r) => r.ok)` check.
   */
  | "MISSING_REQUIRED_LABEL";

export interface VerifyErrorOptions {
  label: string;
  keyId?: string | undefined;
  alg?: string | undefined;
  nonce?: string | undefined;
  tag?: string | undefined;
  created?: number | undefined;
  expires?: number | undefined;
}

/**
 * Typed verification failure. Extends `Error`, so existing generic
 * `catch (e)` handlers keep working; inspect `.code` for programmatic
 * handling instead of string-matching `.message`.
 */
export class VerifyError extends Error {
  readonly code: VerifyFailureCode;
  readonly reason: string;
  readonly label: string;
  readonly keyId?: string | undefined;
  readonly alg?: string | undefined;
  readonly nonce?: string | undefined;
  readonly tag?: string | undefined;
  readonly created?: number | undefined;
  readonly expires?: number | undefined;

  constructor(
    code: VerifyFailureCode,
    reason: string,
    opts: VerifyErrorOptions,
  ) {
    super(reason);
    this.name = "VerifyError";
    this.code = code;
    this.reason = reason;
    this.label = opts.label;
    this.keyId = opts.keyId;
    this.alg = opts.alg;
    this.nonce = opts.nonce;
    this.tag = opts.tag;
    this.created = opts.created;
    this.expires = opts.expires;
  }
}

/** Type guard for `VerifyError`. */
export function isVerifyError(e: unknown): e is VerifyError {
  return e instanceof VerifyError;
}
