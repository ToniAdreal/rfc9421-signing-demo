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
  /** `alg` parameter names an unsupported algorithm. */
  | "UNSUPPORTED_ALG"
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
  /** Body present but no `sha-512` entry in `content-digest`. */
  | "MISSING_CONTENT_DIGEST"
  /** Body bytes do not match the signed `sha-512` digest. */
  | "BODY_DIGEST_MISMATCH"
  /** `expires` timestamp is in the past (beyond tolerance). */
  | "EXPIRED"
  /** `created` timestamp is in the future (beyond clock-skew tolerance). */
  | "CREATED_IN_FUTURE";

export interface VerifyErrorOptions {
  label: string;
  keyId?: string;
  alg?: string;
  nonce?: string;
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
  readonly keyId?: string;
  readonly alg?: string;
  readonly nonce?: string;

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
  }
}

/** Type guard for `VerifyError`. */
export function isVerifyError(e: unknown): e is VerifyError {
  return e instanceof VerifyError;
}
