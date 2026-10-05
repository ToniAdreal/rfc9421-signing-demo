import {
  createHash,
  createHmac,
  timingSafeEqual,
  verify as edVerify,
  type KeyObject,
} from "node:crypto";
import {
  buildSignatureBase,
  getHeader,
  listSignatureLabels,
  parseSignatureField,
  parseSignatureInput,
  type RequestLike,
} from "./components.js";
import { VerifyError, type VerifyFailureCode } from "./errors.js";

export interface VerifyOptions {
  /**
   * ed25519: the signer's public KeyObject.
   * hmac-sha256: the shared secret KeyObject.
   */
  key: KeyObject;
  /** Signature label to verify. Defaults to "sig1". */
  label?: string;
  /** Unix seconds. Defaults to now. */
  now?: number;
  /**
   * Accept signatures created up to this many seconds in the future
   * (clock skew between signer and verifier). Defaults to 60.
   */
  clockSkewToleranceSec?: number;
  /**
   * Accept signatures whose `expires` timestamp is up to this many
   * seconds in the past. Defaults to 0: expiry is enforced strictly,
   * with no grace period. Set a small positive value to tolerate
   * verifier clock lag during deployments and key rollovers.
   */
  expiredToleranceSec?: number;
  /**
   * Optional `keyid` pinning (key-confusion protection): after the
   * cryptographic check passes, the `keyid` claimed in the
   * signature-input must equal this value, otherwise verification
   * fails with `KEYID_MISMATCH`. A signature that carries no `keyid`
   * also fails when this is set. Defaults to unset: no check is made.
   * In `verifyAllLabels` the same expectation applies to every label.
   */
  expectedKeyId?: string;
}

export interface VerifyResult {
  ok: boolean;
  reason?: string;
  /**
   * Machine-readable failure code. Present on every failure; stable
   * across versions (the human `reason` strings may be reworded).
   */
  code?: VerifyFailureCode;
  label: string;
  keyId?: string;
  alg?: string;
  /**
   * The `nonce` signature-input parameter parsed from the request, as
   * seen on the wire (i.e. *before* signature verification establishes
   * its authenticity). Absent when the signer did not send one.
   */
  nonce?: string;
}

/**
 * Verify an RFC 9421 signed request: rebuild the signature base from the
 * covered components, check the cryptographic signature, then enforce
 * freshness (expires / created).
 *
 * Never throws on verification failure: returns `{ ok: false, code, reason }`.
 * For a throwing variant, see `verifyRequestOrThrow`.
 */
export function verifyRequest(
  req: RequestLike,
  opts: VerifyOptions,
): VerifyResult {
  const label = opts.label ?? "sig1";
  const now = opts.now ?? Math.floor(Date.now() / 1000);
  const skew = opts.clockSkewToleranceSec ?? 60;
  const expiredTolerance = opts.expiredToleranceSec ?? 0;

  const sigInput = getHeader(req.headers, "signature-input");
  if (!sigInput)
    return {
      ok: false,
      code: "MISSING_SIGNATURE_INPUT",
      reason: "missing signature-input header",
      label,
    };
  const sigField = getHeader(req.headers, "signature");
  if (!sigField)
    return {
      ok: false,
      code: "MISSING_SIGNATURE",
      reason: "missing signature header",
      label,
    };

  let parsed;
  try {
    parsed = parseSignatureInput(sigInput, label);
  } catch (e) {
    return {
      ok: false,
      code: "MALFORMED_SIGNATURE_INPUT",
      reason: `bad signature-input: ${(e as Error).message}`,
      label,
    };
  }

  let base: string;
  try {
    base = buildSignatureBase(parsed.componentIds, req, parsed.params);
  } catch (e) {
    return {
      ok: false,
      code: "SIGNATURE_BASE_BUILD_FAILED",
      reason: `cannot rebuild signature base: ${(e as Error).message}`,
      label,
    };
  }

  let sigBytes: Buffer;
  try {
    sigBytes = parseSignatureField(sigField, label);
  } catch (e) {
    return {
      ok: false,
      code: "MALFORMED_SIGNATURE",
      reason: `bad signature field: ${(e as Error).message}`,
      label,
      keyId: parsed.params.keyid,
      alg: parsed.params.alg,
      nonce: parsed.params.nonce,
    };
  }

  const alg = parsed.params.alg ?? "ed25519";
  let cryptoOk = false;
  try {
    if (alg === "ed25519") {
      cryptoOk = edVerify(null, Buffer.from(base, "utf8"), opts.key, sigBytes);
    } else if (alg === "hmac-sha256") {
      const expected = createHmac("sha256", opts.key)
        .update(base, "utf8")
        .digest();
      cryptoOk =
        sigBytes.length === expected.length &&
        timingSafeEqual(sigBytes, expected);
    } else {
      return {
        ok: false,
        code: "UNSUPPORTED_ALG",
        reason: `unsupported alg "${alg}"`,
        label,
        nonce: parsed.params.nonce,
      };
    }
  } catch (e) {
    return {
      ok: false,
      code: "VERIFICATION_ERROR",
      reason: `verification error: ${(e as Error).message}`,
      label,
      nonce: parsed.params.nonce,
    };
  }
  if (!cryptoOk)
    return {
      ok: false,
      code: "SIGNATURE_MISMATCH",
      reason: "signature mismatch",
      label,
      keyId: parsed.params.keyid,
      alg,
      nonce: parsed.params.nonce,
    };

  // Key-id pinning (key-confusion defense): the signature is already
  // authenticated by the crypto check above, and `keyid` is part of the
  // signed params, so the claim here is trustworthy. Reject when it is
  // not the key the verifier expected to see.
  const expectedKeyId = opts.expectedKeyId;
  if (expectedKeyId !== undefined && parsed.params.keyid !== expectedKeyId)
    return {
      ok: false,
      code: "KEYID_MISMATCH",
      reason: `keyid mismatch: expected "${expectedKeyId}", got ${
        parsed.params.keyid === undefined
          ? "no keyid"
          : `"${parsed.params.keyid}"`
      }`,
      label,
      keyId: parsed.params.keyid,
      alg,
      nonce: parsed.params.nonce,
    };

  // Body binding (RFC 9530): the signature only covers the *value* of the
  // content-digest header, so the verifier must additionally check that the
  // body actually matches the digest. Without this, swapping the body while
  // keeping the header would still verify.
  const digestHeader = getHeader(req.headers, "content-digest");
  if (digestHeader !== undefined) {
    const bodyBytes =
      req.body === undefined
        ? Buffer.alloc(0)
        : typeof req.body === "string"
          ? Buffer.from(req.body, "utf8")
          : req.body;
    const dm = /(?:^|,)\s*sha-512\s*=:([A-Za-z0-9+/=]+):/.exec(digestHeader);
    if (!dm)
      return {
        ok: false,
        code: "MISSING_CONTENT_DIGEST",
        reason: "cannot verify body: no sha-512 content-digest present",
        label,
        keyId: parsed.params.keyid,
        alg,
        nonce: parsed.params.nonce,
      };
    const expected = createHash("sha512").update(bodyBytes).digest();
    const actual = Buffer.from(dm[1], "base64");
    if (actual.length !== expected.length || !timingSafeEqual(actual, expected))
      return {
        ok: false,
        code: "BODY_DIGEST_MISMATCH",
        reason: "body does not match content-digest",
        label,
        keyId: parsed.params.keyid,
        alg,
        nonce: parsed.params.nonce,
      };
  }

  if (
    parsed.params.expires !== undefined &&
    now > parsed.params.expires + expiredTolerance
  )
    return {
      ok: false,
      code: "EXPIRED",
      reason: "signature expired",
      label,
      keyId: parsed.params.keyid,
      alg,
      nonce: parsed.params.nonce,
    };
  if (
    parsed.params.created !== undefined &&
    parsed.params.created > now + skew
  )
    return {
      ok: false,
      code: "CREATED_IN_FUTURE",
      reason: "signature created in the future (clock skew)",
      label,
      keyId: parsed.params.keyid,
      alg,
      nonce: parsed.params.nonce,
    };

  return {
    ok: true,
    label,
    keyId: parsed.params.keyid,
    alg,
    nonce: parsed.params.nonce,
  };
}

/**
 * Like `verifyRequest`, but throws a `VerifyError` — an `Error` subclass
 * carrying a machine-readable `.code` — instead of returning
 * `{ ok: false, ... }`. Use when callers prefer exceptions over
 * result-branching.
 */
export function verifyRequestOrThrow(
  req: RequestLike,
  opts: VerifyOptions,
): { label: string; keyId?: string; alg?: string; nonce?: string } {
  const res = verifyRequest(req, opts);
  if (res.ok)
    return { label: res.label, keyId: res.keyId, alg: res.alg, nonce: res.nonce };
  throw new VerifyError(
    res.code ?? "VERIFICATION_ERROR",
    res.reason ?? "verification failed",
    { label: res.label, keyId: res.keyId, alg: res.alg, nonce: res.nonce },
  );
}

export interface VerifyAllOptions extends Omit<VerifyOptions, "label"> {
  /**
   * Per-label verification keys for multi-party signatures (e.g. a
   * merchant signature plus a payment-gateway signature on the same
   * request). A label absent from the map falls back to `key`.
   */
  keys?: Record<string, KeyObject>;
}

/**
 * Verify every signature carried by the request. Parses all labels from
 * the `Signature-Input` header and verifies each one with
 * `verifyRequest`, returning one `VerifyResult` per label in wire order.
 * A failing label never blocks the remaining labels.
 *
 * Returns an empty array when the request has no `Signature-Input`
 * header. Duplicate labels are verified once (first occurrence).
 */
export function verifyAllLabels(
  req: RequestLike,
  opts: VerifyAllOptions,
): VerifyResult[] {
  const sigInput = getHeader(req.headers, "signature-input");
  if (sigInput === undefined) return [];
  return listSignatureLabels(sigInput).map((label) => {
    const key = opts.keys?.[label] ?? opts.key;
    return verifyRequest(req, { ...opts, label, key });
  });
}
