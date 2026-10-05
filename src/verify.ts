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
import type { ReplayCache } from "./replay.js";

export interface VerifyOptions {
  /**
   * ed25519: the signer's public KeyObject.
   * hmac-sha256: the shared secret KeyObject.
   *
   * Required unless `keyResolver` is set; mutually exclusive with it.
   */
  key?: KeyObject;
  /**
   * Optional `keyid`→key resolution (key discovery / rotation support).
   * Called with the `keyid` claimed in the signature-input *after* the
   * header parses and *before* the cryptographic check; the returned
   * KeyObject is the key the signature is checked against. A signature
   * with no `keyid`, or a `keyid` the resolver cannot map, fails with
   * `KEY_RESOLUTION_FAILED` (never a silent fallback to another key).
   * Mutually exclusive with `key`: passing both throws a configuration
   * `Error`. Composes with `expectedKeyId` (checked after the crypto
   * step) and with `verifyAllLabels` (resolved independently per label).
   */
  keyResolver?: (keyId: string) => KeyObject | undefined;
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
  /**
   * Optional nonce replay cache (see `ReplayCache`). When set and the
   * signature carries a non-empty `nonce`, the cache is consulted *after*
   * every other check has passed: a nonce seen within the cache TTL fails
   * with `NONCE_REPLAY`, otherwise the nonce is recorded. Failed
   * verifications never record anything, so forgeries cannot pollute the
   * cache. A signature without a nonce bypasses the cache entirely.
   * Defaults to unset: no replay detection (backwards compatible).
   *
   * Note: the cache is shared across `verifyAllLabels` labels and across
   * calls, so re-verifying the *same* request with the same cache is
   * itself reported as a replay — one cache per verifier lifetime is the
   * intended usage.
   */
  replayCache?: ReplayCache;
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
 * Validate the `key` / `keyResolver` pairing of a verify call. This is a
 * caller configuration error, not a verification failure, so it throws
 * rather than returning `{ ok: false }`.
 */
function assertKeyConfig(
  opts: Pick<VerifyOptions, "key" | "keyResolver">,
): void {
  if (opts.key !== undefined && opts.keyResolver !== undefined)
    throw new Error(
      "verifyRequest: `key` and `keyResolver` are mutually exclusive — pass one or the other",
    );
}

/**
 * Verify an RFC 9421 signed request: rebuild the signature base from the
 * covered components, check the cryptographic signature, then enforce
 * freshness (expires / created).
 *
 * Never throws on verification failure: returns `{ ok: false, code, reason }`.
 * For a throwing variant, see `verifyRequestOrThrow`.
 *
 * Throws only on caller configuration errors (e.g. both `key` and
 * `keyResolver` set, or neither set).
 */
export function verifyRequest(
  req: RequestLike,
  opts: VerifyOptions,
): VerifyResult {
  assertKeyConfig(opts);
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

  // Key resolution: `keyid`→key lookup happens here, after the header
  // parsed cleanly but before any crypto runs. The `keyid` claim is still
  // untrusted at this point — the cryptographic check below is what
  // authenticates it (the params are part of the signature base).
  let key: KeyObject | undefined = opts.key;
  if (opts.keyResolver !== undefined) {
    const claimedKeyId = parsed.params.keyid;
    if (claimedKeyId === undefined || claimedKeyId === "")
      return {
        ok: false,
        code: "KEY_RESOLUTION_FAILED",
        reason: "signature carries no keyid to resolve",
        label,
        alg: parsed.params.alg,
        nonce: parsed.params.nonce,
      };
    let resolved: KeyObject | undefined;
    try {
      resolved = opts.keyResolver(claimedKeyId);
    } catch (e) {
      return {
        ok: false,
        code: "VERIFICATION_ERROR",
        reason: `key resolver threw: ${(e as Error).message}`,
        label,
        keyId: claimedKeyId,
        alg: parsed.params.alg,
        nonce: parsed.params.nonce,
      };
    }
    if (resolved === undefined)
      return {
        ok: false,
        code: "KEY_RESOLUTION_FAILED",
        reason: `keyid "${claimedKeyId}" could not be resolved to a key`,
        label,
        keyId: claimedKeyId,
        alg: parsed.params.alg,
        nonce: parsed.params.nonce,
      };
    key = resolved;
  }
  if (key === undefined)
    throw new Error(
      "verifyRequest: either `key` or `keyResolver` must be provided",
    );

  let cryptoOk = false;
  try {
    if (alg === "ed25519") {
      cryptoOk = edVerify(null, Buffer.from(base, "utf8"), key, sigBytes);
    } else if (alg === "hmac-sha256") {
      const expected = createHmac("sha256", key).update(base, "utf8").digest();
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

  // Nonce replay detection: consulted only *after* the signature has
  // passed every check, so failed forgeries never pollute the cache.
  // Signatures without a (non-empty) nonce bypass the cache entirely.
  const nonce = parsed.params.nonce;
  const cache = opts.replayCache;
  if (cache !== undefined && nonce !== undefined && nonce !== "") {
    if (cache.check(nonce, now))
      return {
        ok: false,
        code: "NONCE_REPLAY",
        reason: `nonce replay detected: "${nonce}" was already seen`,
        label,
        keyId: parsed.params.keyid,
        alg,
        nonce,
      };
  }

  return {
    ok: true,
    label,
    keyId: parsed.params.keyid,
    alg,
    nonce,
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
   * Mutually exclusive with `keyResolver`: passing `keys` (or `key`)
   * together with `keyResolver` throws a configuration `Error`.
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
 * header. When the header is present but cannot even be split into
 * labels, returns a single-element array with `ok: false` and code
 * `MALFORMED_SIGNATURE_INPUT` (the header carries no usable label).
 * Like `verifyRequest`, this function never throws on malformed input.
 * Duplicate labels are verified once (first occurrence).
 */
export function verifyAllLabels(
  req: RequestLike,
  opts: VerifyAllOptions,
): VerifyResult[] {
  const sigInput = getHeader(req.headers, "signature-input");
  if (sigInput === undefined) return [];
  let labels: string[];
  try {
    labels = listSignatureLabels(sigInput);
  } catch (e) {
    return [
      {
        ok: false,
        code: "MALFORMED_SIGNATURE_INPUT",
        reason: `bad signature-input: ${(e as Error).message}`,
        label: "",
      },
    ];
  }
  return labels.map((label) => {
    const key = opts.keys?.[label] ?? opts.key;
    if (key !== undefined && opts.keyResolver !== undefined)
      throw new Error(
        "verifyAllLabels: `keys`/`key` is mutually exclusive with `keyResolver` — pass one or the other",
      );
    return verifyRequest(req, { ...opts, label, key });
  });
}
