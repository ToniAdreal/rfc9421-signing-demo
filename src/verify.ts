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
  parseSignatureField,
  parseSignatureInput,
  type RequestLike,
} from "./components.js";

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
}

export interface VerifyResult {
  ok: boolean;
  reason?: string;
  label: string;
  keyId?: string;
  alg?: string;
}

/**
 * Verify an RFC 9421 signed request: rebuild the signature base from the
 * covered components, check the cryptographic signature, then enforce
 * freshness (expires / created).
 */
export function verifyRequest(
  req: RequestLike,
  opts: VerifyOptions,
): VerifyResult {
  const label = opts.label ?? "sig1";
  const now = opts.now ?? Math.floor(Date.now() / 1000);
  const skew = opts.clockSkewToleranceSec ?? 60;

  const sigInput = getHeader(req.headers, "signature-input");
  if (!sigInput)
    return { ok: false, reason: "missing signature-input header", label };
  const sigField = getHeader(req.headers, "signature");
  if (!sigField)
    return { ok: false, reason: "missing signature header", label };

  let parsed;
  try {
    parsed = parseSignatureInput(sigInput, label);
  } catch (e) {
    return {
      ok: false,
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
      reason: `bad signature field: ${(e as Error).message}`,
      label,
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
      return { ok: false, reason: `unsupported alg "${alg}"`, label };
    }
  } catch (e) {
    return {
      ok: false,
      reason: `verification error: ${(e as Error).message}`,
      label,
    };
  }
  if (!cryptoOk)
    return {
      ok: false,
      reason: "signature mismatch",
      label,
      keyId: parsed.params.keyid,
      alg,
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
        reason: "cannot verify body: no sha-512 content-digest present",
        label,
        keyId: parsed.params.keyid,
        alg,
      };
    const expected = createHash("sha512").update(bodyBytes).digest();
    const actual = Buffer.from(dm[1], "base64");
    if (actual.length !== expected.length || !timingSafeEqual(actual, expected))
      return {
        ok: false,
        reason: "body does not match content-digest",
        label,
        keyId: parsed.params.keyid,
        alg,
      };
  }

  if (parsed.params.expires !== undefined && now > parsed.params.expires)
    return {
      ok: false,
      reason: "signature expired",
      label,
      keyId: parsed.params.keyid,
      alg,
    };
  if (
    parsed.params.created !== undefined &&
    parsed.params.created > now + skew
  )
    return {
      ok: false,
      reason: "signature created in the future (clock skew)",
      label,
      keyId: parsed.params.keyid,
      alg,
    };

  return { ok: true, label, keyId: parsed.params.keyid, alg };
}
