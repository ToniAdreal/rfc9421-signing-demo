import {
  constants,
  createHash,
  createHmac,
  createVerify,
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
import { assertHmacSecretLength } from "./keys.js";
import type { NonceStore } from "./replay.js";

export interface VerifyOptions {
  /**
   * ed25519: the signer's public KeyObject.
   * ecdsa-p256-sha256: the signer's P-256 public KeyObject.
   * rsa-pss-sha512: the signer's RSA public KeyObject (verified with
   * RSASSA-PSS, SHA-512, MGF1 with SHA-512, 64-byte salt — RFC 9421
   * §3.3.1).
   * hmac-sha256: the shared secret KeyObject (≥ 32 bytes).
   * hmac-sha512: the shared secret KeyObject (≥ 64 bytes).
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
   * Reject signatures that carry no `created` parameter. RFC 9421 leaves
   * `created` optional and this library's `signRequest` always sends it,
   * but a hand-rolled or third-party signature may omit it — an omitted
   * timestamp is a signature with no bounded age, which some verifiers
   * must not accept. Defaults to false (backwards compatible): no check
   * is made unless you opt in. Fails with `MISSING_CREATED`, checked
   * only *after* the cryptographic check, so forgeries are still
   * reported as `SIGNATURE_MISMATCH`.
   */
  requireCreated?: boolean;
  /**
   * Reject signatures that carry no `expires` parameter. Same rationale
   * as `requireCreated`, but for bounded lifetimes. Defaults to false.
   * Fails with `MISSING_EXPIRES`, checked only *after* the cryptographic
   * check.
   */
  requireExpires?: boolean;
  /**
   * Maximum acceptable signature age, in seconds (opt-in). When set, a
   * signature whose `created` timestamp is older than this is rejected
   * with `SIGNATURE_TOO_OLD` — even when it carries no `expires` (an old
   * signature that would otherwise be accepted indefinitely). This is
   * the webhook-timestamp-window analog (cf. Stripe's few-minutes
   * tolerance): it bounds replayability of long-lived signed messages
   * without requiring a nonce replay cache. Must be a non-negative
   * finite number — anything else throws a caller configuration `Error`.
   *
   * Defaults to unset (backwards compatible): no age check is made.
   * Checked *after* the cryptographic check and the `expires`/`created`
   * window checks, so forgeries still report `SIGNATURE_MISMATCH`, and
   * *before* the nonce replay cache. A signature that carries no
   * `created` parameter never triggers this check — orthogonal to
   * `requireCreated`: combine the two when an undated signature must be
   * rejected rather than passed through.
   */
  maxSignatureAgeSec?: number;
  /**
   * Optional `keyid` pinning (key-confusion protection): after the
   * cryptographic check passes, the `keyid` claimed in the
   * signature-input must equal this value, otherwise verification
   * fails with `KEYID_MISMATCH`. A signature that carries no `keyid`
   * also fails when this is set. Defaults to unset: no check is made.
   * In `verifyAllLabels` the same expectation applies to every label,
   * unless overridden per label via `VerifyAllOptions.expectedKeyIds`.
   */
  expectedKeyId?: string;
  /**
   * Fallback strategy when the `signature-input` carries no `alg`
   * parameter. RFC 9421 leaves `alg` optional (Appendix B.2.5's
   * hmac-sha256 vector omits it), while this library historically
   * defaults a missing `alg` to `"ed25519"` — so a spec-conformant
   * foreign signature without `alg` could not previously be verified
   * end-to-end.
   *
   * - `"infer"` (explicit opt-in): when `alg` is absent, the verifier
   *   infers the algorithm from the *resolved* key's shape — a `secret`
   *   key implies `hmac-sha256`, an ed25519 key implies `ed25519`, a
   *   P-256 (`prime256v1`) EC key implies `ecdsa-p256-sha256`, and an
   *   RSA key implies `rsa-pss-sha512`; an unmappable key shape throws
   *   a caller configuration `Error`. When
   *   the wire *does* carry `alg`, the key's shape is checked against
   *   it and a mismatch (e.g. wire `alg="ed25519"` with a `secret`
   *   key) throws a caller configuration `Error` instead of surfacing
   *   as a confusing `VERIFICATION_ERROR` from the crypto layer.
   * - unset or `false` (default): legacy behavior — a missing `alg`
   *   defaults to `"ed25519"` and no key-shape checking is done.
   *
   * Automatic detection is opt-in only: the default path is untouched
   * (a missing `alg` without this option keeps meaning `"ed25519"`).
   */
  algFallback?: "infer" | false;
  /**
   * Optional nonce replay store (see `NonceStore`). When set and the
   * signature carries a non-empty `nonce`, the store is consulted *after*
   * every other check has passed: a nonce already seen fails with
   * `NONCE_REPLAY`, otherwise the nonce is recorded. Failed
   * verifications never record anything, so forgeries cannot pollute the
   * store. A signature without a nonce bypasses the store entirely.
   * Defaults to unset: no replay detection (backwards compatible).
   *
   * `ReplayCache` is the built-in in-memory implementation; implement
   * `NonceStore` over shared storage (e.g. Redis) for multi-instance
   * deployments — see SECURITY.md for an example. The call is
   * synchronous, so an async backend must be checked in the caller's own
   * layer, not inside `check`.
   *
   * Note: the store is shared across `verifyAllLabels` labels and across
   * calls, so re-verifying the *same* request with the same store is
   * itself reported as a replay — one store per verifier lifetime is the
   * intended usage.
   */
  replayCache?: NonceStore;
  /**
   * Require the signature to cover specific components (opt-in component
   * coverage policy). A signature covering only `"@method"` is
   * cryptographically valid, but it protects nothing — a payment-gateway
   * verifier typically wants `content-digest` (so the body cannot be
   * swapped) and/or `@path` (so the URL target cannot be changed)
   * covered. When set and non-empty, every listed component must appear
   * in the signature's covered component list, otherwise verification
   * fails with `MISSING_REQUIRED_COMPONENT`. The check is
   * case-insensitive (matching the `cid.toLowerCase()` convention of
   * `resolveComponent`) and happens *before* any cryptographic work:
   * a missing component is a policy violation, not an authenticity
   * verdict. An empty array disables the check. Defaults to unset:
   * no check is made (backwards compatible). Composes with
   * `verifyAllLabels` (checked independently per label).
   *
   * A malformed value (non-array, or a non-string / empty-string entry)
   * is a caller configuration error (throw), in the same style as
   * `expectedKeyIds`.
   */
  requiredComponents?: string[];
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
 * Validate the `maxSignatureAgeSec` option. A bogus window is a caller
 * configuration error (throw), not a verification failure.
 */
function assertMaxSignatureAgeSec(value: number | undefined): void {
  if (value === undefined) return;
  if (typeof value !== "number" || !Number.isFinite(value) || value < 0)
    throw new Error(
      `verifyRequest: \`maxSignatureAgeSec\` must be a non-negative finite number, got ${typeof value === "number" ? String(value) : typeof value}`,
    );
}

/** The RFC 9421 signature algorithms this library implements. */
type SupportedAlg =
  | "ed25519"
  | "hmac-sha256"
  | "hmac-sha512"
  | "ecdsa-p256-sha256"
  | "rsa-pss-sha512";

/**
 * Human-readable description of a KeyObject's shape, used in caller
 * configuration error messages.
 */
function describeKey(key: KeyObject): string {
  if (key.type === "secret") return "a secret (symmetric) key";
  const curve = key.asymmetricKeyDetails?.namedCurve;
  return `an asymmetric ${key.asymmetricKeyType ?? "unknown"} key${
    curve ? ` (${curve})` : ""
  }`;
}

/**
 * Infer the signature algorithm from the resolved key's shape. Used only
 * under the explicit `algFallback: "infer"` opt-in, when the
 * signature-input carries no `alg` parameter. An unmappable key shape is
 * a caller configuration error (throw), not a verification failure.
 */
function inferAlgFromKeyShape(key: KeyObject): SupportedAlg {
  if (key.type === "secret") return "hmac-sha256";
  if (key.asymmetricKeyType === "ed25519") return "ed25519";
  if (
    key.asymmetricKeyType === "ec" &&
    key.asymmetricKeyDetails?.namedCurve === "prime256v1"
  )
    return "ecdsa-p256-sha256";
  if (key.asymmetricKeyType === "rsa") return "rsa-pss-sha512";
  throw new Error(
    `verifyRequest: algFallback "infer" cannot infer an algorithm for ${describeKey(key)} — supported key shapes are secret keys (hmac-sha256), ed25519 keys, P-256 (prime256v1) EC keys, and RSA keys (rsa-pss-sha512)`,
  );
}

/**
 * Under the explicit `algFallback: "infer"` opt-in, a wire-carried `alg`
 * must agree with the resolved key's shape. A mismatch (e.g. wire
 * `alg="ed25519"` with a `secret` key) is a caller configuration error
 * (throw) rather than a confusing `VERIFICATION_ERROR` from the crypto
 * layer. Unknown `alg` values are left alone: they still fail with
 * `UNSUPPORTED_ALG` in the crypto dispatch below.
 */
function assertAlgMatchesKeyShape(alg: SupportedAlg, key: KeyObject): void {
  const ok =
    (alg === "ed25519" && key.asymmetricKeyType === "ed25519") ||
    (alg === "hmac-sha256" && key.type === "secret") ||
    (alg === "hmac-sha512" && key.type === "secret") ||
    (alg === "ecdsa-p256-sha256" &&
      key.asymmetricKeyType === "ec" &&
      key.asymmetricKeyDetails?.namedCurve === "prime256v1") ||
    (alg === "rsa-pss-sha512" && key.asymmetricKeyType === "rsa");
  if (ok) return;
  throw new Error(
    `verifyRequest: wire alg "${alg}" is incompatible with the configured key (${describeKey(key)}) — pass a matching key or remove the algFallback "infer" opt-in`,
  );
}

/**
 * Validate the `requiredComponents` option. A malformed list is a caller
 * configuration error, not a verification failure, so it throws rather
 * than returning `{ ok: false }`.
 */
function assertRequiredComponents(
  components: string[] | undefined,
): void {
  if (components === undefined) return;
  if (!Array.isArray(components))
    throw new Error(
      "verifyRequest: `requiredComponents` must be an array of component identifiers",
    );
  for (const c of components) {
    if (typeof c !== "string" || c === "")
      throw new Error(
        `verifyRequest: \`requiredComponents\` entries must be non-empty strings, got ${typeof c === "string" ? '""' : typeof c}`,
      );
  }
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
 * `keyResolver` set, or neither set — and a configured HMAC secret shorter
 * than the per-algorithm floor (≥ 32 bytes for `hmac-sha256`, ≥ 64 bytes
 * for `hmac-sha512`), which is rejected loudly on both the sign and verify
 * sides).
 */
export function verifyRequest(
  req: RequestLike,
  opts: VerifyOptions,
): VerifyResult {
  assertKeyConfig(opts);
  assertMaxSignatureAgeSec(opts.maxSignatureAgeSec);
  assertRequiredComponents(opts.requiredComponents);
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
  // Required covered components (opt-in, fail-fast policy check): a
  // signature covering only "@method" is cryptographically valid but
  // protects nothing. This runs *before* any crypto work — a missing
  // component is a policy violation, not an authenticity verdict — and
  // is case-insensitive, matching the `cid.toLowerCase()` convention of
  // `resolveComponent`.
  const requiredComponents = opts.requiredComponents;
  if (requiredComponents !== undefined && requiredComponents.length > 0) {
    const covered = new Set(
      parsed.componentIds.map((c) => c.toLowerCase()),
    );
    const missing = requiredComponents.filter(
      (r) => !covered.has(r.toLowerCase()),
    );
    if (missing.length > 0)
      return {
        ok: false,
        code: "MISSING_REQUIRED_COMPONENT",
        reason: `signature does not cover required component${missing.length === 1 ? "" : "s"}: ${missing
          .map((m) => `"${m}"`)
          .join(", ")}`,
        label,
        keyId: parsed.params.keyid,
        alg: parsed.params.alg,
        nonce: parsed.params.nonce,
      };
  }
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

  const alg = parsed.params.alg;

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

  // Algorithm selection. RFC 9421 leaves `alg` optional, so a
  // spec-conformant foreign signature may not carry it (RFC 9421
  // Appendix B.2.5's hmac-sha256 vector omits it). The historical
  // default for a missing `alg` is "ed25519"; `algFallback: "infer"` is
  // an explicit opt-in that instead infers the algorithm from the
  // resolved key's shape — automatic detection never happens silently.
  // Under the opt-in, a wire-carried `alg` that contradicts the key's
  // shape is a caller configuration error (throw), not a verification
  // failure; without the opt-in, that path stays exactly as before.
  const effectiveAlg: string =
    alg === undefined
      ? opts.algFallback === "infer"
        ? inferAlgFromKeyShape(key)
        : "ed25519"
      : alg;
  if (
    opts.algFallback === "infer" &&
    (effectiveAlg === "ed25519" ||
      effectiveAlg === "hmac-sha256" ||
      effectiveAlg === "hmac-sha512" ||
      effectiveAlg === "ecdsa-p256-sha256" ||
      effectiveAlg === "rsa-pss-sha512") &&
    alg !== undefined
  ) {
    assertAlgMatchesKeyShape(effectiveAlg, key);
  }

  // HMAC key-length enforcement happens *before* the crypto try/catch on
  // purpose: a weak configured secret is a caller configuration error
  // (throw), not a verification failure — symmetric with the sign side,
  // which also throws. It must not be swallowed into a VERIFICATION_ERROR.
  // The floor is paired with the algorithm (RFC 2104 §3): hmac-sha256 →
  // ≥ 32 bytes, hmac-sha512 → ≥ 64 bytes.
  if (effectiveAlg === "hmac-sha256" || effectiveAlg === "hmac-sha512")
    assertHmacSecretLength(key, effectiveAlg);

  let cryptoOk = false;
  try {
    if (effectiveAlg === "ed25519") {
      cryptoOk = edVerify(null, Buffer.from(base, "utf8"), key, sigBytes);
    } else if (effectiveAlg === "ecdsa-p256-sha256") {
      // Expects the DER-encoded ECDSA value that createSign produces on
      // the sign side (RFC 9421 §3.3.4).
      cryptoOk = createVerify("sha256")
        .update(base, "utf8")
        .verify(key, sigBytes);
    } else if (effectiveAlg === "rsa-pss-sha512") {
      // RSASSA-PSS-VERIFY per RFC 9421 §3.3.1: SHA-512, MGF1 with
      // SHA-512, 64-byte salt — the same parameters the sign side uses,
      // so a v1.5 (PKCS#1 padding) signature never verifies here.
      cryptoOk = createVerify("sha512")
        .update(base, "utf8")
        .verify(
          {
            key,
            padding: constants.RSA_PKCS1_PSS_PADDING,
            saltLength: 64,
          },
          sigBytes,
        );
    } else if (effectiveAlg === "hmac-sha256") {
      const expected = createHmac("sha256", key).update(base, "utf8").digest();
      cryptoOk =
        sigBytes.length === expected.length &&
        timingSafeEqual(sigBytes, expected);
    } else if (effectiveAlg === "hmac-sha512") {
      // SHA-512 twin of the hmac-sha256 branch: constant-time compare
      // against the recomputed MAC. A hmac-sha256 signature never
      // verifies here and vice versa — the digest lengths differ (32 vs
      // 64 bytes) and the MAC constructions differ, so the two
      // algorithms cannot be confused with each other.
      const expected = createHmac("sha512", key).update(base, "utf8").digest();
      cryptoOk =
        sigBytes.length === expected.length &&
        timingSafeEqual(sigBytes, expected);
    } else {
      return {
        ok: false,
        code: "UNSUPPORTED_ALG",
        reason: `unsupported alg "${effectiveAlg}"`,
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
      alg: effectiveAlg,
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
      alg: effectiveAlg,
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
    // Prefer sha-512 when the header carries both algorithms; fall back to
    // sha-256 when no sha-512 entry is present (RFC 9530 allows either).
    // Signing still emits sha-512 only (see src/digest.ts); the fallback
    // exists for foreign signers that only send sha-256.
    const dm512 = /(?:^|,)\s*sha-512\s*=:([A-Za-z0-9+/=]+):/.exec(digestHeader);
    const dm256 = /(?:^|,)\s*sha-256\s*=:([A-Za-z0-9+/=]+):/.exec(digestHeader);
    const dm = dm512 ?? dm256;
    if (!dm)
      return {
        ok: false,
        code: "MISSING_CONTENT_DIGEST",
        reason:
          "cannot verify body: no sha-512 or sha-256 content-digest present",
        label,
        keyId: parsed.params.keyid,
        alg: effectiveAlg,
        nonce: parsed.params.nonce,
      };
    const expected = createHash(dm === dm512 ? "sha512" : "sha256")
      .update(bodyBytes)
      .digest();
    const actual = Buffer.from(dm[1], "base64");
    if (actual.length !== expected.length || !timingSafeEqual(actual, expected))
      return {
        ok: false,
        code: "BODY_DIGEST_MISMATCH",
        reason: "body does not match content-digest",
        label,
        keyId: parsed.params.keyid,
        alg: effectiveAlg,
        nonce: parsed.params.nonce,
      };
  }

  // Freshness: the `created`/`expires` parameters are optional on the
  // wire, so the window checks below only apply when the signer sent
  // them. `requireCreated`/`requireExpires` let a verifier demand their
  // presence; the check happens here, after the cryptographic check, so
  // a forged undated signature is still reported as SIGNATURE_MISMATCH
  // rather than being mistaken for a mere policy violation.
  if (opts.requireCreated === true && parsed.params.created === undefined)
    return {
      ok: false,
      code: "MISSING_CREATED",
      reason: "signature carries no `created` timestamp but requireCreated is set",
      label,
      keyId: parsed.params.keyid,
      alg: effectiveAlg,
      nonce: parsed.params.nonce,
    };
  if (opts.requireExpires === true && parsed.params.expires === undefined)
    return {
      ok: false,
      code: "MISSING_EXPIRES",
      reason: "signature carries no `expires` timestamp but requireExpires is set",
      label,
      keyId: parsed.params.keyid,
      alg: effectiveAlg,
      nonce: parsed.params.nonce,
    };

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
      alg: effectiveAlg,
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
      alg: effectiveAlg,
      nonce: parsed.params.nonce,
    };

  // Maximum signature age (opt-in webhook-timestamp window): an old
  // `created` with no `expires` would otherwise be accepted forever.
  // Checked after the crypto and freshness-window checks so forgeries
  // still report their true failure mode, and before the nonce replay
  // cache. A signature with no `created` parameter bypasses this check
  // entirely — orthogonal to `requireCreated`.
  const maxAge = opts.maxSignatureAgeSec;
  if (
    maxAge !== undefined &&
    parsed.params.created !== undefined &&
    now - parsed.params.created > maxAge
  )
    return {
      ok: false,
      code: "SIGNATURE_TOO_OLD",
      reason: `signature is too old: created ${now - parsed.params.created}s ago, older than maxSignatureAgeSec=${maxAge}`,
      label,
      keyId: parsed.params.keyid,
      alg: effectiveAlg,
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
        alg: effectiveAlg,
        nonce,
      };
  }

  return {
    ok: true,
    label,
    keyId: parsed.params.keyid,
    alg: effectiveAlg,
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
  /**
   * Per-label `keyid` pinning for multi-party signatures: maps a
   * signature label to the `keyid` that label is expected to carry
   * (key-confusion defense when the merchant and the gateway use
   * different key ids). A label absent from the map falls back to the
   * global `expectedKeyId`. Values must be non-empty strings — any
   * other value is a caller configuration error (throw).
   */
  expectedKeyIds?: Record<string, string>;
}

/**
 * Validate the per-label `keyid` pinning map. A malformed map is a
 * caller configuration error, not a verification failure, so it throws
 * rather than returning `{ ok: false }`.
 */
function assertExpectedKeyIds(
  map: Record<string, string> | undefined,
): void {
  if (map === undefined) return;
  if (typeof map !== "object" || map === null || Array.isArray(map))
    throw new Error(
      "verifyAllLabels: `expectedKeyIds` must be a label→keyid object",
    );
  for (const [label, keyId] of Object.entries(map)) {
    if (typeof keyId !== "string" || keyId === "")
      throw new Error(
        `verifyAllLabels: \`expectedKeyIds["${label}"]\` must be a non-empty string, got ${typeof keyId === "string" ? '""' : typeof keyId}`,
      );
  }
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
  assertExpectedKeyIds(opts.expectedKeyIds);
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
    // Per-label keyid pinning: a label pinned in `expectedKeyIds` is
    // checked against its own expectation; every other label falls back
    // to the global `expectedKeyId` (unset means no pinning for it).
    const expectedKeyId = opts.expectedKeyIds?.[label] ?? opts.expectedKeyId;
    return verifyRequest(req, { ...opts, label, key, expectedKeyId });
  });
}
