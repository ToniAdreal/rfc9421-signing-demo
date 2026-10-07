import {
  createHmac,
  createSign,
  sign as edSign,
  type KeyObject,
} from "node:crypto";
import {
  buildSignatureBase,
  signatureInputValue,
  type RequestLike,
  type SignatureParams,
} from "./components.js";
import { contentDigest } from "./digest.js";
import { assertHmacSecretLength } from "./keys.js";

export type SignAlg = "ed25519" | "hmac-sha256" | "ecdsa-p256-sha256";

export interface SignOptions {
  keyId: string;
  alg: SignAlg;
  /**
   * ed25519: a private KeyObject (see keys.generateEd25519KeyPair).
   * ecdsa-p256-sha256: a P-256 private KeyObject (see
   * keys.generateP256KeyPair); signatures are DER-encoded ECDSA values
   * (RFC 9421 §3.3.2).
   * hmac-sha256: a secret KeyObject (see keys.secretKey).
   */
  key: KeyObject;
  /** Unix seconds. Defaults to now. */
  created?: number;
  /** Unix seconds. Optional; verifiers reject the signature after this time. */
  expires?: number;
  /** Signature label. Defaults to "sig1". */
  label?: string;
  /**
   * Optional nonce (RFC 9421 §2.3): emitted as a `nonce` signature-input
   * parameter and therefore covered by the signature. The verifier
   * returns it on `VerifyResult.nonce`; tracking seen nonces to detect
   * replays is the caller's job.
   */
  nonce?: string;
  /**
   * Covered components, in order. Defaults to
   * ["@method", "@authority", "@path"] plus "content-digest" when a body
   * is present.
   */
  coveredComponents?: string[];
}

export interface SignedHttpRequest {
  method: string;
  url: string;
  headers: Record<string, string>;
  body?: string | Buffer;
}

function defaultCoveredComponents(hasBody: boolean): string[] {
  return hasBody
    ? ["@method", "@authority", "@path", "content-digest"]
    : ["@method", "@authority", "@path"];
}

/**
 * `created`/`expires` are Unix seconds on the wire, and the verifier's
 * `signature-input` parser only recognizes the `-?\d+` integer shape.
 * Reject anything else here so the signer can never emit a timestamp the
 * verifier would silently truncate (e.g. `1759.5` → `1759`).
 */
function assertTimestamp(name: "created" | "expires", value: number): void {
  if (!Number.isInteger(value))
    throw new Error(
      `signRequest: "${name}" must be an integer number of Unix seconds, got ${value}`,
    );
}

/**
 * Sign an HTTP request per RFC 9421. Returns a copy of the request with
 * `Signature-Input`, `Signature` (and `Content-Digest` when the body is
 * covered) headers attached. The input request is not mutated.
 *
 * Fail-fast configuration errors (thrown, not embedded in the signature):
 * - `coveredComponents: []` signs nothing, so it is rejected;
 * - `created` / `expires` must be finite integers (Unix seconds) — the
 *   verifier's `signature-input` parser only recognizes integer values, so
 *   a fractional timestamp would silently diverge between signer and
 *   verifier;
 * - `expires < created` would mint a signature that is already expired, so
 *   it is rejected (`expires === created` is allowed).
 */
export function signRequest(
  req: RequestLike,
  opts: SignOptions,
): SignedHttpRequest {
  const label = opts.label ?? "sig1";
  const created = opts.created ?? Math.floor(Date.now() / 1000);
  assertTimestamp("created", created);
  if (opts.expires !== undefined) {
    assertTimestamp("expires", opts.expires);
    if (opts.expires < created)
      throw new Error(
        `signRequest: "expires" (${opts.expires}) must not be earlier than "created" (${created}); the signature would be expired at birth`,
      );
  }
  const covered =
    opts.coveredComponents ?? defaultCoveredComponents(req.body !== undefined);
  if (covered.length === 0)
    throw new Error(
      'signRequest: "coveredComponents" must cover at least one component; an empty list would sign nothing',
    );

  const headers: Record<string, string> = {};
  for (const [k, v] of Object.entries(req.headers)) {
    if (v === undefined) continue;
    headers[k] = Array.isArray(v) ? v.join(", ") : v;
  }
  if (covered.map((c) => c.toLowerCase()).includes("content-digest")) {
    if (req.body === undefined)
      throw new Error('content-digest is covered but the request has no body');
    headers["content-digest"] = contentDigest(req.body);
  }

  const params: SignatureParams = { created, keyid: opts.keyId, alg: opts.alg };
  if (opts.expires !== undefined) params.expires = opts.expires;
  if (opts.nonce !== undefined) params.nonce = opts.nonce;

  const signingInput: RequestLike = {
    method: req.method,
    url: req.url,
    headers,
    body: req.body,
  };
  const base = buildSignatureBase(covered, signingInput, params);

  let sig: Buffer;
  if (opts.alg === "ed25519") {
    sig = edSign(null, Buffer.from(base, "utf8"), opts.key);
  } else if (opts.alg === "ecdsa-p256-sha256") {
    // RFC 9421 §3.3.2: the signature value is the DER encoding of the
    // ASN.1 ECDSA structure. node:crypto's createSign emits exactly that
    // by default, and verifyRequest consumes it with createVerify below.
    sig = createSign("sha256").update(base, "utf8").sign(opts.key);
  } else if (opts.alg === "hmac-sha256") {
    // Fail fast on weak secrets: a short key must never silently mint
    // signatures the verifier would also (correctly) refuse to check.
    assertHmacSecretLength(opts.key);
    sig = createHmac("sha256", opts.key).update(base, "utf8").digest();
  } else {
    throw new Error(`unsupported alg "${opts.alg as string}"`);
  }

  headers["signature-input"] = signatureInputValue(label, covered, params);
  headers["signature"] = `${label}=:${sig.toString("base64")}:`;

  return { method: req.method, url: req.url, headers, body: req.body };
}
