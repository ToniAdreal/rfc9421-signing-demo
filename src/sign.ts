import { createHmac, sign as edSign, type KeyObject } from "node:crypto";
import {
  buildSignatureBase,
  signatureInputValue,
  type RequestLike,
  type SignatureParams,
} from "./components.js";
import { contentDigest } from "./digest.js";
import { assertHmacSecretLength } from "./keys.js";

export type SignAlg = "ed25519" | "hmac-sha256";

export interface SignOptions {
  keyId: string;
  alg: SignAlg;
  /**
   * ed25519: a private KeyObject (see keys.generateEd25519KeyPair).
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
 * Sign an HTTP request per RFC 9421. Returns a copy of the request with
 * `Signature-Input`, `Signature` (and `Content-Digest` when the body is
 * covered) headers attached. The input request is not mutated.
 */
export function signRequest(
  req: RequestLike,
  opts: SignOptions,
): SignedHttpRequest {
  const label = opts.label ?? "sig1";
  const created = opts.created ?? Math.floor(Date.now() / 1000);
  const covered =
    opts.coveredComponents ?? defaultCoveredComponents(req.body !== undefined);

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
