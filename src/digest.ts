import { createHash } from "node:crypto";

/**
 * Content-Digest hash algorithms this library can emit when signing.
 * sha-512 is the default; sha-256 exists for peers (e.g. payment
 * gateways) that only accept sha-256 digests.
 */
export type ContentDigestAlg = "sha-512" | "sha-256";

const NODE_HASH_ALG: Record<ContentDigestAlg, string> = {
  "sha-512": "sha512",
  "sha-256": "sha256",
};

/**
 * Fail fast on an unsupported digest algorithm. This is a caller
 * configuration error (thrown), never a verification failure: the
 * signer must never emit a digest it cannot name on the wire.
 */
export function assertContentDigestAlg(
  alg: unknown,
): asserts alg is ContentDigestAlg {
  if (alg !== "sha-512" && alg !== "sha-256")
    throw new Error(
      `contentDigest: "alg" must be "sha-512" or "sha-256", got ${JSON.stringify(alg)}`,
    );
}

/**
 * RFC 9530 Content-Digest field value for a request body, defaulting to
 * sha-512. Pass `"sha-256"` when the peer only accepts sha-256 digests.
 * Covering this component binds the body to the signature: any tampering
 * with the body invalidates the signature.
 *
 * Signing emits sha-512 unless the caller opts into sha-256; the verifier
 * (src/verify.ts) additionally accepts sha-256 as a fallback when no
 * sha-512 entry is present, for foreign signers that only send sha-256.
 */
export function contentDigest(
  body: string | Buffer,
  alg: ContentDigestAlg = "sha-512",
): string {
  assertContentDigestAlg(alg);
  const buf = typeof body === "string" ? Buffer.from(body, "utf8") : body;
  return `${alg}=:${createHash(NODE_HASH_ALG[alg]).update(buf).digest("base64")}:`;
}

/**
 * Read the digest algorithm off an already-emitted Content-Digest header
 * value (e.g. `"sha-512=:...:"` → `"sha-512"`). Returns `undefined` for
 * algorithms this library cannot emit or for malformed values — the
 * caller decides whether that is a hard error (see `addSignature`,
 * where a second signature must cover the same wire value).
 */
export function contentDigestAlgOf(value: string): ContentDigestAlg | undefined {
  const alg = value.slice(0, value.indexOf("="));
  return alg === "sha-512" || alg === "sha-256" ? alg : undefined;
}
