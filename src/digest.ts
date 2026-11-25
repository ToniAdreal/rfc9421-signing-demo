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
 * The body shapes the sign/verify path accepts. A `Uint8Array` holds
 * raw bytes exactly as received (e.g. a settlement receipt read with
 * `arrayBuffer()`, or a protobuf payload) — a form a UTF-8 string
 * cannot express — so it is a first-class body input alongside the
 * string and `Buffer` forms, normalized to bytes by `bodyToBuffer`
 * (backlog #1397).
 */
export type BodyInput = string | Buffer | Uint8Array;

/**
 * Normalize a message body to its exact bytes. A string encodes as
 * UTF-8; a `Buffer` passes through untouched; a `Uint8Array` is copied
 * into a `Buffer` holding exactly the viewed bytes — `Buffer.from(view)`
 * honors `byteOffset`/`byteLength`, so a subarray over a larger
 * backing store hashes only its slice, never the whole store. Any
 * other shape is a caller configuration error (thrown, never a
 * verification failure — the verifier guards first and reports
 * `VERIFICATION_ERROR` instead, see src/verify.ts).
 */
export function bodyToBuffer(body: BodyInput): Buffer {
  if (typeof body === "string") return Buffer.from(body, "utf8");
  if (Buffer.isBuffer(body)) return body;
  if (body instanceof Uint8Array) return Buffer.from(body);
  throw new Error(
    `body must be a string, a Buffer, or a Uint8Array, got ${typeof body}`,
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
 *
 * The body may be a string (UTF-8), a `Buffer`, or a `Uint8Array`
 * (backlog #1397) — all three hash the same bytes for the same content.
 */
export function contentDigest(
  body: BodyInput,
  alg: ContentDigestAlg = "sha-512",
): string {
  assertContentDigestAlg(alg);
  if (
    typeof body !== "string" &&
    !Buffer.isBuffer(body) &&
    !(body instanceof Uint8Array)
  )
    throw new Error(
      `contentDigest: "body" must be a string, a Buffer, or a Uint8Array, got ${typeof body}`,
    );
  const buf = bodyToBuffer(body);
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
  if (typeof value !== "string")
    throw new Error(
      `contentDigestAlgOf: "value" must be a string, got ${typeof value}`,
    );
  const alg = value.slice(0, value.indexOf("="));
  return alg === "sha-512" || alg === "sha-256" ? alg : undefined;
}

/**
 * RFC 3230 `Digest` hash algorithms this library can emit and verify
 * for legacy gateway interop. Only sha-256/sha-512: md5 is explicitly
 * out of scope — it is not a supported `DigestAlg`, `digest()` refuses
 * to emit it, and the verifier fails closed on it (see src/verify.ts).
 */
export type DigestAlg = "sha-256" | "sha-512";

/**
 * Fail fast on an unsupported `Digest` algorithm. This is a caller
 * configuration error (thrown), never a verification failure: the
 * signer must never emit a digest it cannot name on the wire.
 * Mirrors `assertContentDigestAlg` for the legacy header.
 */
export function assertDigestAlg(alg: unknown): asserts alg is DigestAlg {
  if (alg !== "sha-256" && alg !== "sha-512")
    throw new Error(
      `digest: "alg" must be "sha-256" or "sha-512", got ${JSON.stringify(alg)}`,
    );
}

/**
 * RFC 3230 `Digest` field value for a request body, emitted in the
 * same `alg=:base64:` rendering as `contentDigest` (e.g.
 * `sha-256=:qHycHWk7IkbwexRKk+xxmcx9yK3dOFd1TTawJhW6NrQ=:`).
 * Prefer `contentDigest` for new integrations: `Digest` exists only
 * for legacy payment gateways that still send `Digest` instead of
 * `Content-Digest`. Covering `digest` binds the body to the signature
 * on the verify side (see src/verify.ts): any tampering with the body
 * fails with `BODY_DIGEST_MISMATCH`, exactly like a `content-digest`
 * binding failure. The `alg` is required (no default) so the caller
 * names the algorithm the peer expects instead of silently getting
 * the library's preferred one.
 *
 * The body may be a string (UTF-8), a `Buffer`, or a `Uint8Array`
 * (backlog #1397) — all three hash the same bytes for the same content.
 */
export function digest(body: BodyInput, alg: DigestAlg): string {
  assertDigestAlg(alg);
  if (
    typeof body !== "string" &&
    !Buffer.isBuffer(body) &&
    !(body instanceof Uint8Array)
  )
    throw new Error(
      `digest: "body" must be a string, a Buffer, or a Uint8Array, got ${typeof body}`,
    );
  const buf = bodyToBuffer(body);
  return `${alg}=:${createHash(NODE_HASH_ALG[alg]).update(buf).digest("base64")}:`;
}
