import { createHash } from "node:crypto";

/**
 * RFC 9530 Content-Digest field value for a request body, using sha-512.
 * Covering this component binds the body to the signature: any tampering
 * with the body invalidates the signature.
 */
export function contentDigest(body: string | Buffer): string {
  const buf = typeof body === "string" ? Buffer.from(body, "utf8") : body;
  return `sha-512=:${createHash("sha512").update(buf).digest("base64")}:`;
}
