import {
  createPrivateKey,
  createPublicKey,
  createSecretKey,
  generateKeyPairSync,
  type KeyObject,
} from "node:crypto";

/** Generate a fresh ed25519 key pair for signing / verification. */
export function generateEd25519KeyPair(): {
  publicKey: KeyObject;
  privateKey: KeyObject;
} {
  return generateKeyPairSync("ed25519");
}

/**
 * Minimum HMAC shared-secret length in bytes. RFC 2104 §3 advises that the
 * HMAC key be at least as long as the hash output; for hmac-sha256 that is
 * 32 bytes. Shorter keys are brute-forceable and are rejected everywhere
 * this library consumes an HMAC secret (`secretKey`, `signRequest`, and
 * `verifyRequest`), so a weak key fails loudly at setup time instead of
 * producing signatures of dubious strength.
 */
export const MIN_HMAC_SECRET_BYTES = 32;

/**
 * Enforce {@link MIN_HMAC_SECRET_BYTES} on an HMAC secret KeyObject.
 * Throws a caller-configuration `Error` — not a verification failure —
 * so both the sign and verify sides fail identically on a weak key.
 * Asymmetric keys passed here are also rejected (they are never valid
 * HMAC secrets); use {@link secretKey} or `node:crypto`'s
 * `createSecretKey` with ≥ 32 bytes of entropy.
 */
export function assertHmacSecretLength(key: KeyObject): void {
  const size = key.symmetricKeySize;
  if (size === undefined)
    throw new Error(
      "assertHmacSecretLength: expected a symmetric secret KeyObject " +
        "(see keys.secretKey), got a non-symmetric key",
    );
  if (size < MIN_HMAC_SECRET_BYTES)
    throw new Error(
      `assertHmacSecretLength: hmac-sha256 secret must be at least ` +
        `${MIN_HMAC_SECRET_BYTES} bytes (RFC 2104: the key SHOULD be at least ` +
        `as long as the hash output; sha-256 → ${MIN_HMAC_SECRET_BYTES} ` +
        `bytes), got ${size} bytes`,
    );
}

/** Wrap a shared secret for hmac-sha256. */
export function secretKey(secret: string | Buffer): KeyObject {
  const bytes =
    typeof secret === "string" ? Buffer.from(secret, "utf8") : secret;
  if (bytes.length < MIN_HMAC_SECRET_BYTES)
    throw new Error(
      `secretKey: hmac secret must be at least ${MIN_HMAC_SECRET_BYTES} bytes ` +
        `(RFC 2104: the key SHOULD be at least as long as the hash output; ` +
        `sha-256 → ${MIN_HMAC_SECRET_BYTES} bytes), got ${bytes.length} bytes`,
    );
  return createSecretKey(bytes);
}

export function importPrivateKey(pem: string | Buffer): KeyObject {
  return createPrivateKey(pem);
}

export function importPublicKey(pem: string | Buffer): KeyObject {
  return createPublicKey(pem);
}

export function exportPrivateKeyPem(key: KeyObject): string {
  return key.export({ format: "pem", type: "pkcs8" }).toString();
}

export function exportPublicKeyPem(key: KeyObject): string {
  return key.export({ format: "pem", type: "spki" }).toString();
}
