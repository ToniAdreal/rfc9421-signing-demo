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

/** Wrap a shared secret for hmac-sha256. */
export function secretKey(secret: string | Buffer): KeyObject {
  return createSecretKey(
    typeof secret === "string" ? Buffer.from(secret, "utf8") : secret,
  );
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
