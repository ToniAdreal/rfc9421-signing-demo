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
 * Generate a fresh NIST P-256 (secp256r1) key pair for the
 * `ecdsa-p256-sha256` algorithm (RFC 9421 §3.3.4). The signatures
 * produced from this pair are DER-encoded ASN.1 ECDSA values, per the
 * RFC — `signRequest` / `verifyRequest` both use node:crypto's default
 * DER encoding, so the wire format stays spec-conformant.
 */
export function generateP256KeyPair(): {
  publicKey: KeyObject;
  privateKey: KeyObject;
} {
  return generateKeyPairSync("ec", { namedCurve: "P-256" });
}

/**
 * Generate a fresh RSA key pair for the `rsa-pss-sha512` algorithm
 * (RFC 9421 §3.3.1: RSASSA-PSS with SHA-512, MGF1 with SHA-512, and a
 * 64-byte salt). 2048-bit modulus is the minimum recommended size for
 * this demo; production deployments should prefer ≥3072 bits.
 * `signRequest` / `verifyRequest` both use PSS padding with
 * `saltLength: 64` per the RFC, so the wire format stays spec-conformant.
 */
export function generateRsaPssKeyPair(): {
  publicKey: KeyObject;
  privateKey: KeyObject;
} {
  return generateKeyPairSync("rsa", { modulusLength: 2048 });
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

/**
 * Public-key-only JWK view of an ed25519 key, exactly as produced by
 * `exportPublicKeyJwk`. Deliberately narrow: this demo only needs ed25519
 * public keys (the public-key-distribution case in webhook / gateway
 * deployments, where PEM is awkward to ship). Private JWKs (`"d"`
 * present) are never produced or accepted here.
 */
export interface Ed25519PublicJwk {
  kty: "OKP";
  crv: "Ed25519";
  /** Base64url-encoded 32-byte ed25519 public key. */
  x: string;
}

/**
 * Export an ed25519 public key as a plain-object JWK (RFC 8037), ready to
 * `JSON.stringify` and ship to a verifier. Uses node:crypto's native JWK
 * support — no third-party dependencies.
 *
 * Throws a caller-configuration `Error` for anything that is not an
 * ed25519 public KeyObject (private keys, symmetric secrets, other
 * algorithms); this helper is the public-key-distribution case only.
 */
export function exportPublicKeyJwk(key: KeyObject): Ed25519PublicJwk {
  if (key.type !== "public" || key.asymmetricKeyType !== "ed25519")
    throw new Error(
      `exportPublicKeyJwk: expected an ed25519 public KeyObject, got ` +
        `type=${String(key.type)} ` +
        `asymmetricKeyType=${String(key.asymmetricKeyType)} ` +
        `(JWK support here is ed25519 public keys only — the public-key-distribution case)`,
    );
  const raw = key.export({ format: "jwk" }) as unknown as Record<
    string,
    unknown
  >;
  // Node emits exactly { kty: "OKP", crv: "Ed25519", x: "<base64url>" }.
  if (
    raw["kty"] !== "OKP" ||
    raw["crv"] !== "Ed25519" ||
    typeof raw["x"] !== "string"
  )
    throw new Error(
      "exportPublicKeyJwk: node:crypto returned an unexpected JWK shape " +
        `for an ed25519 public key: ${JSON.stringify(Object.keys(raw))}`,
    );
  return { kty: "OKP", crv: "Ed25519", x: raw["x"] };
}

/**
 * Import an ed25519 public key from a JWK object (RFC 8037), as produced by
 * {@link exportPublicKeyJwk} and typically received over the wire as JSON.
 *
 * Strictly validates before touching node:crypto: the input must be a
 * plain object with `kty: "OKP"`, `crv: "Ed25519"`, and a non-empty string
 * `x`. Anything else throws a descriptive `Error` — never a verification
 * failure, since this is key setup, not signature checking. JWKs carrying
 * private material (`"d"`) are refused outright: this helper is public-key
 * distribution only, and silently accepting a private JWK would encourage
 * shipping secrets around.
 */
export function importPublicKeyJwk(jwk: unknown): KeyObject {
  const fail = (why: string): never => {
    throw new Error(`importPublicKeyJwk: invalid JWK: ${why}`);
  };
  if (typeof jwk !== "object" || jwk === null || Array.isArray(jwk))
    fail(
      `expected a JWK object, got ${
        Array.isArray(jwk) ? "an array" : jwk === null ? "null" : typeof jwk
      }`,
    );
  const o = jwk as Record<string, unknown>;
  if ("d" in o)
    fail(
      'private key material ("d") is not accepted; this helper imports ' +
        "public keys only (keep private keys in PEM on the signer side)",
    );
  if (!("kty" in o)) fail(`missing "kty" parameter`);
  if (o["kty"] !== "OKP")
    fail(`expected kty "OKP", got ${JSON.stringify(o["kty"])}`);
  if (!("crv" in o)) fail(`missing "crv" parameter`);
  if (o["crv"] !== "Ed25519")
    fail(`expected crv "Ed25519", got ${JSON.stringify(o["crv"])}`);
  const x = o["x"];
  if (typeof x !== "string" || x.length === 0)
    throw new Error(
      `importPublicKeyJwk: invalid JWK: missing or empty "x" (the base64url public key parameter)`,
    );
  try {
    return createPublicKey({
      key: { kty: "OKP", crv: "Ed25519", x },
      format: "jwk",
    });
  } catch (err) {
    throw new Error(
      `importPublicKeyJwk: node:crypto rejected the JWK: ${
        err instanceof Error ? err.message : String(err)
      }`,
    );
  }
}
