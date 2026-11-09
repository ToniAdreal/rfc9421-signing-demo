import {
  createHash,
  createPrivateKey,
  createPublicKey,
  createSecretKey,
  generateKeyPairSync,
  randomBytes,
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
 * produced from this pair are the raw concatenation of the two ECDSA
 * integers r and s, each padded to 32 octets (64 octets in total), as
 * §3.3.4 defines — `signRequest` / `verifyRequest` both pass
 * `dsaEncoding: "ieee-p1363"` to node:crypto, so the wire format stays
 * spec-conformant.
 */
export function generateP256KeyPair(): {
  publicKey: KeyObject;
  privateKey: KeyObject;
} {
  return generateKeyPairSync("ec", { namedCurve: "P-256" });
}

/**
 * Generate a fresh NIST P-384 (secp384r1) key pair for the
 * `ecdsa-p384-sha384` algorithm (RFC 9421 §3.3.5). The signatures
 * produced from this pair are the raw concatenation of the two ECDSA
 * integers r and s, each padded to 48 octets (96 octets in total), as
 * §3.3.5 defines — `signRequest` / `verifyRequest` both pass
 * `dsaEncoding: "ieee-p1363"` to node:crypto, so the wire format stays
 * spec-conformant. P-384 is the stronger-curve tier common in
 * enterprise PKI / government gateway deployments.
 */
export function generateP384KeyPair(): {
  publicKey: KeyObject;
  privateKey: KeyObject;
} {
  return generateKeyPairSync("ec", { namedCurve: "P-384" });
}

/**
 * Generate a fresh NIST P-521 (secp521r1) key pair for the
 * `ecdsa-p521-sha512` algorithm (RFC 9421 §3.3.6). The signatures
 * produced from this pair are the raw concatenation of the two ECDSA
 * integers r and s, each padded to 66 octets (132 octets in total), as
 * §3.3.6 defines — `signRequest` / `verifyRequest` both pass
 * `dsaEncoding: "ieee-p1363"` to node:crypto, so the wire format stays
 * spec-conformant. P-521 is the highest-strength tier in the RFC's
 * registry, common in enterprise / government PKI deployments; with it,
 * every ECDSA algorithm RFC 9421 registers is implemented here.
 */
export function generateP521KeyPair(): {
  publicKey: KeyObject;
  privateKey: KeyObject;
} {
  return generateKeyPairSync("ec", { namedCurve: "P-521" });
}

/**
 * Minimum RSA modulus size in bits accepted by this library's RSA
 * signature algorithms (`rsa-pss-sha512`, `rsa-v1_5-sha256`). The key
 * generators below mint exactly this size; production deployments
 * should prefer ≥3072 bits. The sign and verify paths for
 * `rsa-v1_5-sha256` enforce this floor via
 * {@link assertRsaModulusLength} so a sub-floor key fails loudly as a
 * caller configuration error instead of minting weak signatures.
 */
export const MIN_RSA_MODULUS_BITS = 2048;

/**
 * Enforce the RSA key-shape and modulus floor for an RSA signature
 * algorithm. Throws a caller-configuration `Error` — not a verification
 * failure — when `key` is not an RSA key at all (e.g. a P-256 key paired
 * with `alg: "rsa-v1_5-sha256"`) or when its modulus is shorter than
 * {@link MIN_RSA_MODULUS_BITS}. Shared by the sign and verify paths so
 * both sides reject the same bad configuration identically.
 */
export function assertRsaModulusLength(key: KeyObject, context: string): void {
  if (key.asymmetricKeyType !== "rsa")
    throw new Error(
      `${context}: expected an RSA key, got ${
        key.type === "secret"
          ? "a secret (symmetric) key"
          : `an asymmetric ${key.asymmetricKeyType ?? "unknown"} key`
      }`,
    );
  const bits = key.asymmetricKeyDetails?.modulusLength;
  if (bits !== undefined && bits < MIN_RSA_MODULUS_BITS)
    throw new Error(
      `${context}: RSA modulus must be at least ${MIN_RSA_MODULUS_BITS} bits, got ${bits} bits`,
    );
}

/**
 * Generate a fresh RSA key pair for the `rsa-pss-sha512` algorithm
 * (RFC 9421 §3.3.1: RSASSA-PSS with SHA-512, MGF1 with SHA-512, and a
 * 64-byte salt). 2048-bit modulus is the minimum recommended size for
 * this demo; production deployments should prefer ≥3072 bits.
 * `signRequest` / `verifyRequest` both use PSS padding with
 * `saltLength: 64` per the RFC, so the wire format stays spec-conformant.
 *
 * The pair is plain RSA key material: the same keys can also sign with
 * `rsa-v1_5-sha256` (see {@link generateRsaV15KeyPair}) — padding and
 * hash are chosen per signature by the `alg` parameter, never by the
 * key, and verifiers dispatch on the declared `alg` for the same reason.
 */
export function generateRsaPssKeyPair(): {
  publicKey: KeyObject;
  privateKey: KeyObject;
} {
  return generateKeyPairSync("rsa", { modulusLength: 2048 });
}

/**
 * Generate a fresh RSA key pair for the `rsa-v1_5-sha256` algorithm
 * (RFC 9421 §3.3.2: RSASSA-PKCS1-v1_5 with SHA-256). This is the exact
 * same RSA key material {@link generateRsaPssKeyPair} produces — one
 * RSA key can serve both algorithms, and the JWK export
 * ({@link exportPublicKeyJwkRsa}) is shared too: a JWK carries no `alg`,
 * so the two algorithms are distinguished solely by the `alg` parameter
 * in `signature-input`, which the verifier uses to pick the padding.
 * Prefer `rsa-pss-sha512` or `ed25519` for new deployments; v1.5 exists
 * here for interoperability with legacy gateway/webhook signers.
 */
export function generateRsaV15KeyPair(): {
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
 * Minimum HMAC shared-secret length in bytes for `hmac-sha512`. RFC 2104 §3
 * advises that the HMAC key be at least as long as the hash output; for
 * sha-512 that is 64 bytes. Each HMAC algorithm enforces its own floor —
 * {@link MIN_HMAC_SECRET_BYTES} (32 bytes) for `hmac-sha256`, this constant
 * (64 bytes) for `hmac-sha512` — so a key that is only adequate for one
 * algorithm is never silently accepted for the other.
 */
export const MIN_HMAC_SHA512_SECRET_BYTES = 64;

/**
 * Enforce the per-algorithm HMAC secret-length floor on an HMAC secret
 * KeyObject. The floor is paired with the algorithm: `hmac-sha256` → ≥
 * {@link MIN_HMAC_SECRET_BYTES} (32) bytes, `hmac-sha512` → ≥
 * {@link MIN_HMAC_SHA512_SECRET_BYTES} (64) bytes (RFC 2104 §3: the key
 * SHOULD be at least as long as the hash output). `alg` defaults to
 * `"hmac-sha256"` for backwards compatibility.
 * Throws a caller-configuration `Error` — not a verification failure —
 * so both the sign and verify sides fail identically on a weak key.
 * Asymmetric keys passed here are also rejected (they are never valid
 * HMAC secrets); use {@link secretKey} or `node:crypto`'s
 * `createSecretKey` with enough entropy for the chosen algorithm.
 */
export function assertHmacSecretLength(
  key: KeyObject,
  alg: "hmac-sha256" | "hmac-sha512" = "hmac-sha256",
): void {
  const minBytes =
    alg === "hmac-sha512"
      ? MIN_HMAC_SHA512_SECRET_BYTES
      : MIN_HMAC_SECRET_BYTES;
  const size = key.symmetricKeySize;
  if (size === undefined)
    throw new Error(
      "assertHmacSecretLength: expected a symmetric secret KeyObject " +
        "(see keys.secretKey), got a non-symmetric key",
    );
  if (size < minBytes)
    throw new Error(
      `assertHmacSecretLength: ${alg} secret must be at least ` +
        `${minBytes} bytes (RFC 2104: the key SHOULD be at least ` +
        `as long as the hash output; ${
          alg === "hmac-sha512" ? "sha-512" : "sha-256"
        } → ${minBytes} ` +
        `bytes), got ${size} bytes`,
    );
}

/**
 * Human-readable description of a KeyObject's shape, used in caller
 * configuration error messages on both the sign and verify sides.
 */
export function describeKey(key: KeyObject): string {
  if (key.type === "secret") return "a secret (symmetric) key";
  const curve = key.asymmetricKeyDetails?.namedCurve;
  return `an asymmetric ${key.asymmetricKeyType ?? "unknown"} key${
    curve ? ` (${curve})` : ""
  }`;
}

/**
 * Whether an algorithm name is compatible with a key's shape:
 * `ed25519` needs an Ed25519 key, `hmac-*` a secret key, each
 * `ecdsa-p*-*` the EC key on the matching curve, `rsa-*` an RSA key.
 * The shared predicate behind the sign-side and verify-side
 * fail-fast checks, so the two sides can never drift apart: the
 * sign side throws before any crypto runs, the verify side (under
 * the `algFallback: "infer"` opt-in) throws instead of handing
 * node:crypto a mismatched pair. An unknown `alg` value is not
 * this predicate's job — it still fails with `UNSUPPORTED_ALG` /
 * `unsupported alg` in the dispatch below.
 */
export function algMatchesKeyShape(alg: string, key: KeyObject): boolean {
  return (
    (alg === "ed25519" && key.asymmetricKeyType === "ed25519") ||
    (alg === "hmac-sha256" && key.type === "secret") ||
    (alg === "hmac-sha512" && key.type === "secret") ||
    (alg === "ecdsa-p256-sha256" &&
      key.asymmetricKeyType === "ec" &&
      key.asymmetricKeyDetails?.namedCurve === "prime256v1") ||
    (alg === "ecdsa-p384-sha384" &&
      key.asymmetricKeyType === "ec" &&
      key.asymmetricKeyDetails?.namedCurve === "secp384r1") ||
    (alg === "ecdsa-p521-sha512" &&
      key.asymmetricKeyType === "ec" &&
      key.asymmetricKeyDetails?.namedCurve === "secp521r1") ||
    (alg === "rsa-pss-sha512" && key.asymmetricKeyType === "rsa") ||
    (alg === "rsa-v1_5-sha256" && key.asymmetricKeyType === "rsa")
  );
}

/**
 * Wrap a shared secret for HMAC signing. Enforces the `hmac-sha256` floor
 * (≥ {@link MIN_HMAC_SECRET_BYTES} bytes); a ≥ 64-byte secret produced here
 * also satisfies the `hmac-sha512` floor
 * ({@link MIN_HMAC_SHA512_SECRET_BYTES}). For `hmac-sha512` with a secret
 * between 32 and 63 bytes, the sign/verify paths throw — the floor is
 * paired with the algorithm, never silently relaxed.
 */
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

/**
 * Public-key-only JWK view of a NIST P-256 key, exactly as produced by
 * {@link exportPublicKeyJwkP256}. RFC 7518 §6.2: EC public keys carry
 * `kty: "EC"`, `crv: "P-256"`, and base64url `x` / `y` coordinates.
 * Private JWKs (`"d"` present) are never produced or accepted here —
 * same public-key-distribution-only policy as {@link Ed25519PublicJwk}.
 */
export interface P256PublicJwk {
  kty: "EC";
  crv: "P-256";
  /** Base64url-encoded 32-byte x coordinate. */
  x: string;
  /** Base64url-encoded 32-byte y coordinate. */
  y: string;
}

/**
 * Export a NIST P-256 public key as a plain-object JWK (RFC 7518 §6.2),
 * ready to `JSON.stringify` and ship to a verifier. Uses node:crypto's
 * native JWK support — no third-party dependencies.
 *
 * Throws a caller-configuration `Error` for anything that is not a P-256
 * public KeyObject (private keys, symmetric secrets, other curves or
 * algorithms); this helper is the public-key-distribution case only.
 */
export function exportPublicKeyJwkP256(key: KeyObject): P256PublicJwk {
  const namedCurve = key.asymmetricKeyDetails?.namedCurve;
  if (
    key.type !== "public" ||
    key.asymmetricKeyType !== "ec" ||
    namedCurve !== "prime256v1"
  )
    throw new Error(
      `exportPublicKeyJwkP256: expected a P-256 public KeyObject, got ` +
        `type=${String(key.type)} ` +
        `asymmetricKeyType=${String(key.asymmetricKeyType)} ` +
        `namedCurve=${String(namedCurve)} ` +
        `(JWK support here is P-256 public keys only — the public-key-distribution case)`,
    );
  const raw = key.export({ format: "jwk" }) as unknown as Record<
    string,
    unknown
  >;
  // Node emits exactly { kty: "EC", crv: "P-256", x: "<base64url>", y: "<base64url>" }.
  if (
    raw["kty"] !== "EC" ||
    raw["crv"] !== "P-256" ||
    typeof raw["x"] !== "string" ||
    typeof raw["y"] !== "string"
  )
    throw new Error(
      "exportPublicKeyJwkP256: node:crypto returned an unexpected JWK shape " +
        `for a P-256 public key: ${JSON.stringify(Object.keys(raw))}`,
    );
  return { kty: "EC", crv: "P-256", x: raw["x"], y: raw["y"] };
}

/**
 * Import a NIST P-256 public key from a JWK object (RFC 7518 §6.2), as
 * produced by {@link exportPublicKeyJwkP256} and typically received over
 * the wire as JSON.
 *
 * Strictly validates before touching node:crypto: the input must be a
 * plain object with `kty: "EC"`, `crv: "P-256"`, and non-empty string
 * `x` / `y`. Anything else throws a descriptive `Error` — never a
 * verification failure, since this is key setup, not signature checking.
 * JWKs carrying private material (`"d"`) are refused outright: this
 * helper is public-key distribution only, and silently accepting a
 * private JWK would encourage shipping secrets around.
 */
export function importPublicKeyJwkP256(jwk: unknown): KeyObject {
  const fail = (why: string): never => {
    throw new Error(`importPublicKeyJwkP256: invalid JWK: ${why}`);
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
  if (o["kty"] !== "EC")
    fail(`expected kty "EC", got ${JSON.stringify(o["kty"])}`);
  if (!("crv" in o)) fail(`missing "crv" parameter`);
  if (o["crv"] !== "P-256")
    fail(`expected crv "P-256", got ${JSON.stringify(o["crv"])}`);
  const x = o["x"];
  if (typeof x !== "string" || x.length === 0)
    throw new Error(
      `importPublicKeyJwkP256: invalid JWK: missing or empty "x" (the base64url x-coordinate)`,
    );
  const y = o["y"];
  if (typeof y !== "string" || y.length === 0)
    throw new Error(
      `importPublicKeyJwkP256: invalid JWK: missing or empty "y" (the base64url y-coordinate)`,
    );
  try {
    return createPublicKey({
      key: { kty: "EC", crv: "P-256", x, y },
      format: "jwk",
    });
  } catch (err) {
    throw new Error(
      `importPublicKeyJwkP256: node:crypto rejected the JWK: ${
        err instanceof Error ? err.message : String(err)
      }`,
    );
  }
}

/**
 * Public-key-only JWK view of a NIST P-384 key, exactly as produced by
 * {@link exportPublicKeyJwkP384}. RFC 7518 §6.2: EC public keys carry
 * `kty: "EC"`, `crv: "P-384"`, and base64url `x` / `y` coordinates.
 * Private JWKs (`"d"` present) are never produced or accepted here —
 * same public-key-distribution-only policy as {@link P256PublicJwk}.
 */
export interface P384PublicJwk {
  kty: "EC";
  crv: "P-384";
  /** Base64url-encoded 48-byte x coordinate. */
  x: string;
  /** Base64url-encoded 48-byte y coordinate. */
  y: string;
}

/**
 * Export a NIST P-384 public key as a plain-object JWK (RFC 7518 §6.2),
 * ready to `JSON.stringify` and ship to a verifier. Uses node:crypto's
 * native JWK support — no third-party dependencies.
 *
 * Throws a caller-configuration `Error` for anything that is not a P-384
 * public KeyObject (private keys, symmetric secrets, other curves or
 * algorithms); this helper is the public-key-distribution case only.
 */
export function exportPublicKeyJwkP384(key: KeyObject): P384PublicJwk {
  const namedCurve = key.asymmetricKeyDetails?.namedCurve;
  if (
    key.type !== "public" ||
    key.asymmetricKeyType !== "ec" ||
    namedCurve !== "secp384r1"
  )
    throw new Error(
      `exportPublicKeyJwkP384: expected a P-384 public KeyObject, got ` +
        `type=${String(key.type)} ` +
        `asymmetricKeyType=${String(key.asymmetricKeyType)} ` +
        `namedCurve=${String(namedCurve)} ` +
        `(JWK support here is P-384 public keys only — the public-key-distribution case)`,
    );
  const raw = key.export({ format: "jwk" }) as unknown as Record<
    string,
    unknown
  >;
  // Node emits exactly { kty: "EC", crv: "P-384", x: "<base64url>", y: "<base64url>" }.
  if (
    raw["kty"] !== "EC" ||
    raw["crv"] !== "P-384" ||
    typeof raw["x"] !== "string" ||
    typeof raw["y"] !== "string"
  )
    throw new Error(
      "exportPublicKeyJwkP384: node:crypto returned an unexpected JWK shape " +
        `for a P-384 public key: ${JSON.stringify(Object.keys(raw))}`,
    );
  return { kty: "EC", crv: "P-384", x: raw["x"], y: raw["y"] };
}

/**
 * Import a NIST P-384 public key from a JWK object (RFC 7518 §6.2), as
 * produced by {@link exportPublicKeyJwkP384} and typically received over
 * the wire as JSON.
 *
 * Strictly validates before touching node:crypto: the input must be a
 * plain object with `kty: "EC"`, `crv: "P-384"`, and non-empty string
 * `x` / `y`. Anything else throws a descriptive `Error` — never a
 * verification failure, since this is key setup, not signature checking.
 * JWKs carrying private material (`"d"`) are refused outright: this
 * helper is public-key distribution only, and silently accepting a
 * private JWK would encourage shipping secrets around. A P-256 JWK is
 * refused here too — the two curves' helpers are deliberately separate
 * so a key can never be silently re-interpreted on the wrong curve.
 */
export function importPublicKeyJwkP384(jwk: unknown): KeyObject {
  const fail = (why: string): never => {
    throw new Error(`importPublicKeyJwkP384: invalid JWK: ${why}`);
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
  if (o["kty"] !== "EC")
    fail(`expected kty "EC", got ${JSON.stringify(o["kty"])}`);
  if (!("crv" in o)) fail(`missing "crv" parameter`);
  if (o["crv"] !== "P-384")
    fail(`expected crv "P-384", got ${JSON.stringify(o["crv"])}`);
  const x = o["x"];
  if (typeof x !== "string" || x.length === 0)
    throw new Error(
      `importPublicKeyJwkP384: invalid JWK: missing or empty "x" (the base64url x-coordinate)`,
    );
  const y = o["y"];
  if (typeof y !== "string" || y.length === 0)
    throw new Error(
      `importPublicKeyJwkP384: invalid JWK: missing or empty "y" (the base64url y-coordinate)`,
    );
  try {
    return createPublicKey({
      key: { kty: "EC", crv: "P-384", x, y },
      format: "jwk",
    });
  } catch (err) {
    throw new Error(
      `importPublicKeyJwkP384: node:crypto rejected the JWK: ${
        err instanceof Error ? err.message : String(err)
      }`,
    );
  }
}

/**
 * Public-key-only JWK view of a NIST P-521 key, exactly as produced by
 * {@link exportPublicKeyJwkP521}. RFC 7518 §6.2: EC public keys carry
 * `kty: "EC"`, `crv: "P-521"`, and base64url `x` / `y` coordinates.
 * Private JWKs (`"d"` present) are never produced or accepted here —
 * same public-key-distribution-only policy as {@link P384PublicJwk}.
 */
export interface P521PublicJwk {
  kty: "EC";
  crv: "P-521";
  /** Base64url-encoded 66-byte x coordinate. */
  x: string;
  /** Base64url-encoded 66-byte y coordinate. */
  y: string;
}

/**
 * Export a NIST P-521 public key as a plain-object JWK (RFC 7518 §6.2),
 * ready to `JSON.stringify` and ship to a verifier. Uses node:crypto's
 * native JWK support — no third-party dependencies.
 *
 * Throws a caller-configuration `Error` for anything that is not a P-521
 * public KeyObject (private keys, symmetric secrets, other curves or
 * algorithms); this helper is the public-key-distribution case only.
 */
export function exportPublicKeyJwkP521(key: KeyObject): P521PublicJwk {
  const namedCurve = key.asymmetricKeyDetails?.namedCurve;
  if (
    key.type !== "public" ||
    key.asymmetricKeyType !== "ec" ||
    namedCurve !== "secp521r1"
  )
    throw new Error(
      `exportPublicKeyJwkP521: expected a P-521 public KeyObject, got ` +
        `type=${String(key.type)} ` +
        `asymmetricKeyType=${String(key.asymmetricKeyType)} ` +
        `namedCurve=${String(namedCurve)} ` +
        `(JWK support here is P-521 public keys only — the public-key-distribution case)`,
    );
  const raw = key.export({ format: "jwk" }) as unknown as Record<
    string,
    unknown
  >;
  // Node emits exactly { kty: "EC", crv: "P-521", x: "<base64url>", y: "<base64url>" }.
  if (
    raw["kty"] !== "EC" ||
    raw["crv"] !== "P-521" ||
    typeof raw["x"] !== "string" ||
    typeof raw["y"] !== "string"
  )
    throw new Error(
      "exportPublicKeyJwkP521: node:crypto returned an unexpected JWK shape " +
        `for a P-521 public key: ${JSON.stringify(Object.keys(raw))}`,
    );
  return { kty: "EC", crv: "P-521", x: raw["x"], y: raw["y"] };
}

/**
 * Import a NIST P-521 public key from a JWK object (RFC 7518 §6.2), as
 * produced by {@link exportPublicKeyJwkP521} and typically received over
 * the wire as JSON.
 *
 * Strictly validates before touching node:crypto: the input must be a
 * plain object with `kty: "EC"`, `crv: "P-521"`, and non-empty string
 * `x` / `y`. Anything else throws a descriptive `Error` — never a
 * verification failure, since this is key setup, not signature checking.
 * JWKs carrying private material (`"d"`) are refused outright: this
 * helper is public-key distribution only, and silently accepting a
 * private JWK would encourage shipping secrets around. P-256 / P-384
 * JWKs are refused here too — the curves' helpers are deliberately
 * separate so a key can never be silently re-interpreted on the wrong
 * curve.
 */
export function importPublicKeyJwkP521(jwk: unknown): KeyObject {
  const fail = (why: string): never => {
    throw new Error(`importPublicKeyJwkP521: invalid JWK: ${why}`);
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
  if (o["kty"] !== "EC")
    fail(`expected kty "EC", got ${JSON.stringify(o["kty"])}`);
  if (!("crv" in o)) fail(`missing "crv" parameter`);
  if (o["crv"] !== "P-521")
    fail(`expected crv "P-521", got ${JSON.stringify(o["crv"])}`);
  const x = o["x"];
  if (typeof x !== "string" || x.length === 0)
    throw new Error(
      `importPublicKeyJwkP521: invalid JWK: missing or empty "x" (the base64url x-coordinate)`,
    );
  const y = o["y"];
  if (typeof y !== "string" || y.length === 0)
    throw new Error(
      `importPublicKeyJwkP521: invalid JWK: missing or empty "y" (the base64url y-coordinate)`,
    );
  try {
    return createPublicKey({
      key: { kty: "EC", crv: "P-521", x, y },
      format: "jwk",
    });
  } catch (err) {
    throw new Error(
      `importPublicKeyJwkP521: node:crypto rejected the JWK: ${
        err instanceof Error ? err.message : String(err)
      }`,
    );
  }
}

/**
 * Public-key-only JWK view of an RSA key, exactly as produced by
 * {@link exportPublicKeyJwkRsa}. RFC 7518 §6.3: RSA public keys carry
 * `kty: "RSA"` with base64url `n` (modulus) and `e` (public exponent).
 * Private JWKs (`"d"` present) are never produced or accepted here —
 * same public-key-distribution-only policy as {@link Ed25519PublicJwk}.
 *
 * Honest caveat: node:crypto's JWK importer is lenient about the RSA
 * modulus — a structurally-valid but cryptographically degenerate `n`
 * (e.g. all-zero) would be accepted by node itself. This helper
 * enforces the 2048-bit modulus floor at import (see
 * {@link importPublicKeyJwkRsa}), so a sub-floor key is refused here
 * instead of failing later at the crypto layer. What import still does
 * not check is modulus *primality*: a 2048-bit composite modulus would
 * be imported and would only fail when used to verify a real signature.
 */
export interface RsaPublicJwk {
  kty: "RSA";
  /** Base64url-encoded modulus. */
  n: string;
  /** Base64url-encoded public exponent (typically "AQAB" = 65537). */
  e: string;
}

/**
 * Export an RSA public key as a plain-object JWK (RFC 7518 §6.3), ready
 * to `JSON.stringify` and ship to a verifier — the RSA counterpart of
 * {@link exportPublicKeyJwk} / {@link exportPublicKeyJwkP256},
 * for gateway/verifier deployments that distribute keys as JSON. The
 * same exported JWK serves both RSA algorithms (`rsa-pss-sha512` and
 * `rsa-v1_5-sha256`): the JWK shape carries no `alg`, so the algorithm
 * distinction lives only in each signature's `alg` parameter.
 *
 * Throws a caller-configuration `Error` for anything that is not an RSA
 * public KeyObject (private keys, symmetric secrets, other algorithms);
 * this helper is the public-key-distribution case only.
 */
export function exportPublicKeyJwkRsa(key: KeyObject): RsaPublicJwk {
  if (key.type !== "public" || key.asymmetricKeyType !== "rsa")
    throw new Error(
      `exportPublicKeyJwkRsa: expected an RSA public KeyObject, got ` +
        `type=${String(key.type)} ` +
        `asymmetricKeyType=${String(key.asymmetricKeyType)} ` +
        `(JWK support here is RSA public keys only — the public-key-distribution case)`,
    );
  const raw = key.export({ format: "jwk" }) as unknown as Record<
    string,
    unknown
  >;
  // Node emits exactly { kty: "RSA", n: "<base64url>", e: "<base64url>" }.
  if (
    raw["kty"] !== "RSA" ||
    typeof raw["n"] !== "string" ||
    typeof raw["e"] !== "string"
  )
    throw new Error(
      "exportPublicKeyJwkRsa: node:crypto returned an unexpected JWK shape " +
        `for an RSA public key: ${JSON.stringify(Object.keys(raw))}`,
    );
  return { kty: "RSA", n: raw["n"], e: raw["e"] };
}

/**
 * Import an RSA public key from a JWK object (RFC 7518 §6.3), as produced
 * by {@link exportPublicKeyJwkRsa} and typically received over the wire
 * as JSON.
 *
 * Strictly validates before touching node:crypto: the input must be a
 * plain object with `kty: "RSA"` and non-empty string `n` / `e`.
 * Anything else throws a descriptive `Error` — never a verification
 * failure, since this is key setup, not signature checking. JWKs carrying
 * private material (`"d"` or other private RSA parameters) are refused
 * outright: this helper is public-key distribution only, and silently
 * accepting a private JWK would encourage shipping secrets around.
 * After node:crypto accepts the JWK, the 2048-bit modulus floor
 * ({@link MIN_RSA_MODULUS_BITS}, via {@link assertRsaModulusLength}) is
 * enforced, so a 1024-bit or degenerate (e.g. all-zero) modulus is
 * refused at import with an `invalid JWK:` error instead of being
 * parked in a JWKS snapshot until a verify happens to use it.
 */
export function importPublicKeyJwkRsa(jwk: unknown): KeyObject {
  const fail = (why: string): never => {
    throw new Error(`importPublicKeyJwkRsa: invalid JWK: ${why}`);
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
  if (o["kty"] !== "RSA")
    fail(`expected kty "RSA", got ${JSON.stringify(o["kty"])}`);
  const n = o["n"];
  if (typeof n !== "string" || n.length === 0)
    throw new Error(
      `importPublicKeyJwkRsa: invalid JWK: missing or empty "n" (the base64url modulus)`,
    );
  const e = o["e"];
  if (typeof e !== "string" || e.length === 0)
    throw new Error(
      `importPublicKeyJwkRsa: invalid JWK: missing or empty "e" (the base64url public exponent)`,
    );
  let key: KeyObject;
  try {
    key = createPublicKey({
      key: { kty: "RSA", n, e },
      format: "jwk",
    });
  } catch (err) {
    throw new Error(
      `importPublicKeyJwkRsa: node:crypto rejected the JWK: ${
        err instanceof Error ? err.message : String(err)
      }`,
    );
  }
  // The 2048-bit floor is enforced here, at import — a JWKS endpoint
  // publishing a 1024-bit (or degenerate, e.g. all-zero) RSA key must
  // fail loudly at refresh time, never be imported and parked in the
  // snapshot until a verify happens to use it. The guard's message
  // already carries this function's name as its caller context, so
  // strip that prefix before wrapping it in the usual `invalid JWK:`
  // style to avoid repeating the name.
  try {
    assertRsaModulusLength(key, "importPublicKeyJwkRsa");
  } catch (err) {
    const detail = err instanceof Error ? err.message : String(err);
    throw new Error(
      `importPublicKeyJwkRsa: invalid JWK: ${detail.replace(/^importPublicKeyJwkRsa: /, "")}`,
    );
  }
  return key;
}

/**
 * Symmetric-key JWK view of an HMAC shared secret, exactly as produced
 * by {@link exportSymmetricKeyJwk}. RFC 7518 §6.4: symmetric keys
 * carry `kty: "oct"` and a base64url `k` holding the raw secret bytes.
 *
 * Unlike the public-key JWK shapes above, this one *is* secret
 * material: whoever holds the JWK can sign as the key's owner, so it
 * must only ever travel over a channel the signer already trusts for
 * the secret itself (an HTTPS JWKS endpoint the verifier trusts, a
 * signed snapshot envelope — never a public directory). `kid` and
 * `alg` are optional metadata: `kid` selects the key in a JWKS
 * document, `alg` pins the HMAC use (`"HS256"` / `"HS512"`).
 */
export interface HmacJwk {
  kty: "oct";
  /** Base64url-encoded shared secret bytes (no padding). */
  k: string;
  kid?: string;
  alg?: "HS256" | "HS512";
}

/** Options for {@link exportSymmetricKeyJwk}. */
export interface ExportSymmetricKeyJwkOptions {
  /**
   * The HMAC use the exported key is intended for, in JWA naming.
   * Sets the secret-length floor enforced at export
   * (`"HS256"` → ≥ 32 bytes, `"HS512"` → ≥ 64 bytes, via
   * {@link assertHmacSecretLength}) and is recorded as the JWK's
   * `alg` member so an importer (and `JwksKeyStore.refresh()`) can
   * enforce the same floor. Defaults to `"HS256"` when omitted, and
   * the `alg` member is then omitted from the JWK as well.
   */
  alg?: "HS256" | "HS512";
  /**
   * Key id to record as the JWK's `kid` member, so the key can be
   * selected by `keyid` in a JWKS document. Must be a non-empty
   * string when given.
   */
  kid?: string;
}

/**
 * Export an HMAC shared secret as a plain-object JWK (RFC 7518 §6.4),
 * ready to `JSON.stringify` and ship to a verifier — the symmetric
 * counterpart of {@link exportPublicKeyJwk} / {@link exportPublicKeyJwkRsa},
 * for gateway/webhook deployments that distribute HMAC keys as JSON
 * (a JWKS `oct` entry) instead of PEM.
 *
 * The secret-length floor is enforced per declared use, reusing
 * {@link assertHmacSecretLength}: ≥ 32 bytes for `"HS256"` (the
 * default), ≥ 64 bytes for `"HS512"` (RFC 2104 §3: the key SHOULD be
 * at least as long as the hash output). Uses node:crypto's native
 * JWK support — no third-party dependencies.
 *
 * Throws a caller-configuration `Error` for anything that is not a
 * secret KeyObject (public/private asymmetric keys) or for a secret
 * below the floor for its declared use. This helper exports secret
 * material by design — unlike the public-key exporters — so callers
 * must treat the returned object like the secret itself: only ship
 * it to verifiers over a trusted channel (see {@link HmacJwk}).
 */
export function exportSymmetricKeyJwk(
  key: KeyObject,
  opts: ExportSymmetricKeyJwkOptions = {},
): HmacJwk {
  const { alg, kid } = opts;
  if (alg !== undefined && alg !== "HS256" && alg !== "HS512")
    throw new Error(
      `exportSymmetricKeyJwk: \`alg\` must be "HS256" or "HS512", got ${JSON.stringify(alg)}`,
    );
  if (kid !== undefined && (typeof kid !== "string" || kid.length === 0))
    throw new Error(
      `exportSymmetricKeyJwk: \`kid\` must be a non-empty string, got ${JSON.stringify(kid)}`,
    );
  if (key.type !== "secret")
    throw new Error(
      `exportSymmetricKeyJwk: expected a secret (symmetric) KeyObject, got ` +
        `type=${String(key.type)} ` +
        `asymmetricKeyType=${String(key.asymmetricKeyType)} ` +
        `(JWK support here is HMAC shared secrets only — public keys use exportPublicKeyJwk*)`,
    );
  assertHmacSecretLength(key, alg === "HS512" ? "hmac-sha512" : "hmac-sha256");
  const raw = key.export({ format: "jwk" }) as unknown as Record<
    string,
    unknown
  >;
  // Node emits exactly { kty: "oct", k: "<base64url>" }.
  if (raw["kty"] !== "oct" || typeof raw["k"] !== "string")
    throw new Error(
      "exportSymmetricKeyJwk: node:crypto returned an unexpected JWK shape " +
        `for a secret key: ${JSON.stringify(Object.keys(raw))}`,
    );
  const jwk: HmacJwk = { kty: "oct", k: raw["k"] };
  if (kid !== undefined) jwk.kid = kid;
  if (alg !== undefined) jwk.alg = alg;
  return jwk;
}

/**
 * Import an HMAC shared secret from a JWK object (RFC 7518 §6.4), as
 * produced by {@link exportSymmetricKeyJwk} and typically received
 * over the wire as JSON (a JWKS `oct` entry).
 *
 * Strictly validates before touching node:crypto: the input must be a
 * plain object with `kty: "oct"` and a non-empty base64url `k`. The
 * decoded secret must satisfy the floor for its declared use, reusing
 * {@link assertHmacSecretLength}: a JWK declaring `alg: "HS512"` needs
 * ≥ 64 bytes, anything else (including no `alg`) needs ≥ 32 bytes.
 * An `alg` value other than `"HS256"` / `"HS512"` is refused, and a
 * non-canonical `k` (characters outside the base64url alphabet,
 * padding, or a length that does not re-encode identically) is
 * refused too — a truncated or mistyped secret must fail here, at
 * setup, never silently become a different key.
 *
 * Anything malformed throws a descriptive `Error` — never a
 * verification failure, since this is key setup, not signature
 * checking. A JWK carrying a `"d"` member is refused outright: `oct`
 * keys have no `"d"`, so its presence means the wrong JWK shape was
 * passed in.
 */
export function importSymmetricKeyJwk(jwk: unknown): KeyObject {
  const fail = (why: string): never => {
    throw new Error(`importSymmetricKeyJwk: invalid JWK: ${why}`);
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
      'unexpected "d" member: oct JWKs carry the secret in "k" only ' +
        "(a JWK with \"d\" is an asymmetric private key, not an HMAC secret)",
    );
  if (!("kty" in o)) fail(`missing "kty" parameter`);
  if (o["kty"] !== "oct")
    fail(`expected kty "oct", got ${JSON.stringify(o["kty"])}`);
  const k = o["k"];
  if (typeof k !== "string" || k.length === 0)
    throw new Error(
      `importSymmetricKeyJwk: invalid JWK: missing or empty "k" (the base64url shared secret)`,
    );
  if (!/^[A-Za-z0-9_-]+$/.test(k))
    fail(
      `"k" must be unpadded base64url (characters A-Z a-z 0-9 - _ only, no "=" padding)`,
    );
  const bytes = Buffer.from(k, "base64url");
  if (bytes.toString("base64url") !== k)
    fail(`"k" is not canonical base64url (decodes to ${bytes.length} bytes but does not re-encode identically)`);
  const alg = o["alg"];
  let signAlg: "hmac-sha256" | "hmac-sha512" = "hmac-sha256";
  if (alg !== undefined) {
    if (alg === "HS256") signAlg = "hmac-sha256";
    else if (alg === "HS512") signAlg = "hmac-sha512";
    else
      fail(
        `unsupported "alg" ${JSON.stringify(alg)} for an oct key (supported: "HS256", "HS512")`,
      );
  }
  const key = createSecretKey(bytes);
  // The floor is the same one the sign/verify paths enforce, so a key
  // imported here can never be weaker than a key the library would
  // accept from `secretKey`. The guard's message already carries its
  // own function name, so strip that prefix before wrapping it in
  // the usual `invalid JWK:` style (same pattern as the RSA importer).
  try {
    assertHmacSecretLength(key, signAlg);
  } catch (err) {
    const detail = err instanceof Error ? err.message : String(err);
    throw new Error(
      `importSymmetricKeyJwk: invalid JWK: ${detail.replace(/^assertHmacSecretLength: /, "")}`,
    );
  }
  return key;
}

/**
 * One entry of a JWKS document to publish: a public key and the `kid`
 * verifiers will resolve it under. The `kid` is the same identifier
 * the signer puts in `signRequest`'s `keyId` and the verifier's
 * `JwksKeyStore` resolves by — publish and consume must agree on it.
 */
export interface JwksDocumentEntry {
  /** A public `KeyObject` (the `.publicKey` half of a generated pair). */
  key: KeyObject;
  /** Non-empty, document-unique key id, e.g. `"ed-key-1"`. */
  kid: string;
}

/**
 * One key inside a published JWKS document: one of the five public
 * JWK shapes this library exports, tagged with its `kid`. Exactly the
 * shape {@link JwksKeyStore} consumes on the verify side, so a
 * document built here round-trips through a store unchanged.
 */
export type JwksDocumentKey =
  | (Ed25519PublicJwk & { kid: string })
  | (P256PublicJwk & { kid: string })
  | (P384PublicJwk & { kid: string })
  | (P521PublicJwk & { kid: string })
  | (RsaPublicJwk & { kid: string });

/**
 * A JWKS document (RFC 7517 §5) as served from
 * `/.well-known/jwks.json`: the `{ keys: [...] }` object a signer
 * publishes so verifiers can fetch its public keys by `kid`.
 */
export interface JwksDocument {
  keys: JwksDocumentKey[];
}

/**
 * Build the JWKS document a signer publishes at
 * `/.well-known/jwks.json` — the publishing half of
 * {@link JwksKeyStore}'s consuming half. Each entry's public key is
 * exported with the matching `exportPublicKeyJwk*` helper (ed25519 →
 * OKP/Ed25519, P-256/P-384/P-521 → EC/`crv`, RSA → `n`/`e`) and
 * tagged with its `kid`, so callers never hand-assemble `{ keys:
 * [...] }` and mistype a `kty`/`crv` or forget a `kid` — mistakes
 * that otherwise surface only later, on the verifier, as
 * `KEY_RESOLUTION_FAILED`.
 *
 * Fail-fast, at build time: `kid` must be a non-empty string and
 * unique across the document (a duplicate would make the published
 * document ambiguous — `JwksKeyStore` lets the later entry win, so
 * the publisher must not ship one); a symmetric secret key is
 * refused outright — a JWKS publishes public keys only, and an
 * `oct` entry would hand the shared secret to every verifier; a
 * private key is refused too (pass the public half). Any key shape
 * outside the five exported families throws a configuration error.
 * The returned document never carries private material: the
 * exporters emit public JWKs only, so no entry has a `"d"` member.
 * Key order is preserved as given, but verifiers resolve by `kid`,
 * so order is irrelevant to verification — a JSON round-trip (or a
 * reordered document) still verifies.
 *
 * Serve the result with `JSON.stringify(doc)` from your
 * `/.well-known/jwks.json` route, over HTTPS (see SECURITY.md);
 * rotation is a new document with the new `kid` added (and the
 * retired `kid` removed once verifiers have re-fetched).
 *
 * @example
 * ```ts
 * import { buildJwksDocument, generateEd25519KeyPair } from "./dist/src/index.js";
 * const { publicKey } = generateEd25519KeyPair();
 * const doc = buildJwksDocument([{ key: publicKey, kid: "ed-key-1" }]);
 * // GET /.well-known/jwks.json -> JSON.stringify(doc)
 * ```
 */
export function buildJwksDocument(
  entries: readonly JwksDocumentEntry[],
): JwksDocument {
  if (!Array.isArray(entries))
    throw new Error(
      `buildJwksDocument: \`entries\` must be an array, got ${
        entries === null ? "null" : typeof entries
      }`,
    );
  const seenKids = new Set<string>();
  const keys: JwksDocumentKey[] = entries.map((entry, i) => {
    const where = `entries[${i}]`;
    if (typeof entry !== "object" || entry === null || Array.isArray(entry))
      throw new Error(
        `buildJwksDocument: ${where} must be an object with \`key\` and \`kid\`, got ${
          Array.isArray(entry)
            ? "an array"
            : entry === null
              ? "null"
              : typeof entry
        }`,
      );
    const { key, kid } = entry as JwksDocumentEntry;
    if (typeof kid !== "string" || kid.length === 0)
      throw new Error(
        `buildJwksDocument: ${where}.kid must be a non-empty string, got ${JSON.stringify(kid)}`,
      );
    if (seenKids.has(kid))
      throw new Error(
        `buildJwksDocument: duplicate kid ${JSON.stringify(kid)} at ${where} ` +
          `(kids must be unique across the document — a verifier resolves by kid alone)`,
      );
    seenKids.add(kid);
    if (typeof key !== "object" || key === null)
      throw new Error(
        `buildJwksDocument: ${where}.key must be a public KeyObject, got ${
          key === null ? "null" : typeof key
        }`,
      );
    const k = key as KeyObject;
    if (k.type === "secret")
      throw new Error(
        `buildJwksDocument: ${where} (kid ${JSON.stringify(kid)}) is a symmetric secret key — ` +
          `a JWKS publishes public keys only; publishing an "oct" entry would hand the shared secret to every verifier`,
      );
    if (k.type === "private")
      throw new Error(
        `buildJwksDocument: ${where} (kid ${JSON.stringify(kid)}) is a private key — ` +
          `pass the public KeyObject (e.g. keyPair.publicKey); a JWKS never carries private material`,
      );
    if (k.type !== "public")
      throw new Error(
        `buildJwksDocument: ${where} (kid ${JSON.stringify(kid)}) has unsupported key type ${JSON.stringify(k.type)}`,
      );
    const curve = k.asymmetricKeyDetails?.namedCurve;
    if (k.asymmetricKeyType === "ed25519")
      return { ...exportPublicKeyJwk(k), kid };
    if (k.asymmetricKeyType === "ec" && curve === "prime256v1")
      return { ...exportPublicKeyJwkP256(k), kid };
    if (k.asymmetricKeyType === "ec" && curve === "secp384r1")
      return { ...exportPublicKeyJwkP384(k), kid };
    if (k.asymmetricKeyType === "ec" && curve === "secp521r1")
      return { ...exportPublicKeyJwkP521(k), kid };
    if (k.asymmetricKeyType === "rsa")
      return { ...exportPublicKeyJwkRsa(k), kid };
    throw new Error(
      `buildJwksDocument: ${where} (kid ${JSON.stringify(kid)}) is an unsupported key shape: ` +
        `${describeKey(k)} — only ed25519, P-256, P-384, P-521 and RSA public keys can be published`,
    );
  });
  return { keys };
}

/**
 * Import a private key from a JWK object (RFC 7517 / RFC 7518 /
 * RFC 8037) — the private counterpart of the `importPublicKeyJwk*`
 * helpers, for the case the key arrives as JSON instead of PEM: a
 * KMS export, a key-rotation payload, or a snapshot envelope a
 * signer hands to a fresh process. Four families are supported,
 * dispatching on `kty` (and `crv` for the curve families):
 *
 * - `OKP` / `Ed25519` — `d` + `x` (RFC 8037 §2), for `ed25519`;
 * - `EC` / `P-256` / `P-384` / `P-521` — `d` + `x` + `y`
 *   (RFC 7518 §6.2), for the three `ecdsa-p*-*` algorithms;
 * - `RSA` — `n` / `e` / `d` plus the full CRT set `p` / `q` /
 *   `dp` / `dq` / `qi` (RFC 7518 §6.3), for `rsa-pss-sha512` and
 *   `rsa-v1_5-sha256` (one RSA key serves both — the JWK carries
 *   no `alg`, as with {@link exportPublicKeyJwkRsa});
 * - `oct` — `k` (RFC 7518 §6.4), for `hmac-sha256` / `hmac-sha512`,
 *   built the same way {@link importSymmetricKeyJwk} builds it.
 *
 * Strictly validates before touching node:crypto, in the same
 * fail-fast style as the public importers: the input must be a
 * plain object carrying private material (`"d"` for the asymmetric
 * families, `"k"` for `oct`) — a public JWK passed here by mistake
 * is refused with a clear error instead of silently importing the
 * wrong half of the key. Anything malformed throws a descriptive
 * `Error` — never a verification failure, since this is key setup,
 * not signature checking.
 *
 * Key-use members are enforced, not ignored: `use`, when present,
 * must be `"sig"` (an `"enc"` key is refused — this library only
 * signs with private keys), and `key_ops`, when present, must be
 * an array containing `"sign"`. node:crypto itself ignores both
 * members, so without this check an encryption-only JWK would be
 * imported and only fail later, at first use.
 *
 * Two honest limits, documented where they bite. First, the RSA
 * shape must carry the complete CRT parameter set: node:crypto
 * refuses an RSA private JWK with only `n` / `e` / `d`, so this
 * helper refuses it too, with a named error, instead of node's
 * generic "Invalid JWK RSA key". KMS exports that omit the CRT
 * parameters must be completed (or converted to PEM) upstream.
 * Second, what import still does not check is modulus primality
 * for RSA (same caveat as {@link importPublicKeyJwkRsa}) — a
 * 2048-bit composite modulus is imported, and the 2048-bit floor
 * ({@link MIN_RSA_MODULUS_BITS}, via {@link assertRsaModulusLength})
 * is enforced, but primality is only proven when the key signs or
 * verifies a real signature.
 *
 * This helper imports secret material by design — unlike the
 * public-key importers — so callers must treat the input JWK like
 * the private key itself: only accept it over a channel already
 * trusted for the key (never a public directory), and never log
 * it. The returned `KeyObject` is a private (or, for `oct`, secret)
 * key; `exportPublicKeyJwk*` / `jwkThumbprint` stay the way to
 * derive the distributable public half.
 */
export function importPrivateKeyJwk(jwk: unknown): KeyObject {
  const fail = (why: string): never => {
    throw new Error(`importPrivateKeyJwk: invalid JWK: ${why}`);
  };
  if (typeof jwk !== "object" || jwk === null || Array.isArray(jwk))
    fail(
      `expected a JWK object, got ${
        Array.isArray(jwk) ? "an array" : jwk === null ? "null" : typeof jwk
      }`,
    );
  const o = jwk as Record<string, unknown>;
  // Key-use policy, checked before the family dispatch so every
  // family gets the same refusal: this library signs with private
  // keys, so an encryption-only JWK is a configuration error here,
  // not a key this helper should ever hand back.
  if ("use" in o) {
    if (o["use"] !== "sig")
      fail(
        `unsupported "use" ${JSON.stringify(o["use"])} for a private signing key ` +
          `(only "sig" is accepted; an "enc" key cannot sign)`,
      );
  }
  if ("key_ops" in o) {
    const ops = o["key_ops"];
    if (!Array.isArray(ops) || ops.some((op) => typeof op !== "string"))
      fail(`"key_ops" must be an array of strings when present`);
    // `fail` above returns `never`, but TypeScript does not narrow
    // `ops` through a never-returning call, so the cast pins the
    // array-of-strings shape the guard just established.
    if (!(ops as string[]).includes("sign"))
      fail(
        `"key_ops" must include "sign" for a private signing key, got ${JSON.stringify(ops)}`,
      );
  }
  if (!("kty" in o)) fail(`missing "kty" parameter`);
  const kty = o["kty"];
  // The `oct` family is a secret, not an asymmetric private key, so
  // it goes through `createSecretKey` exactly the way
  // `importSymmetricKeyJwk` builds it (same canonical-`k` check,
  // same per-`alg` floor) — `createPrivateKey` rejects `oct` outright.
  if (kty === "oct") {
    if ("d" in o)
      fail(
        'unexpected "d" member: oct JWKs carry the secret in "k" only ' +
          "(a JWK with \"d\" is an asymmetric private key, not an HMAC secret)",
      );
    const k = o["k"];
    if (typeof k !== "string" || k.length === 0)
      throw new Error(
        `importPrivateKeyJwk: invalid JWK: missing or empty "k" (the base64url shared secret)`,
      );
    if (!/^[A-Za-z0-9_-]+$/.test(k))
      fail(
        `"k" must be unpadded base64url (characters A-Z a-z 0-9 - _ only, no "=" padding)`,
      );
    const bytes = Buffer.from(k, "base64url");
    if (bytes.toString("base64url") !== k)
      fail(`"k" is not canonical base64url (decodes to ${bytes.length} bytes but does not re-encode identically)`);
    const alg = o["alg"];
    let signAlg: "hmac-sha256" | "hmac-sha512" = "hmac-sha256";
    if (alg !== undefined) {
      if (alg === "HS256") signAlg = "hmac-sha256";
      else if (alg === "HS512") signAlg = "hmac-sha512";
      else
        fail(
          `unsupported "alg" ${JSON.stringify(alg)} for an oct key (supported: "HS256", "HS512")`,
        );
    }
    const key = createSecretKey(bytes);
    try {
      assertHmacSecretLength(key, signAlg);
    } catch (err) {
      const detail = err instanceof Error ? err.message : String(err);
      throw new Error(
        `importPrivateKeyJwk: invalid JWK: ${detail.replace(/^assertHmacSecretLength: /, "")}`,
      );
    }
    return key;
  }
  // Required member for this family: a non-empty string, else a
  // named refusal (a public JWK passed by mistake fails here, on
  // the missing "d", with the member named).
  const member = (name: string): string => {
    const value = o[name];
    if (typeof value !== "string" || value.length === 0)
      throw new Error(
        `importPrivateKeyJwk: invalid JWK: missing or empty "${name}" (a required member for this private JWK)`,
      );
    return value;
  };
  // Only the members node:crypto needs are passed through — `kid`,
  // `alg`, `use` and `key_ops` are validated above where they matter
  // and otherwise ignored, so a KMS export carrying metadata still
  // imports.
  let nodeJwk: Record<string, string>;
  if (kty === "OKP") {
    if (!("crv" in o)) fail(`missing "crv" parameter`);
    if (o["crv"] !== "Ed25519")
      fail(`expected crv "Ed25519", got ${JSON.stringify(o["crv"])}`);
    nodeJwk = { kty: "OKP", crv: "Ed25519", x: member("x"), d: member("d") };
  } else if (kty === "EC") {
    if (!("crv" in o)) fail(`missing "crv" parameter`);
    const crv = o["crv"];
    if (crv !== "P-256" && crv !== "P-384" && crv !== "P-521")
      fail(
        `unsupported crv ${JSON.stringify(crv)} (supported: "P-256", "P-384", "P-521")`,
      );
    nodeJwk = {
      kty: "EC",
      crv: crv as string,
      x: member("x"),
      y: member("y"),
      d: member("d"),
    };
  } else if (kty === "RSA") {
    // The full CRT set is required: node:crypto refuses an RSA
    // private JWK with only n/e/d, so each CRT member is demanded
    // by name here instead of letting node fail generically.
    nodeJwk = {
      kty: "RSA",
      n: member("n"),
      e: member("e"),
      d: member("d"),
      p: member("p"),
      q: member("q"),
      dp: member("dp"),
      dq: member("dq"),
      qi: member("qi"),
    };
  } else {
    // A direct `throw` (rather than the `fail` helper) so the
    // compiler sees this branch as terminating and `nodeJwk` as
    // definitely assigned below.
    throw new Error(
      `importPrivateKeyJwk: invalid JWK: unsupported kty ${JSON.stringify(kty)} (supported: "OKP", "EC", "RSA", "oct")`,
    );
  }
  let key: KeyObject;
  try {
    key = createPrivateKey({ key: nodeJwk, format: "jwk" });
  } catch (err) {
    throw new Error(
      `importPrivateKeyJwk: node:crypto rejected the JWK: ${
        err instanceof Error ? err.message : String(err)
      }`,
    );
  }
  if (key.type !== "private")
    throw new Error(
      `importPrivateKeyJwk: node:crypto returned a non-private key for a private JWK`,
    );
  if (kty === "RSA") {
    // Same floor as the public RSA importer, enforced at import so
    // a sub-floor private key fails loudly at setup, never at first
    // sign. The guard's message already carries this function's
    // name, so strip that prefix before wrapping it (same pattern
    // as the RSA public importer).
    try {
      assertRsaModulusLength(key, "importPrivateKeyJwk");
    } catch (err) {
      const detail = err instanceof Error ? err.message : String(err);
      throw new Error(
        `importPrivateKeyJwk: invalid JWK: ${detail.replace(/^importPrivateKeyJwk: /, "")}`,
      );
    }
  }
  return key;
}

/**
 * Required JWK members per `kty` for the RFC 7638 thumbprint
 * computation (RFC 7638 §3.2, with the member sets defined by
 * RFC 7517/7518 and RFC 8037/8038). Only these members — plus `kty`
 * itself — participate in the hash; every other member (`kid`, `alg`,
 * `use`, …) is ignored, so two serializations of the same key that
 * differ only in metadata produce the same thumbprint.
 */
const JWK_THUMBPRINT_REQUIRED_MEMBERS: Readonly<
  Record<string, readonly string[]>
> = {
  OKP: ["crv", "x"],
  EC: ["crv", "x", "y"],
  RSA: ["e", "n"],
};

/**
 * Compute the RFC 7638 JWK Thumbprint of a public-key JWK — a stable,
 * content-derived identifier for the key, suitable for use as a
 * `keyid` / JWKS `kid` that both sides of a key distribution derive
 * identically instead of inventing local names.
 *
 * The computation follows RFC 7638 §3 exactly: take only the required
 * members for the JWK's `kty` (OKP: `crv`/`x`; EC: `crv`/`x`/`y`;
 * RSA: `e`/`n` — plus `kty` in every case), build the JSON object
 * with those members in lexicographic order and no whitespace, hash
 * its UTF-8 octets with SHA-256, and base64url-encode the digest.
 * Member order in the input and extra members (`kid`, `alg`, `use`,
 * …) do not affect the result. The `crv` value is not restricted to
 * the curves this library imports — the thumbprint is defined for
 * any curve name; curve support stays the import helpers' concern.
 *
 * Strictly validates before hashing, in the same fail-fast style as
 * the `importPublicKeyJwk*` helpers: the input must be a plain
 * object with a known `kty` and non-empty string values for every
 * required member. JWKs carrying private material (`"d"`) are
 * refused outright — this helper identifies *public* keys, and
 * silently hashing a private JWK would encourage shipping secrets
 * around. Anything else malformed throws a descriptive `Error` —
 * never a verification failure, since this is key setup, not
 * signature checking.
 *
 * Honest limit: a thumbprint is an identifier derived from public
 * material. It is not a proof of key possession and not a signature —
 * anyone who has the public key can compute it, so it must never be
 * treated as an authentication credential by itself.
 */
export function jwkThumbprint(jwk: unknown): string {
  const fail = (why: string): never => {
    throw new Error(`jwkThumbprint: invalid JWK: ${why}`);
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
      'private key material ("d") is not accepted; thumbprints here ' +
        "identify public keys only (keep private keys in PEM on the signer side)",
    );
  if (!("kty" in o)) fail(`missing "kty" parameter`);
  const kty = o["kty"];
  if (typeof kty !== "string" || !(kty in JWK_THUMBPRINT_REQUIRED_MEMBERS))
    throw new Error(
      `jwkThumbprint: invalid JWK: unsupported kty ${JSON.stringify(kty)} ` +
        `(supported: ${Object.keys(JWK_THUMBPRINT_REQUIRED_MEMBERS).join(", ")})`,
    );
  const required = JWK_THUMBPRINT_REQUIRED_MEMBERS[kty]!;
  const members: Record<string, string> = { kty };
  for (const name of required) {
    const value = o[name];
    if (typeof value !== "string" || value.length === 0)
      throw new Error(
        `jwkThumbprint: invalid JWK: missing or empty "${name}" ` +
          `(a required member for kty "${kty}")`,
      );
    members[name] = value;
  }
  // RFC 7638 §3.3: members in lexicographic order, no whitespace.
  const canonical = `{${Object.keys(members)
    .sort()
    .map((name) => `${JSON.stringify(name)}:${JSON.stringify(members[name])}`)
    .join(",")}}`;
  return createHash("sha256").update(canonical, "utf8").digest("base64url");
}

/**
 * Generate a cryptographically-secure random nonce for the `nonce`
 * option of `signRequest` (RFC 9421 §2.3), base64url-encoded.
 *
 * Why this exists instead of letting callers hand-roll one:
 * `signRequest`'s `nonce` is caller-supplied, and hand-rolled nonces
 * (`Math.random()` / `Date.now()` concatenation) are predictable — a
 * predictable nonce space makes the `NONCE_REPLAY` line of defense
 * (see `VerifyOptions.replayCache` / SECURITY.md) meaningless, because
 * an attacker can pre-claim the nonce values they intend to replay.
 * This helper draws from `node:crypto` `randomBytes` (the CSPRNG), so
 * each nonce is unpredictable.
 *
 * The output uses the base64url alphabet (`A–Z a–z 0–9 - _`), which is
 * safe inside the `signature-input` quoted-string parameter and also
 * URL-safe for logging and transport. `bytes` defaults to 16 (128 bits
 * of entropy — the standard nonce strength); it must be a positive
 * integer, anything else throws a configuration `Error` fail-fast.
 * The result is never empty, so it always passes `signRequest`'s
 * empty-nonce guard.
 *
 * @example
 * ```ts
 * const signed = signRequest(req, {
 *   keyId: "my-key",
 *   alg: "ed25519",
 *   key: privateKey,
 *   nonce: generateNonce(),
 * });
 * ```
 */
export function generateNonce(bytes = 16): string {
  if (
    typeof bytes !== "number" ||
    !Number.isInteger(bytes) ||
    bytes <= 0
  ) {
    throw new Error(
      `generateNonce: \`bytes\` must be a positive integer, got ${String(
        bytes,
      )}`,
    );
  }
  return randomBytes(bytes).toString("base64url");
}

/**
 * Options for {@link memoizeKeyResolver}.
 */
export interface MemoizeKeyResolverOptions {
  /**
   * Cache TTL in seconds for successful `keyid`→key resolutions.
   * Defaults to 300. Must be a finite number > 0.
   */
  ttlSec?: number;
  /**
   * Maximum number of cached `keyid`→key entries. Defaults to 10_000 —
   * the same bound as `ReplayCache` — so a long-lived verifier facing
   * many one-off `keyid`s (multi-tenant gateways, fast-rotating webhook
   * signers) cannot grow the cache without bound: inserting a new entry
   * into a full cache first reclaims expired entries, then evicts the
   * least recently used entry. Must be a positive integer. Wrappers
   * created before this option existed were unbounded; the default is
   * a deliberate behaviour change, bounded so high that ordinary
   * keystores never notice it.
   */
  maxEntries?: number;
  /**
   * Injected clock returning unix seconds — the same convention as
   * `ReplayCacheOptions.now` — so tests can pin time deterministically.
   * Defaults to the wall clock.
   */
  now?: () => number;
}

/**
 * Detached snapshot of a {@link MemoizedKeyResolver}'s cache counters,
 * produced by `stats()` — the same shape as `ReplayCacheStats`, so the
 * two cache primitives report identically.
 *
 * - `size`: entries currently cached.
 * - `hits`: lookups served from the cache (a hit refreshes recency but
 *   never extends the entry's TTL).
 * - `misses`: lookups that found no live entry — no entry, an expired
 *   entry, or an unknown `keyid` the resolver returned `undefined` for.
 * - `evictions`: entries removed by expiry reclamation or LRU pressure
 *   — an expired entry found on read, expired entries reclaimed while
 *   making room, and least-recently-used entries evicted from a full
 *   cache. `clear()` resets all four fields to zero.
 */
export interface MemoizeKeyResolverStats {
  size: number;
  hits: number;
  misses: number;
  evictions: number;
}

/**
 * A `keyid`→key resolver returned by {@link memoizeKeyResolver}: still
 * directly callable as a `VerifyOptions.keyResolver`, with cache
 * observability attached.
 *
 * - `stats()` returns a detached snapshot — mutating it never affects
 *   the cache.
 * - `clear()` empties the cache and resets every counter to zero, so a
 *   key rotation (or a test) can start from a known-empty state.
 */
export interface MemoizedKeyResolver {
  (keyId: string): KeyObject | undefined;
  stats(): MemoizeKeyResolverStats;
  clear(): void;
}

/**
 * Wrap a `keyid`→key resolver (see `VerifyOptions.keyResolver`) with an
 * in-memory TTL cache keyed by `keyid`.
 *
 * `keyResolver` is called on *every* `verifyRequest` today, so when the
 * resolver sits in front of a remote or otherwise slow keystore, high-rate
 * verification hammers the keystore once per signature. This helper is the
 * library's cache primitive so callers stop hand-rolling expiry semantics:
 *
 * - Successful resolutions (`KeyObject` returned) are cached for `ttlSec`
 *   (default 300s); repeated `verifyRequest` calls with the same `keyid`
 *   then skip the underlying resolver entirely.
 * - `undefined` (unknown `keyid`) is deliberately **not** cached — a newly
 *   rotated-in `keyid` must be discoverable on the very next verify.
 * - A throwing resolver is not cached either: the error propagates
 *   unchanged, and `verifyRequest` still converges it to `VERIFICATION_ERROR`
 *   exactly as it does for an uncached resolver.
 *
 * The cache is per-wrapper instance and process-local; deployments with
 * several verifier processes get one cache each, so `ttlSec` also bounds
 * cross-instance key staleness. Different `keyid`s have independent
 * entries; expired entries are evicted on read.
 *
 * The cache is bounded by `maxEntries` (default 10_000, matching
 * `ReplayCache`): inserting into a full cache first reclaims expired
 * entries, then evicts least-recently-used ones. A cache hit refreshes
 * an entry's recency but never extends its TTL — a hit cannot keep a
 * rotated-out key alive past its original expiry, mirroring
 * `ReplayCache`'s "hit does not renew" semantics.
 *
 * Observability: the returned resolver carries `.stats()` (a detached
 * `{ size, hits, misses, evictions }` snapshot, same shape as
 * `ReplayCacheStats`) and `.clear()` (empties the cache and resets the
 * counters), so a caller can tell whether the cache is actually working
 * and whether a stream of one-off `keyid`s is driving LRU evictions —
 * the same counters `ReplayCache` and `JwksKeyStore` already expose.
 *
 * @example
 * ```ts
 * import { memoizeKeyResolver } from "./dist/src/index.js";
 * const store = new Map([["my-key", publicKey]]);
 * const keyResolver = memoizeKeyResolver((id) => store.get(id), {
 *   ttlSec: 300,
 * });
 * // pass `keyResolver` to every verifyRequest call
 * keyResolver.stats(); // { size, hits, misses, evictions }
 * ```
 */
export function memoizeKeyResolver(
  resolver: (keyId: string) => KeyObject | undefined,
  opts: MemoizeKeyResolverOptions = {},
): MemoizedKeyResolver {
  if (typeof resolver !== "function") {
    throw new Error("memoizeKeyResolver: `resolver` must be a function");
  }
  const {
    ttlSec = 300,
    maxEntries = 10_000,
    now = () => Math.floor(Date.now() / 1000),
  } = opts;
  if (typeof ttlSec !== "number" || !Number.isFinite(ttlSec) || ttlSec <= 0) {
    throw new Error(
      `memoizeKeyResolver: \`ttlSec\` must be a finite number > 0, got ${String(ttlSec)}`,
    );
  }
  if (!Number.isInteger(maxEntries) || maxEntries < 1) {
    throw new Error(
      `memoizeKeyResolver: \`maxEntries\` must be a positive integer, got ${String(maxEntries)}`,
    );
  }
  if (typeof now !== "function") {
    throw new Error(
      "memoizeKeyResolver: `now` must be a function returning unix seconds",
    );
  }
  // Insertion order = LRU order: hits re-insert their entry at the tail.
  const cache = new Map<string, { key: KeyObject; expiresAt: number }>();
  let hits = 0;
  let misses = 0;
  let evictions = 0;
  // Make room for one new entry: reclaim expired entries first, then
  // evict least recently used (head of the Map) until there is room.
  // Every entry removed here — expired or LRU — counts as an eviction.
  const makeRoom = (t: number): void => {
    if (cache.size < maxEntries) return;
    for (const [id, entry] of cache) {
      if (t >= entry.expiresAt) {
        cache.delete(id);
        evictions++;
      }
      if (cache.size < maxEntries) return;
    }
    while (cache.size >= maxEntries) {
      const oldest = cache.keys().next();
      if (oldest.done) break;
      cache.delete(oldest.value);
      evictions++;
    }
  };
  const memoized = ((keyId: string): KeyObject | undefined => {
    const t = now();
    const hit = cache.get(keyId);
    if (hit !== undefined) {
      if (t < hit.expiresAt) {
        // Refresh recency only — expiresAt is kept, so the hit does
        // not extend the entry's TTL.
        cache.delete(keyId);
        cache.set(keyId, hit);
        hits++;
        return hit.key;
      }
      // Expired on read: reclaim the stale entry (counts as an
      // eviction) and fall through to a miss below.
      cache.delete(keyId);
      evictions++;
    }
    misses++;
    const resolved = resolver(keyId);
    if (resolved !== undefined) {
      makeRoom(t);
      cache.set(keyId, { key: resolved, expiresAt: t + ttlSec });
    }
    return resolved;
  }) as MemoizedKeyResolver;
  memoized.stats = (): MemoizeKeyResolverStats => ({
    size: cache.size,
    hits,
    misses,
    evictions,
  });
  memoized.clear = (): void => {
    cache.clear();
    hits = 0;
    misses = 0;
    evictions = 0;
  };
  return memoized;
}
