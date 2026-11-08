import test from "node:test";
import assert from "node:assert/strict";
import { createPublicKey, generateKeyPairSync } from "node:crypto";
import {
  exportPublicKeyJwk,
  exportPublicKeyJwkRsa,
  exportSymmetricKeyJwk,
  generateEd25519KeyPair,
  generateP256KeyPair,
  generateP384KeyPair,
  generateP521KeyPair,
  generateRsaPssKeyPair,
  importPrivateKeyJwk,
  secretKey,
  signRequest,
  verifyRequest,
  type SignedHttpRequest,
} from "../src/index.js";

const CREATED = 1700000000;
const REQ = {
  method: "POST",
  url: "https://api.example.com/v1/payments",
  headers: {} as Record<string, string>,
  body: '{"amount":100}',
};

function freshReq(): typeof REQ {
  return { ...REQ, headers: { ...REQ.headers } };
}

function signWith(
  key: Parameters<typeof signRequest>[1]["key"],
  alg: Parameters<typeof signRequest>[1]["alg"],
): SignedHttpRequest {
  return signRequest(freshReq(), { keyId: "k1", alg, key, created: CREATED });
}

/** The JWK as received over the wire: JSON text, like a KMS export. */
function wire(jwk: unknown): unknown {
  return JSON.parse(JSON.stringify(jwk)) as unknown;
}

test("ed25519 private JWK round-trip: import signs, original public key verifies", () => {
  const { publicKey, privateKey } = generateEd25519KeyPair();
  const exported = privateKey.export({ format: "jwk" }) as unknown;
  const imported = importPrivateKeyJwk(wire(exported));
  assert.equal(imported.type, "private");
  assert.equal(imported.asymmetricKeyType, "ed25519");
  // The public half of the imported key is the original public key.
  const importedPublic = createPublicKey(imported);
  assert.deepEqual(
    importedPublic.export({ format: "jwk" }),
    publicKey.export({ format: "jwk" }),
  );
  const signed = signWith(imported, "ed25519");
  assert.equal(verifyRequest(signed, { key: publicKey, now: CREATED }).ok, true);
});

test("P-256 private JWK round-trip signs ecdsa-p256-sha256", () => {
  const { publicKey, privateKey } = generateP256KeyPair();
  const imported = importPrivateKeyJwk(
    wire(privateKey.export({ format: "jwk" })),
  );
  assert.equal(imported.type, "private");
  assert.equal(imported.asymmetricKeyDetails?.namedCurve, "prime256v1");
  const signed = signWith(imported, "ecdsa-p256-sha256");
  assert.equal(verifyRequest(signed, { key: publicKey, now: CREATED }).ok, true);
});

test("P-384 private JWK round-trip signs ecdsa-p384-sha384", () => {
  const { publicKey, privateKey } = generateP384KeyPair();
  const imported = importPrivateKeyJwk(
    wire(privateKey.export({ format: "jwk" })),
  );
  assert.equal(imported.asymmetricKeyDetails?.namedCurve, "secp384r1");
  const signed = signWith(imported, "ecdsa-p384-sha384");
  assert.equal(verifyRequest(signed, { key: publicKey, now: CREATED }).ok, true);
});

test("P-521 private JWK round-trip signs ecdsa-p521-sha512", () => {
  const { publicKey, privateKey } = generateP521KeyPair();
  const imported = importPrivateKeyJwk(
    wire(privateKey.export({ format: "jwk" })),
  );
  assert.equal(imported.asymmetricKeyDetails?.namedCurve, "secp521r1");
  const signed = signWith(imported, "ecdsa-p521-sha512");
  assert.equal(verifyRequest(signed, { key: publicKey, now: CREATED }).ok, true);
});

test("RSA private JWK round-trip signs both rsa-pss-sha512 and rsa-v1_5-sha256", () => {
  const { publicKey, privateKey } = generateRsaPssKeyPair();
  const imported = importPrivateKeyJwk(
    wire(privateKey.export({ format: "jwk" })),
  );
  assert.equal(imported.type, "private");
  assert.equal(imported.asymmetricKeyType, "rsa");
  const pss = signWith(imported, "rsa-pss-sha512");
  assert.equal(verifyRequest(pss, { key: publicKey, now: CREATED }).ok, true);
  const v15 = signWith(imported, "rsa-v1_5-sha256");
  assert.equal(verifyRequest(v15, { key: publicKey, now: CREATED }).ok, true);
});

test("oct private JWK round-trip: import signs hmac-sha256 with the same secret", () => {
  const secret = secretKey(Buffer.alloc(32, 7));
  const jwk = exportSymmetricKeyJwk(secret);
  const imported = importPrivateKeyJwk(wire(jwk));
  assert.equal(imported.type, "secret");
  const importedJwk = imported.export({ format: "jwk" }) as unknown as {
    k: string;
  };
  assert.equal(importedJwk.k, jwk.k);
  const signed = signWith(imported, "hmac-sha256");
  assert.equal(verifyRequest(signed, { key: secret, now: CREATED }).ok, true);
});

test("oct JWK with alg HS512 imports a 64-byte secret and signs hmac-sha512", () => {
  const secret = secretKey(Buffer.alloc(64, 9));
  const jwk = exportSymmetricKeyJwk(secret, { alg: "HS512" });
  const imported = importPrivateKeyJwk(wire(jwk));
  const signed = signWith(imported, "hmac-sha512");
  assert.equal(verifyRequest(signed, { key: secret, now: CREATED }).ok, true);
});

test("oct JWK declaring HS512 with only 32 bytes is refused by the floor", () => {
  const secret = secretKey(Buffer.alloc(32, 7));
  const jwk = exportSymmetricKeyJwk(secret);
  assert.throws(
    () => importPrivateKeyJwk({ ...jwk, alg: "HS512" }),
    /importPrivateKeyJwk: invalid JWK: .*at least 64 bytes/,
  );
});

test("public JWKs (missing d) are refused, ed25519 and RSA", () => {
  const { publicKey: edPublic } = generateEd25519KeyPair();
  assert.throws(
    () => importPrivateKeyJwk(wire(exportPublicKeyJwk(edPublic))),
    /importPrivateKeyJwk: invalid JWK: missing or empty "d"/,
  );
  const { publicKey: rsaPublic } = generateRsaPssKeyPair();
  assert.throws(
    () => importPrivateKeyJwk(wire(exportPublicKeyJwkRsa(rsaPublic))),
    /importPrivateKeyJwk: invalid JWK: missing or empty "d"/,
  );
});

test("unsupported kty is refused", () => {
  assert.throws(
    () => importPrivateKeyJwk({ kty: "foo", d: "AAAA" }),
    /importPrivateKeyJwk: invalid JWK: unsupported kty "foo"/,
  );
  assert.throws(
    () => importPrivateKeyJwk({ d: "AAAA" }),
    /importPrivateKeyJwk: invalid JWK: missing "kty"/,
  );
});

test("unsupported crv is refused, OKP and EC", () => {
  const { privateKey } = generateEd25519KeyPair();
  const edJwk = privateKey.export({ format: "jwk" }) as Record<string, unknown>;
  assert.throws(
    () => importPrivateKeyJwk({ ...edJwk, crv: "X25519" }),
    /importPrivateKeyJwk: invalid JWK: expected crv "Ed25519"/,
  );
  const { privateKey: p256 } = generateP256KeyPair();
  const ecJwk = p256.export({ format: "jwk" }) as Record<string, unknown>;
  assert.throws(
    () => importPrivateKeyJwk({ ...ecJwk, crv: "P-999" }),
    /importPrivateKeyJwk: invalid JWK: unsupported crv "P-999"/,
  );
});

test("EC private JWK missing y is refused", () => {
  const { privateKey } = generateP256KeyPair();
  const jwk = privateKey.export({ format: "jwk" }) as Record<string, unknown>;
  const { y: _y, ...withoutY } = jwk;
  assert.throws(
    () => importPrivateKeyJwk(withoutY),
    /importPrivateKeyJwk: invalid JWK: missing or empty "y"/,
  );
});

test("RSA private JWK without the CRT parameters is refused by name", () => {
  const { privateKey } = generateRsaPssKeyPair();
  const jwk = privateKey.export({ format: "jwk" }) as Record<string, unknown>;
  const { n, e, d } = jwk;
  assert.throws(
    () => importPrivateKeyJwk({ kty: "RSA", n, e, d }),
    /importPrivateKeyJwk: invalid JWK: missing or empty "p"/,
  );
});

test("RSA private JWK below the 2048-bit floor is refused at import", () => {
  const { privateKey } = generateKeyPairSync("rsa", { modulusLength: 1024 });
  assert.throws(
    () => importPrivateKeyJwk(wire(privateKey.export({ format: "jwk" }))),
    /importPrivateKeyJwk: invalid JWK: RSA modulus must be at least 2048 bits/,
  );
});

test("short oct secret is refused by the hmac-sha256 floor", () => {
  const k = Buffer.alloc(16, 1).toString("base64url");
  assert.throws(
    () => importPrivateKeyJwk({ kty: "oct", k }),
    /importPrivateKeyJwk: invalid JWK: .*at least 32 bytes/,
  );
});

test("non-canonical oct k (padded base64url) is refused", () => {
  const k = `${Buffer.alloc(32, 7).toString("base64url")}=`;
  assert.throws(
    () => importPrivateKeyJwk({ kty: "oct", k }),
    /importPrivateKeyJwk: invalid JWK: "k" must be unpadded base64url/,
  );
});

test('use "enc" is refused, use "sig" imports and signs', () => {
  const { publicKey, privateKey } = generateEd25519KeyPair();
  const jwk = privateKey.export({ format: "jwk" }) as Record<string, unknown>;
  assert.throws(
    () => importPrivateKeyJwk({ ...jwk, use: "enc" }),
    /importPrivateKeyJwk: invalid JWK: unsupported "use" "enc"/,
  );
  const imported = importPrivateKeyJwk({ ...jwk, use: "sig" });
  const signed = signWith(imported, "ed25519");
  assert.equal(verifyRequest(signed, { key: publicKey, now: CREATED }).ok, true);
});

test('key_ops must include "sign" when present', () => {
  const { publicKey, privateKey } = generateEd25519KeyPair();
  const jwk = privateKey.export({ format: "jwk" }) as Record<string, unknown>;
  assert.throws(
    () => importPrivateKeyJwk({ ...jwk, key_ops: ["verify"] }),
    /importPrivateKeyJwk: invalid JWK: "key_ops" must include "sign"/,
  );
  assert.throws(
    () => importPrivateKeyJwk({ ...jwk, key_ops: "sign" }),
    /importPrivateKeyJwk: invalid JWK: "key_ops" must be an array of strings/,
  );
  const imported = importPrivateKeyJwk({
    ...jwk,
    key_ops: ["sign", "verify"],
  });
  const signed = signWith(imported, "ed25519");
  assert.equal(verifyRequest(signed, { key: publicKey, now: CREATED }).ok, true);
});

test("non-object inputs are refused", () => {
  assert.throws(
    () => importPrivateKeyJwk(null),
    /importPrivateKeyJwk: invalid JWK: expected a JWK object, got null/,
  );
  assert.throws(
    () => importPrivateKeyJwk("not-a-jwk"),
    /importPrivateKeyJwk: invalid JWK: expected a JWK object, got string/,
  );
  assert.throws(
    () => importPrivateKeyJwk([]),
    /importPrivateKeyJwk: invalid JWK: expected a JWK object, got an array/,
  );
});

test("extra members (kid, alg) are accepted and the key still signs", () => {
  const { publicKey, privateKey } = generateEd25519KeyPair();
  const jwk = privateKey.export({ format: "jwk" }) as Record<string, unknown>;
  const imported = importPrivateKeyJwk({
    ...jwk,
    kid: "kms-key-1",
    alg: "EdDSA",
  });
  const signed = signWith(imported, "ed25519");
  assert.equal(verifyRequest(signed, { key: publicKey, now: CREATED }).ok, true);
});
