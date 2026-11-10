import test from "node:test";
import assert from "node:assert/strict";
import { createPublicKey, generateKeyPairSync } from "node:crypto";
import {
  exportPrivateKeyJwk,
  exportPrivateKeyJwkP256,
  exportPrivateKeyJwkP384,
  exportPrivateKeyJwkP521,
  exportPrivateKeyJwkRsa,
  exportPublicKeyJwk,
  exportPublicKeyJwkRsa,
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

test("ed25519 private JWK: export -> wire -> import -> sign -> verify, x/d byte-identical", () => {
  const { publicKey, privateKey } = generateEd25519KeyPair();
  const exported = exportPrivateKeyJwk(privateKey);
  // Exact shape: no extra members beyond the documented four.
  assert.deepEqual(Object.keys(exported).sort(), ["crv", "d", "kty", "x"]);
  assert.equal(exported.kty, "OKP");
  assert.equal(exported.crv, "Ed25519");
  // `x` is the public half, `d` the private seed — both byte-identical
  // to what node:crypto itself emits for the same key.
  const raw = privateKey.export({ format: "jwk" }) as unknown as Record<
    string,
    string
  >;
  assert.equal(exported.x, raw["x"]);
  assert.equal(exported.d, raw["d"]);
  assert.equal(exported.x, exportPublicKeyJwk(publicKey).x);
  // The exported JWK round-trips through JSON text and imports to a
  // key that signs; the original public key verifies the signature.
  const imported = importPrivateKeyJwk(wire(exported));
  assert.equal(imported.type, "private");
  assert.equal(imported.asymmetricKeyType, "ed25519");
  const signed = signWith(imported, "ed25519");
  assert.equal(verifyRequest(signed, { key: publicKey, now: CREATED }).ok, true);
});

test("P-256 private JWK round-trip signs ecdsa-p256-sha256", () => {
  const { publicKey, privateKey } = generateP256KeyPair();
  const exported = exportPrivateKeyJwkP256(privateKey);
  assert.deepEqual(Object.keys(exported).sort(), [
    "crv",
    "d",
    "kty",
    "x",
    "y",
  ]);
  assert.equal(exported.crv, "P-256");
  const raw = privateKey.export({ format: "jwk" }) as unknown as Record<
    string,
    string
  >;
  assert.equal(exported.x, raw["x"]);
  assert.equal(exported.y, raw["y"]);
  assert.equal(exported.d, raw["d"]);
  const imported = importPrivateKeyJwk(wire(exported));
  const signed = signWith(imported, "ecdsa-p256-sha256");
  assert.equal(verifyRequest(signed, { key: publicKey, now: CREATED }).ok, true);
});

test("P-384 private JWK round-trip signs ecdsa-p384-sha384", () => {
  const { publicKey, privateKey } = generateP384KeyPair();
  const exported = exportPrivateKeyJwkP384(privateKey);
  assert.deepEqual(Object.keys(exported).sort(), [
    "crv",
    "d",
    "kty",
    "x",
    "y",
  ]);
  assert.equal(exported.crv, "P-384");
  const raw = privateKey.export({ format: "jwk" }) as unknown as Record<
    string,
    string
  >;
  assert.equal(exported.x, raw["x"]);
  assert.equal(exported.y, raw["y"]);
  assert.equal(exported.d, raw["d"]);
  const imported = importPrivateKeyJwk(wire(exported));
  const signed = signWith(imported, "ecdsa-p384-sha384");
  assert.equal(verifyRequest(signed, { key: publicKey, now: CREATED }).ok, true);
});

test("P-521 private JWK round-trip signs ecdsa-p521-sha512", () => {
  const { publicKey, privateKey } = generateP521KeyPair();
  const exported = exportPrivateKeyJwkP521(privateKey);
  assert.deepEqual(Object.keys(exported).sort(), [
    "crv",
    "d",
    "kty",
    "x",
    "y",
  ]);
  assert.equal(exported.crv, "P-521");
  const raw = privateKey.export({ format: "jwk" }) as unknown as Record<
    string,
    string
  >;
  assert.equal(exported.x, raw["x"]);
  assert.equal(exported.y, raw["y"]);
  assert.equal(exported.d, raw["d"]);
  const imported = importPrivateKeyJwk(wire(exported));
  const signed = signWith(imported, "ecdsa-p521-sha512");
  assert.equal(verifyRequest(signed, { key: publicKey, now: CREATED }).ok, true);
});

test("RSA private JWK: full CRT set, no extra members, serves both RSA algs", () => {
  const { publicKey, privateKey } = generateRsaPssKeyPair();
  const exported = exportPrivateKeyJwkRsa(privateKey);
  assert.deepEqual(Object.keys(exported).sort(), [
    "d",
    "dp",
    "dq",
    "e",
    "kty",
    "n",
    "p",
    "q",
    "qi",
  ]);
  assert.equal(exported.kty, "RSA");
  const raw = privateKey.export({ format: "jwk" }) as unknown as Record<
    string,
    string
  >;
  for (const member of ["n", "e", "d", "p", "q", "dp", "dq", "qi"] as const) {
    assert.equal(exported[member], raw[member]);
    assert.ok(exported[member].length > 0, `${member} must be non-empty`);
  }
  assert.equal(exported.n, exportPublicKeyJwkRsa(publicKey).n);
  // The imported key signs with both RSA algorithms: the JWK carries
  // no `alg`, so padding/hash live in the signature, not the key.
  const imported = importPrivateKeyJwk(wire(exported));
  const pss = signWith(imported, "rsa-pss-sha512");
  assert.equal(verifyRequest(pss, { key: publicKey, now: CREATED }).ok, true);
  const v15 = signWith(imported, "rsa-v1_5-sha256");
  assert.equal(verifyRequest(v15, { key: publicKey, now: CREATED }).ok, true);
});

test("re-export after import is byte-identical (ed25519 and RSA)", () => {
  const ed = generateEd25519KeyPair();
  const edExported = exportPrivateKeyJwk(ed.privateKey);
  const edReimported = importPrivateKeyJwk(wire(edExported));
  assert.deepEqual(exportPrivateKeyJwk(edReimported), edExported);
  const rsa = generateRsaPssKeyPair();
  const rsaExported = exportPrivateKeyJwkRsa(rsa.privateKey);
  const rsaReimported = importPrivateKeyJwk(wire(rsaExported));
  assert.deepEqual(exportPrivateKeyJwkRsa(rsaReimported), rsaExported);
  // The public half of the re-imported key is the original public key.
  assert.deepEqual(
    createPublicKey(rsaReimported).export({ format: "jwk" }),
    rsa.publicKey.export({ format: "jwk" }),
  );
});

test("exporting the same key twice is deterministic", () => {
  const { privateKey } = generateEd25519KeyPair();
  assert.deepEqual(
    exportPrivateKeyJwk(privateKey),
    exportPrivateKeyJwk(privateKey),
  );
  const rsa = generateRsaPssKeyPair();
  assert.deepEqual(
    exportPrivateKeyJwkRsa(rsa.privateKey),
    exportPrivateKeyJwkRsa(rsa.privateKey),
  );
});

test("public keys are refused by every private exporter", () => {
  const ed = generateEd25519KeyPair();
  assert.throws(() => exportPrivateKeyJwk(ed.publicKey), /ed25519 private/);
  const p256 = generateP256KeyPair();
  assert.throws(
    () => exportPrivateKeyJwkP256(p256.publicKey),
    /P-256 private/,
  );
  const p384 = generateP384KeyPair();
  assert.throws(
    () => exportPrivateKeyJwkP384(p384.publicKey),
    /P-384 private/,
  );
  const p521 = generateP521KeyPair();
  assert.throws(
    () => exportPrivateKeyJwkP521(p521.publicKey),
    /P-521 private/,
  );
  const rsa = generateRsaPssKeyPair();
  assert.throws(() => exportPrivateKeyJwkRsa(rsa.publicKey), /RSA private/);
});

test("curve mismatch is refused, never silently re-interpreted", () => {
  const p256 = generateP256KeyPair();
  assert.throws(
    () => exportPrivateKeyJwkP384(p256.privateKey),
    /P-384 private/,
  );
  assert.throws(
    () => exportPrivateKeyJwkP521(p256.privateKey),
    /P-521 private/,
  );
  const p384 = generateP384KeyPair();
  assert.throws(
    () => exportPrivateKeyJwkP256(p384.privateKey),
    /P-256 private/,
  );
  const p521 = generateP521KeyPair();
  assert.throws(
    () => exportPrivateKeyJwkP384(p521.privateKey),
    /P-384 private/,
  );
});

test("cross-family keys are refused (ed25519 into EC, RSA into ed25519)", () => {
  const ed = generateEd25519KeyPair();
  assert.throws(
    () => exportPrivateKeyJwkP256(ed.privateKey),
    /P-256 private/,
  );
  const rsa = generateRsaPssKeyPair();
  assert.throws(() => exportPrivateKeyJwk(rsa.privateKey), /ed25519 private/);
  const p256 = generateP256KeyPair();
  assert.throws(
    () => exportPrivateKeyJwkRsa(p256.privateKey),
    /RSA private/,
  );
});

test("RSA below the 2048-bit floor is refused at export", () => {
  const weak = generateKeyPairSync("rsa", { modulusLength: 1024 });
  assert.throws(
    () => exportPrivateKeyJwkRsa(weak.privateKey),
    /RSA modulus must be at least 2048 bits, got 1024 bits/,
  );
});

test("oct symmetric secrets are refused (they have their own exporter)", () => {
  const secret = secretKey(Buffer.alloc(32, 7));
  assert.throws(() => exportPrivateKeyJwk(secret), /ed25519 private/);
  assert.throws(() => exportPrivateKeyJwkRsa(secret), /RSA private/);
});

test("the original KeyObject still signs after export", () => {
  const ed = generateEd25519KeyPair();
  exportPrivateKeyJwk(ed.privateKey);
  const signed = signWith(ed.privateKey, "ed25519");
  assert.equal(
    verifyRequest(signed, { key: ed.publicKey, now: CREATED }).ok,
    true,
  );
  const rsa = generateRsaPssKeyPair();
  exportPrivateKeyJwkRsa(rsa.privateKey);
  const rsaSigned = signWith(rsa.privateKey, "rsa-pss-sha512");
  assert.equal(
    verifyRequest(rsaSigned, { key: rsa.publicKey, now: CREATED }).ok,
    true,
  );
});
