import test from "node:test";
import assert from "node:assert/strict";
import {
  exportPublicKeyJwk,
  exportPublicKeyJwkP256,
  exportPublicKeyJwkRsa,
  generateEd25519KeyPair,
  generateP256KeyPair,
  generateRsaPssKeyPair,
  importPublicKeyJwk,
  importPublicKeyJwkP256,
  importPublicKeyJwkRsa,
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

function signRsaPss(
  privateKey: Parameters<typeof signRequest>[1]["key"],
): SignedHttpRequest {
  return signRequest(
    { ...REQ, headers: { ...REQ.headers } },
    {
      keyId: "gateway-rsa",
      alg: "rsa-pss-sha512",
      key: privateKey,
      created: CREATED,
    },
  );
}

test("export→JSON wire→import→verify rsa-pss-sha512 round-trip passes", () => {
  const { publicKey, privateKey } = generateRsaPssKeyPair();
  const jwk = exportPublicKeyJwkRsa(publicKey);
  // The JWK crosses the wire as JSON text, like a webhook public-key endpoint.
  const received = JSON.parse(JSON.stringify(jwk)) as unknown;
  const imported = importPublicKeyJwkRsa(received);
  // Bit identity: same DER as the original public key.
  assert.equal(
    imported.export({ format: "pem", type: "spki" }).toString(),
    publicKey.export({ format: "pem", type: "spki" }).toString(),
  );
  const signed = signRsaPss(privateKey);
  const result = verifyRequest(signed, { key: imported, now: CREATED });
  assert.equal(result.ok, true);
  assert.equal(result.alg, "rsa-pss-sha512");
});

test("exported JWK has the RFC 7518 RSA shape", () => {
  const { publicKey } = generateRsaPssKeyPair();
  const jwk = exportPublicKeyJwkRsa(publicKey);
  assert.deepEqual(Object.keys(jwk).sort(), ["e", "kty", "n"]);
  assert.equal(jwk.kty, "RSA");
  // 2048-bit modulus → 256 bytes base64url, no padding; e = 65537.
  assert.match(jwk.n, /^[A-Za-z0-9_-]{342,343}$/);
  assert.equal(jwk.e, "AQAB");
  assert.ok(!("d" in jwk), "public JWK must not carry private material");
});

test("export is deterministic for the same key", () => {
  const { publicKey } = generateRsaPssKeyPair();
  assert.deepEqual(
    exportPublicKeyJwkRsa(publicKey),
    exportPublicKeyJwkRsa(publicKey),
  );
});

test("exportPublicKeyJwkRsa rejects non-RSA-public keys", () => {
  const { privateKey: rsaPriv } = generateRsaPssKeyPair();
  assert.throws(() => exportPublicKeyJwkRsa(rsaPriv), /RSA public/);

  const { publicKey: ed25519Pub } = generateEd25519KeyPair();
  assert.throws(() => exportPublicKeyJwkRsa(ed25519Pub), /RSA public/);

  const { publicKey: p256Pub } = generateP256KeyPair();
  assert.throws(() => exportPublicKeyJwkRsa(p256Pub), /RSA public/);

  const secret = secretKey("a".repeat(32));
  assert.throws(() => exportPublicKeyJwkRsa(secret), /RSA public/);
});

test("importPublicKeyJwkRsa rejects malformed JWK shapes", () => {
  const { publicKey } = generateRsaPssKeyPair();
  const good = exportPublicKeyJwkRsa(publicKey) as unknown as Record<
    string,
    unknown
  >;

  assert.throws(() => importPublicKeyJwkRsa(null), /invalid JWK/);
  assert.throws(() => importPublicKeyJwkRsa("not-an-object"), /invalid JWK/);
  assert.throws(() => importPublicKeyJwkRsa([]), /invalid JWK/);

  const missingN = { ...good };
  delete missingN["n"];
  assert.throws(() => importPublicKeyJwkRsa(missingN), /missing or empty "n"/);

  const missingE = { ...good };
  delete missingE["e"];
  assert.throws(() => importPublicKeyJwkRsa(missingE), /missing or empty "e"/);

  assert.throws(
    () => importPublicKeyJwkRsa({ ...good, kty: "OKP" }),
    /expected kty "RSA"/,
  );
  assert.throws(
    () => importPublicKeyJwkRsa({ ...good, kty: "EC", crv: "P-256" }),
    /expected kty "RSA"/,
  );
  assert.throws(
    () => importPublicKeyJwkRsa({ ...good, d: "AAAA" }),
    /private key material/,
  );
  assert.throws(
    () => importPublicKeyJwkRsa({ ...good, n: "" }),
    /missing or empty "n"/,
  );
  assert.throws(
    () => importPublicKeyJwkRsa({ ...good, e: 65537 }),
    /missing or empty "e"/,
  );
});

test("a cryptographically degenerate modulus fails closed at verify time", () => {
  // node:crypto's RSA JWK importer is lenient: a zero-length modulus is
  // accepted at import. The failure must therefore surface at verify time,
  // as a verification failure — never a silent ok:true.
  const { privateKey } = generateRsaPssKeyPair();
  const degen = importPublicKeyJwkRsa({ kty: "RSA", n: "AAAA", e: "AQAB" });
  const signed = signRsaPss(privateKey);
  const result = verifyRequest(signed, { key: degen, now: CREATED });
  assert.equal(result.ok, false);
  assert.equal(result.code, "SIGNATURE_MISMATCH");
});

test("imported RSA key composes with keyResolver", () => {
  const { publicKey, privateKey } = generateRsaPssKeyPair();
  const jwk = exportPublicKeyJwkRsa(publicKey);
  const received = JSON.parse(JSON.stringify(jwk)) as unknown;
  const signed = signRsaPss(privateKey);
  const result = verifyRequest(signed, {
    keyResolver: (keyId) =>
      keyId === "gateway-rsa" ? importPublicKeyJwkRsa(received) : undefined,
    now: CREATED,
  });
  assert.equal(result.ok, true);
});

test("ed25519 and P-256 JWK paths are unaffected by the RSA additions", () => {
  const { publicKey: edPub, privateKey: edPriv } = generateEd25519KeyPair();
  const edJwk = exportPublicKeyJwk(edPub);
  const edImported = importPublicKeyJwk(JSON.parse(JSON.stringify(edJwk)));
  const edSigned = signRequest(
    { ...REQ, headers: { ...REQ.headers } },
    { keyId: "merchant-key-1", alg: "ed25519", key: edPriv, created: CREATED },
  );
  assert.equal(
    verifyRequest(edSigned, { key: edImported, now: CREATED }).ok,
    true,
  );

  const { publicKey: p256Pub, privateKey: p256Priv } = generateP256KeyPair();
  const p256Jwk = exportPublicKeyJwkP256(p256Pub);
  const p256Imported = importPublicKeyJwkP256(
    JSON.parse(JSON.stringify(p256Jwk)),
  );
  const p256Signed = signRequest(
    { ...REQ, headers: { ...REQ.headers } },
    {
      keyId: "gateway-p256",
      alg: "ecdsa-p256-sha256",
      key: p256Priv,
      created: CREATED,
    },
  );
  assert.equal(
    verifyRequest(p256Signed, { key: p256Imported, now: CREATED }).ok,
    true,
  );

  // Cross-rejection: the RSA importer still refuses the other shapes.
  assert.throws(
    () => importPublicKeyJwkRsa(edJwk as unknown),
    /expected kty "RSA"/,
  );
  assert.throws(
    () => importPublicKeyJwkRsa(p256Jwk as unknown),
    /expected kty "RSA"/,
  );
  // Cross-rejection: the ed25519 / P-256 importers still refuse the RSA shape.
  const { publicKey: rsaPub } = generateRsaPssKeyPair();
  const rsaJwk = exportPublicKeyJwkRsa(rsaPub);
  assert.throws(
    () => importPublicKeyJwk(rsaJwk as unknown),
    /expected kty "OKP"/,
  );
  assert.throws(
    () => importPublicKeyJwkP256(rsaJwk as unknown),
    /expected kty "EC"/,
  );
});
