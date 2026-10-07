import test from "node:test";
import assert from "node:assert/strict";
import {
  exportPublicKeyJwk,
  exportPublicKeyJwkP256,
  generateEd25519KeyPair,
  generateP256KeyPair,
  generateRsaPssKeyPair,
  importPublicKeyJwk,
  importPublicKeyJwkP256,
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

function signP256(
  privateKey: Parameters<typeof signRequest>[1]["key"],
): SignedHttpRequest {
  return signRequest(
    { ...REQ, headers: { ...REQ.headers } },
    {
      keyId: "gateway-p256",
      alg: "ecdsa-p256-sha256",
      key: privateKey,
      created: CREATED,
    },
  );
}

test("export→JSON wire→import→verify round-trip passes", () => {
  const { publicKey, privateKey } = generateP256KeyPair();
  const jwk = exportPublicKeyJwkP256(publicKey);
  // The JWK crosses the wire as JSON text, like a webhook public-key endpoint.
  const received = JSON.parse(JSON.stringify(jwk)) as unknown;
  const imported = importPublicKeyJwkP256(received);
  // Bit identity: same DER as the original public key.
  assert.equal(
    imported.export({ format: "pem", type: "spki" }).toString(),
    publicKey.export({ format: "pem", type: "spki" }).toString(),
  );
  const signed = signP256(privateKey);
  const result = verifyRequest(signed, { key: imported, now: CREATED });
  assert.equal(result.ok, true);
});

test("exported JWK has the RFC 7518 P-256 shape", () => {
  const { publicKey } = generateP256KeyPair();
  const jwk = exportPublicKeyJwkP256(publicKey);
  assert.deepEqual(Object.keys(jwk).sort(), ["crv", "kty", "x", "y"]);
  assert.equal(jwk.kty, "EC");
  assert.equal(jwk.crv, "P-256");
  assert.match(jwk.x, /^[A-Za-z0-9_-]{43}$/); // 32 bytes base64url, no padding
  assert.match(jwk.y, /^[A-Za-z0-9_-]{43}$/);
  assert.ok(!("d" in jwk), "public JWK must not carry private material");
});

test("export is deterministic for the same key", () => {
  const { publicKey } = generateP256KeyPair();
  assert.deepEqual(
    exportPublicKeyJwkP256(publicKey),
    exportPublicKeyJwkP256(publicKey),
  );
});

test("exportPublicKeyJwkP256 rejects non-P-256-public keys", () => {
  const { publicKey: ed25519Pub } = generateEd25519KeyPair();
  assert.throws(() => exportPublicKeyJwkP256(ed25519Pub), /P-256 public/);

  const { privateKey: p256Priv } = generateP256KeyPair();
  assert.throws(() => exportPublicKeyJwkP256(p256Priv), /P-256 public/);

  const { publicKey: rsaPub } = generateRsaPssKeyPair();
  assert.throws(() => exportPublicKeyJwkP256(rsaPub), /P-256 public/);

  const secret = secretKey("a".repeat(32));
  assert.throws(() => exportPublicKeyJwkP256(secret), /P-256 public/);
});

test("importPublicKeyJwkP256 rejects malformed JWK shapes", () => {
  const { publicKey } = generateP256KeyPair();
  const good = exportPublicKeyJwkP256(publicKey) as unknown as Record<
    string,
    unknown
  >;

  assert.throws(() => importPublicKeyJwkP256(null), /invalid JWK/);
  assert.throws(() => importPublicKeyJwkP256("not-an-object"), /invalid JWK/);
  assert.throws(() => importPublicKeyJwkP256([]), /invalid JWK/);

  const missingY = { ...good };
  delete missingY["y"];
  assert.throws(() => importPublicKeyJwkP256(missingY), /missing or empty "y"/);

  const missingX = { ...good };
  delete missingX["x"];
  assert.throws(() => importPublicKeyJwkP256(missingX), /missing or empty "x"/);

  assert.throws(
    () => importPublicKeyJwkP256({ ...good, crv: "P-384" }),
    /expected crv "P-256"/,
  );
  assert.throws(
    () => importPublicKeyJwkP256({ ...good, kty: "OKP" }),
    /expected kty "EC"/,
  );
  assert.throws(
    () => importPublicKeyJwkP256({ ...good, d: "AAAA" }),
    /private key material/,
  );
  assert.throws(
    () => importPublicKeyJwkP256({ ...good, x: "" }),
    /missing or empty "x"/,
  );
});

test("importPublicKeyJwkP256 rejects cryptographically invalid coordinates", () => {
  const { publicKey } = generateP256KeyPair();
  const good = exportPublicKeyJwkP256(publicKey);

  // Right shape, wrong-length x: passes our shape checks, node:crypto refuses.
  assert.throws(
    () => importPublicKeyJwkP256({ ...good, x: "AAAA" }),
    /node:crypto rejected the JWK/,
  );
  // 32 bytes of zeroes is not a valid curve point.
  assert.throws(
    () =>
      importPublicKeyJwkP256({
        ...good,
        x: Buffer.alloc(32).toString("base64url"),
        y: Buffer.alloc(32).toString("base64url"),
      }),
    /node:crypto rejected the JWK/,
  );
});

test("imported P-256 key composes with keyResolver", () => {
  const { publicKey, privateKey } = generateP256KeyPair();
  const jwk = exportPublicKeyJwkP256(publicKey);
  const received = JSON.parse(JSON.stringify(jwk)) as unknown;
  const signed = signP256(privateKey);
  const result = verifyRequest(signed, {
    keyResolver: (keyId) =>
      keyId === "gateway-p256" ? importPublicKeyJwkP256(received) : undefined,
    now: CREATED,
  });
  assert.equal(result.ok, true);
});

test("flipped signature byte fails with SIGNATURE_MISMATCH under the imported P-256 key", () => {
  const { publicKey, privateKey } = generateP256KeyPair();
  const imported = importPublicKeyJwkP256(
    JSON.parse(JSON.stringify(exportPublicKeyJwkP256(publicKey))),
  );
  const signed = signP256(privateKey);
  const raw = Buffer.from(
    signed.headers["signature"].slice("sig1=:".length, -1),
    "base64",
  );
  raw[raw.length - 1] ^= 0x01;
  const tampered: SignedHttpRequest = {
    ...signed,
    headers: {
      ...signed.headers,
      signature: `sig1=:${raw.toString("base64")}:`,
    },
  };
  const result = verifyRequest(tampered, { key: imported, now: CREATED });
  assert.equal(result.ok, false);
  assert.equal(result.code, "SIGNATURE_MISMATCH");
});

test("ed25519 JWK path is unaffected by the P-256 additions", () => {
  const { publicKey: edPub, privateKey: edPriv } = generateEd25519KeyPair();
  const jwk = exportPublicKeyJwk(edPub) as unknown as Record<string, unknown>;
  const imported = importPublicKeyJwk(JSON.parse(JSON.stringify(jwk)));
  const signed = signRequest(
    { ...REQ, headers: { ...REQ.headers } },
    {
      keyId: "merchant-key-1",
      alg: "ed25519",
      key: edPriv,
      created: CREATED,
    },
  );
  const result = verifyRequest(signed, { key: imported, now: CREATED });
  assert.equal(result.ok, true);
  // Cross-rejection: the ed25519 importer still refuses P-256 JWK shapes.
  const { publicKey: p256Pub } = generateP256KeyPair();
  assert.throws(
    () => importPublicKeyJwk(exportPublicKeyJwkP256(p256Pub) as unknown),
    /invalid JWK/,
  );
  // Cross-rejection: the P-256 importer still refuses ed25519 JWK shapes.
  assert.throws(
    () => importPublicKeyJwkP256(jwk as unknown),
    /invalid JWK/,
  );
});
