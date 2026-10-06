import test from "node:test";
import assert from "node:assert/strict";
import { createPublicKey } from "node:crypto";
import {
  exportPublicKeyJwk,
  generateEd25519KeyPair,
  importPublicKeyJwk,
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

function signWith(privateKey: Parameters<typeof signRequest>[1]["key"]): SignedHttpRequest {
  return signRequest(
    { ...REQ, headers: { ...REQ.headers } },
    { keyId: "merchant-key-1", alg: "ed25519", key: privateKey, created: CREATED },
  );
}

test("export→JSON wire→import→verify round-trip passes", () => {
  const { publicKey, privateKey } = generateEd25519KeyPair();
  const jwk = exportPublicKeyJwk(publicKey);
  // The JWK crosses the wire as JSON text, like a webhook public-key endpoint.
  const received = JSON.parse(JSON.stringify(jwk)) as unknown;
  const imported = importPublicKeyJwk(received);
  // Bit identity: same DER as the original public key.
  assert.equal(
    imported.export({ format: "pem", type: "spki" }).toString(),
    publicKey.export({ format: "pem", type: "spki" }).toString(),
  );
  const signed = signWith(privateKey);
  const result = verifyRequest(signed, { key: imported, now: CREATED });
  assert.equal(result.ok, true);
});

test("exported JWK has the RFC 8037 ed25519 shape", () => {
  const { publicKey } = generateEd25519KeyPair();
  const jwk = exportPublicKeyJwk(publicKey);
  assert.deepEqual(Object.keys(jwk).sort(), ["crv", "kty", "x"]);
  assert.equal(jwk.kty, "OKP");
  assert.equal(jwk.crv, "Ed25519");
  assert.match(jwk.x, /^[A-Za-z0-9_-]{43}$/); // 32 bytes base64url, no padding
  assert.ok(!("d" in jwk), "public JWK must not carry private material");
});

test("export is deterministic for the same key", () => {
  const { publicKey } = generateEd25519KeyPair();
  assert.deepEqual(exportPublicKeyJwk(publicKey), exportPublicKeyJwk(publicKey));
});

test("exportPublicKeyJwk rejects non-ed25519-public keys", () => {
  const { publicKey, privateKey } = generateEd25519KeyPair();
  const secret = secretKey("a-shared-hmac-secret-of-32-bytes!!");
  assert.throws(() => exportPublicKeyJwk(privateKey), /ed25519 public KeyObject/);
  assert.throws(() => exportPublicKeyJwk(secret), /ed25519 public KeyObject/);
  // The imported key stays public: re-exporting it as JWK carries no "d".
  const imported = importPublicKeyJwk(exportPublicKeyJwk(publicKey));
  assert.ok(!("d" in (imported.export({ format: "jwk" }) as object)));
});

test("importPublicKeyJwk rejects structurally bad JWKs", () => {
  const { publicKey } = generateEd25519KeyPair();
  const good = exportPublicKeyJwk(publicKey);
  const { kty: _k, ...noKty } = good;
  const { crv: _c, ...noCrv } = good;
  const { x: _x, ...noX } = good;
  const cases: Array<[string, unknown, RegExp]> = [
    ["null", null, /expected a JWK object/],
    ["string", "{}", /expected a JWK object/],
    ["array", [good], /expected a JWK object/],
    ["missing kty", noKty, /missing "kty"/],
    ["missing crv", noCrv, /missing "crv"/],
    ["missing x", noX, /missing or empty "x"/],
    ["wrong kty", { ...good, kty: "RSA" }, /expected kty "OKP"/],
    ["wrong crv", { ...good, crv: "secp256k1" }, /expected crv "Ed25519"/],
    ["x not a string", { ...good, x: 42 }, /missing or empty "x"/],
    ["x empty", { ...good, x: "" }, /missing or empty "x"/],
    ["private JWK (d present)", { ...good, d: "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA" }, /private key material/],
  ];
  for (const [name, input, re] of cases) {
    assert.throws(() => importPublicKeyJwk(input), re, name);
  }
});

test("importPublicKeyJwk rejects cryptographically invalid x values", () => {
  const { publicKey } = generateEd25519KeyPair();
  const good = exportPublicKeyJwk(publicKey);
  // Node's native rejection is wrapped, never a verification failure.
  for (const [name, x] of [
    ["not base64url", "!!!not-base64!!!"],
    ["too short", "AAAA"],
    ["too long", good.x + good.x],
  ] as Array<[string, string]>) {
    assert.throws(() => importPublicKeyJwk({ ...good, x }), /invalid JWK/i, name);
  }
});

test("imported key is a real ed25519 public key that rejects tampered bodies", () => {
  const { publicKey, privateKey } = generateEd25519KeyPair();
  const imported = importPublicKeyJwk(
    JSON.parse(JSON.stringify(exportPublicKeyJwk(publicKey))),
  );
  const signed = signWith(privateKey);
  const tampered = {
    ...signed,
    headers: { ...signed.headers },
    body: '{"amount":999}',
  };
  const result = verifyRequest(tampered, { key: imported, now: CREATED });
  assert.equal(result.ok, false);
  assert.equal(result.code, "BODY_DIGEST_MISMATCH");
});

test("imported JWK key works behind a keyResolver (gateway pattern)", () => {
  const { publicKey, privateKey } = generateEd25519KeyPair();
  // Verifier side only ever sees the JWK, e.g. fetched from a key endpoint.
  const wireJwk = JSON.parse(JSON.stringify(exportPublicKeyJwk(publicKey)));
  const store = new Map<string, ReturnType<typeof createPublicKey>>();
  const signed = signWith(privateKey);
  const result = verifyRequest(signed, {
    now: CREATED,
    keyResolver: (keyId) => {
      if (keyId !== "merchant-key-1") return undefined;
      let key = store.get(keyId);
      if (!key) {
        key = importPublicKeyJwk(wireJwk);
        store.set(keyId, key);
      }
      return key;
    },
  });
  assert.equal(result.ok, true);
  assert.equal(result.keyId, "merchant-key-1");
});
