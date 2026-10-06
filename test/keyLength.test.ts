import test from "node:test";
import assert from "node:assert/strict";
import { createSecretKey, type KeyObject } from "node:crypto";
import {
  assertHmacSecretLength,
  generateEd25519KeyPair,
  MIN_HMAC_SECRET_BYTES,
  secretKey,
  signRequest,
  verifyRequest,
  verifyRequestOrThrow,
} from "../src/index.js";

const CREATED = 1700000000;
const REQ = {
  method: "POST",
  url: "https://api.example.com/v1/payments",
  headers: {},
  body: '{"amount":100}',
};

function hmacReq(secret: string | Buffer) {
  return signRequest(REQ, {
    keyId: "hmac-key-1",
    alg: "hmac-sha256",
    key: secretKey(secret),
    created: CREATED,
  });
}

/** A secret KeyObject that bypasses secretKey() — what a careless caller
 *  could hand to sign/verify directly via node:crypto. */
function rawSecret(bytes: number): KeyObject {
  return createSecretKey(Buffer.alloc(bytes, 0xab));
}

test("MIN_HMAC_SECRET_BYTES is 32 (RFC 2104: key ≥ hash output)", () => {
  assert.equal(MIN_HMAC_SECRET_BYTES, 32);
});

test("secretKey: 31-byte secret throws, 32 and 64 bytes pass", () => {
  assert.throws(
    () => secretKey(Buffer.alloc(31, 0x42)),
    /at least 32 bytes.*got 31 bytes/,
  );
  assert.doesNotThrow(() => secretKey(Buffer.alloc(32, 0x42)));
  assert.doesNotThrow(() => secretKey(Buffer.alloc(64, 0x42)));
});

test("secretKey: short string secret throws with a clear config message", () => {
  assert.throws(() => secretKey("s3cret"), /secretKey: .*at least 32 bytes/);
  assert.throws(() => secretKey(""), /got 0 bytes/);
});

test("assertHmacSecretLength: rejects asymmetric keys (never valid HMAC secrets)", () => {
  const { publicKey, privateKey } = generateEd25519KeyPair();
  assert.throws(
    () => assertHmacSecretLength(publicKey),
    /expected a symmetric secret KeyObject/,
  );
  assert.throws(
    () => assertHmacSecretLength(privateKey),
    /expected a symmetric secret KeyObject/,
  );
});

test("signRequest hmac-sha256: rejects a short raw secret even when secretKey() is bypassed", () => {
  assert.throws(
    () =>
      signRequest(REQ, {
        keyId: "k",
        alg: "hmac-sha256",
        key: rawSecret(31),
        created: CREATED,
      }),
    /assertHmacSecretLength: .*at least 32 bytes.*got 31 bytes/,
  );
  // 32 bytes is fine and signs normally.
  const signed = signRequest(REQ, {
    keyId: "k",
    alg: "hmac-sha256",
    key: rawSecret(32),
    created: CREATED,
  });
  assert.match(signed.headers["signature"], /^sig1=:[A-Za-z0-9+/=]+:$/);
});

test("verifyRequest hmac-sha256: rejects a short raw secret (symmetric with the sign side)", () => {
  const signed = hmacReq(Buffer.alloc(32, 0xab));
  assert.throws(
    () => verifyRequest(signed, { key: rawSecret(31), now: CREATED + 60 }),
    /assertHmacSecretLength: .*at least 32 bytes.*got 31 bytes/,
  );
  // 32-byte secret verifies the same request just fine.
  const ok = verifyRequest(signed, { key: rawSecret(32), now: CREATED + 60 });
  assert.equal(ok.ok, true);
});

test("verifyRequestOrThrow: short hmac secret propagates as a config Error (not VerifyError)", () => {
  const signed = hmacReq(Buffer.alloc(64, 0xab));
  assert.throws(
    () => verifyRequestOrThrow(signed, { key: rawSecret(16) }),
    (e: unknown) =>
      e instanceof Error &&
      e.name === "Error" && // not VerifyError: configuration, not verification failure
      /at least 32 bytes/.test(e.message),
  );
});

test("hmac boundary round-trip: 32-byte and 64-byte secrets sign→verify cleanly", () => {
  for (const n of [32, 64]) {
    const key = secretKey(Buffer.alloc(n, 0xcd));
    const signed = signRequest(REQ, {
      keyId: "k",
      alg: "hmac-sha256",
      key,
      created: CREATED,
    });
    const res = verifyRequest(signed, { key, now: CREATED + 60 });
    assert.equal(res.ok, true);
    assert.equal(res.alg, "hmac-sha256");
  }
});

test("ed25519 path is unaffected by the HMAC floor", () => {
  const { publicKey, privateKey } = generateEd25519KeyPair();
  const signed = signRequest(REQ, {
    keyId: "ed-key-1",
    alg: "ed25519",
    key: privateKey,
    created: CREATED,
  });
  const res = verifyRequest(signed, { key: publicKey, now: CREATED + 60 });
  assert.equal(res.ok, true);
  assert.equal(res.alg, "ed25519");
});
