import test from "node:test";
import assert from "node:assert/strict";
import {
  assertHmacSecretLength,
  generateHmacSecret,
  MIN_HMAC_SECRET_BYTES,
  MIN_HMAC_SHA512_SECRET_BYTES,
  secretKey,
  signRequest,
  verifyRequest,
} from "../src/index.js";

const CREATED = 1700000000;
const NOW = CREATED + 60;
const REQ = {
  method: "POST",
  url: "https://api.example.com/v1/payments",
  headers: { "content-type": "application/json" },
  body: '{"amount":100}',
};

test("generateHmacSecret defaults to 32 bytes for hmac-sha256", () => {
  const secret = generateHmacSecret();
  assert.ok(Buffer.isBuffer(secret), "returns a Buffer");
  assert.equal(secret.length, 32);
  assert.equal(secret.length, MIN_HMAC_SECRET_BYTES);
});

test("generateHmacSecret defaults to 64 bytes for hmac-sha512", () => {
  const secret = generateHmacSecret("hmac-sha512");
  assert.ok(Buffer.isBuffer(secret), "returns a Buffer");
  assert.equal(secret.length, 64);
  assert.equal(secret.length, MIN_HMAC_SHA512_SECRET_BYTES);
});

test("generateHmacSecret honors an explicit longer byte length", () => {
  assert.equal(generateHmacSecret("hmac-sha256", 48).length, 48);
  assert.equal(generateHmacSecret("hmac-sha512", 96).length, 96);
});

test("generateHmacSecret accepts an explicit length exactly at the floor", () => {
  assert.equal(generateHmacSecret("hmac-sha256", 32).length, 32);
  assert.equal(generateHmacSecret("hmac-sha512", 64).length, 64);
});

test("generateHmacSecret below the hmac-sha256 floor throws with the assertHmacSecretLength wording", () => {
  assert.throws(
    () => generateHmacSecret("hmac-sha256", 16),
    (err: unknown) => {
      assert.ok(err instanceof Error);
      assert.match(err.message, /at least 32 bytes/);
      assert.match(err.message, /got 16 bytes/);
      assert.match(err.message, /assertHmacSecretLength/);
      return true;
    },
  );
});

test("generateHmacSecret below the hmac-sha512 floor throws with the assertHmacSecretLength wording", () => {
  assert.throws(
    () => generateHmacSecret("hmac-sha512", 48),
    (err: unknown) => {
      assert.ok(err instanceof Error);
      assert.match(err.message, /at least 64 bytes/);
      assert.match(err.message, /got 48 bytes/);
      assert.match(err.message, /assertHmacSecretLength/);
      return true;
    },
  );
});

test("generateHmacSecret rejects non-integer, negative, and NaN byte lengths", () => {
  for (const bad of [1.5, -1, -32, NaN, Infinity]) {
    assert.throws(
      () => generateHmacSecret("hmac-sha256", bad),
      /must be a non-negative integer/,
    );
  }
  // @ts-expect-error - runtime guard for non-number input
  assert.throws(() => generateHmacSecret("hmac-sha256", "32"), /must be a non-negative integer/);
  // @ts-expect-error - runtime guard for non-number input
  assert.throws(() => generateHmacSecret("hmac-sha256", null), /must be a non-negative integer/);
});

test("generateHmacSecret draws fresh random bytes on every call", () => {
  const a = generateHmacSecret();
  const b = generateHmacSecret();
  assert.ok(!a.equals(b), "two draws must differ");
  assert.ok(!a.equals(Buffer.alloc(32)), "a draw is not all zeros");
  const c = generateHmacSecret("hmac-sha512");
  const d = generateHmacSecret("hmac-sha512");
  assert.ok(!c.equals(d), "two sha-512 draws must differ");
});

test("generateHmacSecret rejects an unsupported alg at runtime", () => {
  // @ts-expect-error - runtime guard for an out-of-union alg
  assert.throws(() => generateHmacSecret("hmac-sha1"), /unsupported alg/);
});

test("round-trip: secretKey(generateHmacSecret()) signs and verifies hmac-sha256", () => {
  const secret = secretKey(generateHmacSecret());
  // The generated secret passes the same floor check the sign side runs.
  assert.doesNotThrow(() => assertHmacSecretLength(secret, "hmac-sha256"));
  const signed = signRequest(REQ, {
    keyId: "hmac256-key-1",
    alg: "hmac-sha256",
    key: secret,
    created: CREATED,
  });
  const res = verifyRequest(signed, { key: secret, now: NOW });
  assert.equal(res.ok, true);
  assert.equal(res.alg, "hmac-sha256");
  assert.equal(res.keyId, "hmac256-key-1");
});

test("round-trip: explicit 64-byte secret signs and verifies hmac-sha512", () => {
  const secret = secretKey(generateHmacSecret("hmac-sha512", 64));
  assert.doesNotThrow(() => assertHmacSecretLength(secret, "hmac-sha512"));
  const signed = signRequest(REQ, {
    keyId: "hmac512-key-1",
    alg: "hmac-sha512",
    key: secret,
    created: CREATED,
  });
  const res = verifyRequest(signed, { key: secret, now: NOW });
  assert.equal(res.ok, true);
  assert.equal(res.alg, "hmac-sha512");
  assert.equal(res.keyId, "hmac512-key-1");
});
