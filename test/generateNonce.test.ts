import test from "node:test";
import assert from "node:assert/strict";
import {
  generateEd25519KeyPair,
  generateNonce,
  ReplayCache,
  signRequest,
  verifyRequest,
} from "../src/index.js";

const CREATED = 1700000000;
const BASE64URL = /^[A-Za-z0-9_-]+$/;

test("generateNonce defaults to 16 bytes (22 base64url chars, 128 bits)", () => {
  const n = generateNonce();
  assert.match(n, BASE64URL);
  // 16 bytes = 128 bits -> ceil(128 / 6) = 22 chars, no padding in base64url
  assert.equal(n.length, 22);
});

test("generateNonce honors a custom byte length", () => {
  const n = generateNonce(32);
  assert.match(n, BASE64URL);
  assert.equal(n.length, 43); // 32 bytes = 256 bits -> ceil(256 / 6) = 43
  assert.equal(generateNonce(1).length, 2); // 1 byte -> ceil(8 / 6) = 2
});

test("generateNonce output is base64url-only (safe for signature-input quoting)", () => {
  for (let i = 0; i < 100; i++) {
    const n = generateNonce();
    assert.match(n, BASE64URL);
    assert.ok(!/[+/=]/.test(n), "no base64 padding or unsafe chars");
    assert.ok(n.length > 0, "never empty");
  }
});

test("generateNonce never repeats within 1000 draws", () => {
  const seen = new Set<string>();
  for (let i = 0; i < 1000; i++) {
    const n = generateNonce();
    assert.ok(!seen.has(n), "duplicate nonce generated");
    seen.add(n);
  }
});

test("generateNonce rejects invalid lengths fail-fast", () => {
  for (const bad of [0, -1, -16, 1.5, NaN, Infinity]) {
    assert.throws(() => generateNonce(bad), /must be a positive integer/);
  }
  // @ts-expect-error - runtime guard for non-number input
  assert.throws(() => generateNonce("16"), /must be a positive integer/);
  // @ts-expect-error - runtime guard for non-number input
  assert.throws(() => generateNonce(null), /must be a positive integer/);
});

test("signRequest({ nonce: generateNonce() }) round-trips via verifyRequest", () => {
  const { publicKey, privateKey } = generateEd25519KeyPair();
  const nonce = generateNonce();
  const signed = signRequest(
    { method: "POST", url: "https://api.example.com/v1/payments", headers: {} },
    {
      keyId: "k",
      alg: "ed25519",
      key: privateKey,
      created: CREATED,
      nonce,
    },
  );
  assert.match(signed.headers["signature-input"], new RegExp(`;nonce="${nonce}"`));
  const res = verifyRequest(signed, { key: publicKey, now: CREATED + 60 });
  assert.equal(res.ok, true);
  assert.equal(res.nonce, nonce);
});

test("generated nonce feeds the replay chain: first verify ok, replay rejected", () => {
  const { publicKey, privateKey } = generateEd25519KeyPair();
  const cache = new ReplayCache({ ttlSec: 3600, now: () => CREATED });
  const signed = signRequest(
    { method: "GET", url: "https://api.example.com/v1/status", headers: {} },
    {
      keyId: "k",
      alg: "ed25519",
      key: privateKey,
      created: CREATED,
      nonce: generateNonce(),
    },
  );
  const first = verifyRequest(signed, {
    key: publicKey,
    now: CREATED + 60,
    replayCache: cache,
  });
  assert.equal(first.ok, true);
  const replay = verifyRequest(signed, {
    key: publicKey,
    now: CREATED + 120,
    replayCache: cache,
  });
  assert.equal(replay.ok, false);
  assert.equal(replay.code, "NONCE_REPLAY");
});
