import test from "node:test";
import assert from "node:assert/strict";
import {
  generateEd25519KeyPair,
  signRequest,
  signResponse,
  verifyAllLabels,
  verifyAllResponseLabels,
  verifyRequest,
  verifyResponse,
  type SignedHttpRequest,
  type SignedHttpResponse,
} from "../src/index.js";

// Backlog #1074: `verifyRequest` validated `maxSignatureAgeSec`,
// header length limits, `requiredComponents` and `allowedAlgs`, but
// the three global clock options were read raw — `now: NaN` makes
// every freshness comparison false, so EXPIRED / CREATED_IN_FUTURE /
// SIGNATURE_TOO_OLD / NONCE_REPLAY could never trigger, and a NaN
// tolerance disables its own check the same way. A webhook receiver
// deriving `now` from a failed `Date.parse` (NaN) would silently
// verify everything. The per-label maps already rejected bogus
// values; the globals now get the same fail-fast treatment, before
// any header is read and before any crypto runs.

const NOW = 1700000000;
const CREATED = NOW;
const EXPIRES = NOW + 300;

const merchant = generateEd25519KeyPair();

function signedRequest(): SignedHttpRequest {
  return signRequest(
    {
      method: "POST",
      url: "https://api.example.com/v1/payments",
      headers: { "content-type": "application/json" },
      body: '{"amount":100}',
    },
    {
      label: "sig1",
      keyId: "merchant-key-1",
      alg: "ed25519",
      key: merchant.privateKey,
      created: CREATED,
      expires: EXPIRES,
      coveredComponents: ["@method", "@authority", "@path"],
    },
  );
}

function signedResponse(): SignedHttpResponse {
  return signResponse(
    {
      status: 200,
      headers: { "content-type": "application/json" },
      body: JSON.stringify({ settled: true, amount: 100 }),
    },
    {
      label: "sig1",
      keyId: "merchant-key-1",
      alg: "ed25519",
      key: merchant.privateKey,
      created: CREATED,
      expires: EXPIRES,
      coveredComponents: ["@status"],
    },
  );
}

const signed = signedRequest();
const response = signedResponse();

test("now: NaN throws a configuration error, no VerifyResult", () => {
  assert.throws(
    () => verifyRequest(signed, { key: merchant.publicKey, now: Number.NaN }),
    /verifyRequest: `now` must be a non-negative integer number of Unix seconds, got NaN/,
  );
});

test("now: Infinity throws", () => {
  assert.throws(
    () =>
      verifyRequest(signed, { key: merchant.publicKey, now: Number.POSITIVE_INFINITY }),
    /`now` must be a non-negative integer/,
  );
});

test("now: -Infinity throws", () => {
  assert.throws(
    () =>
      verifyRequest(signed, { key: merchant.publicKey, now: Number.NEGATIVE_INFINITY }),
    /`now` must be a non-negative integer/,
  );
});

test("now: negative throws (pre-epoch is not a clock this library keeps)", () => {
  assert.throws(
    () => verifyRequest(signed, { key: merchant.publicKey, now: -1 }),
    /`now` must be a non-negative integer number of Unix seconds, got -1/,
  );
});

test("now: fractional throws, matching the signing side's integer timestamps", () => {
  assert.throws(
    () => verifyRequest(signed, { key: merchant.publicKey, now: NOW + 0.5 }),
    /`now` must be a non-negative integer/,
  );
});

test("now: non-number throws", () => {
  assert.throws(
    () =>
      verifyRequest(signed, {
        key: merchant.publicKey,
        now: "1700000000" as unknown as number,
      }),
    /`now` must be a non-negative integer number of Unix seconds, got string/,
  );
});

test("clockSkewToleranceSec: NaN throws", () => {
  assert.throws(
    () =>
      verifyRequest(signed, {
        key: merchant.publicKey,
        now: NOW,
        clockSkewToleranceSec: Number.NaN,
      }),
    /`clockSkewToleranceSec` must be a positive finite number, got NaN/,
  );
});

test("clockSkewToleranceSec: zero throws", () => {
  assert.throws(
    () =>
      verifyRequest(signed, {
        key: merchant.publicKey,
        now: NOW,
        clockSkewToleranceSec: 0,
      }),
    /`clockSkewToleranceSec` must be a positive finite number, got 0/,
  );
});

test("clockSkewToleranceSec: negative throws", () => {
  assert.throws(
    () =>
      verifyRequest(signed, {
        key: merchant.publicKey,
        now: NOW,
        clockSkewToleranceSec: -1,
      }),
    /`clockSkewToleranceSec` must be a positive finite number, got -1/,
  );
});

test("clockSkewToleranceSec: Infinity throws", () => {
  assert.throws(
    () =>
      verifyRequest(signed, {
        key: merchant.publicKey,
        now: NOW,
        clockSkewToleranceSec: Number.POSITIVE_INFINITY,
      }),
    /`clockSkewToleranceSec` must be a positive finite number, got Infinity/,
  );
});

test("clockSkewToleranceSec: non-number throws", () => {
  assert.throws(
    () =>
      verifyRequest(signed, {
        key: merchant.publicKey,
        now: NOW,
        clockSkewToleranceSec: "60" as unknown as number,
      }),
    /`clockSkewToleranceSec` must be a positive finite number, got string/,
  );
});

test("expiredToleranceSec: NaN throws", () => {
  assert.throws(
    () =>
      verifyRequest(signed, {
        key: merchant.publicKey,
        now: NOW,
        expiredToleranceSec: Number.NaN,
      }),
    /`expiredToleranceSec` must be a non-negative finite number, got NaN/,
  );
});

test("expiredToleranceSec: negative throws", () => {
  assert.throws(
    () =>
      verifyRequest(signed, {
        key: merchant.publicKey,
        now: NOW,
        expiredToleranceSec: -1,
      }),
    /`expiredToleranceSec` must be a non-negative finite number, got -1/,
  );
});

test("expiredToleranceSec: Infinity throws", () => {
  assert.throws(
    () =>
      verifyRequest(signed, {
        key: merchant.publicKey,
        now: NOW,
        expiredToleranceSec: Number.POSITIVE_INFINITY,
      }),
    /`expiredToleranceSec` must be a non-negative finite number, got Infinity/,
  );
});

test("expiredToleranceSec: non-number throws", () => {
  assert.throws(
    () =>
      verifyRequest(signed, {
        key: merchant.publicKey,
        now: NOW,
        expiredToleranceSec: "0" as unknown as number,
      }),
    /`expiredToleranceSec` must be a non-negative finite number, got string/,
  );
});

test("bogus clock options throw before header handling, not MISSING_*", () => {
  const unsigned: SignedHttpRequest = {
    method: "POST",
    url: "https://api.example.com/v1/payments",
    headers: { "content-type": "application/json" },
    body: '{"amount":100}',
  };
  assert.throws(
    () => verifyRequest(unsigned, { key: merchant.publicKey, now: Number.NaN }),
    /`now` must be a non-negative integer/,
  );
});

test("legal boundary values still verify: now exactly equals created", () => {
  const result = verifyRequest(signed, {
    key: merchant.publicKey,
    now: CREATED,
    clockSkewToleranceSec: 60,
    expiredToleranceSec: 0,
  });
  assert.equal(result.ok, true);
});

test("fractional tolerances are accepted: skew 0.5 and tolerance 0.5", () => {
  const result = verifyRequest(signed, {
    key: merchant.publicKey,
    now: CREATED,
    clockSkewToleranceSec: 0.5,
    expiredToleranceSec: 0.5,
  });
  assert.equal(result.ok, true);
});

test("verifyResponse inherits the global clock validation", () => {
  assert.throws(
    () =>
      verifyResponse(response, { key: merchant.publicKey, now: Number.NaN }),
    /verifyRequest: `now` must be a non-negative integer/,
  );
  const ok = verifyResponse(response, { key: merchant.publicKey, now: NOW });
  assert.equal(ok.ok, true);
});

test("verifyAllLabels inherits the global clock validation", () => {
  assert.throws(
    () =>
      verifyAllLabels(signed, { key: merchant.publicKey, now: Number.NaN }),
    /verifyRequest: `now` must be a non-negative integer/,
  );
});

test("verifyAllResponseLabels inherits the global clock validation", () => {
  assert.throws(
    () =>
      verifyAllResponseLabels(response, {
        key: merchant.publicKey,
        now: Number.NaN,
      }),
    /verifyRequest: `now` must be a non-negative integer/,
  );
});

test("per-label clock maps are still validated independently", () => {
  assert.throws(
    () =>
      verifyAllLabels(signed, {
        key: merchant.publicKey,
        now: NOW,
        clockSkewToleranceSecByLabel: { sig1: 0 },
      }),
    /verifyAllLabels: `clockSkewToleranceSecByLabel\["sig1"\]` must be a positive finite number, got 0/,
  );
  assert.throws(
    () =>
      verifyAllLabels(signed, {
        key: merchant.publicKey,
        now: NOW,
        expiredToleranceSecByLabel: { sig1: -1 },
      }),
    /verifyAllLabels: `expiredToleranceSecByLabel\["sig1"\]` must be a non-negative finite number, got -1/,
  );
});
