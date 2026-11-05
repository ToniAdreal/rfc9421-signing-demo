import test from "node:test";
import assert from "node:assert/strict";
import type { KeyObject } from "node:crypto";
import {
  generateEd25519KeyPair,
  signResponse,
  verifyResponse,
  type HttpResponseLike,
  type SignedHttpResponse,
} from "../src/index.js";

// Backlog #899: `verifyResponse` inherits
// `VerifyOptions.clockSkewToleranceSec` (default 60) and
// `VerifyOptions.expiredToleranceSec` (default 0) from `verifyRequest`,
// so a gateway callback verifier can tolerate a signer clock running
// ahead and grant a grace window past `expires` — but no response-side
// test ever proved either tolerance survives the response path. That
// matters because the response signature's `created`/`expires` come
// from the response's own `signature-input` header, not from any
// request header: the request-side tolerance tests cannot prove the
// response forwarder reads the response's timestamps, passes the
// injected `now` through, or reports `CREATED_IN_FUTURE` / `EXPIRED`
// on the response shape. These tests pin the response side directly,
// mirroring the request-side semantics one for one: a future `created`
// inside the skew tolerance verifies, one second past it fails with
// `CREATED_IN_FUTURE`, the boundary itself verifies (the check is a
// strict `>`), an expired signature inside the grace window verifies,
// one second past the grace fails with `EXPIRED`, the default grace
// of 0 rejects an expired signature at once, and a tolerance only
// widens the verifier-side time window — it never rescues a forgery.

const NOW = 1700000000;
const BODY = JSON.stringify({ settled: true, amount: 100 });

function response(overrides: Partial<HttpResponseLike> = {}): HttpResponseLike {
  return { status: 200, headers: {}, body: BODY, ...overrides };
}

function signTimed(
  created: number,
  expires: number,
  overrides: Partial<HttpResponseLike> = {},
): {
  signed: SignedHttpResponse;
  publicKey: KeyObject;
} {
  const { publicKey, privateKey } = generateEd25519KeyPair();
  const signed = signResponse(response(overrides), {
    keyId: "gateway-key-1",
    alg: "ed25519",
    key: privateKey,
    created,
    expires,
  });
  return { signed, publicKey };
}

test("response clock tolerance: future created inside the default 60s skew verifies", () => {
  const { signed, publicKey } = signTimed(NOW + 30, NOW + 3630);
  const result = verifyResponse(signed, { key: publicKey, now: NOW });
  assert.equal(result.ok, true, `expected ok, got ${JSON.stringify(result)}`);
  assert.equal(result.keyId, "gateway-key-1");
  assert.equal(result.alg, "ed25519");
  assert.equal(result.created, NOW + 30);
  assert.equal(result.expires, NOW + 3630);
});

test("response clock tolerance: future created beyond the default 60s skew fails with CREATED_IN_FUTURE", () => {
  const { signed, publicKey } = signTimed(NOW + 120, NOW + 3720);
  const result = verifyResponse(signed, { key: publicKey, now: NOW });
  assert.equal(result.ok, false);
  assert.equal(result.code, "CREATED_IN_FUTURE");
  assert.equal(result.reason, "signature created in the future (clock skew)");
  assert.equal(result.created, NOW + 120);
});

test("response clock tolerance: created exactly at the default skew boundary verifies (strict >)", () => {
  const { signed, publicKey } = signTimed(NOW + 60, NOW + 3660);
  const result = verifyResponse(signed, { key: publicKey, now: NOW });
  assert.equal(result.ok, true, `expected ok, got ${JSON.stringify(result)}`);
});

test("response clock tolerance: the same future signature verifies under a wide tolerance and fails under a tight one", () => {
  const { signed, publicKey } = signTimed(NOW + 120, NOW + 3720);
  const wide = verifyResponse(signed, {
    key: publicKey,
    now: NOW,
    clockSkewToleranceSec: 180,
  });
  assert.equal(wide.ok, true, `expected ok, got ${JSON.stringify(wide)}`);
  const tight = verifyResponse(signed, {
    key: publicKey,
    now: NOW,
    clockSkewToleranceSec: 10,
  });
  assert.equal(tight.ok, false);
  assert.equal(tight.code, "CREATED_IN_FUTURE");
  // One second past the tight window is still the same code; the
  // boundary itself (created == now + 10) is not reached here.
  const onePast = verifyResponse(signed, {
    key: publicKey,
    now: NOW + 109,
    clockSkewToleranceSec: 10,
  });
  assert.equal(onePast.ok, false);
  assert.equal(onePast.code, "CREATED_IN_FUTURE");
});

test("response clock tolerance: expired signature inside the expiredToleranceSec grace verifies", () => {
  const { signed, publicKey } = signTimed(NOW, NOW + 300);
  const result = verifyResponse(signed, {
    key: publicKey,
    now: NOW + 330,
    expiredToleranceSec: 60,
  });
  assert.equal(result.ok, true, `expected ok, got ${JSON.stringify(result)}`);
  assert.equal(result.expires, NOW + 300);
});

test("response clock tolerance: the same expired signature fails once past the grace window with EXPIRED", () => {
  const { signed, publicKey } = signTimed(NOW, NOW + 300);
  const beyond = verifyResponse(signed, {
    key: publicKey,
    now: NOW + 330,
    expiredToleranceSec: 10,
  });
  assert.equal(beyond.ok, false);
  assert.equal(beyond.code, "EXPIRED");
  assert.equal(beyond.reason, "signature expired");
  assert.equal(beyond.expires, NOW + 300);
  // Exactly at the grace boundary (now == expires + grace) still
  // verifies: the check is a strict `>`.
  const atBoundary = verifyResponse(signed, {
    key: publicKey,
    now: NOW + 310,
    expiredToleranceSec: 10,
  });
  assert.equal(
    atBoundary.ok,
    true,
    `expected ok, got ${JSON.stringify(atBoundary)}`,
  );
});

test("response clock tolerance: default expiredToleranceSec=0 rejects an expired signature at once", () => {
  const { signed, publicKey } = signTimed(NOW, NOW + 300);
  const atExpiry = verifyResponse(signed, {
    key: publicKey,
    now: NOW + 300,
  });
  assert.equal(
    atExpiry.ok,
    true,
    `expected ok at the expiry instant, got ${JSON.stringify(atExpiry)}`,
  );
  const onePast = verifyResponse(signed, {
    key: publicKey,
    now: NOW + 301,
  });
  assert.equal(onePast.ok, false);
  assert.equal(onePast.code, "EXPIRED");
});

test("response clock tolerance: tolerance widens only the time window — a forgery still reports SIGNATURE_MISMATCH", () => {
  const { signed, publicKey } = signTimed(NOW + 120, NOW + 3720);
  const tampered: SignedHttpResponse = {
    ...signed,
    headers: {
      ...signed.headers,
      signature: (signed.headers["signature"] as string).replace(
        /^sig1=:/,
        "sig1=:AAAA",
      ),
    },
  };
  // Future-created beyond the default tolerance AND forged: the crypto
  // check runs first, so the true failure mode is reported.
  const result = verifyResponse(tampered, { key: publicKey, now: NOW });
  assert.equal(result.ok, false);
  assert.equal(result.code, "SIGNATURE_MISMATCH");
  // The same forgery stays a mismatch even under a tolerance wide
  // enough to admit the timestamps.
  const wide = verifyResponse(tampered, {
    key: publicKey,
    now: NOW,
    clockSkewToleranceSec: 180,
  });
  assert.equal(wide.ok, false);
  assert.equal(wide.code, "SIGNATURE_MISMATCH");
});

test("response clock tolerance: an expired body-less (@status-only) response follows the same grace rules", () => {
  const { signed, publicKey } = signTimed(NOW, NOW + 300, {
    body: undefined,
  });
  const within = verifyResponse(signed, {
    key: publicKey,
    now: NOW + 330,
    expiredToleranceSec: 60,
  });
  assert.equal(within.ok, true, `expected ok, got ${JSON.stringify(within)}`);
  assert.deepEqual(within.coveredComponents, ["@status"]);
  const beyond = verifyResponse(signed, {
    key: publicKey,
    now: NOW + 330,
    expiredToleranceSec: 10,
  });
  assert.equal(beyond.ok, false);
  assert.equal(beyond.code, "EXPIRED");
  assert.deepEqual(beyond.coveredComponents, ["@status"]);
});

test("response clock tolerance: a future-created body-less (@status-only) response follows the same skew rules", () => {
  const { signed, publicKey } = signTimed(NOW + 120, NOW + 3720, {
    body: undefined,
  });
  const beyond = verifyResponse(signed, { key: publicKey, now: NOW });
  assert.equal(beyond.ok, false);
  assert.equal(beyond.code, "CREATED_IN_FUTURE");
  assert.deepEqual(beyond.coveredComponents, ["@status"]);
  const within = verifyResponse(signed, {
    key: publicKey,
    now: NOW,
    clockSkewToleranceSec: 180,
  });
  assert.equal(within.ok, true, `expected ok, got ${JSON.stringify(within)}`);
  assert.deepEqual(within.coveredComponents, ["@status"]);
});
