import test from "node:test";
import assert from "node:assert/strict";
import {
  addResponseSignature,
  generateEd25519KeyPair,
  secretKey,
  signResponse,
  verifyAllResponseLabels,
  verifyAllResponseLabelsOrThrow,
  type HttpResponseLike,
  type SignedHttpResponse,
  type VerifyAllResponseOptions,
} from "../src/index.js";

// Backlog #1351: `verifyAllResponseLabels` was the one response-side
// entry point #1344 deliberately left out of scope — it dereferenced
// its arguments with no shape guard, so a `null` response escaped as
// a bare `TypeError` (`reading 'status'`) and a `null` options object
// as a bare `TypeError` from `Object.keys` inside
// `assertNoUnknownOptions`. The shared `assertObjectParam` guard now
// runs first in `verifyAllResponseLabels`, before
// `assertNoUnknownOptions` and every other check, and
// `verifyAllResponseLabelsOrThrow` inherits it through the same
// delegation. These tests pin the exact wording, the plain-`Error`
// (never `TypeError`) shape, and the untouched wire contract: a
// malformed signature is still a `{ ok: false, code }` result, never
// a throw.

const CREATED = 1700000000;
const NOW = CREATED + 60;
const BODY = JSON.stringify({ settled: true, amount: 100 });

const merchant = generateEd25519KeyPair();
const gatewaySecret = secretKey("gateway-shared-secret-32-bytes-0!");

function dualSigned(): SignedHttpResponse {
  const merchantSigned = signResponse(
    {
      status: 200,
      headers: { "content-type": "application/json" },
      body: BODY,
    },
    {
      keyId: "merchant-key-1",
      alg: "ed25519",
      key: merchant.privateKey,
      created: CREATED,
      label: "merchant",
    },
  );
  return addResponseSignature(merchantSigned, {
    keyId: "gateway-key-7",
    alg: "hmac-sha256",
    key: gatewaySecret,
    created: CREATED,
    label: "gateway",
  });
}

function keys() {
  return { merchant: merchant.publicKey, gateway: gatewaySecret };
}

function asRes(value: unknown): HttpResponseLike {
  return value as HttpResponseLike;
}
function asOpts(value: unknown): VerifyAllResponseOptions {
  return value as VerifyAllResponseOptions;
}

/** The error must be a plain named `Error` with the exact message — never a bare `TypeError`. */
function assertNamedError(fn: () => unknown, message: string): void {
  assert.throws(fn, (e: unknown) => {
    assert.ok(e instanceof Error, `must throw an Error: ${String(e)}`);
    assert.ok(
      !(e instanceof TypeError),
      `must be a named Error, not a bare TypeError: ${e}`,
    );
    assert.equal(e.name, "Error");
    assert.equal(e.message, message);
    return true;
  });
}

test("null res throws a named error, not a bare TypeError", () => {
  assertNamedError(
    () => verifyAllResponseLabels(asRes(null), { keys: keys(), now: NOW }),
    "verifyAllResponseLabels: res must be an object",
  );
});

test("non-object res (string, number, array) throws the same named error", () => {
  for (const bad of ["x", 42, []]) {
    assertNamedError(
      () => verifyAllResponseLabels(asRes(bad), { keys: keys(), now: NOW }),
      "verifyAllResponseLabels: res must be an object",
    );
  }
});

test("null opts throws a named error, not a bare TypeError from Object.keys", () => {
  assertNamedError(
    () => verifyAllResponseLabels(dualSigned(), asOpts(null)),
    "verifyAllResponseLabels: opts must be an object",
  );
});

test("non-object opts (string, number, array) throws the same named error", () => {
  for (const bad of ["x", 42, []]) {
    assertNamedError(
      () => verifyAllResponseLabels(dualSigned(), asOpts(bad)),
      "verifyAllResponseLabels: opts must be an object",
    );
  }
});

test("undefined res / opts also throw the named error (not a bare TypeError)", () => {
  assertNamedError(
    () =>
      verifyAllResponseLabels(asRes(undefined), { keys: keys(), now: NOW }),
    "verifyAllResponseLabels: res must be an object",
  );
  assertNamedError(
    () => verifyAllResponseLabels(dualSigned(), asOpts(undefined)),
    "verifyAllResponseLabels: opts must be an object",
  );
});

test("guard runs before the unknown-options check: null opts with a valid res still names opts", () => {
  // Without the guard, `assertNoUnknownOptions` dereferences `opts`
  // first (`Object.keys(null)`); the message must name the param.
  assertNamedError(
    () => verifyAllResponseLabels(dualSigned(), asOpts(null)),
    "verifyAllResponseLabels: opts must be an object",
  );
});

test("response with null headers throws the getHeader named error", () => {
  assertNamedError(
    () =>
      verifyAllResponseLabels(
        { status: 200, headers: null, body: BODY } as unknown as HttpResponseLike,
        { keys: keys(), now: NOW },
      ),
    "getHeader: headers must be an object",
  );
});

test("verifyAllResponseLabelsOrThrow inherits the guard for null res and null opts", () => {
  assertNamedError(
    () =>
      verifyAllResponseLabelsOrThrow(asRes(null), { keys: keys(), now: NOW }),
    "verifyAllResponseLabels: res must be an object",
  );
  assertNamedError(
    () => verifyAllResponseLabelsOrThrow(dualSigned(), asOpts(null)),
    "verifyAllResponseLabels: opts must be an object",
  );
});

test("valid dual-label round-trip is unchanged: both labels verify", () => {
  const results = verifyAllResponseLabels(dualSigned(), {
    keys: keys(),
    now: NOW,
  });
  assert.equal(results.length, 2);
  assert.deepEqual(
    results.map((r) => r.label),
    ["merchant", "gateway"],
  );
  assert.deepEqual(
    results.map((r) => r.ok),
    [true, true],
  );
});

test("valid dual-label round-trip through the OrThrow variant returns both results", () => {
  const results = verifyAllResponseLabelsOrThrow(dualSigned(), {
    keys: keys(),
    now: NOW,
  });
  assert.equal(results.length, 2);
  assert.deepEqual(
    results.map((r) => r.ok),
    [true, true],
  );
});

test("malformed signature still returns { ok: false, code }, never throws", () => {
  const malformed: HttpResponseLike = {
    status: 200,
    headers: {
      "signature-input": "not-a-list",
      signature: "sig1=:AAAA:",
    },
    body: BODY,
  };
  const results = verifyAllResponseLabels(malformed, {
    keys: keys(),
    now: NOW,
  });
  assert.equal(results.length, 1);
  assert.equal(results[0]?.ok, false);
  assert.equal(results[0]?.code, "MALFORMED_SIGNATURE_INPUT");
});

test("status tamper still fails both labels with SIGNATURE_MISMATCH, no throw", () => {
  const results = verifyAllResponseLabels(
    { ...dualSigned(), status: 500 },
    { keys: keys(), now: NOW },
  );
  assert.equal(results.length, 2);
  assert.deepEqual(
    results.map((r) => r.ok),
    [false, false],
  );
  assert.deepEqual(
    results.map((r) => r.code),
    ["SIGNATURE_MISMATCH", "SIGNATURE_MISMATCH"],
  );
});
