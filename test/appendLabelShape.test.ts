import test from "node:test";
import assert from "node:assert/strict";
import {
  addResponseSignature,
  addSignature,
  generateEd25519KeyPair,
  secretKey,
  signRequest,
  signResponse,
  verifyAllLabels,
  verifyAllResponseLabels,
  type SignedHttpRequest,
  type SignedHttpResponse,
} from "../src/index.js";

// Backlog #1084: `addSignature` / `addResponseSignature` used to let a
// malformed label fall through to the delegated `signRequest`, whose
// `assertLabelShape` threw naming `signRequest` — the wrong entry point.
// Both append functions now check the label shape themselves, right
// after the empty check, and the error names the function the caller
// actually used. The behavior (reject before any crypto) is unchanged;
// only the attribution is fixed.

const CREATED = 1700000000;
const NOW = CREATED + 60;

const merchantKey = generateEd25519KeyPair();
const gatewayKey = generateEd25519KeyPair();
const gatewaySecret = secretKey("gateway-shared-secret-32-bytes-0!");

function paymentRequest() {
  return {
    method: "POST",
    url: "https://api.example.com/v1/payments",
    headers: { "content-type": "application/json" },
    body: JSON.stringify({ amount: 250, currency: "USD" }),
  };
}

function merchantSignedRequest(): SignedHttpRequest {
  return signRequest(paymentRequest(), {
    keyId: "merchant-key-1",
    alg: "ed25519",
    key: merchantKey.privateKey,
    created: CREATED,
    label: "merchant",
  });
}

function settlementResponse() {
  return {
    status: 200,
    headers: { "content-type": "application/json" },
    body: JSON.stringify({ settled: true, amount: 100 }),
  };
}

function merchantSignedResponse(): SignedHttpResponse {
  return signResponse(settlementResponse(), {
    keyId: "merchant-key-1",
    alg: "ed25519",
    key: merchantKey.privateKey,
    created: CREATED,
    label: "merchant",
  });
}

function appendOpts(label: string) {
  return {
    keyId: "gateway-key-7",
    alg: "hmac-sha256" as const,
    key: gatewaySecret,
    created: CREATED,
    label,
  };
}

/** Assert the thrown message names `caller` and never `signRequest`. */
function assertNamesCaller(fn: () => unknown, caller: string): void {
  let message = "";
  try {
    fn();
  } catch (e) {
    message = (e as Error).message;
  }
  assert.ok(message.length > 0, `expected ${caller} to throw, but it did not`);
  assert.ok(
    message.startsWith(`${caller}: "label" must be an RFC 9421 token`),
    `expected the error to name ${caller}, got: ${message}`,
  );
  assert.ok(
    !message.includes("signRequest"),
    `error must not name the delegated signRequest, got: ${message}`,
  );
}

test('addSignature rejects "bad label" naming addSignature, not signRequest', () => {
  assertNamesCaller(
    () => addSignature(merchantSignedRequest(), appendOpts("bad label")),
    "addSignature",
  );
});

test('addSignature rejects "a,b" naming addSignature, not signRequest', () => {
  assertNamesCaller(
    () => addSignature(merchantSignedRequest(), appendOpts("a,b")),
    "addSignature",
  );
});

test('addResponseSignature rejects "bad label" naming addResponseSignature, not signRequest', () => {
  assertNamesCaller(
    () => addResponseSignature(merchantSignedResponse(), appendOpts("bad label")),
    "addResponseSignature",
  );
});

test('addResponseSignature rejects "a,b" naming addResponseSignature, not signRequest', () => {
  assertNamesCaller(
    () => addResponseSignature(merchantSignedResponse(), appendOpts("a,b")),
    "addResponseSignature",
  );
});

test("addSignature still appends legal labels (sig1 default and gateway)", () => {
  const dualDefault = addSignature(merchantSignedRequest(), {
    keyId: "gateway-key-7",
    alg: "hmac-sha256",
    key: gatewaySecret,
    created: CREATED,
  });
  const resultsDefault = verifyAllLabels(dualDefault, {
    key: merchantKey.publicKey,
    now: NOW,
    keys: { sig1: gatewaySecret },
  });
  assert.deepEqual(
    resultsDefault.map((r) => r.label),
    ["merchant", "sig1"],
  );
  assert.ok(resultsDefault.every((r) => r.ok));

  const dual = addSignature(merchantSignedRequest(), appendOpts("gateway"));
  const results = verifyAllLabels(dual, {
    key: merchantKey.publicKey,
    now: NOW,
    keys: { gateway: gatewaySecret },
  });
  assert.deepEqual(
    results.map((r) => r.label),
    ["merchant", "gateway"],
  );
  assert.ok(results.every((r) => r.ok));
});

test("addResponseSignature still appends legal labels (sig1 default and gateway)", () => {
  const dualDefault = addResponseSignature(merchantSignedResponse(), {
    keyId: "gateway-key-7",
    alg: "hmac-sha256",
    key: gatewaySecret,
    created: CREATED,
  });
  const resultsDefault = verifyAllResponseLabels(dualDefault, {
    key: merchantKey.publicKey,
    now: NOW,
    keys: { sig1: gatewaySecret },
  });
  assert.deepEqual(
    resultsDefault.map((r) => r.label),
    ["merchant", "sig1"],
  );
  assert.ok(resultsDefault.every((r) => r.ok));

  const dual = addResponseSignature(merchantSignedResponse(), appendOpts("gateway"));
  const results = verifyAllResponseLabels(dual, {
    key: merchantKey.publicKey,
    now: NOW,
    keys: { gateway: gatewaySecret },
  });
  assert.deepEqual(
    results.map((r) => r.label),
    ["merchant", "gateway"],
  );
  assert.ok(results.every((r) => r.ok));
});

test("addSignature duplicate check still fires first for an already-present legal label", () => {
  assert.throws(
    () => addSignature(merchantSignedRequest(), appendOpts("merchant")),
    /addSignature: label "merchant" is already present/,
  );
});

test("addResponseSignature duplicate check still fires first for an already-present legal label", () => {
  assert.throws(
    () => addResponseSignature(merchantSignedResponse(), appendOpts("merchant")),
    /addResponseSignature: label "merchant" is already present/,
  );
});

test("addSignature empty label keeps its existing wording", () => {
  assert.throws(
    () => addSignature(merchantSignedRequest(), appendOpts("")),
    /addSignature: "label" must be a non-empty string/,
  );
});

test("addResponseSignature empty label keeps its existing wording", () => {
  assert.throws(
    () => addResponseSignature(merchantSignedResponse(), appendOpts("")),
    /addResponseSignature: "label" must be a non-empty string/,
  );
});

test("addSignature shape check fires before the no-signature-headers check", () => {
  assertNamesCaller(
    () => addSignature(paymentRequest() as SignedHttpRequest, appendOpts("bad label")),
    "addSignature",
  );
});

test("addResponseSignature shape check fires before the no-signature-headers check", () => {
  assertNamesCaller(
    () =>
      addResponseSignature(
        settlementResponse() as SignedHttpResponse,
        appendOpts("bad label"),
      ),
    "addResponseSignature",
  );
});
