import test from "node:test";
import assert from "node:assert/strict";
import {
  addResponseSignature,
  addSignature,
  generateEd25519KeyPair,
  signRequest,
  signResponse,
  verifyAllResponseLabels,
  verifyRequest,
  verifyResponse,
} from "../src/index.js";

const CREATED = 1700000000;
const NOW = CREATED + 60;
const URL = "https://api.example.com/v1/charge?order=42";
const STATUS_REJECTION =
  /signRequest: "@status" must not be covered in a request signature \(RFC 9421 §2\.2\.9/;

function response(status = 200) {
  return { method: "GET", url: URL, headers: {}, status };
}

function signOpts(key: ReturnType<typeof generateEd25519KeyPair>) {
  return {
    keyId: "resp-key",
    alg: "ed25519" as const,
    key: key.privateKey,
    created: CREATED,
  };
}

test("signRequest covering bare @status throws the RFC 9421 §2.2.9 rejection", () => {
  const keys = generateEd25519KeyPair();
  assert.throws(
    () =>
      signRequest(response(), {
        ...signOpts(keys),
        coveredComponents: ["@status"],
      }),
    STATUS_REJECTION,
  );
});

test("signRequest covering @status with a ;req parameter throws the same rejection", () => {
  const keys = generateEd25519KeyPair();
  assert.throws(
    () =>
      signRequest(response(), {
        ...signOpts(keys),
        coveredComponents: ["@status;req"],
      }),
    STATUS_REJECTION,
  );
});

test("signRequest covering @STATUS (case variant) throws the same rejection", () => {
  const keys = generateEd25519KeyPair();
  assert.throws(
    () =>
      signRequest(response(), {
        ...signOpts(keys),
        coveredComponents: ["@STATUS"],
      }),
    STATUS_REJECTION,
  );
});

test("signRequest covering @status among other components throws before any crypto runs", () => {
  const keys = generateEd25519KeyPair();
  assert.throws(
    () =>
      signRequest(response(), {
        ...signOpts(keys),
        coveredComponents: ["@method", "@authority", "@status", "@query"],
      }),
    STATUS_REJECTION,
  );
});

test("signResponse covering @status still signs and verifies", () => {
  const keys = generateEd25519KeyPair();
  const signed = signResponse(
    { status: 200, headers: {} },
    { ...signOpts(keys), coveredComponents: ["@status"] },
  );
  assert.match(signed.headers["signature-input"], /"@status"/);
  const result = verifyResponse(signed, { key: keys.publicKey, now: NOW });
  assert.equal(result.ok, true);
});

test("addSignature covering @status inherits the request-side rejection", () => {
  const keys = generateEd25519KeyPair();
  const signed = signRequest(
    { method: "POST", url: URL, headers: {} },
    { ...signOpts(keys), label: "merchant" },
  );
  assert.throws(
    () =>
      addSignature(signed, {
        ...signOpts(keys),
        label: "gateway",
        coveredComponents: ["@status"],
      }),
    STATUS_REJECTION,
  );
});

test("addResponseSignature covering @status still appends and verifies both labels", () => {
  const merchant = generateEd25519KeyPair();
  const gateway = generateEd25519KeyPair();
  const merchantSigned = signResponse(
    { status: 200, headers: {} },
    {
      keyId: "merchant-key",
      alg: "ed25519",
      key: merchant.privateKey,
      created: CREATED,
      label: "merchant",
      coveredComponents: ["@status"],
    },
  );
  const dual = addResponseSignature(merchantSigned, {
    keyId: "gateway-key",
    alg: "ed25519",
    key: gateway.privateKey,
    created: CREATED,
    label: "gateway",
    coveredComponents: ["@status"],
  });
  const results = verifyAllResponseLabels(dual, {
    keys: { merchant: merchant.publicKey, gateway: gateway.publicKey },
    now: NOW,
  });
  assert.deepEqual(
    results.map((r) => [r.label, r.ok]),
    [
      ["merchant", true],
      ["gateway", true],
    ],
  );
});

test("verifyRequest verifying a response-side @status signature is unaffected", () => {
  const keys = generateEd25519KeyPair();
  const signed = signResponse(
    { status: 200, headers: {} },
    { ...signOpts(keys), coveredComponents: ["@status"] },
  );
  // The verify side still accepts a @status signature presented as a
  // request-shaped message (it also carries response verification,
  // so it must not apply the sign-side refusal).
  const result = verifyRequest(
    { method: "GET", url: URL, headers: signed.headers, status: 200 },
    { key: keys.publicKey, now: NOW },
  );
  assert.equal(result.ok, true);
});

test("request paths that do not cover @status are unchanged", () => {
  const keys = generateEd25519KeyPair();
  const signed = signRequest(
    { method: "POST", url: URL, headers: {}, body: JSON.stringify({ amount: 100 }) },
    { ...signOpts(keys) },
  );
  assert.doesNotMatch(signed.headers["signature-input"], /"@status"/);
  const result = verifyRequest(signed, { key: keys.publicKey, now: NOW });
  assert.equal(result.ok, true);
});

test("a status carried on a request is still passed through when @status is not covered", () => {
  const keys = generateEd25519KeyPair();
  const signed = signRequest(response(201), { ...signOpts(keys) });
  assert.equal(signed.status, 201);
  assert.doesNotMatch(signed.headers["signature-input"], /"@status"/);
});

test("the rejection names signResponse as the way to sign a response", () => {
  const keys = generateEd25519KeyPair();
  assert.throws(
    () =>
      signRequest(response(), {
        ...signOpts(keys),
        coveredComponents: ["@status"],
      }),
    /sign the response with signResponse instead/,
  );
});
