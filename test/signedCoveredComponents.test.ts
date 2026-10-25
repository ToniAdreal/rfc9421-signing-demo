import test from "node:test";
import assert from "node:assert/strict";
import {
  addSignature,
  generateEd25519KeyPair,
  secretKey,
  signRequest,
  verifyAllLabels,
  verifyRequest,
  type RequestLike,
} from "../src/index.js";

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------
// `SignedHttpRequest.coveredComponents` (#578) is the sign-side mirror of
// `VerifyResult.coveredComponents` (#566): the list `signRequest` actually
// wrote into `signature-input`, echoed back so a caller can audit what a
// signature covers without parsing the header a second time.
function baseRequest(): RequestLike {
  return {
    method: "POST",
    url: "https://api.example.com/v1/payments",
    headers: { "content-type": "application/json" },
  };
}

test("explicit covered set is echoed verbatim, in order", () => {
  const { publicKey, privateKey } = generateEd25519KeyPair();
  const covered = ["@method", "@authority", "@path", "content-digest"];
  const signed = signRequest(
    { ...baseRequest(), body: JSON.stringify({ amount: 100 }) },
    { keyId: "k", alg: "ed25519", key: privateKey, coveredComponents: covered },
  );
  assert.deepEqual(signed.coveredComponents, covered);
  assert.equal(verifyRequest(signed, { key: publicKey }).ok, true);
});

test("default set with a body includes content-digest", () => {
  const { privateKey } = generateEd25519KeyPair();
  const signed = signRequest(
    { ...baseRequest(), body: JSON.stringify({ amount: 100 }) },
    { keyId: "k", alg: "ed25519", key: privateKey },
  );
  assert.deepEqual(signed.coveredComponents, [
    "@method",
    "@authority",
    "@path",
    "content-digest",
  ]);
});

test("default set without a body omits content-digest", () => {
  const { privateKey } = generateEd25519KeyPair();
  const signed = signRequest(baseRequest(), {
    keyId: "k",
    alg: "ed25519",
    key: privateKey,
  });
  assert.deepEqual(signed.coveredComponents, [
    "@method",
    "@authority",
    "@path",
  ]);
});

test("returned array is a detached copy of the caller's options array", () => {
  const { privateKey } = generateEd25519KeyPair();
  const covered = ["@method", "@authority"];
  const signed = signRequest(baseRequest(), {
    keyId: "k",
    alg: "ed25519",
    key: privateKey,
    coveredComponents: covered,
  });
  signed.coveredComponents!.push("content-digest");
  assert.deepEqual(covered, ["@method", "@authority"]);
  assert.deepEqual(signed.coveredComponents, [
    "@method",
    "@authority",
    "content-digest",
  ]);
});

test("mutating the returned array does not affect later verification", () => {
  const { publicKey, privateKey } = generateEd25519KeyPair();
  const signed = signRequest(baseRequest(), {
    keyId: "k",
    alg: "ed25519",
    key: privateKey,
  });
  signed.coveredComponents!.push("@query");
  signed.coveredComponents!.length = 0;
  const result = verifyRequest(signed, { key: publicKey });
  assert.equal(result.ok, true);
  assert.deepEqual(result.coveredComponents, [
    "@method",
    "@authority",
    "@path",
  ]);
});

test("sign-side echo matches verify-side coveredComponents item for item", () => {
  const { publicKey, privateKey } = generateEd25519KeyPair();
  const covered = ["@method", "@path", "content-type"];
  const signed = signRequest(
    { ...baseRequest(), body: JSON.stringify({ amount: 100 }) },
    { keyId: "k", alg: "ed25519", key: privateKey, coveredComponents: covered },
  );
  const result = verifyRequest(signed, { key: publicKey });
  assert.equal(result.ok, true);
  assert.deepEqual(signed.coveredComponents, covered);
  assert.deepEqual(result.coveredComponents, signed.coveredComponents);
});

test("addSignature echoes only the appended signature's own covered set", () => {
  const { privateKey } = generateEd25519KeyPair();
  const secret = secretKey("a-shared-hmac-secret-of-32-bytes!!");
  const merchant = signRequest(baseRequest(), {
    label: "merchant",
    keyId: "m",
    alg: "ed25519",
    key: privateKey,
    coveredComponents: ["@method", "@authority", "@path"],
  });
  const dual = addSignature(merchant, {
    label: "gateway",
    keyId: "g",
    alg: "hmac-sha256",
    key: secret,
    coveredComponents: ["@method", "@path"],
  });
  assert.deepEqual(merchant.coveredComponents, [
    "@method",
    "@authority",
    "@path",
  ]);
  assert.deepEqual(dual.coveredComponents, ["@method", "@path"]);
});

test("addSignature does not rewrite the first signature's echoed list", () => {
  const { privateKey } = generateEd25519KeyPair();
  const secret = secretKey("a-shared-hmac-secret-of-32-bytes!!");
  const first = signRequest(baseRequest(), {
    label: "merchant",
    keyId: "m",
    alg: "ed25519",
    key: privateKey,
    coveredComponents: ["@method", "@authority"],
  });
  const before = [...first.coveredComponents!];
  addSignature(first, {
    label: "gateway",
    keyId: "g",
    alg: "hmac-sha256",
    key: secret,
    coveredComponents: ["@path"],
  });
  assert.deepEqual(first.coveredComponents, before);
});

test("verifyAllLabels per-label lists match the two sign-side echoes", () => {
  const { publicKey, privateKey } = generateEd25519KeyPair();
  const secret = secretKey("a-shared-hmac-secret-of-32-bytes!!");
  const merchant = signRequest(baseRequest(), {
    label: "merchant",
    keyId: "m",
    alg: "ed25519",
    key: privateKey,
    coveredComponents: ["@method", "@authority"],
  });
  const dual = addSignature(merchant, {
    label: "gateway",
    keyId: "g",
    alg: "hmac-sha256",
    key: secret,
    coveredComponents: ["@path"],
  });
  const results = verifyAllLabels(dual, {
    key: publicKey,
    keys: { gateway: secret },
  });
  assert.equal(results.length, 2);
  assert.equal(results[0].ok, true);
  assert.equal(results[1].ok, true);
  assert.deepEqual(results[0].coveredComponents, merchant.coveredComponents);
  assert.deepEqual(results[1].coveredComponents, dual.coveredComponents);
});

test("@status response signature echoes its covered set", () => {
  const { publicKey, privateKey } = generateEd25519KeyPair();
  const signed = signRequest(
    {
      method: "GET",
      url: "https://api.example.com/v1/payments/42",
      headers: {},
      status: 200,
    },
    {
      keyId: "k",
      alg: "ed25519",
      key: privateKey,
      coveredComponents: ["@status"],
    },
  );
  assert.deepEqual(signed.coveredComponents, ["@status"]);
  assert.equal(verifyRequest(signed, { key: publicKey }).ok, true);
});

test("derived @query component is echoed and verifies", () => {
  const { publicKey, privateKey } = generateEd25519KeyPair();
  const signed = signRequest(
    {
      method: "GET",
      url: "https://api.example.com/v1/payments?a=1&b=2",
      headers: {},
    },
    {
      keyId: "k",
      alg: "ed25519",
      key: privateKey,
      coveredComponents: ["@method", "@query"],
    },
  );
  assert.deepEqual(signed.coveredComponents, ["@method", "@query"]);
  assert.equal(verifyRequest(signed, { key: publicKey }).ok, true);
});
