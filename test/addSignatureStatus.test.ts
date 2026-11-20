import test from "node:test";
import assert from "node:assert/strict";
import {
  addResponseSignature,
  addSignature,
  buildSignatureBase,
  generateEd25519KeyPair,
  secretKey,
  signRequest,
  signResponse,
  verifyAllLabels,
  verifyAllResponseLabels,
  verifyRequest,
  verifyResponse,
  type SignedHttpRequest,
  type SignedHttpResponse,
} from "../src/index.js";

const CREATED = 1700000000;
const NOW = CREATED + 60;
const URL = "https://api.example.com/v1/charge?order=42";
const BODY = JSON.stringify({ settled: true, amount: 100 });
const COVER_STATUS = ["@status"];

function response(status?: number) {
  return status === undefined
    ? { method: "GET", url: URL, headers: {} }
    : { method: "GET", url: URL, headers: {}, status };
}

test("signResponse preserves status on the returned object", () => {
  const { publicKey, privateKey } = generateEd25519KeyPair();
  const signed = signResponse(
    { status: 200, headers: {} },
    {
      keyId: "merchant-key-1",
      alg: "ed25519",
      key: privateKey,
      created: CREATED,
      label: "merchant",
      coveredComponents: COVER_STATUS,
    },
  );
  assert.equal(signed.status, 200);
  // No manual `{ ...signed, status }` workaround needed anymore.
  const res = verifyResponse(signed, {
    key: publicKey,
    now: NOW,
    label: "merchant",
  });
  assert.equal(res.ok, true);
});

test("addResponseSignature appends a second label to a signed response covering @status", () => {
  const merchant = generateEd25519KeyPair();
  const gatewaySecret = secretKey("gateway-shared-secret-32-bytes-0!");
  const merchantSigned = signResponse(
    { status: 200, headers: {} },
    {
      keyId: "merchant-key-1",
      alg: "ed25519",
      key: merchant.privateKey,
      created: CREATED,
      label: "merchant",
      coveredComponents: COVER_STATUS,
    },
  );
  const dual = addResponseSignature(merchantSigned, {
    keyId: "gateway-key-7",
    alg: "hmac-sha256",
    key: gatewaySecret,
    created: CREATED,
    label: "gateway",
    coveredComponents: COVER_STATUS,
  });
  assert.equal(dual.status, 200);
  const results = verifyAllResponseLabels(dual, {
    key: merchant.publicKey,
    now: NOW,
    keys: { gateway: gatewaySecret },
  });
  assert.deepEqual(
    results.map((r) => [r.label, r.ok]),
    [
      ["merchant", true],
      ["gateway", true],
    ],
  );
});

test("tampered status fails the @status-covering second label but not the first without @status", () => {
  const merchant = generateEd25519KeyPair();
  const gateway = generateEd25519KeyPair();
  // Merchant signs with content-digest only (no @status); gateway
  // appends a signature that does cover @status.
  const merchantSigned = signResponse(
    { status: 200, headers: {}, body: BODY },
    {
      keyId: "merchant-key-1",
      alg: "ed25519",
      key: merchant.privateKey,
      created: CREATED,
      label: "merchant",
      coveredComponents: ["content-digest"],
    },
  );
  const dual = addResponseSignature(merchantSigned, {
    keyId: "gateway-key-7",
    alg: "ed25519",
    key: gateway.privateKey,
    created: CREATED,
    label: "gateway",
    coveredComponents: COVER_STATUS,
  });
  const tampered: SignedHttpResponse = { ...dual, status: 500 };
  const results = verifyAllResponseLabels(tampered, {
    key: merchant.publicKey,
    now: NOW,
    keys: { gateway: gateway.publicKey },
  });
  assert.equal(results[0].ok, true);
  assert.equal(results[1].ok, false);
  assert.equal(results[1].code, "SIGNATURE_MISMATCH");
});

test("tampered status fails both labels when both cover @status", () => {
  const merchant = generateEd25519KeyPair();
  const gatewaySecret = secretKey("gateway-shared-secret-32-bytes-0!");
  const merchantSigned = signResponse(
    { status: 200, headers: {} },
    {
      keyId: "merchant-key-1",
      alg: "ed25519",
      key: merchant.privateKey,
      created: CREATED,
      label: "merchant",
      coveredComponents: COVER_STATUS,
    },
  );
  const dual = addResponseSignature(merchantSigned, {
    keyId: "gateway-key-7",
    alg: "hmac-sha256",
    key: gatewaySecret,
    created: CREATED,
    label: "gateway",
    coveredComponents: COVER_STATUS,
  });
  const results = verifyAllResponseLabels(
    { ...dual, status: 500 },
    { key: merchant.publicKey, now: NOW, keys: { gateway: gatewaySecret } },
  );
  assert.equal(results[0].ok, false);
  assert.equal(results[0].code, "SIGNATURE_MISMATCH");
  assert.equal(results[1].ok, false);
  assert.equal(results[1].code, "SIGNATURE_MISMATCH");
});

test("ordinary request without status is unchanged: no status field, addSignature still works", () => {
  const merchant = generateEd25519KeyPair();
  const gatewaySecret = secretKey("gateway-shared-secret-32-bytes-0!");
  const req = {
    method: "POST",
    url: "https://api.example.com/v1/payments",
    headers: { "content-type": "application/json" },
    body: JSON.stringify({ amount: 250, currency: "USD" }),
  };
  const signed = signRequest(req, {
    keyId: "merchant-key-1",
    alg: "ed25519",
    key: merchant.privateKey,
    created: CREATED,
    label: "merchant",
  });
  assert.equal("status" in signed, false);
  assert.equal(signed.status, undefined);
  const dual = addSignature(signed, {
    keyId: "gateway-key-7",
    alg: "hmac-sha256",
    key: gatewaySecret,
    created: CREATED,
    label: "gateway",
  });
  assert.equal("status" in dual, false);
  const results = verifyAllLabels(dual, {
    key: merchant.publicKey,
    now: NOW,
    keys: { gateway: gatewaySecret },
  });
  assert.deepEqual(results.map((r) => r.ok), [true, true]);
});

test("addSignature covering @status on a status-less signed request throws the §2.2.9 rejection", () => {
  const { privateKey } = generateEd25519KeyPair();
  const signed = signRequest(response(), {
    keyId: "k",
    alg: "ed25519",
    key: privateKey,
    created: CREATED,
    label: "merchant",
  });
  assert.throws(
    () =>
      addSignature(signed, {
        keyId: "k2",
        alg: "ed25519",
        key: privateKey,
        created: CREATED,
        label: "gateway",
        coveredComponents: COVER_STATUS,
      }),
    /signRequest: "@status" must not be covered in a request signature \(RFC 9421 §2\.2\.9/,
  );
});

test("status passthrough does not affect the base when @status is not covered", () => {
  const { publicKey, privateKey } = generateEd25519KeyPair();
  const signed = signRequest(response(200), {
    keyId: "s1",
    alg: "ed25519",
    key: privateKey,
    created: CREATED,
    label: "merchant",
  });
  assert.equal(signed.status, 200);
  assert.doesNotMatch(signed.headers["signature-input"], /"@status"/);
  const base = buildSignatureBase(
    ["@method", "@authority", "@path"],
    response(200),
    { created: CREATED, alg: "ed25519", keyid: "s1" },
  );
  assert.doesNotMatch(base, /@status/);
  // Uncovered status is ignored at verify time, exactly as before.
  const res = verifyRequest(
    { ...signed, status: 500 },
    { key: publicKey, now: NOW, label: "merchant" },
  );
  assert.equal(res.ok, true);
});

test("addResponseSignature does not mutate the first signed response", () => {
  const merchant = generateEd25519KeyPair();
  const signed = signResponse(
    { status: 201, headers: {} },
    {
      keyId: "merchant-key-1",
      alg: "ed25519",
      key: merchant.privateKey,
      created: CREATED,
      label: "merchant",
      coveredComponents: COVER_STATUS,
    },
  );
  const before = JSON.stringify(signed.headers);
  const dual = addResponseSignature(signed, {
    keyId: "gateway-key-7",
    alg: "ed25519",
    key: generateEd25519KeyPair().privateKey,
    created: CREATED,
    label: "gateway",
    coveredComponents: COVER_STATUS,
  });
  assert.equal(signed.status, 201);
  assert.equal(dual.status, 201);
  assert.equal(JSON.stringify(signed.headers), before);
  assert.notEqual(dual.headers, signed.headers);
});
