import test from "node:test";
import assert from "node:assert/strict";
import {
  generateEd25519KeyPair,
  signResponse,
  verifyResponse,
  type RequestLike,
  type SignedHttpResponse,
} from "../src/index.js";

const CREATED = 1700000000;
const NOW = CREATED + 60;
const COVERED = ["@status", "@method;req", "x-checksum;tr"];

function triggeringRequest(overrides: Partial<RequestLike> = {}): RequestLike {
  return {
    method: "POST",
    url: "https://api.example.com/v1/charge?order=42",
    headers: { "x-charge-id": "ch_42" },
    ...overrides,
  };
}

function signOpts(key: ReturnType<typeof generateEd25519KeyPair>) {
  return {
    keyId: "gateway-key",
    alg: "ed25519" as const,
    key: key.privateKey,
    created: CREATED,
  };
}

function verifyOpts(key: ReturnType<typeof generateEd25519KeyPair>) {
  return { key: key.publicKey, now: NOW };
}

function signedCombined(
  key: ReturnType<typeof generateEd25519KeyPair>,
  request: RequestLike,
): SignedHttpResponse {
  return signResponse(
    { status: 200, headers: {}, trailers: { "x-checksum": "abc" } },
    { ...signOpts(key), coveredComponents: [...COVERED], request },
  );
}

test("round-trip: @status + ;req method + ;tr trailer verify together, in wire order", () => {
  const keys = generateEd25519KeyPair();
  const request = triggeringRequest();
  const signed = signedCombined(keys, request);
  assert.match(signed.headers["signature-input"] as string, /"@method";req/);
  assert.match(signed.headers["signature-input"] as string, /"x-checksum";tr/);
  const result = verifyResponse(signed, { ...verifyOpts(keys), request });
  assert.equal(result.ok, true);
  assert.deepEqual(result.coveredComponents, [...COVERED]);
});

test("tampered trailer fails with SIGNATURE_MISMATCH, other bindings untouched", () => {
  const keys = generateEd25519KeyPair();
  const request = triggeringRequest();
  const signed = signedCombined(keys, request);
  const tampered: SignedHttpResponse = {
    ...signed,
    trailers: { "x-checksum": "abd" },
  };
  const result = verifyResponse(tampered, { ...verifyOpts(keys), request });
  assert.equal(result.ok, false);
  assert.equal(result.code, "SIGNATURE_MISMATCH");
});

test("tampered triggering request method fails with SIGNATURE_MISMATCH", () => {
  const keys = generateEd25519KeyPair();
  const request = triggeringRequest();
  const signed = signedCombined(keys, request);
  const tamperedRequest = triggeringRequest({ method: "DELETE" });
  const result = verifyResponse(signed, {
    ...verifyOpts(keys),
    request: tamperedRequest,
  });
  assert.equal(result.ok, false);
  assert.equal(result.code, "SIGNATURE_MISMATCH");
});

test("tampered status fails with SIGNATURE_MISMATCH alongside ;req and ;tr", () => {
  const keys = generateEd25519KeyPair();
  const request = triggeringRequest();
  const signed = signedCombined(keys, request);
  const result = verifyResponse(
    { ...signed, status: 500 },
    { ...verifyOpts(keys), request },
  );
  assert.equal(result.ok, false);
  assert.equal(result.code, "SIGNATURE_MISMATCH");
});

test("verify side still rejects the combined ;req signature with no request attached", () => {
  const keys = generateEd25519KeyPair();
  const signed = signedCombined(keys, triggeringRequest());
  assert.throws(
    () => verifyResponse(signed, verifyOpts(keys)),
    /verifyResponse: covered component .* derives from the request.*verifyRequest/,
  );
});

test("sign side still rejects the combined ;req coverage with no request attached", () => {
  const keys = generateEd25519KeyPair();
  assert.throws(
    () =>
      signResponse(
        { status: 200, headers: {}, trailers: { "x-checksum": "abc" } },
        { ...signOpts(keys), coveredComponents: [...COVERED] },
      ),
    /signResponse: covered component .* derives from the request.*signRequest.*request.*option/,
  );
});

test("covered trailer missing at verify time fails closed, not silently skipped", () => {
  const keys = generateEd25519KeyPair();
  const request = triggeringRequest();
  const signed = signedCombined(keys, request);
  const result = verifyResponse(
    { ...signed, trailers: {} },
    { ...verifyOpts(keys), request },
  );
  assert.equal(result.ok, false);
  assert.equal(result.code, "SIGNATURE_BASE_BUILD_FAILED");
});

test("uncovered trailer change still verifies: only the covered trailer binds", () => {
  const keys = generateEd25519KeyPair();
  const request = triggeringRequest();
  const signed = signedCombined(keys, request);
  const result = verifyResponse(
    {
      ...signed,
      trailers: { "x-checksum": "abc", "x-other": "changed-after-signing" },
    },
    { ...verifyOpts(keys), request },
  );
  assert.equal(result.ok, true);
});
