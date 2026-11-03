import test from "node:test";
import assert from "node:assert/strict";
import {
  generateEd25519KeyPair,
  secretKey,
  signRequest,
  signResponse,
  verifyRequest,
  verifyResponse,
  type HttpResponseLike,
  type SignedHttpResponse,
} from "../src/index.js";

const CREATED = 1700000000;
const NOW = CREATED + 60;
const BODY = JSON.stringify({ settled: true, amount: 100 });

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

function response(overrides: Partial<HttpResponseLike> = {}): HttpResponseLike {
  return { status: 200, headers: {}, body: BODY, ...overrides };
}

test("round-trip: @status + content-digest covered by default, signature-input says so", () => {
  const keys = generateEd25519KeyPair();
  const signed = signResponse(response(), signOpts(keys));
  assert.match(
    signed.headers["signature-input"] as string,
    /"@status" "content-digest"/,
  );
  assert.deepEqual(signed.coveredComponents, ["@status", "content-digest"]);
  assert.equal(signed.status, 200);
  assert.equal(signed.body, BODY);
  const result = verifyResponse(signed, verifyOpts(keys));
  assert.equal(result.ok, true);
  assert.deepEqual(result.coveredComponents, ["@status", "content-digest"]);
});

test("round-trip: body-less response covers @status only, no content-digest minted", () => {
  const keys = generateEd25519KeyPair();
  const signed = signResponse(response({ body: undefined }), signOpts(keys));
  assert.match(signed.headers["signature-input"] as string, /"@status"/);
  assert.doesNotMatch(
    signed.headers["signature-input"] as string,
    /content-digest/,
  );
  assert.equal(signed.headers["content-digest"], undefined);
  assert.equal(verifyResponse(signed, verifyOpts(keys)).ok, true);
});

test("tampered status 200 -> 201 fails with SIGNATURE_MISMATCH", () => {
  const keys = generateEd25519KeyPair();
  const signed = signResponse(response(), signOpts(keys));
  const result = verifyResponse({ ...signed, status: 201 }, verifyOpts(keys));
  assert.equal(result.ok, false);
  assert.equal(result.code, "SIGNATURE_MISMATCH");
});

test("tampered body fails with BODY_DIGEST_MISMATCH", () => {
  const keys = generateEd25519KeyPair();
  const signed = signResponse(response(), signOpts(keys));
  const result = verifyResponse(
    { ...signed, body: JSON.stringify({ settled: true, amount: 101 }) },
    verifyOpts(keys),
  );
  assert.equal(result.ok, false);
  assert.equal(result.code, "BODY_DIGEST_MISMATCH");
});

test("explicit coveredComponents override: response header field binds, tamper rejected", () => {
  const keys = generateEd25519KeyPair();
  const signed = signResponse(
    response({ headers: { "x-settlement-id": "stl_42" } }),
    { ...signOpts(keys), coveredComponents: ["@status", "x-settlement-id"] },
  );
  assert.equal(verifyResponse(signed, verifyOpts(keys)).ok, true);
  const tampered: SignedHttpResponse = {
    ...signed,
    headers: { ...signed.headers, "x-settlement-id": "stl_43" },
  };
  const result = verifyResponse(tampered, verifyOpts(keys));
  assert.equal(result.ok, false);
  assert.equal(result.code, "SIGNATURE_MISMATCH");
});

test("hmac-sha256 response round-trip (alg-agnostic wrapper)", () => {
  const secret = secretKey("gateway-shared-secret-at-least-32-bytes!!");
  const signed = signResponse(response(), {
    alg: "hmac-sha256",
    key: secret,
    created: CREATED,
  });
  assert.equal(
    verifyResponse(signed, { key: secret, now: NOW }).ok,
    true,
  );
});

test("trailers: covered ;tr component verifies on the response side", () => {
  const keys = generateEd25519KeyPair();
  const signed = signResponse(
    response({ trailers: { "x-checksum": "abc" } }),
    { ...signOpts(keys), coveredComponents: ["@status", "x-checksum;tr"] },
  );
  assert.equal(verifyResponse(signed, verifyOpts(keys)).ok, true);
  const tampered: SignedHttpResponse = {
    ...signed,
    trailers: { "x-checksum": "abd" },
  };
  assert.equal(verifyResponse(tampered, verifyOpts(keys)).ok, false);
});

test("sign side rejects a non-integer status instead of signing a bogus @status", () => {
  const keys = generateEd25519KeyPair();
  assert.throws(
    () =>
      signResponse(
        { status: 200.5, headers: {} } as unknown as HttpResponseLike,
        signOpts(keys),
      ),
    /signResponse: "status" must be an integer/,
  );
  assert.throws(
    () =>
      signResponse(
        { headers: {} } as unknown as HttpResponseLike,
        signOpts(keys),
      ),
    /signResponse: "status" must be an integer/,
  );
});

test("sign side rejects request-derived and ;req components, pointing at signRequest", () => {
  const keys = generateEd25519KeyPair();
  for (const coveredComponents of [
    ["@status", "@method"],
    ["@status", "@authority"],
    ["@status", "x-ref;req"],
  ]) {
    assert.throws(
      () =>
        signResponse(response(), {
          ...signOpts(keys),
          coveredComponents,
        }),
      /signResponse: covered component .* derives from the request.*signRequest/,
    );
  }
});

test("verify side rejects a request-component signature, pointing at verifyRequest", () => {
  const keys = generateEd25519KeyPair();
  const signedRequest = signRequest(
    { method: "GET", url: "https://api.example.com/v1/charge", headers: {} },
    { ...signOpts(keys), coveredComponents: ["@method", "@authority", "@path"] },
  );
  assert.throws(
    () =>
      verifyResponse(
        { status: 200, headers: signedRequest.headers },
        verifyOpts(keys),
      ),
    /verifyResponse: covered component .* derives from the request.*verifyRequest/,
  );
});

test("request and response signatures with the same key do not cross-verify", () => {
  const keys = generateEd25519KeyPair();
  // A response signature bound to @status cannot be transplanted onto
  // a status-less request shape: the base cannot be rebuilt there.
  const signedResponse = signResponse(response(), signOpts(keys));
  const requestSide = verifyRequest(
    {
      method: "GET",
      url: "https://api.example.com/v1/charge",
      headers: signedResponse.headers,
      body: BODY,
    },
    verifyOpts(keys),
  );
  assert.equal(requestSide.ok, false);
  assert.equal(requestSide.code, "SIGNATURE_BASE_BUILD_FAILED");
  // And the response signature still verifies on its own side.
  assert.equal(verifyResponse(signedResponse, verifyOpts(keys)).ok, true);
  // A request signature (different covered set, same key) verifies on
  // the request side and is untouched by response signing.
  const signedRequest = signRequest(
    { method: "POST", url: "https://api.example.com/v1/charge", headers: {}, body: BODY },
    { ...signOpts(keys), coveredComponents: ["@method", "@authority", "@path", "content-digest"] },
  );
  assert.equal(
    verifyRequest(signedRequest, verifyOpts(keys)).ok,
    true,
  );
});

test("returned coveredComponents is a detached copy", () => {
  const keys = generateEd25519KeyPair();
  const signed = signResponse(response(), signOpts(keys));
  (signed.coveredComponents as string[]).push("@method");
  const signedAgain = signResponse(response(), signOpts(keys));
  assert.deepEqual(signedAgain.coveredComponents, ["@status", "content-digest"]);
  assert.equal(verifyResponse(signedAgain, verifyOpts(keys)).ok, true);
});

test("input response is not mutated by signing", () => {
  const keys = generateEd25519KeyPair();
  const res = response();
  const before = JSON.stringify({ ...res, body: BODY });
  signResponse(res, signOpts(keys));
  assert.equal(JSON.stringify({ ...res, body: BODY }), before);
  assert.equal(res.headers["signature-input"], undefined);
});
