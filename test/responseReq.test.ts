import test from "node:test";
import assert from "node:assert/strict";
import {
  generateEd25519KeyPair,
  signResponse,
  verifyResponse,
  type RequestLike,
} from "../src/index.js";

const CREATED = 1700000000;
const NOW = CREATED + 60;

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

test("round-trip: ;req components bind the response to its triggering request", () => {
  const keys = generateEd25519KeyPair();
  const request = triggeringRequest();
  const signed = signResponse(
    { status: 200, headers: {} },
    {
      ...signOpts(keys),
      coveredComponents: ["@status", "@method;req", "@authority;req"],
      request,
    },
  );
  assert.match(signed.headers["signature-input"] as string, /"@method";req/);
  assert.match(signed.headers["signature-input"] as string, /"@authority";req/);
  const result = verifyResponse(signed, { ...verifyOpts(keys), request });
  assert.equal(result.ok, true);
  assert.deepEqual(result.coveredComponents, [
    "@status",
    "@method;req",
    "@authority;req",
  ]);
});

test("round-trip: ;req header field reads the triggering request's headers", () => {
  const keys = generateEd25519KeyPair();
  const request = triggeringRequest();
  const signed = signResponse(
    { status: 200, headers: {} },
    {
      ...signOpts(keys),
      coveredComponents: ["@status", "x-charge-id;req"],
      request,
    },
  );
  assert.equal(
    verifyResponse(signed, { ...verifyOpts(keys), request }).ok,
    true,
  );
  const tampered = triggeringRequest({ headers: { "x-charge-id": "ch_43" } });
  const result = verifyResponse(signed, { ...verifyOpts(keys), request: tampered });
  assert.equal(result.ok, false);
  assert.equal(result.code, "SIGNATURE_MISMATCH");
});

test("tampered triggering request method fails with SIGNATURE_MISMATCH", () => {
  const keys = generateEd25519KeyPair();
  const request = triggeringRequest();
  const signed = signResponse(
    { status: 200, headers: {} },
    {
      ...signOpts(keys),
      coveredComponents: ["@status", "@method;req"],
      request,
    },
  );
  const tampered = triggeringRequest({ method: "DELETE" });
  const result = verifyResponse(signed, { ...verifyOpts(keys), request: tampered });
  assert.equal(result.ok, false);
  assert.equal(result.code, "SIGNATURE_MISMATCH");
});

test("response transplanted onto another request fails (authority differs)", () => {
  const keys = generateEd25519KeyPair();
  const request = triggeringRequest();
  const signed = signResponse(
    { status: 200, headers: {} },
    {
      ...signOpts(keys),
      coveredComponents: ["@status", "@authority;req"],
      request,
    },
  );
  const other = triggeringRequest({
    url: "https://attacker.example.com/v1/charge?order=42",
  });
  const result = verifyResponse(signed, { ...verifyOpts(keys), request: other });
  assert.equal(result.ok, false);
  assert.equal(result.code, "SIGNATURE_MISMATCH");
});

test("sign side still rejects ;req with no request attached, pointing at the option", () => {
  const keys = generateEd25519KeyPair();
  assert.throws(
    () =>
      signResponse(
        { status: 200, headers: {} },
        {
          ...signOpts(keys),
          coveredComponents: ["@status", "@method;req"],
        },
      ),
    /signResponse: covered component .* derives from the request.*signRequest.*request.*option/,
  );
});

test("verify side still rejects a ;req signature with no request attached", () => {
  const keys = generateEd25519KeyPair();
  const request = triggeringRequest();
  const signed = signResponse(
    { status: 200, headers: {} },
    {
      ...signOpts(keys),
      coveredComponents: ["@status", "@method;req"],
      request,
    },
  );
  assert.throws(
    () => verifyResponse(signed, verifyOpts(keys)),
    /verifyResponse: covered component .* derives from the request.*verifyRequest/,
  );
});

test("plain derived component still rejected even with a request attached, pointing at ;req", () => {
  const keys = generateEd25519KeyPair();
  const request = triggeringRequest();
  assert.throws(
    () =>
      signResponse(
        { status: 200, headers: {} },
        {
          ...signOpts(keys),
          coveredComponents: ["@status", "@method"],
          request,
        },
      ),
    /signResponse: covered component "@method" derives from the request.*cover "@method";req/,
  );
});

test("attached request is inert when no ;req component is covered", () => {
  const keys = generateEd25519KeyPair();
  const request = triggeringRequest();
  const signed = signResponse(
    { status: 200, headers: {} },
    { ...signOpts(keys), request },
  );
  assert.deepEqual(signed.coveredComponents, ["@status"]);
  // Verifies without any request attached, exactly as before.
  assert.equal(verifyResponse(signed, verifyOpts(keys)).ok, true);
});

test("@status stays bound alongside ;req: tampered status still rejected", () => {
  const keys = generateEd25519KeyPair();
  const request = triggeringRequest();
  const signed = signResponse(
    { status: 200, headers: {} },
    {
      ...signOpts(keys),
      coveredComponents: ["@status", "@method;req"],
      request,
    },
  );
  const result = verifyResponse(
    { ...signed, status: 500 },
    { ...verifyOpts(keys), request },
  );
  assert.equal(result.ok, false);
  assert.equal(result.code, "SIGNATURE_MISMATCH");
});
