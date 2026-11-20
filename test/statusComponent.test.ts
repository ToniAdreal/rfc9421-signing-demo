import test from "node:test";
import assert from "node:assert/strict";
import {
  buildSignatureBase,
  generateEd25519KeyPair,
  signRequest,
  signResponse,
  verifyRequest,
  verifyResponse,
} from "../src/index.js";

const CREATED = 1700000000;
const URL = "https://api.example.com/v1/charge?order=42";

// The response-side covered list: `@status` binds the response
// itself, the rest bind the triggering request via `;req` (a bare
// `@method` / `@authority` / `@query` would be rejected by
// `signResponse` — those components derive from the request).
const COVERED = ["@method;req", "@authority;req", "@status", "@query;req"];

function makeReq() {
  return { method: "GET", url: URL, headers: {} };
}

function makeResp(status?: number) {
  return status === undefined
    ? { method: "GET", url: URL, headers: {} }
    : { method: "GET", url: URL, headers: {}, status };
}

test("golden: @status serializes as a plain integer line in the signature base", () => {
  const base = buildSignatureBase(["@status"], makeResp(201), {});
  assert.match(base, /^"@status": 201$/m);
});

test("sign→verify round-trip with @status covered (response verification)", () => {
  const { publicKey, privateKey } = generateEd25519KeyPair();
  const signed = signResponse(
    { status: 200, headers: {} },
    {
      keyId: "s1",
      alg: "ed25519",
      key: privateKey,
      created: CREATED,
      request: makeReq(),
      coveredComponents: COVERED,
    },
  );
  assert.match(signed.headers["signature-input"], /"@status"/);
  const res = verifyResponse(signed, {
    key: publicKey,
    now: CREATED + 60,
    request: makeReq(),
  });
  assert.equal(res.ok, true);
});

test("tampered status (200→500) fails with SIGNATURE_MISMATCH", () => {
  const { publicKey, privateKey } = generateEd25519KeyPair();
  const signed = signResponse(
    { status: 200, headers: {} },
    {
      keyId: "s1",
      alg: "ed25519",
      key: privateKey,
      created: CREATED,
      request: makeReq(),
      coveredComponents: COVERED,
    },
  );
  const res = verifyResponse(
    { ...signed, status: 500 },
    { key: publicKey, now: CREATED + 60, request: makeReq() },
  );
  assert.equal(res.ok, false);
  assert.equal(res.code, "SIGNATURE_MISMATCH");
});

test("signResponse with @status covered but no status throws a clear configuration error", () => {
  const { privateKey } = generateEd25519KeyPair();
  assert.throws(
    () =>
      signResponse(
        { status: undefined as unknown as number, headers: {} },
        {
          keyId: "s1",
          alg: "ed25519",
          key: privateKey,
          created: CREATED,
          coveredComponents: COVERED,
        },
      ),
    /signResponse: "status" must be an integer HTTP status code/,
  );
});

test("verify with @status covered but no status returns SIGNATURE_BASE_BUILD_FAILED", () => {
  const { publicKey, privateKey } = generateEd25519KeyPair();
  const signed = signResponse(
    { status: 200, headers: {} },
    {
      keyId: "s1",
      alg: "ed25519",
      key: privateKey,
      created: CREATED,
      request: makeReq(),
      coveredComponents: COVERED,
    },
  );
  // The request-shaped verify path reports a missing status as a
  // base-build failure rather than throwing (the response entry
  // point throws instead — see the test above).
  const res = verifyRequest(
    { method: "GET", url: URL, headers: signed.headers, request: makeReq() },
    { key: publicKey, now: CREATED + 60 },
  );
  assert.equal(res.ok, false);
  assert.equal(res.code, "SIGNATURE_BASE_BUILD_FAILED");
});

test("plain request path unchanged: @status uncovered is ignored, status absent still works", () => {
  const { publicKey, privateKey } = generateEd25519KeyPair();
  // Status present but not covered: must not affect verification.
  const signed = signRequest(makeResp(200), {
    keyId: "s1",
    alg: "ed25519",
    key: privateKey,
    created: CREATED,
  });
  const res = verifyRequest({ ...signed, status: 500 }, { key: publicKey, now: CREATED + 60 });
  assert.equal(res.ok, true);
  // Old shape with no status field at all: still fine.
  const res2 = verifyRequest(signed, { key: publicKey, now: CREATED + 60 });
  assert.equal(res2.ok, true);
});

test("component id is case-insensitive: '@STATUS' covered works", () => {
  const { publicKey, privateKey } = generateEd25519KeyPair();
  const signed = signResponse(
    { status: 204, headers: {} },
    {
      keyId: "s1",
      alg: "ed25519",
      key: privateKey,
      created: CREATED,
      coveredComponents: ["@STATUS"],
    },
  );
  assert.match(signed.headers["signature-input"], /"@status"/);
  const res = verifyResponse(signed, { key: publicKey, now: CREATED + 60 });
  assert.equal(res.ok, true);
});
