import test from "node:test";
import assert from "node:assert/strict";
import {
  buildSignatureBase,
  generateEd25519KeyPair,
  parseSignatureInput,
  signRequest,
  signResponse,
  verifyRequest,
  verifyResponse,
  type RequestLike,
} from "../src/index.js";

const CREATED = 1700000000;
const COVERED = ["@status", "@method;req", "@authority;req"];

function makeRequest(): RequestLike {
  return {
    method: "POST",
    url: "https://api.example.com/v1/charge?order=42",
    headers: { "x-charge-id": "ch_42" },
  };
}

function makeResponse(withRequest = true): RequestLike {
  return {
    method: "GET",
    url: "https://callbacks.example.com/v1/result",
    headers: {},
    status: 200,
    ...(withRequest ? { request: makeRequest() } : {}),
  };
}

function signResp(covered: string[] = COVERED) {
  const keys = generateEd25519KeyPair();
  const signed = signResponse(
    { status: 200, headers: {} },
    {
      keyId: "resp-1",
      alg: "ed25519",
      key: keys.privateKey,
      created: CREATED,
      request: makeRequest(),
      coveredComponents: covered,
    },
  );
  return { ...keys, signed };
}

test("golden: ;req line serializes as \"@method\";req in base and signature-params", () => {
  const base = buildSignatureBase(["@status", "@method;req"], makeResponse(), {});
  assert.equal(
    base,
    `"@status": 200\n` +
      `"@method";req: POST\n` +
      `"@signature-params": ("@status" "@method";req)`,
  );
});

test("sign→verify round-trip: response signature bound to its request via ;req", () => {
  const { publicKey, signed } = signResp();
  assert.match(signed.headers["signature-input"], /"@method";req/);
  assert.match(signed.headers["signature-input"], /"@authority";req/);
  // The associated request travels via the `request` option, so
  // verification needs it passed back explicitly.
  const res = verifyResponse(signed, {
    key: publicKey,
    now: CREATED + 60,
    request: makeRequest(),
  });
  assert.equal(res.ok, true);
});

test("parse: parseSignatureInput preserves the ;req suffix (does not swallow it)", () => {
  const { signed } = signResp();
  const parsed = parseSignatureInput(signed.headers["signature-input"], "sig1");
  assert.deepEqual(parsed.componentIds, [
    "@status",
    "@method;req",
    "@authority;req",
  ]);
});

test("tampered associated request method (POST→DELETE) fails with SIGNATURE_MISMATCH", () => {
  const { publicKey, signed } = signResp();
  const res = verifyResponse(signed, {
    key: publicKey,
    now: CREATED + 60,
    request: { ...makeRequest(), method: "DELETE" },
  });
  assert.equal(res.ok, false);
  assert.equal(res.code, "SIGNATURE_MISMATCH");
});

test("tampered associated request authority fails with SIGNATURE_MISMATCH (response transplanted)", () => {
  const { publicKey, signed } = signResp();
  const res = verifyResponse(signed, {
    key: publicKey,
    now: CREATED + 60,
    request: {
      ...makeRequest(),
      url: "https://attacker.example.com/v1/charge?order=42",
    },
  });
  assert.equal(res.ok, false);
  assert.equal(res.code, "SIGNATURE_MISMATCH");
});

test("same base: @method (response) and @method;req (request) coexist", () => {
  const { publicKey, privateKey } = generateEd25519KeyPair();
  const resp = makeResponse();
  const base = buildSignatureBase(["@method", "@method;req"], resp, {});
  assert.match(base, /^"@method": GET$/m);
  assert.match(base, /^"@method";req: POST$/m);
  const signed = signRequest(resp, {
    keyId: "resp-1",
    alg: "ed25519",
    key: privateKey,
    created: CREATED,
    coveredComponents: ["@method", "@method;req"],
  });
  const res = verifyRequest(signed, { key: publicKey, now: CREATED + 60 });
  assert.equal(res.ok, true);
});

test("sign with ;req covered but no associated request throws a configuration error", () => {
  const { privateKey } = generateEd25519KeyPair();
  assert.throws(
    () =>
      signResponse(
        { status: 200, headers: {} },
        {
          keyId: "resp-1",
          alg: "ed25519",
          key: privateKey,
          created: CREATED,
          coveredComponents: COVERED,
        },
      ),
    /signResponse: covered component "@method;req" derives from the request.*attach the triggering request via the `request` option/,
  );
});

test("verify with ;req covered but no associated request returns SIGNATURE_BASE_BUILD_FAILED", () => {
  const { publicKey, signed } = signResp();
  // The request-shaped verify path reports a missing associated
  // request as a base-build failure rather than throwing (the
  // response entry point throws instead — see the test above).
  const res = verifyRequest(
    {
      method: "GET",
      url: "https://callbacks.example.com/v1/result",
      headers: signed.headers,
    },
    { key: publicKey, now: CREATED + 60 },
  );
  assert.equal(res.ok, false);
  assert.equal(res.code, "SIGNATURE_BASE_BUILD_FAILED");
});

test("header field with ;req resolves from the associated request and verifies", () => {
  const { publicKey, signed } = signResp(["@status", "x-charge-id;req"]);
  assert.match(signed.headers["signature-input"], /"x-charge-id";req/);
  const res = verifyResponse(signed, {
    key: publicKey,
    now: CREATED + 60,
    request: makeRequest(),
  });
  assert.equal(res.ok, true);
});

test("tampered ;req header value on the associated request fails with SIGNATURE_MISMATCH", () => {
  const { publicKey, signed } = signResp(["@status", "x-charge-id;req"]);
  const res = verifyResponse(signed, {
    key: publicKey,
    now: CREATED + 60,
    request: { ...makeRequest(), headers: { "x-charge-id": "ch_99" } },
  });
  assert.equal(res.ok, false);
  assert.equal(res.code, "SIGNATURE_MISMATCH");
});

test("component id and ;req parameter are case-insensitive: '@METHOD;REQ' works", () => {
  const { publicKey, privateKey } = generateEd25519KeyPair();
  const signed = signResponse(
    { status: 200, headers: {} },
    {
      keyId: "resp-1",
      alg: "ed25519",
      key: privateKey,
      created: CREATED,
      request: makeRequest(),
      coveredComponents: ["@STATUS", "@METHOD;REQ"],
    },
  );
  assert.match(signed.headers["signature-input"], /"@method";req/);
  const res = verifyResponse(signed, {
    key: publicKey,
    now: CREATED + 60,
    request: makeRequest(),
  });
  assert.equal(res.ok, true);
});

test("unsupported component parameter fails closed on the sign side", () => {
  const { privateKey } = generateEd25519KeyPair();
  assert.throws(
    () =>
      signResponse(
        { status: 200, headers: {} },
        {
          keyId: "resp-1",
          alg: "ed25519",
          key: privateKey,
          created: CREATED,
          request: makeRequest(),
          coveredComponents: ["@status", "content-digest;zz"],
        },
      ),
    /unsupported component parameter ";zz".*only ";req", ";bs", ";sf", ";key", ";tr" and ";name" are supported/,
  );
});
