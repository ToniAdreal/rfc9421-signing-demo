import test from "node:test";
import assert from "node:assert/strict";
import {
  buildSignatureBase,
  generateEd25519KeyPair,
  parseSignatureInput,
  signRequest,
  verifyRequest,
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

function signResponse(covered: string[] = COVERED) {
  const keys = generateEd25519KeyPair();
  const signed = signRequest(makeResponse(), {
    keyId: "resp-1",
    alg: "ed25519",
    key: keys.privateKey,
    created: CREATED,
    coveredComponents: covered,
  });
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
  const { publicKey, signed } = signResponse();
  assert.match(signed.headers["signature-input"], /"@method";req/);
  assert.match(signed.headers["signature-input"], /"@authority";req/);
  // The associated request is carried through on the signed object, so
  // verification needs nothing re-attached by hand.
  assert.equal(signed.request?.method, "POST");
  const res = verifyRequest(signed, { key: publicKey, now: CREATED + 60 });
  assert.equal(res.ok, true);
});

test("parse: parseSignatureInput preserves the ;req suffix (does not swallow it)", () => {
  const { signed } = signResponse();
  const parsed = parseSignatureInput(signed.headers["signature-input"], "sig1");
  assert.deepEqual(parsed.componentIds, [
    "@status",
    "@method;req",
    "@authority;req",
  ]);
});

test("tampered associated request method (POST→DELETE) fails with SIGNATURE_MISMATCH", () => {
  const { publicKey, signed } = signResponse();
  const tampered = {
    ...signed,
    request: { ...makeRequest(), method: "DELETE" },
  };
  const res = verifyRequest(tampered, { key: publicKey, now: CREATED + 60 });
  assert.equal(res.ok, false);
  assert.equal(res.code, "SIGNATURE_MISMATCH");
});

test("tampered associated request authority fails with SIGNATURE_MISMATCH (response transplanted)", () => {
  const { publicKey, signed } = signResponse();
  const tampered = {
    ...signed,
    request: {
      ...makeRequest(),
      url: "https://attacker.example.com/v1/charge?order=42",
    },
  };
  const res = verifyRequest(tampered, { key: publicKey, now: CREATED + 60 });
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
      signRequest(makeResponse(false), {
        keyId: "resp-1",
        alg: "ed25519",
        key: privateKey,
        created: CREATED,
        coveredComponents: COVERED,
      }),
    /"@method";req is covered but no associated request was given/,
  );
});

test("verify with ;req covered but no associated request returns SIGNATURE_BASE_BUILD_FAILED", () => {
  const { publicKey, signed } = signResponse();
  const { request: _dropped, ...withoutRequest } = signed;
  const res = verifyRequest(withoutRequest, {
    key: publicKey,
    now: CREATED + 60,
  });
  assert.equal(res.ok, false);
  assert.equal(res.code, "SIGNATURE_BASE_BUILD_FAILED");
});

test("header field with ;req resolves from the associated request and verifies", () => {
  const { publicKey, signed } = signResponse(["@status", "x-charge-id;req"]);
  assert.match(signed.headers["signature-input"], /"x-charge-id";req/);
  const res = verifyRequest(signed, { key: publicKey, now: CREATED + 60 });
  assert.equal(res.ok, true);
});

test("tampered ;req header value on the associated request fails with SIGNATURE_MISMATCH", () => {
  const { publicKey, signed } = signResponse(["@status", "x-charge-id;req"]);
  const tampered = {
    ...signed,
    request: { ...makeRequest(), headers: { "x-charge-id": "ch_99" } },
  };
  const res = verifyRequest(tampered, { key: publicKey, now: CREATED + 60 });
  assert.equal(res.ok, false);
  assert.equal(res.code, "SIGNATURE_MISMATCH");
});

test("component id and ;req parameter are case-insensitive: '@METHOD;REQ' works", () => {
  const { publicKey, privateKey } = generateEd25519KeyPair();
  const signed = signRequest(makeResponse(), {
    keyId: "resp-1",
    alg: "ed25519",
    key: privateKey,
    created: CREATED,
    coveredComponents: ["@STATUS", "@METHOD;REQ"],
  });
  assert.match(signed.headers["signature-input"], /"@method";req/);
  const res = verifyRequest(signed, { key: publicKey, now: CREATED + 60 });
  assert.equal(res.ok, true);
});

test("unsupported component parameter fails closed on the sign side", () => {
  const { privateKey } = generateEd25519KeyPair();
  assert.throws(
    () =>
      signRequest(makeResponse(), {
        keyId: "resp-1",
        alg: "ed25519",
        key: privateKey,
        created: CREATED,
        coveredComponents: ["@status", "content-digest;zz"],
      }),
    /unsupported component parameter ";zz".*only ";req", ";bs", ";sf", ";key" and ";tr" are supported/,
  );
});
