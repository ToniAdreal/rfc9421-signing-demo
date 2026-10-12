import test from "node:test";
import assert from "node:assert/strict";
import {
  buildSignatureBase,
  generateEd25519KeyPair,
  signRequest,
  verifyRequest,
  type RequestLike,
} from "../src/index.js";

const CREATED = 1700000000;
const COVERED = ["@method", "@authority", "@request-target"];

function makeReq(url: string): RequestLike {
  return { method: "POST", url, headers: {} };
}

test("sign→verify round-trip with @request-target covered (with query)", () => {
  const { publicKey, privateKey } = generateEd25519KeyPair();
  const signed = signRequest(makeReq("https://api.example.com/v1/payments?a=1"), {
    keyId: "rt1",
    alg: "ed25519",
    key: privateKey,
    created: CREATED,
    coveredComponents: COVERED,
  });
  assert.match(signed.headers["signature-input"], /"@request-target"/);
  const res = verifyRequest(signed, { key: publicKey, now: CREATED + 60 });
  assert.equal(res.ok, true);
});

test("tampered path fails with SIGNATURE_MISMATCH", () => {
  const { publicKey, privateKey } = generateEd25519KeyPair();
  const signed = signRequest(makeReq("https://api.example.com/v1/payments?a=1"), {
    keyId: "rt1",
    alg: "ed25519",
    key: privateKey,
    created: CREATED,
    coveredComponents: COVERED,
  });
  const tampered = { ...signed, url: "https://api.example.com/v1/refunds?a=1" };
  const res = verifyRequest(tampered, { key: publicKey, now: CREATED + 60 });
  assert.equal(res.ok, false);
  assert.equal(res.code, "SIGNATURE_MISMATCH");
});

test("tampered query fails with SIGNATURE_MISMATCH", () => {
  const { publicKey, privateKey } = generateEd25519KeyPair();
  const signed = signRequest(makeReq("https://api.example.com/v1/payments?a=1"), {
    keyId: "rt1",
    alg: "ed25519",
    key: privateKey,
    created: CREATED,
    coveredComponents: COVERED,
  });
  const tampered = { ...signed, url: "https://api.example.com/v1/payments?a=2" };
  const res = verifyRequest(tampered, { key: publicKey, now: CREATED + 60 });
  assert.equal(res.ok, false);
  assert.equal(res.code, "SIGNATURE_MISMATCH");
});

test("golden signature base contains the \"@request-target\": /v1/payments?a=1 line", () => {
  const base = buildSignatureBase(
    ["@method", "@request-target"],
    makeReq("https://api.example.com/v1/payments?a=1"),
    { created: CREATED, keyid: "k1", alg: "ed25519" },
  );
  assert.equal(
    base,
    `"@method": POST\n` +
      `"@request-target": /v1/payments?a=1\n` +
      `"@signature-params": ("@method" "@request-target");created=1700000000;keyid="k1";alg="ed25519"`,
  );
});

test("no query string: golden base has no trailing \"?\"", () => {
  const base = buildSignatureBase(
    ["@request-target"],
    makeReq("https://api.example.com/v1/payments"),
    { created: CREATED, keyid: "k1", alg: "ed25519" },
  );
  assert.equal(
    base,
    `"@request-target": /v1/payments\n` +
      `"@signature-params": ("@request-target");created=1700000000;keyid="k1";alg="ed25519"`,
  );
});

test("empty path with a query yields \"/?a=1\" (path defaults to /)", () => {
  const base = buildSignatureBase(
    ["@request-target"],
    makeReq("https://api.example.com?a=1"),
    {},
  );
  assert.match(base, /^"@request-target": \/\?a=1$/m);
});

test("fragment never participates in @request-target", () => {
  const base = buildSignatureBase(
    ["@request-target"],
    makeReq("https://api.example.com/v1/payments?a=1#section"),
    {},
  );
  assert.match(base, /^"@request-target": \/v1\/payments\?a=1$/m);
  assert.doesNotMatch(base, /section/);
});

test("scheme/authority are not bound: same path+query on another authority still verifies when only @request-target is covered", () => {
  const { publicKey, privateKey } = generateEd25519KeyPair();
  const signed = signRequest(makeReq("https://api.example.com/v1/payments?a=1"), {
    keyId: "rt1",
    alg: "ed25519",
    key: privateKey,
    created: CREATED,
    coveredComponents: ["@request-target"],
  });
  // Unlike @target-uri, @request-target excludes scheme and authority:
  // moving the same request target to another host does not break it.
  const moved = { ...signed, url: "http://other.example.net/v1/payments?a=1" };
  const res = verifyRequest(moved, { key: publicKey, now: CREATED + 60 });
  assert.equal(res.ok, true);
});

test("\"@request-target\";req resolves against the associated request", () => {
  const { publicKey, privateKey } = generateEd25519KeyPair();
  const response: RequestLike = {
    method: "GET",
    url: "https://callbacks.example.com/v1/result",
    headers: {},
    status: 200,
    request: makeReq("https://api.example.com/v1/payments?a=1"),
  };
  const base = buildSignatureBase(["@request-target;req"], response, {});
  assert.match(base, /^"@request-target";req: \/v1\/payments\?a=1$/m);
  const signed = signRequest(response, {
    keyId: "rt1",
    alg: "ed25519",
    key: privateKey,
    created: CREATED,
    coveredComponents: ["@status", "@request-target;req"],
  });
  const res = verifyRequest(signed, { key: publicKey, now: CREATED + 60 });
  assert.equal(res.ok, true);
  const tampered = {
    ...signed,
    request: makeReq("https://api.example.com/v1/payments?a=9"),
  };
  const res2 = verifyRequest(tampered, { key: publicKey, now: CREATED + 60 });
  assert.equal(res2.ok, false);
  assert.equal(res2.code, "SIGNATURE_MISMATCH");
});

test(";bs on @request-target is rejected like on any derived component", () => {
  const { privateKey } = generateEd25519KeyPair();
  assert.throws(
    () =>
      signRequest(makeReq("https://api.example.com/v1/payments?a=1"), {
        keyId: "rt1",
        alg: "ed25519",
        key: privateKey,
        created: CREATED,
        coveredComponents: ["@request-target;bs"],
      }),
    /";bs" on derived component "@request-target"/,
  );
});

test("component id is case-insensitive: '@REQUEST-TARGET' works", () => {
  const { publicKey, privateKey } = generateEd25519KeyPair();
  const signed = signRequest(makeReq("https://api.example.com/v1/payments?a=1"), {
    keyId: "rt1",
    alg: "ed25519",
    key: privateKey,
    created: CREATED,
    coveredComponents: ["@REQUEST-TARGET"],
  });
  assert.match(signed.headers["signature-input"], /"@request-target"/);
  const res = verifyRequest(signed, { key: publicKey, now: CREATED + 60 });
  assert.equal(res.ok, true);
});
