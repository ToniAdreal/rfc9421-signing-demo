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
const COVERED = ["@request-target"];

function makeReq(url: string, requestTarget?: string): RequestLike {
  return requestTarget === undefined
    ? { method: "POST", url, headers: {} }
    : { method: "POST", url, headers: {}, requestTarget };
}

function signAndVerify(req: RequestLike) {
  const { publicKey, privateKey } = generateEd25519KeyPair();
  const signed = signRequest(req, {
    keyId: "rt-override",
    alg: "ed25519",
    key: privateKey,
    created: CREATED,
    coveredComponents: COVERED,
  });
  return { signed, res: verifyRequest(signed, { key: publicKey, now: CREATED + 60 }) };
}

test("absolute-form override round-trips (and the signed object carries it)", () => {
  const target = "https://api.example.com/v1/payments?a=1";
  const { signed, res } = signAndVerify(makeReq("https://api.example.com/v1/payments?a=1", target));
  assert.equal(signed.requestTarget, target);
  assert.equal(res.ok, true);
  const base = buildSignatureBase(
    COVERED,
    makeReq("https://api.example.com/v1/payments?a=1", target),
    { created: CREATED, keyid: "k1", alg: "ed25519" },
  );
  assert.equal(
    base,
    `"@request-target": ${target}\n` +
      `"@signature-params": ("@request-target");created=1700000000;keyid="k1";alg="ed25519"`,
  );
});

test("authority-form override round-trips", () => {
  const { res } = signAndVerify(
    makeReq("https://api.example.com/v1/payments?a=1", "api.example.com:443"),
  );
  assert.equal(res.ok, true);
  // Golden base pins the override, not the origin-form rebuild: a
  // round-trip alone cannot tell them apart (both sides rebuild the
  // same value), so the base line is the real assertion here.
  const base = buildSignatureBase(
    COVERED,
    makeReq("https://api.example.com/v1/payments?a=1", "api.example.com:443"),
    {},
  );
  assert.match(base, /^"@request-target": api\.example\.com:443$/m);
});

test("asterisk-form override round-trips", () => {
  const { res } = signAndVerify(makeReq("https://api.example.com/v1/payments?a=1", "*"));
  assert.equal(res.ok, true);
  const base = buildSignatureBase(
    COVERED,
    makeReq("https://api.example.com/v1/payments?a=1", "*"),
    {},
  );
  assert.match(base, /^"@request-target": \*$/m);
});

test("tampered override fails with SIGNATURE_MISMATCH", () => {
  const { publicKey, privateKey } = generateEd25519KeyPair();
  const signed = signRequest(makeReq("https://api.example.com/v1/payments?a=1", "*"), {
    keyId: "rt-override",
    alg: "ed25519",
    key: privateKey,
    created: CREATED,
    coveredComponents: COVERED,
  });
  const tampered = { ...signed, requestTarget: "/v1/refunds" };
  const res = verifyRequest(tampered, { key: publicKey, now: CREATED + 60 });
  assert.equal(res.ok, false);
  assert.equal(res.code, "SIGNATURE_MISMATCH");
});

test("empty-string override is rejected on the sign side", () => {
  const { privateKey } = generateEd25519KeyPair();
  assert.throws(
    () =>
      signRequest(makeReq("https://api.example.com/v1/payments?a=1", ""), {
        keyId: "rt-override",
        alg: "ed25519",
        key: privateKey,
        created: CREATED,
        coveredComponents: COVERED,
      }),
    /requestTarget must be a non-empty string/,
  );
  assert.throws(
    () =>
      buildSignatureBase(
        COVERED,
        makeReq("https://api.example.com/v1/payments?a=1", ""),
        {},
      ),
    /requestTarget must be a non-empty string/,
  );
});

test("empty-string override on the verify side fails closed (no crypto verdict)", () => {
  const { publicKey, privateKey } = generateEd25519KeyPair();
  const signed = signRequest(makeReq("https://api.example.com/v1/payments?a=1", "*"), {
    keyId: "rt-override",
    alg: "ed25519",
    key: privateKey,
    created: CREATED,
    coveredComponents: COVERED,
  });
  const tampered = { ...signed, requestTarget: "" };
  const res = verifyRequest(tampered, { key: publicKey, now: CREATED + 60 });
  assert.equal(res.ok, false);
  assert.equal(res.code, "SIGNATURE_BASE_BUILD_FAILED");
});

test("unset override keeps the origin-form reconstruction", () => {
  const { res } = signAndVerify(makeReq("https://api.example.com/v1/payments?a=1"));
  assert.equal(res.ok, true);
  const base = buildSignatureBase(
    COVERED,
    makeReq("https://api.example.com/v1/payments?a=1"),
    { created: CREATED, keyid: "k1", alg: "ed25519" },
  );
  assert.match(base, /^"@request-target": \/v1\/payments\?a=1$/m);
});

test("\"@request-target\";req resolves against the associated request's override", () => {
  const { publicKey, privateKey } = generateEd25519KeyPair();
  const response: RequestLike = {
    method: "GET",
    url: "https://callbacks.example.com/v1/result",
    headers: {},
    status: 200,
    request: makeReq("https://api.example.com/v1/payments?a=1", "*"),
  };
  const base = buildSignatureBase(["@request-target;req"], response, {});
  assert.match(base, /^"@request-target";req: \*$/m);
  const signed = signRequest(response, {
    keyId: "rt-override",
    alg: "ed25519",
    key: privateKey,
    created: CREATED,
    coveredComponents: ["@status", "@request-target;req"],
  });
  const res = verifyRequest(signed, { key: publicKey, now: CREATED + 60 });
  assert.equal(res.ok, true);
  const tampered = {
    ...signed,
    request: makeReq("https://api.example.com/v1/payments?a=1", "/v1/other"),
  };
  const res2 = verifyRequest(tampered, { key: publicKey, now: CREATED + 60 });
  assert.equal(res2.ok, false);
  assert.equal(res2.code, "SIGNATURE_MISMATCH");
});
