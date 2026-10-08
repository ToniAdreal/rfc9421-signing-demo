import test from "node:test";
import assert from "node:assert/strict";
import {
  buildSignatureBase,
  generateEd25519KeyPair,
  signRequest,
  verifyRequest,
} from "../src/index.js";

const CREATED = 1700000000;
const COVERED = ["@method", "@authority", "@status", "@query"];
const URL = "https://api.example.com/v1/charge?order=42";

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
  const signed = signRequest(makeResp(200), {
    keyId: "s1",
    alg: "ed25519",
    key: privateKey,
    created: CREATED,
    coveredComponents: COVERED,
  });
  assert.match(signed.headers["signature-input"], /"@status"/);
  const res = verifyRequest({ ...signed, status: 200 }, { key: publicKey, now: CREATED + 60 });
  assert.equal(res.ok, true);
});

test("tampered status (200→500) fails with SIGNATURE_MISMATCH", () => {
  const { publicKey, privateKey } = generateEd25519KeyPair();
  const signed = signRequest(makeResp(200), {
    keyId: "s1",
    alg: "ed25519",
    key: privateKey,
    created: CREATED,
    coveredComponents: COVERED,
  });
  const res = verifyRequest({ ...signed, status: 500 }, { key: publicKey, now: CREATED + 60 });
  assert.equal(res.ok, false);
  assert.equal(res.code, "SIGNATURE_MISMATCH");
});

test("sign with @status covered but no status throws a clear configuration error", () => {
  const { privateKey } = generateEd25519KeyPair();
  assert.throws(
    () =>
      signRequest(makeResp(), {
        keyId: "s1",
        alg: "ed25519",
        key: privateKey,
        created: CREATED,
        coveredComponents: COVERED,
      }),
    /"@status" is covered but no status was given/,
  );
});

test("verify with @status covered but no status returns SIGNATURE_BASE_BUILD_FAILED", () => {
  const { publicKey, privateKey } = generateEd25519KeyPair();
  const signed = signRequest(makeResp(200), {
    keyId: "s1",
    alg: "ed25519",
    key: privateKey,
    created: CREATED,
    coveredComponents: COVERED,
  });
  const { status: _dropped, ...withoutStatus } = signed as typeof signed & { status?: number };
  const res = verifyRequest(withoutStatus, { key: publicKey, now: CREATED + 60 });
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
  const signed = signRequest(makeResp(204), {
    keyId: "s1",
    alg: "ed25519",
    key: privateKey,
    created: CREATED,
    coveredComponents: ["@STATUS"],
  });
  assert.match(signed.headers["signature-input"], /"@status"/);
  const res = verifyRequest({ ...signed, status: 204 }, { key: publicKey, now: CREATED + 60 });
  assert.equal(res.ok, true);
});
