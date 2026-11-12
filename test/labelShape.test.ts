import test from "node:test";
import assert from "node:assert/strict";
import {
  addSignature,
  generateEd25519KeyPair,
  signRequest,
  verifyRequest,
  verifyAllLabels,
} from "../src/index.js";

const CREATED = 1700000000;
const req = {
  method: "GET",
  url: "https://api.example.com/v1/status",
  headers: {},
};
const signOpts = (label: string) => ({
  keyId: "k",
  alg: "ed25519" as const,
  key: generateEd25519KeyPair().privateKey,
  created: CREATED,
  label,
});

test("label containing a comma is rejected with a configuration error", () => {
  assert.throws(() => signRequest(req, signOpts("merchant,gateway")), /must be an RFC 9421 token/);
});

test("label containing a space is rejected with a configuration error", () => {
  assert.throws(() => signRequest(req, signOpts("my sig")), /must be an RFC 9421 token/);
});

test("empty-string label is rejected with a configuration error", () => {
  assert.throws(() => signRequest(req, signOpts("")), /must be an RFC 9421 token/);
});

test("label containing a colon is rejected (verifyAllLabels cannot split it back)", () => {
  assert.throws(() => signRequest(req, signOpts("merchant:1")), /must be an RFC 9421 token/);
});

test("legal label with -_. characters signs and verifies", () => {
  const { publicKey, privateKey } = generateEd25519KeyPair();
  const label = "merchant-1.key_sig";
  const signed = signRequest(req, {
    keyId: "k",
    alg: "ed25519",
    key: privateKey,
    created: CREATED,
    label,
  });
  assert.ok(
    signed.headers["signature-input"].startsWith(`${label}=`),
    `wire label mismatch: ${signed.headers["signature-input"]}`,
  );
  const res = verifyRequest(signed, {
    key: publicKey,
    label,
    now: CREATED + 60,
  });
  assert.equal(res.ok, true);
});

test("legal label survives the verifyAllLabels multi-label path", () => {
  const { publicKey, privateKey } = generateEd25519KeyPair();
  const label = "gw-2.sig";
  const signed = signRequest(req, {
    keyId: "k",
    alg: "ed25519",
    key: privateKey,
    created: CREATED,
    label,
  });
  const results = verifyAllLabels(signed, { key: publicKey, now: CREATED + 60 });
  assert.equal(results.length, 1);
  assert.equal(results[0].label, label);
  assert.equal(results[0].ok, true);
});

test('default label "sig1" is unchanged', () => {
  const { publicKey, privateKey } = generateEd25519KeyPair();
  const signed = signRequest(req, {
    keyId: "k",
    alg: "ed25519",
    key: privateKey,
    created: CREATED,
  });
  assert.ok(signed.headers["signature-input"].startsWith("sig1="));
  const res = verifyRequest(signed, { key: publicKey, now: CREATED + 60 });
  assert.equal(res.ok, true);
});

test("addSignature with an illegal label is rejected naming addSignature (backlog #1084)", () => {
  const { privateKey } = generateEd25519KeyPair();
  const signed = signRequest(req, {
    keyId: "k",
    alg: "ed25519",
    key: privateKey,
    created: CREATED,
  });
  let message = "";
  try {
    addSignature(signed, {
      keyId: "k2",
      alg: "ed25519",
      key: privateKey,
      created: CREATED,
      label: "bad label",
    });
  } catch (e) {
    message = (e as Error).message;
  }
  assert.ok(
    message.startsWith('addSignature: "label" must be an RFC 9421 token'),
    `expected the error to name addSignature, got: ${message}`,
  );
  assert.ok(
    !message.includes("signRequest"),
    `error must not name the delegated signRequest, got: ${message}`,
  );
});
