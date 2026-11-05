import test from "node:test";
import assert from "node:assert/strict";
import type { KeyObject } from "node:crypto";
import {
  generateEd25519KeyPair,
  signResponse,
  verifyResponse,
  type HttpResponseLike,
  type SignedHttpResponse,
  type VerifyResponseOptions,
} from "../src/index.js";

// Backlog #896: `verifyResponse` inherits `VerifyOptions.requireTag` /
// `requireNonce` / `expectedKeyId` from `verifyRequest`, but no
// response-side test ever proved the gates fire on a response
// signature — the request side pins them (test/requireTag.test.ts,
// test/requireNonce.test.ts, and the expectedKeyId cases), while the
// response side only had `requiredComponents: ["@status"]` coverage
// in test/nodeHttpResponse*.test.ts, which is a coverage requirement,
// not these three presence/binding gates. These tests pin the
// response side directly: a gateway callback that omits the tag or
// nonce the receiver demands, or that arrives under an unexpected
// keyid, is rejected with the exact request-side code — and a forged
// signature is still reported as SIGNATURE_MISMATCH, never masked by
// a policy gate (the gates run after the crypto check).

const CREATED = 1700000000;
const NOW = CREATED + 60;
const BODY = JSON.stringify({ settled: true, amount: 100 });

function response(overrides: Partial<HttpResponseLike> = {}): HttpResponseLike {
  return { status: 200, headers: {}, body: BODY, ...overrides };
}

function keys() {
  const pair = generateEd25519KeyPair();
  const other = generateEd25519KeyPair();
  return { pair, other };
}

interface SignOpts {
  keyId?: string;
  tag?: string;
  nonce?: string;
  key: KeyObject;
}

function signAs(
  opts: SignOpts,
  overrides: Partial<HttpResponseLike> = {},
): SignedHttpResponse {
  return signResponse(response(overrides), {
    ...(opts.keyId !== undefined ? { keyId: opts.keyId } : {}),
    ...(opts.tag !== undefined ? { tag: opts.tag } : {}),
    ...(opts.nonce !== undefined ? { nonce: opts.nonce } : {}),
    alg: "ed25519",
    key: opts.key,
    created: CREATED,
  });
}

function verify(
  signed: SignedHttpResponse,
  opts: VerifyResponseOptions,
  key: KeyObject,
) {
  return verifyResponse(signed, { key, now: NOW, ...opts });
}

test("response requireTag: untagged response is rejected with MISSING_TAG", () => {
  const { pair } = keys();
  const signed = signAs({ key: pair.privateKey });
  const result = verify(signed, { requireTag: true }, pair.publicKey);
  assert.equal(result.ok, false);
  assert.equal(result.code, "MISSING_TAG");
  assert.match(result.reason ?? "", /no `tag` but requireTag is set/);
});

test("response requireTag: tagged response verifies and echoes the tag", () => {
  const { pair } = keys();
  const signed = signAs({ key: pair.privateKey, tag: "webhook.settled" });
  const result = verify(signed, { requireTag: true }, pair.publicKey);
  assert.equal(result.ok, true, `expected ok, got ${JSON.stringify(result)}`);
  assert.equal(result.tag, "webhook.settled");
});

test("response requireNonce: nonce-less response is rejected with MISSING_NONCE", () => {
  const { pair } = keys();
  const signed = signAs({ key: pair.privateKey });
  const result = verify(signed, { requireNonce: true }, pair.publicKey);
  assert.equal(result.ok, false);
  assert.equal(result.code, "MISSING_NONCE");
  assert.match(result.reason ?? "", /no `nonce` but requireNonce is set/);
});

test("response requireNonce: nonce-carrying response verifies and echoes the nonce", () => {
  const { pair } = keys();
  const signed = signAs({ key: pair.privateKey, nonce: "resp-nonce-1" });
  const result = verify(signed, { requireNonce: true }, pair.publicKey);
  assert.equal(result.ok, true, `expected ok, got ${JSON.stringify(result)}`);
  assert.equal(result.nonce, "resp-nonce-1");
});

test("response expectedKeyId: wrong keyid is rejected with KEYID_MISMATCH", () => {
  const { pair } = keys();
  const signed = signAs({ key: pair.privateKey, keyId: "gateway-key-2" });
  const result = verify(
    signed,
    { expectedKeyId: "gateway-key-1" },
    pair.publicKey,
  );
  assert.equal(result.ok, false);
  assert.equal(result.code, "KEYID_MISMATCH");
  assert.equal(result.keyId, "gateway-key-2");
  assert.match(result.reason ?? "", /keyid mismatch/);
});

test("response expectedKeyId: matching keyid verifies and echoes the keyid", () => {
  const { pair } = keys();
  const signed = signAs({ key: pair.privateKey, keyId: "gateway-key-1" });
  const result = verify(
    signed,
    { expectedKeyId: "gateway-key-1" },
    pair.publicKey,
  );
  assert.equal(result.ok, true, `expected ok, got ${JSON.stringify(result)}`);
  assert.equal(result.keyId, "gateway-key-1");
});

test("response expectedKeyId: signature with no keyid is rejected with KEYID_MISMATCH", () => {
  const { pair } = keys();
  const signed = signAs({ key: pair.privateKey });
  const result = verify(
    signed,
    { expectedKeyId: "gateway-key-1" },
    pair.publicKey,
  );
  assert.equal(result.ok, false);
  assert.equal(result.code, "KEYID_MISMATCH");
  assert.match(result.reason ?? "", /no keyid/);
});

test("response gates off: the same untagged, nonce-less, unpinned batch verifies", () => {
  const { pair } = keys();
  const signed = signAs({ key: pair.privateKey });
  const result = verify(signed, {}, pair.publicKey);
  assert.equal(result.ok, true, `expected ok, got ${JSON.stringify(result)}`);
  assert.equal(result.tag, undefined);
  assert.equal(result.nonce, undefined);
  assert.equal(result.keyId, undefined);
});

test("response gates on: a fully conforming signature passes all three gates", () => {
  const { pair } = keys();
  const signed = signAs({
    key: pair.privateKey,
    keyId: "gateway-key-1",
    tag: "webhook.settled",
    nonce: "resp-nonce-1",
  });
  const result = verify(
    signed,
    {
      requireTag: true,
      requireNonce: true,
      expectedKeyId: "gateway-key-1",
    },
    pair.publicKey,
  );
  assert.equal(result.ok, true, `expected ok, got ${JSON.stringify(result)}`);
  assert.equal(result.tag, "webhook.settled");
  assert.equal(result.nonce, "resp-nonce-1");
  assert.equal(result.keyId, "gateway-key-1");
});

test("response gates do not mask forgery: wrong key + requireTag/requireNonce -> SIGNATURE_MISMATCH", () => {
  const { pair, other } = keys();
  const signed = signAs({ key: pair.privateKey });
  const result = verify(
    signed,
    { requireTag: true, requireNonce: true },
    other.publicKey,
  );
  assert.equal(result.ok, false);
  assert.equal(result.code, "SIGNATURE_MISMATCH");
});

test("response requireTag: body-less response (@status only) is rejected the same way", () => {
  const { pair } = keys();
  const signed = signAs({ key: pair.privateKey }, { body: undefined });
  const result = verify(signed, { requireTag: true }, pair.publicKey);
  assert.equal(result.ok, false);
  assert.equal(result.code, "MISSING_TAG");
  assert.deepEqual(result.coveredComponents, ["@status"]);
});
