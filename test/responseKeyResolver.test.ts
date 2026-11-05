import test from "node:test";
import assert from "node:assert/strict";
import type { KeyObject } from "node:crypto";
import {
  generateEd25519KeyPair,
  signResponse,
  verifyResponse,
  type HttpResponseLike,
  type SignedHttpResponse,
} from "../src/index.js";

// Backlog #894: `verifyResponse` inherits `VerifyOptions.keyResolver`
// from `verifyRequest`, but no response-side test ever proved it —
// the request side has full keyResolver coverage
// (test/keyResolver.test.ts), while a gateway callback whose
// signature keyid is resolved dynamically was rejected on the
// response side only by inheritance assumption. These tests pin the
// response side directly: the resolver gates `verifyResponse`
// exactly as it gates `verifyRequest`, including the unknown-keyid,
// throwing-resolver, mutual-exclusion, and rotation cases.

const CREATED = 1700000000;
const NOW = CREATED + 60;
const BODY = JSON.stringify({ settled: true, amount: 100 });

function response(overrides: Partial<HttpResponseLike> = {}): HttpResponseLike {
  return { status: 200, headers: {}, body: BODY, ...overrides };
}

/** Two rotating gateway key pairs behind a `keyid`→key map. */
function keystore() {
  const k1 = generateEd25519KeyPair();
  const k2 = generateEd25519KeyPair();
  const store = new Map<string, KeyObject>([
    ["gateway-key-1", k1.publicKey],
    ["gateway-key-2", k2.publicKey],
  ]);
  return { k1, k2, store, keyResolver: (id: string) => store.get(id) };
}

function signAs(
  keyId: string | undefined,
  privateKey: KeyObject,
  overrides: Partial<HttpResponseLike> = {},
): SignedHttpResponse {
  return signResponse(response(overrides), {
    ...(keyId !== undefined ? { keyId } : {}),
    alg: "ed25519",
    key: privateKey,
    created: CREATED,
  });
}

test("response keyid resolves through keyResolver and verifies", () => {
  const { k1, keyResolver } = keystore();
  const signed = signAs("gateway-key-1", k1.privateKey);
  const result = verifyResponse(signed, { keyResolver, now: NOW });
  assert.equal(result.ok, true, `expected ok, got ${JSON.stringify(result)}`);
  assert.equal(result.keyId, "gateway-key-1");
  assert.equal(result.alg, "ed25519");
  assert.deepEqual(result.coveredComponents, ["@status", "content-digest"]);
});

test("response keyResolver: both key ids verify (rotation round-trip)", () => {
  const { k1, k2, keyResolver } = keystore();
  const s1 = signAs("gateway-key-1", k1.privateKey);
  const s2 = signAs("gateway-key-2", k2.privateKey);
  const r1 = verifyResponse(s1, { keyResolver, now: NOW });
  const r2 = verifyResponse(s2, { keyResolver, now: NOW });
  assert.equal(r1.ok, true);
  assert.equal(r1.keyId, "gateway-key-1");
  assert.equal(r2.ok, true);
  assert.equal(r2.keyId, "gateway-key-2");
});

test("response keyResolver: unknown keyid fails with KEY_RESOLUTION_FAILED", () => {
  const { k1, keyResolver } = keystore();
  const signed = signAs("attacker-key", k1.privateKey);
  const result = verifyResponse(signed, { keyResolver, now: NOW });
  assert.equal(result.ok, false);
  assert.equal(result.code, "KEY_RESOLUTION_FAILED");
  assert.equal(result.keyId, "attacker-key");
  assert.match(result.reason ?? "", /could not be resolved/);
});

test("response keyResolver: signature with no keyid fails with KEY_RESOLUTION_FAILED", () => {
  const { k1, keyResolver } = keystore();
  const signed = signAs(undefined, k1.privateKey);
  const result = verifyResponse(signed, { keyResolver, now: NOW });
  assert.equal(result.ok, false);
  assert.equal(result.code, "KEY_RESOLUTION_FAILED");
  assert.match(result.reason ?? "", /no keyid/);
});

test("response keyResolver: resolver returning the wrong key -> SIGNATURE_MISMATCH", () => {
  const { k1, k2 } = keystore();
  const signed = signAs("gateway-key-1", k1.privateKey);
  // Resolver maps to k2's public key: the keyid resolves, but the
  // crypto check must still reject because the signature was made
  // with k1.
  const result = verifyResponse(signed, {
    keyResolver: () => k2.publicKey,
    now: NOW,
  });
  assert.equal(result.ok, false);
  assert.equal(result.code, "SIGNATURE_MISMATCH");
});

test("response keyResolver: key + keyResolver together throws a configuration error", () => {
  const { k1, keyResolver } = keystore();
  const signed = signAs("gateway-key-1", k1.privateKey);
  assert.throws(
    () =>
      verifyResponse(signed, {
        key: k1.publicKey,
        keyResolver,
        now: NOW,
      }),
    /mutually exclusive/,
  );
});

test("response keyResolver: a throwing resolver surfaces VERIFICATION_ERROR, never escapes", () => {
  const { k1 } = keystore();
  const signed = signAs("gateway-key-1", k1.privateKey);
  const result = verifyResponse(signed, {
    keyResolver: () => {
      throw new Error("store is down");
    },
    now: NOW,
  });
  assert.equal(result.ok, false);
  assert.equal(result.code, "VERIFICATION_ERROR");
  assert.match(result.reason ?? "", /key resolver threw/);
});

test("response keyResolver: rotation — retired keyid is rejected, new keyid verifies", () => {
  const { k1, k2, store, keyResolver } = keystore();
  const oldSig = signAs("gateway-key-1", k1.privateKey);
  const newSig = signAs("gateway-key-2", k2.privateKey);
  // "Rotate": the old id is retired from the store.
  store.delete("gateway-key-1");
  assert.equal(verifyResponse(newSig, { keyResolver, now: NOW }).ok, true);
  const retired = verifyResponse(oldSig, { keyResolver, now: NOW });
  assert.equal(retired.ok, false);
  assert.equal(retired.code, "KEY_RESOLUTION_FAILED");
});

test("response keyResolver: body-less response (@status only) resolves the same way", () => {
  const { k1, keyResolver } = keystore();
  const signed = signAs("gateway-key-1", k1.privateKey, { body: undefined });
  const result = verifyResponse(signed, { keyResolver, now: NOW });
  assert.equal(result.ok, true, `expected ok, got ${JSON.stringify(result)}`);
  assert.deepEqual(result.coveredComponents, ["@status"]);
});
