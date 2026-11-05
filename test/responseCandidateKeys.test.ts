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

// Backlog #895: `verifyResponse` inherits `VerifyOptions.candidateKeys`
// from `verifyRequest`, but no response-side test ever proved it —
// the request side has full candidateKeys coverage
// (test/candidateKeys.test.ts), while a gateway callback whose
// signature was minted with the second key of a rotation list was
// verified on the response side only by inheritance assumption.
// These tests pin the response side directly: the rotation walk
// gates `verifyResponse` exactly as it gates `verifyRequest`,
// including the second-candidate hit, the all-mismatch verdict, the
// configuration errors, and the retire-old-key rotation story.

const CREATED = 1700000000;
const NOW = CREATED + 60;
const BODY = JSON.stringify({ settled: true, amount: 100 });

function response(overrides: Partial<HttpResponseLike> = {}): HttpResponseLike {
  return { status: 200, headers: {}, body: BODY, ...overrides };
}

/** Three gateway key pairs: old, new, and an unrelated third party. */
function keypairs() {
  const oldPair = generateEd25519KeyPair();
  const newPair = generateEd25519KeyPair();
  const otherPair = generateEd25519KeyPair();
  return { oldPair, newPair, otherPair };
}

function signAs(
  keyId: string,
  privateKey: KeyObject,
  overrides: Partial<HttpResponseLike> = {},
): SignedHttpResponse {
  return signResponse(response(overrides), {
    keyId,
    alg: "ed25519",
    key: privateKey,
    created: CREATED,
  });
}

test("response candidateKeys: signature verifies against the second candidate", () => {
  const { oldPair, newPair } = keypairs();
  const signed = signAs("gateway-key-2", newPair.privateKey);
  const result = verifyResponse(signed, {
    candidateKeys: [oldPair.publicKey, newPair.publicKey],
    now: NOW,
  });
  assert.equal(result.ok, true, `expected ok, got ${JSON.stringify(result)}`);
  assert.equal(result.keyId, "gateway-key-2");
  assert.equal(result.alg, "ed25519");
  assert.deepEqual(result.coveredComponents, ["@status", "content-digest"]);
});

test("response candidateKeys: first-candidate hit verifies with its keyid", () => {
  const { oldPair, newPair } = keypairs();
  const signed = signAs("gateway-key-1", oldPair.privateKey);
  const result = verifyResponse(signed, {
    candidateKeys: [oldPair.publicKey, newPair.publicKey],
    now: NOW,
  });
  assert.equal(result.ok, true);
  assert.equal(result.keyId, "gateway-key-1");
  assert.equal(result.alg, "ed25519");
});

test("response candidateKeys: no matching candidate returns SIGNATURE_MISMATCH, not KEY_RESOLUTION_FAILED", () => {
  const { oldPair, newPair, otherPair } = keypairs();
  const signed = signAs("gateway-key-2", newPair.privateKey);
  const result = verifyResponse(signed, {
    candidateKeys: [oldPair.publicKey, otherPair.publicKey],
    now: NOW,
  });
  assert.equal(result.ok, false);
  assert.equal(result.code, "SIGNATURE_MISMATCH");
});

test("response candidateKeys: empty list throws a configuration error", () => {
  const { newPair } = keypairs();
  const signed = signAs("gateway-key-2", newPair.privateKey);
  assert.throws(
    () => verifyResponse(signed, { candidateKeys: [], now: NOW }),
    /non-empty array/,
  );
});

test("response candidateKeys: non-KeyObject entries throw a configuration error", () => {
  const { oldPair, newPair } = keypairs();
  const signed = signAs("gateway-key-2", newPair.privateKey);
  assert.throws(
    () =>
      verifyResponse(signed, {
        candidateKeys: ["not-a-key" as unknown as KeyObject],
        now: NOW,
      }),
    /candidateKeys\[0\].*must be a KeyObject/,
  );
  assert.throws(
    () =>
      verifyResponse(signed, {
        candidateKeys: [oldPair.publicKey, null as unknown as KeyObject],
        now: NOW,
      }),
    /candidateKeys\[1\].*must be a KeyObject/,
  );
});

test("response candidateKeys: key + candidateKeys together throws a configuration error", () => {
  const { oldPair, newPair } = keypairs();
  const signed = signAs("gateway-key-2", newPair.privateKey);
  assert.throws(
    () =>
      verifyResponse(signed, {
        key: newPair.publicKey,
        candidateKeys: [oldPair.publicKey, newPair.publicKey],
        now: NOW,
      }),
    /mutually exclusive/,
  );
});

test("response candidateKeys: keyResolver + candidateKeys together throws a configuration error", () => {
  const { oldPair, newPair } = keypairs();
  const signed = signAs("gateway-key-2", newPair.privateKey);
  assert.throws(
    () =>
      verifyResponse(signed, {
        keyResolver: () => newPair.publicKey,
        candidateKeys: [oldPair.publicKey, newPair.publicKey],
        now: NOW,
      }),
    /mutually exclusive/,
  );
});

test("response candidateKeys: rotation — old key still in the list verifies", () => {
  const { oldPair, newPair } = keypairs();
  // During the rotation window the new key is listed first, but a
  // callback still signed with the old key must keep verifying.
  const signed = signAs("gateway-key-1", oldPair.privateKey);
  const result = verifyResponse(signed, {
    candidateKeys: [newPair.publicKey, oldPair.publicKey],
    now: NOW,
  });
  assert.equal(result.ok, true);
  assert.equal(result.keyId, "gateway-key-1");
});

test("response candidateKeys: rotation — old key removed from the list is rejected", () => {
  const { oldPair, newPair, otherPair } = keypairs();
  const signed = signAs("gateway-key-1", oldPair.privateKey);
  const result = verifyResponse(signed, {
    candidateKeys: [newPair.publicKey, otherPair.publicKey],
    now: NOW,
  });
  assert.equal(result.ok, false);
  assert.equal(result.code, "SIGNATURE_MISMATCH");
});

test("response candidateKeys: body-less response (@status only) walks the list the same way", () => {
  const { oldPair, newPair } = keypairs();
  const signed = signAs("gateway-key-2", newPair.privateKey, { body: undefined });
  const result = verifyResponse(signed, {
    candidateKeys: [oldPair.publicKey, newPair.publicKey],
    now: NOW,
  });
  assert.equal(result.ok, true, `expected ok, got ${JSON.stringify(result)}`);
  assert.deepEqual(result.coveredComponents, ["@status"]);
});
