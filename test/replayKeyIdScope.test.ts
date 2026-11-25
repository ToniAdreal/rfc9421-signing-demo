import test from "node:test";
import assert from "node:assert/strict";
import {
  generateEd25519KeyPair,
  ReplayCache,
  signRequest,
  verifyRequest,
} from "../src/index.js";

// Backlog #1412: replay entries are scoped by the signature's wire
// `keyid`, so two signers sharing one cache no longer collide on the
// same nonce string. The default scope "" keeps keyid-less signatures
// on the old single-namespace behavior among themselves.

const CREATED = 1700000000;
const NOW = CREATED + 60;

function cache() {
  return new ReplayCache({ ttlSec: 3600, now: () => NOW });
}

function signed(
  keyId: string | undefined,
  nonce: string,
  privateKey: ReturnType<typeof generateEd25519KeyPair>["privateKey"],
) {
  return signRequest(
    { method: "POST", url: "https://api.example.com/v1/payments", headers: {} },
    {
      ...(keyId === undefined ? {} : { keyId }),
      alg: "ed25519",
      key: privateKey,
      created: CREATED,
      nonce,
    },
  );
}

function verify(
  signedReq: ReturnType<typeof signRequest>,
  publicKey: ReturnType<typeof generateEd25519KeyPair>["publicKey"],
  c: ReplayCache,
) {
  return verifyRequest(signedReq, {
    key: publicKey,
    now: NOW,
    replayCache: c,
    maxSignatureAgeSec: 3600,
  });
}

test("check: the same nonce under two scopes records two independent entries", () => {
  const c = cache();
  assert.equal(c.check("n", NOW, "tenant-a"), false);
  assert.equal(c.check("n", NOW, "tenant-b"), false);
  assert.equal(c.size, 2);
  // Same scope replays; the other scope is untouched.
  assert.equal(c.check("n", NOW, "tenant-a"), true);
  assert.equal(c.size, 2);
});

test("check: scope/nonce pairs with separator bytes cannot collide", () => {
  const c = cache();
  assert.equal(c.check("b\0c", NOW, "a"), false);
  assert.equal(c.check("c", NOW, "a\0b"), false);
  assert.equal(c.size, 2);
  assert.equal(c.has("b\0c", NOW, "a"), true);
  assert.equal(c.has("c", NOW, "a\0b"), true);
  assert.equal(c.has("b\0c", NOW, "a\0b"), false);
});

test("has: a probe only reports the entry recorded under its own scope", () => {
  const c = cache();
  assert.equal(c.check("n", NOW, "tenant-a"), false);
  assert.equal(c.has("n", NOW, "tenant-a"), true);
  assert.equal(c.has("n", NOW, "tenant-b"), false);
  assert.equal(c.has("n", NOW), false);
  assert.equal(c.has("n", NOW, ""), false);
});

test("release: only the entry recorded under the released scope is forgotten", () => {
  const c = cache();
  assert.equal(c.check("n", NOW, "tenant-a"), false);
  assert.equal(c.check("n", NOW, "tenant-b"), false);
  assert.equal(c.release("n", NOW, "tenant-a"), true);
  assert.equal(c.has("n", NOW, "tenant-a"), false);
  assert.equal(c.has("n", NOW, "tenant-b"), true);
  assert.equal(c.size, 1);
  // Releasing the same scope twice reports nothing left to release.
  assert.equal(c.release("n", NOW, "tenant-a"), false);
});

test("check/has/release: a non-string scope throws instead of coercing a key", () => {
  const c = cache();
  assert.throws(
    () => c.check("n", NOW, 42 as unknown as string),
    /scope must be a string/,
  );
  assert.throws(
    () => c.has("n", NOW, null as unknown as string),
    /scope must be a string/,
  );
  assert.equal(c.size, 0);
});

test("restore: a v: 1 snapshot migrates to the empty scope and never blocks a keyed signer", () => {
  const restored = ReplayCache.restore(
    { v: 1, entries: [["legacy-nonce", 1000]] },
    { ttlSec: 3600, now: () => 1000 },
  );
  // The migrated entry blocks only unscoped (keyid-less) replays.
  assert.equal(restored.has("legacy-nonce", 1000), true);
  assert.equal(restored.has("legacy-nonce", 1000, ""), true);
  assert.equal(restored.has("legacy-nonce", 1000, "tenant-a"), false);
  assert.equal(restored.check("legacy-nonce", 1000, "tenant-a"), false);
  // The re-export is v: 2 with the migrated scope written out.
  const migrated = ReplayCache.restore(
    { v: 1, entries: [["legacy-nonce", 1000]] },
    { ttlSec: 3600, now: () => 1000 },
  );
  assert.deepEqual(migrated.exportSnapshot(), {
    v: 2,
    entries: [["", "legacy-nonce", 1000]],
  });
});

test("snapshot round-trip: scoped entries survive export and restore per scope", () => {
  const c = cache();
  assert.equal(c.check("n", NOW, "tenant-a"), false);
  assert.equal(c.check("n", NOW, "tenant-b"), false);
  assert.equal(c.check("other", NOW, "tenant-a"), false);
  const restored = ReplayCache.restore(c.exportSnapshot(), {
    ttlSec: 3600,
    now: () => NOW,
  });
  assert.equal(restored.has("n", NOW, "tenant-a"), true);
  assert.equal(restored.has("n", NOW, "tenant-b"), true);
  assert.equal(restored.has("other", NOW, "tenant-a"), true);
  assert.equal(restored.has("other", NOW, "tenant-b"), false);
  assert.equal(restored.has("n", NOW), false);
});

test("verifyRequest: a keyed signer's nonce does not block a keyid-less signer (and vice versa)", () => {
  const keyed = generateEd25519KeyPair();
  const keyless = generateEd25519KeyPair();
  const c = cache();
  const first = verify(signed("tenant-a", "shared-nonce", keyed.privateKey), keyed.publicKey, c);
  assert.equal(first.ok, true);
  assert.equal(first.keyId, "tenant-a");
  const second = verify(signed(undefined, "shared-nonce", keyless.privateKey), keyless.publicKey, c);
  assert.equal(second.ok, true);
  assert.equal(second.keyId, undefined);
  // And the keyid-less entry does not block a second keyed signer either.
  const third = verify(signed("tenant-b", "shared-nonce", keyed.privateKey), keyed.publicKey, c);
  assert.equal(third.ok, true);
  assert.equal(c.size, 3);
});

test("verifyRequest: an attacker cannot plant a victim's nonce with their own key", () => {
  const attacker = generateEd25519KeyPair();
  const victim = generateEd25519KeyPair();
  const c = cache();
  // The attacker signs a message with the victim's future nonce under
  // the attacker's own keyid; the attacker's signature is legitimate,
  // so it verifies — and records the nonce under the attacker's scope.
  const planted = verify(
    signed("attacker-key", "victim-nonce", attacker.privateKey),
    attacker.publicKey,
    c,
  );
  assert.equal(planted.ok, true);
  // The victim's own signature with the same nonce still verifies:
  // the planted entry lives in a different scope.
  const legit = verify(
    signed("victim-key", "victim-nonce", victim.privateKey),
    victim.publicKey,
    c,
  );
  assert.equal(legit.ok, true);
  // A genuine replay of the victim's request is still caught.
  const replay = verify(
    signed("victim-key", "victim-nonce", victim.privateKey),
    victim.publicKey,
    c,
  );
  assert.equal(replay.ok, false);
  assert.equal(replay.code, "NONCE_REPLAY");
});
